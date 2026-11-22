"""Tool execution validation — allowlist, argument sanitization, policy, safe subprocess."""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import os
import re
import shlex
import shutil
import signal
import socket
import sys
import tempfile
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server.audit import (  # noqa: E402
    log_blocked,
    log_dns,
    log_execution,
    log_pipeline_result,
    log_pipeline_start,
    log_pipeline_step,
    log_rate_limit,
    log_script_execution,
    log_script_result,
    log_validation,
    redact_credentials,
)
from mcp_server.local_sandbox import protective_flag as _protective_flag  # noqa: E402
from mcp_server.local_sandbox import wrap as _sandbox_wrap  # noqa: E402
from mcp_server.sanitize import sanitize_output, truncate_output  # noqa: E402
from mcp_server.tools_db import (  # noqa: E402
    GIT_BIN_NAMES,
    GIT_NETWORK_TOOLS,
    HOST_CONTROL_OPT_INS,
    ToolsDatabase,
    binary_candidates,
    execution_metadata,
    package_for_extra_binary,
    resolve_installed_binary,
)

# System utilities allowed for execution without being in tools_config.json.
# These are standard Linux/macOS CLI tools commonly used in CTF and security work.
#
# EXCLUDED (dangerous / allows arbitrary code execution):
#   Destructive:  rm, rmdir, dd, mkfs, kill, pkill, killall, chmod, chown,
#                 chgrp, shutdown, reboot, halt, poweroff, fdisk, wipefs,
#                 shred, su, sudo, mount, umount, iptables, useradd,
#                 userdel, passwd, crontab
#   Interpreters: python3, python, perl, ruby, node, php, bash, sh, zsh
#                 (these allow arbitrary code execution via -c/-e flags)
#   Meta-exec:    timeout, xargs, parallel, find
#                 (these execute other commands as arguments, bypassing allowlist)
#   Shell escape: dc (its ! command runs a shell command, also from a program
#                 read on stdin, so no flag check can cover it)
SYSTEM_UTILITIES: frozenset[str] = frozenset(
    {
        # File analysis & forensics
        "file",
        "strings",
        "xxd",
        "hexdump",
        "od",
        "readelf",
        "objdump",
        "nm",
        "ldd",
        "strace",
        "ltrace",
        "binwalk",
        # Encoding & hashing
        "base64",
        "base32",
        "md5sum",
        "sha1sum",
        "sha256sum",
        "sha512sum",
        "shasum",
        "cksum",
        "openssl",
        # Text processing
        "grep",
        "egrep",
        "fgrep",
        "sed",
        "awk",
        "cut",
        "sort",
        "uniq",
        "wc",
        "head",
        "tail",
        "tr",
        "tee",
        "diff",
        "comm",
        "paste",
        "column",
        "rev",
        "fold",
        "expand",
        "unexpand",
        "fmt",
        "nl",
        # Search & find (note: find is excluded — it supports -exec/-delete)
        "locate",
        "which",
        "whereis",
        "type",
        # Network utilities
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        # socat — excluded (EXEC:/SYSTEM: address types allow arbitrary command execution)
        "dig",
        "host",
        "nslookup",
        "ping",
        "traceroute",
        "tracepath",
        "whois",
        "ss",
        "netstat",
        "ip",
        "ifconfig",
        "arp",
        # Archive & compression
        "tar",
        "gzip",
        "gunzip",
        "bzip2",
        "bunzip2",
        "xz",
        "unxz",
        "zip",
        "unzip",
        "7z",
        "zcat",
        "zgrep",
        "zless",
        # Image & media (CTF stego)
        "identify",
        "convert",
        "exiftool",
        "exiv2",
        "foremost",
        "steghide",
        "zsteg",
        "pngcheck",
        # Crypto
        "gpg",
        "age",
        "ssh-keygen",
        # Document & data
        "jq",
        "yq",
        "xmllint",
        "csvtool",
        "pdftotext",
        "pdfinfo",
        # QR & barcode
        "zbarimg",
        "qrencode",
        # System info (read-only)
        "uname",
        "hostname",
        "id",
        "whoami",
        "date",
        "uptime",
        "df",
        "du",
        "free",
        "locale",
        # File operations. Read-only ones (cat/ls/stat/...) are unconditionally
        # safe. The write-capable ones (cp/mv/ln/tee/touch/mkdir) are allowed but
        # check_policy() runs _is_sensitive_write_target() on their destination
        # so they cannot overwrite/symlink into dotfiles, shell-rc/login files,
        # cron, or system dirs (/etc, /usr, ...). Writes to /tmp/CWD stay allowed.
        "cat",
        "less",
        "more",
        "cp",
        "mv",
        "mkdir",
        "touch",
        "ln",
        "ls",
        "stat",
        "realpath",
        "basename",
        "dirname",
        "pwd",
        "tac",
        "shuf",
        # Misc CTF
        "bc",
        "expr",
        "printf",
        "echo",
    }
)

# Block only the command-substitution and pipe vectors (| ` $( ${); no shell is ever
# used (create_subprocess_exec), so ; & > < $ are harmless literals that tools legitimately
# need (URL query strings, regex anchors, awk fields, XML/comparisons) and pipes must go
# through run_pipeline.
_DANGEROUS_PATTERNS = re.compile(r"[|`]|\$[({]")

# Environment variables never passed to spawned tools/scripts: the server's own
# process may hold operator credentials, and an allowlisted tool that can read
# the environment (e.g. awk's ENVIRON) would otherwise disclose them. A denylist
# keeps PATH/HOME/LANG/proxy and other benign variables that tools rely on.
_SENSITIVE_ENV_RE = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|APIKEY|DSN"
    r"|CONNECTION[_-]?STRING"
    r"|(?:API|ACCESS|PRIVATE|SECRET|SESSION)[_-]?KEY"
    # Any variable named like a key or password under an arbitrary prefix
    # (OPENAI_KEY, FOO_KEY, DB_PASS, MYSQL_PWD, REDISCLI_AUTH) — a credential
    # regardless of the vendor. PWD and OLDPWD have no separator and are kept.
    r"|[_-](?:KEY|PASS|PWD|AUTH)$"
    r"|AUTH[_-]?KEY"
    r"|JWT|COOKIE|BEARER|CREDS|SIGNATURE"
    r"|^OP_(?:SESSION_|SERVICE_ACCOUNT)"
    r"|^(?:SSHPASS|BW_SESSION|SSH_AGENT_PID|GPG_AGENT_INFO)$)",
    re.IGNORECASE,
)
_SENSITIVE_ENV_PREFIX_RE = re.compile(
    r"^(AWS|AZURE|GCP|GOOGLE|GITHUB|GITLAB|STRIPE|SLACK|TWILIO|CLOUDFLARE"
    r"|DIGITALOCEAN|HEROKU|NPM|PYPI|DOCKER|TF_VAR"
    r"|OPENAI|ANTHROPIC|GEMINI|HF|HUGGINGFACE|OPENROUTER|COHERE|MISTRAL|GROQ|PERPLEXITY"
    r"|VAULT|SENTRY|DATADOG|SNYK|JIRA|SONAR)_",
    re.IGNORECASE,
)
# Credential-bearing values under a neutral name (DATABASE_URL, REDIS_URL, a DSN):
# a URL whose userinfo carries a password (scheme://user:pass@host). Matched on the
# value, not the name, so a URL without embedded credentials is still inherited.
_CREDENTIAL_URL_VALUE_RE = re.compile(r"://[^/\s:@]*:[^/\s@]+@")
# Proxy settings are kept even with credentials: tools cannot reach the network without them.
_PROXY_ENV_RE = re.compile(r"(?:HTTPS?|FTP|ALL|NO)_PROXY", re.IGNORECASE)


# The path of the operator's ssh-agent: a program that inherits it can log in anywhere
# their keys are accepted. Only the SSH transport to a configured remote host gets it.
_SSH_AGENT_ENV = "SSH_AUTH_SOCK"


def _tool_module(tool_name: str, tools_db: ToolsDatabase) -> str | None:
    """The module a registry tool belongs to; decides which credentials the host sandbox leaves it."""
    package = package_for_extra_binary(tool_name)
    return (tools_db.tools_by_name.get(tool_name) or tools_db.tools_by_name.get(package or "") or {}).get("module")


def _child_env(*, ssh_agent: bool = False) -> dict[str, str]:
    """A copy of the process environment with credential-shaped variables removed.

    Drops variables named like a credential and, name-agnostically, any whose
    value embeds URL userinfo credentials (e.g. ``DATABASE_URL=postgres://u:p@h``),
    except the standard proxy variables. The ssh-agent socket is passed on only
    with ``ssh_agent=True``.
    """
    return {
        key: value
        for key, value in os.environ.items()
        if not _SENSITIVE_ENV_RE.search(key)
        and not _SENSITIVE_ENV_PREFIX_RE.match(key)
        and (ssh_agent or key != _SSH_AGENT_ENV)
        and (_PROXY_ENV_RE.fullmatch(key) or not _CREDENTIAL_URL_VALUE_RE.search(value))
    }


# Execution policy — restrict *what* tools can do, not just *which* tools run

# Flag patterns that are destructive or dangerous in most security tools.
# Each entry is (compiled regex, human-readable description).
BLOCKED_FLAGS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^--delete$"), "destructive flag --delete"),
    (re.compile(r"^-rf$"), "destructive flag -rf"),
    (re.compile(r"^--force-?delete"), "destructive flag --force-delete"),
    (re.compile(r"^--remove-all$"), "destructive flag --remove-all"),
    (re.compile(r"^--exploit$"), "active exploitation flag --exploit"),
]

# nc/ncat/netcat -e/--exec/--sh-exec/--lua-exec (and -c on traditional nc) spawn
# an arbitrary program connected to the socket — the exact bind/reverse-shell
# primitive socat/bash/sh/python are deliberately excluded for. Best-effort
# denylist: anchored short-flag forms cover both separated (-e /bin/sh) and the
# command-bearing long flags (--exec=...). A benign "nc -zv host 80" still passes.
_NC_BLOCKED_FLAGS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^-e$"), "nc: -e exec program (arbitrary command execution)"),
    (re.compile(r"^-c$"), "nc: -c shell command (arbitrary command execution)"),
    (re.compile(r"^--exec(?:$|=)"), "nc: --exec program (arbitrary command execution)"),
    (re.compile(r"^--sh-exec(?:$|=)"), "nc: --sh-exec shell command (arbitrary command execution)"),
    (re.compile(r"^--lua-exec(?:$|=)"), "nc: --lua-exec script (arbitrary command execution)"),
]

# awk/gawk: the inline system()/pipe-to-getline patterns are blocked, but the
# same RCE is reachable through an uninspected *program file* or extension load.
# -f/--file run a script file, --source runs inline program text, and
# --load/-l/@load dlopen an arbitrary gawk extension (.so) = command execution.
# Block them so the inline-only checks can't be bypassed.
_AWK_BLOCKED_FLAGS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"system\s*\(", re.IGNORECASE), "awk: system() command execution"),
    (re.compile(r"\|\s*getline", re.IGNORECASE), "awk: pipe to getline"),
    (re.compile(r"\|&?\s*[\"']", re.IGNORECASE), 'awk: pipe/coprocess to command (print | "cmd")'),
    (re.compile(r"^-f"), "awk: -f program file (uninspected script execution)"),
    (re.compile(r"^--file(?:$|=)"), "awk: --file program file (uninspected script execution)"),
    (re.compile(r"^--source(?:$|=)"), "awk: --source inline program (uninspected script execution)"),
    (re.compile(r"^-e"), "awk: -e inline program (uninspected script execution)"),
    (re.compile(r"^-E"), "awk: -E program file (uninspected script execution)"),
    (re.compile(r"^--exec(?:$|=)"), "awk: --exec program file (uninspected script execution)"),
    (re.compile(r"^-i"), "awk: -i include file (uninspected script execution)"),
    (re.compile(r"^--include(?:$|=)"), "awk: --include file (uninspected script execution)"),
    (re.compile(r"^--load(?:$|=)"), "awk: --load extension (command execution)"),
    (re.compile(r"^-l$"), "awk: -l load extension (command execution)"),
    (re.compile(r"(?:^|[\s;])@load\b"), "awk: @load extension directive (command execution)"),
    (re.compile(r"(?:^|[\s;{}])@(?:ns)?include\b"), "awk: @include directive (uninspected script execution)"),
    (re.compile(r"/inet[46]?/(?:tcp|udp|raw)/"), "awk: gawk network special file (outbound connection)"),
]

# radare2/r2 share a command interface with shell-escape (`!`), pipe (`#!`) and
# source (`. file`) syntax, plus -i/-I to run a script file. Best-effort denylist.
_R2_BLOCKED_FLAGS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^-i$"), "radare2: -i run script file"),
    (re.compile(r"^-I$"), "radare2: -I run startup script file"),
    (re.compile(r"(?:^|[\s;])!"), "radare2: ! shell escape"),
    (re.compile(r"#!"), "radare2: #! pipe/lang execution"),
    (re.compile(r"(?:^|[\s;])\.\s"), "radare2: . source/interpret command"),
]


def _masscan_option(name: str) -> re.Pattern[str]:
    sep = "[-._]*"
    return re.compile(r"^--" + sep + sep.join(name) + r"(?:$|=)", re.IGNORECASE)


# Tool-specific blocked flags — dangerous per-tool options.

TOOL_BLOCKED_FLAGS: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "sqlmap": [
        (re.compile(r"^--os-shell(?:$|=)"), "sqlmap: OS shell access"),
        (re.compile(r"^--os-cmd(?:$|=)"), "sqlmap: OS command execution"),
        (re.compile(r"^--os-pwn(?:$|=)"), "sqlmap: OOB exploitation"),
        (re.compile(r"^--priv-esc(?:$|=)"), "sqlmap: privilege escalation"),
        (re.compile(r"^--file-read(?:$|=)"), "sqlmap: arbitrary file read"),
        (re.compile(r"^--file-write(?:$|=)"), "sqlmap: arbitrary file write"),
        (re.compile(r"^--file-dest(?:$|=)"), "sqlmap: file write destination"),
        (re.compile(r"^--udf-inject(?:$|=)"), "sqlmap: user-defined function injection"),
        (re.compile(r"^--shared-lib(?:$|=)"), "sqlmap: shared library injection"),
        # These run Python or a host command chosen by the caller.
        (re.compile(r"^--eval(?:$|=)"), "sqlmap: --eval Python code execution"),
        (re.compile(r"^--tamper(?:$|=)"), "sqlmap: --tamper script (uninspected script execution)"),
        (re.compile(r"^--preprocess(?:$|=)"), "sqlmap: --preprocess script (uninspected script execution)"),
        (re.compile(r"^--postprocess(?:$|=)"), "sqlmap: --postprocess script (uninspected script execution)"),
        (re.compile(r"^--alert(?:$|=)"), "sqlmap: --alert host command execution"),
        # A config file can set every option above; the rest name targets or proxies
        # in a file or search result, where target validation cannot see them.
        (re.compile(r"^-c"), "sqlmap: -c config file (bypasses flag and target validation)"),
        (re.compile(r"^-m"), "sqlmap: -m target list from file (bypasses target validation)"),
        (re.compile(r"^-r"), "sqlmap: -r request file (bypasses target validation); use -u with --data"),
        (re.compile(r"^-l"), "sqlmap: -l targets from a proxy log (bypasses target validation)"),
        (re.compile(r"^-g"), "sqlmap: -g targets from a search dork (bypasses target validation)"),
        (re.compile(r"^--second-req(?:$|=)"), "sqlmap: --second-req request file (bypasses target validation)"),
        (re.compile(r"^--proxy-file(?:$|=)"), "sqlmap: --proxy-file proxy list (bypasses target validation)"),
    ],
    "sed": [
        (re.compile(r"^-i"), "sed: in-place file modification"),
        (re.compile(r"^--in-place"), "sed: in-place file modification"),
        (re.compile(r"^--file(?:$|=)"), "sed: --file script file (uninspected e/r/w commands)"),
        # GNU sed's e/r/w script commands run a shell command or read/write files.
        # Match them at a command position: start, or after ; { } newline, a
        # regex-address close (/), or an address char (digit $ , ~ + !). Prefer
        # --sandbox at the argv level for exotic forms; this closes the reachable
        # e/r/w vectors.
        (re.compile(r"(?:^|[;{}\n/0-9$,~+!])\s*e(?:\s|$)"), "sed: e command (command execution)"),
        (re.compile(r"(?:^|[;{}\n/0-9$,~+!])\s*[wWrR](?:\s|$)"), "sed: r/w file command"),
        (re.compile(r"(?:[^a-zA-Z0-9]|^)s(.).*\1.*\1[a-z0-9]*e"), "sed: s///e execute flag"),
    ],
    "nmap": [
        (re.compile(r"^-iL"), "nmap: target list from file (bypasses target validation)"),
        (re.compile(r"^-iR"), "nmap: random target generation (bypasses target validation)"),
        # --script / --script-args load arbitrary NSE (Lua with os.execute) = RCE.
        (re.compile(r"^--script"), "nmap: NSE script execution (--script*)"),
        (re.compile(r"^--resume(?:$|=)"), "nmap: resume from a log file (bypasses target validation)"),
        # A data directory supplies the NSE scripts that -sC/-A run.
        (re.compile(r"^--datadir(?:$|=)"), "nmap: --datadir supplies NSE scripts (command execution)"),
        (re.compile(r"^--servicedb(?:$|=)"), "nmap: --servicedb alternate data file"),
        (re.compile(r"^--versiondb(?:$|=)"), "nmap: --versiondb alternate data file"),
    ],
    "masscan": [
        # masscan ignores case and any '-', '.', '_' inside a long option name.
        (_masscan_option("includefile"), "masscan: target list from file"),
        (re.compile(r"^-iL"), "masscan: -iL target list from file"),
        (_masscan_option("conf"), "masscan: --conf config file (bypasses target validation)"),
        (re.compile(r"^-c"), "masscan: -c config file (bypasses target validation)"),
        (_masscan_option("resume"), "masscan: --resume from a state file (bypasses target validation)"),
    ],
    "binwalk": [
        (re.compile(r"^-D"), "binwalk: -D runs a command on each extracted file"),
        (re.compile(r"^--dd(?:$|=)"), "binwalk: --dd runs a command on each extracted file"),
        (re.compile(r"^--run-as(?:$|=)"), "binwalk: --run-as changes the extractor user"),
    ],
    "awk": _AWK_BLOCKED_FLAGS,
    "gawk": _AWK_BLOCKED_FLAGS,
    "sort": [
        # sort pipes its temporary files through the named program.
        (re.compile(r"^--compress-program(?:$|=)"), "sort: external compressor (command execution)"),
    ],
    "tar": [
        (re.compile(r"^--checkpoint-action"), "tar: checkpoint-action command execution"),
        (re.compile(r"^--to-command"), "tar: to-command command execution"),
        # -I / --use-compress-program run an arbitrary program as the (de)compressor.
        (re.compile(r"^-I$"), "tar: -I external compressor (command execution)"),
        (re.compile(r"^--use-compress-program(?:$|=)"), "tar: external compressor (command execution)"),
        (re.compile(r"^--info-script(?:$|=)"), "tar: --info-script volume-change command (command execution)"),
        (
            re.compile(r"^--new-volume-script(?:$|=)"),
            "tar: --new-volume-script volume-change command (command execution)",
        ),
        (re.compile(r"^--rmt-command(?:$|=)"), "tar: --rmt-command (command execution)"),
        (re.compile(r"^--rsh-command(?:$|=)"), "tar: --rsh-command (command execution)"),
    ],
    # Debuggers / disassemblers with interactive command interfaces can shell
    # out or run inline interpreters — treat their command-bearing flags and
    # known shell-escape syntax as RCE. Best-effort denylist (use run_script for
    # advanced debugging); covers the obvious vectors.
    "gdb": [
        (re.compile(r"^-x$"), "gdb: -x command file execution"),
        (re.compile(r"^--command(?:$|=)"), "gdb: command file execution"),
        (re.compile(r"^--init-command(?:$|=)"), "gdb: init command file"),
        (re.compile(r"^--init-eval-command(?:$|=)"), "gdb: init eval command"),
        (re.compile(r"^-ix$"), "gdb: init command file"),
        (re.compile(r"(?:^|[\s'\"(])shell\b", re.IGNORECASE), "gdb: shell command execution"),
        (re.compile(r"(?:^|[\s'\"(])(?:python|py|pi)\b", re.IGNORECASE), "gdb: python/pipe execution"),
        (re.compile(r"system\s*\("), "gdb: call system()"),
        (re.compile(r"(?:^|[\s'\"(])!"), "gdb: shell escape"),
        # Launching the inferior (vs. static inspection) is an allowlist bypass: the
        # run/start commands and --args let gdb execute an arbitrary program. Static
        # analysis (-ex 'info functions' /bin/ls) does not need these and still passes.
        (re.compile(r"^--args$"), "gdb: --args launches an inferior program"),
    ],
    "tshark": [
        (re.compile(r"^-X$"), "tshark: -X extension (lua_script: command execution)"),
        (re.compile(r"lua_script:", re.IGNORECASE), "tshark: lua_script extension (command execution)"),
    ],
    "tcpdump": [
        (re.compile(r"^-z$"), "tcpdump: -z postrotate command execution"),
        (re.compile(r"^--postrotate-command(?:$|=)"), "tcpdump: postrotate command execution"),
    ],
    "radare2": _R2_BLOCKED_FLAGS,
    "r2": _R2_BLOCKED_FLAGS,
    "gpg": [
        (re.compile(r"^--recv-keys?$"), "gpg: key import from external keyserver"),
        (re.compile(r"^--keyserver$"), "gpg: external keyserver specification"),
        (re.compile(r"^--fetch-keys?$"), "gpg: key fetch from URL"),
    ],
    "socat": [
        (re.compile(r"EXEC[12]?\s*:", re.IGNORECASE), "socat: EXEC address (arbitrary command execution)"),
        (re.compile(r"SYSTEM\s*:", re.IGNORECASE), "socat: SYSTEM address (arbitrary command execution)"),
    ],
    "nc": _NC_BLOCKED_FLAGS,
    "ncat": _NC_BLOCKED_FLAGS,
    "netcat": _NC_BLOCKED_FLAGS,
    # curl/wget use getopt-style short flags, so the file argument can be attached
    # (-Kcfg.txt), separated (-K cfg.txt) or =-joined (-K=cfg.txt). Match the flag as
    # a prefix so all three single-token forms are blocked (these are single-letter
    # short flags with no same-prefix siblings, so prefix matching is safe).
    "curl": [
        (re.compile(r"^-K"), "curl: config file flag bypasses target validation"),
        (re.compile(r"^--config(?:$|=)"), "curl: config file flag bypasses target validation"),
        # -T/--upload-file sends an arbitrary host file to the URL (file read → exfil).
        (re.compile(r"^-T"), "curl: -T uploads an arbitrary host file"),
        (re.compile(r"^--upload-file(?:$|=)"), "curl: --upload-file reads an arbitrary host file"),
    ],
    "wget": [
        (re.compile(r"^-i"), "wget: URL list from file bypasses target validation"),
        (re.compile(r"^--input-file(?:$|=)"), "wget: URL list from file bypasses target validation"),
        (re.compile(r"^--use-askpass(?:$|=)"), "wget: --use-askpass runs an external command"),
        (re.compile(r"^--post-file(?:$|=)"), "wget: --post-file sends an arbitrary host file"),
        (re.compile(r"^--body-file(?:$|=)"), "wget: --body-file sends an arbitrary host file"),
        (re.compile(r"^--load-cookies(?:$|=)"), "wget: --load-cookies reads an arbitrary host file"),
    ],
    # zip/exiftool/openssl are allowlisted for legitimate archive/metadata/crypto
    # use, but each has an option that shells out or evaluates code — block those.
    "zip": [
        # -TT inside an option group (-qTTcmd, -X-TTcmd) is found by _check_zip_policy.
        (re.compile(r"^-TT"), "zip: -TT unzip test command (command execution)"),
        (re.compile(r"^--unzip-command(?:$|=)"), "zip: --unzip-command (command execution)"),
    ],
    "exiftool": [
        (re.compile(r"^-if\d*$"), "exiftool: -if evaluates a Perl expression"),
        (re.compile(r"^-p$"), "exiftool: -p print-format can evaluate expressions"),
        (re.compile(r"^-api$"), "exiftool: -api can set Perl-evaluated options"),
        (re.compile(r"^-@$"), "exiftool: -@ argfile bypasses argument validation"),
        (re.compile(r"^-geotag$"), "exiftool: -geotag can run external helpers"),
    ],
    "openssl": [
        # openssl reads options with one or two dashes and with "=value" attached.
        (re.compile(r"^(?:engine|fipsinstall)$"), "openssl: engine and fipsinstall load an arbitrary shared object"),
        (re.compile(r"^--?engine(?:_impl)?(?:=|$)"), "openssl: -engine loads an arbitrary shared object"),
        (re.compile(r"^--?provider(?:-path)?(?:=|$)"), "openssl: -provider loads an arbitrary shared object"),
        (re.compile(r"^--?module(?:=|$)"), "openssl: -module loads an arbitrary shared object"),
        (
            re.compile(r"^--?conf(?:ig)?(?:=|$)"),
            "openssl: -config loads an arbitrary configuration (engines, providers)",
        ),
    ],
    "ssh-keygen": [
        (re.compile(r"^-[A-Za-z]*[DwK]"), "ssh-keygen: -D/-w/-K load a PKCS#11 or FIDO provider library"),
    ],
    # ProjectDiscovery and similar recon/scan tools read targets from a file via
    # list flags, which would defeat the private/loopback target allowlist the
    # same way nmap -iL / wget -i do. Block the file-list flags defensively,
    # including attached short-flag forms; exact CLI parsing differs by version,
    # and the policy layer must fail closed.
    "nuclei": [
        (re.compile(r"^--?l"), "nuclei: target list from file bypasses target validation"),
        (re.compile(r"^--?list(?:$|=)"), "nuclei: target list from file bypasses target validation"),
        (re.compile(r"^--?(?:config|cfg)(?:$|=)"), "nuclei: config file bypasses flag and target validation"),
        (re.compile(r"^--?code$"), "nuclei: -code enables code templates (command execution)"),
        (re.compile(r"^--?sign$"), "nuclei: -sign signs local templates"),
        (re.compile(r"^--?headless$"), "nuclei: -headless launches a browser"),
        (
            re.compile(r"^--?(?:ut|up|update|update-templates|update-template-dir|tu)(?:$|=)"),
            "nuclei: update flags contact external services",
        ),
        (re.compile(r"^--?w(?:orkflows)?(?:$|=)"), "nuclei: workflow files are not validated"),
    ],
    "httpx": [
        (re.compile(r"^--?l(?!ocation(?:$|=))"), "httpx: target list from file bypasses target validation"),
        (re.compile(r"^--?list(?:$|=)"), "httpx: target list from file bypasses target validation"),
        (re.compile(r"^--?rr(?:$|=)"), "httpx: request file bypasses target validation"),
        (re.compile(r"^--?config(?:$|=)"), "httpx: config file bypasses target validation"),
    ],
    "nikto": [
        (re.compile(r"^-config(?:$|=)"), "nikto: config file bypasses target validation"),
    ],
    "hydra": [
        (re.compile(r"^-M$"), "hydra: target list from file bypasses target validation"),
    ],
    "fping": [
        (re.compile(r"^-f$"), "fping: target list from file bypasses target validation"),
    ],
    "naabu": [
        (re.compile(r"^--?l(?:ist)?(?:$|=)"), "naabu: target list from file bypasses target validation"),
    ],
    "dnsx": [
        (re.compile(r"^--?l(?:ist)?(?:$|=)"), "dnsx: target list from file bypasses target validation"),
    ],
    "katana": [
        (re.compile(r"^--?list(?:$|=)"), "katana: target list from file bypasses target validation"),
    ],
    "shuffledns": [
        (re.compile(r"^--?l(?:ist)?(?:$|=)"), "shuffledns: subdomain list from file bypasses target validation"),
    ],
    "tlsx": [
        (re.compile(r"^--?l(?:ist)?(?:$|=)"), "tlsx: target list from file bypasses target validation"),
    ],
    "sslscan": [
        (re.compile(r"^--targets(?:$|=)"), "sslscan: target list from file bypasses target validation"),
    ],
    "testssl.sh": [
        (re.compile(r"^--file(?:$|=)"), "testssl.sh: target list from file bypasses target validation"),
    ],
    "dirsearch": [
        (re.compile(r"^-l$"), "dirsearch: URL list from file bypasses target validation"),
        (re.compile(r"^--urls-file(?:$|=)"), "dirsearch: URL list from file bypasses target validation"),
    ],
    "gospider": [
        (re.compile(r"^-S$"), "gospider: site list from file bypasses target validation"),
    ],
    "ffuf": [
        (re.compile(r"^--?request$"), "ffuf: request file bypasses target validation"),
        (re.compile(r"^--?config$"), "ffuf: config file bypasses target validation"),
    ],
    "feroxbuster": [
        (re.compile(r"^--config(?:$|=)"), "feroxbuster: config file bypasses target validation"),
        (re.compile(r"^--resume-from(?:$|=)"), "feroxbuster: resume state file bypasses target validation"),
        (re.compile(r"^--stdin$"), "feroxbuster: target list from stdin bypasses target validation"),
    ],
    "subfinder": [
        (re.compile(r"^--?dL"), "subfinder: domain list from file bypasses target validation"),
        (re.compile(r"^--?list(?:$|=)"), "subfinder: domain list from file bypasses target validation"),
    ],
    "amass": [
        (re.compile(r"^-df"), "amass: domain list from file bypasses target validation"),
    ],
    # arjun (argparse) and whatweb (Ruby OptionParser) accept attached short-flag
    # values (-iurls.txt) as well, so prefix-match the single-letter -i flag.
    "arjun": [
        (re.compile(r"^-i"), "arjun: URL list from file bypasses target validation"),
        (re.compile(r"^--input(?:$|=)"), "arjun: URL list from file bypasses target validation"),
        (re.compile(r"^--urls(?:$|=)"), "arjun: URL list from file bypasses target validation"),
    ],
    "wafw00f": [
        (re.compile(r"^-i"), "wafw00f: target list from file bypasses target validation"),
        (re.compile(r"^--input-file(?:$|=)"), "wafw00f: target list from file bypasses target validation"),
    ],
    "whatweb": [
        (re.compile(r"^-i"), "whatweb: target list from file bypasses target validation"),
        (re.compile(r"^--input-file(?:$|=)"), "whatweb: target list from file bypasses target validation"),
    ],
}

# Parsers that resolve an unambiguous prefix of a long option to the full option
# (GNU getopt_long, Python argparse/optparse, Ruby OptionParser). For these a
# blocked long flag can be reached by an abbreviation, so the denylist above,
# which anchors the full spelling, must also reject prefixes of it.
_ABBREV_TOOLS = frozenset(
    {
        "sed",
        "tar",
        "gdb",
        "wget",
        "zip",
        "arjun",
        "whatweb",
        "wafw00f",
        "sqlmap",
        "awk",
        "gawk",
        "nmap",
        "sort",
        "nc",
        "ncat",
        "netcat",
        "binwalk",
        "curl",
    }
)

# Abbreviations that collide with a distinct, safe real option of the same tool.
# getopt_long resolves an exact match before a prefix, so the tool reads these as
# the safe option, not the blocked one; blocking them would be a false positive.
_ABBREV_SAFE: dict[str, frozenset[str]] = {
    "tar": frozenset({"checkpoint"}),
    "sqlmap": frozenset({"proxy"}),
    "nmap": frozenset({"version", "data"}),
}

_LONG_OPT_NAME_RE = re.compile(r"^\^--([a-z0-9][a-z0-9-]*)")
_LONG_OPT_ARG_RE = re.compile(r"^--([a-z0-9][a-z0-9-]*)(?:=|$)", re.IGNORECASE)


def _blocked_long_options(patterns: list[tuple[re.Pattern[str], str]]) -> list[tuple[str, str]]:
    """Canonical ``--name`` spellings a pattern list blocks, for abbreviation checks."""
    out: list[tuple[str, str]] = []
    for pattern, desc in patterns:
        match = _LONG_OPT_NAME_RE.match(pattern.pattern)
        if match:
            out.append((match.group(1), desc))
    return out


# Derived once from the compiled patterns so it cannot drift from TOOL_BLOCKED_FLAGS.
_ABBREV_BLOCKED: dict[str, list[tuple[str, str]]] = {
    tool: _blocked_long_options(TOOL_BLOCKED_FLAGS[tool]) for tool in _ABBREV_TOOLS if tool in TOOL_BLOCKED_FLAGS
}
# getopt_long resolves any unambiguous prefix, down to a single character (sed --i
# is --in-place, gawk --e is --exec). A prefix that is ambiguous among the tool's own
# options makes the tool error out, so blocking it is harmless; only an exact
# safe option (_ABBREV_SAFE) is a real false positive.
_ABBREV_MIN_LEN = 1


def _check_long_option_abbreviations(tool_name: str, binary: str, arg_list: list[str]) -> None:
    """Reject an abbreviated long flag that resolves to a blocked one.

    Only for parsers in ``_ABBREV_TOOLS``; the exact spelling is already caught by
    ``TOOL_BLOCKED_FLAGS``. A prefix that is also a distinct safe option
    (``_ABBREV_SAFE``) is left alone.
    """
    blocked: list[tuple[str, str]] = []
    safe: set[str] = set()
    for key in (tool_name, binary):
        blocked += _ABBREV_BLOCKED.get(key, [])
        safe |= _ABBREV_SAFE.get(key, frozenset())
    if not blocked:
        return
    for arg in arg_list:
        match = _LONG_OPT_ARG_RE.match(arg)
        if not match:
            continue
        name = match.group(1).lower()
        if len(name) < _ABBREV_MIN_LEN or name in safe:
            continue
        for canonical, desc in blocked:
            if name != canonical and canonical.startswith(name):
                raise ValueError(f"Blocked by policy: {desc} (via abbreviation --{name})")


# A URL in any scheme (http, ftp, gopher, sftp, ...), matched case-insensitively by the class.
_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")

# Flags whose values look like a network target to the heuristic but are
# actually something else for specific tools (e.g. curl's ``-u user:pass``
# is HTTP Basic auth, not a target). When one of these is present for its
# owning tool, the flag+value pair is skipped during target validation.
#
# Keep this list to flags whose values are *not* connection destinations
# (headers, credentials, methods, wordlists, output files, template paths).
# Do not add proxy/resolver/connect-to flags here: those can redirect real
# network traffic and must still pass target validation.
_TARGET_FLAG_EXEMPTIONS: dict[str, set[str]] = {
    "curl": {
        "-u",
        "--user",
        "-H",
        "--header",
        "-A",
        "--user-agent",
        "-b",
        "--cookie",
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "--json",
        "-X",
        "--request",
        "-o",
        "--output",
        "-w",
        "--write-out",
    },
    "wget": {
        "--header",
        "--user-agent",
        "--post-data",
        "--post-file",
        "-O",
        "--output-document",
        "-P",
        "--directory-prefix",
    },
    "ffuf": {
        "-w",
        "-H",
        "-X",
        "-d",
        "-b",
        "-o",
        "-of",
        "-e",
        "-mode",
        "-mc",
        "-fc",
        "-ms",
        "-fs",
        "-mw",
        "-fw",
        "-ml",
        "-fl",
        "-mr",
        "-fr",
        "-p",
        "-rate",
        "-recursion-depth",
    },
    "wpscan": {"-e", "--enumerate", "-t", "--threads"},
    "dig": {"-t", "-c"},
    "host": {"-t", "-c"},
    "nikto": {"-Tuning", "-Format", "-evasion"},
    "openssl": {
        "-starttls",
        "-alpn",
        "-proto",
        "-cipher",
        "-ciphersuites",
        "-groups",
        "-curves",
        "-named_curve",
        "-sigalgs",
        "-client_sigalgs",
        "-servername",
    },
    "tshark": {
        "-r",
        "-Y",
        "-R",
        "-T",
        "-e",
        "-E",
        "-z",
        "-f",
        "-i",
        "-w",
        "-o",
        "-d",
        "-O",
        "-J",
        "-N",
        "-s",
        "-c",
        "-a",
        "-b",
    },
    "tcpdump": {"-i", "-r", "-w", "-c", "-s", "-F", "-C", "-G", "-W", "-z"},
    "feroxbuster": {"-w", "-H", "-A", "-b", "-x", "-o", "--output"},
    "gobuster": {"-w", "-H", "-U", "-P", "-x", "-o", "--output"},
    "hydra": {"-l", "-L", "-p", "-P", "-s", "-t", "-o", "-x", "-e"},
    "patator": {"-x", "-l", "-p", "-L", "-P", "-o", "--output"},
    "httpx": {"-H", "-header", "-headers", "-path", "-body", "-method", "-o", "-json"},
    "nuclei": {"-H", "-header", "-t", "-templates", "-tags", "-severity", "-o", "-json-export", "-markdown-export"},
    "sqlmap": {
        "-p",
        "--headers",
        "--cookie",
        "--data",
        "--user-agent",
        "--method",
        "--risk",
        "--level",
        "-o",
        "-D",
        "-T",
        "-C",
        "--dbms",
        "--technique",
    },
    "netexec": {"-u", "-p", "-H", "-d", "--log", "--jitter"},
    "impacket": {"-hashes", "-outputfile", "-resumefile", "-just-dc-user"},
    "certipy-ad": {"-u", "-p", "-hashes", "-username", "-password", "-out", "-scheme"},
    "bloodhound": {"-u", "-p", "-c", "--collectionmethod", "--hashes"},
    "ldapsearchad": {"-u", "-p", "--username", "--password", "--output"},
    "evil-winrm": {"-u", "-p", "-H", "-r", "-s", "-e"},
    "nmap": {"-oA", "-oN", "-oX", "-oG", "--top-ports", "--max-retries", "-p", "-T", "-e"},
    "masscan": {"-p", "-oL", "-oJ", "-oX", "-oG", "--rate", "--max-rate"},
}

# Exempt flag values that may still trigger outbound fetches when they are URLs.
# They are not the scan target, but default-safe MCP mode also promises no
# unexpected external network access. Validate URL values for these flags before
# skipping normal target parsing.
_REMOTE_RESOURCE_FLAGS: dict[str, set[str]] = {
    "ffuf": {"-w"},
    "feroxbuster": {"-w"},
    "gobuster": {"-w"},
    "nuclei": {"-t", "-templates"},
    "tshark": {"-i"},
    "tcpdump": {"-i"},
}

# Remote-capture interface forms that make the capture tool connect out.
_REMOTE_CAPTURE_IFACE_RE = re.compile(r"^(?:(?:rpcaps?|ssh)://|(?:tcp|udp)@)", re.IGNORECASE)

# Positional words that are command modes/protocol names, not host targets. Keep
# this narrow: arbitrary single-label hostnames must still be validated/blocked
# in default-safe mode.
# dig reads a bare record type or class after the name (``dig example.org MX``) as such, not as a host.
_DNS_RECORD_WORDS: set[str] = {
    "a",
    "aaaa",
    "any",
    "axfr",
    "caa",
    "cname",
    "ds",
    "dnskey",
    "hinfo",
    "ixfr",
    "mx",
    "naptr",
    "ns",
    "nsec",
    "ptr",
    "rrsig",
    "soa",
    "spf",
    "srv",
    "sshfp",
    "tlsa",
    "txt",
    "in",
    "ch",
    "hs",
}

_NON_TARGET_POSITIONALS: dict[str, set[str]] = {
    "netexec": {"smb", "ldap", "ssh", "winrm", "wmi", "rdp", "vnc", "nfs", "ftp", "mssql"},
    "certipy-ad": {"find", "req", "auth", "shadow", "account", "template", "ca", "relay", "cert"},
    "dig": _DNS_RECORD_WORDS,
    "gobuster": {"dir", "dns", "vhost", "s3", "gcs", "fuzz", "tftp"},
    "amass": {"enum", "intel", "viz", "track", "db"},
    "dalfox": {"url", "file", "pipe", "server", "payload", "sxss"},
    # Capture-filter keywords of a live capture; an address after one is still validated.
    "tcpdump": {
        "tcp",
        "udp",
        "icmp",
        "icmp6",
        "ip",
        "ip6",
        "arp",
        "rarp",
        "ether",
        "vlan",
        "port",
        "portrange",
        "host",
        "net",
        "src",
        "dst",
        "and",
        "or",
        "not",
        "less",
        "greater",
    },
    "hydra": {
        "ftp",
        "ftps",
        "ssh",
        "ssh2",
        "telnet",
        "smtp",
        "smtps",
        "pop3",
        "pop3s",
        "imap",
        "imaps",
        "ldap2",
        "ldap3",
        "smb",
        "rdp",
        "vnc",
        "mysql",
        "postgres",
        "mssql",
        "redis",
        "mongodb",
        "http-get",
        "http-post",
        "http-head",
        "http-get-form",
        "http-post-form",
    },
}


def _exempt_flag_value(
    tool_name: str,
    binary: str,
    arg: str,
    next_arg: str | None,
) -> tuple[bool, int, str | None, str | None]:
    """Return exemption match details for a flag and optional value.

    The integer is how many argv tokens to consume. The value is populated for
    separated (``-w words.txt``), equals-joined (``--templates=http://...``), and
    attached short forms (``-whttp://...``).
    """
    exempt = _TARGET_FLAG_EXEMPTIONS.get(tool_name, set()) | _TARGET_FLAG_EXEMPTIONS.get(binary, set())
    if arg in exempt:
        if next_arg is not None and not next_arg.startswith("-"):
            return True, 2, arg, next_arg
        return True, 1, arg, None
    if "=" in arg:
        flag, value = arg.split("=", 1)
        if flag in exempt:
            return True, 1, flag, value
        # An '=' means the flag is exactly the pre-'=' token (handled above). Do
        # NOT fall through to attached-short prefix matching, or a longer flag like
        # goflags' -target= would be mis-split as the exempt short flag -t with value
        # "arget=http://…", laundering the URL past _validate_exempt_remote_resource.
        return False, 0, None, None
    for flag in sorted(exempt, key=len, reverse=True):
        if flag.startswith("--") or len(flag) != 2:
            continue
        if arg.startswith(flag) and len(arg) > len(flag):
            value = arg[len(flag) :]
            return True, 1, flag, value
    return False, 0, None, None


def _validate_exempt_remote_resource(tool_name: str, binary: str, flag: str | None, value: str | None) -> None:
    """Validate URL-like values for exempt flags that may fetch remote resources."""
    if not flag or not value:
        return
    remote_flags = _REMOTE_RESOURCE_FLAGS.get(tool_name, set()) | _REMOTE_RESOURCE_FLAGS.get(binary, set())
    if flag not in remote_flags:
        return
    if flag == "-i" and _REMOTE_CAPTURE_IFACE_RE.match(value):
        as_url = value if _URL_SCHEME_RE.match(value) else value.replace("@", "://", 1)
        if not _is_safe_target(_network_target_host(as_url)):
            raise ValueError(
                f"Blocked by policy: remote capture interface '{value}' for {tool_name} is not in a "
                "private/local range. Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 for authorized external captures."
            )
        return
    if _URL_SCHEME_RE.match(value) and not _is_safe_target(_network_target_host(value)):
        raise ValueError(
            f"Blocked by policy: remote resource '{value}' for {tool_name} {flag} is not in a private/local range. "
            "Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 for authorized external resource URLs."
        )


_OPENSSL_NETWORK_COMMANDS = frozenset({"s_client", "s_server", "s_time", "ocsp", "cmp"})
# Commands that work on local files only. openssl resolves a command by its hash and first eight
# characters, so a name that is not listed exactly gets the network command's full target check.
_OPENSSL_OFFLINE_COMMANDS = frozenset(
    {
        "asn1parse",
        "base64",
        "ciphers",
        "cms",
        "crl",
        "crl2pkcs7",
        "dgst",
        "dhparam",
        "dsa",
        "dsaparam",
        "ec",
        "ecparam",
        "enc",
        "errstr",
        "gendsa",
        "genpkey",
        "genrsa",
        "help",
        "info",
        "kdf",
        "list",
        "mac",
        "nseq",
        "passwd",
        "pkcs7",
        "pkcs8",
        "pkcs12",
        "pkey",
        "pkeyparam",
        "pkeyutl",
        "prime",
        "rand",
        "req",
        "rsa",
        "rsautl",
        "sess_id",
        "skeyutl",
        "smime",
        "speed",
        "spkac",
        "verify",
        "version",
        "x509",
    }
)
# Where each URL inside a value starts; every occurrence is checked, also one nested in a list.
_URL_START_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
# openssl also accepts a digest or cipher name as its command (`openssl sha256 f`, `openssl aes-256-cbc -d`).
_OPENSSL_ALGORITHM_COMMAND_RE = re.compile(
    r"md[45]|mdc2|rmd160|sm3|sha(?:1|224|256|384|512(?:-224|-256)?)|sha3-(?:224|256|384|512)|shake(?:128|256)"
    r"|blake2[bs](?:256|512)|(?:aes|aria|camellia)-(?:128|192|256)-[a-z0-9]+|des(?:3|-[a-z0-9-]+)?"
    r"|(?:bf|cast5?|rc2|rc4|seed|sm4|idea)(?:-[a-z0-9]+)?"
)


def _is_non_target_positional(tool_name: str, binary: str, arg: str) -> bool:
    """Return True for known positional mode/protocol tokens."""
    lowered = arg.lower()
    if {tool_name.casefold(), binary.casefold()} & {"jwt_tool"} and re.fullmatch(
        r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", arg
    ):
        return True
    return lowered in (_NON_TARGET_POSITIONALS.get(tool_name, set()) | _NON_TARGET_POSITIONALS.get(binary, set()))


# Tools that perform network operations and need target validation.
_NETWORK_TOOLS: set[str] = {
    "azurehound",
    "gosecretsdump",
    "GoExec",
    "GoMapEnum",
    "rusthound",
    "rusthound-ce",
    "nmap",
    "masscan",
    "sqlmap",
    "ffuf",
    "feroxbuster",
    "gobuster",
    "nikto",
    "nuclei",
    "httpx",
    "whatweb",
    "hydra",
    "patator",
    "Responder",
    "bettercap",
    "mitmproxy",
    "reaver",
    "aircrack-ng",
    "wifite2",
    "amass",
    "subfinder",
    "shodan",
    "arjun",
    "dalfox",
    "prowler",
    "pacu",
    "scapy",
    "tshark",
    "tcpdump",
    # System network utilities
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "dig",
    "host",
    "nslookup",
    "ping",
    "traceroute",
    "tracepath",
    "whois",
    # Utilities that can make outbound network connections
    "openssl",  # openssl s_client -connect
    "gpg",  # gpg --recv-keys --keyserver
    # Registry tools whose targets use the private/loopback allowlist.
    # Keep synchronized with test_network_tools_cover_registry.
    # Port / host / service scanners
    "rustscan",
    "zmap",
    "naabu",
    "nbtscan",
    "onesixtyone",
    "fping",
    "arping",
    "hping3",
    "ncrack",
    "smap",
    "asnmap",
    "ssh-audit",
    # DNS / subdomain enumeration
    "dnsenum",
    "dnsrecon",
    "dnstwist",
    "dnsx",
    "massdns",
    "puredns",
    "shuffledns",
    "findomain",
    "chaos",
    "github-subdomains",
    # URL / host harvesting and crawling
    "gau",
    "waybackurls",
    "httprobe",
    "hakrawler",
    "hakrevdns",
    "meg",
    "gowitness",
    "theHarvester",
    "emailharvester",
    "uncover",
    "cariddi",
    "katana",
    "paramspider",
    # Recon frameworks that take a target host/domain
    "bbot",
    "osmedeus",
    "reconftw",
    "Sn1per",
    "nmapAutomator",
    "maryam",
    "metabigor",
    "parsero",
    "EyeWitness",
    "GooFuzz",
    "raccoon-scanner",
    "censys",
    # TLS / web-app scanners
    "sslscan",
    "sslyze",
    "testssl.sh",
    "tlsx",
    "wafw00f",
    "webanalyze",
    "wpscan",
    "CMSmap",
    "droopescan",
    "subzy",
    # Web attack tools that take a --url / host
    "commix",
    "crlfuzz",
    "corscanner",
    "Corsy",
    "Gxss",
    "kxss",
    "NoSQLMap",
    "jaeles",
    "smuggler",
    "h2csmuggler",
    "git-dumper",
    "xsrfprobe",
    "symfony-exploits",
    "tomcatwardeployer",
    "kr",
    "XXEinjector",
    "PadBuster",
    "XSStrike",
    # Tunnels / pivots / proxies that connect to a remote endpoint
    "chisel",
    "frpc",
    "frps",
    "ligolo-agent",
    "ligolo-proxy",
    "dns2tcp",
    "dnscat2",
    "iodine",
    "sshuttle",
    "pwnat",
    "sslsplit",
    # SMB / file services
    "smbclient",
    "smbmap",
    # Directory/content brute-forcers and URL scanners that take an argv target.
    "dirsearch",
    "ghauri",
    "clairvoyance",
    "graphw00f",
    "Oralyzer",
    "nomore403",
    "x8",
    "tplmap",
    # Subdomain / URL enumeration and crawling.
    "assetfinder",
    "sublist3r",
    "waymore",
    "knock-subdomains",
    "gospider",
    "Photon",
    # Classic external-target scanners not in the registry, covered if added later.
    "fierce",
    "dirb",
    "zaproxy",
    "snmp",
    "snmpwalk",
    "netexec",
    "nxc",
    "impacket",
    "impacket-secretsdump",
    "certipy-ad",
    "certipy",
    "bloodhound",
    "bloodhound-python",
    "ldapsearchad",
    "ldapsearch-ad.py",
    "coercer",
    "mitm6",
    "lsassy",
    "sprayhound",
    "ldapdomaindump",
    "adidnsdump",
    "dploot",
    "bloodyad",
    "hekatomb",
    "certsync",
    "masky",
    "pywhisker",
    "autobloody",
    "krbjack",
    "roadtx",
    "pywerview",
    "pysnaffler",
    "powerview",
    "aclpwn",
    "ldeep",
    "smbclientng",
    "godap",
    "pretender",
    "evil-winrm",
}

# Env-configurable: CYBERSEC_MCP_ALLOW_EXTERNAL=1 unlocks external targets.
# Default: only loopback and RFC 1918 ranges are allowed.
# Evaluated dynamically so env changes take effect without restart.


def _allow_external() -> bool:
    return os.environ.get("CYBERSEC_MCP_ALLOW_EXTERNAL", "").strip() == "1"


# Env-configurable: CYBERSEC_MCP_ALLOW_SCRIPTS=1 unlocks script execution.
# Default: script execution is disabled.


def _allow_scripts() -> bool:
    return os.environ.get("CYBERSEC_MCP_ALLOW_SCRIPTS", "").strip() == "1"


def _allow_host_control(tool_name: str) -> bool:
    variable = HOST_CONTROL_OPT_INS.get(package_for_extra_binary(tool_name) or tool_name)
    return variable is not None and os.environ.get(variable, "").strip() == "1"


def _host_control_information(tool_name: str, arg_list: list[str]) -> bool:
    if arg_list in (["-h"], ["--help"], ["--version"], ["-V"]):
        return True
    return tool_name == "nipe" and arg_list in ([], ["help"])


# Private/safe network ranges (loopback + RFC 1918 + link-local + CGNAT/VPN).
_SAFE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    # RFC 6598 CGNAT range — used by Tailscale, some VPN providers, and
    # carrier-grade NAT. Safe for CTF/pentest VPN tunnels.
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Link-local cloud metadata endpoints can expose workload credentials and must
# require the same explicit opt-in as other sensitive external destinations.
_BLOCKED_SAFE_MODE_NETWORKS = [
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.170.2/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    # Alibaba Cloud metadata, inside the CGNAT range that is otherwise safe.
    ipaddress.ip_network("100.100.100.200/32"),
]


def _address_is_safe(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return whether an address is allowed by the default network policy."""
    mapped = getattr(addr, "ipv4_mapped", None)
    effective = mapped if mapped is not None else addr
    if any(effective in net for net in _BLOCKED_SAFE_MODE_NETWORKS if effective.version == net.version):
        return False
    return any(effective in net for net in _SAFE_NETWORKS if effective.version == net.version)


def _network_is_safe(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Return whether an entire network is allowed by the default policy."""
    effective: ipaddress.IPv4Network | ipaddress.IPv6Network = net
    if isinstance(net, ipaddress.IPv6Network) and net.prefixlen >= 96:
        mapped = net.network_address.ipv4_mapped
        if mapped is not None:
            effective = ipaddress.ip_network((mapped, net.prefixlen - 96), strict=False)

    same_version_blocked = (blocked for blocked in _BLOCKED_SAFE_MODE_NETWORKS if blocked.version == effective.version)
    if any(effective.overlaps(blocked) for blocked in same_version_blocked):
        return False
    same_version_safe = (safe for safe in _SAFE_NETWORKS if safe.version == effective.version)
    return any(effective.subnet_of(safe) for safe in same_version_safe)


class _RateLimiter:
    """Concurrency + sliding-window rate limiter for tool execution."""

    def __init__(self, max_concurrent: int = 10, max_per_minute: int = 60):
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._timestamps: list[float] = []
        self._max_per_minute = max_per_minute
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < 60]
            current = len(self._timestamps)
            if current >= self._max_per_minute:
                log_rate_limit("exceeded", current, self._max_per_minute)
                raise ValueError(f"Rate limit exceeded: max {self._max_per_minute} tool executions per minute")
            self._timestamps.append(now)
            log_rate_limit("acquired", current + 1, self._max_per_minute)


_rate_limiter = _RateLimiter()


# Bounded DNS resolver pool. Target validation runs before the rate limiter and
# concurrency semaphore, so without a cap a burst of requests would spawn one daemon
# thread per call. A fixed-size pool caps concurrent getaddrinfo calls; excess
# submissions queue instead of allocating unbounded OS threads. A hung lookup still
# occupies its worker until the OS resolver gives up (future.cancel cannot interrupt
# getaddrinfo), which is the intended bound, not a leak.
_DNS_MAX_WORKERS = 8
_dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=_DNS_MAX_WORKERS, thread_name_prefix="cybersec-dns")


def _resolve_with_timeout(hostname: str, timeout: float = 5.0) -> list:
    """Resolve hostname via getaddrinfo with a per-call timeout, through a bounded pool.

    The timeout is per call because socket.setdefaulttimeout is process-global and
    would race between concurrent tool executions.
    """
    start = time.monotonic()
    future = _dns_executor.submit(socket.getaddrinfo, hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    try:
        result = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        future.cancel()  # best-effort; a running getaddrinfo cannot be interrupted
        elapsed = (time.monotonic() - start) * 1000
        log_dns(hostname, resolved=False, duration_ms=elapsed, error="timeout")
        raise socket.timeout(f"DNS resolution timed out after {timeout}s") from None
    except (socket.gaierror, OSError) as exc:
        elapsed = (time.monotonic() - start) * 1000
        log_dns(hostname, resolved=False, duration_ms=elapsed, error=str(exc))
        raise
    elapsed = (time.monotonic() - start) * 1000
    if result:
        first_ip = result[0][4][0]
        is_safe = all(_address_is_safe(ipaddress.ip_address(sa[4][0])) for sa in result)
        log_dns(hostname, resolved=True, ip=first_ip, safe=is_safe, duration_ms=elapsed)
    else:
        log_dns(hostname, resolved=False, duration_ms=elapsed, error="empty_result")
    return result


def _decode_encoded_ipv4(value: str) -> ipaddress.IPv4Address | None:
    """Decode a non-dotted IPv4 encoding (decimal/hex/octal) to an address.

    Catches obfuscations like ``134744072`` (== 8.8.8.8) and ``0x08080808``
    that bare-positional tools (nc, ncat, ping) accept as a host but that the
    dotted-quad parser misses, letting an external host slip past the allowlist.

    Returns ``None`` when *value* is not a single-integer host encoding — bare
    decimals <= 65535 are excluded so ports/timeouts (``-p 80``) are not
    mis-validated as targets.
    """
    s = value.strip()
    if not s:
        return None
    try:
        if s.lower().startswith(("0x", "0o", "0b")):
            n = int(s, 0)
        elif s.isdigit():
            n = int(s, 10)
            if n <= 65535:  # port / timeout range — not an encoded IP
                return None
        else:
            return None
    except ValueError:
        return None
    if 0 <= n <= 0xFFFFFFFF:
        return ipaddress.IPv4Address(n)
    return None


def _resolves_only_to_safe(host: str) -> bool:
    """Resolve *host* and require every address to be safe; any failure denies.

    Residual risk: this validation is independent of the tool's connect-time
    resolution, so an attacker-controlled short-TTL/multi-answer record can rebind
    past the default-safe check (DNS rebinding/TOCTOU); IP/CIDR/IPv6 literals are
    validated directly in _is_safe_target and are unaffected.
    """
    try:
        info = _resolve_with_timeout(host)
        if not info:
            return False
        return all(_address_is_safe(ipaddress.ip_address(sockaddr[0])) for _, _, _, _, sockaddr in info)
    except (socket.gaierror, OSError, socket.timeout, ValueError):
        return False


_OCTET_SPEC_RE = re.compile(r"^\d{1,3}(?:-\d{1,3})?(?:,\d{1,3}(?:-\d{1,3})?)*$")


def _address_range_is_safe(value: str) -> bool | None:
    """Classify an nmap octet range (``192.168.1.1-254``, ``10.0.0.1,5``) or a masscan
    ``A-B`` address range. ``None`` when *value* is not range syntax.

    The range is widened to the integer span between its lowest and highest address and
    every covering network must be safe, so a list that skips over unsafe space fails.
    """
    pair = value.split("-")
    if len(pair) == 2 and "." in pair[0] and "." in pair[1]:
        try:
            low, high = ipaddress.IPv4Address(pair[0]), ipaddress.IPv4Address(pair[1])
        except ValueError:
            pass
        else:
            if low > high:
                return False
            return all(_network_is_safe(net) for net in ipaddress.summarize_address_range(low, high))
    octets = value.split(".")
    if len(octets) != 4 or not all(_OCTET_SPEC_RE.match(octet) for octet in octets):
        return None
    if not any("-" in octet or "," in octet for octet in octets):
        return None
    lows: list[int] = []
    highs: list[int] = []
    for octet in octets:
        numbers = [int(n) for n in re.split(r"[-,]", octet)]
        if any(n > 255 for n in numbers):
            return False
        for item in octet.split(","):
            bounds = [int(n) for n in item.split("-")]
            if len(bounds) == 2 and bounds[0] > bounds[1]:
                return False
        lows.append(min(numbers))
        highs.append(max(numbers))
    low = ipaddress.IPv4Address(".".join(map(str, lows)))
    high = ipaddress.IPv4Address(".".join(map(str, highs)))
    return all(_network_is_safe(net) for net in ipaddress.summarize_address_range(low, high))


def _is_safe_target(value: str) -> bool:
    """Check if a string looks like a network target and is in a safe range."""
    if not value:
        return True  # Empty string is not a network target
    if value == _AMBIGUOUS_AUTHORITY_HOST:
        return False

    # Non-dotted encoded IPv4 (decimal/hex/octal) — e.g. 134744072 == 8.8.8.8.
    # Resolve before the dotted-quad parser so obfuscated externals are caught.
    encoded = _decode_encoded_ipv4(value)
    if encoded is not None:
        return _address_is_safe(encoded)

    # Try parsing as IP address directly
    try:
        addr = ipaddress.ip_address(value)
        return _address_is_safe(addr)
    except ValueError:
        pass

    # Try parsing as CIDR
    try:
        net = ipaddress.ip_network(value, strict=False)
        return _network_is_safe(net)
    except (ValueError, TypeError):
        pass

    # Loopback names resolve locally even where no resolver or hosts entry exists.
    if value.lower() in {"localhost", "localhost.localdomain"}:
        return True

    in_range = _address_range_is_safe(value)
    if in_range is not None:
        return in_range

    # Check for hostname-like strings (contains dots, no path separators)
    if "." in value and "/" not in value and not value.startswith("-"):
        return _resolves_only_to_safe(value)

    # Not a recognizable IP/hostname — could be a decimal IP, bare hostname, etc.
    # Values that look like file paths or flags are allowed through.
    if value.startswith(("-", "/", "./", "~")):
        return True

    # DNS resolution as a last resort catches targets like "google". Can't resolve —
    # could be a transient failure — so deny; genuine non-network values (flags/paths)
    # are caught above.
    return _resolves_only_to_safe(value)


_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Text / data
        ".txt",
        ".json",
        ".xml",
        ".csv",
        ".html",
        ".htm",
        ".log",
        ".md",
        ".rst",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".env",
        ".bak",
        ".old",
        ".pdf",
        ".rtf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        # Archives / compression
        ".gz",
        ".bz2",
        ".xz",
        ".zst",
        ".lz4",
        ".zip",
        ".7z",
        ".rar",
        ".tar",
        ".tgz",
        ".tar.gz",
        # Packet captures / network
        ".pcap",
        ".pcapng",
        ".cap",
        ".netxml",
        ".gnmap",
        ".nmap",
        # Binary / forensics
        ".bin",
        ".raw",
        ".img",
        ".iso",
        ".dd",
        ".dmp",
        ".mem",
        ".vmem",
        ".exe",
        ".dll",
        ".elf",
        ".so",
        ".dylib",
        ".o",
        ".a",
        ".apk",
        ".ipa",
        ".dex",
        ".class",
        ".jar",
        ".war",
        # Disk / filesystem images
        ".e01",
        ".aff",
        ".qcow2",
        ".vdi",
        ".vmdk",
        ".vhd",
        # Output / report
        ".out",
        ".dat",
        ".rep",
        ".report",
        ".result",
        ".results",
        # Images / stego
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".tiff",
        ".tif",
        ".svg",
        ".ico",
        ".webp",
        ".ppm",
        ".pgm",
        ".pbm",
        # Audio / video stego
        ".wav",
        ".mp3",
        ".flac",
        ".ogg",
        ".mp4",
        ".avi",
        ".mkv",
        # Crypto / certs
        ".pem",
        ".crt",
        ".cer",
        ".der",
        ".key",
        ".p12",
        ".pfx",
        ".csr",
        ".pub",
        ".asc",
        ".sig",
        ".gpg",
        ".enc",
        # Code / scripts
        ".py",
        ".sh",
        ".rb",
        ".js",
        ".ts",
        ".go",
        ".rs",
        ".c",
        ".h",
        ".cpp",
        ".java",
        ".php",
        ".pl",
        ".ps1",
        ".bat",
        ".lua",
        ".nse",
        ".sql",
        ".r",
        ".m",
        ".swift",
        # Web
        ".css",
        ".jsx",
        ".tsx",
        ".wasm",
        # Wordlists / rules
        ".lst",
        ".dict",
        ".rule",
        ".hcrule",
        ".mask",
        # Hashes / loot
        ".hash",
        ".hashes",
        ".pot",
        ".loot",
        ".creds",
        # Misc CTF / security
        ".flag",
        ".challenge",
        ".ctf",
        ".exploit",
        ".payload",
        ".yar",
        ".yara",
        ".sigma",
        ".suricata",
        ".snort",
        ".burp",
        ".zap",
        ".har",
        # Database
        ".db",
        ".sqlite",
        ".sqlite3",
        ".mdb",
        ".ldf",
        ".mdf",
    }
)


def _has_file_extension(value: str) -> bool:
    """Return True if value ends with a known file extension."""
    lower = value.lower()
    return any(lower.endswith(ext) for ext in _FILE_EXTENSIONS)


# File extensions that are ALSO real public TLDs. A token like "example.zip"
# or "http://evil.mobi" ends in one of these "extensions" but is a live
# external host, so it must NOT be treated as a benign local filename when
# deciding whether to skip target validation after an unknown flag.
_EXTENSION_TLDS: frozenset[str] = frozenset(
    {
        ".zip",
        ".mobi",
        ".sh",
        ".java",
        ".md",
        ".pl",
        ".pub",
        ".py",
        ".report",
        ".rs",
        ".so",
        ".app",
        ".dev",
        ".bar",
        ".dad",
        ".day",
        ".foo",
        ".mov",
        ".phd",
        ".prof",
    }
)


def _leads_with_host(value: str) -> bool:
    """Return True when a scheme-less ``host/path`` token starts with an address or dotted host.

    curl, wget and similar tools read such a token as a URL. A single-label first
    segment (``out/a.txt``) stays a path: relative paths are written that way, and
    such a name resolves only through local search domains. A relative directory
    with a dot in its name is therefore validated as a host; write it as ``./dir.name/``.
    """
    head = value.split("/", 1)[0]
    if "@" in head:
        head = head.rsplit("@", 1)[1]
    if head.startswith("["):
        return True
    host = head.rsplit(":", 1)[0] if head.count(":") == 1 else head
    if not host or set(host) <= {"."}:
        return False
    # Resolvers accept a fully qualified name with its root dot and labels with an underscore.
    host = host.removesuffix(".")
    if _decode_encoded_ipv4(host) is not None:
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return "." in host and re.fullmatch(r"[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9_])?", host) is not None


def _is_local_path(value: str) -> bool:
    """Return True if *value* is clearly a local filesystem path, not a target.

    A token counts as local when it contains a path separator (``/`` or ``\\``)
    or ends in a known file extension that is NOT also a real TLD. URLs, tokens
    whose first path segment is a host (``203.0.113.9/a.txt``), and tokens that only
    "look like a file" because their extension doubles as a TLD (``.zip``, ``.md``,
    ``.sh``) are deliberately rejected here so an external host such as
    ``http://evil.zip`` or ``example.zip`` still gets target-validated.
    """
    # A URL in any scheme (ftp, sftp, gopher, ...) is never a local path, even though it contains "/".
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        return False
    lower = value.lower()
    if "/" in value or "\\" in value:
        return not _leads_with_host(value)
    if any(lower.endswith(ext) for ext in _EXTENSION_TLDS):
        return False
    return _has_file_extension(value)


def _looks_like_target(value: str) -> bool:
    """Heuristic: does this positional arg look like a network target?

    Returns True for IPs, hostnames, URLs, CIDRs.  Returns False for bare
    numbers (port/timeout values), plain words (flag values like usernames),
    and other non-target strings.  This prevents flag values from being
    incorrectly validated as network targets (e.g. ``-p 80`` where ``80`` is
    a port, not a host).
    """
    # URL
    if _URL_SCHEME_RE.match(value):
        return True
    # IPv6 (contains colons) — but skip Windows drive letters like C:\path
    if ":" in value and not re.match(r"^[A-Za-z]:[/\\]", value):
        return True
    # CIDR notation
    if "/" in value and re.match(r"^[\d.]", value):
        return True
    # IP-like (digits and dots, at least one dot)
    if "." in value and re.match(r"^[\d.]+$", value):
        return True
    # Hostname (contains dot, starts with alphanumeric or the underscore of a service label)
    if "." in value and re.match(r"^[a-zA-Z0-9_]", value):
        return True
    # localhost special case
    if value.lower() == "localhost":
        return True
    # Encoded IPv4 (decimal/hex/octal, e.g. 134744072 == 8.8.8.8). Bare ports
    # and timeouts (<= 65535) are excluded by _decode_encoded_ipv4 so flag
    # values like "80" are still skipped.
    if _decode_encoded_ipv4(value) is not None:
        return True
    # Single-label hostname: alphabetic word (possibly with hyphens/digits) that
    # is not purely numeric.  Values like "google", "scanme" are valid DNS names
    # and must go through target validation.  Pure numbers ("80", "4") are
    # skipped — they are port/timeout values.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", value):
        return True
    return False


def _looks_like_external_target(value: str) -> bool:
    """Stricter than :func:`_looks_like_target`: match only unambiguous network
    targets (URL, IP, dotted host, IPv6, CIDR, encoded IPv4), never bare
    single-label words.

    Used to decide whether a value embedded in an *unrecognized* flag
    (``-flag=<host>`` or attached ``-f<host>``) must clear the external-target
    allowlist. Excluding bare words keeps boolean flags (``-silent``) and local
    output names (``-o=results``) from falsely tripping the gate, while still
    catching goflags-style ``-target=http://…`` / ``-host=8.8.8.8`` bypasses.
    """
    if not _looks_like_target(value):
        return False
    if _URL_SCHEME_RE.match(value):
        return True
    if "." in value or ":" in value or "/" in value:
        return True
    return _decode_encoded_ipv4(value) is not None


# A backslash, whitespace or control character in a URL authority is read differently by urlsplit,
# browsers and curl (``http://evil.example\@127.0.0.1/``), so the real destination is unknowable.
_AMBIGUOUS_AUTHORITY_RE = re.compile(r"[\\\s\x00-\x1f\x7f]")
_AMBIGUOUS_AUTHORITY_HOST = "ambiguous-url-authority.invalid"


def _has_ambiguous_authority(value: str) -> bool:
    authority = re.split(r"[/?#]", _URL_SCHEME_RE.sub("", value), maxsplit=1)[0]
    if not (_URL_SCHEME_RE.match(value) or "@" in authority):
        return False
    return bool(_AMBIGUOUS_AUTHORITY_RE.search(authority))


def _takes_domain_credentials(tool_name: str, binary: str) -> bool:
    """Whether the tool's positional target is Impacket's ``[DOMAIN/]user[:password]@host``."""
    return any(name.casefold().startswith("impacket") for name in (tool_name, binary))


def _network_target_host(value: str, *, domain_credentials: bool = False) -> str:
    """Normalize a URL/host argument to the host value used for allowlist checks.

    An authority that parsers disagree on yields a placeholder host that is never safe.
    *domain_credentials* is for tools whose target is ``DOMAIN/user:password@host``: the host is
    what follows the last ``@``. For any other scheme-less value the authority ends at the first
    ``/``, ``?`` or ``#``, so ``evil.example/x@10.0.0.1`` is evil.example, not 10.0.0.1.
    """
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass

    if domain_credentials and not _URL_SCHEME_RE.match(value) and "@" in value:
        value = value.rsplit("@", 1)[-1]
    if _has_ambiguous_authority(value):
        return _AMBIGUOUS_AUTHORITY_HOST
    clean = _URL_SCHEME_RE.sub("", value)
    # Isolate the authority before stripping URL userinfo.
    clean = re.split(r"[/?#]", clean, maxsplit=1)[0]
    if "@" in clean:
        clean = clean.rsplit("@", 1)[-1]
    if clean.startswith("["):
        bracket_end = clean.find("]")
        if bracket_end != -1:
            return clean[1:bracket_end]
        return clean
    if clean.count(":") == 1:
        return clean.split(":")[0]
    return clean


# Proxy and upstream destinations use the same network scope policy as targets.
_PROXY_FLAGS: frozenset[str] = frozenset({"-x", "--proxy", "--preproxy", "-proxy", "-http-proxy", "--proxy-host"})
_ATTACHED_PROXY_FLAGS: frozenset[str] = frozenset({"-x"})


def _validate_proxy_target(value: str) -> None:
    """Raise if the host inside a proxy-flag *value* is not private/loopback.

    Only validates when the extracted host actually looks like a network target,
    so benign non-host values never produce a spurious block. No-op when external
    targets are allowed (the caller already returned in that case).
    """
    stripped = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", value)
    if "@" in stripped:
        stripped = stripped.rsplit("@", 1)[1]
    host = _network_target_host(value) if _has_ambiguous_authority(value) else _network_target_host(stripped)
    if host and _looks_like_target(host) and not _is_safe_target(host):
        raise ValueError(
            f"Blocked by policy: proxy target '{value}' is not in a private/local "
            "range (set CYBERSEC_MCP_ALLOW_EXTERNAL=1 to allow external proxies)"
        )


# curl --connect-to/--resolve redirect the connection to a host other than the URL, so validate it too.
_CURL_REDIRECT_FLAGS: frozenset[str] = frozenset({"--connect-to", "--resolve"})


def _validate_curl_redirect_target(flag: str, value: str) -> None:
    """Raise if the connection destination in a curl --connect-to/--resolve value is
    not private/loopback. No-op when external targets are allowed (caller returned)."""
    if flag == "--resolve":
        # [+|-]HOST:PORT:ADDR[,ADDR...] — the removal form ("-HOST:PORT") carries no
        # address; otherwise validate every mapped address after the 2nd colon.
        spec = value[1:] if value[:1] in ("+", "-") else value
        parts = spec.split(":", 2)
        dests = parts[2].split(",") if len(parts) == 3 else []
    else:  # --connect-to HOST1:PORT1:HOST2:PORT2 — validate the connect host HOST2:PORT2
        parts = value.split(":", 2)
        dests = [parts[2]] if len(parts) == 3 else []
    for dest in dests:
        host = _network_target_host(dest.strip())
        if host and _looks_like_target(host) and not _is_safe_target(host):
            raise ValueError(
                f"Blocked by policy: {flag} redirects to '{dest.strip()}' which is not in a "
                "private/local range (set CYBERSEC_MCP_ALLOW_EXTERNAL=1 to allow external hosts)"
            )


# Write-destination guard

# Allowlisted utilities whose positional arguments can create, overwrite, or
# symlink a file. Tools with mode-dependent output paths are handled separately
# in _check_write_destinations().
_WRITE_CAPABLE_TOOLS: frozenset[str] = frozenset({"cp", "mv", "ln", "tee", "touch", "mkdir"})

# Absolute system directories that must never be written into.
_SENSITIVE_WRITE_DIRS: tuple[str, ...] = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/root",
    "/var/spool/cron",
    "/var/spool/at",
    "/proc",
    "/sys",
    "/dev",
    "/var/lib",
    "/var/www",
    "/srv",
    "/opt",
    "/run",
)

# Device nodes that are routinely redirected to and are harmless to write.
_SAFE_DEVICE_PATHS: frozenset[str] = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty"})
_SAFE_DEVICE_PREFIXES: tuple[str, ...] = ("/dev/shm/", "/dev/fd/")

# Application directories that are writable working locations when the server runs from them.
_SOFT_WRITE_DIRS: frozenset[str] = frozenset({"/opt", "/srv", "/run", "/var/lib", "/var/www"})

# Login/shell-rc and other startup files that are dangerous to overwrite even
# when they sit directly in $HOME (matched by basename anywhere under $HOME).
_SENSITIVE_BASENAMES: frozenset[str] = frozenset(
    {
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zlogin",
        ".zshenv",
        ".kshrc",
        ".cshrc",
        ".tcshrc",
        ".login",
        ".inputrc",
        ".netrc",
        ".gitconfig",
        ".vimrc",
        "authorized_keys",
        "crontab",
    }
)


def _normalize_write_path(path: str) -> str | None:
    """Expand *path* to an absolute lexical path for prefix checks.

    Returns None for values that are not plausible filesystem destinations
    (URLs, ``-`` stdout sentinel, empty). Symlink resolution is performed
    separately so both the path the caller supplied and its real destination
    are checked.
    """
    if not path or path == "-":
        return None
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", path):
        return None  # URL, not a local path
    # os.path.join ignores cwd when the expanded path is already absolute, so
    # this covers both cases without a separate isabs branch.
    return os.path.normpath(os.path.join(os.getcwd(), os.path.expanduser(path)))


def _write_path_candidates(path: str) -> tuple[str, ...]:
    """Return lexical and symlink-resolved forms of a possible write path."""
    norm = _normalize_write_path(path)
    if norm is None:
        return ()
    resolved = os.path.realpath(norm)
    return (norm,) if resolved == norm else (norm, resolved)


def _working_roots() -> tuple[str, ...]:
    """Return the server's working directory and toolkit root, which are ordinary write locations."""
    roots = {os.path.realpath(os.getcwd())}
    roots.add(os.path.realpath(os.environ.get("CYBERSEC_INSTALLER_ROOT") or os.path.dirname(os.path.dirname(__file__))))
    return tuple(roots)


def _is_sensitive_normalized_path(norm: str) -> bool:
    """Classify one absolute, normalized write path."""
    for directory in _SENSITIVE_WRITE_DIRS:
        for protected in {directory, os.path.realpath(directory)}:
            if norm == protected or norm.startswith(protected + os.sep):
                if directory in _SOFT_WRITE_DIRS and any(
                    root not in {directory, protected} and (norm == root or norm.startswith(root + os.sep))
                    for root in _working_roots()
                ):
                    continue
                return True

    if os.path.basename(norm) in _SENSITIVE_BASENAMES:
        return True

    home = os.path.normpath(os.path.expanduser("~"))
    for base in {home, os.path.realpath(home)}:
        if base and base != os.sep and (norm == base or norm.startswith(base + os.sep)):
            rel = os.path.relpath(norm, base)
            if any(part.startswith(".") and part not in ("", ".", "..") for part in rel.split(os.sep)):
                return True

    # Dotted paths (~/.ssh, ~/.config/autostart) under any other account's home.
    other_home = re.match(r"^/(?:home|Users)/[^/]+/(.+)$", norm)
    if other_home and any(part.startswith(".") for part in other_home.group(1).split("/")):
        return True

    return False


def _is_sensitive_write_target(path: str) -> bool:
    """Return True if writing to *path* would hit a sensitive location.

    Blocks: any dotfile under $HOME (``~/.bashrc``, ``~/.ssh/``,
    ``~/.config/autostart/``, ``~/.config/systemd/``, ...), known shell-rc/login
    files by basename, cron dirs, and system dirs (/etc, /usr, /bin, ...). Does
    NOT block /tmp, the CWD, or other ordinary working locations.
    """
    candidates = _write_path_candidates(path)
    if candidates and (candidates[0] in _SAFE_DEVICE_PATHS or candidates[0].startswith(_SAFE_DEVICE_PREFIXES)):
        return False
    return any(_is_sensitive_normalized_path(candidate) for candidate in candidates)


def _raise_sensitive_write(name: str, dest: str) -> None:
    """Raise the consistent policy error for a protected write destination."""
    if _is_sensitive_write_target(dest):
        raise ValueError(
            f"Blocked by policy: {name} target '{dest}' resolves into a sensitive "
            "location (dotfile/shell-rc/cron/system dir). Write to /tmp or the working dir."
        )


def _flag_values(
    arg_list: list[str],
    *,
    short_flags: frozenset[str] = frozenset(),
    long_flags: frozenset[str] = frozenset(),
) -> list[str]:
    """Extract separated, ``--flag=value``, and attached short-flag values.

    A ``--`` option that abbreviates one of *long_flags* counts as that flag: getopt_long,
    argparse and GnuPG all resolve an unambiguous prefix, so ``--outp=FILE`` is ``--output``.
    """
    values: list[str] = []
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        name, attached, value = arg.partition("=")
        is_long = name in long_flags or (
            name.startswith("--")
            and len(name) >= 2 + _ABBREV_MIN_LEN
            and any(flag.startswith(name) for flag in long_flags)
        )
        if arg in short_flags or (is_long and not attached):
            if i + 1 < len(arg_list):
                values.append(arg_list[i + 1])
                i += 2
                continue
        if is_long and attached:
            values.append(value)
        else:
            for flag in short_flags:
                if arg.startswith(flag) and arg != flag:
                    values.append(arg[len(flag) :])
                    break
        i += 1
    return values


def _getopt_values(arg_list: list[str], *, shorts: str, longs: frozenset[str], value_shorts: str = "") -> list[str]:
    """Values of the named options as GNU getopt_long reads them.

    Covers the spellings a literal match misses: an unambiguous prefix of a long
    option (``--outp=FILE``, ``--out FILE``) and a short option inside a bundle
    (``-uo FILE``, ``-uoFILE``). *value_shorts* names the tool's other short options
    that take a value, whose remaining characters are not options. The argument
    after an option is reported as its value and still read as an option in its own
    right, so an option whose value is optional cannot hide the one that follows.
    """
    values: list[str] = []
    for i, arg in enumerate(arg_list):
        if arg == "--":
            break
        following = arg_list[i + 1] if i + 1 < len(arg_list) else None
        if arg.startswith("--"):
            name, attached, value = arg[2:].partition("=")
            if name and any(flag[2:].startswith(name) for flag in longs):
                if attached:
                    values.append(value)
                elif following is not None:
                    values.append(following)
        elif arg.startswith("-") and len(arg) > 1:
            for position, char in enumerate(arg[1:], start=2):
                if char in shorts:
                    if arg[position:]:
                        values.append(arg[position:])
                    elif following is not None:
                        values.append(following)
                    break
                if char in value_shorts:
                    break
    return values


# GNU tar short options that take a value, and the other value-taking short options of
# curl, wget and unzip: inside a bundle, what follows one of them is its value, not more options.
_TAR_VALUE_SHORTS = "bCfFgHIKLNTVX"
_CURL_VALUE_SHORTS = "AbCdeEFHKmPQrtTuUwxXyYz"
_WGET_VALUE_SHORTS = "eiBtTwQlARDIXU"
# Those tables leave out the output options the write-destination scan reads itself. Every
# other scan needs them too, or it reads the value attached to one (-oTest.bin, -Oindex.html)
# as further options and finds a -T or -i that is not there.
_CURL_ALL_VALUE_SHORTS = _CURL_VALUE_SHORTS + "oDc"
_WGET_ALL_VALUE_SHORTS = _WGET_VALUE_SHORTS + "OoaP"
# unzip reads -x in the option bundle as "extract"; the exclusion list it also names follows the archive.
_UNZIP_VALUE_SHORTS = "P"
# zip options that take a value (the "req" rows of `zip -so`); the value is never the archive operand.
_ZIP_VALUE_SHORTS = frozenset({"-b", "-ds", "-lf", "-n", "-O", "-P", "-s", "-t", "-tt", "-TT", "-UN", "-Z"})
_ZIP_VALUE_LONGS = frozenset(
    {
        "--temp-path",
        "--dot-size",
        "--logfile-path",
        "--suffixes",
        "--output-file",
        "--password",
        "--split-size",
        "--from-date",
        "--before-date",
        "--unzip-command",
        "--unicode",
        "--compression-method",
    }
)


# Two-letter short options of zip 3.0 (`zip -so`); zip matches them before one-letter ones.
_ZIP_TWO_LETTER_OPTIONS = frozenset(
    "db dc dd dg ds du dv DF FF FI FS fd fz h2 ll lf la li mm MM nw RE sp sv sb sc sd sf so su sU tt TT UN ws".split()
)


def _zip_group(arg: str) -> list[tuple[str, str | None, bool]]:
    """Split a zip short-option group the way zip 3.0 reads it, longest option first.

    Returns (option, value, value_is_next_word) triples; value is the attached text, which
    "=" may leave empty. A "-" after an option negates it and the group goes on; other
    unknown text ends the group.
    """
    options: list[tuple[str, str | None, bool]] = []
    rest = arg[1:]
    while rest:
        if rest[0] == "-":
            rest = rest[1:]
            continue
        if rest[:2] in _ZIP_TWO_LETTER_OPTIONS:
            option = rest[:2]
        elif rest[0].isalnum() or rest[0] in "@$":
            option = rest[0]
        else:
            break
        rest = rest[len(option) :]
        if f"-{option}" in _ZIP_VALUE_SHORTS:
            if rest:
                options.append((option, rest[1:] if rest.startswith("=") else rest, False))
            else:
                options.append((option, None, True))
            break
        options.append((option, None, False))
    return options


def _check_zip_policy(arg_list: list[str]) -> None:
    for arg in arg_list:
        if arg == "--":
            return
        if arg.startswith("-") and not arg.startswith("--"):
            if any(option == "TT" for option, _, _ in _zip_group(arg)):
                raise ValueError("Blocked by policy: zip: -TT unzip test command (command execution)")


def _zip_write_targets(arg_list: list[str]) -> list[str]:
    """Paths a zip invocation creates, overwrites or (with -m) deletes.

    An -x/-i pattern list runs until the next option, so the archive is the first operand
    after the start or after an option; the first operand of every such run counts.
    """
    operands: list[str] = []
    targets: list[str] = []
    moving = False
    run_start = True
    options_ended = False
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        if options_ended or not arg.startswith("-") or len(arg) < 2:
            if run_start:
                targets.append(arg)
                run_start = False
            operands.append(arg)
            i += 1
            continue
        if arg == "--":
            options_ended = True
            i += 1
            continue
        run_start = True
        following = arg_list[i + 1] if i + 1 < len(arg_list) else None
        if arg.startswith("--"):
            flag, has_value, value = arg.partition("=")
            matches = [option for option in _ZIP_VALUE_LONGS if len(flag) > 2 and option.startswith(flag)]
            moving = moving or (len(flag) > 3 and "--move".startswith(flag))
            if matches and not has_value:
                value = following or ""
                i += 1
            if any(option in {"--output-file", "--logfile-path"} for option in matches) and value:
                targets.append(value)
            i += 1
            continue
        for option, value, value_is_next_word in _zip_group(arg):
            if option == "m":
                moving = True
            if value_is_next_word:
                value = following
                i += 1
            if option in {"O", "lf"} and value:
                targets.append(value)
        i += 1
    if moving:
        targets += operands
    return targets


def _tar_short_flag_values(arg_list: list[str], flag: str) -> list[str]:
    """Extract values for value-taking tar flags inside short-option bundles."""
    values: list[str] = []
    for i, arg in enumerate(arg_list):
        if i == 0 and re.fullmatch(r"[A-Za-z]+", arg):
            # Traditional syntax (``tar xfC archive.tar dir``): the values follow the bundle
            # in the order their letters appear in it.
            takers = [letter for letter in arg if letter in _TAR_VALUE_SHORTS]
            for position, letter in enumerate(takers):
                if letter == flag and i + 1 + position < len(arg_list):
                    values.append(arg_list[i + 1 + position])
            continue
        if not arg.startswith("-") or arg.startswith("--") or flag not in arg[1:]:
            continue
        suffix = arg[1:].split(flag, 1)[1]
        if suffix:
            values.append(suffix)
        elif i + 1 < len(arg_list):
            values.append(arg_list[i + 1])
    return values


def _tar_short_bundles(arg_list: list[str]) -> list[str]:
    """Return tar's dashed and traditional first-argument option bundles."""
    bundles: list[str] = []
    for i, arg in enumerate(arg_list):
        if arg.startswith("-") and not arg.startswith("--"):
            bundles.append(arg[1:])
        elif i == 0 and re.fullmatch(r"[A-Za-z]+", arg):
            bundles.append(arg)
    return bundles


def _check_curl_file_reads(tool_name: str, binary: str, arg_list: list[str]) -> None:
    """Block curl options that read a host file into the request or load a config.

    ``-d @/etc/passwd`` (and --data/--data-binary/--data-ascii/--data-urlencode),
    ``--json @file``, ``-F name=@file``/``name=<file``, ``--variable name@file``,
    ``-T``/``--upload-file`` and ``-K``/``--config`` are checked through getopt
    parsing, so bundles (``-sd``, ``-sK``) and unambiguous long-option prefixes are
    seen. ``--data-raw`` does not interpret ``@`` and is left alone; ``@-`` is stdin.
    """
    if "curl" not in (tool_name, binary):
        return
    for arg in arg_list:
        if re.match(r"(?i)^(?:--url=)?file:/", arg):
            raise ValueError("Blocked by policy: curl: file:// URL reads an arbitrary host file")
    for value in _getopt_values(
        arg_list,
        shorts="d",
        longs=frozenset({"--data", "--data-binary", "--data-ascii", "--data-urlencode"}),
        value_shorts=_CURL_ALL_VALUE_SHORTS,
    ):
        # @path, or name@path for --data-urlencode; @- is stdin, not a host file.
        ref = value.split("@", 1)[1] if "@" in value else ""
        if ref and ref != "-":
            raise ValueError("Blocked by policy: curl: @file data reads an arbitrary host file")
    for value in _getopt_values(arg_list, shorts="", longs=frozenset({"--json"}), value_shorts=_CURL_ALL_VALUE_SHORTS):
        if value.startswith("@") and value != "@-":
            raise ValueError("Blocked by policy: curl: --json @file reads an arbitrary host file")
    for value in _getopt_values(arg_list, shorts="F", longs=frozenset({"--form"}), value_shorts=_CURL_ALL_VALUE_SHORTS):
        content = value.partition("=")[2]
        if content.startswith(("@", "<")) and content[1:] != "-":
            raise ValueError("Blocked by policy: curl: -F file upload reads an arbitrary host file")
    for value in _getopt_values(
        arg_list, shorts="", longs=frozenset({"--variable"}), value_shorts=_CURL_ALL_VALUE_SHORTS
    ):
        if "@" in value.split("=", 1)[0]:
            raise ValueError("Blocked by policy: curl: --variable name@file reads an arbitrary host file")
    if _getopt_values(arg_list, shorts="T", longs=frozenset({"--upload-file"}), value_shorts=_CURL_ALL_VALUE_SHORTS):
        raise ValueError("Blocked by policy: curl: -T uploads an arbitrary host file")
    if _getopt_values(arg_list, shorts="K", longs=frozenset({"--config"}), value_shorts=_CURL_ALL_VALUE_SHORTS):
        raise ValueError("Blocked by policy: curl: config file flag bypasses target validation")


def _check_wget_policy(arg_list: list[str]) -> None:
    """Block wget's ``-i`` URL list inside an option bundle (``-qi urls.txt``)."""
    if _getopt_values(
        arg_list,
        shorts="i",
        longs=frozenset({"--input-file"}),
        value_shorts=_WGET_ALL_VALUE_SHORTS.replace("i", ""),
    ):
        raise ValueError("Blocked by policy: wget: URL list from file bypasses target validation")


def _check_nc_policy(arg_list: list[str]) -> None:
    """Reject -e/-c in any short-option bundle of nc/ncat/netcat (``-nve``, ``-e/bin/sh``).

    Fails closed: a bundle containing either letter is refused wherever it sits,
    because which letters take a value differs between nc implementations.
    """
    for arg in arg_list:
        if arg == "--":
            break
        if arg.startswith("-") and not arg.startswith("--") and any(char in "ec" for char in arg[1:]):
            raise ValueError("Blocked by policy: nc: -e/-c exec program (arbitrary command execution)")


def _check_binwalk_policy(arg_list: list[str]) -> None:
    """Reject ``-D``/``--dd`` (runs a command on extracted files) inside a bundle too."""
    if _getopt_values(arg_list, shorts="D", longs=frozenset({"--dd", "--run-as"}), value_shorts="C"):
        raise ValueError("Blocked by policy: binwalk: -D/--dd runs a command on each extracted file")


def _check_ip_policy(arg_list: list[str]) -> None:
    """Block ``ip ... exec`` (netns/vrf command execution) and ``ip -batch FILE``.

    iproute2 resolves any prefix of a keyword, so ``ex`` is ``exec`` and ``-ba`` is ``-batch``.
    """
    for arg in arg_list:
        word = arg.removeprefix("-") if arg.startswith("--") else arg
        if arg in {"e", "ex", "exe", "exec"}:
            raise ValueError("Blocked by policy: ip: exec runs a command inside a namespace")
        if len(word) >= 2 and word.startswith("-") and "-batch".startswith(word):
            raise ValueError("Blocked by policy: ip: -batch reads commands from a file")


def _check_url_operands_policy(arg_list: list[str]) -> None:
    """Validate URL operands of tools that fetch a URL but are otherwise file tools (xmllint, exiv2)."""
    if _allow_external():
        return
    for arg in arg_list:
        if _URL_SCHEME_RE.match(arg) and not _is_safe_target(_network_target_host(arg)):
            raise ValueError(
                f"Blocked by policy: URL '{arg}' is not in a private/local network range. "
                "Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 to allow external targets."
            )


_SED_VALUE_LONGS = {"expression": True, "line-length": False}


def _sed_scripts(arg_list: list[str]) -> list[str]:
    """The sed program texts on the command line: -e/--expression values, else the first operand."""
    scripts: list[str] = []
    operands: list[str] = []
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        i += 1
        if arg == "--":
            operands.extend(arg_list[i:])
            break
        if arg.startswith("--"):
            name, sep, value = arg[2:].partition("=")
            for long_name, is_script in _SED_VALUE_LONGS.items():
                if name and long_name.startswith(name):
                    if not sep and i < len(arg_list):
                        value = arg_list[i]
                        i += 1
                    if is_script:
                        scripts.append(value)
                    break
        elif arg.startswith("-") and len(arg) > 1:
            for position, char in enumerate(arg[1:], start=2):
                if char in "el":
                    value = arg[position:]
                    if not value and i < len(arg_list):
                        value = arg_list[i]
                        i += 1
                    if char == "e":
                        scripts.append(value)
                    break
        else:
            operands.append(arg)
    return scripts or operands[:1]


def _sed_unsafe_command(script: str) -> str | None:
    """Return the first e/r/R/w/W command (or s///e, s///w flag) in a sed program.

    Walks the script the way sed reads it, skipping addresses, s/y bodies and a/i/c text,
    so ``1eid``, ``w/path`` and ``;ee`` are found without a space after the letter. A
    program that cannot be parsed is reported, so the check fails closed.
    """
    n = len(script)
    i = 0

    def skip_delimited(start: int, delim: str) -> int:
        j = start
        while j < n:
            if script[j] == "\\":
                j += 2
                continue
            if script[j] == delim:
                return j + 1
            j += 1
        return -1

    while i < n:
        char = script[i]
        if char in " \t\n;{}":
            i += 1
            continue
        if char == "#":
            newline = script.find("\n", i)
            i = n if newline == -1 else newline + 1
            continue
        while i < n:
            char = script[i]
            if char.isdigit() or char in "$,~+":
                i += 1
            elif char in "/\\":
                if char == "\\":
                    i += 1
                if i >= n:
                    return "unparsable address"
                end = skip_delimited(i + 1, script[i])
                if end < 0:
                    return "unparsable address"
                i = end
                while i < n and script[i] in "IM":
                    i += 1
            else:
                break
        while i < n and script[i] in " \t!":
            i += 1
        if i >= n:
            break
        command = script[i]
        i += 1
        if command in "erRwW":
            return command
        if command in "sy":
            if i >= n:
                return "unparsable s command"
            delim = script[i]
            middle = skip_delimited(i + 1, delim)
            end = skip_delimited(middle, delim) if middle >= 0 else -1
            if end < 0:
                return "unparsable s command"
            i = end
            while i < n and script[i] not in ";\n}#":
                if command == "s" and script[i] in "ew":
                    return f"s///{script[i]}"
                i += 1
        elif command in "aic":
            while i < n and script[i] != "\n":
                i += 2 if script[i] == "\\" else 1
        elif command in ":btT":
            while i < n and script[i] not in ";\n":
                i += 1
    return None


def _check_sed_policy(arg_list: list[str]) -> None:
    """Block in-place editing, script files (-f/--file) and e/r/R/w/W commands however they are spelled."""
    for arg in arg_list:
        if arg == "--":
            break
        if arg.startswith("-") and not arg.startswith("--"):
            # In a bundle (-Ei, -nEi, -ni.bak) -i is read wherever it sits, until a value-taking letter.
            for char in arg[1:]:
                if char == "i":
                    raise ValueError("Blocked by policy: sed: in-place file modification")
                if char in "efl":
                    break
    if _getopt_values(arg_list, shorts="f", longs=frozenset({"--file"}), value_shorts="el"):
        raise ValueError("Blocked by policy: sed: -f/--file script file (uninspected e/r/w commands)")
    for script in _sed_scripts(arg_list):
        found = _sed_unsafe_command(script)
        if found is not None:
            raise ValueError(f"Blocked by policy: sed: {found} (command execution or file access)")


_TAR_VALUE_SHORTS_NO_IF = _TAR_VALUE_SHORTS.replace("I", "").replace("F", "")


def _tar_dashed(arg_list: list[str]) -> list[str]:
    """Rewrite tar's traditional first-argument bundle (``xIf``) as a dashed one."""
    if arg_list and re.fullmatch(r"[A-Za-z]+", arg_list[0]):
        return ["-" + arg_list[0], *arg_list[1:]]
    return list(arg_list)


def _tar_has_short(arg_list: list[str], letter: str) -> bool:
    """Whether a short option letter appears as a flag in a bundle (not inside a value)."""
    for arg in _tar_dashed(arg_list):
        if arg == "--":
            break
        if arg.startswith("-") and not arg.startswith("--"):
            for char in arg[1:]:
                if char == letter:
                    return True
                if char in _TAR_VALUE_SHORTS:
                    break
    return False


def _check_tar_policy(arg_list: list[str]) -> None:
    """Block -I/-F and their long forms anywhere in a bundle: each runs a program."""
    if _getopt_values(
        _tar_dashed(arg_list),
        shorts="IF",
        longs=frozenset({"--use-compress-program", "--info-script", "--new-volume-script"}),
        value_shorts=_TAR_VALUE_SHORTS_NO_IF,
    ):
        raise ValueError("Blocked by policy: tar: -I/-F run an external program (command execution)")


def _tar_transform_unsafe(expression: str) -> bool:
    """Whether a --transform expression rewrites member names to an absolute or parent path."""
    if len(expression) < 2 or expression[0] != "s" or expression[1] in "\\\n;":
        return True
    delimiter = expression[1]
    # Split on unescaped delimiters only: ``s/a\//\/etc\//`` replaces with ``/etc/``.
    parts: list[str] = []
    current: list[str] = []
    i = 2
    while i < len(expression):
        char = expression[i]
        if char == "\\" and i + 1 < len(expression):
            current.append(expression[i : i + 2])
            i += 2
            continue
        if char == delimiter:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    parts.append("".join(current))
    # s<d>pattern<d>replacement<d>flags: a second command after the flags is not inspected.
    if len(parts) != 3 or not re.fullmatch(r"[A-Za-z0-9]*", parts[2]):
        return True
    replacement = re.sub(r"\\(.)", r"\1", parts[1])
    return replacement.startswith("/") or ".." in replacement


# A literal after ">" in awk source: a redirection target or the right side of a comparison.
_AWK_REDIRECT_RE = re.compile(r'>>?\s*"([^"\\]+)"')

# Only source with a print statement can redirect output; other arguments are not scanned.
_AWK_PRINT_RE = re.compile(r"\bprintf?\b")

# Words after which awk expects an operand, so a following "/" opens a regex.
_AWK_OPERAND_EXPECTED_AFTER = frozenset(
    "print printf return if while for do else in delete exit case switch default function func".split()
)
_AWK_CONTROL_WORDS = frozenset({"if", "while", "for", "switch"})


def _awk_string_end(program: str, start: int) -> int:
    """Index after the string literal opening at *start*; -1 when it does not close on its line."""
    i = start + 1
    while i < len(program):
        ch = program[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "\n":
            return -1
        if ch == '"':
            return i + 1
        i += 1
    return -1


def _awk_regex_end(program: str, start: int) -> int:
    """Index after the regex literal opening at *start*; -1 when its end is not certain.

    awk implementations disagree on whether "/" inside a bracket expression ends the
    literal, so that spelling is treated as unreadable rather than guessed at.
    """
    i = start + 1
    in_bracket = False
    while i < len(program):
        ch = program[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "\n":
            return -1
        if in_bracket:
            if ch == "/":
                return -1
            if ch == "]":
                in_bracket = False
        elif ch == "[":
            in_bracket = True
            # A "]" right after "[" or "[^" is a member of the set, not its end.
            if program[i + 1 : i + 2] == "^":
                i += 1
            if program[i + 1 : i + 2] == "]":
                i += 1
        elif ch == "/":
            return i + 1
        i += 1
    return -1


def _awk_plain_target(program: str, start: int) -> str | None:
    """The redirection target at *start* when it is one plain string literal ending the statement."""
    i = start
    while program[i : i + 1] in {" ", "\t"}:
        i += 1
    if program[i : i + 1] != '"':
        return None
    end = _awk_string_end(program, i)
    if end < 0:
        return None
    literal = program[i + 1 : end - 1]
    while program[end : end + 1] in {" ", "\t", "\r"}:
        end += 1
    if "\\" in literal or not literal or program[end : end + 1] not in {"", ";", "}", "\n", "#"}:
        return None
    return literal


class _AwkUnreadable(ValueError):
    """awk source whose string or regex literals cannot be delimited with certainty."""


def _awk_redirect_targets(program: str) -> list[str | None]:
    """Targets of the output redirections in awk source, in order.

    ``None`` stands for a target that cannot be read before the run: a variable, a
    concatenation or an escape sequence. ">" is a redirection only in a print statement
    outside parentheses, and "/" opens a regex only where awk expects an operand; both
    are tracked the way awk's own lexer does. Raises _AwkUnreadable when a literal has
    no certain end, since everything after it could be read wrongly.
    """
    targets: list[str | None] = []
    i, n = 0, len(program)
    in_print = False
    depth = 0
    operand = False
    continues = False
    control_parens: list[bool] = []
    pending_control = False
    while i < n:
        ch = program[i]
        if ch in " \t\r":
            i += 1
            continue
        if ch == "\\" and program[i + 1 : i + 2] == "\n":
            i += 2
            continue
        if ch == "\n":
            if in_print and depth == 0 and not continues:
                in_print = False
            operand = False
            i += 1
            continue
        if ch == "#":
            end = program.find("\n", i)
            i = n if end < 0 else end
            continue
        was_control, pending_control = pending_control, False
        continues = False
        if ch == '"':
            end = _awk_string_end(program, i)
            if end < 0:
                raise _AwkUnreadable("an unterminated string")
            operand = True
            i = end
            continue
        if ch == "/" and not operand:
            end = _awk_regex_end(program, i)
            if end < 0:
                raise _AwkUnreadable('an unterminated regex, or one with "/" inside brackets')
            operand = True
            i = end
            continue
        if ch.isalpha() or ch == "_":
            end = i + 1
            while end < n and (program[end].isalnum() or program[end] == "_"):
                end += 1
            word = program[i:end]
            if word in {"print", "printf"}:
                in_print, depth = True, 0
            pending_control = word in _AWK_CONTROL_WORDS
            operand = word not in _AWK_OPERAND_EXPECTED_AFTER
            i = end
            continue
        if ch.isdigit() or (ch == "." and program[i + 1 : i + 2].isdigit()):
            end = i + 1
            while end < n and (program[end].isalnum() or program[end] == "."):
                end += 1
            operand = True
            i = end
            continue
        if ch in "([":
            control_parens.append(ch == "(" and was_control)
            if in_print:
                depth += 1
            operand = False
        elif ch in ")]":
            # The parenthesis that closes an if/while/for header is followed by a statement.
            operand = not (control_parens.pop() if control_parens else False)
            if in_print and depth > 0:
                depth -= 1
        elif ch in ";{}":
            in_print = False
            operand = False
        elif ch == ">" and in_print and depth == 0:
            end = i + 2 if program[i + 1 : i + 2] == ">" else i + 1
            targets.append(_awk_plain_target(program, end))
            in_print = False
            operand = False
            i = end
            continue
        elif program[i : i + 2] in {"++", "--"}:
            i += 2
            continue
        else:
            continues = ch == "," or program[i : i + 2] in {"&&", "||"}
            operand = False
            if program[i : i + 2] in {"&&", "||"}:
                i += 1
        i += 1
    return targets


# Short options that take a separate value, so the value is not read as a file operand.
_UNIQ_VALUE_FLAGS: frozenset[str] = frozenset({"-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"})
_XXD_VALUE_FLAGS: frozenset[str] = frozenset(
    {"-c", "-cols", "-g", "-groupsize", "-l", "-len", "-n", "-name", "-o", "-offset", "-s", "-seek"}
)


def _file_operands(arg_list: list[str], value_flags: frozenset[str]) -> list[str]:
    """Return the non-option arguments, skipping the values of *value_flags*."""
    operands: list[str] = []
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        if arg == "--":
            operands.extend(arg_list[i + 1 :])
            break
        if arg in value_flags:
            i += 2
            continue
        if not arg.startswith("-") or arg == "-":
            operands.append(arg)
        i += 1
    return operands


def _check_write_destinations(tool_name: str, binary: str, arg_list: list[str]) -> None:
    """Block file-mutating invocations that target a sensitive destination.

    Covers the write-capable system utilities (cp/mv/ln/tee/touch/mkdir), the
    curl/wget output flags (``-o``/``--output``, ``-O``/``--output-document``),
    and the output file of text utilities such as sort, uniq, xxd and awk.
    For ln, both the link path and the symlink target are checked. Positional
    arguments for the file utilities are all checked, since any of them can be a
    destination (cp/mv) and there is no benign reason to write into the blocked
    locations.
    """
    name = tool_name if tool_name in SYSTEM_UTILITIES else binary

    if name in {"sstrip", "rebind", "infect"}:
        for operand in arg_list:
            if not operand.startswith("-"):
                _raise_sensitive_write(name, operand)
        for destination in _flag_values(arg_list, short_flags=frozenset({"-o"}), long_flags=frozenset({"--output"})):
            _raise_sensitive_write(name, destination)
        return

    if name in _WRITE_CAPABLE_TOOLS:
        positionals = [arg for arg in arg_list if not arg.startswith("-") and arg != "--"]
        if name == "cp":
            # cp reads every positional except the last destination.
            positionals = positionals[-1:]
        for arg in positionals:
            if arg.startswith("-") or arg == "--":
                continue
            _raise_sensitive_write(name, arg)
        for dest in _flag_values(
            arg_list,
            short_flags=frozenset({"-t"}),
            long_flags=frozenset({"--target-directory"}),
        ):
            _raise_sensitive_write(name, dest)
        if name in {"cp", "mv", "ln"}:
            # -t also arrives inside a bundle (cp -vt DIR), which the literal match above does not see.
            for dest in _getopt_values(arg_list, shorts="t", longs=frozenset({"--target-directory"}), value_shorts="S"):
                _raise_sensitive_write(name, dest)
        return

    if name == "curl":
        for dest in _flag_values(
            arg_list,
            short_flags=frozenset({"-o", "-D", "-c"}),
            long_flags=frozenset(
                {
                    "--output",
                    "--dump-header",
                    "--cookie-jar",
                    "--trace",
                    "--trace-ascii",
                    "--output-dir",
                }
            ),
        ):
            _raise_sensitive_write(name, dest)
        # The same options inside a bundle, as in the everyday ``curl -sLo FILE``.
        for dest in _getopt_values(arg_list, shorts="oDc", longs=frozenset(), value_shorts=_CURL_VALUE_SHORTS):
            _raise_sensitive_write(name, dest)
        return

    if name == "wget":
        for dest in _flag_values(
            arg_list,
            short_flags=frozenset({"-O", "-o", "-a", "-P"}),
            long_flags=frozenset(
                {
                    "--output-document",
                    "--output-file",
                    "--append-output",
                    "--directory-prefix",
                    "--save-cookies",
                    "--hsts-file",
                    "--rejected-log",
                    "--warc-file",
                }
            ),
        ):
            _raise_sensitive_write(name, dest)
        for dest in _getopt_values(arg_list, shorts="OoaP", longs=frozenset(), value_shorts=_WGET_VALUE_SHORTS):
            _raise_sensitive_write(name, dest)
        return

    if name == "tsk_recover":
        # The last operand is the directory the recovered files are written into.
        operands = [arg for arg in arg_list if not arg.startswith("-")]
        if operands:
            _raise_sensitive_write(name, operands[-1])
        return

    if name in ("nmap", "masscan"):
        # Scanner output flags write to an operator-named file; block clobbering a
        # sensitive path. -oA takes a basename that expands to several files.
        # nmap also accepts the double-dash spellings (--oN FILE).
        for i, arg in enumerate(arg_list):
            match = re.fullmatch(r"--?o[NXGSALJB](.*)", arg)
            if match and match.group(1):
                _raise_sensitive_write(name, match.group(1).removeprefix("="))
            elif match and i + 1 < len(arg_list):
                _raise_sensitive_write(name, arg_list[i + 1])
            option, sep, value = arg.partition("=")
            if option == "--output-filename":
                if sep:
                    _raise_sensitive_write(name, value)
                elif i + 1 < len(arg_list):
                    _raise_sensitive_write(name, arg_list[i + 1])
        return

    if name in ("tcpdump", "tshark"):
        for dest in _flag_values(arg_list, short_flags=frozenset({"-w"}), long_flags=frozenset()):
            _raise_sensitive_write(name, dest)
        return

    if name == "tar":
        bundles = _tar_short_bundles(arg_list)
        # Extraction writes below CWD unless -C/--directory selects a target.
        extracting = any(arg in ("--extract", "--get") for arg in arg_list) or any("x" in bundle for bundle in bundles)
        if extracting:
            directories = _flag_values(
                arg_list,
                short_flags=frozenset({"-C"}),
                long_flags=frozenset({"--directory"}),
            )
            directories.extend(_tar_short_flag_values(arg_list, "C"))
            for arg in arg_list:
                option, sep, value = arg.partition("=")
                if sep and len(option) > 2 and option.startswith("--") and "--one-top-level".startswith(option):
                    directories.append(value)
            for dest in directories or [os.getcwd()]:
                _raise_sensitive_write(name, dest)
            if _tar_has_short(arg_list, "P") or any(
                arg.startswith("--") and len(arg) > 3 and "--absolute-names".startswith(arg.partition("=")[0])
                for arg in arg_list
            ):
                raise ValueError("Blocked by policy: tar: absolute member names can write anywhere")
            for expression in _getopt_values(
                _tar_dashed(arg_list),
                shorts="",
                longs=frozenset({"--transform", "--xform"}),
                value_shorts=_TAR_VALUE_SHORTS,
            ):
                if _tar_transform_unsafe(expression):
                    raise ValueError(
                        "Blocked by policy: tar: --transform may rewrite members to an absolute or parent path"
                    )

        # Create/append/update modes write the archive named by -f/--file.
        writing_archive = any(arg in ("--create", "--append", "--update") for arg in arg_list) or any(
            any(mode in bundle for mode in "cru") for bundle in bundles
        )
        if writing_archive:
            archives = _flag_values(
                arg_list,
                short_flags=frozenset({"-f"}),
                long_flags=frozenset({"--file"}),
            )
            archives.extend(_tar_short_flag_values(arg_list, "f"))
            for dest in archives:
                _raise_sensitive_write(name, dest)
        return

    if name == "unzip":
        destinations = _flag_values(arg_list, short_flags=frozenset({"-d"}))
        destinations.extend(_getopt_values(arg_list, shorts="d", longs=frozenset(), value_shorts=_UNZIP_VALUE_SHORTS))
        for dest in destinations or [os.getcwd()]:
            _raise_sensitive_write(name, dest)
        return

    if name == "7z":
        destinations = _flag_values(arg_list, short_flags=frozenset({"-o"}))
        command = next((arg for arg in arg_list if not arg.startswith("-")), "")
        if command in {"x", "e"} and any(arg.lower().startswith("-spf") for arg in arg_list):
            raise ValueError("Blocked by policy: 7z: -spf extracts to the absolute paths stored in the archive")
        if command in {"x", "e"}:
            destinations = destinations or [os.getcwd()]
        elif command in {"a", "u", "d", "rn"}:
            positionals = [arg for arg in arg_list if not arg.startswith("-")]
            destinations.extend(positionals[1:2])
        for dest in destinations:
            _raise_sensitive_write(name, dest)
        return

    if name == "zip":
        for target in _zip_write_targets(arg_list):
            _raise_sensitive_write(name, target)
        return

    if name in {"gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz"}:
        # Without stdout mode these tools replace or create files beside each input.
        if not any(arg in {"-c", "--stdout", "--to-stdout"} for arg in arg_list):
            for path in (arg for arg in arg_list if not arg.startswith("-")):
                _raise_sensitive_write(name, path)
        return

    if name == "openssl":
        for dest in _flag_values(
            arg_list,
            short_flags=frozenset({"-out", "-keyout", "-writerand"}),
        ):
            _raise_sensitive_write(name, dest)
        return

    if name in {"gpg", "age"}:
        for dest in _flag_values(
            arg_list,
            short_flags=frozenset({"-o"}),
            long_flags=frozenset({"--output"}),
        ):
            _raise_sensitive_write(name, dest)
        return

    if name == "ssh-keygen":
        for dest in _flag_values(arg_list, short_flags=frozenset({"-f"})):
            _raise_sensitive_write(name, dest)
        return

    if name in {"convert", "magick"}:
        positionals = [arg for arg in arg_list if not arg.startswith("-")]
        if positionals:
            _raise_sensitive_write(name, positionals[-1])
        for flag, dest in zip(arg_list, arg_list[1:]):
            if flag == "-write":
                _raise_sensitive_write(name, dest)
        return

    if name == "exiftool":
        for dest in _flag_values(arg_list, short_flags=frozenset({"-w", "-W", "-o", "-textOut"})):
            _raise_sensitive_write(name, dest)
        return

    if name == "steghide":
        for dest in _flag_values(
            arg_list,
            short_flags=frozenset({"-xf", "-sf"}),
            long_flags=frozenset({"--extractfile", "--stegofile"}),
        ):
            _raise_sensitive_write(name, dest)
        return

    if name == "csvtool":
        for dest in _flag_values(arg_list, short_flags=frozenset({"-o"}), long_flags=frozenset({"--output"})):
            _raise_sensitive_write(name, dest)
        return

    if name in {"strace", "ltrace"}:
        for dest in _getopt_values(
            arg_list,
            shorts="o",
            longs=frozenset({"--output"}),
            value_shorts="".join(sorted(_TRACER_SHORT_REQUIRED[name] - {"o"})),
        ):
            _raise_sensitive_write(name, dest)
        return

    if name == "sqlmap":
        for dest in _flag_values(
            arg_list,
            short_flags=frozenset({"-t", "-s"}),
            long_flags=frozenset({"--output-dir", "--traffic-file", "--har"}),
        ):
            _raise_sensitive_write(name, dest)
        return

    if name == "binwalk":
        for dest in _getopt_values(arg_list, shorts="C", longs=frozenset({"--directory"})):
            _raise_sensitive_write(name, dest)
        return

    if name in {"foremost", "qrencode"}:
        for dest in _flag_values(
            arg_list,
            short_flags=frozenset({"-o"}),
            long_flags=frozenset({"--output"}),
        ):
            _raise_sensitive_write(name, dest)
        return

    if name == "pdftotext":
        positionals = [arg for arg in arg_list if not arg.startswith("-")]
        if len(positionals) >= 2:
            _raise_sensitive_write(name, positionals[-1])
        elif positionals:
            source = _normalize_write_path(positionals[0])
            if source:
                _raise_sensitive_write(name, os.path.splitext(source)[0] + ".txt")
        return

    if name in {"sort", "shuf"}:
        # Both use getopt_long, so -o also arrives abbreviated (--outp=) or bundled (-uo).
        value_shorts = "kStT" if name == "sort" else "in"
        for dest in _getopt_values(arg_list, shorts="o", longs=frozenset({"--output"}), value_shorts=value_shorts):
            _raise_sensitive_write(name, dest)
        return

    if name == "xmllint":
        # xmllint compares whole option names and takes the file as the next argument.
        for flag, dest in zip(arg_list, arg_list[1:]):
            if flag in {"-o", "-output", "--output"}:
                _raise_sensitive_write(name, dest)
        return

    if name in {"uniq", "xxd"}:
        # Both take an optional second file operand that names the output. Every operand
        # after the first is checked: an option value in a spelling the tables do not list
        # is counted as an operand and would otherwise push the output out of second place.
        operands = _file_operands(arg_list, _UNIQ_VALUE_FLAGS if name == "uniq" else _XXD_VALUE_FLAGS)
        for dest in operands[1:]:
            _raise_sensitive_write(name, dest)
        return

    if name in {"awk", "gawk"}:
        # gawk writes these reports to the named file. A redirection is allowed only
        # to a file name spelled out as one literal, which is then checked like any other.
        for dest in _getopt_values(
            arg_list,
            shorts="opd",
            longs=frozenset({"--pretty-print", "--profile", "--dump-variables"}),
            value_shorts="fFveEilLD",
        ):
            _raise_sensitive_write(name, dest)
        for arg in arg_list:
            for dest in _AWK_REDIRECT_RE.findall(arg):
                _raise_sensitive_write(name, dest)
            try:
                targets = _awk_redirect_targets(arg) if _AWK_PRINT_RE.search(arg) else []
            except _AwkUnreadable as exc:
                raise ValueError(
                    f"Blocked by policy: awk: the program has {exc}, so its print statements "
                    "cannot be checked for output redirection"
                ) from None
            for dest in targets:
                if dest is None:
                    raise ValueError(
                        "Blocked by policy: awk: output redirection to a file name that is not one plain "
                        'string literal. Spell the name out, as in print > "out.txt"'
                    )
                _raise_sensitive_write(name, dest)
        return

    if name == "yq" and any(arg in {"-i", "--inplace"} for arg in arg_list):
        for path in (arg for arg in arg_list if not arg.startswith("-")):
            _raise_sensitive_write(name, path)


# Tracers whose command line names a program to execute.
_TRACER_SHORT_REQUIRED = {
    "strace": frozenset("abeEIoOpPsSuUX"),
    "ltrace": frozenset("aADeFlnopsuwx"),
}
_TRACER_SHORT_FLAGS = {
    "strace": frozenset("AcCdDfFhiknNqrtTvVwxyYzZ"),
    "ltrace": frozenset("bcCfhiLrStTV"),
}
_TRACER_LONG_REQUIRED = {
    "strace": frozenset(
        "env attach user argv0 detach-on interruptible trace signals status trace-fds trace-path columns "
        "abbrev verbose raw read write kvm stack-trace-frame-limit syscall-limit "
        "string-limit output const-print-style decode-pids summary-syscall-overhead "
        "summary-sort-by summary-columns inject fault".split()
    ),
    "ltrace": frozenset("align debug config library indent output where".split()),
}
# Version-dependent or optional values must be inline so a program operand cannot be consumed as an option value.
_TRACER_LONG_OPTIONAL = {
    "strace": frozenset(
        "daemonize daemonised daemonized color secontext stack-trace stack-traces relative-timestamps "
        "absolute-timestamps timestamps syscall-times strings-in-hex tips namespace quiet silent silence "
        "decode-fds".split()
    ),
    "ltrace": frozenset(),
}
_TRACER_LONG_FLAGS = {
    "strace": frozenset(
        "follow-forks kill-on-exit successful-only failed-only failing-only instruction-pointer syscall-number "
        "arg-names "
        "output-append-mode output-separately no-abbrev always-show-pid summary-only summary "
        "summary-wall-clock debug help seccomp-bpf version pidns-translation".split()
    ),
    "ltrace": frozenset("no-signals demangle help version".split()),
}


def _check_tracer_attach_only(binary: str, arg_list: list[str]) -> None:
    """Reject program operands after parsing the tracer's known options."""
    launch_error = (
        f"Blocked by policy: {binary} launches the program named on its command line; "
        "only attaching to a running process (-p PID) is permitted — use run_script to trace a new program"
    )
    attached = False
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        i += 1
        if arg == "--":
            if i < len(arg_list):
                raise ValueError(launch_error)
            break
        if not arg.startswith("-") or arg == "-":
            raise ValueError(launch_error)
        options: list[tuple[str, str | None]] = []
        if arg.startswith("--"):
            name, sep, value = arg[2:].partition("=")
            known = _TRACER_LONG_REQUIRED[binary] | _TRACER_LONG_OPTIONAL[binary] | _TRACER_LONG_FLAGS[binary]
            matches = [option for option in known if option.startswith(name)]
            if name not in known:
                if not name or len(matches) != 1:
                    raise ValueError(f"Blocked by policy: {binary} attach-only policy cannot validate option {arg}")
                name = matches[0]
            if name in _TRACER_LONG_REQUIRED[binary] and not sep:
                if i >= len(arg_list):
                    raise ValueError(f"Blocked by policy: {binary} option --{name} requires a value")
                value = arg_list[i]
                i += 1
            elif name in _TRACER_LONG_FLAGS[binary] and sep:
                raise ValueError(f"Blocked by policy: {binary} option --{name} does not take a value")
            options.append((name, value if sep or name in _TRACER_LONG_REQUIRED[binary] else None))
        else:
            cluster = arg[1:]
            for pos, name in enumerate(cluster):
                if name in _TRACER_SHORT_REQUIRED[binary]:
                    value = cluster[pos + 1 :]
                    if not value:
                        if i >= len(arg_list):
                            raise ValueError(f"Blocked by policy: {binary} option -{name} requires a value")
                        value = arg_list[i]
                        i += 1
                    options.append((name, value))
                    break
                if name not in _TRACER_SHORT_FLAGS[binary]:
                    raise ValueError(f"Blocked by policy: {binary} attach-only policy cannot validate option -{name}")
                options.append((name, None))
        for name, value in options:
            if name in {"p", "attach"}:
                pid_pattern = r"[1-9]\d*(?:[,\s]+[1-9]\d*)*" if binary == "strace" else r"[1-9]\d*"
                if value is None or re.fullmatch(pid_pattern, value) is None:
                    raise ValueError(f"Blocked by policy: {binary} requires a positive PID for attaching")
                attached = True
            if binary == "strace" and name in {"o", "output"} and value and value.startswith(("|", "!")):
                raise ValueError("Blocked by policy: strace output command executes a shell")
    if not attached:
        raise ValueError(launch_error)


def _getopt_flag_given(
    arg_list: list[str], *, shorts: str, longs: frozenset[str] = frozenset(), value_shorts: str = ""
) -> bool:
    """Whether one of the named options appears, as getopt_long or argparse reads it.

    A short option counts inside a bundle (``-nr``) until a value-taking option starts its
    value, and a long option through any prefix of its name (``--ru``).
    """
    for arg in arg_list:
        if arg == "--":
            break
        if arg.startswith("--"):
            name = arg[2:].partition("=")[0]
            if name and any(flag[2:].startswith(name) for flag in longs):
                return True
        elif arg.startswith("-") and len(arg) > 1:
            for char in arg[1:]:
                if char in shorts:
                    return True
                if char in value_shorts:
                    break
    return False


_RUNNER_HELP_FLAGS = frozenset({"-h", "-help", "--help"})
_QEMU_INFO_FLAGS = _RUNNER_HELP_FLAGS | {"-version", "--version"}
# Each runs the program, machine image or console commands named on its command line,
# which is run_script's job: through run_tool it gives help and version output only.
# Values: (flags accepted as the only argument, options accepted with the single value
# "help", names it is reached by).
_INFO_ONLY_RUNNERS: dict[str, tuple[frozenset[str], frozenset[str], tuple[str, ...]]] = {
    "valgrind": (_RUNNER_HELP_FLAGS | {"--help-debug", "--help-dyn-options", "--version"}, frozenset(), ()),
    "qemu-user-static": (_QEMU_INFO_FLAGS, frozenset({"-cpu", "-d", "-trace"}), ("qemu-x86_64-static", "qemu-x86_64")),
    "qemu-system-x86": (
        _QEMU_INFO_FLAGS,
        frozenset({"-accel", "-cpu", "-d", "-device", "-M", "-machine", "-trace"}),
        ("qemu-system-x86_64",),
    ),
    "proxychains4": (_RUNNER_HELP_FLAGS, frozenset(), ()),
    "honggfuzz": (_RUNNER_HELP_FLAGS, frozenset(), ()),
    "aflplusplus": (_RUNNER_HELP_FLAGS, frozenset(), ("afl-fuzz",)),
    "metasploit": (_RUNNER_HELP_FLAGS | {"-v", "-V", "--version"}, frozenset(), ("msfconsole",)),
}


# What run_tool leaves each restricted tool, keyed by casefolded registry name, for the
# access guidance get_tool_info and the advisors return.
_ATTACH_ONLY_NOTE = "run_tool attaches to a running process (-p PID) only; trace a new program through run_script."
_R2_NOTE = (
    "run_tool permits read-only analysis commands; debugging, writes, plugins, projects, shell and remote io "
    "are refused."
)
RUN_TOOL_ROUTE_NOTES: dict[str, str] = {
    "strace": _ATTACH_ONLY_NOTE,
    "ltrace": _ATTACH_ONLY_NOTE,
    "gdb": "run_tool permits static inspection; running the inferior, calls, scripts and file writes are refused.",
    "rr": "run_tool inspects recorded traces (ps, dump, sources, traceinfo); record and replay through run_script.",
    "radare2": _R2_NOTE,
    "rizin": _R2_NOTE,
    "pwntools": "run_tool refuses debug, template and update, and --run/--debug of asm, shellcraft and scramble.",
    "volatility3": "run_tool refuses --plugin-dirs.",
    "frida-tools": "run_tool instruments a USB (-U), device-ID (-D) or remote-host IP (-H) target only.",
}


def _check_info_only_runner(name: str, arg_list: list[str]) -> None:
    flags, help_options, _ = _INFO_ONLY_RUNNERS[name]
    if (len(arg_list) == 1 and arg_list[0] in flags) or (
        len(arg_list) == 2 and arg_list[0] in help_options and arg_list[1] == "help"
    ):
        return
    raise ValueError(
        f"Blocked by policy: {name} runs the program, image or console commands given on its command line; "
        "run_tool permits its help and version output only — use run_script (CYBERSEC_MCP_ALLOW_SCRIPTS=1)"
    )


# rr subcommands that read a recorded trace. record, replay and rerun execute it, and a first
# word rr does not know as a command is recorded as a program.
_RR_INSPECTION_COMMANDS = frozenset({"buildid", "cpufeatures", "dump", "help", "ls", "ps", "sources", "traceinfo"})


def _check_rr_policy(arg_list: list[str]) -> None:
    if arg_list in (["-h"], ["--help"], ["-V"], ["--version"]) or (arg_list and arg_list[0] in _RR_INSPECTION_COMMANDS):
        return
    raise ValueError(
        "Blocked by policy: rr records or replays the program on its command line; run_tool permits "
        "trace inspection (ps, dump, sources, traceinfo, ...) only — use run_script to record or replay"
    )


# pwn subcommands refused outright. template also renders ~/.config/pwntools/templates/pwnup.mako
# when that file exists, so it runs Python code even without --template.
_PWN_BLOCKED_COMMANDS = {
    "debug": "starts gdb on a program or process",
    "template": "renders a Mako template, which runs Python code",
    "update": "installs packages from the network",
}
# Subcommands whose -r/--run or -d/--debug executes the shellcode they build, with their
# value-taking short options and their output option.
_PWN_SHELLCODE_COMMANDS = {
    "asm": ("fovcei", "--output"),
    "scramble": ("fovc", "--output"),
    "shellcraft": ("ofv", "--out"),
}


def _check_pwntools_policy(arg_list: list[str]) -> None:
    command_index = next((i for i, arg in enumerate(arg_list) if not arg.startswith("-")), None)
    if command_index is None:
        return
    command, rest = arg_list[command_index], arg_list[command_index + 1 :]
    if command in _PWN_BLOCKED_COMMANDS:
        raise ValueError(f"Blocked by policy: pwn {command} {_PWN_BLOCKED_COMMANDS[command]}")
    if command in _PWN_SHELLCODE_COMMANDS:
        value_shorts, output = _PWN_SHELLCODE_COMMANDS[command]
        if _getopt_flag_given(rest, shorts="rd", longs=frozenset({"--run", "--debug"}), value_shorts=value_shorts):
            raise ValueError(f"Blocked by policy: pwn {command} --run/--debug executes the shellcode")
        for destination in _getopt_values(
            rest, shorts="o", longs=frozenset({output}), value_shorts=value_shorts.replace("o", "")
        ):
            _raise_sensitive_write(f"pwn {command}", destination)
    elif command == "pwnstrip":
        for destination in _getopt_values(rest, shorts="o", longs=frozenset({"--output"}), value_shorts="p"):
            _raise_sensitive_write("pwn pwnstrip", destination)
    elif command == "disablenx":
        for operand in rest:
            if not operand.startswith("-"):
                _raise_sensitive_write("pwn disablenx", operand)
    elif command == "libcdb" and not _allow_external():
        subcommand = next((arg for arg in rest if not arg.startswith("-")), None)
        offline = any(_git_option_matches(arg, "--offline-only") for arg in rest)
        download = _getopt_flag_given(rest, shorts="d", longs=frozenset({"--download-libc"}), value_shorts="tso")
        if subcommand != "file" and not (subcommand in {"lookup", "hash"} and offline and not download):
            raise ValueError(
                "Blocked by policy: pwn libcdb queries online libc databases; use 'libcdb file', "
                "--offline-only, or set CYBERSEC_MCP_ALLOW_EXTERNAL=1 for authorized lookups"
            )


# volatility3 options that take a value; -p/--plugin-dirs imports Python from the directory named.
_VOL_VALUE_SHORTS = "cepslofur"


def _check_volatility_policy(arg_list: list[str]) -> None:
    if _getopt_flag_given(arg_list, shorts="p", longs=frozenset({"--plugin-dirs"}), value_shorts=_VOL_VALUE_SHORTS):
        raise ValueError("Blocked by policy: volatility3: --plugin-dirs imports Python plugins from a chosen directory")
    for destination in _getopt_values(
        arg_list,
        shorts="lo",
        longs=frozenset({"--log", "--output-dir", "--save-config", "--cache-path"}),
        value_shorts="cepsfur",
    ):
        _raise_sensitive_write("volatility3", destination)
    if not _allow_external():
        for url in _getopt_values(arg_list, shorts="u", longs=frozenset({"--remote-isf-url"}), value_shorts="cepslofr"):
            if not _is_safe_target(_network_target_host(url)):
                raise ValueError(
                    f"Blocked by policy: volatility3: remote ISF URL '{url}' is not in a private/local range. "
                    "Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 for authorized external resource URLs."
                )


_FRIDA_VALUE_SHORTS = "ODHfnNpWlPCcteo"
# Device IDs that name this machine (socket is the frida-server on 127.0.0.1); barebone drives a local GDB stub.
_FRIDA_LOCAL_DEVICES = frozenset({"local", "socket", "barebone"})


def _frida_values(arg_list: list[str], short: str, long: str) -> list[str]:
    return _getopt_values(
        arg_list, shorts=short, longs=frozenset({long}), value_shorts=_FRIDA_VALUE_SHORTS.replace(short, "")
    )


def _address_is_this_machine(address: str) -> bool:
    """Loopback, unspecified (both also IPv4-mapped), or an address assigned to one of this host's interfaces."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified:
        return True
    # Binding succeeds only for an address one of this host's interfaces carries.
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.bind((str(ip), 0))
    except OSError:
        return False
    return True


def _check_frida_policy(arg_list: list[str]) -> None:
    """Allow instrumentation of a USB, device-ID or remote-host target, never of this machine."""
    if arg_list in (["-h"], ["--help"], ["--version"]):
        return
    if _getopt_flag_given(arg_list, shorts="O", longs=frozenset({"--options-file"}), value_shorts=_FRIDA_VALUE_SHORTS):
        raise ValueError("Blocked by policy: frida: --options-file adds options the policy cannot inspect")
    for destination in _frida_values(arg_list, "o", "--output"):
        _raise_sensitive_write("frida", destination)
    if not _allow_external() and (
        _frida_values(arg_list, "c", "--codeshare")
        or _getopt_flag_given(arg_list, shorts="", longs=frozenset({"--p2p", "--relay", "--stun-server"}))
    ):
        raise ValueError(
            "Blocked by policy: frida: codeshare scripts and peer-to-peer relays reach external services; "
            "set CYBERSEC_MCP_ALLOW_EXTERNAL=1 for authorized use"
        )
    hosts = _frida_values(arg_list, "H", "--host")
    for host in hosts:
        address = _network_target_host(host).strip("[]")
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise ValueError(
                f"Blocked by policy: frida: -H takes an IP address, not '{host}': a name can resolve elsewhere "
                "by the time frida connects"
            ) from None
        if _address_is_this_machine(address):
            raise ValueError("Blocked by policy: frida: a frida-server on this machine instruments its processes")
        if not _allow_external() and not _is_safe_target(address):
            raise ValueError(
                f"Blocked by policy: frida: host '{host}' is not in a private/local range. "
                "Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 for authorized external targets."
            )
    devices = _frida_values(arg_list, "D", "--device")
    usb = _getopt_flag_given(arg_list, shorts="U", longs=frozenset({"--usb"}), value_shorts=_FRIDA_VALUE_SHORTS)
    local_server = _getopt_flag_given(
        arg_list, shorts="R", longs=frozenset({"--remote"}), value_shorts=_FRIDA_VALUE_SHORTS
    )
    if local_server or any(device in _FRIDA_LOCAL_DEVICES for device in devices) or not (usb or hosts or devices):
        raise ValueError(
            "Blocked by policy: frida instruments processes on this machine; run_tool permits a USB (-U), "
            "device-ID (-D) or remote-host IP (-H) target only — use run_script for local instrumentation"
        )


# radare2/rizin short options that take a value. Options whose argument-taking is version
# dependent (-H, -p) are read as flags, so the argument after them is still checked.
_R2_VALUE_SHORTS = "abBcDeFiIklmPrRs"
_R2_BLOCKED_SHORTS = {
    "d": "debugs (starts or attaches to) a program",
    "D": "debugs (starts or attaches to) a program",
    "r": "loads a run profile, which starts a program",
    "R": "applies a run directive, which starts a program",
    "w": "opens the file for writing",
    "l": "loads a plugin library",
    "p": "loads a project, which replays saved commands",
    "P": "applies a patch file to the binary",
    "C": "connects to a remote server",
    "=": "runs commands on a remote server",
    "i": "runs a script file",
    "I": "runs a script file",
}
# io backends that are local buffers or containers; others (rap, gdb, http, tcp, winedbg, ...) reach out.
_R2_LOCAL_SCHEMES = frozenset({"apk", "base64", "ihex", "malloc", "null", "sparse", "srec", "zip"})
# First characters of the read-only analysis commands run_tool permits: analysis (a), metadata (C),
# config (e, checked below), flags (f), info (i), print (p), quit (q), seek (s), types (t),
# hexdump (x), search (/) and help (?).
_R2_COMMAND_FAMILIES = frozenset("aCefipqstx/?")
# Within those families: iO dumps or resizes, idp fetches PDBs, ?t/?+/?-/?? run a nested command;
# an ag graph in the w format is rendered by running dot.
_R2_BLOCKED_COMMAND_PREFIXES = ("iO", "idp", "?t", "?+", "?-", "??")
_R2_GRAPH_WRITE_RE = re.compile(r"ag\S*w")
_R2_SAFE_CONFIG_PREFIXES = ("anal.", "analysis.", "asm.", "emu.")
_R2_SAFE_CONFIG_KEYS = frozenset(
    {"bin.cache", "bin.demangle", "bin.relocs", "bin.strings", "io.cache", "scr.color", "scr.interactive", "scr.utf8"}
)


def _r2_config_safe(setting: str) -> bool:
    key = setting.partition("=")[0].strip()
    return key.startswith(_R2_SAFE_CONFIG_PREFIXES) or key in _R2_SAFE_CONFIG_KEYS


def _check_r2_commands(binary: str, commands: str) -> None:
    for segment in re.split(r"[;\r\n]", commands):
        segment = segment.strip()
        if not segment:
            continue
        # Shell escapes and pipes (!, |), file redirection (>), command substitution (`, $(),
        # iteration over a command's output (@@c) and temporary config (@e:).
        if re.search(r"[!|>`]|\$\(|@@c|@e:", segment, re.IGNORECASE):
            raise ValueError(f"Blocked by policy: {binary}: shell, redirection or nested commands in '{segment}'")
        word, _, setting = segment.partition(" ")
        if segment[0] == "e":
            if word != "e" or ("=" in setting and not _r2_config_safe(setting)):
                raise ValueError(f"Blocked by policy: {binary}: config change '{segment}' is not permitted")
            continue
        if (
            segment[0] not in _R2_COMMAND_FAMILIES
            or segment.startswith(_R2_BLOCKED_COMMAND_PREFIXES)
            or _R2_GRAPH_WRITE_RE.match(word)
        ):
            raise ValueError(
                f"Blocked by policy: {binary}: '{word}' is outside the read-only analysis commands "
                "run_tool permits (a, C, f, i, p, s, t, x, /, ?) — use run_script for the rest"
            )


def _check_r2_policy(binary: str, arg_list: list[str]) -> None:
    for arg in arg_list:
        for scheme in re.findall(r"([A-Za-z][A-Za-z0-9+.-]*)://", arg):
            if scheme.lower() not in _R2_LOCAL_SCHEMES:
                raise ValueError(f"Blocked by policy: {binary}: {scheme}:// opens a remote or debugger backend")
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        i += 1
        if arg == "--":
            break
        if not arg.startswith("-") or arg == "-":
            continue
        cluster = arg[1:]
        for pos, char in enumerate(cluster):
            if char in _R2_BLOCKED_SHORTS:
                raise ValueError(f"Blocked by policy: {binary}: -{char} {_R2_BLOCKED_SHORTS[char]}")
            if char in _R2_VALUE_SHORTS:
                value = cluster[pos + 1 :]
                if not value and i < len(arg_list):
                    value = arg_list[i]
                    i += 1
                if char == "c":
                    _check_r2_commands(binary, value)
                elif char == "e" and not _r2_config_safe(value):
                    raise ValueError(f"Blocked by policy: {binary}: config change '{value}' is not permitted")
                break


def _gdb_is(token: str, full: str, minimum: int) -> bool:
    """Whether *token* is *full* or an unambiguous-enough abbreviation (gdb resolves prefixes)."""
    return len(token) >= minimum and full.startswith(token)


# Commands that run code, reach the network, or write files; (full name, shortest abbreviation checked).
_GDB_BLOCKED_COMMANDS: tuple[tuple[str, int], ...] = (
    ("source", 2),
    ("pipe", 2),
    ("target", 2),
    ("attach", 2),
    ("call", 2),
    ("edit", 2),
    ("guile", 2),
    ("dump", 2),
    ("append", 2),
    ("restore", 3),
    ("save", 2),
    ("shell", 2),
    ("compile", 4),
    ("gcore", 4),
    ("generate-core-file", 3),
)
_GDB_EXPRESSION_COMMANDS = frozenset({"print", "p", "inspect", "output", "set", "display", "x", "printf"})
_GDB_CALL_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*\(")
_GDB_CALL_SAFE = frozenset({"sizeof", "alignof", "_Alignof"})
_GDB_APPLY_SPEC_RE = re.compile(r"[0-9$*][\w.$*-]*")


def _gdb_nested_command(tokens: list[str]) -> list[str] | None:
    """The command a wrapper runs: ``server``, ``thread|frame apply``, ``taas``, ``faas``, ``tfaas``.

    The wrapper's own first word hides the command from the first-word checks, so the policy
    reads the nested one. Returns None when *tokens* is not such a wrapper or names no command.
    """
    first = tokens[0]
    rest: list[str]
    if _gdb_is(first, "server", 3) or first in {"taas", "faas", "tfaas"}:
        rest = tokens[1:]
    elif (
        (_gdb_is(first, "thread", 1) or _gdb_is(first, "frame", 1))
        and len(tokens) > 2
        and _gdb_is(tokens[1], "apply", 1)
    ):
        rest = tokens[2:]
        if rest and rest[0] == "all":
            rest = rest[1:]
        else:
            while rest and _GDB_APPLY_SPEC_RE.fullmatch(rest[0]):
                rest = rest[1:]
    else:
        return None
    while rest and (rest[0] == "--" or (rest[0].startswith("-") and len(rest[0]) > 1 and rest[0][1].isalpha())):
        rest = rest[1:]
    return rest or None


def _check_gdb_command(tokens: list[str]) -> None:
    """Check one parsed gdb command (its words, quotes removed) against the policy."""
    nested = _gdb_nested_command(tokens)
    if nested is not None:
        _check_gdb_command(nested)
    first = tokens[0]
    if re.match(r"(?:r(?:u(?:n)?)?|start(?:i)?)(?:$|[^a-zA-Z0-9_-])", first):
        raise ValueError("Blocked by policy: gdb: run/start executes the inferior")
    if (
        first in {"ali", "alia", "alias", "ev", "eva", "eval", "w", "wi", "wit", "with"}
        or len(first) >= 3
        and "interpreter-exec".startswith(first)
    ):
        raise ValueError("Blocked by policy: gdb: nested command evaluation")
    base = first.split("/", 1)[0]
    if base.startswith("|") or any(_gdb_is(base, full, minimum) for full, minimum in _GDB_BLOCKED_COMMANDS):
        raise ValueError(f"Blocked by policy: gdb: '{base}' runs code, connects out or writes files")
    if (
        _gdb_is(base, "set", 3)
        and len(tokens) > 1
        and any(_gdb_is(tokens[1], word, 2) for word in ("logging", "history"))
    ):
        raise ValueError("Blocked by policy: gdb: set logging/history writes files")
    if base in _GDB_EXPRESSION_COMMANDS or _gdb_is(base, "print", 2) or _gdb_is(base, "set", 3):
        for name in _GDB_CALL_RE.findall(" ".join(tokens[1:])):
            if name not in _GDB_CALL_SAFE:
                raise ValueError("Blocked by policy: gdb: function calls in expressions execute code in the inferior")


def _check_gdb_execution_commands(arg_list: list[str]) -> None:
    """Check evaluation commands without interpreting their symbol arguments as commands."""
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        i += 1
        if arg == "--":
            break
        if not arg.startswith("-"):
            continue
        name, sep, command = arg.lstrip("-").partition("=")
        if name not in {"ex", "iex"} and not (
            len(name) >= 2 and any(option.startswith(name) for option in ("eval-command", "init-eval-command"))
        ):
            continue
        if not sep:
            if i >= len(arg_list):
                continue
            command = arg_list[i]
            i += 1
        # Quoted strings remain single tokens so an echo or print argument cannot
        # turn a mentioned command into an execution-policy false positive.
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";\r\n")
        lexer.whitespace = " \t"
        lexer.whitespace_split = True
        lexer.commenters = ""
        segment: list[str] = []
        for token in lexer:
            if token and all(char in ";\r\n" for char in token):
                if segment:
                    _check_gdb_command(segment)
                segment = []
            else:
                segment.append(token)
        if segment:
            _check_gdb_command(segment)


_TAKAJO_OFFLINE_COMMANDS = frozenset(
    "automagic convert-flatten-json extract-credentials extract-scriptblocks html-report "
    "list-domains list-hashes list-ip-addresses list-undetected-evtx list-unused-rules "
    "split-csv-timeline split-json-timeline metrics-computers metrics-users "
    "stack-cmdlines stack-computers stack-dns stack-ip-addresses stack-logons "
    "stack-processes stack-services stack-tasks stack-users sysmon-process-tree "
    "timeline-logon timeline-partition-diagnostic timeline-suspicious-processes timeline-tasks "
    "ttp-summary ttp-visualize ttp-visualize-sigma".split()
)
_TAKAJO_RESTRICTED_COMMANDS = frozenset({"html-server", "vt-domain-lookup", "vt-hash-lookup", "vt-ip-lookup"})
_TAKAJO_BOOLEAN_SHORT_FLAGS = {
    command: frozenset("h" + flags)
    for commands, flags in (
        ("automagic", "sdq"),
        ("convert-flatten-json extract-credentials", "qs"),
        (
            "extract-scriptblocks list-hashes metrics-computers metrics-users stack-dns stack-tasks "
            "timeline-partition-diagnostic timeline-suspicious-processes timeline-tasks ttp-summary ttp-visualize",
            "sq",
        ),
        ("html-report", "qC"),
        ("list-domains", "dwsq"),
        ("list-ip-addresses", "iOspq"),
        ("list-undetected-evtx list-unused-rules split-json-timeline sysmon-process-tree ttp-visualize-sigma", "q"),
        ("split-csv-timeline", "mq"),
        ("stack-cmdlines stack-processes stack-services", "yesq"),
        ("stack-computers", "csq"),
        ("stack-ip-addresses", "asq"),
        ("stack-logons", "lfsq"),
        ("stack-users", "scfq"),
        ("timeline-logon", "clasq"),
    )
    for command in commands.split()
}
_TAKAJO_OUTPUT_PREFIX_CONFLICTS = {
    "list-ip-addresses": ("outbound",),
    "timeline-logon": ("outputadminlogonevents", "outputlogoffevents"),
    "timeline-tasks": ("outputlogoffevents",),
}
_VT_LOOKUP_COMMANDS = frozenset({"file", "url", "ip", "domain"})
_VT_HASH_RE = re.compile(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_VT_DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?\Z"
)


def _takajo_output_destinations(command: str, args: list[str]) -> list[str]:
    path_options = {"output", "dboutput"} if command == "html-report" else {"output"}
    short_options = {"o", "s"} if command == "html-report" else {"o"}
    destinations: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        option = None
        value = ""
        attached = False
        if arg.startswith("--"):
            match = re.fullmatch(r"--([^=:]*)(?:([=:])(.*))?", arg)
            if match:
                raw_name, separator, value = match.groups()
                operation = raw_name[-1:] if raw_name[-1:] in "+&^/" else ""
                name = re.sub(r"[-_]", "", raw_name.removesuffix(operation)).casefold()
                matches = [candidate for candidate in path_options if name and candidate.startswith(name)]
                if matches:
                    if operation:
                        raise ValueError("Blocked by policy: takajo: output string update operators are not permitted")
                    if name not in path_options and any(
                        candidate.startswith(name) for candidate in _TAKAJO_OUTPUT_PREFIX_CONFLICTS.get(command, ())
                    ):
                        raise ValueError("Blocked by policy: takajo: ambiguous output option prefix")
                    option = matches[0]
                    attached = separator is not None
                    value = value or ""
        elif arg.startswith("-") and arg != "-":
            for index, letter in enumerate(arg[1:], 1):
                if letter in short_options:
                    option = letter
                    value = arg[index + 1 :]
                    if re.match(r"^[+&^/][=:]", value):
                        raise ValueError("Blocked by policy: takajo: output string update operators are not permitted")
                    attached = bool(value)
                    if value.startswith(("=", ":")):
                        value = value[1:]
                    break
                if letter not in _TAKAJO_BOOLEAN_SHORT_FLAGS.get(command, frozenset()) or arg[index + 1 :].startswith(
                    ("=", ":")
                ):
                    break
        if option is not None:
            if not attached:
                i += 1
                if i >= len(args):
                    raise ValueError("Blocked by policy: takajo: output option requires a value")
                value = args[i]
            destinations.append(value)
        i += 1
    return destinations


def _parse_readonly_options(
    tool: str, args: list[str], value_flags: set[str], boolean_flags: set[str]
) -> tuple[list[str], dict[str, str]]:
    positional: list[str] = []
    values: dict[str, str] = {}
    i = 0
    while i < len(args):
        arg = args[i]
        if not arg.startswith("-"):
            positional.append(arg)
            i += 1
            continue
        flag, separator, value = arg.partition("=")
        if not separator and not arg.startswith("--") and len(arg) > 2 and arg[:2] in value_flags:
            flag, separator, value = arg[:2], "=", arg[2:]
        if flag in boolean_flags:
            if separator and value not in {"true", "false"}:
                raise ValueError(f"Blocked by policy: {tool}: invalid boolean option")
        elif flag in value_flags:
            if not separator:
                i += 1
                if i >= len(args) or args[i].startswith("-"):
                    raise ValueError(f"Blocked by policy: {tool}: option requires a value")
                value = args[i]
            if not value:
                raise ValueError(f"Blocked by policy: {tool}: empty option value")
            values[flag] = value
        else:
            raise ValueError(f"Blocked by policy: {tool}: unsupported option for read-only operations")
        i += 1
    return positional, values


def _check_vt_policy(arg_list: list[str]) -> None:
    for arg in arg_list:
        if re.match(r"^--api[-_]?key(?:=|$)", arg, re.IGNORECASE) or re.match(r"^-[sIvP]*k", arg):
            raise ValueError("Blocked by policy: vt: inline API keys are not permitted; use the operator's ~/.vt.toml")
    if arg_list in ([], ["--help"], ["-h"], ["help"], ["version"]):
        return
    if len(arg_list) == 2 and (
        arg_list[0] in _VT_LOOKUP_COMMANDS
        and arg_list[1] in {"--help", "-h"}
        or arg_list[0] == "help"
        and arg_list[1] in _VT_LOOKUP_COMMANDS
    ):
        return
    positional, options = _parse_readonly_options(
        "vt",
        arg_list,
        {"--format", "--include", "-i", "--exclude", "-x", "--threads", "-t"},
        {"--identifiers-only", "-I", "--silent", "-s", "--private", "-P"},
    )
    if len(positional) < 2 or positional[0] not in _VT_LOOKUP_COMMANDS:
        raise ValueError("Blocked by policy: vt: only file/hash, URL, IP, and domain report lookups are permitted")
    command, *targets = positional
    if options.get("--format", "yaml") not in {"yaml", "json", "csv"}:
        raise ValueError("Blocked by policy: vt: unsupported output format")
    for flag in ("--threads", "-t"):
        if flag in options and (not options[flag].isdigit() or int(options[flag]) < 1):
            raise ValueError("Blocked by policy: vt: thread count must be a positive integer")
    for target in targets:
        valid = False
        if command == "file":
            valid = _VT_HASH_RE.fullmatch(target) is not None
        elif command == "domain":
            valid = "." in target.rstrip(".") and _VT_DOMAIN_RE.fullmatch(target) is not None
        elif command == "ip":
            try:
                ipaddress.ip_address(target)
                valid = True
            except ValueError:
                pass
        elif command == "url":
            if re.fullmatch(r"[0-9a-fA-F]{64}", target):
                valid = True
            else:
                try:
                    parsed = urlsplit(target)
                    valid = (
                        parsed.scheme in {"http", "https"}
                        and bool(parsed.hostname)
                        and parsed.username is None
                        and parsed.password is None
                        and parsed.port != 0
                        and not any(char.isspace() for char in target)
                    )
                except ValueError:
                    pass
        if not valid:
            raise ValueError("Blocked by policy: vt: invalid lookup identifier or unbounded stdin/file input")
    if not _allow_external():
        raise ValueError(
            "Blocked by policy: vt: report lookups contact the external VirusTotal API; "
            "set CYBERSEC_MCP_ALLOW_EXTERNAL=1 for authorized lookups"
        )


def _check_openscap_policy(arg_list: list[str]) -> None:
    if arg_list in ([], ["--help"], ["-h"], ["--version"], ["-V"], ["version"]):
        return
    if (
        len(arg_list) in {2, 3}
        and arg_list[-1] in {"--help", "-h"}
        and arg_list[0] in {"info", "oval", "xccdf", "cpe", "cve", "ds"}
    ):
        return
    if arg_list[:2] in (["xccdf", "eval"], ["xccdf", "remediate"]):
        raise ValueError(
            "Blocked by policy: oscap: XCCDF evaluation/remediation can execute profile SCE or fix scripts; "
            "use validation or read-only OVAL evaluation"
        )
    if arg_list[:1] == ["info"]:
        args = arg_list[1:]
        value_flags = {"--profile", "--local-files"}
        boolean_flags = {"--list-rules", "--list-vars"}
    elif arg_list[:2] == ["oval", "eval"]:
        args = arg_list[2:]
        value_flags = {
            "--id",
            "--variables",
            "--directives",
            "--results",
            "--report",
            "--datastream-id",
            "--oval-id",
            "--local-files",
            "--verbose",
            "--verbose-log-file",
        }
        boolean_flags = {"--without-syschar"}
    elif tuple(arg_list[:2]) in {
        ("oval", "validate"),
        ("xccdf", "validate"),
        ("cpe", "validate"),
        ("cve", "validate"),
        ("ds", "sds-validate"),
        ("ds", "rds-validate"),
    }:
        args = arg_list[2:]
        value_flags = {"--verbose", "--verbose-log-file"}
        boolean_flags = {"--skip-schematron"}
        if arg_list[0] == "oval":
            boolean_flags |= {"--definitions", "--variables", "--syschar", "--results"}
    else:
        raise ValueError("Blocked by policy: oscap: only info, validation, and read-only OVAL evaluation are permitted")
    positional, options = _parse_readonly_options("oscap", args, value_flags, boolean_flags)
    if len(positional) != 1:
        raise ValueError("Blocked by policy: oscap: a single local SCAP input file is required")
    for value in [*positional, *options.values()]:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
            raise ValueError("Blocked by policy: oscap: remote resources require a dedicated scope adapter")
    for flag in ("--results", "--report", "--verbose-log-file"):
        if flag in options and _is_sensitive_write_target(options[flag]):
            _raise_sensitive_write("oscap", options[flag])


def _check_teamfiltration_policy(arg_list: list[str]) -> None:
    if arg_list not in ([], ["--help"]):
        raise ValueError(
            "Blocked by policy: TeamFiltration: MCP permits only help; config/database-backed cloud actions "
            "and interactive credential commands need a dedicated scope adapter"
        )


def _check_rea_policy(arg_list: list[str]) -> None:
    if arg_list in ([], ["--help"], ["-h"], ["--version"]):
        return
    if len(arg_list) == 2 and arg_list[1] in ("--help", "-h") and re.fullmatch(r"[a-z][a-z0-9-]*", arg_list[0]):
        return
    raise ValueError(
        "Blocked by policy: rea: MCP permits only help; process, browser, device, listener and "
        "agent-configuration commands need a dedicated scope adapter"
    )


def _check_ssldump_policy(arg_list: list[str]) -> None:
    """Permit offline TLS analysis without live capture, DNS resolution or BPF hostname lookups."""
    has_capture = False
    numeric = False
    informational = False
    value_options = frozenset("rfklw")
    boolean_options = frozenset("vjyaTznsAxXhHVNdqeP")
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        i += 1
        if arg == "--" and i == len(arg_list):
            break
        if arg.startswith("--") or not arg.startswith("-") or arg == "-":
            raise ValueError("Blocked by policy: ssldump: offline analysis does not accept capture filters or operands")
        bundle = arg[1:]
        for position, option in enumerate(bundle):
            if option in value_options:
                value = bundle[position + 1 :]
                if not value:
                    if i >= len(arg_list):
                        raise ValueError("Blocked by policy: ssldump: option requires a value")
                    value = arg_list[i]
                    i += 1
                if option in {"r", "f"}:
                    has_capture = True
                elif option == "w":
                    _raise_sensitive_write("ssldump", value)
                break
            if option not in boolean_options:
                raise ValueError("Blocked by policy: ssldump: unsupported option for offline analysis")
            numeric |= option == "n"
            informational |= option in {"h", "v"}
    if not informational and not (has_capture and numeric):
        raise ValueError("Blocked by policy: ssldump: MCP requires -n and -r capture.pcap for offline analysis")


def _check_readpst_policy(arg_list: list[str]) -> None:
    """Validate explicit PST output paths and refuse destructive overwrite mode."""
    value_options = frozenset("CLacdjot")
    boolean_options = frozenset("DMSVbehkmqru8")
    output_directories: list[str] = []
    debug_files: list[str] = []
    informational = False
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        i += 1
        if arg == "--":
            break
        if arg == "-" or not arg.startswith("-"):
            continue
        if arg.startswith("--"):
            raise ValueError("Blocked by policy: readpst: unsupported option")
        bundle = arg[1:]
        for position, option in enumerate(bundle):
            if option == "w":
                raise ValueError("Blocked by policy: readpst: -w can overwrite output and delete existing files")
            if option in value_options:
                value = bundle[position + 1 :]
                if not value:
                    if i >= len(arg_list):
                        raise ValueError("Blocked by policy: readpst: option requires a value")
                    value = arg_list[i]
                    i += 1
                if option == "o":
                    output_directories.append(value)
                elif option == "d":
                    debug_files.append(value)
                break
            if option not in boolean_options:
                raise ValueError("Blocked by policy: readpst: unsupported option")
            informational |= option in {"h", "V"}
    for destination in debug_files:
        _raise_sensitive_write("readpst", destination)
    for destination in output_directories or ([] if informational else [os.getcwd()]):
        _raise_sensitive_write("readpst", destination)


def _check_takajo_policy(arg_list: list[str]) -> None:
    if arg_list in ([], ["--help"], ["-h"], ["--version"], ["help"]):
        return
    if (
        len(arg_list) == 2
        and arg_list[0] == "help"
        and arg_list[1] in (_TAKAJO_OFFLINE_COMMANDS | _TAKAJO_RESTRICTED_COMMANDS)
    ):
        return
    if arg_list[0] in _TAKAJO_RESTRICTED_COMMANDS:
        raise ValueError("Blocked by policy: takajo: persistent servers and VirusTotal API commands are not permitted")
    if arg_list[0] not in _TAKAJO_OFFLINE_COMMANDS:
        raise ValueError("Blocked by policy: takajo: only documented offline analysis commands are permitted")
    for value in _takajo_output_destinations(arg_list[0], arg_list[1:]):
        if _is_sensitive_write_target(value):
            _raise_sensitive_write("takajo", value)


_ARGUMENT_POLICIES: dict[str, Callable[[list[str]], None]] = {
    "ssldump": _check_ssldump_policy,
    "pst-utils": _check_readpst_policy,
    "readpst": _check_readpst_policy,
    "strace": partial(_check_tracer_attach_only, "strace"),
    "ltrace": partial(_check_tracer_attach_only, "ltrace"),
    "gdb": _check_gdb_execution_commands,
    "sed": _check_sed_policy,
    "tar": _check_tar_policy,
    "zip": _check_zip_policy,
    "wget": _check_wget_policy,
    "nc": _check_nc_policy,
    "ncat": _check_nc_policy,
    "netcat": _check_nc_policy,
    "binwalk": _check_binwalk_policy,
    "ip": _check_ip_policy,
    "xmllint": _check_url_operands_policy,
    "exiv2": _check_url_operands_policy,
    "teamfiltration": _check_teamfiltration_policy,
    "rea": _check_rea_policy,
    "rea-agents": _check_rea_policy,
    "takajo": _check_takajo_policy,
    "oscap": _check_openscap_policy,
    "openscap-scanner": _check_openscap_policy,
    "vt": _check_vt_policy,
    "vt-cli": _check_vt_policy,
    "rr": _check_rr_policy,
    "pwntools": _check_pwntools_policy,
    "pwn": _check_pwntools_policy,
    "volatility3": _check_volatility_policy,
    "vol": _check_volatility_policy,
    "frida-tools": _check_frida_policy,
    "frida": _check_frida_policy,
    "radare2": partial(_check_r2_policy, "radare2"),
    "r2": partial(_check_r2_policy, "radare2"),
    "rizin": partial(_check_r2_policy, "rizin"),
    **{
        name: partial(_check_info_only_runner, runner)
        for runner, (_, _, aliases) in _INFO_ONLY_RUNNERS.items()
        for name in (runner, *aliases)
    },
}


# These options load caller-selected code/configuration, change the installation,
# or hide target selection from the argv scope check.
_GIT_CODE_OPTIONS = frozenset(
    {
        "--eval",
        "--exec",
        "--execute",
        "--script",
        "--scripts",
        "--plugin",
        "--plugins",
        "--config",
        "--config-file",
        "--command-file",
        "--resource-file",
        "--update",
        "--upgrade",
        "--self-update",
        "--install",
    }
)
_GIT_BLOCKED_OPTIONS: dict[str, frozenset[str]] = {
    "commix": frozenset(
        {
            "--oob",
            "--oob-server",
            "--oob-domain",
            "--oob-port",
            "--oob-session",
            "--oob-poll-interval",
            "--os-cmd",
            "--os-shell",
            "--file-read",
            "--file-write",
            "--file-upload",
            "--file-dest",
            "--reg-read",
            "--reg-add",
            "--reg-del",
            "--tamper",
            "--alter-shell",
            "--auth-file",
            # -c loads an INI file that may set any option, the blocked ones included.
            "-c",
        }
    ),
    "bettercap": frozenset({"-eval", "-caplet", "-script", "-env-file"}),
    "recon-ng": frozenset({"-r", "-x"}),
    "PhpSploit": frozenset({"-c", "-s", "-e", "-l", "--source", "--load"}),
    "phpggc": frozenset({"--test-payload", "--wrapper", "-w"}),
    "tplmap": frozenset(
        {"--os-shell", "--os-cmd", "--bind-shell", "--reverse-shell", "--upload", "--download", "--force-overwrite"}
    ),
    "smuggler": frozenset({"-c", "--configfile"}),
    "testssl.sh": frozenset({"--openssl"}),
    "cupp": frozenset({"-a", "--alecto", "-l"}),
    # deepce reads its options from a bash case statement: these short spellings are separate entries.
    "deepce": frozenset(
        {
            "--exploit",
            "-e",
            "--install",
            "--command",
            "-cmd",
            "--payload",
            "-x",
            "--listen",
            "-l",
            "--shadow",
            "-s",
            "--username",
            "--password",
            "-doc",
        }
    ),
    "CMSmap": frozenset({"-U"}),
    "crowbar": frozenset({"-m"}),
    "NoSQLMap": frozenset({"--load", "--save", "--shell"}),
    "Qiling": frozenset({"--env", "--profile", "--qdb", "--gdb", "-g"}),
    "firefox_decrypt": frozenset({"--pass-cmd", "-m"}),
    "ShellNoob": frozenset({"--to-strace", "--to-gdb", "--uninstall", "--file-patch", "--vm-patch"}),
    "PRET": frozenset({"-i", "--load"}),
    "nmapAutomator": frozenset({"-s", "--static-nmap"}),
}
_GIT_TARGET_FILE_OPTIONS: dict[str, frozenset[str]] = {
    "commix": frozenset({"-r", "-m", "--bulkfile", "--requestfile", "--session-file"}),
    "ghauri": frozenset({"-r", "-m", "--requestfile", "--bulkfile"}),
    "XSStrike": frozenset({"--seeds", "--proxy"}),
    "SSRFmap": frozenset({"-r"}),
    "nikto": frozenset({"-useproxy", "-url", "-list-plugins"}),
    "CMSmap": frozenset({"-i", "--input"}),
    "h2csmuggler": frozenset({"--scan-list"}),
    "Corsy": frozenset({"-i"}),
    "EyeWitness": frozenset({"-f", "-x"}),
    "testssl.sh": frozenset({"--file", "-iL"}),
    "Photon": frozenset({"--seeds", "--proxy"}),
    "jwt_tool": frozenset({"-M", "--mode", "-X", "--exploit", "-r", "--request"}),
}
# Flags that take a host or URL but also read a list of them from a file when given a path
# (``nikto -h hosts.txt``), so the argv scope check never sees the real targets.
_GIT_HOST_OR_FILE_FLAGS: dict[str, frozenset[str]] = {
    "nikto": frozenset({"-h", "-host"}),
}
# Interface-wide actions and implicit service endpoints cannot be reduced to a
# private argv target, so they require the same explicit network opt-in as public hosts.
_IMPLICIT_NETWORK_TOOLS = frozenset(
    {
        "azurehound",
        "SET",
        "Zphisher",
        "SquarePhish",
        "CredMaster",
        "Modlishka",
        "spiderfoot",
        "bettercap",
        "PRET",
        "recon-ng",
        "reconftw",
        "nmapAutomator",
        "Sn1per",
        "blackbird",
        "GooFuzz",
        "Telepathy",
        "certSniff",
        "linkedin2username",
        "theHarvester",
        "osmedeus",
        "paramspider",
        "RouterSploit",
        "Penelope",
        "Hoaxshell",
        "Villain",
        "Responder",
        "linWinPwn",
        "PXEThief",
        "pywsus",
        "roastinthemiddle",
        "asrepcatcher",
        "wifite2",
        "airgeddon",
        "wifiphisher",
        "eaphammer",
        "wifipumpkin3",
        "CloudBrute",
        "enumerate-iam",
        "GCPBucketBrute",
        "cloud_enum",
        "dnschef",
        "yersinia",
        "robin",
        "stringcheese",
        "FuzzyAI",
        "pallms",
        "medusa-frida",
        "dnscat2",
        "PCredz",
        "fluxion",
        "hostapd-mana",
        "PurplePanda",
        "cloudmapper",
    }
)
_GIT_OUTPUT_LONG_OPTIONS = frozenset(
    {
        "--output",
        "--output-file",
        "--output-dir",
        "--output-directory",
        "--report",
        "--report-file",
        "--log",
        "--logfile",
        "--log-file",
        "--log-dir",
        "--filename",
        "--dump-file",
        "--jsonfile",
        "--jsonfile-pretty",
        "--csvfile",
        "--htmlfile",
        "--outfile",
        "--outFile",
    }
)
_GIT_OUTPUT_SHORT_OPTIONS: dict[str, frozenset[str]] = {
    "LaZagne": frozenset({"-output"}),
    "commix": frozenset({"-t"}),
    "XSStrike": frozenset(),
    "ghauri": frozenset(),
    "nikto": frozenset({"-output", "-o"}),
    "jwt_tool": frozenset({"-o"}),
    "smuggler": frozenset({"-l"}),
    "CMSmap": frozenset({"-o"}),
    "testssl.sh": frozenset({"-oL", "-oj", "-oJ", "-oC", "-oH", "-oa", "-oA"}),
    "RsaCtfTool": frozenset(),
    "rsatool": frozenset({"-o"}),
    "pyinstxtractor": frozenset(),
    "Depix": frozenset({"-o"}),
    "enum4linux-ng": frozenset({"-oA", "-oJ", "-oY"}),
    "Photon": frozenset({"-o"}),
    "LinkFinder": frozenset({"-o"}),
    "SecretFinder": frozenset({"-o"}),
    "graphw00f": frozenset({"-o"}),
    "Oralyzer": frozenset({"-o"}),
    "targetedKerberoast": frozenset({"-o"}),
    "Qiling": frozenset({"-c"}),
}
_GIT_NON_TARGET_VALUES = {
    "--data",
    "--cookie",
    "--cookies",
    "--header",
    "--headers",
    "--user-agent",
    "--useragent",
    "--uagent",
    "--method",
    "--technique",
    "--techniques",
    "--dbms",
    "--param",
    "--parameter",
    "--username",
    "--password",
    "--output",
    "--output-file",
    "--output-dir",
    "--report",
    "--logfile",
    "--log-file",
    "--format",
}
for _git_name in GIT_BIN_NAMES:
    _TARGET_FLAG_EXEMPTIONS.setdefault(_git_name, set()).update(_GIT_NON_TARGET_VALUES)
for _enterprise_name in {
    "coercer",
    "lsassy",
    "sprayhound",
    "ldapdomaindump",
    "adidnsdump",
    "dploot",
    "bloodyad",
    "hekatomb",
    "certsync",
    "masky",
    "pywhisker",
    "autobloody",
    "roadtx",
    "pywerview",
    "pysnaffler",
    "powerview",
    "aclpwn",
    "ldeep",
    "smbclientng",
}:
    _TARGET_FLAG_EXEMPTIONS.setdefault(_enterprise_name, set()).update(
        {"-u", "-p", "--username", "--password", "-hashes", "--hashes", "-U", "-P"}
    )
_TARGET_FLAG_EXEMPTIONS.setdefault("commix", set()).update({"-p", "--auth-cred", "--auth-type"})
_TARGET_FLAG_EXEMPTIONS.setdefault("ghauri", set()).update({"-p", "-D", "-T", "-C", "--string", "--not-string"})
_TARGET_FLAG_EXEMPTIONS.setdefault("XSStrike", set()).update({"-f", "--file", "-e", "--encode"})
_TARGET_FLAG_EXEMPTIONS.setdefault("jwt_tool", set()).update(
    {"-S", "-p", "-k", "-kf", "-pk", "-jw", "-hc", "-pc", "-hv", "-pv", "-H", "-rh", "-rc", "-pd"}
)
_TARGET_FLAG_EXEMPTIONS.setdefault("enum4linux-ng", set()).update({"-u", "-p", "-w", "-oA", "-oJ", "-oY"})


# rip.pl reads options with Getopt::Long (prefix "-", "--" or "/", any case, unique prefixes) and
# loads <plugins dir>/<value>.pl for -p and the plugin list <plugins dir>/<value> for -f.
_REGRIPPER_OPTION_RE = re.compile(r"(?:--?|/)([A-Za-z]+)(?:=(.*))?", re.S)


def _check_regripper_options(arg_list: list[str]) -> None:
    i = 0
    while i < len(arg_list):
        match = _REGRIPPER_OPTION_RE.fullmatch(arg_list[i])
        i += 1
        if not match:
            continue
        name, value = match.group(1).lower(), match.group(2)
        if name == "up" or (len(name) > 2 and "update".startswith(name)):
            raise ValueError("Blocked by policy: RegRipper: update replaces its plugins from the network")
        loads = "plugin".startswith(name) or "file".startswith(name)
        if not (loads or name in {"r", "u", "s"} or any(option.startswith(name) for option in ("reg", "user", "sys"))):
            continue
        if value is None and i < len(arg_list):
            value = arg_list[i]
            i += 1
        if loads and (value is None or ".." in value or not re.fullmatch(r"[A-Za-z0-9_.-]+", value)):
            raise ValueError(
                "Blocked by policy: RegRipper: -p and -f take a plugin or plugin-list name from its "
                "plugins directory, not a path"
            )


def _git_option_matches(arg: str, option: str) -> bool:
    name = arg.split("=", 1)[0]
    if option.startswith("--"):
        return name.startswith("--") and len(name) > 2 and (option.startswith(name) or name.startswith(option + "-"))
    return arg == option or arg.startswith(option + "=") or (len(option) == 2 and arg.startswith(option))


def _check_git_policy(tool_name: str, binary: str, arg_list: list[str]) -> None:
    name = next((name for name, launcher in GIT_BIN_NAMES.items() if tool_name == name or binary == launcher), None)
    if name is None:
        return
    if arg_list in (["-h"], ["--help"], ["--version"], ["-V"]):
        return
    if name in HOST_CONTROL_OPT_INS:
        if _host_control_information(name, arg_list):
            return
        if not _allow_host_control(name):
            raise ValueError(
                f"Blocked by policy: {name}: host shutdown, wiping or network changes require "
                f"{HOST_CONTROL_OPT_INS[name]}=1; help/version remains available without activation"
            )
        return
    if name == "Gopherus":
        modes = {
            "mysql",
            "postgresql",
            "fastcgi",
            "redis",
            "smtp",
            "zabbix",
            "pymemcache",
            "rbmemcache",
            "phpmemcache",
            "dmpmemcache",
        }
        if len(arg_list) == 2 and arg_list[0] == "--exploit" and arg_list[1] in modes:
            return
        if len(arg_list) == 1 and arg_list[0].startswith("--exploit=") and arg_list[0].split("=", 1)[1] in modes:
            return
        raise ValueError("Blocked by policy: Gopherus: select a documented local payload generator with --exploit")
    if name == "USB-HID-decoders":
        for mode in _flag_values(arg_list, short_flags=frozenset({"-m"}), long_flags=frozenset({"--mode"})):
            if mode not in {"raw", "simulate"}:
                raise ValueError("Blocked by policy: USB-HID-decoders: keyboard replay can execute captured host input")
    if name == "firefox_decrypt":
        format_options = frozenset(arg.split("=", 1)[0] for arg in arg_list if _git_option_matches(arg, "--format"))
        for output_format in _flag_values(arg_list, short_flags=frozenset({"-f"}), long_flags=format_options):
            if output_format == "pass":
                raise ValueError(
                    "Blocked by policy: firefox_decrypt: pass export executes a host password-store command"
                )
    if name == "ShellNoob":
        for operand in arg_list:
            if not operand.startswith("-"):
                _raise_sensitive_write(name, operand)
    if name == "pp-finder" and any(arg == "run" for arg in arg_list):
        raise ValueError("Blocked by policy: pp-finder: run launches an arbitrary host command")
    if name == "Qiling":
        if "qltui" in arg_list:
            raise ValueError("Blocked by policy: Qiling: qltui can load host Python hooks")
        for rootfs in _flag_values(arg_list, long_flags=frozenset({"--rootfs"})):
            resolved = Path(rootfs).expanduser().resolve()
            if resolved in {Path("/"), Path.home(), Path.home().parent}:
                raise ValueError(
                    "Blocked by policy: Qiling: use a dedicated emulated rootfs, not a host root/home tree"
                )
            _raise_sensitive_write("Qiling rootfs", rootfs)
        for output in _flag_values(arg_list, long_flags=frozenset({"--coverage-file"})):
            _raise_sensitive_write("Qiling coverage", output)
    blocked = _GIT_CODE_OPTIONS | _GIT_BLOCKED_OPTIONS.get(name, frozenset())
    for arg in arg_list:
        for option in blocked:
            if _git_option_matches(arg, option):
                raise ValueError(f"Blocked by policy: {name}: {option} can execute code, modify files or disclose data")
    # searchsploit joins every single-dash group into one getopts string, so a u anywhere is -u (--update).
    if name == "exploitdb" and any(arg.startswith("-") and not arg.startswith("--") and "u" in arg for arg in arg_list):
        raise ValueError("Blocked by policy: exploitdb: -u updates the installation over the network")
    if name == "RegRipper":
        _check_regripper_options(arg_list)
    for destination in _flag_values(
        arg_list,
        short_flags=_GIT_OUTPUT_SHORT_OPTIONS.get(name, frozenset({"-o"})),
        long_flags=_GIT_OUTPUT_LONG_OPTIONS,
    ):
        _raise_sensitive_write(name, destination)
    if name == "SSRFmap" and any(_git_option_matches(arg, "-l") for arg in arg_list):
        raise ValueError("Blocked by policy: SSRFmap: -l launches a local reverse-shell handler")
    if _allow_external():
        return
    opaque = _GIT_TARGET_FILE_OPTIONS.get(name, frozenset())
    if name in GIT_NETWORK_TOOLS:
        opaque |= frozenset(
            {
                "--target-file",
                "--targets-file",
                "--targets",
                "--input-file",
                "--url-file",
                "--urls-file",
                "--request-file",
                "--requestfile",
                "--bulkfile",
                "--bulk-file",
                "--proxy-file",
                "--seeds",
            }
        )
    for arg in arg_list:
        flag = arg.split("=", 1)[0]
        safe_exact = flag in _GIT_NON_TARGET_VALUES | {"--url", "--target", "--host", "--ip"}
        if flag in opaque or (not safe_exact and any(_git_option_matches(arg, option) for option in opaque)):
            raise ValueError(
                f"Blocked by policy: {name}: targets or callbacks selected outside argv require "
                "CYBERSEC_MCP_ALLOW_EXTERNAL=1 and an authorized sandbox scope"
            )
    host_flags = _GIT_HOST_OR_FILE_FLAGS.get(name, frozenset())
    if host_flags and any(_is_local_path(value) for value in _flag_values(arg_list, short_flags=host_flags)):
        raise ValueError(
            f"Blocked by policy: {name}: a host list read from a file requires "
            "CYBERSEC_MCP_ALLOW_EXTERNAL=1 and an authorized sandbox scope"
        )
    if name == "RsaCtfTool":
        if any(_git_option_matches(arg, "--sendtofdb") for arg in arg_list):
            raise ValueError(
                "Blocked by policy: RsaCtfTool: FactorDB submission requires CYBERSEC_MCP_ALLOW_EXTERNAL=1"
            )
        attacks: list[str] = []
        collecting = False
        for arg in arg_list:
            # argparse also accepts an unambiguous prefix (--att, --atta=...) for --attack.
            if _git_option_matches(arg, "--attack"):
                if "=" in arg:
                    attacks.extend(arg.split("=", 1)[1].split(","))
                collecting = True
            elif arg.startswith("-"):
                collecting = False
            elif collecting:
                attacks.extend(arg.split(","))
        local_attacks = {
            "wiener",
            "fermat",
            "hastads",
            "common_factors",
            "common_modulus",
            "boneh_durfee",
            "pollard_rho",
        }

        def given(option: str) -> bool:
            return any(_git_option_matches(arg, option) for arg in arg_list)

        # Mirrors upstream's early exits: these modes return before any attack runs.
        decrypting = given("--decrypt") or given("--decryptfile")
        inspecting = any(arg in {"--createpub", "--isroca", "--convert_idrsa_pub"} for arg in arg_list) or (
            "--dumpkey" in arg_list and (given("--key") or (given("--publickey") and not decrypting))
        )
        if not inspecting and (not attacks or not set(attacks) <= local_attacks):
            raise ValueError(
                "Blocked by policy: RsaCtfTool: default/all attacks can contact external databases; "
                "select a reviewed offline --attack (for example wiener or fermat), "
                "or set CYBERSEC_MCP_ALLOW_EXTERNAL=1"
            )


def _check_zaproxy_policy(arg_list: list[str]) -> None:
    if arg_list in (["-h"], ["-help"], ["--help"], ["-version"]):
        return
    booleans = {"-cmd", "-silent", "-quickprogress", "-lowmem", "-nostdout"}
    values = {"-quickurl", "-quickout", "-dir", "-newsession", "-loglevel", "-host", "-port"}
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        if arg in booleans:
            i += 1
            continue
        if arg not in values or i + 1 >= len(arg_list):
            raise ValueError(
                "Blocked by policy: zaproxy: only bounded -cmd scans with explicit -quickurl are supported; "
                "scripts, configuration, add-on installation and daemon mode need a dedicated adapter"
            )
        value = arg_list[i + 1]
        if arg in {"-quickout", "-dir", "-newsession"}:
            _raise_sensitive_write("zaproxy", value)
        elif arg in {"-quickurl", "-host"} and not _allow_external():
            if not _is_safe_target(_network_target_host(value)):
                raise ValueError("Blocked by policy: zaproxy: target is not in a private/local network range")
        i += 2
    if "-cmd" not in arg_list or "-quickurl" not in arg_list:
        raise ValueError("Blocked by policy: zaproxy: provide -cmd and an explicit -quickurl")


def _check_bluetooth_policy(arg_list: list[str]) -> None:
    if arg_list in ([], ["--help"], ["-h"], ["--version"], ["-v"]):
        return
    if arg_list[0] in {"list", "show", "devices", "info", "version", "help"} and len(arg_list) <= 2:
        if len(arg_list) == 1 or re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", arg_list[1]):
            return
        if arg_list[0] == "devices" and arg_list[1] in {"Paired", "Connected", "Trusted", "Bonded"}:
            return
    raise ValueError("Blocked by policy: bluetoothctl: only controller/device information commands are permitted")


def _check_iwconfig_policy(arg_list: list[str]) -> None:
    if not arg_list or arg_list in (["--help"], ["--version"]):
        return
    if len(arg_list) == 1 and re.fullmatch(r"[A-Za-z0-9_.:-]+", arg_list[0]) and not arg_list[0].startswith("-"):
        return
    raise ValueError("Blocked by policy: iwconfig: only interface information queries are permitted")


def _check_osquery_policy(arg_list: list[str]) -> None:
    if arg_list in (["--help"], ["-h"], ["--version"]):
        return
    queries = []
    for arg in arg_list:
        if arg in {"--json", "--csv", "--line", "--list", "--table", "--header"}:
            continue
        if arg.startswith("-"):
            raise ValueError(
                "Blocked by policy: osqueryi: custom flags, configuration and extensions are not permitted"
            )
        queries.append(arg)
    if len(queries) != 1:
        raise ValueError("Blocked by policy: osqueryi: provide one explicit read-only query")
    query = queries[0].strip().removesuffix(";").strip()
    if query in {".tables", ".help", ".version"} or re.fullmatch(r"\.schema(?:\s+[A-Za-z0-9_]+)?", query):
        return
    if not re.match(r"^SELECT\b", query, re.IGNORECASE) or re.search(
        r";|(?:^|\n)\s*\.|\b(?:load_extension|writefile|attach|detach|insert|update|delete|create|drop|alter|vacuum)\b",
        query,
        re.IGNORECASE,
    ):
        raise ValueError("Blocked by policy: osqueryi: only read-only SELECT and information commands are permitted")
    if not _allow_external() and re.search(r"\b(?:curl|dns_lookup|connectivity)\b", query, re.IGNORECASE):
        raise ValueError("Blocked by policy: osqueryi: network tables require CYBERSEC_MCP_ALLOW_EXTERNAL=1")


def _check_snmpwalk_policy(arg_list: list[str]) -> None:
    if arg_list in (["--help"], ["-h"], ["--version"], ["-V"], ["-H"]):
        return
    value_options = set("vcuAaXxlneEtrmMOPIDZ")
    operands: list[str] = []
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        i += 1
        if arg in {"-d", "-Le", "-Lo"}:
            continue
        if arg.startswith("-"):
            if arg.startswith("--") or len(arg) < 2 or arg[1] not in value_options:
                raise ValueError(
                    "Blocked by policy: snmpwalk: config overrides, alternate transports and file logs are disabled"
                )
            if len(arg) == 2:
                if i >= len(arg_list):
                    raise ValueError("Blocked by policy: snmpwalk: option requires a value")
                i += 1
            continue
        operands.append(arg)
    if not 1 <= len(operands) <= 2:
        raise ValueError("Blocked by policy: snmpwalk: provide one explicit agent and an optional OID")
    target = re.sub(r"^(?:udp|tcp|udp6|tcp6):", "", operands[0], flags=re.IGNORECASE)
    if re.match(r"^[A-Za-z]+:", target):
        raise ValueError("Blocked by policy: snmpwalk: unsupported transport or configuration alias")
    if not _allow_external() and not _is_safe_target(_network_target_host(target)):
        raise ValueError("Blocked by policy: snmpwalk: target is not in a private/local network range")


def _check_argument_policies(tool_name: str, binary: str, arg_list: list[str]) -> None:
    _check_git_policy(tool_name, binary, arg_list)
    if "zaproxy" in {tool_name, binary}:
        _check_zaproxy_policy(arg_list)
    if {tool_name, binary} & {"bluez", "bluetoothctl"}:
        _check_bluetooth_policy(arg_list)
    if {tool_name, binary} & {"wireless-tools", "iwconfig"}:
        _check_iwconfig_policy(arg_list)
    if {tool_name, binary} & {"osquery", "osqueryi"}:
        _check_osquery_policy(arg_list)
    if {tool_name, binary} & {"snmp", "snmpwalk"}:
        _check_snmpwalk_policy(arg_list)
    if {tool_name, binary} & {"netexec", "nxc"}:
        for arg in arg_list:
            if any(_git_option_matches(arg, flag) for flag in {"-M", "--module", "--module-path", "--config"}):
                raise ValueError(
                    "Blocked by policy: netexec: uninspected Python modules and configuration are disabled"
                )
        for destination in _flag_values(arg_list, long_flags=frozenset({"--log"})):
            _raise_sensitive_write("netexec", destination)
    if tool_name in {"impacket", "certipy-ad", "bloodhound", "ldapsearchad"}:
        for destination in _flag_values(
            arg_list, short_flags=frozenset({"-outputfile", "-out", "-o"}), long_flags=frozenset({"--output"})
        ):
            _raise_sensitive_write(tool_name, destination)
    applied: set[Callable[[list[str]], None]] = set()
    for name in (tool_name.casefold(), binary.casefold()):
        policy = _ARGUMENT_POLICIES.get(name)
        if policy is not None and policy not in applied:
            policy(arg_list)
            applied.add(policy)


def _execution_arg_list(tool_name: str, binary: str, arg_list: list[str]) -> list[str]:
    if {tool_name, binary} & {"osquery", "osqueryi"}:
        return ["--flagfile=/dev/null", "--disable_extensions=true", "--disable_events=true", *arg_list]
    if "zaproxy" in {tool_name, binary} and "-silent" not in arg_list:
        return ["-silent", *arg_list]
    if {tool_name.casefold(), binary.casefold()} & {"vt", "vt-cli"}:
        # Viper config can override the API host or enable API-key output unless CLI flags take precedence.
        return [*arg_list, "--verbose=false", "--host=www.virustotal.com"]
    if "xmllint" in {tool_name.casefold(), binary.casefold()} and not _allow_external():
        # libxml2 would otherwise fetch external DTDs and entities over the network.
        return ["--nonet", *arg_list]
    return arg_list


def _blocked_args_for_logging(tool_name: str, args: str, binary: str | None = None) -> str:
    if {tool_name.casefold(), (binary or tool_name).casefold()} & {"vt", "vt-cli", "takajo", "teamfiltration"}:
        return "[REDACTED arguments]"
    return args


def _tool_policy_error(tool_name: str, binary: str, error: ValueError) -> str:
    reason = str(error)
    names = {tool_name.casefold(), binary.casefold()}
    if names & {"vt", "vt-cli", "takajo", "teamfiltration"} and reason.startswith(
        "Arguments contain blocked shell metacharacters:"
    ):
        return "Arguments contain blocked shell metacharacters"
    return reason


def _pipeline_args_for_audit(tool_name: str, args: str) -> str:
    name = tool_name.casefold()
    if name == "teamfiltration" and args.strip() not in {"", "--help"}:
        return "[REDACTED arguments]"
    if name == "takajo":
        try:
            tokens = shlex.split(args)
        except ValueError:
            return "[REDACTED arguments]"
        if tokens and tokens[0] not in _TAKAJO_OFFLINE_COMMANDS:
            if tokens not in ([], ["--help"], ["-h"], ["--version"], ["help"]) and not (
                len(tokens) == 2
                and tokens[0] == "help"
                and tokens[1] in _TAKAJO_OFFLINE_COMMANDS | _TAKAJO_RESTRICTED_COMMANDS
            ):
                return "[REDACTED arguments]"
    if name in {"vt", "vt-cli"} and re.search(
        r"(?:^|\s)[\"']?(?:--api[-_]?key(?:=|\s|[\"']|$)|-[sIvP]*k)", args, re.IGNORECASE
    ):
        return "[REDACTED arguments]"
    return args


def check_policy(tool_name: str, arg_list: list[str], binary: str | None = None) -> None:
    """Enforce execution policy on the resolved arguments.

    Raises ValueError if the command violates policy.
    """
    binary = binary or tool_name
    # A package's public launcher must receive the same rules as its registry name.
    tool_name = package_for_extra_binary(tool_name) or tool_name

    # 1. Check for blocked flags (universal)
    for arg in arg_list:
        for pattern, desc in BLOCKED_FLAGS:
            if pattern.match(arg):
                if tool_name == "Gopherus" and arg == "--exploit":
                    continue
                raise ValueError(f"Blocked by policy: {desc}")

    # 1b. Check for tool-specific blocked flags — search() not match(), since patterns
    # may match anywhere in the arg (e.g. awk's system() inside '{...}').
    for blocked_list in (TOOL_BLOCKED_FLAGS.get(tool_name, []), TOOL_BLOCKED_FLAGS.get(binary, [])):
        for arg in arg_list:
            for pattern, desc in blocked_list:
                if pattern.search(arg):
                    raise ValueError(f"Blocked by policy: {desc}")

    # 1b-ii. A blocked long flag can also be reached by an unambiguous prefix on
    # parsers that honour abbreviation, so reject those too.
    _check_long_option_abbreviations(tool_name, binary, arg_list)

    # Command semantics are checked for both registry names and resolved binaries before network opt-in.
    _check_argument_policies(tool_name, binary, arg_list)

    # 1c. Block file-mutating utilities (and curl/wget output flags) from writing
    # into dotfiles/shell-rc/cron/system dirs. This is a local-write concern, so
    # it runs regardless of the external-network policy below.
    _check_write_destinations(tool_name, binary, arg_list)
    _check_curl_file_reads(tool_name, binary, arg_list)

    if tool_name in HOST_CONTROL_OPT_INS:
        if tool_name == "nipe" and not _host_control_information(tool_name, arg_list) and arg_list != ["stop"]:
            if not _allow_external():
                raise ValueError(
                    "Blocked by policy: nipe: Tor routing, installation and status requests require "
                    "CYBERSEC_MCP_ALLOW_EXTERNAL=1 and an authorized sandbox scope"
                )
        return

    # 2. Network target checks (only for network tools, unless external is allowed)
    if _allow_external():
        return

    if tool_name in _IMPLICIT_NETWORK_TOOLS | {"mitm6", "krbjack", "pretender"} and arg_list not in (
        ["-h"],
        ["--help"],
        ["--version"],
        ["-V"],
    ):
        raise ValueError(
            f"Blocked by policy: {tool_name}: interface-wide or implicit external service access requires "
            "CYBERSEC_MCP_ALLOW_EXTERNAL=1 and an authorized sandbox scope"
        )

    # Offline RSA attacks were selected above; their key files and attack names are not hosts.
    if tool_name in {"RsaCtfTool", "Gopherus", "snmp", "osquery"} or binary in {"snmpwalk", "osqueryi"}:
        return

    if binary not in _NETWORK_TOOLS | GIT_NETWORK_TOOLS and tool_name not in _NETWORK_TOOLS | GIT_NETWORK_TOOLS:
        return

    if "openssl" in {tool_name, binary}:
        if any(re.fullmatch(r"--?crl_download", arg) for arg in arg_list):
            raise ValueError(
                "Blocked by policy: openssl: -crl_download fetches the CRLs a certificate names; "
                "requires CYBERSEC_MCP_ALLOW_EXTERNAL=1"
            )
        command = arg_list[0] if arg_list else ""
        # Offline commands read local files, so words such as rsa:2048 or pass:secret are not
        # hosts; a URL inside any value is, since openssl loads certificates and CRLs over HTTP.
        if command in _OPENSSL_OFFLINE_COMMANDS or _OPENSSL_ALGORITHM_COMMAND_RE.fullmatch(command.lower()):
            for arg in arg_list[1:]:
                for start in _URL_START_RE.finditer(arg):
                    rest = re.split(r"\s", arg[start.end() :], maxsplit=1)[0]
                    # OpenSSL takes the host after the first @ anywhere in the rest of the URL, so a
                    # private-looking prefix (10.0.0.5/x@8.8.8.8) can hide where it connects.
                    if "@" in rest:
                        raise ValueError("Blocked by policy: openssl: a URL with user information hides its host")
                    # A comma or semicolon separates list entries (URI:http://a,URI:http://b); the next
                    # URL is checked on its own.
                    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
                    host = _network_target_host("http://" + re.split(r"[,;]", authority, maxsplit=1)[0])
                    if not _is_safe_target(host):
                        raise ValueError(
                            f"Blocked by policy: target '{host}' is not in a private/local network range. "
                            "Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 to allow external targets."
                        )
            return
        # The command word of a network command is not a host; everything after it is checked.
        if command in _OPENSSL_NETWORK_COMMANDS:
            arg_list = arg_list[1:]

    # Reading a capture file connects nowhere; its filter words are not hosts. A remote
    # capture interface given alongside still connects out, so it is validated first.
    if {tool_name, binary} & {"tshark", "tcpdump"} and any(
        arg == "--read-file" or (arg.startswith("-r") and not arg.startswith("--")) for arg in arg_list
    ):
        for idx, arg in enumerate(arg_list):
            matched, _, flag, iface = _exempt_flag_value(
                tool_name, binary, arg, arg_list[idx + 1] if idx + 1 < len(arg_list) else None
            )
            if matched and flag == "-i":
                _validate_exempt_remote_resource(tool_name, binary, flag, iface)
        return

    # Check positional args and unambiguous target flags for external targets; ambiguous
    # short flags (-t, -h) are excluded and still caught by the positional-arg heuristic below.
    target_flags = {"--target", "-u", "--url", "--host", "--ip"}
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        value = None

        # Tool-specific exemption: flag+value pair that must not be validated
        # as a target (e.g. curl's "-u user:pass" is HTTP auth, not a URL).
        matched, consumed, flag, exempt_value = _exempt_flag_value(
            tool_name,
            binary,
            arg,
            arg_list[i + 1] if i + 1 < len(arg_list) else None,
        )
        if matched:
            _validate_exempt_remote_resource(tool_name, binary, flag, exempt_value)
            i += consumed
            continue

        if arg in target_flags and i + 1 < len(arg_list):
            value = arg_list[i + 1]
            i += 2
        elif "=" in arg and arg.split("=", 1)[0] in target_flags:
            value = arg.split("=", 1)[1]
            i += 1
        elif arg.startswith("@") and len(arg) > 1:
            # dig/host/nslookup "@server" selects an explicit resolver that must be
            # allowlist-validated (else "dig @8.8.8.8 localhost" reaches a public resolver),
            # so strip the '@' and classify the remainder.
            server = arg[1:]
            if _looks_like_target(server):
                value = server
            i += 1
        elif (tool_name == "curl" or binary == "curl") and arg in _CURL_REDIRECT_FLAGS and i + 1 < len(arg_list):
            _validate_curl_redirect_target(arg, arg_list[i + 1])
            i += 2
            continue
        elif (tool_name == "curl" or binary == "curl") and "=" in arg and arg.split("=", 1)[0] in _CURL_REDIRECT_FLAGS:
            _cr_flag, _cr_val = arg.split("=", 1)
            _validate_curl_redirect_target(_cr_flag, _cr_val)
            i += 1
            continue
        elif arg in _PROXY_FLAGS and i + 1 < len(arg_list):
            _validate_proxy_target(arg_list[i + 1])
            i += 2
            continue
        elif any(arg.startswith(flag) and arg != flag for flag in _ATTACHED_PROXY_FLAGS):
            for flag in _ATTACHED_PROXY_FLAGS:
                if arg.startswith(flag) and arg != flag:
                    value = arg[len(flag) :]
                    if value.startswith("="):
                        value = value[1:]
                    _validate_proxy_target(value)
                    break
            i += 1
            continue
        elif "=" in arg and arg.split("=", 1)[0] in _PROXY_FLAGS:
            _validate_proxy_target(arg.split("=", 1)[1])
            i += 1
            continue
        elif not arg.startswith("-") and not arg.startswith("/"):
            # Positional arg — only validate if it looks like a network target.
            # Skip bare numbers (port/timeout values for flags like -p 80, -T 4)
            # and plain words (flag values like -l admin, --script vuln).
            if _looks_like_target(arg) and not _is_non_target_positional(tool_name, binary, arg):
                value = arg
            i += 1
        else:
            # Unrecognized flag. First close the embedded-value bypass: a target
            # joined to the flag as -flag=<host> (single/double-dash long flags like
            # goflags' -target=/-host=/-domain=) or attached as -f<host> never reaches
            # the separated-token heuristic below, so extract and allowlist-check it
            # here. Only strong targets are validated (see _looks_like_external_target)
            # so boolean flags (-silent) and local output names (-o=results) don't trip.
            _embedded = None
            if "=" in arg:
                _embedded = arg.split("=", 1)[1]
            elif not arg.startswith("--") and len(arg) > 2:
                _embedded = arg[2:]
            if (
                _embedded
                and _looks_like_external_target(_embedded)
                and not (_has_file_extension(_embedded) and _is_local_path(_embedded))
            ):
                value = _embedded
                i += 1
                # fall through (no continue) to the allowlist check below
            else:
                # After --long-flags, the next non-flag token may be a flag value
                # (--script vuln) or a real target after a boolean flag (--open evil.com).
                # Use the same _looks_like_target heuristic as positional args so
                # encoded-integer IPs and bare single-label hostnames (which lack
                # dots/colons/slashes) are still validated — a leading-flag form must
                # not be more lenient than the positional one. Plain non-target words
                # are consumed as flag values.
                if arg.startswith("-") and i + 1 < len(arg_list) and not arg_list[i + 1].startswith("-"):
                    next_token = arg_list[i + 1]
                    # Skip tokens with file extensions as flag values (scan.txt, report.json)
                    # — but only when clearly a LOCAL path, since some extensions are also live
                    # TLDs (evil.zip, example.mobi) that must fall through to target validation
                    # and not launder an external host past the allowlist.
                    if _looks_like_target(next_token) and (
                        not _has_file_extension(next_token) or not _is_local_path(next_token)
                    ):
                        # Looks like a real target — don't consume, validate next iteration
                        i += 1
                    else:
                        # Plain word or filename — likely a flag value, consume it
                        i += 2
                else:
                    i += 1
                continue

        if value:
            clean = _network_target_host(value, domain_credentials=_takes_domain_credentials(tool_name, binary))
            if not _is_safe_target(clean):
                raise ValueError(
                    f"Blocked by policy: target '{value}' is not in a private/local "
                    f"network range. Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 to allow "
                    f"external targets."
                )


# Validation and execution logic
def validate_tool_for_execution(tool_name: str, tools_db: ToolsDatabase) -> str:
    """Validate that a tool can be executed. Returns the resolved binary name.

    System utilities (cat, grep, curl, etc.) bypass the registry check but
    still require the binary to be present in PATH.

    Raises ValueError if the tool cannot be executed.
    """
    # System utilities: skip registry check, just verify PATH
    if tool_name in SYSTEM_UTILITIES:
        path = shutil.which(tool_name)
        if not path:
            raise ValueError(f"System utility '{tool_name}' is not installed or not in PATH")
        return tool_name

    tool = tools_db.tools_by_name.get(tool_name)
    package = None if tool else package_for_extra_binary(tool_name)
    if package and tools_db.tools_by_name.get(package):
        tool = tools_db.tools_by_name[package]
    if not tool:
        raise ValueError(f"Tool '{tool_name}' not found in tools_config.json")

    metadata = execution_metadata(tool)
    if not metadata["executable"]:
        raise ValueError(f"Tool '{tool_name}' is not directly executable as a CLI command: {metadata['reason']}")

    # Resolve binary name (pipx packages may have different binary names)
    if package:
        binary = tool_name
    elif len(binary_candidates(tool["method"], tool["name"])) > 1:
        binary = resolve_installed_binary(tool["method"], tool["name"])
    else:
        binary = metadata["binary"]

    path = shutil.which(binary)
    if not path:
        raise ValueError(f"Tool '{tool_name}' (binary: '{binary}') is not installed or not in PATH")

    return binary


# Max length for args string to prevent DoS from huge input (100KB is plenty for CLI args)
MAX_ARGS_LEN = 100_000

# Per-read chunk size for _bounded_communicate.
_READ_CHUNK = 65_536


def _kill_process_group(process: asyncio.subprocess.Process) -> None:
    """SIGKILL the whole process group so a timed-out tool's forked children die too.

    Each subprocess is started with ``start_new_session=True``, making it the leader
    of a new group whose id equals its pid. ``process.kill()`` signals only the
    direct child, leaving grandchildren (workers a tool forked) running past the
    timeout. Falls back to the direct process if the group is already gone. (SSH
    remotes are the exception: killing the local ssh client cannot reap a process
    still running on the remote host.)
    """
    pid = process.pid
    # os.killpg() accepts any object with __index__, and a test double coerces to 1.
    # killpg(1) is kill(-1): SIGKILL to every process this user owns. killpg(0) would
    # signal our own group. Neither is ever a valid target, so require a real child pid.
    if not isinstance(pid, int) or pid <= 1:
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except ProcessLookupError:
            pass


class _StreamCapture:
    """Bytes captured so far from one pipe, readable by the caller after a cancel."""

    __slots__ = ("data", "truncated")

    def __init__(self) -> None:
        self.data = bytearray()
        self.truncated = False


# How long pipes may stay open after the process itself has exited. A forked helper
# that inherited stdout/stderr would otherwise hold the call until the timeout.
_DRAIN_GRACE_SECONDS = 2.0


def _partial_streams(process: asyncio.subprocess.Process, max_bytes: int) -> tuple[str, str, bool]:
    """Sanitized stdout and stderr captured before a timeout, and whether either was capped."""
    capture = getattr(process, "_cybersec_capture", None)
    if not (isinstance(capture, tuple) and all(isinstance(part, _StreamCapture) for part in capture)):
        return "", "", False
    out, err = capture
    stdout, out_capped = _finalize_stream_with_status(
        out.data.decode("utf-8", errors="replace"), max_bytes, out.truncated
    )
    stderr, err_capped = _finalize_stream_with_status(
        err.data.decode("utf-8", errors="replace"), max_bytes, err.truncated
    )
    return stdout, stderr, out_capped or err_capped


async def _bounded_communicate(
    process: asyncio.subprocess.Process,
    *,
    input_bytes: bytes | None = None,
    max_stream_bytes: int,
) -> tuple[bytes, bool, bytes, bool]:
    """Bounded, concurrent replacement for ``process.communicate()``.

    Streams stdout/stderr off the child concurrently (so a full pipe buffer
    on either stream does not deadlock the child), keeping at most
    *max_stream_bytes* in memory per stream. Any bytes past the cap are
    still drained from the pipe — and discarded — so the child can exit.

    Returns ``(stdout_bytes, stdout_truncated, stderr_bytes, stderr_truncated)``.

    Memory stays O(max_stream_bytes) however much the child writes. The caller
    is still responsible for the timeout; what was captured before a cancel stays
    readable through :func:`_partial_streams`. When the process has exited but a
    descendant still holds the pipes, the group is killed after a short grace period
    and what was read is returned.
    """
    out = _StreamCapture()
    err = _StreamCapture()
    try:
        process._cybersec_capture = (out, err)  # type: ignore[attr-defined]
    except AttributeError:
        pass

    async def _drain(stream: asyncio.StreamReader | None, capture: _StreamCapture) -> None:
        if stream is None:
            return
        while True:
            chunk = await stream.read(_READ_CHUNK)
            if not chunk:
                break
            space = max_stream_bytes - len(capture.data)
            if space > 0:
                capture.data.extend(chunk[:space])
                if len(chunk) > space:
                    capture.truncated = True
            else:
                capture.truncated = True

    async def _write_stdin() -> None:
        if process.stdin is None or input_bytes is None:
            return
        try:
            process.stdin.write(input_bytes)
            await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                process.stdin.close()
            except Exception:
                pass

    # Drain both pipes concurrently; write stdin alongside so a child that
    # blocks on a full stdout pipe while we block on its stdin can't deadlock.
    tasks = [
        asyncio.create_task(_drain(process.stdout, out)),
        asyncio.create_task(_drain(process.stderr, err)),
    ]
    if input_bytes is not None and process.stdin is not None:
        tasks.append(asyncio.create_task(_write_stdin()))

    # Process.wait() on Python 3.11 blocks while a descendant holds the pipes, so detect exit via returncode.
    wait_task = asyncio.create_task(process.wait())
    try:
        while process.returncode is None and not wait_task.done():
            running = {task for task in tasks if not task.done()}
            if not running:
                await wait_task
                break
            # Unfinished tasks only: a finished one (the stdin writer, a closed stream) would make
            # FIRST_COMPLETED return at once on every pass and spin a core for the whole run.
            await asyncio.wait({wait_task, *running}, timeout=0.05, return_when=asyncio.FIRST_COMPLETED)
        pending = {task for task in tasks if not task.done()}
        if pending:
            _, pending = await asyncio.wait(pending, timeout=_DRAIN_GRACE_SECONDS)
        if pending:
            _kill_process_group(process)
            await asyncio.wait(pending, timeout=1.0)
    finally:
        for task in (*tasks, wait_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, wait_task, return_exceptions=True)

    return bytes(out.data), out.truncated, bytes(err.data), err.truncated


def _append_truncation_marker(text: str, max_bytes: int) -> str:
    """Append the truncation marker within max_bytes; forced even when the text
    fits because the stream was capped upstream.
    """
    max_bytes = max(0, max_bytes)
    truncated_text, was_truncated = truncate_output(text, max_bytes)
    if was_truncated:
        return truncated_text
    # truncate_output left text intact (it already fit within max_bytes), but the
    # stream WAS bounded upstream — append the marker using the same format,
    # trimming from the tail if needed to stay within max_bytes.
    marker = f"\n... [truncated at {max_bytes} bytes]"
    marker_bytes = marker.encode("utf-8")
    if len(marker_bytes) > max_bytes:
        return marker_bytes[:max_bytes].decode("utf-8", errors="ignore")
    encoded = text.encode("utf-8")
    if len(encoded) + len(marker_bytes) <= max_bytes:
        return text + marker
    cut = max(0, max_bytes - len(marker_bytes))
    return encoded[:cut].decode("utf-8", errors="ignore") + marker


def _redact_output_enabled() -> bool:
    """Opt-in redaction of credential-shaped strings in returned tool output.

    A protective switch accepts the common truthy spellings, so ``=true`` does not
    silently leave redaction off. The permissive switches above stay strict.
    """
    return _protective_flag("CYBERSEC_MCP_REDACT_OUTPUT")


def _sanitize_for_model(text: str) -> str:
    """Sanitize output returned to the client, which passes it to its model provider.

    With CYBERSEC_MCP_REDACT_OUTPUT=1, credentials a tool finds on a target are
    redacted too; by default they are returned as-is because the operator may
    need them for a proof of concept.
    """
    text = sanitize_output(text)
    return redact_credentials(text) if _redact_output_enabled() else text


def _finalize_stream(text: str, max_bytes: int, was_capped: bool) -> str:
    return _finalize_stream_with_status(text, max_bytes, was_capped)[0]


def _finalize_stream_with_status(text: str, max_bytes: int, was_capped: bool) -> tuple[str, bool]:
    """Sanitize a captured stream, then bound it to ``max_bytes``.

    Order matters: :func:`sanitize_output` inserts ``[SANITIZED] `` prefixes, so
    applying the byte budget first lets the returned text exceed ``max_bytes``.
    The budget is applied even when the stream was not capped upstream, for the
    same reason — sanitizing can push an under-limit stream over it.
    """
    text = _sanitize_for_model(text)
    if was_capped:
        return _append_truncation_marker(text, max_bytes), True
    return truncate_output(text, max_bytes)


def _step_args_to_str(step: dict) -> str:
    """Normalize pipeline step 'args' to a string for sanitize_args.

    Accepts str or list of strings (e.g. from JSON API). Other types are stringified.
    """
    raw = step.get("args", "")
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        return " ".join(shlex.quote(str(a)) for a in raw)
    return str(raw) if raw is not None else ""


def sanitize_args(args: str) -> list[str]:
    """Parse and sanitize command-line arguments.

    Raises ValueError on dangerous patterns.
    """
    if not isinstance(args, str):
        args = str(args) if args is not None else ""
    if not args or not args.strip():
        return []

    if len(args) > MAX_ARGS_LEN:
        raise ValueError(
            f"Arguments string exceeds max length ({MAX_ARGS_LEN} bytes). "
            "Split into multiple tool calls or shorten arguments."
        )

    # A NUL byte truncates the arg at the execve boundary, so reject it rather
    # than let exec raise a raw ValueError past the policy layer.
    if "\x00" in args:
        raise ValueError("Arguments contain a NUL byte")

    # Check for dangerous shell metacharacters before parsing
    if _DANGEROUS_PATTERNS.search(args):
        raise ValueError(f"Arguments contain blocked shell metacharacters: {args!r}. Blocked patterns: | ` $( ${{")

    try:
        parsed = shlex.split(args)
    except ValueError as e:
        raise ValueError(f"Failed to parse arguments: {e}") from e

    return parsed


async def execute_tool(
    tool_name: str,
    args: str,
    tools_db: ToolsDatabase,
    timeout: int = 120,
    max_output: int = 200000,
) -> dict:
    """Execute a tool safely and return its output.

    Returns dict with: exit_code, stdout, stderr, truncated, command.
    """
    exec_start = time.monotonic()
    binary = tool_name

    # Validate, sanitize, and enforce policy — return structured errors
    try:
        binary = validate_tool_for_execution(tool_name, tools_db)
        log_validation(tool_name, "resolve", True, detail=binary)
        arg_list = sanitize_args(args)
        log_validation(tool_name, "sanitize", True, detail=f"{len(arg_list)} args")
        await asyncio.to_thread(check_policy, tool_name, arg_list, binary)
        log_validation(tool_name, "policy", True)
    except ValueError as e:
        args = _blocked_args_for_logging(tool_name, args, binary)
        reason = _tool_policy_error(tool_name, binary, e)
        log_validation(tool_name, "failed", False, detail=reason)
        log_blocked(tool_name=tool_name, args=args, reason=reason)
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": reason,
            "truncated": False,
            "command": tool_name + (" " + args if args else ""),
        }

    timeout = max(1, min(timeout, 300))

    command = [binary] + _execution_arg_list(tool_name, binary, arg_list)

    # Check rate limit BEFORE acquiring semaphore to avoid holding slots on rate-limit errors
    try:
        await _rate_limiter.acquire()
    except ValueError as e:
        log_blocked(tool_name=tool_name, args=args, reason=str(e))
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "truncated": False,
            "command": tool_name + (" " + args if args else ""),
        }

    async with _rate_limiter._semaphore:
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *_sandbox_wrap(command, module=_tool_module(tool_name, tools_db)),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # own process group, so killpg reaps forks
                env=_child_env(),
            )

            try:
                stdout_bytes, t_read_stdout, stderr_bytes, t_read_stderr = await asyncio.wait_for(
                    _bounded_communicate(process, max_stream_bytes=max_output),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                _kill_process_group(process)
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    pass  # Process may be in D state; leave as zombie rather than hang
                cmd_str = shlex.join(command)
                elapsed = (time.monotonic() - exec_start) * 1000
                partial_out, partial_err, partial_truncated = _partial_streams(process, max_output)
                log_execution(
                    tool_name=tool_name,
                    args=args,
                    host="localhost",
                    exit_code=-1,
                    command=cmd_str,
                    duration_ms=elapsed,
                    stdout_len=len(partial_out.encode("utf-8")),
                    stderr_len=len(partial_err.encode("utf-8")),
                    truncated=partial_truncated,
                    outcome="timeout",
                )
                return {
                    "exit_code": -1,
                    "stdout": partial_out,
                    "stderr": f"Process timed out after {timeout} seconds"
                    + (f"\n{partial_err}" if partial_err else ""),
                    "truncated": partial_truncated,
                    "command": cmd_str,
                }
            # A descendant that detached from the pipes must not outlive the audited call.
            _kill_process_group(process)

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            stdout, out_capped = _finalize_stream_with_status(stdout, max_output, t_read_stdout)
            stderr, err_capped = _finalize_stream_with_status(stderr, max_output, t_read_stderr)
            truncated = out_capped or err_capped

            cmd_str = shlex.join(command)
            rc = process.returncode if process.returncode is not None else -1
            elapsed = (time.monotonic() - exec_start) * 1000
            log_execution(
                tool_name=tool_name,
                args=args,
                host="localhost",
                exit_code=rc,
                command=cmd_str,
                duration_ms=elapsed,
                stdout_len=len(stdout.encode("utf-8")),
                stderr_len=len(stderr.encode("utf-8")),
                truncated=truncated,
                outcome="ok",
            )

            return {
                "exit_code": rc,
                "stdout": stdout,
                "stderr": stderr,
                "truncated": truncated,
                "command": cmd_str,
            }

        except asyncio.CancelledError:
            if process is not None:
                _kill_process_group(process)
            log_execution(
                tool_name=tool_name,
                args=args,
                host="localhost",
                exit_code=-1,
                command=shlex.join(command),
                duration_ms=(time.monotonic() - exec_start) * 1000,
                outcome="cancelled",
            )
            raise
        except FileNotFoundError:
            cmd_str = shlex.join(command)
            elapsed = (time.monotonic() - exec_start) * 1000
            log_execution(
                tool_name=tool_name,
                args=args,
                host="localhost",
                exit_code=-1,
                command=cmd_str,
                duration_ms=elapsed,
                outcome="error",
            )
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Binary '{binary}' not found",
                "truncated": False,
                "command": cmd_str,
            }
        except OSError as e:
            cmd_str = shlex.join(command)
            elapsed = (time.monotonic() - exec_start) * 1000
            log_execution(
                tool_name=tool_name,
                args=args,
                host="localhost",
                exit_code=-1,
                command=cmd_str,
                duration_ms=elapsed,
                outcome="error",
            )
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Failed to execute: {e}",
                "truncated": False,
                "command": cmd_str,
            }


# Pipeline execution — safe stdin piping without shell


def _remote_outcome(result: dict) -> str:
    if str(result.get("stderr", "")).startswith("Remote process timed out"):
        return "timeout"
    return "error" if result.get("exit_code", -1) == -1 else "ok"


def _pipeline_outcome(result: dict) -> str:
    if str(result.get("stderr", "")).startswith("Pipeline timed out"):
        return "timeout"
    return "error" if result.get("exit_code", -1) == -1 else "ok"


MAX_PIPELINE_STEPS = 10


def _pipeline_error(msg: str) -> dict:
    """Return a structured error for pipeline failures."""
    return {
        "exit_code": -1,
        "stdout": "",
        "stderr": msg,
        "truncated": False,
        "commands": [],
        "step_count": 0,
        "step_results": [],
        "had_failures": True,
    }


def _pipeline_tools_for_audit(steps: list[dict]) -> str:
    """The tool names of a pipeline, for records that must not carry arguments."""
    return " | ".join(str(step.get("tool", "")) for step in steps)


_STDIN_COMMAND_CONSOLES = frozenset(
    {
        "gdb",
        "radare2",
        "r2",
        "bettercap",
        "recon-ng",
        "PhpSploit",
        "RouterSploit",
        "Penelope",
        "Villain",
        "Hoaxshell",
        "dnscat2",
        "ropium",
        "featherduster",
        "medusa-frida",
        "osquery",
        "osqueryi",
        "bluez",
        "bluetoothctl",
        "SET",
        "PRET",
        "pret",
        "NoSQLMap",
        "krbrelayx",
        "evil-winrm",
    }
)


def _check_pipeline_stdin(tool_name: str, binary: str, arg_list: list[str], index: int) -> None:
    if index == 0 or arg_list in (["-h"], ["--help"], ["--version"], ["-V"]):
        return
    owner = package_for_extra_binary(tool_name) or tool_name
    if {owner, tool_name, binary} & _STDIN_COMMAND_CONSOLES:
        raise ValueError(
            f"Blocked by policy: {owner}: piped stdin can execute unvalidated console commands; "
            "use an explicit supported argv invocation"
        )


async def _run_pipeline_steps(
    steps: list[dict],
    tools_db: ToolsDatabase,
    timeout: int,
    max_output: int,
    pipeline_id: str = "",
) -> dict:
    """Execute validated pipeline steps, piping stdout→stdin between them.

    Piped stdin is not scope-validated: a stdin-reading network tool can be fed
    an external target produced by a prior step. See execute_pipeline and
    SECURITY.md.
    """
    deadline = time.monotonic() + timeout
    prev_output: bytes | None = None
    commands: list[str] = []
    step_results: list[dict[str, Any]] = []
    truncated_any = False
    last_stderr_bytes = b""
    last_stdout_capped = False
    last_stderr_capped = False

    for i, step in enumerate(steps):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Pipeline timed out at step {i + 1}",
                "truncated": truncated_any,
                "commands": commands,
                "step_count": i,
                "failed_step": i + 1,
                "step_results": step_results,
                "had_failures": True,
            }

        step_start = time.monotonic()
        # Revalidate inside the try: a binary can vanish between pre-validation and launch.
        try:
            binary = validate_tool_for_execution(step["tool"], tools_db)
            arg_list = sanitize_args(_step_args_to_str(step))
            _check_pipeline_stdin(step["tool"], binary, arg_list, i)
        except ValueError as e:
            log_pipeline_step(pipeline_id, i + 1, step["tool"], -1, (time.monotonic() - step_start) * 1000)
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Step {i + 1} ({step['tool']}): {e}",
                "truncated": truncated_any,
                "commands": commands,
                "step_count": i + 1,
                "failed_step": i + 1,
                "step_results": step_results,
                "had_failures": True,
            }
        command = [binary] + _execution_arg_list(step["tool"], binary, arg_list)
        cmd_str = shlex.join(command)
        commands.append(cmd_str)

        stdin_mode = asyncio.subprocess.DEVNULL if i == 0 else asyncio.subprocess.PIPE

        try:
            process = await asyncio.create_subprocess_exec(
                *_sandbox_wrap(command, module=_tool_module(step["tool"], tools_db)),
                stdin=stdin_mode,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
                env=_child_env(),
            )

            try:
                stdout_bytes, t_read_stdout, stderr_bytes, t_read_stderr = await asyncio.wait_for(
                    _bounded_communicate(
                        process,
                        input_bytes=prev_output if i > 0 else None,
                        max_stream_bytes=max_output,
                    ),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                _kill_process_group(process)
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    pass
                step_elapsed = (time.monotonic() - step_start) * 1000
                log_pipeline_step(pipeline_id, i + 1, step["tool"], -1, step_elapsed)
                partial_out, partial_err, partial_truncated = _partial_streams(process, max_output)
                return {
                    "exit_code": -1,
                    "stdout": partial_out,
                    "stderr": f"Pipeline timed out at step {i + 1} after {timeout}s"
                    + (f"\n{partial_err}" if partial_err else ""),
                    "truncated": truncated_any or partial_truncated,
                    "commands": commands,
                    "step_count": i + 1,
                    "failed_step": i + 1,
                    "step_results": step_results
                    + [
                        {
                            "step": i + 1,
                            "tool": step["tool"],
                            "exit_code": -1,
                            "stderr": f"Pipeline timed out after {timeout}s",
                            "output_bytes": 0,
                            "truncated": False,
                        }
                    ],
                    "had_failures": True,
                }
            except asyncio.CancelledError:
                _kill_process_group(process)
                log_pipeline_step(pipeline_id, i + 1, step["tool"], -1, (time.monotonic() - step_start) * 1000)
                raise
            _kill_process_group(process)

            truncated_any = truncated_any or t_read_stdout or t_read_stderr
            last_stderr_bytes, last_stdout_capped, last_stderr_capped = stderr_bytes, t_read_stdout, t_read_stderr

            rc = process.returncode if process.returncode is not None else -1
            step_elapsed = (time.monotonic() - step_start) * 1000
            log_pipeline_step(
                pipeline_id,
                i + 1,
                step["tool"],
                rc,
                step_elapsed,
                output_bytes=len(stdout_bytes),
            )
            step_stderr, step_stderr_truncated = truncate_output(
                _sanitize_for_model(stderr_bytes.decode("utf-8", errors="replace")),
                4096,
            )
            truncated_any = truncated_any or step_stderr_truncated
            step_results.append(
                {
                    "step": i + 1,
                    "tool": step["tool"],
                    "exit_code": rc,
                    "stderr": step_stderr,
                    "output_bytes": len(stdout_bytes),
                    "truncated": t_read_stdout or t_read_stderr or step_stderr_truncated,
                }
            )
            if rc != 0 and i < len(steps) - 1:
                # Intermediate step with non-zero exit (e.g. grep returning 1
                # for "no matches") — continue the pipeline with whatever
                # output was produced, mirroring shell pipe behaviour.
                prev_output = stdout_bytes
                continue
            elif rc != 0:
                # Last step with non-zero exit — return output along with
                # the exit code (like a shell pipe does).
                stdout, out_capped = _finalize_stream_with_status(
                    stdout_bytes.decode("utf-8", errors="replace"), max_output, t_read_stdout
                )
                stderr, err_capped = _finalize_stream_with_status(
                    stderr_bytes.decode("utf-8", errors="replace"), max_output, t_read_stderr
                )
                return {
                    "exit_code": rc,
                    "stdout": stdout,
                    "stderr": stderr,
                    "truncated": truncated_any or out_capped or err_capped,
                    "commands": commands,
                    "step_count": len(steps),
                    "step_results": step_results,
                    "had_failures": True,
                }
            else:
                prev_output = stdout_bytes

        except FileNotFoundError:
            step_elapsed = (time.monotonic() - step_start) * 1000
            log_pipeline_step(pipeline_id, i + 1, step["tool"], -1, step_elapsed)
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Binary not found for step {i + 1}: {cmd_str}",
                "truncated": truncated_any,
                "commands": commands,
                "step_count": i + 1,
                "failed_step": i + 1,
                "step_results": step_results,
                "had_failures": True,
            }
        except OSError as e:
            step_elapsed = (time.monotonic() - step_start) * 1000
            log_pipeline_step(pipeline_id, i + 1, step["tool"], -1, step_elapsed)
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Failed to execute step {i + 1}: {e}",
                "truncated": truncated_any,
                "commands": commands,
                "step_count": i + 1,
                "failed_step": i + 1,
                "step_results": step_results,
                "had_failures": True,
            }

    # The truncation marker belongs to the stream it cuts: the last step's own capture.
    stdout, out_capped = _finalize_stream_with_status(
        (prev_output or b"").decode("utf-8", errors="replace"), max_output, last_stdout_capped
    )
    stderr, err_capped = _finalize_stream_with_status(
        last_stderr_bytes.decode("utf-8", errors="replace"), max_output, last_stderr_capped
    )

    return {
        "exit_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": truncated_any or out_capped or err_capped,
        "commands": commands,
        "step_count": len(steps),
        "step_results": step_results,
        "had_failures": any(step["exit_code"] != 0 for step in step_results),
    }


async def execute_pipeline(
    steps: list[dict],
    tools_db: ToolsDatabase,
    timeout: int = 120,
    max_output: int = 200000,
) -> dict:
    """Execute a pipeline of tools, piping stdout→stdin between steps.

    Each step is validated (allowlist, sanitize_args, check_policy) before
    any process is started. Uses asyncio.create_subprocess_exec (no shell).

    Scope note: check_policy inspects each step's argv only. A step that reads
    its targets from stdin (e.g. httpx/dnsx/naabu) is not scope-checked on the
    piped-in bytes, so a prior step's stdout can carry an external target that
    the argv-only external-network policy would reject on a lone run_tool call.
    Pipelines are a no-shell composition primitive, not a network-scope
    boundary; see SECURITY.md.

    Args:
        steps: List of dicts with 'tool' and optional 'args' keys.
        tools_db: ToolsDatabase for allowlist validation.
        timeout: Global timeout for entire pipeline (clamped 1-300).
        max_output: Max output size for final step.

    Returns:
        Dict with exit_code, stdout, stderr, truncated, commands, step_count,
        step_results, and had_failures. The final exit code retains shell-pipe
        compatibility while step_results exposes intermediate failures.
    """
    if not steps:
        return _pipeline_error("Pipeline must have at least 1 step")
    if len(steps) > MAX_PIPELINE_STEPS:
        return _pipeline_error(f"Pipeline exceeds max {MAX_PIPELINE_STEPS} steps (got {len(steps)})")

    # Validate step shape before logging, which reads each step's fields.
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            return _pipeline_error(f"Step {i + 1} must be an object with a 'tool' key")
        if "tool" not in step:
            return _pipeline_error(f"Step {i + 1} missing required 'tool' key")
        if not isinstance(step["tool"], str):
            return _pipeline_error(f"Step {i + 1} 'tool' must be a string")

    audit_steps = [{**step, "args": _pipeline_args_for_audit(step["tool"], _step_args_to_str(step))} for step in steps]
    pipeline_id = log_pipeline_start(audit_steps, timeout)
    pipe_start = time.monotonic()

    result: dict | None = None
    outcome = "error"
    try:
        # Pre-validate ALL steps before executing any (shape already checked above).
        for i, step in enumerate(steps):
            binary = step["tool"]
            try:
                binary = validate_tool_for_execution(step["tool"], tools_db)
                args_str = _step_args_to_str(step)
                arg_list = sanitize_args(args_str)
                await asyncio.to_thread(check_policy, step["tool"], arg_list, binary)
                _check_pipeline_stdin(step["tool"], binary, arg_list, i)
            except ValueError as e:
                safe_args = _blocked_args_for_logging(step["tool"], _step_args_to_str(step))
                reason = _tool_policy_error(step["tool"], binary, e)
                log_blocked(tool_name=step["tool"], args=safe_args, reason=reason)
                return _pipeline_error(f"Step {i + 1} ({step['tool']}): {reason}")

        timeout = max(1, min(timeout, 300))

        # Check rate limit BEFORE acquiring semaphore
        try:
            await _rate_limiter.acquire()
        except ValueError as e:
            log_blocked(tool_name="pipeline", args=_pipeline_tools_for_audit(steps), reason=str(e))
            return _pipeline_error(str(e))

        async with _rate_limiter._semaphore:
            result = await _run_pipeline_steps(steps, tools_db, timeout, max_output, pipeline_id)
        outcome = _pipeline_outcome(result)
    except asyncio.CancelledError:
        outcome = "cancelled"
        raise
    finally:
        # Also on cancel or an unexpected error: every started pipeline gets a result record.
        log_pipeline_result(
            pipeline_id,
            result.get("exit_code", -1) if result else -1,
            (time.monotonic() - pipe_start) * 1000,
            result.get("step_count", 0) if result else 0,
            result.get("truncated", False) if result else False,
            outcome=outcome,
        )
    return result


# Script execution — write-and-run Python/Bash scripts

_SCRIPT_LANGUAGES = {"python": ".py", "bash": ".sh"}


def _resolve_venv_interpreter(venv_name: str) -> str | None:
    """Resolve a venv name to its Python interpreter path.

    Searches CYBERSEC_MCP_VENVS_DIR (default ~/.ctf-venvs/) for a venv
    with the given name and returns the python binary path if it exists.

    The venv name is validated to prevent path traversal outside the
    venvs directory.
    """
    # Reject path separators and traversal components
    if os.sep in venv_name or "/" in venv_name or "\x00" in venv_name or venv_name in (".", ".."):
        return None
    venvs_dir = os.environ.get("CYBERSEC_MCP_VENVS_DIR", "").strip()
    if not venvs_dir:
        venvs_dir = os.path.expanduser("~/.ctf-venvs")
    try:
        venvs_dir = os.path.realpath(venvs_dir)
    except OSError:
        return None
    venv_root = os.path.join(venvs_dir, venv_name)
    # Require venv path to exist and be a directory before resolving (avoids realpath on missing path)
    if not os.path.isdir(venv_root):
        return None
    try:
        if not os.path.realpath(venv_root).startswith(venvs_dir + os.sep):
            return None
    except OSError:
        return None
    venv_python = os.path.join(venv_root, "bin", "python")
    if os.path.isfile(venv_python):
        return venv_python
    # Windows compat
    venv_python_win = os.path.join(venv_root, "Scripts", "python.exe")
    if os.path.isfile(venv_python_win):
        return venv_python_win
    return None


async def execute_script(
    code: str,
    language: str = "python",
    timeout: int = 120,
    max_output: int = 200000,
    working_dir: str | None = None,
    venv: str | None = None,
) -> dict:
    """Write code to a temp file and execute it via python3/bash.

    Gated by CYBERSEC_MCP_ALLOW_SCRIPTS=1 env variable.

    Returns dict with: exit_code, stdout, stderr, truncated, language,
    script_file, working_dir.
    """
    # Env gate
    if not _allow_scripts():
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": ("Script execution is disabled. Set CYBERSEC_MCP_ALLOW_SCRIPTS=1 to enable."),
            "truncated": False,
            "language": language,
            "script_file": "",
            "working_dir": "",
        }

    lang = language.lower().strip()
    if lang not in _SCRIPT_LANGUAGES:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Unsupported language '{language}'. Supported: {', '.join(sorted(_SCRIPT_LANGUAGES))}",
            "truncated": False,
            "language": language,
            "script_file": "",
            "working_dir": "",
        }

    if not code or not code.strip():
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "Script code is empty",
            "truncated": False,
            "language": lang,
            "script_file": "",
            "working_dir": "",
        }

    # Find interpreter
    if lang == "python":
        if venv:
            resolved = _resolve_venv_interpreter(venv)
            if resolved:
                interpreter = resolved
            else:
                venvs_dir = os.environ.get("CYBERSEC_MCP_VENVS_DIR", "").strip() or os.path.expanduser("~/.ctf-venvs")
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Venv '{venv}' not found. Expected: {venvs_dir}/{venv}/bin/python",
                    "truncated": False,
                    "language": lang,
                    "script_file": "",
                    "working_dir": "",
                }
        else:
            interpreter = sys.executable
    else:
        interpreter = shutil.which("bash")
        if not interpreter:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Interpreter 'bash' not found in PATH",
                "truncated": False,
                "language": lang,
                "script_file": "",
                "working_dir": "",
            }

    if working_dir:
        wd = Path(working_dir)
        if not wd.is_dir():
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Working directory '{working_dir}' does not exist or is not a directory",
                "truncated": False,
                "language": lang,
                "script_file": "",
                "working_dir": working_dir,
            }
        cwd = str(wd)
    else:
        cwd = tempfile.gettempdir()

    timeout = max(1, min(timeout, 300))

    try:
        payload = code.encode("utf-8")
    except UnicodeEncodeError as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Script code is not valid UTF-8 text: {e.reason} at position {e.start}",
            "truncated": False,
            "language": lang,
            "script_file": "",
            "working_dir": cwd,
        }

    # Rate-limit before the pre-execution audit record, so that record means the script ran.
    try:
        await _rate_limiter.acquire()
    except ValueError as e:
        log_blocked(tool_name="run_script", args=f"{lang} script", reason=str(e))
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "truncated": False,
            "language": lang,
            "script_file": "",
            "working_dir": cwd,
        }

    suffix = _SCRIPT_LANGUAGES[lang]
    try:
        fd, script_path = tempfile.mkstemp(suffix=suffix, prefix="mcp_script_")
    except OSError as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Failed to create the script file: {e}",
            "truncated": False,
            "language": lang,
            "script_file": "",
            "working_dir": cwd,
        }
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)

        async with _rate_limiter._semaphore:
            log_script_execution(
                language=lang,
                code=code,
                script_file=script_path,
                working_dir=cwd,
                venv=venv or "",
            )
            script_start = time.monotonic()
            process = None
            # Execute
            try:
                process = await asyncio.create_subprocess_exec(
                    *_sandbox_wrap([interpreter, script_path]),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                    start_new_session=True,
                    env=_child_env(),
                )

                try:
                    stdout_bytes, t_read_stdout, stderr_bytes, t_read_stderr = await asyncio.wait_for(
                        _bounded_communicate(process, max_stream_bytes=max_output),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    _kill_process_group(process)
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        pass
                    elapsed = (time.monotonic() - script_start) * 1000
                    log_script_result(lang, -1, elapsed, script_file=script_path, outcome="timeout")
                    partial_out, partial_err, partial_truncated = _partial_streams(process, max_output)
                    return {
                        "exit_code": -1,
                        "stdout": partial_out,
                        "stderr": f"Script timed out after {timeout} seconds"
                        + (f"\n{partial_err}" if partial_err else ""),
                        "truncated": partial_truncated,
                        "language": lang,
                        "script_file": script_path,
                        "working_dir": cwd,
                    }
                _kill_process_group(process)

                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")

                stdout, out_capped = _finalize_stream_with_status(stdout, max_output, t_read_stdout)
                stderr, err_capped = _finalize_stream_with_status(stderr, max_output, t_read_stderr)
                truncated = out_capped or err_capped

                rc = process.returncode if process.returncode is not None else -1
                elapsed = (time.monotonic() - script_start) * 1000
                log_script_result(
                    lang,
                    rc,
                    elapsed,
                    script_file=script_path,
                    stdout_len=len(stdout.encode("utf-8")),
                    stderr_len=len(stderr.encode("utf-8")),
                    truncated=truncated,
                    outcome="ok",
                )

                return {
                    "exit_code": rc,
                    "stdout": stdout,
                    "stderr": stderr,
                    "truncated": truncated,
                    "language": lang,
                    "script_file": script_path,
                    "working_dir": cwd,
                }

            except asyncio.CancelledError:
                if process is not None:
                    _kill_process_group(process)
                log_script_result(
                    lang,
                    -1,
                    (time.monotonic() - script_start) * 1000,
                    script_file=script_path,
                    outcome="cancelled",
                )
                raise
            except FileNotFoundError:
                elapsed = (time.monotonic() - script_start) * 1000
                log_script_result(lang, -1, elapsed, script_file=script_path, outcome="error")
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Interpreter '{interpreter}' not found",
                    "truncated": False,
                    "language": lang,
                    "script_file": script_path,
                    "working_dir": cwd,
                }
            except OSError as e:
                elapsed = (time.monotonic() - script_start) * 1000
                log_script_result(lang, -1, elapsed, script_file=script_path, outcome="error")
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Failed to execute script: {e}",
                    "truncated": False,
                    "language": lang,
                    "script_file": script_path,
                    "working_dir": cwd,
                }
    finally:
        # Cleanup temp file
        try:
            os.unlink(script_path)
        except OSError:
            pass


# Remote execution support


def validate_tool_for_remote_execution(tool_name: str, tools_db: ToolsDatabase) -> str:
    """Validate that a tool can be executed remotely. Returns the resolved binary name.

    Like validate_tool_for_execution but skips the local shutil.which() check
    since the tool only needs to be installed on the remote host.
    System utilities bypass the registry check entirely for remote execution.

    Raises ValueError if the tool cannot be executed.
    """
    # System utilities: no registry or PATH check needed for remote
    if tool_name in SYSTEM_UTILITIES:
        return tool_name

    tool = tools_db.tools_by_name.get(tool_name)
    package = None if tool else package_for_extra_binary(tool_name)
    if package and tools_db.tools_by_name.get(package):
        tool = tools_db.tools_by_name[package]
    if not tool:
        raise ValueError(f"Tool '{tool_name}' not found in tools_config.json")

    metadata = execution_metadata(tool)
    if not metadata["executable"]:
        raise ValueError(f"Tool '{tool_name}' is not directly executable as a CLI command: {metadata['reason']}")

    return tool_name if package else metadata["binary"]


async def execute_tool_remote(
    tool_name: str,
    args: str,
    tools_db: ToolsDatabase,
    remote_config: Any,
    host: str,
    timeout: int = 120,
    max_output: int = 200000,
) -> dict:
    """Execute a tool on a remote host via SSH.

    Runs all security checks (sanitize_args, check_policy) locally before
    sending the command over SSH.

    Returns dict with: exit_code, stdout, stderr, truncated, command, remote.
    """
    from mcp_server.remote import execute_remote_command

    # Validate, sanitize, and enforce policy locally
    binary = tool_name
    try:
        # Allowlist check first
        if not remote_config.check_tool_allowed(host, tool_name):
            raise ValueError(f"Tool '{tool_name}' is not in the allowlist for host '{host}'")
        binary = validate_tool_for_remote_execution(tool_name, tools_db)
        arg_list = sanitize_args(args)
        await asyncio.to_thread(check_policy, tool_name, arg_list, binary)
        # Target validation may block on DNS.
        ssh_args = await asyncio.to_thread(remote_config.get_ssh_base_args, host)
    except ValueError as e:
        args = _blocked_args_for_logging(tool_name, args, binary)
        reason = _tool_policy_error(tool_name, binary, e)
        log_blocked(tool_name=tool_name, args=args, reason=reason, host=host, remote=True)
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": reason,
            "truncated": False,
            "command": tool_name + (" " + args if args else ""),
            "remote": True,
        }

    command = [binary] + _execution_arg_list(tool_name, binary, arg_list)

    # Check rate limit BEFORE acquiring semaphore (consistent with execute_tool)
    try:
        await _rate_limiter.acquire()
    except ValueError as e:
        log_blocked(tool_name=tool_name, args=args, reason=str(e), host=host, remote=True)
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "truncated": False,
            "command": tool_name + (" " + args if args else ""),
            "remote": True,
        }

    remote_start = time.monotonic()
    try:
        async with _rate_limiter._semaphore:
            registered = tools_db.tools_by_name.get(tool_name)
            if registered:
                candidates = binary_candidates(registered["method"], registered["name"])
                if len(candidates) > 1:
                    ordered = [binary, *(candidate for candidate in candidates if candidate != binary)]
                    for candidate in ordered:
                        installed = await execute_remote_command(
                            ssh_args, ["which", candidate], timeout=min(timeout, 10), max_output=4096
                        )
                        if installed.get("exit_code") == 0 and installed.get("stdout", "").strip():
                            command[0] = candidate
                            break
            result = await execute_remote_command(ssh_args, command, timeout=timeout, max_output=max_output)
    except asyncio.CancelledError:
        log_execution(
            tool_name=tool_name,
            args=args,
            host=host,
            exit_code=-1,
            command=shlex.join(command),
            remote=True,
            duration_ms=(time.monotonic() - remote_start) * 1000,
            outcome="cancelled",
        )
        raise

    # Streams arrive already marked when capped; only the byte budget is applied here.
    result["stdout"], out_capped = _finalize_stream_with_status(result.get("stdout", ""), max_output, False)
    result["stderr"], err_capped = _finalize_stream_with_status(result.get("stderr", ""), max_output, False)
    result["truncated"] = bool(result.get("truncated", False)) or out_capped or err_capped

    log_execution(
        tool_name=tool_name,
        args=args,
        host=host,
        exit_code=result.get("exit_code", -1),
        command=result.get("command", ""),
        remote=True,
        duration_ms=(time.monotonic() - remote_start) * 1000,
        stdout_len=len(result["stdout"].encode("utf-8")),
        stderr_len=len(result["stderr"].encode("utf-8")),
        truncated=bool(result.get("truncated", False)),
        outcome=_remote_outcome(result),
    )

    return result
