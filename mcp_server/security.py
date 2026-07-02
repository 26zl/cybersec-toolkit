"""Tool execution validation — allowlist, argument sanitization, policy, safe subprocess."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shlex
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

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
)
from mcp_server.sanitize import sanitize_output, truncate_output  # noqa: E402
from mcp_server.tools_db import ToolsDatabase, resolve_binary_name  # noqa: E402

# Methods that are not directly executable as CLI commands.
NON_EXECUTABLE_METHODS = {"git", "docker", "snap"}

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
        "dc",
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
    (re.compile(r"^--load(?:$|=)"), "awk: --load extension (command execution)"),
    (re.compile(r"^-l$"), "awk: -l load extension (command execution)"),
    (re.compile(r"(?:^|[\s;])@load\b"), "awk: @load extension directive (command execution)"),
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

# Tool-specific blocked flags — dangerous per-tool options.
TOOL_BLOCKED_FLAGS: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "sqlmap": [
        (re.compile(r"^--os-shell$"), "sqlmap: OS shell access"),
        (re.compile(r"^--os-cmd$"), "sqlmap: OS command execution"),
        (re.compile(r"^--os-pwn$"), "sqlmap: OOB exploitation"),
        (re.compile(r"^--priv-esc$"), "sqlmap: privilege escalation"),
        (re.compile(r"^--file-read$"), "sqlmap: arbitrary file read"),
        (re.compile(r"^--file-write$"), "sqlmap: arbitrary file write"),
        (re.compile(r"^--file-dest$"), "sqlmap: file write destination"),
    ],
    "sed": [
        (re.compile(r"^-i"), "sed: in-place file modification"),
        (re.compile(r"^--in-place"), "sed: in-place file modification"),
    ],
    "nmap": [
        (re.compile(r"^-iL"), "nmap: target list from file (bypasses target validation)"),
        (re.compile(r"^-iR"), "nmap: random target generation (bypasses target validation)"),
        # --script / --script-args load arbitrary NSE (Lua with os.execute) = RCE.
        (re.compile(r"^--script"), "nmap: NSE script execution (--script*)"),
    ],
    "masscan": [
        (re.compile(r"^--includefile(?:$|=)"), "masscan: target list from file"),
    ],
    "awk": _AWK_BLOCKED_FLAGS,
    "gawk": _AWK_BLOCKED_FLAGS,
    "tar": [
        (re.compile(r"^--checkpoint-action"), "tar: checkpoint-action command execution"),
        (re.compile(r"^--to-command"), "tar: to-command command execution"),
        # -I / --use-compress-program run an arbitrary program as the (de)compressor.
        (re.compile(r"^-I$"), "tar: -I external compressor (command execution)"),
        (re.compile(r"^--use-compress-program(?:$|=)"), "tar: external compressor (command execution)"),
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
        (re.compile(r"(?:^|[\s'\"(])shell\b", re.IGNORECASE), "gdb: shell command execution"),
        (re.compile(r"(?:^|[\s'\"(])(?:python|py|pi)\b", re.IGNORECASE), "gdb: python/pipe execution"),
        (re.compile(r"system\s*\("), "gdb: call system()"),
        (re.compile(r"(?:^|[\s'\"(])!"), "gdb: shell escape"),
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
    ],
    "wget": [
        (re.compile(r"^-i"), "wget: URL list from file bypasses target validation"),
        (re.compile(r"^--input-file(?:$|=)"), "wget: URL list from file bypasses target validation"),
    ],
    # ProjectDiscovery and similar recon/scan tools read targets from a file via
    # list flags, which would defeat the private/loopback target allowlist the
    # same way nmap -iL / wget -i do. Block the file-list flags defensively,
    # including attached short-flag forms; exact CLI parsing differs by version,
    # and the policy layer must fail closed.
    "nuclei": [
        (re.compile(r"^-l"), "nuclei: target list from file bypasses target validation"),
        (re.compile(r"^-list(?:$|=)"), "nuclei: target list from file bypasses target validation"),
    ],
    "httpx": [
        (re.compile(r"^-l(?!ocation(?:$|=))"), "httpx: target list from file bypasses target validation"),
        (re.compile(r"^-list(?:$|=)"), "httpx: target list from file bypasses target validation"),
    ],
    "subfinder": [
        (re.compile(r"^-dL"), "subfinder: domain list from file bypasses target validation"),
        (re.compile(r"^-list(?:$|=)"), "subfinder: domain list from file bypasses target validation"),
    ],
    "amass": [
        (re.compile(r"^-df"), "amass: domain list from file bypasses target validation"),
    ],
    # arjun (argparse) and whatweb (Ruby OptionParser) accept attached short-flag
    # values (-iurls.txt) as well, so prefix-match the single-letter -i flag.
    "arjun": [
        (re.compile(r"^-i"), "arjun: URL list from file bypasses target validation"),
        (re.compile(r"^--input(?:$|=)"), "arjun: URL list from file bypasses target validation"),
    ],
    "whatweb": [
        (re.compile(r"^-i"), "whatweb: target list from file bypasses target validation"),
        (re.compile(r"^--input-file(?:$|=)"), "whatweb: target list from file bypasses target validation"),
    ],
}

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
    "ffuf": {"-w", "-H", "-X", "-d", "-b", "-o", "-of", "-e"},
    "feroxbuster": {"-w", "-H", "-A", "-b", "-x", "-o", "--output"},
    "gobuster": {"-w", "-H", "-U", "-P", "-x", "-o", "--output"},
    "hydra": {"-l", "-L", "-p", "-P", "-s", "-t", "-o", "-x"},
    "patator": {"-x", "-l", "-p", "-L", "-P", "-o", "--output"},
    "httpx": {"-H", "-header", "-headers", "-path", "-body", "-method", "-o", "-json"},
    "nuclei": {"-H", "-header", "-t", "-templates", "-tags", "-severity", "-o", "-json-export", "-markdown-export"},
    "sqlmap": {"-p", "--headers", "--cookie", "--data", "--user-agent", "--method", "--risk", "--level", "-o"},
    "nmap": {"-oA", "-oN", "-oX", "-oG", "--top-ports", "--max-retries", "-p", "-T"},
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
}

# Positional words that are command modes/protocol names, not host targets. Keep
# this narrow: arbitrary single-label hostnames must still be validated/blocked
# in default-safe mode.
_NON_TARGET_POSITIONALS: dict[str, set[str]] = {
    "gobuster": {"dir", "dns", "vhost", "s3", "gcs", "fuzz", "tftp"},
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
    "openssl": {
        "asn1parse",
        "base64",
        "cms",
        "crl",
        "dgst",
        "enc",
        "genpkey",
        "list",
        "passwd",
        "pkcs7",
        "pkcs12",
        "pkey",
        "pkeyutl",
        "prime",
        "rand",
        "req",
        "rsa",
        "rsautl",
        "s_client",
        "s_server",
        "speed",
        "verify",
        "version",
        "x509",
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
    for flag in sorted(exempt, key=len, reverse=True):
        if flag.startswith("--") or len(flag) != 2:
            continue
        if arg.startswith(flag) and len(arg) > len(flag):
            value = arg[len(flag) :]
            if value.startswith("="):
                value = value[1:]
            return True, 1, flag, value
    return False, 0, None, None


def _validate_exempt_remote_resource(tool_name: str, binary: str, flag: str | None, value: str | None) -> None:
    """Validate URL-like values for exempt flags that may fetch remote resources."""
    if not flag or not value:
        return
    remote_flags = _REMOTE_RESOURCE_FLAGS.get(tool_name, set()) | _REMOTE_RESOURCE_FLAGS.get(binary, set())
    if flag not in remote_flags:
        return
    if re.match(r"^https?://", value, re.IGNORECASE) and not _is_safe_target(_network_target_host(value)):
        raise ValueError(
            f"Blocked by policy: remote resource '{value}' for {tool_name} {flag} is not in a private/local range. "
            "Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 for authorized external resource URLs."
        )


def _is_non_target_positional(tool_name: str, binary: str, arg: str) -> bool:
    """Return True for known positional mode/protocol tokens."""
    lowered = arg.lower()
    return lowered in (_NON_TARGET_POSITIONALS.get(tool_name, set()) | _NON_TARGET_POSITIONALS.get(binary, set()))


# Tools that perform network operations and need target validation.
_NETWORK_TOOLS: set[str] = {
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


# Thread-safe DNS resolution with per-call timeout (avoids process-global
# socket.setdefaulttimeout which races under concurrent tool executions).


def _resolve_with_timeout(hostname: str, timeout: float = 5.0) -> list:
    """Resolve hostname via getaddrinfo with a timeout.

    Uses a daemon thread so the calling thread is not blocked beyond *timeout*.
    """
    result: list = []
    error: list = []
    start = time.monotonic()

    def _resolve() -> None:
        try:
            result.extend(socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM))
        except (socket.gaierror, OSError) as exc:
            error.append(exc)

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout)
    elapsed = (time.monotonic() - start) * 1000
    if t.is_alive():
        log_dns(hostname, resolved=False, duration_ms=elapsed, error="timeout")
        raise socket.timeout(f"DNS resolution timed out after {timeout}s")
    if error:
        log_dns(hostname, resolved=False, duration_ms=elapsed, error=str(error[0]))
        raise error[0]
    if result:
        first_ip = result[0][4][0]
        is_safe = all(any(ipaddress.ip_address(sa[4][0]) in net for net in _SAFE_NETWORKS) for sa in result)
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


def _is_safe_target(value: str) -> bool:
    """Check if a string looks like a network target and is in a safe range."""
    if not value:
        return True  # Empty string is not a network target

    # Non-dotted encoded IPv4 (decimal/hex/octal) — e.g. 134744072 == 8.8.8.8.
    # Resolve before the dotted-quad parser so obfuscated externals are caught.
    encoded = _decode_encoded_ipv4(value)
    if encoded is not None:
        return any(encoded in net for net in _SAFE_NETWORKS)

    # Try parsing as IP address directly
    try:
        addr = ipaddress.ip_address(value)
        if any(addr in net for net in _SAFE_NETWORKS):
            return True
        # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:10.0.0.1 → 10.0.0.1)
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            return any(mapped in net for net in _SAFE_NETWORKS)
        return False
    except ValueError:
        pass

    # Try parsing as CIDR
    try:
        net = ipaddress.ip_network(value, strict=False)
        same_ver: list[Any] = [s for s in _SAFE_NETWORKS if s.version == net.version]
        return any(net.subnet_of(s) for s in same_ver)
    except (ValueError, TypeError):
        pass

    # Check for hostname-like strings (contains dots, no path separators)
    if "." in value and "/" not in value and not value.startswith("-"):
        # Common local/safe hostnames
        safe_hosts = {"localhost", "localhost.localdomain"}
        if value.lower() in safe_hosts:
            return True
        # Resolve and check — residual risk: this validation is independent of the tool's
        # connect-time resolution, so an attacker-controlled short-TTL/multi-answer record
        # can rebind past the default-safe check (DNS rebinding/TOCTOU); IP/CIDR/IPv6 literals
        # are validated directly above and are unaffected.
        try:
            info = _resolve_with_timeout(value)
            if not info:
                return False  # No resolution results — treat as unsafe
            for _, _, _, _, sockaddr in info:
                addr = ipaddress.ip_address(sockaddr[0])
                if not any(addr in net for net in _SAFE_NETWORKS):
                    return False
            return True
        except (socket.gaierror, OSError, socket.timeout):
            # Can't resolve — treat as potentially external
            return False

    # Not a recognizable IP/hostname — could be a decimal IP, bare hostname, etc.
    # Values that look like file paths or flags are allowed through.
    if value.startswith(("-", "/", "./", "~")):
        return True

    # Try DNS resolution as a last resort to catch targets like "google" or "134744072"
    try:
        info = _resolve_with_timeout(value)
        if not info:
            return False  # No resolution results — treat as unsafe
        for _, _, _, _, sockaddr in info:
            addr = ipaddress.ip_address(sockaddr[0])
            if not any(addr in net for net in _SAFE_NETWORKS):
                return False
        return True
    except (socket.gaierror, OSError, socket.timeout, ValueError):
        # Can't resolve — could be a bare hostname with transient DNS failure.
        # Deny to be safe; genuine non-network values (flags/paths) are caught above.
        return False


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


def _is_local_path(value: str) -> bool:
    """Return True if *value* is clearly a local filesystem path, not a target.

    A token counts as local when it contains a path separator (``/`` or ``\\``)
    or ends in a known file extension that is NOT also a real TLD. URLs and
    tokens that only "look like a file" because their extension doubles as a TLD
    (``.zip``, ``.mobi``, ``.sh``) are deliberately rejected here so an external
    host such as ``http://evil.zip`` or ``example.zip`` still gets
    target-validated.
    """
    # A URL is never a local path, even though it contains "/".
    if re.match(r"^https?://", value, re.IGNORECASE):
        return False
    lower = value.lower()
    if any(lower.endswith(ext) for ext in _EXTENSION_TLDS):
        return False
    if "/" in value or "\\" in value:
        return True
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
    if re.match(r"^https?://", value):
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
    # Hostname (contains dot, starts with alphanumeric)
    if "." in value and re.match(r"^[a-zA-Z0-9]", value):
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


def _network_target_host(value: str) -> str:
    """Normalize a URL/host argument to the host value used for allowlist checks."""
    clean = re.sub(r"^https?://", "", value)
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
    host = _network_target_host(stripped)
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


# ---------------------------------------------------------------------------
# Write-destination guard
# ---------------------------------------------------------------------------

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
)

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


def _is_sensitive_normalized_path(norm: str) -> bool:
    """Classify one absolute, normalized write path."""
    for directory in _SENSITIVE_WRITE_DIRS:
        for protected in {directory, os.path.realpath(directory)}:
            if norm == protected or norm.startswith(protected + os.sep):
                return True

    if os.path.basename(norm) in _SENSITIVE_BASENAMES:
        return True

    home = os.path.normpath(os.path.expanduser("~"))
    if home and home != os.sep and (norm == home or norm.startswith(home + os.sep)):
        rel = os.path.relpath(norm, home)
        if any(part.startswith(".") and part not in ("", ".", "..") for part in rel.split(os.sep)):
            return True

    return False


def _is_sensitive_write_target(path: str) -> bool:
    """Return True if writing to *path* would hit a sensitive location.

    Blocks: any dotfile under $HOME (``~/.bashrc``, ``~/.ssh/``,
    ``~/.config/autostart/``, ``~/.config/systemd/``, ...), known shell-rc/login
    files by basename, cron dirs, and system dirs (/etc, /usr, /bin, ...). Does
    NOT block /tmp, the CWD, or other ordinary working locations.
    """
    return any(_is_sensitive_normalized_path(candidate) for candidate in _write_path_candidates(path))


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
    """Extract separated, ``--flag=value``, and attached short-flag values."""
    values: list[str] = []
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        if arg in short_flags or arg in long_flags:
            if i + 1 < len(arg_list):
                values.append(arg_list[i + 1])
                i += 2
                continue
        if "=" in arg and arg.split("=", 1)[0] in long_flags:
            values.append(arg.split("=", 1)[1])
        else:
            for flag in short_flags:
                if arg.startswith(flag) and arg != flag:
                    values.append(arg[len(flag) :])
                    break
        i += 1
    return values


def _tar_short_flag_values(arg_list: list[str], flag: str) -> list[str]:
    """Extract values for value-taking tar flags inside short-option bundles."""
    values: list[str] = []
    for i, arg in enumerate(arg_list):
        body = ""
        if arg.startswith("-") and not arg.startswith("--"):
            body = arg[1:]
        elif i == 0 and re.fullmatch(r"[A-Za-z]+", arg):
            body = arg  # traditional tar syntax: ``tar xzf archive.tar.gz``
        if flag not in body:
            continue
        suffix = body.split(flag, 1)[1]
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


def _check_write_destinations(tool_name: str, binary: str, arg_list: list[str]) -> None:
    """Block file-mutating invocations that target a sensitive destination.

    Covers the write-capable system utilities (cp/mv/ln/tee/touch/mkdir) and the
    curl/wget output flags (``-o``/``--output``, ``-O``/``--output-document``).
    For ln, both the link path and the symlink target are checked. Positional
    arguments for the file utilities are all checked, since any of them can be a
    destination (cp/mv) and there is no benign reason to write into the blocked
    locations.
    """
    name = tool_name if tool_name in SYSTEM_UTILITIES else binary

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
                }
            ),
        ):
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
            for dest in directories or [os.getcwd()]:
                _raise_sensitive_write(name, dest)

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
        for dest in destinations or [os.getcwd()]:
            _raise_sensitive_write(name, dest)
        return

    if name == "7z":
        destinations = _flag_values(arg_list, short_flags=frozenset({"-o"}))
        command = next((arg for arg in arg_list if not arg.startswith("-")), "")
        if command in {"x", "e"}:
            destinations = destinations or [os.getcwd()]
        elif command in {"a", "u", "d", "rn"}:
            positionals = [arg for arg in arg_list if not arg.startswith("-")]
            destinations.extend(positionals[1:2])
        for dest in destinations:
            _raise_sensitive_write(name, dest)
        return

    if name == "zip":
        for arg in arg_list:
            if not arg.startswith("-"):
                _raise_sensitive_write(name, arg)
                break

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

    if name == "convert":
        positionals = [arg for arg in arg_list if not arg.startswith("-")]
        if positionals:
            _raise_sensitive_write(name, positionals[-1])
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

    if name == "yq" and any(arg in {"-i", "--inplace"} for arg in arg_list):
        for path in (arg for arg in arg_list if not arg.startswith("-")):
            _raise_sensitive_write(name, path)


def check_policy(tool_name: str, arg_list: list[str], binary: str | None = None) -> None:
    """Enforce execution policy on the resolved arguments.

    Raises ValueError if the command violates policy.
    """
    # 1. Check for blocked flags (universal)
    for arg in arg_list:
        for pattern, desc in BLOCKED_FLAGS:
            if pattern.match(arg):
                raise ValueError(f"Blocked by policy: {desc}")

    # 1b. Check for tool-specific blocked flags — search() not match(), since patterns
    # may match anywhere in the arg (e.g. awk's system() inside '{...}').
    binary = binary or tool_name
    for blocked_list in (TOOL_BLOCKED_FLAGS.get(tool_name, []), TOOL_BLOCKED_FLAGS.get(binary, [])):
        for arg in arg_list:
            for pattern, desc in blocked_list:
                if pattern.search(arg):
                    raise ValueError(f"Blocked by policy: {desc}")

    # 1c. Block file-mutating utilities (and curl/wget output flags) from writing
    # into dotfiles/shell-rc/cron/system dirs. This is a local-write concern, so
    # it runs regardless of the external-network policy below.
    _check_write_destinations(tool_name, binary, arg_list)

    # 2. Network target checks (only for network tools, unless external is allowed)
    if _allow_external():
        return

    if binary not in _NETWORK_TOOLS and tool_name not in _NETWORK_TOOLS:
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
            # Unrecognized flag. After --long-flags, the next non-flag token
            # may be a flag value (--script vuln) or a real target after a
            # boolean flag (--open evil.com). Use the same _looks_like_target
            # heuristic as positional args so encoded-integer IPs and bare
            # single-label hostnames (which lack dots/colons/slashes) are still
            # validated — a leading-flag form must not be more lenient than the
            # positional one. Plain non-target words are consumed as flag values.
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
            clean = _network_target_host(value)
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
    if not tool:
        raise ValueError(f"Tool '{tool_name}' not found in tools_config.json")

    if tool["method"] in NON_EXECUTABLE_METHODS:
        raise ValueError(
            f"Tool '{tool_name}' uses install method '{tool['method']}' and is not directly executable as a CLI command"
        )

    # Resolve binary name (pipx packages may have different binary names)
    binary = resolve_binary_name(tool["method"], tool_name)

    path = shutil.which(binary)
    if not path:
        raise ValueError(f"Tool '{tool_name}' (binary: '{binary}') is not installed or not in PATH")

    return binary


# Max length for args string to prevent DoS from huge input (100KB is plenty for CLI args)
MAX_ARGS_LEN = 100_000

# Per-read chunk size for _bounded_communicate.
_READ_CHUNK = 65_536


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

    A process that produces unbounded output no longer risks unbounded memory
    growth; memory is O(max_stream_bytes) regardless of how much the child
    writes. The caller is still responsible for timeout + kill on hang.
    """
    stdout_truncated = [False]
    stderr_truncated = [False]

    async def _drain(stream: asyncio.StreamReader | None, flag: list[bool]) -> bytes:
        if stream is None:
            return b""
        captured = bytearray()
        while True:
            chunk = await stream.read(_READ_CHUNK)
            if not chunk:
                break
            if len(captured) < max_stream_bytes:
                space = max_stream_bytes - len(captured)
                captured.extend(chunk[:space])
                if len(chunk) > space:
                    flag[0] = True
            else:
                flag[0] = True
        return bytes(captured)

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
    stdout_task = asyncio.create_task(_drain(process.stdout, stdout_truncated))
    stderr_task = asyncio.create_task(_drain(process.stderr, stderr_truncated))
    writer_task: asyncio.Task[None] | None = None
    if input_bytes is not None and process.stdin is not None:
        writer_task = asyncio.create_task(_write_stdin())

    stdout_bytes, stderr_bytes = await asyncio.gather(stdout_task, stderr_task)
    if writer_task is not None:
        await writer_task

    await process.wait()

    return stdout_bytes, stdout_truncated[0], stderr_bytes, stderr_truncated[0]


def _append_truncation_marker(text: str, max_bytes: int) -> str:
    """Append the standard truncation marker, keeping total UTF-8 size <= max_bytes.

    Delegates the cut-to-fit + marker to :func:`mcp_server.sanitize.truncate_output`
    so the two implementations cannot drift (truncate_output is the single source
    of the marker string and byte budget). This is the production caller of
    truncate_output. Callers invoke this only when the stream was actually
    capped, so the marker is forced even in the rare case the captured bytes land
    just under ``max_bytes`` (e.g. a multibyte boundary).
    """
    truncated_text, was_truncated = truncate_output(text, max_bytes)
    if was_truncated:
        return truncated_text
    # truncate_output left text intact (it already fit within max_bytes), but the
    # stream WAS bounded upstream — append the marker using the same format,
    # trimming from the tail if needed to stay within max_bytes.
    marker = f"\n... [truncated at {max_bytes} bytes]"
    marker_bytes = marker.encode("utf-8")
    encoded = text.encode("utf-8")
    if len(encoded) + len(marker_bytes) <= max_bytes:
        return text + marker
    cut = max(0, max_bytes - len(marker_bytes))
    return encoded[:cut].decode("utf-8", errors="ignore") + marker


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

    # Validate, sanitize, and enforce policy — return structured errors
    try:
        binary = validate_tool_for_execution(tool_name, tools_db)
        log_validation(tool_name, "resolve", True, detail=binary)
        arg_list = sanitize_args(args)
        log_validation(tool_name, "sanitize", True, detail=f"{len(arg_list)} args")
        await asyncio.to_thread(check_policy, tool_name, arg_list, binary)
        log_validation(tool_name, "policy", True)
    except ValueError as e:
        log_validation(tool_name, "failed", False, detail=str(e))
        log_blocked(tool_name=tool_name, args=args, reason=str(e))
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
            "truncated": False,
            "command": tool_name + (" " + args if args else ""),
        }

    # Clamp timeout to 1-300 seconds
    timeout = max(1, min(timeout, 300))

    command = [binary] + arg_list

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
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, t_read_stdout, stderr_bytes, t_read_stderr = await asyncio.wait_for(
                    _bounded_communicate(process, max_stream_bytes=max_output),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    pass  # Process may be in D state; leave as zombie rather than hang
                cmd_str = shlex.join(command)
                elapsed = (time.monotonic() - exec_start) * 1000
                log_execution(
                    tool_name=tool_name,
                    args=args,
                    host="localhost",
                    exit_code=-1,
                    command=cmd_str,
                    duration_ms=elapsed,
                )
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Process timed out after {timeout} seconds",
                    "truncated": False,
                    "command": cmd_str,
                }

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            if t_read_stdout:
                stdout = _append_truncation_marker(stdout, max_output)
            if t_read_stderr:
                stderr = _append_truncation_marker(stderr, max_output)
            truncated = t_read_stdout or t_read_stderr

            stdout = sanitize_output(stdout)
            stderr = sanitize_output(stderr)

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
                stdout_len=len(stdout),
                stderr_len=len(stderr),
                truncated=truncated,
            )

            return {
                "exit_code": rc,
                "stdout": stdout,
                "stderr": stderr,
                "truncated": truncated,
                "command": cmd_str,
            }

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
            )
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Failed to execute: {e}",
                "truncated": False,
                "command": cmd_str,
            }


# ---------------------------------------------------------------------------
# Pipeline execution — safe stdin piping without shell
# ---------------------------------------------------------------------------

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


async def _run_pipeline_steps(
    steps: list[dict],
    tools_db: ToolsDatabase,
    timeout: int,
    max_output: int,
    pipeline_id: str = "",
) -> dict:
    """Execute validated pipeline steps, piping stdout→stdin between them."""
    deadline = asyncio.get_event_loop().time() + timeout
    prev_output: bytes | None = None
    commands: list[str] = []
    step_results: list[dict[str, Any]] = []
    truncated_any = False

    for i, step in enumerate(steps):
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Pipeline timed out at step {i + 1}",
                "truncated": False,
                "commands": commands,
                "step_count": i,
                "failed_step": i + 1,
                "step_results": step_results,
                "had_failures": True,
            }

        step_start = time.monotonic()
        binary = validate_tool_for_execution(step["tool"], tools_db)
        arg_list = sanitize_args(_step_args_to_str(step))
        command = [binary] + arg_list
        cmd_str = shlex.join(command)
        commands.append(cmd_str)

        stdin_mode = asyncio.subprocess.DEVNULL if i == 0 else asyncio.subprocess.PIPE

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=stdin_mode,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
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
                process.kill()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    pass
                step_elapsed = (time.monotonic() - step_start) * 1000
                log_pipeline_step(pipeline_id, i + 1, step["tool"], -1, step_elapsed)
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Pipeline timed out at step {i + 1} after {timeout}s",
                    "truncated": False,
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

            truncated_any = truncated_any or t_read_stdout or t_read_stderr

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
                sanitize_output(stderr_bytes.decode("utf-8", errors="replace")),
                4096,
            )
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
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                if truncated_any:
                    stdout = _append_truncation_marker(stdout, max_output)
                stdout = sanitize_output(stdout)
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                stderr = sanitize_output(stderr)
                return {
                    "exit_code": rc,
                    "stdout": stdout,
                    "stderr": stderr,
                    "truncated": truncated_any,
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
                "truncated": False,
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
                "truncated": False,
                "commands": commands,
                "step_count": i + 1,
                "failed_step": i + 1,
                "step_results": step_results,
                "had_failures": True,
            }

    # Final output — append truncation marker if any step was bounded
    stdout = (prev_output or b"").decode("utf-8", errors="replace")
    if truncated_any:
        stdout = _append_truncation_marker(stdout, max_output)
    stdout = sanitize_output(stdout)

    return {
        "exit_code": 0,
        "stdout": stdout,
        "stderr": "",
        "truncated": truncated_any,
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

    pipeline_id = log_pipeline_start(steps, timeout)
    pipe_start = time.monotonic()

    # Pre-validate ALL steps before executing any
    for i, step in enumerate(steps):
        if "tool" not in step:
            return _pipeline_error(f"Step {i + 1} missing required 'tool' key")
        try:
            binary = validate_tool_for_execution(step["tool"], tools_db)
            args_str = _step_args_to_str(step)
            arg_list = sanitize_args(args_str)
            await asyncio.to_thread(check_policy, step["tool"], arg_list, binary)
        except ValueError as e:
            log_blocked(tool_name=step["tool"], args=_step_args_to_str(step), reason=str(e))
            return _pipeline_error(f"Step {i + 1} ({step['tool']}): {e}")

    # Clamp timeout
    timeout = max(1, min(timeout, 300))

    # Check rate limit BEFORE acquiring semaphore
    try:
        await _rate_limiter.acquire()
    except ValueError as e:
        return _pipeline_error(str(e))

    async with _rate_limiter._semaphore:
        result = await _run_pipeline_steps(steps, tools_db, timeout, max_output, pipeline_id)

    elapsed = (time.monotonic() - pipe_start) * 1000
    log_pipeline_result(
        pipeline_id,
        result.get("exit_code", -1),
        elapsed,
        result.get("step_count", 0),
        result.get("truncated", False),
    )
    return result


# ---------------------------------------------------------------------------
# Script execution — write-and-run Python/Bash scripts
# ---------------------------------------------------------------------------

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
    # 1. Env gate
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

    # 2. Validate language
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

    # 3. Check code not empty
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

    # 4. Find interpreter
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

    # 5. Validate working_dir
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

    # 6. Clamp timeout
    timeout = max(1, min(timeout, 300))

    # 7. Write code to temp file
    suffix = _SCRIPT_LANGUAGES[lang]
    fd, script_path = tempfile.mkstemp(suffix=suffix, prefix="mcp_script_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(code.encode("utf-8"))

        # 8. Audit log BEFORE execution
        log_script_execution(
            language=lang,
            code=code,
            script_file=script_path,
            working_dir=cwd,
            venv=venv or "",
        )
        script_start = time.monotonic()

        # 9. Check rate limit BEFORE acquiring semaphore
        try:
            await _rate_limiter.acquire()
        except ValueError as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "truncated": False,
                "language": lang,
                "script_file": script_path,
                "working_dir": cwd,
            }

        async with _rate_limiter._semaphore:
            # 10. Execute
            try:
                process = await asyncio.create_subprocess_exec(
                    interpreter,
                    script_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                )

                try:
                    stdout_bytes, t_read_stdout, stderr_bytes, t_read_stderr = await asyncio.wait_for(
                        _bounded_communicate(process, max_stream_bytes=max_output),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        pass
                    elapsed = (time.monotonic() - script_start) * 1000
                    log_script_result(lang, -1, elapsed, script_file=script_path)
                    return {
                        "exit_code": -1,
                        "stdout": "",
                        "stderr": f"Script timed out after {timeout} seconds",
                        "truncated": False,
                        "language": lang,
                        "script_file": script_path,
                        "working_dir": cwd,
                    }

                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")

                if t_read_stdout:
                    stdout = _append_truncation_marker(stdout, max_output)
                if t_read_stderr:
                    stderr = _append_truncation_marker(stderr, max_output)
                truncated = t_read_stdout or t_read_stderr

                stdout = sanitize_output(stdout)
                stderr = sanitize_output(stderr)

                rc = process.returncode if process.returncode is not None else -1
                elapsed = (time.monotonic() - script_start) * 1000
                log_script_result(
                    lang,
                    rc,
                    elapsed,
                    script_file=script_path,
                    stdout_len=len(stdout),
                    stderr_len=len(stderr),
                    truncated=truncated,
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

            except FileNotFoundError:
                elapsed = (time.monotonic() - script_start) * 1000
                log_script_result(lang, -1, elapsed, script_file=script_path)
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
                log_script_result(lang, -1, elapsed, script_file=script_path)
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
        # 13. Cleanup temp file
        try:
            os.unlink(script_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Remote execution support
# ---------------------------------------------------------------------------


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
    if not tool:
        raise ValueError(f"Tool '{tool_name}' not found in tools_config.json")

    if tool["method"] in NON_EXECUTABLE_METHODS:
        raise ValueError(
            f"Tool '{tool_name}' uses install method '{tool['method']}' and is not directly executable as a CLI command"
        )

    return resolve_binary_name(tool["method"], tool_name)


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
    try:
        # Allowlist check first
        if not remote_config.check_tool_allowed(host, tool_name):
            raise ValueError(f"Tool '{tool_name}' is not in the allowlist for host '{host}'")
        binary = validate_tool_for_remote_execution(tool_name, tools_db)
        arg_list = sanitize_args(args)
        await asyncio.to_thread(check_policy, tool_name, arg_list, binary)
        ssh_args = remote_config.get_ssh_base_args(host)
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

    command = [binary] + arg_list

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

    async with _rate_limiter._semaphore:
        result = await execute_remote_command(ssh_args, command, timeout=timeout, max_output=max_output)

    # Sanitize output to strip prompt-injection patterns
    result["stdout"] = sanitize_output(result.get("stdout", ""))
    result["stderr"] = sanitize_output(result.get("stderr", ""))

    log_execution(
        tool_name=tool_name,
        args=args,
        host=host,
        exit_code=result.get("exit_code", -1),
        command=result.get("command", ""),
        remote=True,
    )

    return result
