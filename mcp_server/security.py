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

from mcp_server.audit import log_blocked, log_execution, log_script_execution  # noqa: E402
from mcp_server.sanitize import sanitize_output, truncate_output  # noqa: E402
from mcp_server.tools_db import PIPX_BIN_NAMES, ToolsDatabase  # noqa: E402

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
        # File operations (safe subset)
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

# Dangerous shell metacharacters that must not appear in arguments.
# Only block shell injection vectors: ; & | ` $( ${
# Note: > < $ are NOT blocked — no shell is used (create_subprocess_exec),
# so they are harmless literals.  Tools need $ for regex anchors (grep 'root$')
# and field references (awk '{print $1}'), and > < for XML/comparisons.
_DANGEROUS_PATTERNS = re.compile(r"[;&|`]|\$[({]")

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
    ],
    "nmap": [
        (re.compile(r"^-iL$"), "nmap: target list from file (bypasses target validation)"),
    ],
    "masscan": [
        (re.compile(r"^--includefile$"), "masscan: target list from file"),
    ],
    "awk": [
        (re.compile(r"system\s*\(", re.IGNORECASE), "awk: system() command execution"),
        (re.compile(r"\|\s*getline", re.IGNORECASE), "awk: pipe to getline"),
    ],
    "tar": [
        (re.compile(r"^--checkpoint-action"), "tar: checkpoint-action command execution"),
        (re.compile(r"^--to-command"), "tar: to-command command execution"),
    ],
    "gpg": [
        (re.compile(r"^--recv-keys?$"), "gpg: key import from external keyserver"),
        (re.compile(r"^--keyserver$"), "gpg: external keyserver specification"),
        (re.compile(r"^--fetch-keys?$"), "gpg: key fetch from URL"),
    ],
}

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
    "trivy",
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


# Private/safe network ranges (loopback + RFC 1918 + link-local).
_SAFE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
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
            if len(self._timestamps) >= self._max_per_minute:
                raise ValueError(f"Rate limit exceeded: max {self._max_per_minute} tool executions per minute")
            self._timestamps.append(now)


_rate_limiter = _RateLimiter()

# Thread-safe DNS resolution with per-call timeout (avoids process-global
# socket.setdefaulttimeout which races under concurrent tool executions).
_dns_lock = threading.Lock()


def _resolve_with_timeout(hostname: str, timeout: float = 5.0) -> list:
    """Resolve hostname via getaddrinfo with a timeout.

    Uses a daemon thread so the calling thread is not blocked beyond *timeout*.
    """
    result: list = []
    error: list = []

    def _resolve() -> None:
        try:
            result.extend(socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM))
        except (socket.gaierror, OSError) as exc:
            error.append(exc)

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise socket.timeout(f"DNS resolution timed out after {timeout}s")
    if error:
        raise error[0]
    return result


def _is_safe_target(value: str) -> bool:
    """Check if a string looks like a network target and is in a safe range."""
    if not value:
        return True  # Empty string is not a network target

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
        # Try to resolve and check
        try:
            info = _resolve_with_timeout(value)
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
    # Single-label hostname: alphabetic word (possibly with hyphens/digits) that
    # is not purely numeric.  Values like "google", "scanme" are valid DNS names
    # and must go through target validation.  Pure numbers ("80", "4") are
    # skipped — they are port/timeout values.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", value):
        return True
    return False


def check_policy(tool_name: str, arg_list: list[str]) -> None:
    """Enforce execution policy on the resolved arguments.

    Raises ValueError if the command violates policy.
    """
    # 1. Check for blocked flags (universal)
    for arg in arg_list:
        for pattern, desc in BLOCKED_FLAGS:
            if pattern.match(arg):
                raise ValueError(f"Blocked by policy: {desc}")

    # 1b. Check for tool-specific blocked flags
    # Use search() instead of match() because tool-specific patterns may need
    # to match anywhere in the argument (e.g. awk's system() inside '{...}').
    binary = PIPX_BIN_NAMES.get(tool_name, tool_name)
    for blocked_list in (TOOL_BLOCKED_FLAGS.get(tool_name, []), TOOL_BLOCKED_FLAGS.get(binary, [])):
        for arg in arg_list:
            for pattern, desc in blocked_list:
                if pattern.search(arg):
                    raise ValueError(f"Blocked by policy: {desc}")

    # 2. Network target checks (only for network tools, unless external is allowed)
    if _allow_external():
        return

    if binary not in _NETWORK_TOOLS and tool_name not in _NETWORK_TOOLS:
        return

    # Check positional args and common target flags for external targets
    # NOTE: Only include unambiguous flags.  Short flags like -t and -h are
    # excluded because they have conflicting meanings across tools (-t is
    # "template" in nuclei, "threads" in ffuf; -h is "help" in most tools).
    # Targets passed via short flags are still caught by the positional-arg
    # heuristic below.
    target_flags = {"--target", "-u", "--url", "--host", "--ip"}
    i = 0
    while i < len(arg_list):
        arg = arg_list[i]
        value = None

        if arg in target_flags and i + 1 < len(arg_list):
            value = arg_list[i + 1]
            i += 2
        elif "=" in arg and arg.split("=", 1)[0] in target_flags:
            value = arg.split("=", 1)[1]
            i += 1
        elif not arg.startswith("-") and not arg.startswith("/"):
            # Positional arg — only validate if it looks like a network target.
            # Skip bare numbers (port/timeout values for flags like -p 80, -T 4)
            # and plain words (flag values like -l admin, --script vuln).
            if _looks_like_target(arg):
                value = arg
            i += 1
        else:
            # Unrecognized flag. After --long-flags, the next non-flag token
            # may be a flag value (--script vuln) or a real target after a
            # boolean flag (--open evil.com). We distinguish by checking for
            # strong target indicators (dots, colons, slashes, http prefix).
            # Plain single-label words (vuln, default, normal) are consumed
            # as flag values. Tokens with target indicators are left for
            # validation in the next iteration.
            if arg.startswith("-") and i + 1 < len(arg_list) and not arg_list[i + 1].startswith("-"):
                next_token = arg_list[i + 1]
                has_target_indicators = (
                    "." in next_token or ":" in next_token or "/" in next_token or next_token.lower().startswith("http")
                )
                # Treat tokens with common file extensions as flag values,
                # not network targets — prevents false positives from
                # output files like scan.txt, report.json, capture.pcap.
                if has_target_indicators and not _has_file_extension(next_token):
                    # Looks like a real target — don't consume, validate next iteration
                    i += 1
                else:
                    # Plain word or filename — likely a flag value, consume it
                    i += 2
            else:
                i += 1
            continue

        if value:
            # Strip protocol prefix for URL-like values
            clean = re.sub(r"^https?://", "", value)
            # Strip bracket notation for IPv6 URLs: [::1] → ::1
            if clean.startswith("["):
                bracket_end = clean.find("]")
                if bracket_end != -1:
                    clean = clean[1:bracket_end]
            else:
                # For non-bracketed values, split off path first, then
                # handle IPv4 port (host:port) vs IPv6 (contains multiple colons).
                clean = clean.split("/")[0]
                if clean.count(":") == 1:
                    # IPv4 with port — take host part
                    clean = clean.split(":")[0]
                # else: bare IPv6 or no port — pass through to _is_safe_target
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
    binary = PIPX_BIN_NAMES.get(tool_name, tool_name)

    path = shutil.which(binary)
    if not path:
        raise ValueError(f"Tool '{tool_name}' (binary: '{binary}') is not installed or not in PATH")

    return binary


def sanitize_args(args: str) -> list[str]:
    """Parse and sanitize command-line arguments.

    Raises ValueError on dangerous patterns.
    """
    if not args or not args.strip():
        return []

    # Check for dangerous shell metacharacters before parsing
    if _DANGEROUS_PATTERNS.search(args):
        raise ValueError(f"Arguments contain blocked shell metacharacters: {args!r}. Blocked patterns: ; & | ` $( ${{")

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
    # Validate, sanitize, and enforce policy — return structured errors
    try:
        binary = validate_tool_for_execution(tool_name, tools_db)
        arg_list = sanitize_args(args)
        await asyncio.to_thread(check_policy, tool_name, arg_list)
    except ValueError as e:
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
                stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                cmd_str = shlex.join(command)
                log_execution(
                    tool_name=tool_name,
                    args=args,
                    host="localhost",
                    exit_code=-1,
                    command=cmd_str,
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

            stdout, t1 = truncate_output(stdout, max_output)
            stderr, t2 = truncate_output(stderr, max_output)
            truncated = t1 or t2

            stdout = sanitize_output(stdout)
            stderr = sanitize_output(stderr)

            cmd_str = shlex.join(command)
            rc = process.returncode if process.returncode is not None else -1
            log_execution(
                tool_name=tool_name,
                args=args,
                host="localhost",
                exit_code=rc,
                command=cmd_str,
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
            log_execution(
                tool_name=tool_name,
                args=args,
                host="localhost",
                exit_code=-1,
                command=cmd_str,
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
            log_execution(
                tool_name=tool_name,
                args=args,
                host="localhost",
                exit_code=-1,
                command=cmd_str,
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
    return {"exit_code": -1, "stdout": "", "stderr": msg, "truncated": False, "commands": [], "step_count": 0}


async def _run_pipeline_steps(
    steps: list[dict],
    tools_db: ToolsDatabase,
    timeout: int,
    max_output: int,
) -> dict:
    """Execute validated pipeline steps, piping stdout→stdin between them."""
    deadline = asyncio.get_event_loop().time() + timeout
    prev_output: bytes | None = None
    commands: list[str] = []

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
            }

        binary = validate_tool_for_execution(step["tool"], tools_db)
        arg_list = sanitize_args(step.get("args", ""))
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
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(input=prev_output if i > 0 else None),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": f"Pipeline timed out at step {i + 1} after {timeout}s",
                    "truncated": False,
                    "commands": commands,
                    "step_count": i + 1,
                    "failed_step": i + 1,
                }

            rc = process.returncode if process.returncode is not None else -1
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
                stdout, truncated = truncate_output(stdout, max_output)
                stdout = sanitize_output(stdout)
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                return {
                    "exit_code": rc,
                    "stdout": stdout,
                    "stderr": stderr,
                    "truncated": truncated,
                    "commands": commands,
                    "step_count": len(steps),
                }
            else:
                prev_output = stdout_bytes

        except FileNotFoundError:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Binary not found for step {i + 1}: {cmd_str}",
                "truncated": False,
                "commands": commands,
                "step_count": i + 1,
                "failed_step": i + 1,
            }
        except OSError as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Failed to execute step {i + 1}: {e}",
                "truncated": False,
                "commands": commands,
                "step_count": i + 1,
                "failed_step": i + 1,
            }

    # Final output — truncate and sanitize
    stdout = (prev_output or b"").decode("utf-8", errors="replace")
    stdout, truncated = truncate_output(stdout, max_output)
    stdout = sanitize_output(stdout)

    return {
        "exit_code": 0,
        "stdout": stdout,
        "stderr": "",
        "truncated": truncated,
        "commands": commands,
        "step_count": len(steps),
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
        Dict with exit_code, stdout, stderr, truncated, commands, step_count.
    """
    if not steps:
        return _pipeline_error("Pipeline must have at least 1 step")
    if len(steps) > MAX_PIPELINE_STEPS:
        return _pipeline_error(f"Pipeline exceeds max {MAX_PIPELINE_STEPS} steps (got {len(steps)})")

    # Pre-validate ALL steps before executing any
    for i, step in enumerate(steps):
        if "tool" not in step:
            return _pipeline_error(f"Step {i + 1} missing required 'tool' key")
        try:
            validate_tool_for_execution(step["tool"], tools_db)
            arg_list = sanitize_args(step.get("args", ""))
            await asyncio.to_thread(check_policy, step["tool"], arg_list)
        except ValueError as e:
            log_blocked(tool_name=step["tool"], args=step.get("args", ""), reason=str(e))
            return _pipeline_error(f"Step {i + 1} ({step['tool']}): {e}")

    # Clamp timeout
    timeout = max(1, min(timeout, 300))

    # Check rate limit BEFORE acquiring semaphore
    try:
        await _rate_limiter.acquire()
    except ValueError as e:
        return _pipeline_error(str(e))

    async with _rate_limiter._semaphore:
        return await _run_pipeline_steps(steps, tools_db, timeout, max_output)


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
    venvs_dir = os.path.realpath(venvs_dir)
    # Ensure the venv directory itself is inside venvs_dir (check before
    # following any symlinks inside the venv — python binary may be a
    # symlink to the system interpreter, which is expected and safe).
    venv_root = os.path.join(venvs_dir, venv_name)
    if not os.path.realpath(venv_root).startswith(venvs_dir + os.sep):
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
            # Static override via env var, fallback to sys.executable
            custom_python = os.environ.get("CYBERSEC_MCP_SCRIPT_PYTHON", "").strip()
            if custom_python and os.path.isfile(custom_python):
                interpreter = custom_python
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
        )

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
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        process.communicate(),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    log_execution(
                        tool_name=f"script:{lang}",
                        args="",
                        host="localhost",
                        exit_code=-1,
                        command=f"{interpreter} {script_path}",
                    )
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

                stdout, t1 = truncate_output(stdout, max_output)
                stderr, t2 = truncate_output(stderr, max_output)
                truncated = t1 or t2

                stdout = sanitize_output(stdout)
                stderr = sanitize_output(stderr)

                rc = process.returncode if process.returncode is not None else -1
                log_execution(
                    tool_name=f"script:{lang}",
                    args="",
                    host="localhost",
                    exit_code=rc,
                    command=f"{interpreter} {script_path}",
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
                log_execution(
                    tool_name=f"script:{lang}",
                    args="",
                    host="localhost",
                    exit_code=-1,
                    command=f"{interpreter} {script_path}",
                )
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
                log_execution(
                    tool_name=f"script:{lang}",
                    args="",
                    host="localhost",
                    exit_code=-1,
                    command=f"{interpreter} {script_path}",
                )
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

    return PIPX_BIN_NAMES.get(tool_name, tool_name)


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
        await asyncio.to_thread(check_policy, tool_name, arg_list)
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
