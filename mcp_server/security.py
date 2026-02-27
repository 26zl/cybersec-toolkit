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
from pathlib import Path
from typing import Any

_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server.tools_db import PIPX_BIN_NAMES, ToolsDatabase  # noqa: E402

# Methods that are not directly executable as CLI commands.
NON_EXECUTABLE_METHODS = {"git", "docker", "snap"}

# Dangerous shell metacharacters that must not appear in arguments.
_DANGEROUS_PATTERNS = re.compile(r"[;&|`$><]|\$\(")

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

# Tools that perform network operations and need target validation.
_NETWORK_TOOLS: set[str] = {
    "nmap",
    "masscan",
    "sqlmap",
    "ffuf",
    "feroxbuster",
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
}

# Env-configurable: CYBERSEC_MCP_ALLOW_EXTERNAL=1 unlocks external targets.
# Default: only loopback and RFC 1918 ranges are allowed.
_ALLOW_EXTERNAL = os.environ.get("CYBERSEC_MCP_ALLOW_EXTERNAL", "").strip() == "1"

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


def _is_safe_target(value: str) -> bool:
    """Check if a string looks like a network target and is in a safe range."""
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
            info = socket.getaddrinfo(value, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for _, _, _, _, sockaddr in info:
                addr = ipaddress.ip_address(sockaddr[0])
                if not any(addr in net for net in _SAFE_NETWORKS):
                    return False
            return True
        except (socket.gaierror, OSError):
            # Can't resolve — treat as potentially external
            return False

    # Not a recognizable IP/hostname — could be a decimal IP, bare hostname, etc.
    # Values that look like file paths or flags are allowed through.
    if value.startswith(("-", "/", "./", "~")):
        return True

    # Try DNS resolution as a last resort to catch targets like "google" or "134744072"
    try:
        info = socket.getaddrinfo(value, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in info:
            addr = ipaddress.ip_address(sockaddr[0])
            if not any(addr in net for net in _SAFE_NETWORKS):
                return False
        return True
    except (socket.gaierror, OSError, ValueError):
        # Can't resolve — could be a bare hostname with transient DNS failure.
        # Deny to be safe; genuine non-network values (flags/paths) are caught above.
        return False


def check_policy(tool_name: str, arg_list: list[str]) -> None:
    """Enforce execution policy on the resolved arguments.

    Raises ValueError if the command violates policy.
    """
    # 1. Check for blocked flags
    for arg in arg_list:
        for pattern, desc in BLOCKED_FLAGS:
            if pattern.match(arg):
                raise ValueError(f"Blocked by policy: {desc}")

    # 2. Network target checks (only for network tools, unless external is allowed)
    if _ALLOW_EXTERNAL:
        return

    binary = PIPX_BIN_NAMES.get(tool_name, tool_name)
    if binary not in _NETWORK_TOOLS and tool_name not in _NETWORK_TOOLS:
        return

    # Check positional args and common target flags for external targets
    target_flags = {"-t", "--target", "-u", "--url", "-h", "--host", "--ip"}
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
            # Positional arg that could be a target (hostname, IP, URL, decimal IP)
            value = arg
            i += 1
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

    Raises ValueError if the tool cannot be executed.
    """
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
        raise ValueError(
            f"Arguments contain blocked shell metacharacters: {args!r}. Blocked characters: ; & | ` $ > < $()"
        )

    try:
        parsed = shlex.split(args)
    except ValueError as e:
        raise ValueError(f"Failed to parse arguments: {e}") from e

    return parsed


async def execute_tool(
    tool_name: str,
    args: str,
    tools_db: ToolsDatabase,
    timeout: int = 30,
    max_output: int = 50000,
) -> dict:
    """Execute a tool safely and return its output.

    Returns dict with: exit_code, stdout, stderr, truncated, command.
    """
    # Validate, sanitize, and enforce policy — return structured errors
    try:
        binary = validate_tool_for_execution(tool_name, tools_db)
        arg_list = sanitize_args(args)
        check_policy(tool_name, arg_list)
    except ValueError as e:
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
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Process timed out after {timeout} seconds",
                "truncated": False,
                "command": shlex.join(command),
            }

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        truncated = False
        trunc_msg = f"\n... [truncated at {max_output} bytes]"
        trunc_limit = max_output - len(trunc_msg)
        if len(stdout) > max_output:
            stdout = stdout[:trunc_limit] + trunc_msg
            truncated = True
        if len(stderr) > max_output:
            stderr = stderr[:trunc_limit] + trunc_msg
            truncated = True

        return {
            "exit_code": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": truncated,
            "command": shlex.join(command),
        }

    except FileNotFoundError:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Binary '{binary}' not found",
            "truncated": False,
            "command": shlex.join(command),
        }
    except OSError as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Failed to execute: {e}",
            "truncated": False,
            "command": shlex.join(command),
        }
