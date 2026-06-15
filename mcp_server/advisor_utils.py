"""Shared helpers for curated MCP tool advisors."""

from __future__ import annotations

import shutil

from mcp_server.tools_db import ToolsDatabase

# Display name -> tools_config.json registry name.
# Only needed when the user-facing name differs from the registry entry.
# Tools not listed here are assumed to match the registry name exactly.
TOOL_ALIASES: dict[str, str] = {
    # Case mismatches
    "cyberchef": "CyberChef",
    "responder": "Responder",
    "rsactftool": "RsaCtfTool",
    "seclists": "SecLists",
    "theharvester": "theHarvester",
    # Naming mismatches (display name -> registry name)
    "jwt-tool": "jwt_tool",
    "afl++": "AFLplusplus",
    "upx": "upx-ucl",
    "exiftool": "libimage-exiftool-perl",
    "wireshark": "wireshark-common",
    "netcat": "netcat-openbsd",
    "wifite": "wifite2",
    "snow": "stegsnow",
    # Sub-components (display name -> parent tool in registry)
    "photorec": "testdisk",
}


def check_tool_installed(tool_name: str, tools_db: ToolsDatabase) -> tuple[bool, bool]:
    """Check if a tool is installed. Returns (installed, in_registry).

    Uses TOOL_ALIASES to map display names to registry names, and falls back
    to PATH checks for tools not in the registry.
    """
    registry_name = TOOL_ALIASES.get(tool_name, tool_name)
    in_registry = registry_name in tools_db.tools_by_name

    if in_registry:
        status = tools_db.check_installed(registry_name)
        if status["installed"]:
            return True, True

    if shutil.which(tool_name):
        return True, in_registry

    return False, in_registry


def build_tool_status_list(tools: list[tuple[str, str]], tools_db: ToolsDatabase) -> tuple[list[dict], int]:
    """Build per-tool install-status entries for an advisor category.

    Shared by the CTF and bounty advisors so the entry shape and the installed
    count stay identical. Each entry carries name/description/installed/
    in_registry, plus ``registry_name`` when the display name differs from the
    registry name. Returns ``(entries, installed_count)``.
    """
    entries: list[dict] = []
    for tool_name, description in tools:
        installed, in_registry = check_tool_installed(tool_name, tools_db)
        entry: dict = {
            "name": tool_name,
            "description": description,
            "installed": installed,
            "in_registry": in_registry,
        }
        registry_name = TOOL_ALIASES.get(tool_name)
        if registry_name:
            entry["registry_name"] = registry_name
        entries.append(entry)
    installed_count = sum(1 for entry in entries if entry["installed"])
    return entries, installed_count
