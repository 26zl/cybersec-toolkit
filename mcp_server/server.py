"""Main FastMCP server — 9 MCP tool registrations + entry point."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP

# Ensure the parent directory is on sys.path so both `python -m mcp_server.server`
# (relative imports) and `fastmcp dev inspector server.py` (direct imports) work.
_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server.ctf_advisor import suggest_for_ctf as _suggest_for_ctf  # noqa: E402, I001
from mcp_server.profiles import PROFILES  # noqa: E402
from mcp_server.profiles import list_profiles as _list_profiles  # noqa: E402
from mcp_server.profiles import recommend_install as _recommend_install  # noqa: E402
from mcp_server.security import execute_tool as _execute_tool  # noqa: E402
from mcp_server.tools_db import MODULE_DESCRIPTIONS, ToolsDatabase  # noqa: E402

mcp = FastMCP(
    "Cybersec Toolkit",
    instructions=(
        "Query and manage 568 cybersecurity tools across 18 modules."
        "Check installation status, get CTF challenge recommendations, "
        "recommend install profiles or individual tools, "
        "and execute installed tools safely."
    ),
)

# Shared database instance (loaded once on server start).
_db = ToolsDatabase()

# Termux runs without sudo; Linux requires it.
_SUDO = "" if os.environ.get("TERMUX_VERSION") else "sudo "


def _cmd(script: str, args: str = "") -> str:
    """Build a shell command string, prefixing sudo when not on Termux."""
    return f"{_SUDO}{script}{' ' + args if args else ''}"


@mcp.tool
def list_tools(
    module: Optional[str] = None,
    method: Optional[str] = None,
    installed_only: bool = False,
) -> dict:
    """List and filter tools from the 568-tool cybersecurity registry.

    Args:
        module: Filter by module (e.g. "web", "pwn", "forensics"). 18 modules available.
        method: Filter by install method (apt, pipx, go, cargo, gem, git, binary, docker, snap, special, source, npm).
        installed_only: If true, only return tools that are currently installed.

    Returns:
        Tool list with count, available filters, and tool entries (name, method, module, url).
    """
    tools = _db.list_tools(module=module, method=method, installed_only=installed_only)

    tool_entries = []
    for t in tools:
        entry: dict = {
            "name": t["name"],
            "method": t["method"],
            "module": t["module"],
            "url": t.get("url", ""),
        }
        if installed_only and "install_status" in t:
            entry["install_status"] = t["install_status"]
        tool_entries.append(entry)

    result: dict = {
        "count": len(tool_entries),
        "total_in_registry": _db.total_tools,
        "tools": tool_entries,
    }

    # Add filter info when no filters applied
    if not module and not method:
        result["available_modules"] = _db.modules
        result["available_methods"] = _db.methods

    return result


@mcp.tool
def check_installed(tool_name: str) -> dict:
    """Check if a specific cybersecurity tool is installed on the system.

    Uses multiple detection strategies: .versions tracking, PATH lookup,
    pipx binary name fallback, /opt directory check, and docker image check.

    Args:
        tool_name: Name of the tool to check (as listed in tools_config.json).

    Returns:
        Installation status with detection method and details.
    """
    tool = _db.tools_by_name.get(tool_name)
    if not tool:
        return {
            "tool": tool_name,
            "in_registry": False,
            "error": f"Tool '{tool_name}' not found in registry. Use list_tools() to see available tools.",
        }

    status = _db.check_installed(tool_name)
    return {
        "tool": tool_name,
        "in_registry": True,
        "module": tool["module"],
        "method": tool["method"],
        "url": tool.get("url", ""),
        **status,
    }


@mcp.tool
def get_tool_info(tool_name: str) -> dict:
    """Get detailed information about a cybersecurity tool.

    Returns the tool's install method, module, URL, installation status,
    module description, and management commands (install, update, remove).

    Args:
        tool_name: Name of the tool to look up.

    Returns:
        Full tool details including install/update/remove commands.
    """
    tool = _db.tools_by_name.get(tool_name)
    if not tool:
        return {
            "error": f"Tool '{tool_name}' not found in registry. Use list_tools() to see available tools.",
        }

    status = _db.check_installed(tool_name)
    module = tool["module"]
    module_desc = MODULE_DESCRIPTIONS.get(module, "")

    return {
        "name": tool["name"],
        "method": tool["method"],
        "module": module,
        "module_description": module_desc,
        "url": tool.get("url", ""),
        "installed": status["installed"],
        "install_details": status["details"],
        "commands": {
            "install": _cmd("./install.sh", f"--module {module}"),
            "update": _cmd("./scripts/update.sh", f"--module {module}"),
            "remove": _cmd("./scripts/remove.sh", f"--module {module}"),
            "verify": _cmd("./scripts/verify.sh", f"--module {module}"),
        },
    }


@mcp.tool
def suggest_for_ctf(challenge_type: str) -> dict:
    """Suggest cybersecurity tools for a CTF challenge category.

    Provides curated tool recommendations with installation status for
    13 challenge types: web, crypto, pwn, reversing, forensics, stego,
    misc, networking, wireless, osint, cloud, mobile, blockchain.

    Also accepts aliases: re/rev (reversing), binary/exploitation (pwn),
    steganography (stego), network (networking), recon (osint), etc.

    Args:
        challenge_type: Type of CTF challenge (e.g. "web", "crypto", "pwn").

    Returns:
        Suggested tools with descriptions and install status, plus relevant modules.
    """
    return _suggest_for_ctf(challenge_type, _db)


@mcp.tool
def recommend_install(task: str) -> dict:
    """Recommend which profile, modules, or individual tools to install.

    Analyzes a natural-language description of what the user wants to do and
    recommends the best installation approach — from a full profile down to
    just a few individual tools. Avoids installing everything when only a
    subset is needed.

    Examples:
        "I want to do CTF competitions" → ctf profile
        "web application pentesting" → web profile
        "I just need nmap and burpsuite" → individual modules networking + web
        "crack some password hashes" → crackstation profile
        "forensics and incident response" → forensics profile
        "everything" → full profile
        "quick minimal setup" → lightweight profile

    Args:
        task: Natural-language description of what the user wants to do.

    Returns:
        Recommendation with install commands, module details, and alternatives.
    """
    return _recommend_install(task, _db)


@mcp.tool
def list_profiles() -> dict:
    """List all 14 available installation profiles with details.

    Each profile is a curated set of modules targeting a specific use case.
    Shows module count, tool count, and install command for each profile.
    Profiles range from 'osint' (2 modules, ~80 tools) to 'full' (18 modules, 568 tools).

    Returns:
        All profiles with descriptions, module lists, tool counts, and install commands.
    """
    return _list_profiles(_db)


@mcp.tool
def get_profile_tools(profile: str) -> dict:
    """List every tool that a specific profile would install.

    Given a profile name, returns the complete list of tools grouped by
    module, with install status for each. This lets you see exactly what
    you get before running the install command.

    Args:
        profile: Profile name (e.g. "ctf", "redteam", "web", "full").

    Returns:
        All tools in the profile grouped by module, with install status and counts.
    """
    profile_lower = profile.lower().strip()
    if profile_lower not in PROFILES:
        return {
            "error": f"Unknown profile '{profile}'. Available: {', '.join(sorted(PROFILES))}",
        }

    profile_data = PROFILES[profile_lower]
    modules = profile_data["modules"]

    by_module: list[dict] = []
    total = 0
    installed = 0

    for mod in modules:
        mod_tools = [t for t in _db._tools if t["module"] == mod]
        tool_entries = []
        for t in mod_tools:
            status = _db.check_installed(t["name"])
            tool_entries.append(
                {
                    "name": t["name"],
                    "method": t["method"],
                    "url": t.get("url", ""),
                    "installed": status["installed"],
                }
            )
            total += 1
            if status["installed"]:
                installed += 1

        by_module.append(
            {
                "module": mod,
                "description": MODULE_DESCRIPTIONS.get(mod, ""),
                "tool_count": len(tool_entries),
                "tools": tool_entries,
            }
        )

    return {
        "profile": profile_lower,
        "description": profile_data["description"],
        "total_tools": total,
        "installed_tools": installed,
        "install_command": _cmd("./install.sh", f"--profile {profile_lower}"),
        "modules": by_module,
    }


@mcp.tool
def get_module_info(module: str) -> dict:
    """Get full details about a module: description, all tools, and management commands.

    Args:
        module: Module name (e.g. "web", "pwn", "forensics").

    Returns:
        Module description, tool list with install status, and install/update/remove commands.
    """
    module_lower = module.lower().strip()
    if module_lower not in MODULE_DESCRIPTIONS:
        return {
            "error": f"Unknown module '{module}'. Available: {', '.join(sorted(MODULE_DESCRIPTIONS))}",
        }

    mod_tools = [t for t in _db._tools if t["module"] == module_lower]
    installed_count = 0
    tool_entries = []

    for t in mod_tools:
        status = _db.check_installed(t["name"])
        tool_entries.append(
            {
                "name": t["name"],
                "method": t["method"],
                "url": t.get("url", ""),
                "installed": status["installed"],
                "details": status["details"],
            }
        )
        if status["installed"]:
            installed_count += 1

    # Group tools by method for overview
    by_method: dict[str, int] = {}
    for t in mod_tools:
        by_method[t["method"]] = by_method.get(t["method"], 0) + 1

    # Which profiles include this module
    in_profiles = [name for name, p in PROFILES.items() if module_lower in p["modules"]]

    return {
        "module": module_lower,
        "description": MODULE_DESCRIPTIONS[module_lower],
        "total_tools": len(mod_tools),
        "installed_tools": installed_count,
        "tools_by_method": by_method,
        "tools": tool_entries,
        "in_profiles": in_profiles,
        "commands": {
            "install": _cmd("./install.sh", f"--module {module_lower}"),
            "update": _cmd("./scripts/update.sh", f"--module {module_lower}"),
            "remove": _cmd("./scripts/remove.sh", f"--module {module_lower}"),
            "verify": _cmd("./scripts/verify.sh", f"--module {module_lower}"),
        },
    }


@mcp.tool
async def run_tool(
    tool_name: str,
    args: str = "",
    timeout: int = 30,
) -> dict:
    """Execute an installed cybersecurity tool and return its output.

    Only runs tools that exist in the registry and are installed. Arguments
    are sanitized to prevent shell injection. Timeout is clamped to 1-300s.
    Output is truncated at 50KB.

    Network tools are restricted to local/private targets by default.
    Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 to allow scanning external targets.

    Args:
        tool_name: Name of the tool to run (must be in registry and installed).
        args: Command-line arguments as a string (e.g. "--version" or "-sV 10.0.0.1").
        timeout: Maximum execution time in seconds (default 30, max 300).

    Returns:
        Execution result with exit_code, stdout, stderr, and the command that was run.
    """
    return await _execute_tool(tool_name, args, _db, timeout=timeout)


def main() -> None:
    """Entry point for the ``cybersec-mcp`` console script."""
    mcp.run()


if __name__ == "__main__":
    main()
