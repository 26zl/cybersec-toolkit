"""Shared helpers for curated MCP tool advisors."""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Container
from pathlib import Path
from typing import Optional

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
    # Python libraries shipped as one venv (modules/crypto.sh CRYPTO_VENV_LIBS);
    # they have no console script of their own to look for on PATH.
    "pycryptodome": "ctf-crypto-venv",
    "sympy": "ctf-crypto-venv",
    "gmpy2": "ctf-crypto-venv",
    "fpylll": "ctf-crypto-venv",
    "cypari2": "ctf-crypto-venv",
}


# Import name for venv libraries whose distribution name differs from the
# package directory pip creates.
VENV_IMPORT_NAMES: dict[str, str] = {"pycryptodome": "Crypto"}


def _venv_provides(registry_name: str, tool_name: str) -> bool:
    """Is this one library actually present in the venv it is registered under?

    A "ctf-<name>-venv" entry stands for a whole set of libraries. The venv
    installer is all-or-nothing, but a partially built venv (a wheel missing for
    the host Python, a hand-made venv) would otherwise report every member of
    the set as installed — the exact false "yes" the registry exists to prevent.
    """
    venvs_dir = os.environ.get("CYBERSEC_MCP_VENVS_DIR", "").strip()
    root = Path(venvs_dir) if venvs_dir else Path.home() / ".ctf-venvs"
    venv = root / registry_name[len("ctf-") : -len("-venv")]
    module = VENV_IMPORT_NAMES.get(tool_name, tool_name)
    return any((site / module).exists() for site in venv.glob("lib/python*/site-packages"))


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
            if registry_name != tool_name and registry_name.startswith("ctf-") and registry_name.endswith("-venv"):
                return _venv_provides(registry_name, tool_name), True
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


def resolve_with_aliases(
    value: str,
    canonical: Container[str],
    aliases: dict[str, str],
) -> Optional[str]:
    """Resolve a category/target string to a canonical name.

    The whole string is tried first, so multi-word aliases ("prompt injection")
    keep resolving to themselves. Only then does each word get a turn, which is
    what makes a natural phrasing like "crypto rsa" or "web sqli" land on a
    category instead of returning an error the caller has to guess its way out of.
    """
    normalized = value.lower().strip()
    if normalized in canonical:
        return normalized
    if normalized in aliases:
        return aliases[normalized]
    for token in re.split(r"[^\w-]+", normalized):
        if not token:
            continue
        if token in canonical:
            return token
        if token in aliases:
            return aliases[token]
    return None


# Methods `install.sh --tool` can resolve: it looks the name up in the module
# arrays. docker, special (the ctf venv, metasploit, foundry) and npm tools are
# installed by their module's own code and have no array entry, so naming one
# after --tool only prints "not found in any module array" — those need the
# module install instead.
SINGLE_TOOL_METHODS = frozenset({"apt", "pipx", "go", "cargo", "gem", "git", "binary", "source"})


def missing_tool_notice(entries: list[dict], modules: list[str], tools_db: ToolsDatabase) -> Optional[dict]:
    """Name the curated tools that are not installed, and how to install them.

    Advisors return their curated set regardless of install state. Without this
    the caller sees an "n/m installed" count and quietly routes around whatever
    is missing; the point of the advisor is that the user hears a recommended
    tool is absent before the workaround starts.
    """
    missing = [entry for entry in entries if not entry["installed"]]
    if not missing:
        return None
    module_flags = " ".join(f"--module {mod}" for mod in modules)
    notice: dict = {
        "missing": [entry["name"] for entry in missing],
        "install_modules": f"./install.sh {module_flags}",
    }
    # --tool matches the installer arrays exactly, so the registry spelling is
    # the one that works ("RsaCtfTool", not the lowercase display name). Offer it
    # only for a tool it can actually install; the module command always works.
    for entry in missing:
        name = entry.get("registry_name", entry["name"])
        if tools_db.tools_by_name.get(name, {}).get("method") in SINGLE_TOOL_METHODS:
            notice["install_single_tool"] = f"./install.sh --tool {name}"
            notice["plan_install"] = f"recommend_install({name!r})"
            break
    notice["agent_action"] = (
        "Tell the user which of these fit the task and that they are not installed, "
        "then ask before installing. Do not silently work around a missing recommended tool, "
        "and do not reimplement it as a script."
    )
    return notice


def script_execution_notice() -> Optional[dict]:
    """Flag that run_script is gated off, when it is.

    Crypto and pwn work reaches a point where the next step is arithmetic, not a
    tool invocation. The gate is a deliberate default (see security._allow_scripts
    for the canonical read), but an advisor that stays silent about it sends the
    agent looking for a tool that does not exist.
    """
    if os.environ.get("CYBERSEC_MCP_ALLOW_SCRIPTS", "").strip() == "1":
        return None
    return {
        "run_script": "disabled",
        "enable_with": "CYBERSEC_MCP_ALLOW_SCRIPTS=1",
        "note": (
            "Solver logic (lattice reduction, gcd/CRT, oracle loops, exploit scripts) needs "
            "run_script. It is off by default and unsandboxed when on — tell the user what the "
            "script would do and let them enable it and restart the server, rather than "
            "shelling out around the policy."
        ),
    }
