#!/usr/bin/env python3
"""CI check: validate MCP server hardcoded data matches bash source files.

Compares MODULE_DESCRIPTIONS, DOCKER_IMAGES, PIPX_BIN_NAMES, and profile
module lists between the Python MCP server and the bash installer sources.

Exit code 0 = all in sync, 1 = drift detected.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []


def parse_bash_assoc_array(text: str, var_name: str) -> dict[str, str]:
    """Parse a bash associative array: declare -A VAR=( [k]="v" ... )."""
    pattern = rf'declare\s+-A\s+{var_name}=\((.*?)\)'
    m = re.search(pattern, text, re.DOTALL)
    if not m:
        return {}
    block = m.group(1)
    entries = re.findall(r'\[([^\]]+)\]="([^"]*)"', block)
    return dict(entries)


def parse_bash_indexed_array(text: str, var_name: str) -> list[str]:
    """Parse a bash indexed array: VAR=( "entry" ... )."""
    pattern = rf'{var_name}=\((.*?)\)'
    m = re.search(pattern, text, re.DOTALL)
    if not m:
        return []
    block = m.group(1)
    return re.findall(r'"([^"]+)"', block)


def check_module_descriptions() -> None:
    """Compare MODULE_DESCRIPTIONS between common.sh and tools_db.py."""
    bash_text = (ROOT / "lib" / "common.sh").read_text(encoding="utf-8")
    bash_descs = parse_bash_assoc_array(bash_text, "MODULE_DESCRIPTIONS")

    # Import Python version
    sys.path.insert(0, str(ROOT))
    from mcp_server.tools_db import MODULE_DESCRIPTIONS as py_descs

    if not bash_descs:
        errors.append("MODULE_DESCRIPTIONS: could not parse from lib/common.sh")
        return

    for key, val in bash_descs.items():
        if key not in py_descs:
            errors.append(f"MODULE_DESCRIPTIONS: '{key}' in bash but missing in Python")
        elif py_descs[key] != val:
            errors.append(
                f"MODULE_DESCRIPTIONS['{key}']: bash={val!r} != python={py_descs[key]!r}"
            )

    for key in py_descs:
        if key not in bash_descs:
            errors.append(f"MODULE_DESCRIPTIONS: '{key}' in Python but missing in bash")

    print(f"MODULE_DESCRIPTIONS: {len(bash_descs)} bash, {len(py_descs)} python")


def check_docker_images() -> None:
    """Compare ALL_DOCKER_IMAGES between installers.sh and tools_db.py."""
    bash_text = (ROOT / "lib" / "installers.sh").read_text(encoding="utf-8")
    bash_entries = parse_bash_indexed_array(bash_text, "ALL_DOCKER_IMAGES")

    from mcp_server.tools_db import DOCKER_IMAGES as py_images

    if not bash_entries:
        errors.append("DOCKER_IMAGES: could not parse ALL_DOCKER_IMAGES from lib/installers.sh")
        return

    # Parse "image|label" format
    bash_map: dict[str, str] = {}
    for entry in bash_entries:
        parts = entry.split("|", 1)
        if len(parts) == 2:
            bash_map[parts[1]] = parts[0]  # label → image

    for label, image in bash_map.items():
        if label not in py_images:
            errors.append(f"DOCKER_IMAGES: '{label}' in bash but missing in Python")
        elif py_images[label] != image:
            errors.append(
                f"DOCKER_IMAGES['{label}']: bash={image!r} != python={py_images[label]!r}"
            )

    for label in py_images:
        if label not in bash_map:
            errors.append(f"DOCKER_IMAGES: '{label}' in Python but missing in bash")

    print(f"DOCKER_IMAGES: {len(bash_map)} bash, {len(py_images)} python")


def check_pipx_bin_names() -> None:
    """Compare _PIPX_BIN_NAMES between verify.sh and tools_db.py."""
    bash_text = (ROOT / "scripts" / "verify.sh").read_text(encoding="utf-8")
    bash_names = parse_bash_assoc_array(bash_text, "_PIPX_BIN_NAMES")

    from mcp_server.tools_db import PIPX_BIN_NAMES as py_names

    if not bash_names:
        errors.append("PIPX_BIN_NAMES: could not parse _PIPX_BIN_NAMES from scripts/verify.sh")
        return

    for key, val in bash_names.items():
        if key not in py_names:
            errors.append(f"PIPX_BIN_NAMES: '{key}' in bash but missing in Python")
        elif py_names[key] != val:
            errors.append(
                f"PIPX_BIN_NAMES['{key}']: bash={val!r} != python={py_names[key]!r}"
            )

    for key in py_names:
        if key not in bash_names:
            errors.append(f"PIPX_BIN_NAMES: '{key}' in Python but missing in bash")

    print(f"PIPX_BIN_NAMES: {len(bash_names)} bash, {len(py_names)} python")


def check_profiles() -> None:
    """Compare profile module lists between profiles/*.conf and profiles.py."""
    from mcp_server.profiles import PROFILES as py_profiles

    profiles_dir = ROOT / "profiles"
    bash_profiles: dict[str, list[str]] = {}

    for conf in sorted(profiles_dir.glob("*.conf")):
        name = conf.stem
        text = conf.read_text(encoding="utf-8")
        m = re.search(r'MODULES="([^"]+)"', text)
        if m:
            bash_profiles[name] = m.group(1).split()

    if not bash_profiles:
        errors.append("PROFILES: no profiles/*.conf files found")
        return

    for name, modules in bash_profiles.items():
        if name not in py_profiles:
            errors.append(f"PROFILES: '{name}' in bash but missing in Python")
            continue
        py_modules = py_profiles[name]["modules"]
        if modules != py_modules:
            errors.append(
                f"PROFILES['{name}'].modules: bash={modules} != python={py_modules}"
            )

    for name in py_profiles:
        if name not in bash_profiles:
            errors.append(f"PROFILES: '{name}' in Python but missing in bash")

    print(f"PROFILES: {len(bash_profiles)} bash, {len(py_profiles)} python")


def main() -> int:
    print("=== MCP Server Data Sync Check ===\n")

    check_module_descriptions()
    check_docker_images()
    check_pipx_bin_names()
    check_profiles()

    print()
    if errors:
        print(f"FAILED: {len(errors)} sync error(s) found:\n")
        for e in errors:
            print(f"  - {e}")
        return 1

    print("OK: All MCP server data in sync with bash sources")
    return 0


if __name__ == "__main__":
    sys.exit(main())
