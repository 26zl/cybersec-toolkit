#!/usr/bin/env python3
"""Validate and sync tools_config.json against module source files.

Usage:
    python3 scripts/validate_tools_config.py            # Validate (CI mode)
    python3 scripts/validate_tools_config.py --sync     # Populate URLs from modules into JSON
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = ROOT / "modules"
INSTALLERS_PATH = ROOT / "lib" / "installers.sh"
SHARED_PATH = ROOT / "lib" / "shared.sh"
CONFIG_PATH = ROOT / "tools_config.json"

ALL_MODULES = [
    "shared",  # pseudo-module: lib/shared.sh base dependencies
    "misc", "networking", "recon", "web", "crypto", "pwn", "reversing",
    "forensics", "enterprise", "wireless", "cracking", "stego",
    "cloud", "containers", "blueteam", "mobile", "blockchain", "llm",
]

MODULE_PREFIX = {
    "misc": "MISC", "networking": "NET", "recon": "RECON", "web": "WEB",
    "crypto": "CRYPTO", "pwn": "PWN", "reversing": "RE",
    "forensics": "FORENSICS", "enterprise": "ENTERPRISE",
    "wireless": "WIRELESS", "cracking": "CRACKING", "stego": "STEGO",
    "cloud": "CLOUD", "containers": "CONTAINER", "blueteam": "BLUETEAM",
    "mobile": "MOBILE", "blockchain": "BLOCKCHAIN", "llm": "LLM",
}

APT_SUFFIXES = {"PACKAGES", "BASE_PACKAGES", "HEAVY_PACKAGES"}
BINARY_RELEASE_SUFFIXES = {"BINARY_RELEASES"}
GIT_SUFFIXES = {"GIT"}
SKIP_SUFFIXES = {"GO_BINS", "GIT_NAMES", "GO", "BUILD_NAMES"}

VALID_METHODS = {
    "apt", "pipx", "go", "cargo", "gem", "git",
    "binary", "source", "docker", "snap", "special", "npm",
}

# Names that differ between code and JSON (code_name → json_name)
NAME_ALIASES = {
    "metasploit-framework": "metasploit",
    "d2j-dex2jar": "dex2jar",
}

# Bash parsing helpers
def strip_comments(text):
    """Remove full-line bash comments."""
    return "\n".join(
        line for line in text.split("\n")
        if not line.lstrip().startswith("#")
    )


def parse_arrays(text):
    """Parse bash arrays: NAME=( ... ) → {NAME: [entries]}."""
    text = strip_comments(text)
    result = {}
    for m in re.finditer(r'(\w+)\s*=\s*\((.*?)\)', text, re.DOTALL):
        name = m.group(1)
        body = m.group(2)
        entries = []
        for item in re.finditer(r'"([^"]*)"|(\S+)', body):
            val = item.group(1) if item.group(1) is not None else item.group(2)
            if val:
                entries.append(val)
        result[name] = entries
    return result


def go_github_url(import_path):
    """github.com/org/repo/... → https://github.com/org/repo"""
    # Strip @latest or @version suffix
    clean = import_path.split("@")[0]
    parts = clean.split("/")
    if len(parts) >= 3 and parts[0] == "github.com":
        return f"https://github.com/{parts[1]}/{parts[2]}"
    return ""


# Map BINARY_RELEASES_* suffix → module name
BINARY_RELEASE_MODULE = {
    "MISC": "misc", "NETWORKING": "networking", "RECON": "recon",
    "WEB": "web", "REVERSING": "reversing", "FORENSICS": "forensics",
    "ENTERPRISE": "enterprise", "BLUETEAM": "blueteam",
    "CONTAINERS": "containers", "STEGO": "stego",
}

# Binary release extraction from installers.sh
def extract_binary_releases():
    """Parse BINARY_RELEASES_* arrays from lib/installers.sh.

    Returns list of {name, method, url, module}.
    """
    text = INSTALLERS_PATH.read_text(encoding="utf-8", errors="replace")
    arrays = parse_arrays(text)
    tools = []
    for arr_name, entries in arrays.items():
        if not arr_name.startswith("BINARY_RELEASES_"):
            continue
        suffix = arr_name[len("BINARY_RELEASES_"):]
        module = BINARY_RELEASE_MODULE.get(suffix)
        if module is None:
            continue
        for entry in entries:
            parts = entry.split("|")
            if len(parts) < 2:
                continue
            repo, binary = parts[0], parts[1]
            url = f"https://github.com/{repo}"
            tools.append({"name": binary, "method": "binary", "url": url, "module": module})
    return tools


# Shared base dependencies from lib/shared.sh
def extract_shared_tools():
    """Parse SHARED_BASE_PACKAGES from lib/shared.sh."""
    text = SHARED_PATH.read_text(encoding="utf-8", errors="replace")
    arrays = parse_arrays(text)
    tools = []
    for pkg in arrays.get("SHARED_BASE_PACKAGES", []):
        tools.append({"name": pkg, "method": "apt", "url": ""})
    return tools


# Module extraction
def extract_module_tools(module_name):
    """Return list of {name, method, url} for every tool in a module."""
    if module_name == "shared":
        return extract_shared_tools()
    filepath = MODULES_DIR / f"{module_name}.sh"
    text = filepath.read_text(encoding="utf-8", errors="replace")
    clean = strip_comments(text)
    arrays = parse_arrays(text)
    prefix = MODULE_PREFIX[module_name]
    tools = []

    # Array-based tools
    for arr_name, entries in arrays.items():
        if not arr_name.startswith(prefix + "_"):
            continue
        suffix = arr_name[len(prefix) + 1:]

        if suffix in APT_SUFFIXES:
            for e in entries:
                tools.append({"name": e, "method": "apt", "url": ""})

        elif suffix == "PIPX":
            for e in entries:
                tools.append({"name": e, "method": "pipx", "url": ""})

        elif suffix == "CARGO":
            for e in entries:
                tools.append({"name": e, "method": "cargo", "url": ""})

        elif suffix == "GEMS":
            for e in entries:
                tools.append({"name": e, "method": "gem", "url": ""})

        elif suffix in GIT_SUFFIXES:
            for e in entries:
                if "=" in e:
                    name, url = e.split("=", 1)
                    url = re.sub(r"\.git$", "", url)
                    tools.append({"name": name, "method": "git", "url": url})

        elif suffix == "DOCKER":
            for e in entries:
                if ":" in e:
                    _, dname = e.split(":", 1)
                    tools.append({"name": dname.lower(), "method": "docker", "url": ""})

        # Skip GO, GO_BINS, GIT_NAMES — handled separately

    # Go tools (from GO_BINS with URLs from GO)
    go_bins_key = f"{prefix}_GO_BINS"
    go_arr_key = f"{prefix}_GO"
    if go_bins_key in arrays and arrays[go_bins_key]:
        url_map = {}
        for entry in arrays.get(go_arr_key, []):
            url = go_github_url(entry)
            if not url:
                continue
            # Last component before @
            last = entry.split("/")[-1].split("@")[0]
            url_map[last] = url
            # cmd/ pattern: github.com/.../cmd/toolname@latest
            if "/cmd/" in entry:
                cmd_name = entry.split("/cmd/")[-1].split("@")[0]
                url_map[cmd_name] = url
            # Also try the ... pattern (amass uses /v4/...)
            if "/..." in entry:
                # github.com/owasp-amass/amass/v4/...@latest → amass
                for part in entry.split("/"):
                    if part and not part.startswith("v") and part != "..." and "@" not in part and "." not in part:
                        url_map[part] = url

        for bin_name in arrays[go_bins_key]:
            url = url_map.get(bin_name, "")
            tools.append({"name": bin_name, "method": "go", "url": url})

    # Function-call tools

    # download_github_release "owner/repo" "tool_name" ...
    for m in re.finditer(
        r'download_github_release\s+"([^"]+)"\s+"([^"]+)"', clean
    ):
        owner_repo, name = m.group(1), m.group(2)
        name = NAME_ALIASES.get(name, name)
        url = f"https://github.com/{owner_repo}"
        tools.append({"name": name, "method": "binary", "url": url})

    # build_from_source "name" "url" "cmd"
    for m in re.finditer(
        r'build_from_source\s+"([^"]+)"\s+"([^"]+)"', clean
    ):
        name = m.group(1)
        url = re.sub(r"\.git$", "", m.group(2))
        tools.append({"name": name, "method": "source", "url": url})

    # docker_pull "image" "name" — skip bash variable refs like "$image" "$name"
    docker_names = {t["name"] for t in tools if t["method"] == "docker"}
    for m in re.finditer(r'docker_pull\s+"([^"]+)"\s+"([^"]+)"', clean):
        raw_name = m.group(2)
        if raw_name.startswith("$"):
            continue  # bash variable, not a literal name
        name = raw_name.lower().replace(" ", "-")
        if name not in docker_names:
            tools.append({"name": name, "method": "docker", "url": ""})
            docker_names.add(name)

    # install_cargo_batch "label" tool1 tool2 ...
    cargo_names = {t["name"] for t in tools if t["method"] == "cargo"}
    for m in re.finditer(r'install_cargo_batch\s+"[^"]+"\s+(.+)', clean):
        rest = re.split(r'\s*\|\||\s*;|\s*#', m.group(1))[0].strip()
        for name in rest.split():
            if re.match(r'^[\w-]+$', name) and name not in cargo_names:
                tools.append({"name": name, "method": "cargo", "url": ""})
                cargo_names.add(name)

    # Special installers
    if "install_metasploit" in clean:
        tools.append({
            "name": "metasploit", "method": "special",
            "url": "https://github.com/rapid7/metasploit-framework",
        })
    if "install_zap" in clean:
        tools.append({
            "name": "zaproxy", "method": "snap",
            "url": "https://github.com/zaproxy/zaproxy",
        })
    if "foundryup" in clean:
        tools.append({
            "name": "foundry", "method": "special",
            "url": "https://github.com/foundry-rs/foundry",
        })
    if "steampipe" in clean:
        tools.append({
            "name": "steampipe", "method": "special",
            "url": "https://github.com/turbot/steampipe",
        })

    # pipx install git+URL patterns (not in PIPX arrays)
    for m in re.finditer(
        r'pipx\s+install\s+"git\+https://github\.com/([^"]+)"', clean
    ):
        repo_path = m.group(1)
        name = repo_path.split("/")[-1].lower()
        tools.append({
            "name": name, "method": "pipx",
            "url": f"https://github.com/{repo_path}",
        })

    # pipx install <name> (plain package name, not git+URL)
    pipx_names = {t["name"] for t in tools if t["method"] == "pipx"}
    for m in re.finditer(r'pipx\s+install\s+([\w][\w-]*)', clean):
        name = m.group(1)
        if name not in pipx_names and name != "git":
            tools.append({"name": name, "method": "pipx", "url": ""})
            pipx_names.add(name)

    # snap_install calls
    for m in re.finditer(r'snap_install\s+(\S+)', clean):
        name = m.group(1)
        tools.append({"name": name, "method": "snap", "url": ""})

    # npm install -g <package>
    for m in re.finditer(r'npm\s+install\s+-g\s+([\w][\w@/-]*)', clean):
        name = m.group(1).split("@")[0]
        tools.append({"name": name, "method": "npm", "url": ""})

    return tools


# Validation
def validate():
    """Cross-validate tools_config.json against module files. Return exit code."""
    errors = 0
    warnings = 0

    # Load JSON
    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}")
        return 1

    # -- Structural checks --
    for i, entry in enumerate(config):
        for field in ("name", "method", "module"):
            if field not in entry:
                print(f"ERROR: Entry {i} missing '{field}': {entry}")
                errors += 1
        if entry.get("method") not in VALID_METHODS:
            print(f"ERROR: Invalid method '{entry.get('method')}' for '{entry.get('name')}'")
            errors += 1
        if entry.get("module") not in ALL_MODULES:
            print(f"ERROR: Invalid module '{entry.get('module')}' for '{entry.get('name')}'")
            errors += 1

    # Duplicate check
    seen = set()
    for entry in config:
        name = entry.get("name", "")
        if name in seen:
            print(f"ERROR: Duplicate tool name: '{name}'")
            errors += 1
        seen.add(name)

    # Cross-validation
    # Build lookup from module arrays: (name, method) → module
    # Skip "shared" — base deps are infrastructure, not tracked in tools_config.json
    module_tools = {}
    for mod in ALL_MODULES:
        if mod == "shared":
            continue
        for t in extract_module_tools(mod):
            module_tools[(t["name"], t["method"])] = mod

    # Merge binary releases from lib/installers.sh
    for t in extract_binary_releases():
        module_tools[(t["name"], t["method"])] = t["module"]

    # Build lookup from JSON: (name, method) → module
    config_tools = {}
    for entry in config:
        config_tools[(entry["name"], entry["method"])] = entry["module"]

    # Tools in modules but missing from JSON → ERROR
    for (name, method), mod in sorted(module_tools.items()):
        if (name, method) not in config_tools:
            # Check if name exists with a different method
            alt = [m for (n, m) in config_tools if n == name]
            if alt:
                # Same tool, different method — just a warning
                pass
            else:
                print(f"ERROR: '{name}' ({method}) in modules/{mod}.sh but MISSING from tools_config.json")
                errors += 1

    # Tools in JSON but not in modules → WARNING (function-call tools may not parse)
    for (name, method), mod in sorted(config_tools.items()):
        if (name, method) not in module_tools:
            alt = [m for (n, m) in module_tools if n == name]
            if not alt:
                print(f"WARNING: '{name}' ({method}) in tools_config.json but not found in modules/{mod}.sh arrays")
                warnings += 1

    # Summary
    print(f"\ntools_config.json: {len(config)} tools")
    print(f"Module arrays:     {len(module_tools)} tools parsed")
    print(f"Errors: {errors}  Warnings: {warnings}")

    return 1 if errors > 0 else 0


# Sync (populate URLs)
def sync():
    """Add/update url field in tools_config.json from module data."""
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

    # Build URL map from all modules: name → url
    url_map = {}
    for mod in ALL_MODULES:
        for t in extract_module_tools(mod):
            if t["url"]:
                url_map[t["name"]] = t["url"]
    # Merge binary releases from lib/installers.sh
    for t in extract_binary_releases():
        if t["url"]:
            url_map.setdefault(t["name"], t["url"])

    # Merge URLs into config
    for entry in config:
        if "url" not in entry or not entry["url"]:
            entry["url"] = url_map.get(entry["name"], "")

    # Write back — one entry per line, matching existing style
    with CONFIG_PATH.open("w", encoding="utf-8", newline="\n") as f:
        f.write("[\n")
        for i, entry in enumerate(config):
            line = json.dumps(entry, ensure_ascii=False)
            comma = "," if i < len(config) - 1 else ""
            f.write(f"  {line}{comma}\n")
        f.write("]\n")

    populated = sum(1 for e in config if e.get("url"))
    print(f"Synced: {populated}/{len(config)} tools have URLs")


# Main
def main():
    if "--sync" in sys.argv:
        sync()
    else:
        sys.exit(validate())


if __name__ == "__main__":
    main()
