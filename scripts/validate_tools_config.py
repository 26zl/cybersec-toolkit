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
# C2_GIT: the INCLUDE_C2-gated git array in modules/misc.sh (same git semantics).
GIT_SUFFIXES = {"GIT", "C2_GIT"}

VALID_METHODS = {
    "apt", "pipx", "go", "cargo", "gem", "git",
    "binary", "source", "docker", "snap", "special", "npm",
}

# Names that differ between code and JSON (code_name → json_name)
NAME_ALIASES = {
    "d2j-dex2jar": "dex2jar",
    "heimdall": "heimdall-rs",
}

# Bash parsing helpers
def strip_comments(text):
    """Remove full-line bash comments."""
    return "\n".join(
        line for line in text.split("\n")
        if not line.lstrip().startswith("#")
    )


def _find_array_body(text, open_idx):
    """Return (body, end_idx) for an array opened at text[open_idx] == '('.

    Scans paren-balanced so a ')' inside a quoted cell can't truncate the array
    early. Quotes (both ' and ") and parens inside them are ignored when balancing.
    Returns (None, open_idx) if the array is never closed.
    """
    depth = 0
    quote = None
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return None, open_idx


def parse_arrays(text):
    """Parse bash arrays: NAME=( ... ) → {NAME: [entries]}.

    Paren-balanced and quote-aware so a ')' inside a quoted cell does not close
    the array prematurely (which would silently drop trailing entries).
    """
    text = strip_comments(text)
    result = {}
    for m in re.finditer(r'(\w+)\s*=\s*\(', text):
        name = m.group(1)
        body, _ = _find_array_body(text, m.end() - 1)
        if body is None:
            continue
        entries = []
        quoted_lines = 0
        for raw_line in body.split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            # A line that is purely one-or-more quoted cells counts toward the
            # quoted-line tally used to detect silent truncation.
            if re.fullmatch(r'(?:"[^"]*"\s*)+', line):
                quoted_lines += len(re.findall(r'"[^"]*"', line))
        for item in re.finditer(r'"([^"]*)"|(\S+)', body):
            val = item.group(1) if item.group(1) is not None else item.group(2)
            if val:
                entries.append(val)
        # Sanity: when the array is written one quoted cell per line, the number
        # of parsed quoted entries must match — a mismatch means a ')' or stray
        # token truncated the body (the bug this guard exists to catch).
        quoted_entries = sum(1 for it in re.finditer(r'"[^"]*"', body))
        if quoted_lines and quoted_entries != quoted_lines:
            print(
                f"WARNING: array '{name}' parsed {quoted_entries} quoted cells "
                f"but found {quoted_lines} quoted-cell lines (possible truncation)"
            )
        result[name] = entries
    return result


def parse_assoc_array(text, name):
    """Parse a bash associative array: declare -A NAME=( [k]="v" ... ) → {k: v}.

    Used for the build-from-source url/cmd maps in modules (single source of truth).
    """
    m = re.search(rf"{re.escape(name)}\s*=\s*\(", text)
    if not m:
        return {}
    body, _ = _find_array_body(text, m.end() - 1)
    if body is None:
        return {}
    return dict(re.findall(r'\[([^\]]+)\]\s*=\s*"([^"]*)"', body))


def go_github_url(import_path):
    """github.com/org/repo/... → https://github.com/org/repo"""
    # Strip @latest or @version suffix
    clean = import_path.split("@")[0]
    parts = clean.split("/")
    if len(parts) >= 3 and parts[0] == "github.com":
        return f"https://github.com/{parts[1]}/{parts[2]}"
    return ""


# Map BINARY_RELEASES_* suffix → module name
# MISC_C2: the INCLUDE_C2-gated binary array in lib/installers.sh (belongs to misc).
BINARY_RELEASE_MODULE = {
    "MISC": "misc", "MISC_C2": "misc", "NETWORKING": "networking", "RECON": "recon",
    "WEB": "web", "REVERSING": "reversing", "FORENSICS": "forensics",
    "ENTERPRISE": "enterprise", "BLUETEAM": "blueteam",
    "CONTAINERS": "containers", "MOBILE": "mobile", "STEGO": "stego",
    "BLOCKCHAIN": "blockchain",
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
            binary = NAME_ALIASES.get(binary, binary)
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

        # Skip GO, GO_BINS, GIT_NAMES — handled separately.
        # No <PREFIX>_DOCKER arrays exist; docker tools come from docker_pull
        # calls (parsed below) and ALL_DOCKER_IMAGES in lib/installers.sh.

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

    # Build-from-source tools: <PREFIX>_BUILD_NAMES + <PREFIX>_BUILD_URLS maps
    # (single source of truth, consumed by install + scripts/update.sh).
    build_urls = parse_assoc_array(clean, f"{prefix}_BUILD_URLS")
    for name in arrays.get(f"{prefix}_BUILD_NAMES", []):
        url = re.sub(r"\.git$", "", build_urls.get(name, ""))
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

    # npm install -g "package@version" or npm install -g package
    for m in re.finditer(r'npm\s+install\s+-g\s+"?([^"\s]+)"?', clean):
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

    # -- Module-set check --
    # ALL_MODULES is hand-maintained; enumerate modules/*.sh so a new module
    # file (or a deleted one) can't silently escape cross-validation. "shared"
    # is a pseudo-module (lib/shared.sh), so it is excluded from the disk set.
    disk_modules = {p.stem for p in MODULES_DIR.glob("*.sh")}
    declared_modules = set(ALL_MODULES) - {"shared"}
    for name in sorted(disk_modules - declared_modules):
        print(f"ERROR: modules/{name}.sh exists but is not listed in ALL_MODULES")
        errors += 1
    for name in sorted(declared_modules - disk_modules):
        print(f"ERROR: '{name}' in ALL_MODULES but modules/{name}.sh not found")
        errors += 1

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
            # A docker tool installed alongside a same-named git clone is stored
            # in JSON with a "-docker" suffix to avoid a duplicate name (e.g.
            # pentagi git + pentagi-docker). That is the documented convention,
            # not method drift — mirror the JSON-side check below.
            if method == "docker" and (f"{name}-docker", "docker") in config_tools:
                continue
            # Check if name exists with a different method
            alt = [m for (n, m) in config_tools if n == name]
            if alt:
                # Same tool name, different method — install-method drift.
                # Name it explicitly so a pipx-vs-git style mismatch (e.g.
                # theHarvester) can't slip past the validator. Treated as an
                # ERROR (not a warning) so CI, which keys off the exit code,
                # fails on method drift per the "0 errors, 0 warnings" contract.
                print(
                    f"ERROR: '{name}' method mismatch: installer array in "
                    f"modules/{mod}.sh uses '{method}' but tools_config.json "
                    f"declares '{', '.join(sorted(set(alt)))}'"
                )
                errors += 1
            else:
                print(f"ERROR: '{name}' ({method}) in modules/{mod}.sh but MISSING from tools_config.json")
                errors += 1

    # Tools in JSON but not in modules → WARNING (function-call tools may not parse)
    for (name, method), mod in sorted(config_tools.items()):
        if (name, method) not in module_tools:
            # Docker tools may use a "-docker" suffix in config when the base
            # name already exists as a git clone (e.g. pentagi-docker vs pentagi).
            if name.endswith("-docker") and method == "docker":
                base = name[: -len("-docker")]
                if (base, method) in module_tools:
                    continue
            alt = [m for (n, m) in module_tools if n == name]
            if not alt:
                print(f"WARNING: '{name}' ({method}) in tools_config.json but not found in modules/{mod}.sh arrays")
                warnings += 1

    # Module-field drift: tool present on both sides but claiming different modules.
    # Membership-in-ALL_MODULES alone (above) cannot catch a wrong-but-valid module.
    for (name, method), mod in sorted(module_tools.items()):
        if (name, method) in config_tools and config_tools[(name, method)] != mod:
            print(
                f"ERROR: '{name}' ({method}) module mismatch: "
                f"tools_config.json says '{config_tools[(name, method)]}' "
                f"but installer array is in modules/{mod}.sh"
            )
            errors += 1

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
