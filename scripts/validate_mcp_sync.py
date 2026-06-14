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


def _balanced_array_body(text: str, open_idx: int) -> str | None:
    """Return the body of an array opened at text[open_idx] == '('.

    Scans paren-balanced and quote-aware so a ')' inside a quoted cell or a
    comment can't close the array early (which would silently drop later
    entries). Returns None if the array is never closed.
    """
    depth = 0
    quote: str | None = None
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
                return text[open_idx + 1 : i]
        i += 1
    return None


def parse_bash_assoc_array(text: str, var_name: str) -> dict[str, str]:
    """Parse a bash associative array: declare -A VAR=( [k]="v" ... )."""
    m = re.search(rf"declare\s+-A\s+{var_name}=\(", text)
    if not m:
        return {}
    block = _balanced_array_body(text, m.end() - 1)
    if block is None:
        return {}
    entries = re.findall(r'\[([^\]]+)\]="([^"]*)"', block)
    return dict(entries)


def parse_bash_indexed_array(text: str, var_name: str) -> list[str]:
    """Parse a bash indexed array: VAR=( "entry" ... ).

    Paren-balanced (see _balanced_array_body) so a ')' inside a quoted cell or
    comment does not truncate the array. Asserts the parsed entry count matches
    the number of quoted-cell lines to catch any silent truncation.
    """
    m = re.search(rf"{var_name}=\(", text)
    if not m:
        return []
    block = _balanced_array_body(text, m.end() - 1)
    if block is None:
        return []
    entries = re.findall(r'"([^"]+)"', block)

    # Cross-check: when the array is one quoted cell per line, the parsed entry
    # count must equal the number of such lines. A mismatch signals truncation.
    quoted_lines = sum(
        1
        for line in block.splitlines()
        if re.fullmatch(r'\s*"[^"]+"\s*,?\s*', line)
    )
    if quoted_lines and len(entries) != quoted_lines:
        errors.append(
            f"{var_name}: parsed {len(entries)} entries but found {quoted_lines} "
            f"quoted-cell lines (possible array truncation)"
        )
    return entries


def parse_bash_unquoted_array(text: str, var_name: str) -> list[str]:
    """Parse a bash indexed array of bare (unquoted) tokens: VAR=( a b-c d )."""
    pattern = rf'(?<![\w-]){var_name}=\((.*?)\)'
    m = re.search(pattern, text, re.DOTALL)
    if not m:
        return []
    tokens: list[str] = []
    for line in m.group(1).splitlines():
        line = line.split("#", 1)[0]  # strip trailing comments
        tokens.extend(line.split())
    return tokens


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


# Sentinel for a flag assignment whose value can't be parsed (vs. genuinely absent).
_UNPARSEABLE = object()

_BASH_TRUE = {"true", "1", "yes"}
_BASH_FALSE = {"false", "0", "no", ""}


def _parse_bash_bool(text: str, var: str):
    """Parse a bash boolean assignment: VAR=true / VAR="1" / VAR=0 ...

    Tolerates optional surrounding single/double quotes. Returns:
      - None if the variable is absent
      - True/False for a recognized truthy/falsy token
      - _UNPARSEABLE for a present-but-unrecognized value (an explicit error,
        so a typo'd flag can't silently pass unverified).
    """
    m = re.search(rf'^{var}=(.*)$', text, re.MULTILINE)
    if not m:
        return None
    raw = m.group(1).strip()
    # Drop a trailing inline comment, then strip one layer of matching quotes.
    raw = raw.split("#", 1)[0].strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        raw = raw[1:-1]
    token = raw.strip().lower()
    if token in _BASH_TRUE:
        return True
    if token in _BASH_FALSE:
        return False
    return _UNPARSEABLE


# .conf variable → profiles.py key for the boolean flags.
_PROFILE_FLAGS = {
    "SKIP_HEAVY": "skip_heavy",
    "ENABLE_DOCKER": "enable_docker",
    "INCLUDE_C2": "include_c2",
}


def check_profiles() -> None:
    """Compare profile module lists AND boolean flags between *.conf and profiles.py."""
    from mcp_server.profiles import PROFILES as py_profiles

    profiles_dir = ROOT / "profiles"
    bash_profiles: dict[str, list[str]] = {}
    bash_flags: dict[str, dict[str, object]] = {}

    for conf in sorted(profiles_dir.glob("*.conf")):
        name = conf.stem
        text = conf.read_text(encoding="utf-8")
        m = re.search(r'MODULES="([^"]+)"', text)
        if m:
            bash_profiles[name] = m.group(1).split()
        bash_flags[name] = {
            py_key: _parse_bash_bool(text, conf_var) for conf_var, py_key in _PROFILE_FLAGS.items()
        }

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
        # Boolean flags (skip_heavy / enable_docker / include_c2).
        # None = flag absent from .conf (Python default applies, skip).
        # _UNPARSEABLE = flag present with an unrecognized value → explicit error
        # so a quoted/typo'd value can't pass unverified.
        for py_key, bash_val in bash_flags[name].items():
            py_val = py_profiles[name].get(py_key)
            if bash_val is _UNPARSEABLE:
                conf_var = next(c for c, p in _PROFILE_FLAGS.items() if p == py_key)
                errors.append(
                    f"PROFILES['{name}'].{py_key}: {conf_var} in {name}.conf has an "
                    f"unparseable boolean value (expected true/false/1/0)"
                )
            elif bash_val is not None and bash_val != py_val:
                errors.append(
                    f"PROFILES['{name}'].{py_key}: bash={bash_val} != python={py_val}"
                )

    for name in py_profiles:
        if name not in bash_profiles:
            errors.append(f"PROFILES: '{name}' in Python but missing in bash")

    print(f"PROFILES: {len(bash_profiles)} bash, {len(py_profiles)} python (modules + flags)")


def check_profile_descriptions() -> None:
    """Compare each profile's '# Profile:' comment description to profiles.py.

    The .conf header is '# Profile: <Description>' where <Description> is the
    canonical text from profiles.py (the single source of truth). Compare the
    whole header (whitespace-normalized) so the marketplace description can't
    drift from the installer's profile comment.
    """
    from mcp_server.profiles import PROFILES as py_profiles

    profiles_dir = ROOT / "profiles"
    checked = 0
    for conf in sorted(profiles_dir.glob("*.conf")):
        name = conf.stem
        if name not in py_profiles:
            continue  # missing-profile drift is already reported by check_profiles()
        py_desc = py_profiles[name].get("description")
        if py_desc is None:
            continue

        text = conf.read_text(encoding="utf-8")
        m = re.search(r'^#\s*Profile:\s*(.+)$', text, re.MULTILINE)
        if not m:
            errors.append(f"PROFILE_DESC: profiles/{name}.conf missing '# Profile:' header")
            continue
        conf_desc = m.group(1).strip()
        if not conf_desc:
            errors.append(
                f"PROFILE_DESC: profiles/{name}.conf '# Profile:' header has no description"
            )
            continue
        checked += 1
        if " ".join(conf_desc.split()) != " ".join(py_desc.split()):
            errors.append(
                f"PROFILE_DESC['{name}']: conf={conf_desc!r} != python={py_desc!r}"
            )

    print(f"PROFILE_DESC: {checked} profile descriptions checked")


def check_tool_aliases() -> None:
    """Every TOOL_ALIASES target must resolve to a real registry tool name."""
    import json

    from mcp_server.advisor_utils import TOOL_ALIASES

    tools = json.loads((ROOT / "tools_config.json").read_text(encoding="utf-8"))
    names = {t["name"] for t in tools}

    for alias, target in TOOL_ALIASES.items():
        if target not in names:
            errors.append(
                f"TOOL_ALIASES['{alias}']: target '{target}' not found in tools_config.json"
            )

    print(f"TOOL_ALIASES: {len(TOOL_ALIASES)} aliases checked against {len(names)} registry tools")


# Advisor tool names that are intentionally NOT registry tools (system utilities
# or shells assumed present, not installed by a module). Empty today — every
# advisor tool currently resolves to a registry entry. Add a name here only with
# a one-line justification if it is genuinely a base system utility.
_ADVISOR_TOOL_EXCEPTIONS: set[str] = set()


def check_advisor_tool_names() -> None:
    """Every tool named in the CTF/bounty advisor maps must be a registry tool.

    advisor_utils.TOOL_ALIASES is small (display→registry name fixups), but the
    hundreds of tool names embedded in ctf_advisor.CTF_CATEGORY_MAP and
    bounty_advisor.BOUNTY_TARGET_MAP were never cross-checked. Resolve each
    through TOOL_ALIASES and error if it isn't in tools_config.json so a renamed
    or removed registry tool can't silently break a suggestion list.
    """
    import json

    from mcp_server.advisor_utils import TOOL_ALIASES
    from mcp_server.bounty_advisor import BOUNTY_TARGET_MAP
    from mcp_server.ctf_advisor import CTF_CATEGORY_MAP

    tools = json.loads((ROOT / "tools_config.json").read_text(encoding="utf-8"))
    names = {t["name"] for t in tools}

    checked = 0
    for source, mapping in (("ctf", CTF_CATEGORY_MAP), ("bounty", BOUNTY_TARGET_MAP)):
        for category, info in mapping.items():
            for tool_name, _desc in info.get("tools", []):
                checked += 1
                if tool_name in _ADVISOR_TOOL_EXCEPTIONS:
                    continue
                resolved = TOOL_ALIASES.get(tool_name, tool_name)
                if resolved not in names:
                    errors.append(
                        f"ADVISOR_TOOLS: {source} category '{category}' lists "
                        f"'{tool_name}' (resolves to '{resolved}') which is not in "
                        f"tools_config.json"
                    )

    print(f"ADVISOR_TOOLS: {checked} tool names checked against {len(names)} registry tools")


def check_c2_tools() -> None:
    """C2_TOOLS (tools_db.py) must match the INCLUDE_C2-gated bash arrays.

    Sources: modules/misc.sh MISC_C2_GIT_NAMES (git) + lib/installers.sh
    BINARY_RELEASES_MISC_C2 (binary, 2nd |-field) + the docker-only 'empire'.
    """
    from mcp_server.tools_db import C2_TOOLS as py_c2

    misc_text = (ROOT / "modules" / "misc.sh").read_text(encoding="utf-8")
    inst_text = (ROOT / "lib" / "installers.sh").read_text(encoding="utf-8")

    git_names = parse_bash_unquoted_array(misc_text, "MISC_C2_GIT_NAMES")
    bin_entries = parse_bash_indexed_array(inst_text, "BINARY_RELEASES_MISC_C2")
    bin_names = [e.split("|")[1] for e in bin_entries if len(e.split("|")) >= 2]

    if not git_names:
        errors.append("C2_TOOLS: could not parse MISC_C2_GIT_NAMES from modules/misc.sh")
    if not bin_names:
        errors.append("C2_TOOLS: could not parse BINARY_RELEASES_MISC_C2 from lib/installers.sh")

    # 'empire' is the docker-only C2 framework gated in install_module_misc (no array).
    bash_c2 = set(git_names) | set(bin_names) | {"empire"}

    for name in bash_c2 - py_c2:
        errors.append(f"C2_TOOLS: '{name}' gated in bash but missing from C2_TOOLS (tools_db.py)")
    for name in py_c2 - bash_c2:
        errors.append(f"C2_TOOLS: '{name}' in C2_TOOLS (tools_db.py) but not gated in bash")

    print(f"C2_TOOLS: {len(bash_c2)} bash, {len(py_c2)} python")


def _registered_mcp_tools() -> list[str]:
    """Function names decorated with @mcp.tool in server.py, in source order.

    Parses the source text (does not import server.py, which would pull in
    FastMCP and the whole runtime) for `@mcp.tool` immediately followed by a
    `def`/`async def` line.
    """
    server_text = (ROOT / "mcp_server" / "server.py").read_text(encoding="utf-8")
    return re.findall(
        r"@mcp\.tool\b[^\n]*\n(?:\s*@[^\n]*\n)*\s*(?:async\s+)?def\s+(\w+)",
        server_text,
    )


def check_mcp_toolchain() -> None:
    """guided_assessment.MCP_TOOLCHAIN must equal the @mcp.tool set in server.py.

    The toolchain advertised to the agent is hardcoded; without this check a tool
    rename/add/remove in server.py would silently drift from the guided-assessment
    list. Compare as sets (order isn't load-bearing) and report both directions.
    """
    from mcp_server.guided_assessment import MCP_TOOLCHAIN

    registered = _registered_mcp_tools()
    if not registered:
        errors.append("MCP_TOOLCHAIN: could not parse any @mcp.tool functions from server.py")
        return

    registered_set = set(registered)
    toolchain_set = set(MCP_TOOLCHAIN)

    for name in registered_set - toolchain_set:
        errors.append(
            f"MCP_TOOLCHAIN: '{name}' is an @mcp.tool in server.py but missing from MCP_TOOLCHAIN"
        )
    for name in toolchain_set - registered_set:
        errors.append(
            f"MCP_TOOLCHAIN: '{name}' in MCP_TOOLCHAIN but not an @mcp.tool in server.py"
        )
    if len(registered) != len(registered_set):
        errors.append("MCP_TOOLCHAIN: server.py has duplicate @mcp.tool function names")

    print(
        f"MCP_TOOLCHAIN: {len(registered_set)} server.py tools, "
        f"{len(toolchain_set)} guided_assessment entries"
    )


def check_cve_advisor() -> None:
    """KNOWN_CVES references must resolve: tools→registry, skills→dir, modules→descs.

    KNOWN_CVES is a hardcoded curated map with no sync validator, so a renamed
    registry tool, deleted skill dir, or dropped module would silently break a CVE
    mapping. Resolve every referenced tool through TOOL_ALIASES, confirm each skill
    exists as .claude/skills/<name>, and each module is a MODULE_DESCRIPTIONS key.
    """
    import json

    from mcp_server.advisor_utils import TOOL_ALIASES
    from mcp_server.cve_advisor import KNOWN_CVES
    from mcp_server.tools_db import MODULE_DESCRIPTIONS

    tools = json.loads((ROOT / "tools_config.json").read_text(encoding="utf-8"))
    names = {t["name"] for t in tools}
    skills_dir = ROOT / ".claude" / "skills"

    tool_refs = skill_refs = module_refs = 0
    for cve_id, entry in KNOWN_CVES.items():
        for tool_name in entry.get("tools", []):
            tool_refs += 1
            resolved = TOOL_ALIASES.get(tool_name, tool_name)
            if resolved not in names:
                errors.append(
                    f"KNOWN_CVES['{cve_id}'].tools: '{tool_name}' (resolves to "
                    f"'{resolved}') not in tools_config.json"
                )
        for skill in entry.get("skills", []):
            skill_refs += 1
            if not (skills_dir / skill / "SKILL.md").is_file():
                errors.append(
                    f"KNOWN_CVES['{cve_id}'].skills: '{skill}' has no "
                    f".claude/skills/{skill}/SKILL.md"
                )
        for module in entry.get("modules", []):
            module_refs += 1
            if module not in MODULE_DESCRIPTIONS:
                errors.append(
                    f"KNOWN_CVES['{cve_id}'].modules: '{module}' not in MODULE_DESCRIPTIONS"
                )

    print(
        f"KNOWN_CVES: {len(KNOWN_CVES)} CVEs, {tool_refs} tool refs, "
        f"{skill_refs} skill refs, {module_refs} module refs checked"
    )


def check_bin_name_maps() -> None:
    """APT_BIN_NAMES / SPECIAL_BIN_NAMES keys must be real registry tool names.

    Both maps translate a registry tool name to its on-PATH binary. A key that is
    no longer a registry tool (rename/removal) is dead config that can mask a
    genuinely-missing install — assert every key exists in tools_config.json.
    """
    import json

    from mcp_server.tools_db import APT_BIN_NAMES, SPECIAL_BIN_NAMES

    tools = json.loads((ROOT / "tools_config.json").read_text(encoding="utf-8"))
    names = {t["name"] for t in tools}

    for map_name, mapping in (
        ("APT_BIN_NAMES", APT_BIN_NAMES),
        ("SPECIAL_BIN_NAMES", SPECIAL_BIN_NAMES),
    ):
        for key in mapping:
            if key not in names:
                errors.append(f"{map_name}: key '{key}' is not a tool in tools_config.json")

    print(
        f"BIN_NAMES: {len(APT_BIN_NAMES)} APT_BIN_NAMES + {len(SPECIAL_BIN_NAMES)} "
        f"SPECIAL_BIN_NAMES keys checked against {len(names)} registry tools"
    )


def main() -> int:
    print("=== MCP Server Data Sync Check ===\n")

    check_module_descriptions()
    check_docker_images()
    check_pipx_bin_names()
    check_profiles()
    check_profile_descriptions()
    check_tool_aliases()
    check_advisor_tool_names()
    check_c2_tools()
    check_mcp_toolchain()
    check_cve_advisor()
    check_bin_name_maps()

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
