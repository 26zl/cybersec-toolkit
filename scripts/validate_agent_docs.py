#!/usr/bin/env python3
"""Validate the single-source agent-documentation contract.

AGENTS.md owns shared rules and repository claims. CLAUDE.md and GEMINI.md must
import that contract with their clients' documented Markdown import syntax and
contain only the small client-specific layer. Run by ``make validate`` and CI;
offline and stdlib-only.
"""

from __future__ import annotations

import glob
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# label -> (regex capturing the number, repo-truth key or None). tools_floor is
# intentionally a floor because the public claim is written as "N+ tools".
CLAIMS: dict[str, tuple[str, str | None]] = {
    "tools (floor)": (r"(\d+)\+ cybersecurity tools", "tools_floor"),
    "install methods": (r"(\d+) install methods", "install_methods"),
    "modules": (r"(\d+) modules", "modules"),
    "profiles": (r"(\d+) profiles", "profiles"),
    "skills": (r"(\d+) on-demand", "skills"),
}

# Shared rules belong in AGENTS.md and must not be copied into client wrappers.
SHARED_SECTIONS = [
    "## MCP Server Usage (MANDATORY tool order)",
    "## DANGER: Never Read Unvalidated Images",
    "## Writeups (MANDATORY)",
    "## Tool-First Approach (MANDATORY)",
    "## Discovering and Adding New Tools (Approval-Gated)",
    "## CTF/Bounty Tactical Methodology",
    "## Adding a New Tool",
]

WRAPPER_CONTRACTS = {
    "CLAUDE.md": {
        "import": r"(?m)^@AGENTS\.md\s*$",
        "markers": [
            "## Claude Code-specific guidance",
            ".mcp.json",
            "/mcp",
            ".claude/skills/",
            "scripts/sync-skills.sh",
        ],
    },
    "GEMINI.md": {
        "import": r"(?m)^@\./AGENTS\.md\s*$",
        "markers": [
            "## Gemini CLI-specific guidance",
            ".gemini/settings.json",
            "/memory show",
            ".agents/skills/",
            "scripts/sync-skills.sh",
        ],
    },
}


def _ints(text: str, pattern: str) -> list[int]:
    return [int(match) for match in re.findall(pattern, text)]


def check(agents: str, wrappers: dict[str, str], truth: dict[str, int]) -> list[str]:
    errors: list[str] = []

    for label, (pattern, truth_key) in CLAIMS.items():
        values = _ints(agents, pattern)
        if not values:
            errors.append(f"AGENTS.md: claim {label!r} not found (pattern {pattern!r} — reworded?)")
            continue
        if len(set(values)) > 1:
            errors.append(f"AGENTS.md: inconsistent {label} counts: {sorted(set(values))}")
            continue
        if truth_key is None:
            continue
        claim = values[0]
        real = truth[truth_key]
        if truth_key == "tools_floor":
            if real < claim:
                errors.append(f"tools floor {claim} exceeds real tool count {real}")
        elif claim != real:
            errors.append(f"{label}: AGENTS.md says {claim} but the repo has {real}")

    for section in SHARED_SECTIONS:
        if section not in agents:
            errors.append(f"AGENTS.md: missing shared-contract section {section!r}")

    for filename, contract in WRAPPER_CONTRACTS.items():
        text = wrappers.get(filename, "")
        if not re.search(str(contract["import"]), text):
            errors.append(f"{filename}: missing canonical AGENTS.md import (expected {contract['import']!r})")
        for marker in contract["markers"]:
            if marker not in text:
                errors.append(f"{filename}: missing client-specific marker {marker!r}")
        for section in SHARED_SECTIONS:
            if section in text:
                errors.append(f"{filename}: duplicates shared section {section!r}; keep it in AGENTS.md")

    return errors


LAYOUT_HEADING = "### MCP Server Module Layout"


def _section(text: str, heading: str) -> str:
    """Return the body under *heading* up to the next heading of the same or higher level."""
    start = text.find(heading)
    if start < 0:
        return ""
    level = len(heading) - len(heading.lstrip("#"))
    body = text[start + len(heading) :]
    end = re.search(rf"(?m)^#{{1,{level}}} ", body)
    return body[: end.start()] if end else body


def check_module_layout(agents: str, modules: list[str]) -> list[str]:
    """Every MCP server module must be named in AGENTS.md's module layout."""
    section = _section(agents, LAYOUT_HEADING)
    if not section:
        return [f"AGENTS.md: section {LAYOUT_HEADING!r} not found"]
    return [
        f"AGENTS.md: {LAYOUT_HEADING.lstrip('# ')} does not name mcp_server/{name}"
        for name in modules
        if f"`{name}`" not in section
    ]


def validate_recipe_commands(makefile: str) -> list[str]:
    """Names of the scripts and modules the Makefile ``validate`` recipe runs, in order."""
    match = re.search(r"(?ms)^validate:[^\n]*\n((?:\t[^\n]*\n|[ \t]*\n)*)", makefile)
    names: list[str] = []
    for line in (match.group(1) if match else "").splitlines():
        found = re.search(r"scripts/([\w.-]+)", line) or re.search(r"-m (unittest)\b", line)
        if found and found.group(1) not in names:
            names.append(found.group(1))
    return names


def check_validate_skill(makefile: str, skill: str) -> list[str]:
    """Every command in the Makefile ``validate`` recipe must be named in the validate-all skill."""
    commands = validate_recipe_commands(makefile)
    if not commands:
        return ["Makefile: validate recipe not found or empty"]
    return [
        f".claude/skills/validate-all/SKILL.md: does not name {name!r}, which `make validate` runs"
        for name in commands
        if name not in skill
    ]


def mcp_modules() -> list[str]:
    return sorted(p.name for p in (ROOT / "mcp_server").glob("*.py") if p.name != "__init__.py")


def repo_truth() -> dict[str, int]:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from validate_tools_config import VALID_METHODS

    tools = json.loads((ROOT / "tools_config.json").read_text())
    return {
        "tools_floor": len(tools),
        "install_methods": len(VALID_METHODS),
        "modules": len(glob.glob(str(ROOT / "modules" / "*.sh"))),
        "profiles": len(glob.glob(str(ROOT / "profiles" / "*.conf"))),
        "skills": len(glob.glob(str(ROOT / ".claude" / "skills" / "*" / "SKILL.md"))),
    }


def selftest() -> int:
    truth = {"tools_floor": 672, "install_methods": 12, "modules": 18, "profiles": 14, "skills": 872}
    agents = (
        "670+ cybersecurity tools ... 12 install methods, 18 modules, 14 profiles. "
        "872 on-demand skills.\n" + "\n".join(SHARED_SECTIONS)
    )
    wrappers = {
        "CLAUDE.md": "@AGENTS.md\n" + "\n".join(WRAPPER_CONTRACTS["CLAUDE.md"]["markers"]),
        "GEMINI.md": "@./AGENTS.md\n" + "\n".join(WRAPPER_CONTRACTS["GEMINI.md"]["markers"]),
    }
    assert check(agents, wrappers, truth) == [], "selftest: valid contract was flagged"

    bad_import = dict(wrappers)
    bad_import["GEMINI.md"] = bad_import["GEMINI.md"].replace("@./AGENTS.md", "[AGENTS](AGENTS.md)")
    assert any("GEMINI.md" in error for error in check(agents, bad_import, truth)), (
        "selftest: missing Gemini import was not caught"
    )

    assert any(
        "install methods" in error for error in check(agents.replace("12 install", "11 install"), wrappers, truth)
    ), "selftest: a wrong install-method count was not caught"

    duplicate = dict(wrappers)
    duplicate["CLAUDE.md"] += "\n## Writeups (MANDATORY)"
    assert any("duplicates shared section" in error for error in check(agents, duplicate, truth)), (
        "selftest: duplicated shared section was not caught"
    )

    lie = agents.replace("670+ cybersecurity", "9000+ cybersecurity")
    assert any("tools floor" in error for error in check(lie, wrappers, truth)), (
        "selftest: inflated tool floor was not caught"
    )

    modules = ["server.py", "audit.py"]
    layout = "## Architecture\n### MCP Server Module Layout\n- `server.py` x\n- `audit.py` y\n### Next\n- `other.py`\n"
    assert check_module_layout(layout, modules) == [], "selftest: complete layout was flagged"
    assert check_module_layout(layout, [*modules, "other.py"]), (
        "selftest: a module named outside the layout was accepted"
    )
    assert check_module_layout(layout.replace("`audit.py`", "audit"), modules), (
        "selftest: an unnamed module was not caught"
    )
    assert check_module_layout("no layout here", modules), "selftest: a missing layout section was not caught"

    makefile = (
        "validate: ## x\n\tpython3 scripts/a.py --strict\n\tbash scripts/b.sh\n\tpython3 -m unittest discover\n"
        "\nother:\n\tscripts/c.py\n"
    )
    assert validate_recipe_commands(makefile) == ["a.py", "b.sh", "unittest"], "selftest: recipe parse is wrong"
    assert check_validate_skill(makefile, "a.py b.sh unittest") == [], "selftest: a complete skill was flagged"
    assert check_validate_skill(makefile, "a.py unittest"), "selftest: a command missing from the skill was accepted"
    assert check_validate_skill("other:\n\tx\n", "a.py"), "selftest: a missing validate recipe was accepted"

    print("selftest OK")
    return 0


def main() -> int:
    from _cli import check_args

    check_args({"--selftest"}, "usage: validate_agent_docs.py [--selftest]")
    if "--selftest" in sys.argv[1:]:
        return selftest()

    agents = (ROOT / "AGENTS.md").read_text()
    wrappers = {filename: (ROOT / filename).read_text() for filename in WRAPPER_CONTRACTS}
    errors = check(agents, wrappers, repo_truth())
    errors += check_module_layout(agents, mcp_modules())
    skill = (ROOT / ".claude" / "skills" / "validate-all" / "SKILL.md").read_text()
    errors += check_validate_skill((ROOT / "Makefile").read_text(), skill)
    if errors:
        print("Agent documentation contract: FAIL", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Agent documentation contract: OK (AGENTS.md owns shared rules; Claude and Gemini imports validated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
