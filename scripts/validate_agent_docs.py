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
    "install methods": (r"(\d+) install methods", None),
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


def repo_truth() -> dict[str, int]:
    tools = json.loads((ROOT / "tools_config.json").read_text())
    return {
        "tools_floor": len(tools),
        "modules": len(glob.glob(str(ROOT / "modules" / "*.sh"))),
        "profiles": len(glob.glob(str(ROOT / "profiles" / "*.conf"))),
        "skills": len(glob.glob(str(ROOT / ".claude" / "skills" / "*" / "SKILL.md"))),
    }


def selftest() -> int:
    truth = {"tools_floor": 594, "modules": 18, "profiles": 14, "skills": 872}
    agents = (
        "580+ cybersecurity tools ... 12 install methods, 18 modules, 14 profiles. "
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

    duplicate = dict(wrappers)
    duplicate["CLAUDE.md"] += "\n## Writeups (MANDATORY)"
    assert any("duplicates shared section" in error for error in check(agents, duplicate, truth)), (
        "selftest: duplicated shared section was not caught"
    )

    lie = agents.replace("580+ cybersecurity", "9000+ cybersecurity")
    assert any("tools floor" in error for error in check(lie, wrappers, truth)), (
        "selftest: inflated tool floor was not caught"
    )

    print("selftest OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()

    agents = (ROOT / "AGENTS.md").read_text()
    wrappers = {filename: (ROOT / filename).read_text() for filename in WRAPPER_CONTRACTS}
    errors = check(agents, wrappers, repo_truth())
    if errors:
        print("Agent documentation contract: FAIL", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Agent documentation contract: OK (AGENTS.md owns shared rules; Claude and Gemini imports validated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
