#!/usr/bin/env python3
"""Consistency gate for CLAUDE.md and AGENTS.md: headline counts must match across both
docs (and the repo where it is the source of truth), and every shared-contract section
must appear in both. Run by `make validate` and CI; offline, stdlib-only."""

from __future__ import annotations

import glob
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# label -> (regex capturing the number, repo-truth key or None); "tools_floor" is a floor (repo >= claim).
CLAIMS: dict[str, tuple[str, str | None]] = {
    "tools (floor)": (r"(\d+)\+ cybersecurity tools", "tools_floor"),
    "install methods": (r"(\d+) install methods", None),
    "modules": (r"(\d+) modules", "modules"),
    "profiles": (r"(\d+) profiles", "profiles"),
    "skills": (r"(\d+) on-demand", "skills"),
}

# H2 sections both agent docs must contain (body wording may differ); add new cross-agent rules here.
SHARED_SECTIONS = [
    "## DANGER: Never Read Unvalidated Images",
    "## Writeups (MANDATORY)",
    "## Tool-First Approach (MANDATORY)",
    "## Discovering and Adding New Tools (Approval-Gated)",
    "## CTF/Bounty Tactical Methodology",
    "## Adding a New Tool",
]


def _ints(text: str, pattern: str) -> list[int]:
    return [int(m) for m in re.findall(pattern, text)]


def check(claude: str, agents: str, truth: dict[str, int]) -> list[str]:
    errors: list[str] = []

    for label, (pattern, truth_key) in CLAIMS.items():
        c, a = _ints(claude, pattern), _ints(agents, pattern)
        if not c:
            errors.append(f"CLAUDE.md: claim {label!r} not found (pattern {pattern!r} — reworded?)")
        if not a:
            errors.append(f"AGENTS.md: claim {label!r} not found (pattern {pattern!r} — reworded?)")
        if not c or not a:
            continue
        if len(set(c)) > 1:
            errors.append(f"CLAUDE.md: inconsistent {label} counts within the file: {sorted(set(c))}")
        if len(set(a)) > 1:
            errors.append(f"AGENTS.md: inconsistent {label} counts within the file: {sorted(set(a))}")
        cv, av = c[0], a[0]
        if cv != av:
            errors.append(f"{label}: CLAUDE.md says {cv} but AGENTS.md says {av}")
            continue
        if truth_key is None:
            continue
        real = truth[truth_key]
        if truth_key == "tools_floor":
            if real < cv:
                errors.append(f"tools floor {cv} exceeds real tool count {real} — lower the claim")
        elif cv != real:
            errors.append(f"{label}: docs say {cv} but the repo has {real}")

    for section in SHARED_SECTIONS:
        if section not in claude:
            errors.append(f"CLAUDE.md: missing shared-contract section {section!r}")
        if section not in agents:
            errors.append(f"AGENTS.md: missing shared-contract section {section!r}")

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
    truth = {"tools_floor": 584, "modules": 18, "profiles": 14, "skills": 872}
    good = (
        "580+ cybersecurity tools ... 12 install methods, 18 modules, 14 profiles. "
        "872 on-demand skills.\n" + "\n".join(SHARED_SECTIONS)
    )
    assert check(good, good, truth) == [], "selftest: consistent docs were flagged"

    drift = good.replace("18 modules", "17 modules").replace("## Writeups (MANDATORY)", "")
    errs = check(good, drift, truth)
    assert any("modules" in e for e in errs), "selftest: cross-file count drift not caught"
    assert any("Writeups" in e for e in errs), "selftest: missing shared section not caught"

    lie = good.replace("580+ cybersecurity", "9000+ cybersecurity")
    assert any("tools floor" in e for e in check(lie, lie, truth)), "selftest: inflated floor not caught"

    print("selftest OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    claude = (ROOT / "CLAUDE.md").read_text()
    agents = (ROOT / "AGENTS.md").read_text()
    errors = check(claude, agents, repo_truth())
    if errors:
        print("CLAUDE.md / AGENTS.md consistency: FAIL", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(
        "CLAUDE.md / AGENTS.md consistency: OK "
        "(headline counts agree across both docs and match the repo; shared sections present)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
