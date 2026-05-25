#!/usr/bin/env python3
"""Validate Claude Code skill metadata and index consistency."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / ".claude" / "skills"
INDEX = SKILLS_DIR / "SKILLS.md"


def _frontmatter(text: str) -> dict[str, str] | None:
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not match:
        return None

    fields: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip().strip('"').strip("'")
    return fields


def _declared_total(index_text: str) -> int | None:
    match = re.search(r"contains\s+(\d+)\s+skills", index_text, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _section_counts(index_text: str) -> list[tuple[str, int]]:
    return [
        (match.group(1), int(match.group(2)))
        for match in re.finditer(r"^##\s+(.+?)\s+\((\d+)\)\s*$", index_text, re.MULTILINE)
    ]


def main() -> int:
    errors: list[str] = []

    if not SKILLS_DIR.is_dir():
        print(f"ERROR: missing skills directory: {SKILLS_DIR.relative_to(ROOT)}")
        return 1

    skill_dirs = sorted(path for path in SKILLS_DIR.iterdir() if path.is_dir())

    for skill_dir in skill_dirs:
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.is_file():
            errors.append(f"{skill_dir.relative_to(ROOT)}: missing SKILL.md")
            continue

        fields = _frontmatter(skill_file.read_text(encoding="utf-8", errors="replace"))
        if fields is None:
            errors.append(f"{skill_file.relative_to(ROOT)}: missing YAML frontmatter")
            continue

        name = fields.get("name", "")
        description = fields.get("description", "")
        if name != skill_dir.name:
            errors.append(f"{skill_file.relative_to(ROOT)}: name={name!r}, expected {skill_dir.name!r}")
        if not description:
            errors.append(f"{skill_file.relative_to(ROOT)}: missing description")

    if not INDEX.is_file():
        errors.append(f"{INDEX.relative_to(ROOT)}: missing index")
    else:
        index_text = INDEX.read_text(encoding="utf-8", errors="replace")
        declared = _declared_total(index_text)
        if declared is None:
            errors.append(f"{INDEX.relative_to(ROOT)}: missing declared skill total")
        elif declared != len(skill_dirs):
            errors.append(f"{INDEX.relative_to(ROOT)}: declares {declared} skills, found {len(skill_dirs)}")

        counted_sections = [(name, count) for name, count in _section_counts(index_text) if "Adding more skills" not in name]
        section_total = sum(count for _, count in counted_sections)
        if counted_sections and section_total != len(skill_dirs):
            errors.append(
                f"{INDEX.relative_to(ROOT)}: section counts sum to {section_total}, found {len(skill_dirs)} skill dirs"
            )

    print(f"Claude skills: {len(skill_dirs)} directories")
    if errors:
        print(f"FAILED: {len(errors)} issue(s) found")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("OK: Claude skill metadata and index are consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
