#!/usr/bin/env python3
"""Validate Claude Code skill metadata and index consistency."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / ".claude" / "skills"
INDEX = SKILLS_DIR / "SKILLS.md"
CURATION_MD = SKILLS_DIR / "CURATION.md"
CURATION_JSON = SKILLS_DIR / "curation.json"


def _frontmatter(text: str) -> dict[str, str] | None:
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not match:
        return None

    fields: dict[str, str] = {}
    lines = match.group(1).splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if ":" not in line:
            index += 1
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value in {">", ">-", "|", "|-"}:
            block: list[str] = []
            index += 1
            while index < len(lines):
                block_line = lines[index]
                if block_line.startswith((" ", "\t")) or not block_line.strip():
                    block.append(block_line.strip())
                    index += 1
                    continue
                break
            if value.startswith(">"):
                fields[key] = " ".join(part for part in block if part)
            else:
                fields[key] = "\n".join(block).strip()
            continue
        fields[key] = value.strip('"').strip("'")
        index += 1
    return fields


def _declared_total(index_text: str) -> int | None:
    match = re.search(r"contains\s+(\d+)\s+skills", index_text, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _section_counts(index_text: str) -> list[tuple[str, int]]:
    return [
        (match.group(1), int(match.group(2)))
        for match in re.finditer(r"^##\s+(.+?)\s+\((\d+)\)\s*$", index_text, re.MULTILINE)
    ]


def _validate_python_scripts(skill_dirs: list[Path], errors: list[str]) -> int:
    """Compile vendored helper scripts without writing __pycache__ files."""
    script_count = 0
    for skill_dir in skill_dirs:
        for script in sorted(skill_dir.rglob("scripts/**/*.py")):
            script_count += 1
            relative = script.relative_to(ROOT)
            source = script.read_text(encoding="utf-8", errors="replace")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", SyntaxWarning)
                try:
                    compile(source, str(script), "exec")
                except SyntaxError as exc:
                    errors.append(f"{relative}:{exc.lineno}: Python syntax error: {exc.msg}")
                    continue

            for warning in caught:
                if issubclass(warning.category, SyntaxWarning):
                    errors.append(f"{relative}:{warning.lineno}: Python syntax warning: {warning.message}")

    return script_count


def _validate_powershell_scripts(skill_dirs: list[Path], errors: list[str]) -> tuple[int, bool]:
    """Parse PowerShell helper scripts when pwsh is available."""
    scripts = sorted(script for skill_dir in skill_dirs for script in skill_dir.rglob("scripts/**/*.ps1"))
    if not scripts:
        return 0, False

    pwsh = shutil.which("pwsh")
    if not pwsh:
        return len(scripts), True

    for script in scripts:
        relative = script.relative_to(ROOT)
        ps_path = str(script).replace("'", "''")
        command = (
            "$errors=$null; "
            f"[System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -LiteralPath '{ps_path}'), "
            "[ref]$errors) > $null; "
            "if ($errors) { "
            "$errors | ForEach-Object { Write-Error (\"$($_.Token.StartLine):$($_.Token.StartColumn) $($_.Message)\") }; "
            "exit 1 "
            "}"
        )
        result = subprocess.run([pwsh, "-NoProfile", "-Command", command], capture_output=True, text=True)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            message = detail[0] if detail else "PowerShell parse failed"
            errors.append(f"{relative}: {message}")

    return len(scripts), False


def _validate_curation(skill_dirs: list[Path], errors: list[str]) -> None:
    expected_names = {skill_dir.name for skill_dir in skill_dirs}

    if not CURATION_MD.is_file():
        errors.append(f"{CURATION_MD.relative_to(ROOT)}: missing curation index")

    if not CURATION_JSON.is_file():
        errors.append(f"{CURATION_JSON.relative_to(ROOT)}: missing curation data")
        return

    try:
        data = json.loads(CURATION_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"{CURATION_JSON.relative_to(ROOT)}: invalid JSON: {exc}")
        return

    total = data.get("total_skills")
    if total != len(skill_dirs):
        errors.append(f"{CURATION_JSON.relative_to(ROOT)}: total_skills={total}, found {len(skill_dirs)}")

    curated_names = {item.get("name") for item in data.get("skills", []) if isinstance(item, dict)}
    if curated_names != expected_names:
        missing = sorted(expected_names - curated_names)
        extra = sorted(curated_names - expected_names)
        if missing:
            errors.append(f"{CURATION_JSON.relative_to(ROOT)}: missing skill(s): {', '.join(missing[:10])}")
        if extra:
            errors.append(f"{CURATION_JSON.relative_to(ROOT)}: extra skill(s): {', '.join(extra[:10])}")


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

    python_script_count = _validate_python_scripts(skill_dirs, errors)
    powershell_script_count, powershell_skipped = _validate_powershell_scripts(skill_dirs, errors)
    _validate_curation(skill_dirs, errors)

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
    print(f"Claude skill Python scripts: {python_script_count} checked")
    if powershell_script_count:
        suffix = " (parse skipped: pwsh not found)" if powershell_skipped else " checked"
        print(f"Claude skill PowerShell scripts: {powershell_script_count}{suffix}")
    if errors:
        print(f"FAILED: {len(errors)} issue(s) found")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("OK: Claude skill metadata and index are consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
