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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _skill_frontmatter import frontmatter as _frontmatter  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / ".claude" / "skills"
INDEX = SKILLS_DIR / "SKILLS.md"
CURATION_MD = SKILLS_DIR / "CURATION.md"
CURATION_JSON = SKILLS_DIR / "curation.json"
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
# Plugin marketplace manifests whose descriptions hardcode the skill count ("N on-demand
# security skills") — reconciled against the real dir count so they can't drift.
PLUGIN_MANIFESTS = (ROOT / ".claude-plugin" / "plugin.json", ROOT / ".claude-plugin" / "marketplace.json")

# THIRD_PARTY_NOTICES.md table rows -> a stable substring of the Source cell, and the
# curate source_for() bucket each represents. The single "remaining N" line aggregates
# the project-authored MIT buckets.
_NOTICES_ROWS = {
    "anthropic": "Anthropic-Cybersecurity-Skills",
    "claude-red": "SnailSploit/Claude-Red",
    "trail-of-bits": "trailofbits/skills",
    "bughunter": "shuvonsec/claude-bug-bounty",
    "transilience": "transilienceai/communitytools",
    "karpathy": "andrej-karpathy-skills",
}
_NOTICES_REMAINING_BUCKETS = {"project", "coverage-anchor", "ctf", "bug-bounty"}


def _import_curate():
    """Import scripts/curate_claude_skills.py without running it (main() is guarded)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import curate_claude_skills  # noqa: PLC0415 — lazy import to keep validator standalone

        return curate_claude_skills
    except Exception:  # noqa: BLE001
        return None


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

    # Freshness: regenerate the curation outputs from the same rules curate_claude_skills.py
    # uses and compare against the committed files, so stale/hand-edited content fails CI
    # (the docs promise this validator checks "curation freshness").
    curate = _import_curate()
    if curate is None:
        errors.append("scripts/curate_claude_skills.py: could not import to verify curation freshness")
        return
    try:
        skills = curate.load_skills()
        expected_json = curate.build_json(skills)
        expected_md = curate.render_md(skills)
    except Exception as exc:  # noqa: BLE001 — surface any curation failure as a validation error
        errors.append(f"scripts/curate_claude_skills.py: failed to regenerate curation ({exc})")
        return
    if data != expected_json:
        errors.append(
            f"{CURATION_JSON.relative_to(ROOT)} is stale; run python3 scripts/curate_claude_skills.py --write"
        )
    if CURATION_MD.is_file() and CURATION_MD.read_text(encoding="utf-8") != expected_md:
        errors.append(
            f"{CURATION_MD.relative_to(ROOT)} is stale; run python3 scripts/curate_claude_skills.py --write"
        )


def _validate_third_party_notices(skill_dirs: list[Path], errors: list[str]) -> None:
    """Reconcile THIRD_PARTY_NOTICES.md per-source counts against the live inventory.

    The counts drive license attribution, so a drift after a skill add/remove/rename is
    a licensing-accuracy issue. source_for() is name-based and authoritative here.
    """
    if not NOTICES.is_file():
        errors.append(f"{NOTICES.relative_to(ROOT)}: missing third-party notices")
        return
    curate = _import_curate()
    if curate is None:
        errors.append("scripts/curate_claude_skills.py: could not import to verify notices counts")
        return

    from collections import Counter

    live = Counter(curate.source_for(p.name) for p in skill_dirs)
    text = NOTICES.read_text(encoding="utf-8", errors="replace")

    for bucket, marker in _NOTICES_ROWS.items():
        match = re.search(rf"\|[^|\n]*{re.escape(marker)}[^|\n]*\|\s*(\d+)\s*\|", text)
        if not match:
            errors.append(f"{NOTICES.relative_to(ROOT)}: could not find table row for {bucket}")
            continue
        declared = int(match.group(1))
        actual = live.get(bucket, 0)
        if declared != actual:
            errors.append(
                f"{NOTICES.relative_to(ROOT)}: {bucket} count={declared}, computed {actual} from source_for()"
            )

    rem = re.search(r"remaining\s+(\d+)\s+skills", text, re.IGNORECASE)
    if not rem:
        errors.append(f"{NOTICES.relative_to(ROOT)}: missing 'remaining N skills' line")
    else:
        declared_rem = int(rem.group(1))
        actual_rem = sum(live.get(b, 0) for b in _NOTICES_REMAINING_BUCKETS)
        if declared_rem != actual_rem:
            errors.append(
                f"{NOTICES.relative_to(ROOT)}: remaining={declared_rem}, computed {actual_rem} "
                f"(project+coverage-anchor+ctf+bug-bounty)"
            )

    accounted = set(_NOTICES_ROWS) | _NOTICES_REMAINING_BUCKETS
    for bucket in live:
        if bucket not in accounted:
            errors.append(f"{NOTICES.relative_to(ROOT)}: source bucket {bucket!r} has no license attribution row")


def _validate_plugin_manifests(skill_dirs: list[Path], errors: list[str]) -> None:
    """Reconcile the hardcoded skill count in the plugin marketplace manifests.

    plugin.json / marketplace.json descriptions advertise "<N> on-demand security
    skills"; keep that in sync with the real dir count so the marketplace listing
    can't drift (validate_claude_skills already guards SKILLS.md/curation/notices).
    """
    expected = len(skill_dirs)
    pattern = re.compile(r"(\d+)\s+on-demand security skills")
    for manifest in PLUGIN_MANIFESTS:
        if not manifest.is_file():
            errors.append(f"{manifest.relative_to(ROOT)}: missing plugin manifest")
            continue
        counts = pattern.findall(manifest.read_text(encoding="utf-8", errors="replace"))
        if not counts:
            errors.append(f"{manifest.relative_to(ROOT)}: no '<N> on-demand security skills' count found")
            continue
        for count in counts:
            if int(count) != expected:
                errors.append(f"{manifest.relative_to(ROOT)}: advertises {count} skills, found {expected}")


def main() -> int:
    errors: list[str] = []
    spec_warnings: list[str] = []

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
        # agentskills.io spec: name is 1-64 chars, kebab-case, no leading/trailing/consecutive hyphens.
        if len(name) > 64:
            errors.append(f"{skill_file.relative_to(ROOT)}: name exceeds the 64-char spec limit")
        if name and not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
            errors.append(f"{skill_file.relative_to(ROOT)}: name {name!r} is not spec kebab-case")
        # Spec caps descriptions at 1024 chars; a few skills exceed it for trigger-keyword coverage.
        if len(description) > 1024:
            spec_warnings.append(
                f"{skill_file.relative_to(ROOT)}: description is {len(description)} chars (>1024 spec guidance)"
            )

    python_script_count = _validate_python_scripts(skill_dirs, errors)
    powershell_script_count, powershell_skipped = _validate_powershell_scripts(skill_dirs, errors)
    _validate_curation(skill_dirs, errors)
    _validate_third_party_notices(skill_dirs, errors)
    _validate_plugin_manifests(skill_dirs, errors)

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
    if spec_warnings:
        print(f"NOTE: {len(spec_warnings)} skill(s) exceed the agentskills.io 1024-char description guidance:")
        for warning in spec_warnings:
            print(f"  - {warning}")
    if errors:
        print(f"FAILED: {len(errors)} issue(s) found")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("OK: Claude skill metadata and index are consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
