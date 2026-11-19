#!/usr/bin/env python3
"""Scan agent skills with NVIDIA SkillSpector and report the findings.

Only the scanner's static analysis runs; no model is called. A static scanner flags
most skills here, because they describe attacks. The useful signal is the change a
re-vendor introduces, so --compare prints the findings that an earlier result lacks.

Usage:
    scan_skills.py [--skills-dir DIR] [--output FILE] [--jobs N] [SKILL ...]
    scan_skills.py --changed-since REF [--at REF] [--output FILE]
    scan_skills.py --compare OLD.json NEW.json

--at REF scans the selected skills as they were at that commit, which gives the
earlier result to compare against.

The scanner is fetched with uvx at a pinned commit and its dependencies are resolved
no newer than the cooldown, so nothing is installed globally.

SKILLSPECTOR_REF (env) overrides the pinned commit. MIN_AGE_DAYS (env, default 5)
is the cooldown for the scanner's own dependencies.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SKILLS_DIR = REPO_ROOT / ".claude" / "skills"

# v2.13.4, pinned by commit because a tag can be moved.
SKILLSPECTOR_REF = os.environ.get("SKILLSPECTOR_REF", "54824463814a0be01360792523ec7245a69190fc")
SKILLSPECTOR_URL = "git+https://github.com/NVIDIA/SkillSpector.git"
# The scanner's recursive mode stops after this many skills.
BATCH_SIZE = 32
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
MAX_LISTED = 200


def scanner_command() -> list[str]:
    days = int(os.environ.get("MIN_AGE_DAYS", "5"))
    cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    return [
        "uvx",
        "--exclude-newer",
        cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "--from",
        f"{SKILLSPECTOR_URL}@{SKILLSPECTOR_REF}",
        "skillspector",
    ]


def changed_skills(skills_dir: Path, ref: str) -> list[str]:
    """Skills with a tracked change since *ref* or an untracked file, by directory name."""
    rel = skills_dir.relative_to(REPO_ROOT).as_posix()
    tracked = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "diff", "--name-only", ref, "--", rel], capture_output=True, text=True, check=True
    ).stdout
    untracked = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "--others", "--exclude-standard", "--", rel],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    names = set()
    for line in (tracked + untracked).splitlines():
        parts = Path(line).relative_to(rel).parts
        if len(parts) > 1 and (skills_dir / parts[0] / "SKILL.md").is_file():
            names.add(parts[0])
    return sorted(names)


def export_at(ref: str, skills_dir: Path, names: list[str], dest: Path) -> list[Path]:
    """Write the named skills as they were at *ref* under *dest*; skills absent there are skipped."""
    rel = skills_dir.relative_to(REPO_ROOT).as_posix()
    present = []
    for name in names:
        exists = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "cat-file", "-e", f"{ref}:{rel}/{name}/SKILL.md"], capture_output=True
        )
        if exists.returncode == 0:
            present.append(name)
    if not present:
        return []
    archive = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "archive", ref, *[f"{rel}/{name}" for name in present]],
        capture_output=True,
        check=True,
    )
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive.stdout, check=True)
    return [dest / rel / name for name in present]


def scan_batch(batch: list[Path], workdir: Path, index: int) -> dict:
    stage = workdir / f"batch-{index:03d}"
    stage.mkdir()
    for skill in batch:
        shutil.copytree(skill, stage / skill.name, symlinks=True)
    report = workdir / f"report-{index:03d}.json"
    proc = subprocess.run(
        [
            *scanner_command(),
            "scan",
            str(stage),
            "--recursive",
            "--no-llm",
            "--format",
            "json",
            "--output",
            str(report),
        ],
        capture_output=True,
        text=True,
    )
    if not report.is_file():
        raise RuntimeError(f"scanner produced no report for batch {index}: {proc.stderr.strip()[-400:]}")
    return json.loads(report.read_text(encoding="utf-8"))


def collect(report: dict) -> tuple[list[dict], list[str], list[str]]:
    """Return the findings, the skills with incomplete analysis, and every skill name the report lists."""
    findings, incomplete, reported = [], [], []
    for skill in report.get("skills", []) if report.get("multi_skill") else [report]:
        name = skill.get("name")
        if not name:
            incomplete.append("(unnamed report entry)")
            reported.append("")
            continue
        reported.append(name)
        if not (skill.get("analysis_completeness") or {}).get("is_complete", True):
            incomplete.append(name)
        for issue in skill.get("issues", []):
            location = issue.get("location") or {}
            evidence = issue.get("code_snippet") or issue.get("finding") or issue.get("explanation") or ""
            findings.append(
                {
                    "skill": name,
                    "rule": issue.get("id", "?"),
                    "severity": issue.get("severity", "?"),
                    "category": issue.get("category", ""),
                    "file": location.get("file", ""),
                    "line": location.get("start_line"),
                    "digest": hashlib.sha256(str(evidence).encode()).hexdigest()[:16],
                    "excerpt": " ".join(str(evidence).replace("`", "'").split())[:160],
                }
            )
    return findings, incomplete, reported


def run_scan(skills: list[Path], jobs: int) -> dict:
    batches = [skills[i : i + BATCH_SIZE] for i in range(0, len(skills), BATCH_SIZE)]
    findings: list[dict] = []
    incomplete: list[str] = []
    scanned = 0
    with tempfile.TemporaryDirectory() as scratch:
        workdir = Path(scratch)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            futures = [pool.submit(scan_batch, batch, workdir, i) for i, batch in enumerate(batches)]
            for batch, future in zip(batches, futures):
                batch_findings, batch_incomplete, reported = collect(future.result())
                expected = Counter(skill.name for skill in batch)
                actual = Counter(reported)
                if actual != expected:
                    absent = list((expected - actual).elements())
                    extra = list((actual - expected).elements())
                    raise RuntimeError(
                        f"scanner reported {len(reported)} of {len(batch)} skills in a batch; "
                        f"not found by directory name: {' '.join(absent[:20]) or '(none)'}; "
                        f"unexpected or repeated: {' '.join(extra[:20]) or '(none)'}"
                    )
                findings.extend(batch_findings)
                incomplete.extend(batch_incomplete)
                scanned += len(reported)
    return {
        "scanner": f"SkillSpector {SKILLSPECTOR_REF}",
        "skills": scanned,
        "incomplete": sorted(incomplete),
        "findings": sorted(findings, key=lambda f: (f["skill"], f["rule"], f["file"], f["digest"])),
    }


def severity_counts(findings: list[dict]) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    ordered = sorted(counts.items(), key=lambda item: SEVERITY_ORDER.get(item[0], 9))
    return ", ".join(f"{count} {severity}" for severity, count in ordered) or "none"


def compare(old: dict, new: dict) -> int:
    def key(finding: dict) -> tuple:
        return (finding["skill"], finding["rule"], finding["file"], finding["digest"])

    known = {key(f) for f in old["findings"]}
    added = [f for f in new["findings"] if key(f) not in known]
    added.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["skill"], f["rule"]))
    print(f"{new['scanner']}: {new['skills']} skills scanned, {severity_counts(new['findings'])}")
    print(f"New since the earlier scan: {severity_counts(added)}")
    newly_incomplete = sorted(set(new.get("incomplete", [])) - set(old.get("incomplete", [])))
    if newly_incomplete:
        print(f"Incomplete analysis only in the newer scan: {' '.join(newly_incomplete[:20])}")
    for finding in added[:MAX_LISTED]:
        where = f"{finding['skill']}/{finding['file']}" + (f":{finding['line']}" if finding["line"] else "")
        print(f"- {finding['severity']} {finding['rule']} ({finding['category']}) {where}: {finding['excerpt']}")
    if len(added) > MAX_LISTED:
        print(f"- ... and {len(added) - MAX_LISTED} more")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("skills", nargs="*", metavar="SKILL", help="skill directory names (default: all)")
    parser.add_argument("--skills-dir", type=Path, default=DEFAULT_SKILLS_DIR)
    parser.add_argument("--changed-since", metavar="REF", help="scan only skills changed since this git ref")
    parser.add_argument("--at", metavar="REF", help="scan the selected skills as they were at this git ref")
    parser.add_argument("--output", type=Path, help="write the result as JSON")
    parser.add_argument("--jobs", type=int, default=4, help="scanner processes to run at once")
    parser.add_argument(
        "--compare", nargs=2, type=Path, metavar=("OLD", "NEW"), help="list findings NEW has and OLD lacks"
    )
    args = parser.parse_args(argv)

    if args.compare:
        old, new = (json.loads(path.read_text(encoding="utf-8")) for path in args.compare)
        return compare(old, new)

    if args.changed_since:
        names = changed_skills(args.skills_dir, args.changed_since)
    else:
        names = args.skills or sorted(p.parent.name for p in args.skills_dir.glob("*/SKILL.md"))
    missing = [] if args.at else [name for name in names if not (args.skills_dir / name / "SKILL.md").is_file()]
    if missing:
        print(f"error: not a skill: {', '.join(missing)}", file=sys.stderr)
        return 2
    try:
        if args.at:
            with tempfile.TemporaryDirectory() as earlier:
                result = run_scan(export_at(args.at, args.skills_dir, names, Path(earlier)), args.jobs)
        else:
            result = run_scan([args.skills_dir / name for name in names], args.jobs)
    except (RuntimeError, OSError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        args.output.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    print(f"{result['scanner']}: {result['skills']} skills scanned, {severity_counts(result['findings'])}")
    if result["incomplete"]:
        print(f"incomplete analysis for {len(result['incomplete'])} skills: {' '.join(result['incomplete'][:20])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
