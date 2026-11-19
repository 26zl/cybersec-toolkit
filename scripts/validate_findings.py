#!/usr/bin/env python3
"""Check a findings file against the rules in docs/FINDINGS.md.

A finding is only as good as the evidence someone else can check. The rules here
keep three things apart that an agent run tends to blur: what was observed, what
the target says about itself, and what a second look confirmed. A string in flag
format, a hint in a README or a banner are claims until a test stands behind them.

Usage: validate_findings.py [--markdown] FILE

FILE is a JSON array of findings, or JSON Lines with one finding per line.
--markdown prints the findings as a table for a writeup when the file is valid.

Offline and stdlib-only.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

KINDS = {"vulnerability", "flag_candidate", "observation"}
STATUSES = {"observed", "claimed", "confirmed", "rejected"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
# Where a piece of evidence came from. "target_claim" is something the target says
# about itself: a hint, a comment, a banner, an error message, text in a file.
SOURCES = {"run_tool", "run_pipeline", "run_script", "manual", "target_claim"}
SHA256 = re.compile(r"[0-9a-f]{64}")
FINDING_KEYS = {
    "id",
    "title",
    "kind",
    "status",
    "severity",
    "target",
    "evidence",
    "derivation",
    "uncertainty",
    "confirmed_by",
}
EVIDENCE_KEYS = {"source", "tool", "tool_version", "command", "captured_at", "locator", "excerpt", "sha256", "audit"}


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _check_evidence(where: str, item: object) -> list[str]:
    if not isinstance(item, dict):
        return [f"{where}: must be an object"]
    problems = [f"{where}: unknown key '{key}'" for key in sorted(set(item) - EVIDENCE_KEYS)]
    if not isinstance(item.get("source"), str) or item["source"] not in SOURCES:
        problems.append(f"{where}: 'source' must be one of {', '.join(sorted(SOURCES))}")
    if not _timestamp(item.get("captured_at")):
        problems.append(f"{where}: 'captured_at' must be an ISO 8601 time with a zone")
    if not _text(item.get("locator")):
        problems.append(f"{where}: 'locator' must say where in the output or file this is (offset, line, URL)")
    if not _text(item.get("excerpt")) and not item.get("sha256"):
        problems.append(f"{where}: needs an 'excerpt', the 'sha256' of the raw data, or both")
    if "sha256" in item and not (isinstance(item["sha256"], str) and SHA256.fullmatch(item["sha256"])):
        problems.append(f"{where}: 'sha256' must be 64 lower-case hex digits")
    if item.get("source") in ("run_tool", "run_pipeline", "run_script") and not _text(item.get("command")):
        problems.append(f"{where}: evidence from a tool needs the 'command' that produced it")
    return problems


def check_finding(index: int, finding: object) -> list[str]:
    """Return the problems of one finding; an empty list means it holds."""
    where = f"finding {index + 1}"
    if not isinstance(finding, dict):
        return [f"{where}: must be an object"]
    if _text(finding.get("id")):
        where = f"{finding['id']}"
    problems = [f"{where}: unknown key '{key}'" for key in sorted(set(finding) - FINDING_KEYS)]

    for key in ("id", "title", "target"):
        if not _text(finding.get(key)):
            problems.append(f"{where}: '{key}' is required")
    kind, status = finding.get("kind"), finding.get("status")
    if not isinstance(kind, str) or kind not in KINDS:
        problems.append(f"{where}: 'kind' must be one of {', '.join(sorted(KINDS))}")
    if not isinstance(status, str) or status not in STATUSES:
        problems.append(f"{where}: 'status' must be one of {', '.join(sorted(STATUSES))}")
    severity = finding.get("severity")
    if "severity" in finding and (not isinstance(severity, str) or severity not in SEVERITIES):
        problems.append(f"{where}: 'severity' must be one of {', '.join(sorted(SEVERITIES))}")

    kind = kind if isinstance(kind, str) else ""
    status = status if isinstance(status, str) else ""

    evidence = finding.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        problems.append(f"{where}: needs at least one 'evidence' item")
        evidence = []
    for number, item in enumerate(evidence, 1):
        problems.extend(_check_evidence(f"{where} evidence {number}", item))
    sources = {item["source"] for item in evidence if isinstance(item, dict) and isinstance(item.get("source"), str)}

    # What the target says about itself is a lead. It becomes an observation when a test shows it.
    if sources and sources <= {"target_claim"} and status in {"observed", "confirmed"}:
        problems.append(f"{where}: every evidence item is a target claim, so the status can only be 'claimed'")
    if status == "claimed" and "target_claim" not in sources and sources:
        problems.append(
            f"{where}: status 'claimed' needs the evidence item that holds the claim (source 'target_claim')"
        )

    if status == "confirmed":
        if not _text(finding.get("derivation")):
            problems.append(f"{where}: a confirmed finding needs a 'derivation' from the evidence to the conclusion")
        if not _text(finding.get("confirmed_by")):
            problems.append(f"{where}: a confirmed finding needs 'confirmed_by': the second, independent check")
        if not any(isinstance(item, dict) and item.get("sha256") for item in evidence):
            problems.append(f"{where}: a confirmed finding needs one evidence item with the 'sha256' of its raw data")
    if kind == "flag_candidate" and status != "rejected" and not _text(finding.get("derivation")):
        problems.append(
            f"{where}: a flag candidate needs a 'derivation' (which step of the challenge yields it); "
            "the flag format alone shows nothing"
        )
    if kind == "vulnerability" and status == "confirmed" and "severity" not in finding:
        problems.append(f"{where}: a confirmed vulnerability needs a 'severity'")
    if status in {"observed", "claimed"} and not _text(finding.get("uncertainty")):
        problems.append(f"{where}: an unconfirmed finding needs 'uncertainty': what has not been checked yet")
    return problems


def load(path: Path) -> list[object]:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return data if isinstance(data, list) else [data]


def check_file(path: Path) -> tuple[list[object], list[str]]:
    try:
        findings = load(path)
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"{path}: cannot be read as JSON or JSON Lines ({exc})"]
    if not findings:
        return [], [f"{path}: holds no findings"]
    problems: list[str] = []
    seen: set[str] = set()
    for index, finding in enumerate(findings):
        problems.extend(check_finding(index, finding))
        ident = finding.get("id") if isinstance(finding, dict) else None
        if isinstance(ident, str):
            if ident in seen:
                problems.append(f"{ident}: this id is used more than once")
            seen.add(ident)
    return findings, problems


def _cell(value: object) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()


def markdown(findings: list[object]) -> str:
    rows = [
        "| ID | Status | Kind | Severity | Title | Target | Evidence |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        count = len(finding.get("evidence") or [])
        cells = [finding.get(key) for key in ("id", "status", "kind", "severity", "title", "target")]
        rows.append("| " + " | ".join(_cell(cell) for cell in [*cells, f"{count} item(s)"]) + " |")
    return "\n".join(rows)


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _cli import check_args

    usage = "usage: validate_findings.py [--markdown] FILE"
    args = check_args({"--markdown"}, usage, positional=True)
    files = [arg for arg in args if not arg.startswith("-")]
    if len(files) != 1:
        print(usage, file=sys.stderr)
        return 2

    findings, problems = check_file(Path(files[0]))
    if problems:
        print(f"Findings: {len(problems)} problem(s) in {files[0]}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    if "--markdown" in args:
        print(markdown(findings))
    else:
        by_status: dict[str, int] = {}
        for finding in findings:
            by_status[finding["status"]] = by_status.get(finding["status"], 0) + 1
        summary = ", ".join(f"{count} {status}" for status, count in sorted(by_status.items())) or "none"
        print(f"Findings: OK ({len(findings)} finding(s): {summary}) — {files[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
