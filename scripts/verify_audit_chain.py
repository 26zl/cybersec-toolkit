#!/usr/bin/env python3
"""Verify the hash chain in a cybersec-toolkit MCP audit log.

Every record carries its chain id, a sequence number, and the SHA256 of the
previous record in that chain, so editing or dropping a record breaks the link
from that point on. Chains are per process, because several sessions may append
to one log.

Two limits are inherent to a plain chain and worth stating: the first record of
a chain seen in a file only anchors it (its predecessor may live in a rotated
file), and truncating a chain's tail is not detectable.

Offline and stdlib-only. Run by ``make audit-verify``.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

# Must stay identical to mcp_server.audit.chain_link; mcp_server/tests asserts it.
CHAIN_GENESIS = "0" * 64


def chain_link(previous: str, line: str) -> str:
    """Return the chain value a record's serialized line hands to the next one."""
    return hashlib.sha256(f"{previous}{line}".encode()).hexdigest()


def default_audit_path() -> Path:
    configured = os.environ.get("CYBERSEC_MCP_AUDIT_LOG", "").strip()
    if configured:
        return Path(configured).expanduser()
    state_home = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return base / "cybersec-tools-mcp" / "audit.log"


def verify(lines: list[str]) -> tuple[list[str], dict[str, int]]:
    """Check every chain in a log. Returns (problems, stats)."""
    problems: list[str] = []
    stats = {"records": 0, "chains": 0, "unchained": 0, "anchors": 0}
    expected: dict[str, str] = {}
    last_seq: dict[str, int] = {}

    for number, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"line {number}: not valid JSON")
            continue

        stats["records"] += 1
        chain = record.get("chain")
        prev = record.get("prev")
        seq = record.get("seq")
        if not isinstance(chain, str) or not isinstance(prev, str) or not isinstance(seq, int):
            stats["unchained"] += 1
            continue

        if chain not in expected:
            stats["chains"] += 1
            if prev != CHAIN_GENESIS:
                # Its predecessor is in a rotated file; anchor rather than fail.
                stats["anchors"] += 1
        elif prev != expected[chain]:
            problems.append(
                f"line {number}: chain {chain[:8]} seq {seq} expected prev {expected[chain][:16]}…, got {prev[:16]}…"
            )
        elif seq != last_seq[chain] + 1:
            problems.append(f"line {number}: chain {chain[:8]} jumped from seq {last_seq[chain]} to {seq}")

        expected[chain] = chain_link(prev, line)
        last_seq[chain] = seq

    return problems, stats


def selftest() -> int:
    def emit(entries: list[dict]) -> list[str]:
        out, prev = [], CHAIN_GENESIS
        for index, entry in enumerate(entries, 1):
            record = {**entry, "chain": "c" * 32, "seq": index, "prev": prev}
            line = json.dumps(record)
            prev = chain_link(prev, line)
            out.append(line)
        return out

    good = emit([{"event": "server_start"}, {"event": "tool_call", "tool": "guided_assessment"}])
    problems, stats = verify(good)
    assert problems == [], f"selftest: intact chain was flagged: {problems}"
    assert stats["records"] == 2 and stats["chains"] == 1, f"selftest: bad stats {stats}"

    edited = list(good)
    edited[0] = edited[0].replace("server_start", "server_stop")
    assert verify(edited)[0], "selftest: an edited record was not caught"

    dropped = [good[0], *emit([{"event": "a"}, {"event": "b"}, {"event": "c"}])[2:]]
    assert verify(dropped)[0], "selftest: a dropped record was not caught"

    legacy = [json.dumps({"event": "tool_call"})]
    assert verify(legacy) == ([], {"records": 1, "chains": 0, "unchained": 1, "anchors": 0}), (
        "selftest: pre-chain records must be reported, not flagged"
    )

    print("selftest OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()

    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    path = Path(args[0]).expanduser() if args else default_audit_path()
    if not path.is_file():
        print(f"Audit log not found: {path}", file=sys.stderr)
        return 2

    problems, stats = verify(path.read_text(encoding="utf-8", errors="replace").splitlines())
    summary = (
        f"{stats['records']} records, {stats['chains']} chain(s), "
        f"{stats['anchors']} continued from rotation, {stats['unchained']} without chain fields"
    )
    if problems:
        print(f"Audit chain: BROKEN — {summary}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"Audit chain: OK ({summary}) — {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
