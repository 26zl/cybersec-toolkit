#!/usr/bin/env python3
"""Bump the project version across every release surface in one step.

Usage: python3 scripts/bump_version.py X.Y.Z
Prefer ``make bump VERSION=X.Y.Z``: it also runs ``uv lock``, without which
mcp_server/uv.lock keeps the old project version and ``uv sync --locked`` fails.

Surfaces kept in sync (enforced by scripts/validate_version.sh):
VERSION, mcp_server/pyproject.toml, .claude-plugin/plugin.json,
.claude-plugin/marketplace.json, CITATION.cff, server.json
(top-level version and the OCI image tag), and the release
tag in README.md's install command.
"""

import os
import re
import sys
from pathlib import Path

# BUMP_VERSION_ROOT points the bump (and scripts/validate_version.sh) at another tree, for tests.
ROOT = Path(os.environ.get("BUMP_VERSION_ROOT") or Path(__file__).resolve().parent.parent)
SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
ANY = r"[0-9]+\.[0-9]+\.[0-9]+"


def sub(pending: dict[str, str], rel: str, pattern: str, repl: str, count: int = 0) -> None:
    """Apply a substitution to the pending text of *rel*; nothing is written here."""
    if rel not in pending:
        pending[rel] = (ROOT / rel).read_text(encoding="utf-8")
    new, n = re.subn(pattern, repl, pending[rel], count=count)
    if n == 0:
        raise SystemExit(f"error: no version string matched in {rel}")
    pending[rel] = new


def main() -> None:
    if len(sys.argv) != 2 or not SEMVER.fullmatch(sys.argv[1]):
        raise SystemExit("usage: python3 scripts/bump_version.py X.Y.Z")
    v = sys.argv[1]
    pending: dict[str, str] = {}
    sub(pending, "mcp_server/pyproject.toml", r'(?m)^(version\s*=\s*)"' + ANY + '"', r'\g<1>"' + v + '"', count=1)
    sub(pending, ".claude-plugin/plugin.json", r'("version":\s*)"' + ANY + '"', r'\g<1>"' + v + '"', count=1)
    sub(pending, ".claude-plugin/marketplace.json", r'("version":\s*)"' + ANY + '"', r'\g<1>"' + v + '"', count=1)
    sub(pending, "CITATION.cff", r'(?m)^(version:\s*)"' + ANY + '"', r'\g<1>"' + v + '"', count=1)
    sub(pending, "server.json", r'("version":\s*)"' + ANY + '"', r'\g<1>"' + v + '"')
    sub(pending, "server.json", r"(cybersec-toolkit:)" + ANY, r"\g<1>" + v)
    sub(pending, "README.md", r"(--branch v)" + ANY, r"\g<1>" + v)
    pending["VERSION"] = v + "\n"
    for rel, text in pending.items():
        (ROOT / rel).write_text(text, encoding="utf-8")
    print(f"bumped all release surfaces to {v}")


if __name__ == "__main__":
    main()
