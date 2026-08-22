#!/usr/bin/env python3
"""Bump the project version across every release surface in one step.

Usage: python3 scripts/bump_version.py X.Y.Z

Surfaces kept in sync (enforced by scripts/validate_version.sh):
VERSION, mcp_server/pyproject.toml, .claude-plugin/plugin.json,
.claude-plugin/marketplace.json, CITATION.cff, and server.json
(top version, package version, and the OCI image tag).
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
ANY = r"\d+\.\d+\.\d+"


def sub(rel: str, pattern: str, repl: str, count: int = 0) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, repl, text, count=count)
    if n == 0:
        raise SystemExit(f"error: no version string matched in {rel}")
    path.write_text(new, encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2 or not SEMVER.match(sys.argv[1]):
        raise SystemExit("usage: python3 scripts/bump_version.py X.Y.Z")
    v = sys.argv[1]
    (ROOT / "VERSION").write_text(v + "\n", encoding="utf-8")
    sub("mcp_server/pyproject.toml", r'(?m)^(version\s*=\s*)"' + ANY + '"', r'\g<1>"' + v + '"', count=1)
    sub(".claude-plugin/plugin.json", r'("version":\s*)"' + ANY + '"', r'\g<1>"' + v + '"', count=1)
    sub(".claude-plugin/marketplace.json", r'("version":\s*)"' + ANY + '"', r'\g<1>"' + v + '"', count=1)
    sub("CITATION.cff", r'(?m)^(version:\s*)"' + ANY + '"', r'\g<1>"' + v + '"', count=1)
    sub("server.json", r'("version":\s*)"' + ANY + '"', r'\g<1>"' + v + '"')
    sub("server.json", r"(cybersec-toolkit:)" + ANY, r"\g<1>" + v)
    print(f"bumped all release surfaces to {v}")


if __name__ == "__main__":
    main()
