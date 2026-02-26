#!/usr/bin/env python3
"""Validate lib/distro_compat.tsv — distro package name mappings.

Checks:
  - Column count: every data line has exactly 5 tab-separated fields
  - No duplicate Debian package names
  - Valid cell values: empty, '-', or package-name characters [a-zA-Z0-9._@+-]

Usage:
    python3 scripts/validate_distro_compat.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TSV_PATH = ROOT / "lib" / "distro_compat.tsv"

# Valid cell: empty, single dash (skip), or package name(s) joined by +
CELL_RE = re.compile(r'^(-|[a-zA-Z0-9._@+-]+(\+[a-zA-Z0-9._@+-]+)*)$')

COLUMNS = ("debian", "dnf", "pacman", "zypper", "pkg")


def validate():
    """Validate distro_compat.tsv. Return exit code."""
    errors = 0
    warnings = 0

    if not TSV_PATH.exists():
        print(f"ERROR: {TSV_PATH} not found")
        return 1

    # Parse TSV
    entries = {}  # debian_name -> {dnf, pacman, zypper, pkg}
    line_count = 0

    for lineno, raw_line in enumerate(
        TSV_PATH.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw_line.rstrip("\r")
        if not line or line.startswith("#"):
            continue
        line_count += 1

        fields = line.split("\t")
        if len(fields) != 5:
            print(
                f"ERROR: line {lineno}: expected 5 tab-separated fields, "
                f"got {len(fields)}: {line!r}"
            )
            errors += 1
            continue

        debian = fields[0]

        # Duplicate check
        if debian in entries:
            print(f"ERROR: line {lineno}: duplicate Debian name '{debian}'")
            errors += 1
            continue

        # Validate each cell value
        for col_idx, value in enumerate(fields):
            if not value:
                continue  # empty = passthrough
            if not CELL_RE.match(value):
                print(
                    f"ERROR: line {lineno}: invalid value in column "
                    f"'{COLUMNS[col_idx]}': {value!r}"
                )
                errors += 1

        entries[debian] = {
            "dnf": fields[1],
            "pacman": fields[2],
            "zypper": fields[3],
            "pkg": fields[4],
        }

    # Summary
    print(f"\ndistro_compat.tsv: {line_count} entries")
    print(f"Errors: {errors}  Warnings: {warnings}")

    return 1 if errors > 0 else 0


def main():
    sys.exit(validate())


if __name__ == "__main__":
    main()
