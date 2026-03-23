#!/usr/bin/env python3
"""Validate lib/distro_compat.tsv — distro package name mappings.

Checks:
  - Column count: every data line has exactly 5 tab-separated fields
  - No duplicate Debian package names
  - Valid cell values: empty, '-', or package name token(s) [a-zA-Z0-9._@-]
    joined by '+' when a mapping expands to multiple packages

Usage:
    python3 scripts/validate_distro_compat.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TSV_PATH = ROOT / "lib" / "distro_compat.tsv"

PACKAGE_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "._@-"
)

COLUMNS = ("debian", "dnf", "pacman", "zypper", "pkg")


def _is_valid_package_token(token: str) -> bool:
    """Return True when token only contains allowed package-name characters."""
    return bool(token) and all(char in PACKAGE_TOKEN_CHARS for char in token)


def _is_valid_cell(value: str) -> bool:
    """Validate a TSV cell.

    '+' is reserved as the multi-package separator in distro_compat.tsv.
    """
    if value == "-":
        return True

    return all(_is_valid_package_token(token) for token in value.split("+"))


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
            if not _is_valid_cell(value):
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
