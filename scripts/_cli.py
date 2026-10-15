"""Shared argument check for the repository's hand-parsed scripts.

Rejects unknown options so a typo cannot silently fall back to the default mode.
"""

from __future__ import annotations

import sys


def check_args(allowed: set[str], usage: str, positional: bool = False) -> list[str]:
    """Print usage and exit 0 on -h/--help, exit 2 on an unknown option.

    Returns the arguments. Positional arguments are accepted only when
    ``positional`` is true.
    """
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print(usage)
        sys.exit(0)
    for arg in args:
        if arg.startswith("-") and arg not in allowed:
            print(f"error: unknown option {arg}\n{usage}", file=sys.stderr)
            sys.exit(2)
        if not arg.startswith("-") and not positional:
            print(f"error: unexpected argument {arg}\n{usage}", file=sys.stderr)
            sys.exit(2)
    return args


if __name__ == "__main__":
    # Self-check: unknown options and stray arguments are rejected.
    sys.argv = ["x", "--strict"]
    assert check_args({"--strict"}, "usage") == ["--strict"]
    for bad, pos in ((["x", "--strcit"], False), (["x", "file"], False)):
        sys.argv = bad
        try:
            check_args({"--strict"}, "usage", positional=pos)
        except SystemExit as exc:
            assert exc.code == 2, bad
        else:
            raise AssertionError(bad)
    sys.argv = ["x", "log.txt"]
    assert check_args(set(), "usage", positional=True) == ["log.txt"]
    print("ok")
