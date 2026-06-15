#!/usr/bin/env python3
"""Shared bash-array body scanner for the config validators.

``validate_tools_config.py`` and ``validate_mcp_sync.py`` both need to extract
the body of a ``NAME=( ... )`` array while ignoring a ``)`` that appears inside a
quoted cell or a comment. This is that one paren-balanced, quote-aware scan; the
higher-level per-format parsers stay in each validator because their cell regexes
and source-format assumptions intentionally differ.
"""

from __future__ import annotations


def balanced_array_body(text: str, open_idx: int) -> str | None:
    """Return the body between the parens of an array whose ``(`` is at *open_idx*.

    Scans paren-balanced and quote-aware so a ``)`` inside a quoted cell or
    comment cannot close the array early (which would silently drop later
    entries). Returns ``None`` if the array is never closed.
    """
    depth = 0
    quote: str | None = None
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i]
        i += 1
    return None
