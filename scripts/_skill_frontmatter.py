"""Minimal YAML-frontmatter reader shared by the skill validator and curator.

Parses the leading ``---``-delimited block of a SKILL.md into a flat
``{key: value}`` dict, handling ``>``/``|`` block scalars and scalars that
continue on following lines. Returns ``None`` when no frontmatter block is
present so callers can tell "absent" from "empty".
"""

from __future__ import annotations

import json
import re


def _scalar(lines: list[str], index: int, value: str) -> tuple[str, int]:
    """Read a plain or quoted scalar that may continue past its key line."""
    parts = [value]
    quote = value[:1] if value[:1] in {"'", '"'} else ""
    if quote and not (len(value) > 1 and value.endswith(quote)):
        # A quoted scalar runs to the line that closes the quote, blank lines included.
        while index < len(lines):
            part = lines[index].strip()
            parts.append(part)
            index += 1
            if part.endswith(quote):
                break
    elif value:
        # A plain scalar continues on indented lines.
        while index < len(lines) and lines[index].startswith((" ", "\t")) and lines[index].strip():
            parts.append(lines[index].strip())
            index += 1
    text = " ".join(part for part in parts if part)
    if quote and len(text) > 1 and text.endswith(quote):
        inner = text[1:-1].strip()
        if quote == "'":
            return inner.replace("''", "'"), index
        try:
            return json.loads(f'"{inner}"'), index
        except ValueError:
            return inner, index
    return text, index


def frontmatter(text: str) -> dict[str, str] | None:
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not match:
        return None

    fields: dict[str, str] = {}
    lines = match.group(1).splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if ":" not in line:
            index += 1
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value in {">", ">-", "|", "|-"}:
            block: list[str] = []
            index += 1
            while index < len(lines):
                block_line = lines[index]
                if block_line.startswith((" ", "\t")) or not block_line.strip():
                    block.append(block_line.strip())
                    index += 1
                    continue
                break
            if value.startswith(">"):
                fields[key] = " ".join(part for part in block if part)
            else:
                fields[key] = "\n".join(block).strip()
            continue
        fields[key], index = _scalar(lines, index + 1, value)
    return fields
