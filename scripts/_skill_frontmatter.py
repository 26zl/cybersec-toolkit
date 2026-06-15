"""Minimal YAML-frontmatter reader shared by the skill validator and curator.

Parses the leading ``---``-delimited block of a SKILL.md into a flat
``{key: value}`` dict, handling ``>``/``|`` block scalars. Returns ``None`` when
no frontmatter block is present so callers can tell "absent" from "empty".
"""

from __future__ import annotations

import re


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
        fields[key] = value.strip('"').strip("'")
        index += 1
    return fields
