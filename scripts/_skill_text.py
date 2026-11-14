"""Text rules shared by the skill validator and the re-vendor tool."""

from __future__ import annotations

import re

# Characters that carry or reorder text a reader cannot see: Unicode tag characters
# decode to ASCII, zero-width spaces hide inside words, and bidi controls change the
# displayed order. An agent reads a skill as instructions, so an example of these
# techniques is written as a visible <U+XXXX> escape instead. The joiners U+200C and
# U+200D stay allowed: emoji and several scripts need them.
INVISIBLE_CHARACTERS = re.compile("[\U000e0000-\U000e007f‪-‮⁦-⁩​⁠-⁤﻿]+")


def find_invisible(text: str) -> re.Match[str] | None:
    """Return the first run of invisible characters, ignoring a leading byte-order mark."""
    return INVISIBLE_CHARACTERS.search(text, 1 if text.startswith("﻿") else 0)


def show_invisible(text: str) -> str:
    """Replace each run of invisible characters with a visible ``<U+XXXX ...>`` escape."""
    start = 1 if text.startswith("﻿") else 0
    visible = INVISIBLE_CHARACTERS.sub(
        lambda run: "<" + " ".join(f"U+{ord(char):04X}" for char in run.group()) + ">", text[start:]
    )
    return text[:start] + visible


FRONTMATTER_FENCE = re.compile(r"(?m)^---[ \t]*\r?$")
FRONTMATTER_KEY = re.compile(r"([A-Za-z0-9_-]+):(\s|$)")

# Claude Code reads this frontmatter key as a grant: while the skill is active, the
# tools it names run without a permission prompt. A lookup inside the workspace is
# harmless; a shell, a file write or a fetch is not for skill text to approve for itself.
TOOL_GRANT_KEY = "allowed-tools"
PROMPT_FREE_TOOLS = frozenset({"Read", "Grep", "Glob"})


def _grant_span(text: str) -> tuple[int, int] | None:
    """Offsets of the tool-grant block, continuation lines included, or None."""
    fences = list(FRONTMATTER_FENCE.finditer(text))
    if not text.startswith("---") or len(fences) < 2 or fences[0].start() != 0:
        return None
    offset = fences[0].end() + 1
    start = None
    for line in text[offset : fences[1].start()].splitlines(keepends=True):
        key = FRONTMATTER_KEY.match(line)
        if key and start is not None:
            break
        if key and key.group(1) == TOOL_GRANT_KEY:
            start = offset
        offset += len(line)
    return None if start is None else (start, offset)


def granted_tools(text: str) -> list[str] | None:
    """The tools a document's frontmatter pre-approves; None when it has no grant."""
    span = _grant_span(text)
    if span is None:
        return None
    value = text[span[0] : span[1]].split(":", 1)[1]
    return re.findall(r"[A-Za-z_][\w-]*(?:\([^)]*\))?", value)


def drop_tool_grant(text: str) -> str:
    """Remove the tool grant from a document's frontmatter."""
    span = _grant_span(text)
    return text if span is None else text[: span[0]] + text[span[1] :]
