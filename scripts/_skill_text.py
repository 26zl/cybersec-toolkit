"""Text rules shared by the skill validator and the re-vendor tool."""

from __future__ import annotations

import re

# Characters that carry or reorder text a reader cannot see: Unicode tag characters
# decode to ASCII, zero-width spaces hide inside words, and bidi controls change the
# displayed order. An agent reads a skill as instructions, so an example of these
# techniques is written as a visible <U+XXXX> escape instead. The joiners U+200C and
# U+200D stay allowed: emoji and several scripts need them.
INVISIBLE_CHARACTERS = re.compile(
    "[\U000e0000-\U000e007f\U000e0100-\U000e01ef\u061c\u180b-\u180e\u202a-\u202e\u2060-\u206f\u200b\ufeff]+"
)


def find_invisible(text: str) -> re.Match[str] | None:
    """Return the first run of invisible characters, ignoring a leading byte-order mark."""
    return INVISIBLE_CHARACTERS.search(text, 1 if text.startswith("\ufeff") else 0)


def show_invisible(text: str) -> str:
    """Replace each run of invisible characters with a visible ``<U+XXXX ...>`` escape."""
    start = 1 if text.startswith("\ufeff") else 0
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
UNPARSED_GRANT = "(unparseable allowed-tools)"

# YAML accepts quoted keys, a space before the colon and the underscore spelling; the
# bare-key reader must not be the only way a grant gets noticed.
_GRANT_LINE = re.compile(r"""(['"]?)allowed[-_]tools\1[ \t]*:""")
_GRANT_MENTION = re.compile(r"""(?<![\w-])['"]?allowed[-_]tools['"]?[ \t]*:""")
_EXPLICIT_GRANT_KEY = re.compile(
    r"""(?m)^[ \t]*\?[ \t]+(?:[!&][^ \t]+[ \t]+)*['"]?allowed[-_]tools['"]?[ \t]*(?:#.*)?$"""
)
_QUOTED_TEXT = re.compile(r'"((?:[^"\\]|\\.)*)"', re.DOTALL)
_KEY_ESCAPE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8}))")
_TOP_LEVEL_KEY = re.compile(r"""(?:[^\s#\-'"\[\]{},][^:\n]*|'[^'\n]*'|"[^"\n]*")[ \t]*:(?:\s|$)""")


def _frontmatter_inner(text: str) -> tuple[int, int] | None:
    """Offsets of the frontmatter body, past an optional byte-order mark, or None."""
    base = 1 if text.startswith("\ufeff") else 0
    fences = list(FRONTMATTER_FENCE.finditer(text[base:]))
    if not text.startswith("---", base) or len(fences) < 2 or fences[0].start() != 0:
        return None
    return base + fences[0].end() + 1, base + fences[1].start()


def _grant_spans(text: str) -> list[tuple[int, int]]:
    """Offsets of every tool-grant block, continuation lines included."""
    bounds = _frontmatter_inner(text)
    if bounds is None:
        return []
    offset, end = bounds
    spans: list[tuple[int, int]] = []
    start = None
    for line in text[offset:end].splitlines(keepends=True):
        top_level = _TOP_LEVEL_KEY.match(line) is not None
        if top_level and start is not None:
            spans.append((start, offset))
            start = None
        if _GRANT_LINE.match(line):
            start = offset
        offset += len(line)
    if start is not None:
        spans.append((start, offset))
    return spans


def has_unparsed_grant(text: str) -> bool:
    """True when the frontmatter names allowed-tools in a form the block reader cannot isolate."""
    bounds = _frontmatter_inner(text)
    if bounds is None:
        return False
    body = text[bounds[0] : bounds[1]]

    def visible_key(match: re.Match[str]) -> str:
        def decode_codepoint(escape: re.Match[str]) -> str:
            value = int(next(group for group in escape.groups() if group is not None), 16)
            return chr(value) if value <= 0x10FFFF else escape.group()

        key = re.sub(r"\\\r?\n[ \t]*", "", match.group(1))
        return '"' + _KEY_ESCAPE.sub(decode_codepoint, key) + '"'

    body = _QUOTED_TEXT.sub(visible_key, body)
    mentions = len(_GRANT_MENTION.findall(body)) + len(_EXPLICIT_GRANT_KEY.findall(body))
    # Aliases can supply a mapping key whose literal spelling appears only in an anchor value.
    if re.search(r"allowed[-_]tools", body) and re.search(r"(?m)^[ \t]*(?:\?[ \t]+\*|\*[^ \t:]+[ \t]*:)", body):
        mentions += 1
    return mentions > len(_grant_spans(text))


def granted_tools(text: str) -> list[str] | None:
    """The tools a document's frontmatter pre-approves; None when it has no grant.

    A grant the reader cannot isolate (a flow mapping, a nested key) is reported as
    UNPARSED_GRANT so a caller refuses it instead of treating it as absent.
    """
    spans = _grant_spans(text)
    unparsed = has_unparsed_grant(text)
    if not spans and not unparsed:
        return None
    tools: list[str] = []
    for start, end in spans:
        block = text[start:end]
        value = block[_GRANT_LINE.match(block).end() :]  # type: ignore[union-attr]
        tools.extend(re.findall(r"[A-Za-z_][\w-]*(?:\([^)]*\))?", value))
    if unparsed:
        tools.append(UNPARSED_GRANT)
    return tools


def drop_tool_grant(text: str) -> str:
    """Remove every tool grant block from a document's frontmatter."""
    for start, end in reversed(_grant_spans(text)):
        text = text[:start] + text[end:]
    return text
