"""Text rules shared by the skill validator and the re-vendor tool."""

from __future__ import annotations

import re

# Characters a reader cannot see, or that make a terminal or an editor show something
# other than the text. An agent reads a skill as instructions, so an example of these
# techniques is written as a visible <U+XXXX> escape instead.
#
# The class holds every code point Unicode marks Default_Ignorable: the soft hyphen,
# the grapheme joiner, the Hangul fillers (blank, yet valid in an identifier), the
# zero-width and bidi controls, the variation selectors, and the tag block, which
# decodes to ASCII. It adds the line and paragraph separators, the interlinear
# annotation marks, and the control characters other than tab, form feed and a line
# ending, which let a terminal overwrite or conceal what came before.
_HIDDEN = (
    r"\x00-\x08\x0b\x0e-\x1f\x7f-\x9f"
    r"\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b\u200e\u200f\u2028-\u202e\u2060-\u206f"
    r"\u3164\ufe00-\ufe0d\ufeff\uffa0\ufff0-\ufffb"
    r"\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff"
)
# A joiner or an emoji selector is ordinary text in two places: beside the pictograph
# it shapes, and inside a script that joins its letters (Arabic, the Indic scripts,
# Myanmar, Khmer, Mongolian). Anywhere else it is as hidden as the rest, and a run of
# them spells bytes. Neither class holds a hidden code point, so escaping one never
# changes the verdict on its neighbour.
_PICTOGRAPH = (
    r"\u00a9\u00ae\u203c\u2049\u2122\u2139\u2190-\u21ff\u2300-\u23ff\u2460-\u24ff\u25a0-\u27bf"
    r"\u2900-\u297f\u2b00-\u2bff\u3030\u303d\u3297\u3299\U0001f000-\U0001faff"
)
_JOINED = _PICTOGRAPH + (
    r"\u0600-\u061b\u061d-\u08ff\u0900-\u0dff\u1000-\u109f\u1780-\u17b3\u17b6-\u17ff\u1800-\u180a\u1810-\u18af"
    r"\ua8e0-\ua8ff\ufb50-\ufdff\ufe70-\ufefc"
)
_KEYCAP = "0-9#*"  # with U+FE0F U+20E3 these form the keycap emoji
_SELECTOR = r"[\ufe0e\ufe0f]"
_JOINER = r"[\u200c\u200d]"
INVISIBLE_CHARACTERS = re.compile(
    rf"(?:[{_HIDDEN}]|\r(?!\n)"
    rf"|(?<![{_PICTOGRAPH}{_KEYCAP}]){_SELECTOR}|(?<=[{_KEYCAP}]){_SELECTOR}(?!\u20e3)"
    rf"|(?<![{_JOINED}])(?<![{_PICTOGRAPH}]\ufe0f){_JOINER}|{_JOINER}(?![{_JOINED}]))+"
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


# Data formats a skill may carry without these rules reading them. A file counts as
# one only when its name and its first bytes both say so. Everything else is text,
# where a NUL byte is one more hidden character instead of a way past the rules.
_BINARY_SIGNATURES = {
    ".png": (b"\x89PNG\x0d\x0a\x1a\x0a",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".webp": (b"RIFF",),
    ".pdf": (b"%PDF-",),
    ".pcap": (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"),
    ".pcapng": (b"\x0a\x0d\x0d\x0a",),
}


def is_binary(name: str, data: bytes) -> bool:
    """True for an image, a PDF or a packet capture: named as one and starting with its signature."""
    return any(name.lower().endswith(suffix) and data.startswith(magic) for suffix, magic in _BINARY_SIGNATURES.items())


# Layout that keeps text out of a reviewer's view while an agent still reads it: text
# pushed past the right edge by blank characters, a line too long to read, and text
# that resumes after a screenful of blank lines. Markdown gets the wider blank run
# because its diagrams indent that far. Each limit sits well clear of what the
# vendored skills use.
MAX_LINE_CHARS = 2000
MAX_BLANK_RUN = 80
MAX_BLANK_RUN_MARKDOWN = 200
MAX_BLANK_LINES = 20
MARKDOWN_SUFFIXES = (".md", ".markdown")

# Space, tab, the Unicode spaces and the Braille blank: none of them draws anything.
_BLANK = r" \t\u00a0\u1680\u2000-\u200a\u202f\u205f\u2800\u3000"
_BLANK_LINE = re.compile(rf"[{_BLANK}]*\r?")
_BLANK_RUNS = {
    markdown: re.compile(rf"[{_BLANK}]{{{limit},}}(?=[^{_BLANK}\r])")
    for markdown, limit in ((False, MAX_BLANK_RUN), (True, MAX_BLANK_RUN_MARKDOWN))
}
# An SVG outline is one long run of coordinates, so a line of an .svg file is measured
# without them. Only path geometry is left out: prose or script on the line still counts.
_SVG_GEOMETRY = re.compile(r"""(\b(?:d|points)\s*=\s*)(["'])[0-9eE.,\s+\-MmLlHhVvCcSsQqTtAaZz]*\2""")


def find_concealed(text: str, name: str = "") -> tuple[int, str] | None:
    """Return the line number and a description of the first place where layout keeps text out of view.

    *name* is the file's name: Markdown gets the wider blank run, an SVG is measured without its geometry.
    """
    markdown = name.lower().endswith(MARKDOWN_SUFFIXES)
    vector = name.lower().endswith(".svg")
    blank_lines = 0
    for number, line in enumerate(text.split("\n"), 1):
        if _BLANK_LINE.fullmatch(line):
            blank_lines += 1
            continue
        if blank_lines >= MAX_BLANK_LINES:
            return number, f"text resumes after {blank_lines} blank lines; {MAX_BLANK_LINES} or more hide it"
        blank_lines = 0
        length = len(_SVG_GEOMETRY.sub(r"\1\2\2", line)) if vector else len(line)
        if length > MAX_LINE_CHARS:
            return number, f"line is {length} characters long; the limit is {MAX_LINE_CHARS}"
        run = _BLANK_RUNS[markdown].search(line)
        if run:
            limit = MAX_BLANK_RUN_MARKDOWN if markdown else MAX_BLANK_RUN
            return number, f"text follows {len(run.group())} blank characters; {limit} or more push it off screen"
    return None


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
