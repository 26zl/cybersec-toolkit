"""Output sanitization — strip prompt-injection patterns from tool output."""

from __future__ import annotations

import re
import unicodedata

# Invisible and bidi format characters, stripped first so they cannot split a keyword,
# reorder text or smuggle ASCII (the tag block) past the checks below.
_ZERO_WIDTH_BIDI_RE = re.compile(
    r"[\u00ad"  # soft hyphen
    r"\u034f"  # combining grapheme joiner
    r"\u180b-\u180e"  # Mongolian variation selectors and vowel separator
    r"\u200b-\u200f"  # ZWSP, ZWNJ, ZWJ, LRM, RLM
    r"\u202a-\u202e"  # LRE, RLE, PDF, LRO, RLO
    r"\u2060-\u2064"  # word joiner + invisible operators
    r"\u2066-\u2069"  # LRI, RLI, FSI, PDI
    r"\u061c"  # Arabic letter mark
    r"\ufe00-\ufe0f"  # variation selectors
    r"\ufeff"  # BOM / zero-width no-break space
    r"\ufff9-\ufffb"  # interlinear annotation controls
    r"\U000e0000-\U000e007f"  # tag characters (invisible ASCII)
    r"\U000e0100-\U000e01ef]"  # variation selectors supplement
)

# Hangul fillers render as blank space, so they become a space rather than vanish.
_FILLER_RE = re.compile(r"[\u115f\u1160\u3164\uffa0]")

# Line breaks other than LF and CRLF; a reader sees a new line, ``^`` does not.
_BARE_LINE_BREAK_RE = re.compile(r"\r(?!\n)|[\x0b\x0c\u2028\u2029]")

# ANSI/VT escape sequences and C1 controls, stripped so a leading sequence cannot hide an
# injection line from the start-anchored prefix checks; negated classes keep matching linear.
_ANSI_RE = re.compile(
    r"\x1b\][^\x07\x1b\x9c\n]*(?:\x07|\x1b\\|\x9c)?"  # OSC ... BEL / ST, else to end of line
    r"|\x1b[P^_X][^\x1b\x9c\n]*(?:\x1b\\|\x9c)?"  # DCS / PM / APC / SOS ... ST, else to end of line
    r"|\x9b[0-?]*[ -/]*[@-~]"  # 8-bit CSI ... final byte
    r"|\x1b\[[0-?]*[ -/]*[@-~]?"  # CSI ... final byte (optional -> also incomplete)
    r"|\x1b[ -/]*[0-~]"  # other nF / simple ESC sequences
    r"|\x1b"  # lone ESC
    r"|[\x80-\x9f]"  # remaining 8-bit C1 controls
)

# Known LLM prompt markers: any <|name|> special token, plus the Llama and Gemma turn markers.
_LLM_MARKERS = re.compile(
    r"<\|[A-Za-z0-9_]{1,40}\|>"
    r"|\[/?INST\]"
    r"|<</?SYS>>"
    r"|</?(?:start|end)_of_turn>",
    re.IGNORECASE,
)

# XML-like tags that attempt to inject system/assistant roles or a tool call. A namespace
# prefix, attributes and trailing whitespace are accepted, since clients parse those forms too.
_XML_INJECTION_RE = re.compile(
    r"</?(?:[A-Za-z][\w.-]{0,30}:)?"
    r"(?:system-reminder|system|assistant|human|tool_call|tool_result|tool_use"
    r"|function_calls|function_call|function_results|function_result|invoke|result)"
    r"(?:\s[^<>\n]{0,200})?\s*/?>",
    re.IGNORECASE,
)

# The strip stages repeat until the text stops changing, so removing an inner match
# cannot assemble a new marker from the characters around it.
_MAX_STRIP_PASSES = 8
_TAG_PLACEHOLDER = "[tag removed]"

# Line-level injection prefixes (case-insensitive, at line start, after optional
# indentation or a quote/list/heading marker).
# Marked with [SANITIZED] so the LLM sees them as neutralized; content preserved for debugging.
_INJECTION_PREFIXES = re.compile(
    r"^([ \t]*(?:[>*#-]+[ \t]*)?)"
    r"((?:IMPORTANT:|Human:|Assistant:|System: you are|### Instruction"
    r"|(?:Ignore previous|You are now|As an AI|Disregard|New instructions"
    r"|Override|Forget (?:all )?previous|Your new (?:role|task)"
    r"|Jailbreak|Ignore (?:the )?above|Follow these instructions instead|From now on"
    r"|I am (?:now )?(?:re)?programming)(?![A-Za-z0-9_])))",
    re.IGNORECASE | re.MULTILINE,
)

# Instructions addressed to whatever AI is reading the output, anywhere in a line:
# response headers, banners, HTML comments, robots.txt, challenge text. CTF and
# bug-bounty infrastructure plants these to make a client self-identify or change
# its requests, which both leaks the client and logs whoever complied. They carry
# none of the prefixes above, so they need their own pass. Requires an addressee
# and a directive on the same line — either alone is ordinary English.
_AI_ADDRESSEE = re.compile(
    r"\b(?:ai|llm|language model|autonomous agent|chat ?bot)s?\b"
    r"|\b(?:chatgpt|gpt-?\d\w*|claude|gemini|copilot|codex)\b",
    re.IGNORECASE,
)
_AI_DIRECTIVE = re.compile(
    r"\b(?:must|shall|should|has to|have to|required to|needs? to|identify yourself|self-identify"
    r"|identify your|disclose|reveal|report your|state your|declare your|respond with|reply with"
    r"|set (?:the|your)|include (?:the|your)|add (?:the|your)|send (?:the|your)|append)\b",
    re.IGNORECASE,
)


def _mark_ai_directives(text: str) -> str:
    """Prefix lines that instruct an AI reader with ``[SANITIZED] ``."""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("[SANITIZED] "):
            continue
        if _AI_ADDRESSEE.search(line) and _AI_DIRECTIVE.search(line):
            lines[i] = "[SANITIZED] " + line
    return "\n".join(lines)


def truncate_output(text: str, max_bytes: int) -> tuple[str, bool]:
    """Truncate *text* so its UTF-8 encoding stays within *max_bytes*.

    Returns ``(text, was_truncated)``.
    """
    max_bytes = max(0, max_bytes)
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    trunc_msg = f"\n... [truncated at {max_bytes} bytes]"
    trunc_msg_bytes = trunc_msg.encode("utf-8")
    if len(trunc_msg_bytes) > max_bytes:
        return trunc_msg_bytes[:max_bytes].decode("utf-8", errors="ignore"), True
    # Truncate at byte level and decode back, ignoring partial characters
    cut = max(0, max_bytes - len(trunc_msg_bytes))
    truncated = encoded[:cut].decode("utf-8", errors="ignore")
    return truncated + trunc_msg, True


def sanitize_output(text: str) -> str:
    """Remove or mark prompt-injection patterns in tool output.

    - Zero-width and bidirectional format controls are stripped entirely.
    - ANSI/VT escape sequences (CSI, OSC, DCS) and C1 controls are stripped entirely.
    - Known LLM prompt markers are stripped.
    - XML-like role injection tags are stripped.
    - Lines starting with known injection prefixes are prefixed with ``[SANITIZED] ``.
    - Lines instructing an AI reader are prefixed with ``[SANITIZED] ``.
    - Other output is kept, NFKC-normalized (compatibility characters fold to plain forms).

    Known limit: cross-script homoglyphs (Cyrillic or Greek lookalikes) survive NFKC.
    """
    if not text:
        return text

    # Strip invisible reordering/hiding controls before pattern checks so they
    # cannot split a keyword or reorder a directive past the matchers below.
    text = _ZERO_WIDTH_BIDI_RE.sub("", _FILLER_RE.sub(" ", text))

    # Normalize Unicode to catch full-width character evasion
    text = unicodedata.normalize("NFKC", text)
    text = _BARE_LINE_BREAK_RE.sub("\n", text)

    for _ in range(_MAX_STRIP_PASSES):
        stripped = _XML_INJECTION_RE.sub("", _LLM_MARKERS.sub("", _ANSI_RE.sub("", text)))
        if stripped == text:
            break
        text = stripped

    # A deeply nested payload can outlast the bounded loop; whatever still matches is
    # replaced by text with no "<", "|" or ">" so it cannot reassemble.
    text = _XML_INJECTION_RE.sub(_TAG_PLACEHOLDER, _LLM_MARKERS.sub(_TAG_PLACEHOLDER, text))

    text = _INJECTION_PREFIXES.sub(r"[SANITIZED] \1\2", text)
    text = _mark_ai_directives(text)

    return text
