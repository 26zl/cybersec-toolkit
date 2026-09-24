"""Output sanitization — strip prompt-injection patterns from tool output."""

from __future__ import annotations

import re
import unicodedata

# Zero-width and bidi format controls, stripped first so they cannot split a keyword
# or reorder text past the checks below.
_ZERO_WIDTH_BIDI_RE = re.compile(
    r"[\u200b-\u200f"  # ZWSP, ZWNJ, ZWJ, LRM, RLM
    r"\u202a-\u202e"  # LRE, RLE, PDF, LRO, RLO
    r"\u2060-\u2064"  # word joiner + invisible operators
    r"\u2066-\u2069"  # LRI, RLI, FSI, PDI
    r"\u061c"  # Arabic letter mark
    r"\u180e"  # Mongolian vowel separator
    r"\ufeff]"  # BOM / zero-width no-break space
)

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

# Known LLM prompt markers
_LLM_MARKERS = re.compile(
    r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>"
    r"|<\|begin_of_text\|>|<\|end_of_text\|>|<\|eot_id\|>"
    r"|<\|start_header_id\|>|<\|end_header_id\|>"
    r"|\[INST\]|\[/INST\]"
)

# XML-like tags that attempt to inject system/assistant roles
_XML_INJECTION_RE = re.compile(
    r"</?(?:system|assistant|tool_call|tool_result|tool_use|function_call|function_result|result)>",
    re.IGNORECASE,
)

# Line-level injection prefixes (case-insensitive, at line start)
# Marked with [SANITIZED] so the LLM sees them as neutralized; content preserved for debugging.
_INJECTION_PREFIXES = re.compile(
    r"^(IMPORTANT:|Ignore previous|You are now|As an AI|Human:|Assistant:|Disregard|New instructions"
    r"|Override|Forget (all )?previous|Your new (role|task)|System: you are|### Instruction"
    r"|Jailbreak|Ignore (the )?above|Follow these instructions instead|From now on|I am (now )?(re)?programming)",
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
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    trunc_msg = f"\n... [truncated at {max_bytes} bytes]"
    trunc_msg_bytes = trunc_msg.encode("utf-8")
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
    """
    if not text:
        return text

    # Strip invisible reordering/hiding controls before pattern checks so they
    # cannot split a keyword or reorder a directive past the matchers below.
    text = _ZERO_WIDTH_BIDI_RE.sub("", text)

    # Normalize Unicode to catch full-width character evasion
    text = unicodedata.normalize("NFKC", text)

    text = _ANSI_RE.sub("", text)

    text = _LLM_MARKERS.sub("", text)

    text = _XML_INJECTION_RE.sub("", text)

    text = _INJECTION_PREFIXES.sub(r"[SANITIZED] \1", text)
    text = _mark_ai_directives(text)

    return text
