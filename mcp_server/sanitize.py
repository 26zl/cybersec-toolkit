"""Output sanitization — strip prompt-injection patterns from tool output."""

from __future__ import annotations

import re
import unicodedata

# ANSI escape codes (e.g. \x1b[31m, \033[0m)
_ANSI_RE = re.compile(r"(\x1b|\033)\[[0-9;]*[A-Za-z]")

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

    - ANSI escape codes are stripped entirely.
    - Known LLM prompt markers are stripped.
    - XML-like role injection tags are stripped.
    - Lines starting with known injection prefixes are prefixed with ``[SANITIZED] ``.
    - Lines instructing an AI reader are prefixed with ``[SANITIZED] ``.
    - All genuine tool output is preserved.
    """
    if not text:
        return text

    # Normalize Unicode to catch full-width character evasion
    text = unicodedata.normalize("NFKC", text)

    # Strip ANSI escapes
    text = _ANSI_RE.sub("", text)

    # Strip LLM markers
    text = _LLM_MARKERS.sub("", text)

    # Strip XML injection tags
    text = _XML_INJECTION_RE.sub("", text)

    # Mark suspicious lines
    text = _INJECTION_PREFIXES.sub(r"[SANITIZED] \1", text)
    text = _mark_ai_directives(text)

    return text
