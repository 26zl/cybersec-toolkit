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
_INJECTION_PREFIXES = re.compile(
    r"^(IMPORTANT:|Ignore previous|You are now|As an AI|Human:|Assistant:|Disregard|New instructions)",
    re.IGNORECASE | re.MULTILINE,
)


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

    return text
