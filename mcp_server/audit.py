"""Audit logging — JSON-line file logger with rotation for tool executions."""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Patterns that may contain credentials in tool arguments.
# Matches: -H "Authorization: Bearer xxx", --password xxx, --token=xxx, etc.
_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"((?:Authorization|Bearer|Token|Api-?Key)\s*[:=]?\s*)\S+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(--?(?:password|passwd|token|secret|api[_-]?key|auth)"
            r"[\s=]+)\S+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
]


def _redact_sensitive(value: str) -> str:
    """Replace likely credentials in a string with [REDACTED]."""
    for pattern, replacement in _SENSITIVE_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


_AUDIT_LOG_PATH = Path(__file__).resolve().parent / "audit.log"

_logger: logging.Logger | None = None


def get_audit_logger() -> logging.Logger:
    """Return (and lazily configure) the audit logger.

    Uses a RotatingFileHandler writing to ``mcp_server/audit.log``
    (max 5 MB per file, 3 backups).
    """
    global _logger
    if _logger is not None:
        return _logger

    _logger = logging.getLogger("cybersec_mcp.audit")
    _logger.setLevel(logging.INFO)
    _logger.propagate = False

    try:
        handler: logging.Handler = logging.handlers.RotatingFileHandler(
            _AUDIT_LOG_PATH,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
    except OSError:
        # Log path unwritable (read-only install, container, etc.) — fall back
        # to a no-op handler so audit calls never crash tool execution.
        handler = logging.NullHandler()

    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)

    return _logger


def log_blocked(
    tool_name: str,
    args: str,
    reason: str,
    host: str = "localhost",
    remote: bool = False,
) -> None:
    """Write a single JSON audit line for a blocked tool execution."""
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": "blocked",
        "tool": tool_name,
        "args": _redact_sensitive(args),
        "host": host,
        "remote": remote,
        "reason": reason,
    }
    try:
        get_audit_logger().warning(json.dumps(entry, ensure_ascii=False))
    except OSError:
        pass


def log_script_execution(
    language: str,
    code: str,
    script_file: str = "",
    working_dir: str = "",
) -> None:
    """Write a single JSON audit line for a script execution (BEFORE running).

    Logs the full source code so that every script run through ``execute_script``
    is captured for forensic review.
    """
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": "script",
        "language": language,
        "code": code,
        "script_file": script_file,
        "working_dir": working_dir,
    }
    try:
        get_audit_logger().info(json.dumps(entry, ensure_ascii=False))
    except OSError:
        pass


def log_execution(
    tool_name: str,
    args: str,
    host: str = "localhost",
    exit_code: int = 0,
    command: str = "",
    remote: bool = False,
) -> None:
    """Write a single JSON audit line for a tool execution."""
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event": "execution",
        "tool": tool_name,
        "args": _redact_sensitive(args),
        "host": host,
        "remote": remote,
        "command": _redact_sensitive(command),
        "exit_code": exit_code,
    }
    try:
        get_audit_logger().info(json.dumps(entry, ensure_ascii=False))
    except OSError:
        pass
