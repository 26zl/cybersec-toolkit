"""Audit logging — comprehensive JSON-line logger for all MCP server activity.

Every action the MCP server performs is logged here: tool calls, executions,
validations, pipeline steps, DNS lookups, config state, and more. The audit
log provides full visibility into what the server does at all times.

Log file: ``mcp_server/audit.log`` (5 MB rotating, 3 backups).
Format: one JSON object per line, always with ``ts`` and ``event`` fields.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Credential redaction
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Logger setup
# ---------------------------------------------------------------------------

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
    _logger.setLevel(logging.DEBUG)
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


def _log(level: int, entry: dict[str, Any]) -> None:
    """Write a JSON audit entry at the given level. Never raises."""
    try:
        get_audit_logger().log(level, json.dumps(entry, ensure_ascii=False))
    except OSError:
        pass


def _ts() -> str:
    """ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------


def log_server_start() -> None:
    """Log server startup with environment/config state."""
    _log(
        logging.INFO,
        {
            "ts": _ts(),
            "event": "server_start",
            "allow_scripts": os.environ.get("CYBERSEC_MCP_ALLOW_SCRIPTS", "0").strip(),
            "allow_external": os.environ.get("CYBERSEC_MCP_ALLOW_EXTERNAL", "0").strip(),
            "venvs_dir": os.environ.get("CYBERSEC_MCP_VENVS_DIR", "~/.ctf-venvs"),
            "installer_root": os.environ.get("CYBERSEC_INSTALLER_ROOT", ""),
            "pid": os.getpid(),
        },
    )


# ---------------------------------------------------------------------------
# MCP tool call tracking
# ---------------------------------------------------------------------------


def log_tool_call(tool_name: str, params: dict[str, Any]) -> str:
    """Log an incoming MCP tool invocation. Returns a call_id for correlation."""
    call_id = f"{time.monotonic_ns()}"
    safe_params = {}
    for k, v in params.items():
        if k == "code":
            # Truncate long scripts in the call log (full code logged by log_script_execution)
            s = str(v)
            safe_params[k] = s[:200] + "..." if len(s) > 200 else s
        elif k in ("args", "command"):
            safe_params[k] = _redact_sensitive(str(v))
        else:
            safe_params[k] = v
    _log(
        logging.INFO,
        {
            "ts": _ts(),
            "event": "tool_call",
            "call_id": call_id,
            "tool": tool_name,
            "params": safe_params,
        },
    )
    return call_id


def log_tool_result(
    tool_name: str,
    call_id: str,
    success: bool,
    duration_ms: float,
    error: str = "",
    summary: str = "",
) -> None:
    """Log the result of an MCP tool invocation."""
    entry: dict[str, Any] = {
        "ts": _ts(),
        "event": "tool_result",
        "call_id": call_id,
        "tool": tool_name,
        "success": success,
        "duration_ms": round(duration_ms, 1),
    }
    if error:
        entry["error"] = error
    if summary:
        entry["summary"] = summary
    _log(logging.INFO, entry)


# ---------------------------------------------------------------------------
# Validation steps (granular)
# ---------------------------------------------------------------------------


def log_validation(
    tool_name: str,
    step: str,
    passed: bool,
    detail: str = "",
) -> None:
    """Log a validation step (resolved binary, args sanitized, policy checked)."""
    entry: dict[str, Any] = {
        "ts": _ts(),
        "event": "validation",
        "tool": tool_name,
        "step": step,
        "passed": passed,
    }
    if detail:
        entry["detail"] = detail
    _log(logging.DEBUG, entry)


# ---------------------------------------------------------------------------
# Execution events (tool, script, pipeline)
# ---------------------------------------------------------------------------


def log_blocked(
    tool_name: str,
    args: str,
    reason: str,
    host: str = "localhost",
    remote: bool = False,
) -> None:
    """Write a single JSON audit line for a blocked tool execution."""
    _log(
        logging.WARNING,
        {
            "ts": _ts(),
            "event": "blocked",
            "tool": tool_name,
            "args": _redact_sensitive(args),
            "host": host,
            "remote": remote,
            "reason": reason,
        },
    )


def log_execution(
    tool_name: str,
    args: str,
    host: str = "localhost",
    exit_code: int = 0,
    command: str = "",
    remote: bool = False,
    duration_ms: float = 0,
    stdout_len: int = 0,
    stderr_len: int = 0,
    truncated: bool = False,
) -> None:
    """Write a single JSON audit line for a tool execution."""
    _log(
        logging.INFO,
        {
            "ts": _ts(),
            "event": "execution",
            "tool": tool_name,
            "args": _redact_sensitive(args),
            "host": host,
            "remote": remote,
            "command": _redact_sensitive(command),
            "exit_code": exit_code,
            "duration_ms": round(duration_ms, 1),
            "stdout_bytes": stdout_len,
            "stderr_bytes": stderr_len,
            "truncated": truncated,
        },
    )


def log_script_execution(
    language: str,
    code: str,
    script_file: str = "",
    working_dir: str = "",
    venv: str = "",
) -> None:
    """Write a single JSON audit line for a script execution (BEFORE running).

    Logs the full source code so that every script run through ``execute_script``
    is captured for forensic review.
    """
    _log(
        logging.INFO,
        {
            "ts": _ts(),
            "event": "script",
            "language": language,
            "code": code,
            "script_file": script_file,
            "working_dir": working_dir,
            "venv": venv,
        },
    )


def log_script_result(
    language: str,
    exit_code: int,
    duration_ms: float,
    script_file: str = "",
    stdout_len: int = 0,
    stderr_len: int = 0,
    truncated: bool = False,
) -> None:
    """Log script execution result (AFTER running)."""
    _log(
        logging.INFO,
        {
            "ts": _ts(),
            "event": "script_result",
            "language": language,
            "exit_code": exit_code,
            "duration_ms": round(duration_ms, 1),
            "script_file": script_file,
            "stdout_bytes": stdout_len,
            "stderr_bytes": stderr_len,
            "truncated": truncated,
        },
    )


# ---------------------------------------------------------------------------
# Pipeline step tracking
# ---------------------------------------------------------------------------


def log_pipeline_start(steps: list[dict], timeout: int) -> str:
    """Log pipeline start. Returns pipeline_id for correlation."""
    pipeline_id = f"pipe_{time.monotonic_ns()}"
    step_summary = [f"{s.get('tool', '?')}({s.get('args', '')})" for s in steps]
    _log(
        logging.INFO,
        {
            "ts": _ts(),
            "event": "pipeline_start",
            "pipeline_id": pipeline_id,
            "steps": step_summary,
            "step_count": len(steps),
            "timeout": timeout,
        },
    )
    return pipeline_id


def log_pipeline_step(
    pipeline_id: str,
    step_num: int,
    tool: str,
    exit_code: int,
    duration_ms: float,
    output_bytes: int = 0,
) -> None:
    """Log individual pipeline step completion."""
    _log(
        logging.DEBUG,
        {
            "ts": _ts(),
            "event": "pipeline_step",
            "pipeline_id": pipeline_id,
            "step": step_num,
            "tool": tool,
            "exit_code": exit_code,
            "duration_ms": round(duration_ms, 1),
            "output_bytes": output_bytes,
        },
    )


def log_pipeline_result(
    pipeline_id: str,
    exit_code: int,
    duration_ms: float,
    step_count: int,
    truncated: bool = False,
) -> None:
    """Log pipeline final result."""
    _log(
        logging.INFO,
        {
            "ts": _ts(),
            "event": "pipeline_result",
            "pipeline_id": pipeline_id,
            "exit_code": exit_code,
            "duration_ms": round(duration_ms, 1),
            "step_count": step_count,
            "truncated": truncated,
        },
    )


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


def log_rate_limit(action: str, current: int, max_val: int) -> None:
    """Log rate limiter events (acquire, exceeded)."""
    _log(
        logging.DEBUG,
        {
            "ts": _ts(),
            "event": "rate_limit",
            "action": action,
            "current": current,
            "max": max_val,
        },
    )


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------


def log_dns(
    hostname: str,
    resolved: bool,
    ip: str = "",
    safe: bool = True,
    duration_ms: float = 0,
    error: str = "",
) -> None:
    """Log DNS resolution attempts during target validation."""
    entry: dict[str, Any] = {
        "ts": _ts(),
        "event": "dns",
        "hostname": hostname,
        "resolved": resolved,
        "duration_ms": round(duration_ms, 1),
    }
    if ip:
        entry["ip"] = ip
    if resolved:
        entry["safe"] = safe
    if error:
        entry["error"] = error
    _log(logging.DEBUG, entry)


# ---------------------------------------------------------------------------
# Remote host management
# ---------------------------------------------------------------------------


def log_remote_op(action: str, host: str = "", detail: str = "") -> None:
    """Log remote host management operations (add, remove, test)."""
    _log(
        logging.INFO,
        {
            "ts": _ts(),
            "event": "remote_op",
            "action": action,
            "host": host,
            "detail": detail,
        },
    )


# ---------------------------------------------------------------------------
# Policy / config events
# ---------------------------------------------------------------------------


def log_policy_check(
    tool_name: str,
    check: str,
    result: str,
    detail: str = "",
) -> None:
    """Log policy enforcement decisions."""
    _log(
        logging.DEBUG,
        {
            "ts": _ts(),
            "event": "policy",
            "tool": tool_name,
            "check": check,
            "result": result,
            "detail": detail,
        },
    )
