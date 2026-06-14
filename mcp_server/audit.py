"""Audit logging — comprehensive JSON-line logger for all MCP server activity.

Every action the MCP server performs is logged here: tool calls, executions,
validations, pipeline steps, DNS lookups, config state, and more. The audit
log provides full visibility into what the server does at all times.

Log file: ``mcp_server/audit.log`` (5 MB rotating, 3 backups).
Format: one JSON object per line, always with ``ts`` and ``event`` fields.
"""

from __future__ import annotations

import hashlib
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
# ``[REDACTED]`` sentinel is never re-consumed: the value-matching parts exclude
# ``]`` (or stop before a literal ``[REDACTED]``) so re-running the redactor is
# idempotent and never leaves a stray ``]`` behind.
_REDACTED = "[REDACTED]"
_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Auth header keywords ("Authorization:", "Api-Key="). A [:=] separator is
    # MANDATORY here so prose like "the token is rotated" is never eaten (a bare
    # keyword followed only by whitespace no longer matches). An optional auth
    # scheme word (Bearer/Basic/Token/Digest) after the separator is preserved so
    # the credential after it — not just the scheme — is what gets redacted
    # ("Authorization: Bearer xyz" -> "...Bearer [REDACTED]"). The value must not
    # already be [REDACTED], and the value matcher stops at quotes so a trailing
    # quote is not consumed (keeps re-runs idempotent / no stray "]" left behind).
    (
        re.compile(
            r"((?:Authorization|Api-?Key)\s*[:=]\s*"
            r"(?:(?:Bearer|Basic|Token|Digest)\s+(?!\[REDACTED\])"  # scheme + credential
            r"|(?!(?:Bearer|Basic|Token|Digest)\b)(?!\[REDACTED\])))"  # or bare credential
            r"[^\s\"']+",
            re.IGNORECASE,
        ),
        r"\1" + _REDACTED,
    ),
    # Bare auth-scheme prefix ("Bearer <token>", "Basic <b64>") wherever it
    # appears — these schemes are unambiguous (a credential always follows), so a
    # whitespace separator is enough. A [:=] separator is also accepted
    # ("Bearer: xyz"). Prose words like "token"/"password" are deliberately NOT
    # in this set, so they still require the [:=]/flag forms below.
    (
        re.compile(
            r"((?:Bearer|Basic|Digest)[\s:=]+)(?!\[REDACTED\])[^\s\"']+",
            re.IGNORECASE,
        ),
        r"\1" + _REDACTED,
    ),
    (
        re.compile(
            r"(--?(?:password|passwd|token|secret|api[_-]?key|auth)"
            r"[\s=]+)(?!\[REDACTED\])\S+",
            re.IGNORECASE,
        ),
        r"\1" + _REDACTED,
    ),
    # HTTP Basic auth: curl/wget "-u user:pass" / "--user user:pass".
    (
        re.compile(r"((?:\B-u|--user)[\s=]+)(?!\[REDACTED\])\S+", re.IGNORECASE),
        r"\1" + _REDACTED,
    ),
    # Inline no-space password flag for DB clients: mysql/mariadb/psql/mongo
    # "-pSECRET". Scoped to a single-dash short flag (the negative lookbehind for
    # "-" stops it firing inside "--password") with a password shape: the value
    # must contain a char outside the nmap port-spec alphabet, so nmap
    # "-p80,443", "-p-", "-pU:53,T:80" survive intact (their values are only
    # digits, commas, dashes, colons, and the U:/T: protocol prefixes).
    (
        re.compile(r"(?<!-)(\B-p)(?![\dUT,:\-]+(?:\s|$))(?=\S*[^\d\s,:\-])(?!\[REDACTED\])\S+"),
        r"\1" + _REDACTED,
    ),
]


def _redact_sensitive(value: str) -> str:
    """Replace likely credentials in a string with [REDACTED]."""
    for pattern, replacement in _SENSITIVE_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


# Script-content patterns — target inline assignments that rarely appear in CLI
# args but are common in Python/Bash/JSON script bodies. Run AFTER
# _SENSITIVE_PATTERNS so CLI-style cases stay covered.
_SCRIPT_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # assignment or key:value form — e.g. API_KEY = "sk-xxx", token: "abc",
    # password='hunter2', os.environ["SECRET_KEY"] = "zzz"
    (
        re.compile(
            r"""
            (
                (?:\b|['"])                                 # word or quoted key
                (?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|
                   auth[_-]?token|bearer[_-]?token|client[_-]?secret|
                   session[_-]?id|session[_-]?token|private[_-]?key|
                   aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|
                   github[_-]?token|openai[_-]?api[_-]?key|
                   token|passwd|passphrase|password|secret)
                ['"]?                                       # optional close quote on key
                \s*[:=]\s*                                  # assignment
            )
            (?!\[REDACTED\])                                # don't re-match a prior redaction
            (?:
                "[^"\r\n]*"                                 # double-quoted
                |'[^'\r\n]*'                                # single-quoted
                |`[^`\r\n]*`                                # backtick-quoted
                |[^\s,;)\}\]]+                              # bare token
            )
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        r"\1[REDACTED]",
    ),
    # Known high-entropy token formats (catches secrets outside assignments).
    (
        re.compile(
            r"""\b(
                sk-[A-Za-z0-9]{16,}                          # OpenAI
                |ghp_[A-Za-z0-9]{20,}                        # GitHub PAT
                |gho_[A-Za-z0-9]{20,}                        # GitHub OAuth
                |ghu_[A-Za-z0-9]{20,}                        # GitHub user
                |ghs_[A-Za-z0-9]{20,}                        # GitHub server
                |github_pat_[A-Za-z0-9_]{20,}                # GitHub fine-grained
                |AIza[0-9A-Za-z_\-]{20,}                     # Google API
                |xox[abprs]-[0-9A-Za-z\-]+                   # Slack
                |(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}  # AWS access key ID
                |eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+  # JWT
            )\b""",
            re.VERBOSE,
        ),
        "[REDACTED]",
    ),
]


def _redact_script_code(code: str) -> str:
    """Redact likely credentials from script source code.

    Runs both the CLI-style ``_SENSITIVE_PATTERNS`` and script-specific
    assignment/high-entropy-token patterns, so ``log_script_execution`` never
    persists credentials in the audit log. Callers still get a SHA256 hash and
    length of the original code for forensic correlation.
    """
    code = _redact_sensitive(code)
    for pattern, replacement in _SCRIPT_SENSITIVE_PATTERNS:
        code = pattern.sub(replacement, code)
    return code


# ---------------------------------------------------------------------------
# Logger setup
# ---------------------------------------------------------------------------

_AUDIT_LOG_PATH = Path(__file__).resolve().parent / "audit.log"

_logger: logging.Logger | None = None


class _SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """RotatingFileHandler that keeps the audit log owner-only (0600).

    The audit log records tool args, command lines, DNS lookups and (redacted,
    best-effort) script bodies, so it must not be readable by other local users.
    chmod is applied on every stream open so it survives initial creation,
    reopen, and post-rotation (rotated .1/.2/.3 backups inherit 0600 because they
    were the 0600 base file before being renamed). Best-effort: a chmod failure
    (e.g. Windows/NTFS) must never break logging.
    """

    def _open(self):  # type: ignore[override]
        stream = super()._open()
        try:
            os.chmod(self.baseFilename, 0o600)
        except OSError:
            pass
        return stream


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
        handler: logging.Handler = _SecureRotatingFileHandler(
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
            "pid": os.getpid(),
        },
    )


# ---------------------------------------------------------------------------
# MCP tool call tracking
# ---------------------------------------------------------------------------


def _redact_steps(steps: Any) -> Any:
    """Redact credentials from a pipeline ``steps`` value for logging.

    Each step is a dict with a ``tool`` and an optional ``args`` (which may carry
    ``-u user:pass`` / bearer tokens). The ``args`` field is run through the full
    :func:`_redact_script_code` so pipeline args get the same coverage as
    standalone tool args — without it, ``run_pipeline`` would be a redaction
    bypass. Non-list / non-dict shapes are returned untouched so logging never
    raises on unexpected input.
    """
    if not isinstance(steps, list):
        return steps
    redacted = []
    for s in steps:
        if isinstance(s, dict):
            s = dict(s)
            if "args" in s:
                s["args"] = _redact_script_code(str(s["args"]))
            redacted.append(s)
        else:
            redacted.append(s)
    return redacted


def log_tool_call(tool_name: str, params: dict[str, Any]) -> str:
    """Log an incoming MCP tool invocation. Returns a call_id for correlation."""
    call_id = f"{time.monotonic_ns()}"
    safe_params = {}
    for k, v in params.items():
        if k == "code":
            # Redact credentials from the script body BEFORE truncating, mirroring
            # log_script_execution so the same code is never logged in cleartext.
            # Redact-first matters: truncating first can split a token mid-pattern
            # and defeat redaction.
            s = _redact_script_code(str(v))
            safe_params[k] = s[:200] + "..." if len(s) > 200 else s
        elif k in ("args", "command"):
            # Use the full script-code redactor (not the weaker CLI-only one) so
            # assignment-form secrets ("--data client_secret=...", "-e API_KEY=...")
            # are covered here exactly as they are in log_execution/log_blocked.
            safe_params[k] = _redact_script_code(str(v))
        elif k == "steps":
            # Pipeline step dicts can carry credentials in their nested args —
            # they aren't reachable via the code/args/command branches above.
            safe_params[k] = _redact_steps(v)
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
            "args": _redact_script_code(args),
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
            "args": _redact_script_code(args),
            "host": host,
            "remote": remote,
            "command": _redact_script_code(command),
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

    Captures the script's logic for forensic review while keeping credentials
    off disk: the code is run through :func:`_redact_script_code` first, and a
    SHA256 of the *original* code plus its byte length are logged alongside
    for correlation (e.g. matching an incident against an exact script body).
    """
    _log(
        logging.INFO,
        {
            "ts": _ts(),
            "event": "script",
            "language": language,
            "code": _redact_script_code(code),
            "code_sha256": hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest(),
            "code_len": len(code),
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
    # Redact each step's args — this runs BEFORE execution-time sanitization, so
    # without it bearer tokens / "-u user:pass" in pipeline steps would persist
    # in cleartext, bypassing the redaction layer for run_pipeline.
    step_summary = [f"{s.get('tool', '?')}({_redact_script_code(str(s.get('args', '')))})" for s in steps]
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
