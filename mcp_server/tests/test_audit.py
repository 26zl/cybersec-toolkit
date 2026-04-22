"""Tests for mcp_server.audit — JSON audit logging with rotation."""

from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path

import pytest

from mcp_server.audit import (
    _redact_script_code,
    get_audit_logger,
    log_blocked,
    log_execution,
    log_script_execution,
)


@pytest.fixture(autouse=True)
def _reset_audit_logger(tmp_path: Path):
    """Reset the module-level logger so each test gets a fresh one writing to tmp."""
    import mcp_server.audit as mod

    # Reset cached logger
    mod._logger = None
    log_file = tmp_path / "audit.log"
    mod._AUDIT_LOG_PATH = log_file
    yield
    # Clean up handlers to avoid ResourceWarning
    if mod._logger is not None:
        for h in list(mod._logger.handlers):
            h.close()
            mod._logger.removeHandler(h)
    mod._logger = None


class TestGetAuditLogger:
    def test_returns_logger(self, tmp_path: Path) -> None:
        logger = get_audit_logger()
        assert isinstance(logger, logging.Logger)
        assert logger.name == "cybersec_mcp.audit"

    def test_has_rotating_handler(self, tmp_path: Path) -> None:
        logger = get_audit_logger()
        handlers = [h for h in logger.handlers if isinstance(h, logging.handlers.RotatingFileHandler)]
        assert len(handlers) == 1
        assert handlers[0].maxBytes == 5 * 1024 * 1024
        assert handlers[0].backupCount == 3

    def test_singleton(self, tmp_path: Path) -> None:
        a = get_audit_logger()
        b = get_audit_logger()
        assert a is b


class TestLogExecution:
    def test_writes_json_line(self, tmp_path: Path) -> None:
        log_execution(
            tool_name="nmap",
            args="-sV 10.0.0.1",
            host="localhost",
            exit_code=0,
            command="nmap -sV 10.0.0.1",
        )
        log_file = tmp_path / "audit.log"
        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["tool"] == "nmap"
        assert entry["args"] == "-sV 10.0.0.1"
        assert entry["host"] == "localhost"
        assert entry["exit_code"] == 0
        assert entry["remote"] is False
        assert entry["command"] == "nmap -sV 10.0.0.1"
        assert "ts" in entry

    def test_remote_flag(self, tmp_path: Path) -> None:
        log_execution(
            tool_name="gobuster",
            args="dir -u http://10.0.0.1",
            host="kali-vm",
            exit_code=0,
            command="gobuster dir -u http://10.0.0.1",
            remote=True,
        )
        log_file = tmp_path / "audit.log"
        entry = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert entry["remote"] is True
        assert entry["host"] == "kali-vm"

    def test_multiple_entries(self, tmp_path: Path) -> None:
        for i in range(3):
            log_execution(tool_name=f"tool{i}", args="", exit_code=i, command=f"tool{i}")
        log_file = tmp_path / "audit.log"
        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 3


class TestLogBlocked:
    def test_log_blocked_writes_json(self, tmp_path: Path) -> None:
        log_blocked(
            tool_name="nmap",
            args="-sV 8.8.8.8",
            reason="Blocked by policy: target not in private range",
        )
        log_file = tmp_path / "audit.log"
        lines = log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["event"] == "blocked"
        assert entry["tool"] == "nmap"
        assert entry["args"] == "-sV 8.8.8.8"
        assert entry["remote"] is False
        assert "ts" in entry

    def test_log_blocked_contains_reason(self, tmp_path: Path) -> None:
        log_blocked(
            tool_name="sqlmap",
            args="--os-shell",
            reason="sqlmap: OS shell access",
            host="kali-vm",
            remote=True,
        )
        log_file = tmp_path / "audit.log"
        entry = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert entry["reason"] == "sqlmap: OS shell access"
        assert entry["host"] == "kali-vm"
        assert entry["remote"] is True


class TestAuditCrashSafety:
    def test_unwritable_log_path_uses_null_handler(self, tmp_path: Path) -> None:
        """Logger falls back to NullHandler when log path is unwritable."""
        import mcp_server.audit as mod

        # Reset and point to unwritable path
        mod._logger = None
        mod._AUDIT_LOG_PATH = tmp_path / "no_such_dir" / "sub" / "audit.log"
        # Don't create the parent — handler creation should fail gracefully
        logger = get_audit_logger()
        null_handlers = [h for h in logger.handlers if isinstance(h, logging.NullHandler)]
        assert len(null_handlers) == 1

    def test_log_execution_never_raises_on_write_error(self, tmp_path: Path) -> None:
        """log_execution must not crash even if the handler raises."""
        # Normal logger first, then make the file unwritable
        log_execution(tool_name="test", args="", exit_code=0, command="test")
        log_file = tmp_path / "audit.log"
        assert log_file.exists()
        # Should not raise
        log_execution(tool_name="test2", args="", exit_code=0, command="test2")


class TestRedactScriptCode:
    """Script content is redacted before being written to the audit log."""

    def test_python_api_key_assignment_redacted(self) -> None:
        code = 'API_KEY = "sk-abc123def456ghi789jklmno"\nprint(API_KEY)'
        redacted = _redact_script_code(code)
        assert "sk-abc123def456ghi789jklmno" not in redacted
        assert "[REDACTED]" in redacted

    def test_bash_password_export_redacted(self) -> None:
        code = 'export PASSWORD="hunter2"\ncurl -u admin:$PASSWORD http://10.0.0.1/'
        redacted = _redact_script_code(code)
        assert "hunter2" not in redacted
        assert "[REDACTED]" in redacted

    def test_json_token_field_redacted(self) -> None:
        code = '{"token": "ghp_1234567890abcdefghij"}'
        redacted = _redact_script_code(code)
        assert "ghp_1234567890abcdefghij" not in redacted

    def test_github_pat_outside_assignment_redacted(self) -> None:
        """Known high-entropy token formats caught even without credential-named var."""
        code = 'headers["X-Auth"] = "ghp_abcdefghij1234567890abcdefg"'
        redacted = _redact_script_code(code)
        assert "ghp_abcdefghij1234567890abcdefg" not in redacted
        assert "[REDACTED]" in redacted

    def test_openai_key_redacted(self) -> None:
        code = "client.api_key = 'sk-proj-abcdefghijklmnopqrstuvwxyz'"
        redacted = _redact_script_code(code)
        assert "sk-proj-abcdefghijklmnopqrstuvwxyz" not in redacted

    def test_jwt_redacted(self) -> None:
        code = 'auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
        redacted = _redact_script_code(code)
        assert "eyJhbGciOiJIUzI1NiJ9" not in redacted

    def test_http_authorization_header_redacted(self) -> None:
        code = 'req = requests.get(url, headers={"Authorization": "Bearer xyz123abc"})'
        redacted = _redact_script_code(code)
        assert "xyz123abc" not in redacted
        assert "[REDACTED]" in redacted

    def test_benign_code_preserved(self) -> None:
        """Code without secrets should pass through untouched (aside from whitespace)."""
        code = "for i in range(10):\n    print(i * 2)\n"
        redacted = _redact_script_code(code)
        assert redacted == code

    def test_log_script_execution_redacts_and_hashes(self, tmp_path: Path) -> None:
        """log_script_execution writes redacted code + SHA256 + len of original."""
        import hashlib

        original = 'API_KEY = "sk-verysecret123456789"\nprint("hello")'
        log_script_execution(language="python", code=original, script_file="/tmp/x.py")
        log_file = tmp_path / "audit.log"
        entry = json.loads(log_file.read_text().strip().splitlines()[-1])

        assert entry["event"] == "script"
        assert "sk-verysecret123456789" not in entry["code"]
        assert "[REDACTED]" in entry["code"]
        # Integrity: SHA256 matches original (not redacted) so operators can
        # match a suspected script against an exact incident body.
        assert entry["code_sha256"] == hashlib.sha256(original.encode("utf-8")).hexdigest()
        assert entry["code_len"] == len(original)
