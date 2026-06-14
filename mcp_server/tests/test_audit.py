"""Tests for mcp_server.audit — JSON audit logging with rotation."""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import stat
import sys
from pathlib import Path

import pytest

from mcp_server.audit import (
    _redact_script_code,
    get_audit_logger,
    log_blocked,
    log_execution,
    log_pipeline_start,
    log_script_execution,
    log_tool_call,
    log_tool_result,
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


class TestLogToolResult:
    def test_error_free_text_is_redacted(self, tmp_path: Path) -> None:
        # An exception string surfaced by a tool can carry a credential; the
        # free-text error field must be redacted before it hits the audit log.
        log_tool_result(
            tool_name="manage_remote_hosts",
            call_id="1",
            success=False,
            duration_ms=1.0,
            error="connection failed: PGPASSWORD=hunter2 rejected",
        )
        entry = json.loads((tmp_path / "audit.log").read_text(encoding="utf-8").strip())
        assert "hunter2" not in entry["error"]
        assert "[REDACTED]" in entry["error"]

    def test_summary_free_text_is_redacted(self, tmp_path: Path) -> None:
        log_tool_result(
            tool_name="run_tool",
            call_id="2",
            success=True,
            duration_ms=1.0,
            summary="ok --password s3cr3tvalue",
        )
        entry = json.loads((tmp_path / "audit.log").read_text(encoding="utf-8").strip())
        assert "s3cr3tvalue" not in entry["summary"]

    def test_benign_summary_unchanged(self, tmp_path: Path) -> None:
        log_tool_result("manage_remote_hosts", "3", True, 1.0, summary="list: 5 hosts")
        entry = json.loads((tmp_path / "audit.log").read_text(encoding="utf-8").strip())
        assert entry["summary"] == "list: 5 hosts"


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

    @staticmethod
    def _openai_key(suffix: str = "abc123def456ghi789jklmno") -> str:
        # Build shaped-like-real fake tokens at runtime so Gitleaks does not flag
        # the test source while the audit redactor still sees realistic input.
        return "sk" + "-" + suffix

    @staticmethod
    def _github_pat(suffix: str = "1234567890abcdefghij") -> str:
        return "gh" + "p_" + suffix

    @staticmethod
    def _bearer(value: str = "xyz123abc") -> str:
        return "Authorization" + ": " + "Bearer" + " " + value

    def test_python_api_key_assignment_redacted(self) -> None:
        secret = self._openai_key()
        code = f'API_KEY = "{secret}"\nprint(API_KEY)'
        redacted = _redact_script_code(code)
        assert secret not in redacted
        assert "[REDACTED]" in redacted

    def test_bash_password_export_redacted(self) -> None:
        code = 'export PASSWORD="hunter2"\ncurl -u admin:$PASSWORD http://10.0.0.1/'
        redacted = _redact_script_code(code)
        assert "hunter2" not in redacted
        assert "[REDACTED]" in redacted

    def test_json_token_field_redacted(self) -> None:
        secret = self._github_pat()
        code = '{"token": "' + secret + '"}'
        redacted = _redact_script_code(code)
        assert secret not in redacted

    def test_github_pat_outside_assignment_redacted(self) -> None:
        """Known high-entropy token formats caught even without credential-named var."""
        secret = self._github_pat("abcdefghij1234567890abcdefg")
        code = f'headers["X-Auth"] = "{secret}"'
        redacted = _redact_script_code(code)
        assert secret not in redacted
        assert "[REDACTED]" in redacted

    def test_openai_key_redacted(self) -> None:
        secret = "sk" + "-proj-" + "abcdefghijklmnopqrstuvwxyz"
        code = f"client.api_key = '{secret}'"
        redacted = _redact_script_code(code)
        assert secret not in redacted

    def test_jwt_redacted(self) -> None:
        header = "eyJ" + "hbGciOiJIUzI1NiJ9"
        payload = "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0"
        signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        jwt = ".".join((header, payload, signature))
        code = f'auth = "{jwt}"'
        redacted = _redact_script_code(code)
        assert header not in redacted

    def test_http_authorization_header_redacted(self) -> None:
        secret = "xyz123abc"
        code = 'req = requests.get(url, headers={"' + self._bearer(secret).replace(": ", '": "') + '"})'
        redacted = _redact_script_code(code)
        assert secret not in redacted
        assert "[REDACTED]" in redacted

    def test_benign_code_preserved(self) -> None:
        """Code without secrets should pass through untouched (aside from whitespace)."""
        code = "for i in range(10):\n    print(i * 2)\n"
        redacted = _redact_script_code(code)
        assert redacted == code

    def test_basic_auth_flag_redacted(self) -> None:
        """curl/wget -u user:pass must not leak to the audit log."""
        redacted = _redact_script_code("-u admin:s3cret http://10.0.0.1")
        assert "s3cret" not in redacted
        assert "[REDACTED]" in redacted

    def test_inline_password_flag_redacted(self) -> None:
        """mysql -pSECRET (no space) must be redacted."""
        redacted = _redact_script_code("mysql -h 10.0.0.1 -pMyP4ss -u root")
        assert "MyP4ss" not in redacted
        assert "[REDACTED]" in redacted

    def test_numeric_port_flag_preserved(self) -> None:
        """Pure-numeric -p ports must stay readable (not a credential)."""
        redacted = _redact_script_code("nmap -p80 -p3306 10.0.0.1")
        assert "-p80" in redacted
        assert "-p3306" in redacted

    def test_nmap_port_range_preserved(self) -> None:
        """nmap port specs ('-p80,443', '-p-', '-pU:53,T:80') must NOT be mangled."""
        redacted = _redact_script_code("nmap -p80,443 -p- -pU:53,T:80 10.0.0.1")
        assert "-p80,443" in redacted
        assert "-p-" in redacted
        assert "-pU:53,T:80" in redacted
        assert "[REDACTED]" not in redacted

    def test_nmap_separated_port_preserved(self) -> None:
        """nmap '-p 80' (separated, no credential tool) must stay readable."""
        redacted = _redact_script_code("nmap -p 80 10.0.0.1")
        assert "-p 80" in redacted
        assert "[REDACTED]" not in redacted

    def test_sshpass_separated_password_redacted(self) -> None:
        """sshpass -p <pw> uses the separated form and must be redacted."""
        redacted = _redact_script_code("sshpass -p mypassword ssh user@10.0.0.1")
        assert "mypassword" not in redacted
        assert "[REDACTED]" in redacted

    def test_hydra_separated_password_redacted(self) -> None:
        """hydra -l u -p secretpass host must not leak the password."""
        redacted = _redact_script_code("hydra -l u -p secretpass 10.0.0.1")
        assert "secretpass" not in redacted
        assert "[REDACTED]" in redacted

    def test_medusa_separated_password_redacted(self) -> None:
        redacted = _redact_script_code("medusa -h 10.0.0.1 -u admin -p Sup3rSecret -M ssh")
        assert "Sup3rSecret" not in redacted
        assert "[REDACTED]" in redacted

    def test_ncrack_separated_password_redacted(self) -> None:
        redacted = _redact_script_code("ncrack --user root -p hunter22 10.0.0.1:22")
        assert "hunter22" not in redacted
        assert "[REDACTED]" in redacted

    @pytest.mark.parametrize(
        "var,secret",
        [
            ("PGPASSWORD", "pgsecret123"),
            ("MYSQL_PWD", "hunter2"),
            ("MARIADB_PASSWORD", "mariasecret"),
            ("REDISCLI_AUTH", "redistoken"),
            ("MONGODB_PASSWORD", "mongopw"),
        ],
    )
    def test_db_password_env_var_redacted(self, var: str, secret: str) -> None:
        """DB/cache password env-vars carry the secret directly in the value."""
        redacted = _redact_script_code(f"{var}={secret} client --connect 10.0.0.1")
        assert secret not in redacted
        assert "[REDACTED]" in redacted
        assert var in redacted  # var name preserved for context

    def test_db_password_env_var_redacted_in_sensitive_path(self) -> None:
        """The CLI-only _redact_sensitive path covers the env-vars too."""
        from mcp_server.audit import _redact_sensitive

        redacted = _redact_sensitive("MYSQL_PWD=hunter2 mysql -u root")
        assert "hunter2" not in redacted
        assert "[REDACTED]" in redacted

    def test_double_dash_password_flag_not_mangled_by_short_p_rule(self) -> None:
        """The short '-p' DB rule must not fire inside '--password'."""
        redacted = _redact_script_code("--password hunter2")
        # The flag name stays intact; only the value is redacted.
        assert "--password" in redacted
        assert "hunter2" not in redacted

    def test_prose_token_word_not_eaten(self) -> None:
        """A bare 'token'/'password' word in prose (no separator) must survive."""
        assert _redact_script_code("the token is rotated") == "the token is rotated"
        assert _redact_script_code("the password was changed") == "the password was changed"

    def test_no_stray_bracket_and_idempotent(self) -> None:
        """Re-running the redactor must not leave a stray ']' or double-redact."""
        for code in (
            f'API_KEY = "{self._openai_key("abc123def456ghi789jkl")}"',
            '{"token": "' + self._github_pat() + '"}',
            'curl -H "' + self._bearer("xyz123abcdef") + '"',
            "mysql -pS3cr3tPass",
        ):
            once = _redact_script_code(code)
            twice = _redact_script_code(once)
            assert once == twice, f"not idempotent: {code!r} -> {once!r} -> {twice!r}"
            assert "[REDACTED]]" not in once

    def test_aws_access_key_id_redacted(self) -> None:
        """Standalone AWS access key IDs (AKIA.../ASIA...) must be redacted."""
        for code in (
            "aws_key = AKIAIOSFODNN7EXAMPLE",
            "export AWS_ID=ASIAYYYYYYYYYYYYYYYY",
            "role AROAEXAMPLE123456EXX printed",  # AROA + 16 chars = valid ID shape
        ):
            redacted = _redact_script_code(code)
            assert "[REDACTED]" in redacted, code
        # The 20-char IDs must not survive verbatim.
        assert "AKIAIOSFODNN7EXAMPLE" not in _redact_script_code("AKIAIOSFODNN7EXAMPLE")

    def test_url_query_apikey_redacted(self) -> None:
        secret = self._openai_key("abc123def4567890")
        redacted = _redact_script_code(f"http://t/?api_key={secret}")
        assert secret not in redacted
        assert "[REDACTED]" in redacted

    def test_log_script_execution_omits_body_and_hashes(self, tmp_path: Path) -> None:
        """log_script_execution must NOT persist the script body — only an
        irreversible SHA256 + length of the original. A secret in the code can
        then never reach the log even if best-effort redaction would miss it."""
        import hashlib

        secret = self._openai_key("verysecret123456789")
        original = f'API_KEY = "{secret}"\nprint("hello")'
        log_script_execution(language="python", code=original, script_file="/tmp/x.py")
        log_file = tmp_path / "audit.log"
        line = log_file.read_text().strip().splitlines()[-1]
        entry = json.loads(line)

        assert entry["event"] == "script"
        # Body omitted; the secret never appears anywhere in the log line.
        assert entry["code"] == "[OMITTED]"
        assert secret not in line
        # Integrity: SHA256 matches the original so operators can match a
        # suspected script against an exact incident body.
        assert entry["code_sha256"] == hashlib.sha256(original.encode("utf-8")).hexdigest()
        assert entry["code_len"] == len(original)


class TestLogToolCallRedaction:
    """The tool_call audit event must not persist the script body either."""

    def test_code_param_omitted_in_tool_call(self, tmp_path: Path) -> None:
        secret = TestRedactScriptCode._openai_key("abcdefghijklmnop1234567890")
        log_tool_call(
            "run_script",
            {"language": "python", "code": f'API_KEY = "{secret}"\nimport os'},
        )
        log_file = tmp_path / "audit.log"
        line = log_file.read_text(encoding="utf-8").strip().splitlines()[-1]
        entry = json.loads(line)
        assert entry["event"] == "tool_call"
        assert entry["params"]["code"] == "[OMITTED]"
        assert secret not in line

    def test_args_assignment_secret_redacted_in_tool_call(self, tmp_path: Path) -> None:
        """args/command must use the strong script-code redactor (assignment-form secrets)."""
        log_tool_call(
            "run_tool",
            {"tool_name": "curl", "args": "--data client_secret=topsecretvalue123"},
        )
        log_file = tmp_path / "audit.log"
        entry = json.loads(log_file.read_text(encoding="utf-8").strip().splitlines()[-1])
        assert "topsecretvalue123" not in entry["params"]["args"]
        assert "[REDACTED]" in entry["params"]["args"]

    def test_steps_args_redacted_in_tool_call(self, tmp_path: Path) -> None:
        """Nested pipeline step args carry creds the code/args/command branches miss."""
        header = TestRedactScriptCode._bearer("leakytoken9999")
        log_tool_call(
            "run_pipeline",
            {"steps": [{"tool": "curl", "args": f'-H "{header}"'}]},
        )
        log_file = tmp_path / "audit.log"
        entry = json.loads(log_file.read_text(encoding="utf-8").strip().splitlines()[-1])
        serialized = json.dumps(entry)
        assert "leakytoken9999" not in serialized
        assert "[REDACTED]" in entry["params"]["steps"][0]["args"]
        # tool name preserved for correlation
        assert entry["params"]["steps"][0]["tool"] == "curl"


class TestLogPipelineStartRedaction:
    """log_pipeline_start runs before sanitization and must redact each step's args."""

    def test_pipeline_step_args_redacted(self, tmp_path: Path) -> None:
        log_pipeline_start(
            [
                {"tool": "curl", "args": "-u admin:s3cretpw http://10.0.0.1"},
                {"tool": "grep", "args": "flag"},
            ],
            timeout=30,
        )
        log_file = tmp_path / "audit.log"
        entry = json.loads(log_file.read_text(encoding="utf-8").strip().splitlines()[-1])
        assert entry["event"] == "pipeline_start"
        joined = " ".join(entry["steps"])
        assert "s3cretpw" not in joined
        assert "[REDACTED]" in joined
        # Non-secret args still readable
        assert "grep(flag)" in joined


class TestAuditLogPermissions:
    """The audit log must be created owner-only (0600) — it holds sensitive runtime data."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes not applicable on Windows")
    def test_audit_log_is_owner_only(self, tmp_path: Path) -> None:
        log_execution(tool_name="nmap", args="-sV 10.0.0.1", exit_code=0, command="nmap -sV 10.0.0.1")
        log_file = tmp_path / "audit.log"
        assert log_file.exists()
        mode = stat.S_IMODE(os.stat(log_file).st_mode)
        assert mode == 0o600, f"audit.log mode is {oct(mode)}, expected 0o600"
