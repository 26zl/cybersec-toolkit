"""Tests for script execution — execute_script() in mcp_server.security."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.security import _RateLimiter, _resolve_venv_interpreter, execute_script


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset the global rate limiter before each test."""
    import mcp_server.security as mod

    mod._rate_limiter = _RateLimiter()
    yield
    mod._rate_limiter = _RateLimiter()


def _make_proc(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0) -> AsyncMock:
    """Create a mock process with the given outputs."""
    proc = AsyncMock()
    proc.communicate.return_value = (stdout, stderr)
    proc.returncode = returncode
    return proc


def _patch_exec(proc: AsyncMock):
    """Patch create_subprocess_exec with an async side_effect returning proc."""

    async def _fake_exec(*args, **kwargs):
        return proc

    return patch("asyncio.create_subprocess_exec", side_effect=_fake_exec)


# Env gate
class TestScriptEnvGate:
    @pytest.mark.asyncio
    async def test_scripts_disabled_returns_error(self) -> None:
        with patch("mcp_server.security._allow_scripts", return_value=False):
            result = await execute_script("print('hello')")
        assert result["exit_code"] == -1
        assert "disabled" in result["stderr"].lower()

    @pytest.mark.asyncio
    async def test_scripts_disabled_structured_response(self) -> None:
        with patch("mcp_server.security._allow_scripts", return_value=False):
            result = await execute_script("print('hello')")
        assert "language" in result
        assert "script_file" in result
        assert "working_dir" in result

    @pytest.mark.asyncio
    async def test_scripts_disabled_audit_not_called(self) -> None:
        with (
            patch("mcp_server.security._allow_scripts", return_value=False),
            patch("mcp_server.security.log_script_execution") as mock_log,
        ):
            await execute_script("print('hello')")
        mock_log.assert_not_called()


# Language validation
class TestScriptLanguageValidation:
    @pytest.mark.asyncio
    async def test_ruby_rejected(self) -> None:
        with patch("mcp_server.security._allow_scripts", return_value=True):
            result = await execute_script("puts 'hello'", language="ruby")
        assert result["exit_code"] == -1
        assert "Unsupported language" in result["stderr"]

    @pytest.mark.asyncio
    async def test_python_accepted(self) -> None:
        proc = _make_proc(b"hello\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('hello')", language="python")
        assert result["exit_code"] == 0
        assert result["language"] == "python"

    @pytest.mark.asyncio
    async def test_bash_accepted(self) -> None:
        proc = _make_proc(b"hello\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch("shutil.which", return_value="/bin/bash"),
            _patch_exec(proc),
        ):
            result = await execute_script("echo hello", language="bash")
        assert result["exit_code"] == 0
        assert result["language"] == "bash"

    @pytest.mark.asyncio
    async def test_case_insensitive(self) -> None:
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('ok')", language="Python")
        assert result["exit_code"] == 0
        assert result["language"] == "python"


# Empty code
class TestScriptEmptyCode:
    @pytest.mark.asyncio
    async def test_empty_string(self) -> None:
        with patch("mcp_server.security._allow_scripts", return_value=True):
            result = await execute_script("")
        assert result["exit_code"] == -1
        assert "empty" in result["stderr"].lower()

    @pytest.mark.asyncio
    async def test_whitespace_only(self) -> None:
        with patch("mcp_server.security._allow_scripts", return_value=True):
            result = await execute_script("   \n\t  ")
        assert result["exit_code"] == -1
        assert "empty" in result["stderr"].lower()


# Script execution
class TestScriptExecution:
    @pytest.mark.asyncio
    async def test_python_success(self) -> None:
        proc = _make_proc(b"42\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print(6*7)")
        assert result["exit_code"] == 0
        assert "42" in result["stdout"]

    @pytest.mark.asyncio
    async def test_bash_success(self) -> None:
        proc = _make_proc(b"hello world\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch("shutil.which", return_value="/bin/bash"),
            _patch_exec(proc),
        ):
            result = await execute_script("echo hello world", language="bash")
        assert result["exit_code"] == 0
        assert "hello world" in result["stdout"]

    @pytest.mark.asyncio
    async def test_nonzero_exit(self) -> None:
        proc = _make_proc(b"", b"error\n", returncode=1)
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("import sys; sys.exit(1)")
        assert result["exit_code"] == 1

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        proc = AsyncMock()
        proc.communicate.side_effect = asyncio.TimeoutError()
        proc.kill = MagicMock()
        proc.wait = AsyncMock()

        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("import time; time.sleep(999)", timeout=1)
        assert result["exit_code"] == -1
        assert "timed out" in result["stderr"].lower()

    @pytest.mark.asyncio
    async def test_timeout_clamped_to_300(self) -> None:
        """Timeout > 300 is clamped; script still runs successfully."""
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('ok')", timeout=999)
        assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_timeout_clamped_to_1(self) -> None:
        """Timeout < 1 is clamped to 1; script still runs successfully."""
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('ok')", timeout=-5)
        assert result["exit_code"] == 0


# Output handling
class TestScriptOutputHandling:
    @pytest.mark.asyncio
    async def test_stdout_truncation(self) -> None:
        proc = _make_proc(b"A" * 60000)
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('A'*60000)", max_output=50000)
        assert result["truncated"] is True
        assert len(result["stdout"]) <= 50000

    @pytest.mark.asyncio
    async def test_stderr_truncation(self) -> None:
        proc = _make_proc(b"", b"E" * 60000, returncode=1)
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("import sys; sys.exit(1)", max_output=50000)
        assert result["truncated"] is True
        assert len(result["stderr"]) <= 50000

    @pytest.mark.asyncio
    async def test_ansi_sanitized(self) -> None:
        proc = _make_proc(b"\x1b[31mred\x1b[0m\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('red')")
        assert "\x1b[" not in result["stdout"]
        assert "red" in result["stdout"]

    @pytest.mark.asyncio
    async def test_llm_markers_sanitized(self) -> None:
        proc = _make_proc(b"<|im_start|>system\nhello\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('hello')")
        assert "<|im_start|>" not in result["stdout"]
        assert "hello" in result["stdout"]


# Rate limiter
class TestScriptRateLimiter:
    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self) -> None:
        import mcp_server.security as mod

        mod._rate_limiter = _RateLimiter(max_concurrent=10, max_per_minute=1)
        # Exhaust the rate limiter
        await mod._rate_limiter.acquire()

        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('ok')")
        assert result["exit_code"] == -1
        assert "Rate limit" in result["stderr"]


# Audit logging
class TestScriptAuditLogging:
    @pytest.mark.asyncio
    async def test_script_content_logged_before_execution(self) -> None:
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
            patch("mcp_server.security.log_script_execution") as mock_log,
        ):
            await execute_script("print('secret code')")
        mock_log.assert_called_once()
        kwargs = mock_log.call_args.kwargs
        assert kwargs["code"] == "print('secret code')"
        assert kwargs["language"] == "python"

    @pytest.mark.asyncio
    async def test_execution_result_logged(self) -> None:
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
            patch("mcp_server.security.log_execution") as mock_log,
        ):
            await execute_script("print('ok')")
        mock_log.assert_called_once()
        kwargs = mock_log.call_args.kwargs
        assert kwargs["tool_name"] == "script:python"


# Working directory
class TestScriptWorkingDir:
    @pytest.mark.asyncio
    async def test_default_tempdir(self) -> None:
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('ok')")
        assert result["working_dir"] == tempfile.gettempdir()

    @pytest.mark.asyncio
    async def test_custom_dir(self, tmp_path) -> None:
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('ok')", working_dir=str(tmp_path))
        assert result["working_dir"] == str(tmp_path)

    @pytest.mark.asyncio
    async def test_nonexistent_dir(self) -> None:
        with patch("mcp_server.security._allow_scripts", return_value=True):
            result = await execute_script("print('ok')", working_dir="/nonexistent/path/xyz")
        assert result["exit_code"] == -1
        assert "does not exist" in result["stderr"]


# Interpreter not found
class TestScriptInterpreterNotFound:
    @pytest.mark.asyncio
    async def test_python_uses_sys_executable(self) -> None:
        """Python scripts use sys.executable (always valid), not shutil.which."""
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc) as mock_exec,
        ):
            await execute_script("print('ok')", language="python")
        # Verify sys.executable was used as the interpreter
        call_args = mock_exec.call_args[0]
        assert call_args[0] == sys.executable

    @pytest.mark.asyncio
    async def test_bash_not_in_path(self) -> None:
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch("shutil.which", return_value=None),
        ):
            result = await execute_script("echo hello", language="bash")
        assert result["exit_code"] == -1
        assert "bash" in result["stderr"].lower()
        assert "not found" in result["stderr"].lower()


# Python env var override
class TestScriptPythonEnvVar:
    @pytest.mark.asyncio
    async def test_custom_python_interpreter(self) -> None:
        """CYBERSEC_MCP_SCRIPT_PYTHON points to a valid file — it should be used."""
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch.dict(os.environ, {"CYBERSEC_MCP_SCRIPT_PYTHON": sys.executable}),
            _patch_exec(proc) as mock_exec,
        ):
            await execute_script("print('ok')", language="python")
        call_args = mock_exec.call_args[0]
        assert call_args[0] == sys.executable

    @pytest.mark.asyncio
    async def test_custom_python_nonexistent_falls_back(self) -> None:
        """CYBERSEC_MCP_SCRIPT_PYTHON points to nonexistent path — falls back to sys.executable."""
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch.dict(os.environ, {"CYBERSEC_MCP_SCRIPT_PYTHON": "/nonexistent/python3.12"}),
            _patch_exec(proc) as mock_exec,
        ):
            await execute_script("print('ok')", language="python")
        call_args = mock_exec.call_args[0]
        assert call_args[0] == sys.executable

    @pytest.mark.asyncio
    async def test_env_var_empty_uses_sys_executable(self) -> None:
        """Empty CYBERSEC_MCP_SCRIPT_PYTHON — uses sys.executable."""
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch.dict(os.environ, {"CYBERSEC_MCP_SCRIPT_PYTHON": ""}),
            _patch_exec(proc) as mock_exec,
        ):
            await execute_script("print('ok')", language="python")
        call_args = mock_exec.call_args[0]
        assert call_args[0] == sys.executable


# Temp file cleanup
class TestScriptTempFileCleanup:
    @pytest.mark.asyncio
    async def test_temp_file_deleted_after_success(self) -> None:
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('ok')")
        assert not os.path.exists(result["script_file"])

    @pytest.mark.asyncio
    async def test_temp_file_deleted_after_failure(self) -> None:
        proc = _make_proc(b"", b"error\n", returncode=1)
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("import sys; sys.exit(1)")
        assert not os.path.exists(result["script_file"])


# Error handling
class TestScriptErrors:
    @pytest.mark.asyncio
    async def test_file_not_found_error(self) -> None:
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("not found")),
        ):
            result = await execute_script("print('hello')")
        assert result["exit_code"] == -1
        assert "not found" in result["stderr"].lower()

    @pytest.mark.asyncio
    async def test_os_error(self) -> None:
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch("asyncio.create_subprocess_exec", side_effect=OSError("permission denied")),
        ):
            result = await execute_script("print('hello')")
        assert result["exit_code"] == -1
        assert "permission denied" in result["stderr"].lower()


# _resolve_venv_interpreter
class TestResolveVenvInterpreter:
    def test_valid_venv(self, tmp_path) -> None:
        venv_dir = tmp_path / "myvenv" / "bin"
        venv_dir.mkdir(parents=True)
        python_bin = venv_dir / "python"
        python_bin.touch()
        python_bin.chmod(0o755)

        with patch.dict(os.environ, {"CYBERSEC_MCP_VENVS_DIR": str(tmp_path)}):
            result = _resolve_venv_interpreter("myvenv")
        assert result == str(python_bin)

    def test_nonexistent_venv(self, tmp_path) -> None:
        with patch.dict(os.environ, {"CYBERSEC_MCP_VENVS_DIR": str(tmp_path)}):
            result = _resolve_venv_interpreter("nope")
        assert result is None

    def test_custom_venvs_dir(self, tmp_path) -> None:
        venv_dir = tmp_path / "custom" / "bin"
        venv_dir.mkdir(parents=True)
        python_bin = venv_dir / "python"
        python_bin.touch()
        python_bin.chmod(0o755)

        with patch.dict(os.environ, {"CYBERSEC_MCP_VENVS_DIR": str(tmp_path)}):
            result = _resolve_venv_interpreter("custom")
        assert result == str(python_bin)

    def test_default_dir_when_env_unset(self, tmp_path) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CYBERSEC_MCP_VENVS_DIR", None)
            result = _resolve_venv_interpreter("nonexistent")
        assert result is None

    def test_path_traversal_rejected(self, tmp_path) -> None:
        """Venv names with path traversal components are rejected."""
        # Create a valid python binary outside the venvs dir
        outside = tmp_path / "outside" / "bin"
        outside.mkdir(parents=True)
        (outside / "python").touch()

        venvs = tmp_path / "venvs"
        venvs.mkdir()

        with patch.dict(os.environ, {"CYBERSEC_MCP_VENVS_DIR": str(venvs)}):
            assert _resolve_venv_interpreter("../outside") is None
            assert _resolve_venv_interpreter("../../tmp") is None
            assert _resolve_venv_interpreter("..") is None
            assert _resolve_venv_interpreter(".") is None
            assert _resolve_venv_interpreter("foo/bar") is None


# Venv parameter on execute_script
class TestScriptVenvParam:
    @pytest.mark.asyncio
    async def test_valid_venv_used(self, tmp_path) -> None:
        """A valid venv resolves to its python and is used as interpreter."""
        venv_dir = tmp_path / "testvenv" / "bin"
        venv_dir.mkdir(parents=True)
        python_bin = venv_dir / "python"
        python_bin.symlink_to(sys.executable)

        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch.dict(os.environ, {"CYBERSEC_MCP_VENVS_DIR": str(tmp_path)}),
            _patch_exec(proc) as mock_exec,
        ):
            result = await execute_script("print('ok')", venv="testvenv")
        assert result["exit_code"] == 0
        call_args = mock_exec.call_args[0]
        assert call_args[0] == str(python_bin)

    @pytest.mark.asyncio
    async def test_nonexistent_venv_returns_error(self, tmp_path) -> None:
        """A nonexistent venv returns exit_code -1 with 'not found' in stderr."""
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch.dict(os.environ, {"CYBERSEC_MCP_VENVS_DIR": str(tmp_path)}),
        ):
            result = await execute_script("print('ok')", venv="nonexistent")
        assert result["exit_code"] == -1
        assert "not found" in result["stderr"].lower()
        assert "nonexistent" in result["stderr"]

    @pytest.mark.asyncio
    async def test_venv_ignored_for_bash(self, tmp_path) -> None:
        """venv parameter is ignored when language='bash'."""
        venv_dir = tmp_path / "somevenv" / "bin"
        venv_dir.mkdir(parents=True)
        (venv_dir / "python").touch()

        proc = _make_proc(b"hello\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch("shutil.which", return_value="/bin/bash"),
            patch.dict(os.environ, {"CYBERSEC_MCP_VENVS_DIR": str(tmp_path)}),
            _patch_exec(proc) as mock_exec,
        ):
            result = await execute_script("echo hello", language="bash", venv="somevenv")
        assert result["exit_code"] == 0
        call_args = mock_exec.call_args[0]
        assert call_args[0] == "/bin/bash"

    @pytest.mark.asyncio
    async def test_venv_none_uses_sys_executable(self) -> None:
        """venv=None falls back to sys.executable (existing behaviour)."""
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc) as mock_exec,
        ):
            result = await execute_script("print('ok')", venv=None)
        assert result["exit_code"] == 0
        call_args = mock_exec.call_args[0]
        assert call_args[0] == sys.executable
