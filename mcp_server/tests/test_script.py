"""Tests for script execution — execute_script() in mcp_server.security."""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.security import (
    _RateLimiter,
    _resolve_venv_interpreter,
    execute_script,
)


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
    @pytest.mark.parametrize(("requested", "expected"), [(999, 300), (-5, 1), (7, 7)])
    async def test_timeout_clamped(self, monkeypatch, requested: int, expected: int) -> None:
        """The timeout handed to wait_for is clamped to 1..300 seconds."""
        import mcp_server.security as sec

        seen: list[float] = []
        real_wait_for = asyncio.wait_for

        async def spy(awaitable, timeout=None):
            seen.append(timeout)
            return await real_wait_for(awaitable, timeout)

        monkeypatch.setattr(sec.asyncio, "wait_for", spy)
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc),
        ):
            result = await execute_script("print('ok')", timeout=requested)
        assert result["exit_code"] == 0
        assert seen == [expected]


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
            patch("mcp_server.security.log_script_execution") as mock_log,
        ):
            result = await execute_script("print('ok')")
        assert result["exit_code"] == -1
        assert "Rate limit" in result["stderr"]
        mock_log.assert_not_called()


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
            patch("mcp_server.security.log_script_result") as mock_log,
        ):
            await execute_script("print('ok')")
        mock_log.assert_called_once()
        args = mock_log.call_args
        assert args[0][0] == "python"  # language
        assert args[0][1] == 0  # exit_code


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


class TestScriptPythonInterpreter:
    @pytest.mark.asyncio
    async def test_python_scripts_use_sys_executable(self) -> None:
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc) as mock_exec,
        ):
            await execute_script("print('ok')", language="python")
        call_args = mock_exec.call_args[0]
        assert call_args[0] == sys.executable

    @pytest.mark.asyncio
    async def test_scripts_use_devnull_stdin(self) -> None:
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc) as mock_exec,
        ):
            await execute_script("print('ok')", language="python")
        assert mock_exec.call_args.kwargs["stdin"] == asyncio.subprocess.DEVNULL


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


class TestScriptVenvParam:
    @pytest.mark.asyncio
    async def test_valid_venv_used(self, tmp_path) -> None:
        """A valid venv resolves to its python and is used as interpreter."""
        venv_dir = tmp_path / "testvenv" / "bin"
        venv_dir.mkdir(parents=True)
        python_bin = venv_dir / "python"
        python_bin.touch()
        python_bin.chmod(0o755)

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
        """venv=None falls back to sys.executable."""
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc) as mock_exec,
        ):
            result = await execute_script("print('ok')", venv=None)
        assert result["exit_code"] == 0
        call_args = mock_exec.call_args[0]
        assert call_args[0] == sys.executable


class TestScriptEncodingAndErrors:
    @pytest.mark.asyncio
    async def test_unencodable_code_returns_structured_error(self) -> None:
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch("mcp_server.security.log_script_execution") as logged,
        ):
            result = await execute_script("print('\ud800')")
        assert result["exit_code"] == -1
        assert "not valid UTF-8" in result["stderr"]
        logged.assert_not_called()

    @pytest.mark.asyncio
    async def test_mkstemp_failure_returns_structured_error(self) -> None:
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch("mcp_server.security.tempfile.mkstemp", side_effect=OSError("No space left on device")),
        ):
            result = await execute_script("print('ok')")
        assert result["exit_code"] == -1
        assert "No space left" in result["stderr"]

    @pytest.mark.asyncio
    async def test_rate_limited_script_is_audited_as_blocked(self) -> None:
        import mcp_server.security as mod

        mod._rate_limiter = _RateLimiter(max_concurrent=5, max_per_minute=0)
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            patch("mcp_server.security.log_blocked") as blocked,
        ):
            result = await execute_script("print('ok')")
        assert result["exit_code"] == -1
        blocked.assert_called_once()
        assert "Rate limit" in blocked.call_args.kwargs["reason"]


posix_only = pytest.mark.skipif(os.name == "nt", reason="process groups and bash are POSIX-only")


@posix_only
class TestRealSubprocess:
    """No mocks: the real spawn, timeout, group kill and environment paths."""

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    @staticmethod
    async def _wait_gone(pid: int, seconds: float = 3.0) -> bool:
        deadline = asyncio.get_running_loop().time() + seconds
        while asyncio.get_running_loop().time() < deadline:
            if not TestRealSubprocess._alive(pid):
                return True
            await asyncio.sleep(0.05)
        return False

    @pytest.mark.asyncio
    async def test_timeout_kills_grandchild_and_returns_partial_output(self, tmp_path) -> None:
        pidfile = tmp_path / "pid"
        code = f"echo partial\nsleep 300 &\necho $! > {pidfile}\nwait\n"
        with patch("mcp_server.security._allow_scripts", return_value=True):
            result = await execute_script(code, language="bash", timeout=1, working_dir=str(tmp_path))
        assert result["exit_code"] == -1
        assert "timed out" in result["stderr"]
        assert "partial" in result["stdout"]
        pid = int(pidfile.read_text())
        assert await self._wait_gone(pid), "grandchild survived the timeout"

    @pytest.mark.asyncio
    async def test_detached_background_process_is_killed_after_normal_exit(self, tmp_path) -> None:
        pidfile = tmp_path / "pid"
        code = f"sleep 300 >/dev/null 2>&1 &\necho $! > {pidfile}\necho done\n"
        with patch("mcp_server.security._allow_scripts", return_value=True):
            result = await execute_script(code, language="bash", timeout=20, working_dir=str(tmp_path))
        assert result["exit_code"] == 0
        assert "done" in result["stdout"]
        assert await self._wait_gone(int(pidfile.read_text())), "background process outlived the call"

    @pytest.mark.asyncio
    async def test_grandchild_holding_pipes_does_not_cost_the_full_timeout(self, monkeypatch, tmp_path) -> None:
        import mcp_server.security as sec

        monkeypatch.setattr(sec, "_DRAIN_GRACE_SECONDS", 0.3)
        loop = asyncio.get_running_loop()
        started = loop.time()
        with patch("mcp_server.security._allow_scripts", return_value=True):
            result = await execute_script(
                "echo finished\nsleep 300 &\n", language="bash", timeout=60, working_dir=str(tmp_path)
            )
        assert loop.time() - started < 15
        assert result["exit_code"] == 0
        assert "finished" in result["stdout"]

    @pytest.mark.asyncio
    async def test_script_environment_is_scrubbed(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("SECRET_TOKEN", "do-not-leak")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "do-not-leak")
        monkeypatch.setenv("BENIGN_SETTING", "kept")
        with patch("mcp_server.security._allow_scripts", return_value=True):
            result = await execute_script("env\n", language="bash", working_dir=str(tmp_path))
        assert result["exit_code"] == 0
        assert "SECRET_TOKEN" not in result["stdout"]
        assert "AWS_ACCESS_KEY_ID" not in result["stdout"]
        assert "do-not-leak" not in result["stdout"]
        assert "BENIGN_SETTING=kept" in result["stdout"]

    @pytest.mark.asyncio
    async def test_spawn_uses_new_session_and_scrubbed_env(self, monkeypatch) -> None:
        monkeypatch.setenv("PLANTED_TOKEN", "x")
        proc = _make_proc(b"ok\n")
        with (
            patch("mcp_server.security._allow_scripts", return_value=True),
            _patch_exec(proc) as spawn,
        ):
            await execute_script("print('ok')")
        kwargs = spawn.call_args.kwargs
        assert kwargs["start_new_session"] is True
        assert "PLANTED_TOKEN" not in kwargs["env"]
