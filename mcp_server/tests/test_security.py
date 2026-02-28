"""Tests for mcp_server.security — argument sanitization, policy, and execution."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.security import (
    SYSTEM_UTILITIES,
    _is_safe_target,
    _RateLimiter,
    check_policy,
    execute_pipeline,
    execute_tool,
    execute_tool_remote,
    sanitize_args,
    validate_tool_for_execution,
    validate_tool_for_remote_execution,
)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset the global rate limiter before each test."""
    import mcp_server.security as mod

    mod._rate_limiter = _RateLimiter()
    yield
    mod._rate_limiter = _RateLimiter()


# ---------------------------------------------------------------------------
# _is_safe_target
# ---------------------------------------------------------------------------
class TestIsSafeTarget:
    """Target validation for private/local network ranges."""

    @pytest.mark.parametrize(
        "ip",
        ["127.0.0.1", "10.0.0.1", "10.255.255.255", "192.168.1.1", "172.16.0.1", "172.31.255.255", "169.254.1.1"],
    )
    def test_private_ipv4(self, ip: str) -> None:
        assert _is_safe_target(ip) is True

    @pytest.mark.parametrize("ip", ["::1", "fc00::1", "fe80::1"])
    def test_private_ipv6(self, ip: str) -> None:
        assert _is_safe_target(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
    def test_public_ipv4_blocked(self, ip: str) -> None:
        assert _is_safe_target(ip) is False

    @pytest.mark.parametrize("ip", ["2001:4860:4860::8888"])
    def test_public_ipv6_blocked(self, ip: str) -> None:
        assert _is_safe_target(ip) is False

    def test_private_cidr(self) -> None:
        assert _is_safe_target("10.0.0.0/24") is True
        assert _is_safe_target("192.168.0.0/16") is True

    def test_public_cidr_blocked(self) -> None:
        assert _is_safe_target("8.8.8.0/24") is False

    def test_localhost_hostname(self) -> None:
        assert _is_safe_target("localhost") is True

    def test_flags_and_paths_passthrough(self) -> None:
        assert _is_safe_target("-v") is True
        assert _is_safe_target("--output") is True
        assert _is_safe_target("/tmp/results.txt") is True
        assert _is_safe_target("./local_file") is True

    def test_empty_string(self) -> None:
        # Empty string should not crash; it's not a valid target
        result = _is_safe_target("")
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# sanitize_args
# ---------------------------------------------------------------------------
class TestSanitizeArgs:
    def test_normal_args(self) -> None:
        assert sanitize_args("-sV --top-ports 100 10.0.0.1") == ["-sV", "--top-ports", "100", "10.0.0.1"]

    def test_quoted_args(self) -> None:
        assert sanitize_args('--header "X-Custom: value"') == ["--header", "X-Custom: value"]

    def test_empty_string(self) -> None:
        assert sanitize_args("") == []

    def test_whitespace_only(self) -> None:
        assert sanitize_args("   ") == []

    def test_none_input(self) -> None:
        assert sanitize_args(None) == []  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "malicious",
        [
            "test; rm -rf /",
            "target & whoami",
            "host | cat /etc/passwd",
            "arg `id`",
            "file $(whoami)",
            "out > /tmp/evil",
            "in < /etc/shadow",
        ],
    )
    def test_shell_injection_blocked(self, malicious: str) -> None:
        with pytest.raises(ValueError, match="blocked shell metacharacters"):
            sanitize_args(malicious)


# ---------------------------------------------------------------------------
# check_policy
# ---------------------------------------------------------------------------
class TestCheckPolicy:
    def test_blocked_flag_delete(self) -> None:
        with pytest.raises(ValueError, match="--delete"):
            check_policy("nmap", ["--delete"])

    def test_blocked_flag_exploit(self) -> None:
        with pytest.raises(ValueError, match="--exploit"):
            check_policy("sqlmap", ["--exploit"])

    def test_blocked_flag_rf(self) -> None:
        with pytest.raises(ValueError, match="-rf"):
            check_policy("nmap", ["-rf"])

    def test_normal_flags_allowed(self) -> None:
        check_policy("nmap", ["-sV", "10.0.0.1"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_network_tool_private_target_allowed(self) -> None:
        check_policy("nmap", ["-sV", "10.0.0.1"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_network_tool_external_target_blocked(self) -> None:
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("nmap", ["-sV", "8.8.8.8"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", True)
    def test_network_tool_external_allowed_with_env(self) -> None:
        check_policy("nmap", ["-sV", "8.8.8.8"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_non_network_tool_any_target(self) -> None:
        # hashcat is not a network tool — targets not checked
        check_policy("hashcat", ["--attack-mode", "0", "hashes.txt", "wordlist.txt"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_network_tool_target_flag(self) -> None:
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("nmap", ["-t", "8.8.8.8"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_network_tool_url_target(self) -> None:
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("sqlmap", ["-u", "http://example.com/page?id=1"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_network_tool_localhost_url_allowed(self) -> None:
        check_policy("sqlmap", ["-u", "http://127.0.0.1/page?id=1"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_single_label_hostname_blocked(self) -> None:
        """Single-label hostnames like 'google' must not bypass target validation."""
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("nmap", ["google"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_single_label_scanme_blocked(self) -> None:
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("nmap", ["scanme"])

    def test_sqlmap_os_shell_blocked(self) -> None:
        with pytest.raises(ValueError, match="sqlmap: OS shell access"):
            check_policy("sqlmap", ["--os-shell"])

    def test_sqlmap_file_read_blocked(self) -> None:
        with pytest.raises(ValueError, match="sqlmap: arbitrary file read"):
            check_policy("sqlmap", ["--file-read"])

    def test_nmap_iL_blocked(self) -> None:
        with pytest.raises(ValueError, match="nmap: target list from file"):
            check_policy("nmap", ["-iL"])

    def test_masscan_includefile_blocked(self) -> None:
        with pytest.raises(ValueError, match="masscan: target list from file"):
            check_policy("masscan", ["--includefile"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_long_flag_value_not_treated_as_target(self) -> None:
        """Values of --long-flags must not be treated as network targets."""
        # --script vuln: "vuln" is a script name, not a target
        check_policy("nmap", ["--script", "vuln", "10.0.0.1"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_long_flag_value_with_external_target_still_blocked(self) -> None:
        """The actual target after a --flag value pair must still be validated."""
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("nmap", ["--script", "vuln", "8.8.8.8"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_short_t_flag_not_treated_as_target_flag(self) -> None:
        """-t is ambiguous (template in nuclei, threads in ffuf) and must not
        cause its value to be validated as a network target."""
        check_policy("nuclei", ["-t", "cves/", "-u", "http://10.0.0.1/"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_explicit_target_flags_still_validated(self) -> None:
        """Unambiguous target flags (--target, -u, --url) must still be validated."""
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("sqlmap", ["-u", "http://example.com/page?id=1"])


# ---------------------------------------------------------------------------
# _RateLimiter
# ---------------------------------------------------------------------------
class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_rate_limit_exceeded(self) -> None:
        limiter = _RateLimiter(max_concurrent=100, max_per_minute=5)
        for _ in range(5):
            await limiter.acquire()
        with pytest.raises(ValueError, match="Rate limit exceeded"):
            await limiter.acquire()

    @pytest.mark.asyncio
    async def test_concurrent_limit(self) -> None:
        limiter = _RateLimiter(max_concurrent=2, max_per_minute=100)
        # Acquire 2 semaphore slots
        await limiter._semaphore.acquire()
        await limiter._semaphore.acquire()
        # Third should not be acquirable immediately
        acquired = limiter._semaphore._value
        assert acquired == 0


# ---------------------------------------------------------------------------
# Validation failure audit logging
# ---------------------------------------------------------------------------
class TestValidationFailureLogged:
    @pytest.mark.asyncio
    async def test_validation_failure_logged(self, tools_db) -> None:
        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("mcp_server.security._ALLOW_EXTERNAL", False),
            patch("mcp_server.security.log_blocked") as mock_log_blocked,
            patch("mcp_server.security._rate_limiter", _RateLimiter()),
        ):
            result = await execute_tool("nmap", "-sV 8.8.8.8", tools_db)
        assert result["exit_code"] == -1
        mock_log_blocked.assert_called_once()
        call_kwargs = mock_log_blocked.call_args
        assert (
            "blocked" in call_kwargs.kwargs.get("reason", call_kwargs[1].get("reason", "")).lower()
            or "not in a private" in call_kwargs.kwargs.get("reason", call_kwargs[1].get("reason", "")).lower()
        )


# ---------------------------------------------------------------------------
# validate_tool_for_execution
# ---------------------------------------------------------------------------
class TestValidateToolForExecution:
    def test_valid_tool(self, tools_db) -> None:
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            binary = validate_tool_for_execution("nmap", tools_db)
        assert binary == "nmap"

    def test_non_executable_method(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not directly executable"):
            validate_tool_for_execution("ghidra", tools_db)

    def test_docker_method_non_executable(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not directly executable"):
            validate_tool_for_execution("BeEF", tools_db)

    def test_missing_binary(self, tools_db) -> None:
        with patch("shutil.which", return_value=None):
            with pytest.raises(ValueError, match="not installed or not in PATH"):
                validate_tool_for_execution("nmap", tools_db)

    def test_unknown_tool(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("nonexistent_tool", tools_db)

    def test_pipx_binary_name_mapping(self, tools_db) -> None:
        with patch("shutil.which", return_value="/usr/local/bin/sherlock"):
            binary = validate_tool_for_execution("sherlock-project", tools_db)
        assert binary == "sherlock"


# ---------------------------------------------------------------------------
# execute_tool (async, mocked subprocess)
# ---------------------------------------------------------------------------
class TestExecuteTool:
    @pytest.mark.asyncio
    async def test_successful_execution(self, tools_db) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"scan results\n", b"")
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await execute_tool("nmap", "-sV 10.0.0.1", tools_db)

        assert result["exit_code"] == 0
        assert result["stdout"] == "scan results\n"
        assert result["stderr"] == ""
        assert result["truncated"] is False

    @pytest.mark.asyncio
    async def test_timeout(self, tools_db) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate.side_effect = asyncio.TimeoutError()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await execute_tool("nmap", "-sV 10.0.0.1", tools_db, timeout=1)

        assert result["exit_code"] == -1
        assert "timed out" in result["stderr"]

    @pytest.mark.asyncio
    async def test_output_truncation(self, tools_db) -> None:
        big_output = b"A" * 60000
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (big_output, b"")
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await execute_tool("nmap", "10.0.0.1", tools_db, max_output=50000)

        assert result["truncated"] is True
        assert len(result["stdout"]) <= 50000

    @pytest.mark.asyncio
    async def test_validation_failure_returns_error(self, tools_db) -> None:
        result = await execute_tool("nonexistent_tool", "", tools_db)
        assert result["exit_code"] == -1
        assert "not found" in result["stderr"]

    @pytest.mark.asyncio
    async def test_shell_injection_returns_error(self, tools_db) -> None:
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            result = await execute_tool("nmap", "10.0.0.1; rm -rf /", tools_db)
        assert result["exit_code"] == -1
        assert "blocked shell metacharacters" in result["stderr"]

    @pytest.mark.asyncio
    async def test_policy_violation_returns_error(self, tools_db) -> None:
        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("mcp_server.security._ALLOW_EXTERNAL", False),
        ):
            result = await execute_tool("nmap", "-sV 8.8.8.8", tools_db)
        assert result["exit_code"] == -1
        assert "not in a private/local" in result["stderr"]


# ---------------------------------------------------------------------------
# validate_tool_for_remote_execution
# ---------------------------------------------------------------------------
class TestValidateToolForRemoteExecution:
    def test_valid_tool(self, tools_db) -> None:
        binary = validate_tool_for_remote_execution("nmap", tools_db)
        assert binary == "nmap"

    def test_non_executable_method(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not directly executable"):
            validate_tool_for_remote_execution("ghidra", tools_db)

    def test_docker_method_non_executable(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not directly executable"):
            validate_tool_for_remote_execution("BeEF", tools_db)

    def test_unknown_tool(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_remote_execution("nonexistent_tool", tools_db)

    def test_pipx_binary_name_mapping(self, tools_db) -> None:
        # Should resolve without needing shutil.which
        binary = validate_tool_for_remote_execution("sherlock-project", tools_db)
        assert binary == "sherlock"

    def test_does_not_require_local_install(self, tools_db) -> None:
        # Even with which returning None, remote validation should succeed
        with patch("shutil.which", return_value=None):
            binary = validate_tool_for_remote_execution("nmap", tools_db)
        assert binary == "nmap"


# ---------------------------------------------------------------------------
# execute_tool_remote (async, mocked subprocess)
# ---------------------------------------------------------------------------
class TestExecuteToolRemote:
    @pytest.mark.asyncio
    async def test_successful_remote_execution(self, tools_db, remote_config) -> None:
        remote_config.add_host(name="kali", hostname="10.0.0.5")
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"remote results\n", b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await execute_tool_remote("nmap", "-sV 10.0.0.1", tools_db, remote_config, "kali")

        assert result["exit_code"] == 0
        assert result["stdout"] == "remote results\n"
        assert result["remote"] is True

    @pytest.mark.asyncio
    async def test_validation_failure(self, tools_db, remote_config) -> None:
        result = await execute_tool_remote("nonexistent_tool", "", tools_db, remote_config, "kali")
        assert result["exit_code"] == -1
        assert "not found" in result["stderr"]
        assert result["remote"] is True

    @pytest.mark.asyncio
    async def test_shell_injection_blocked(self, tools_db, remote_config) -> None:
        remote_config.add_host(name="kali", hostname="10.0.0.5")
        result = await execute_tool_remote("nmap", "10.0.0.1; rm -rf /", tools_db, remote_config, "kali")
        assert result["exit_code"] == -1
        assert "blocked shell metacharacters" in result["stderr"]
        assert result["remote"] is True

    @pytest.mark.asyncio
    async def test_policy_violation(self, tools_db, remote_config) -> None:
        remote_config.add_host(name="kali", hostname="10.0.0.5")
        with patch("mcp_server.security._ALLOW_EXTERNAL", False):
            result = await execute_tool_remote("nmap", "-sV 8.8.8.8", tools_db, remote_config, "kali")
        assert result["exit_code"] == -1
        assert "not in a private/local" in result["stderr"]
        assert result["remote"] is True

    @pytest.mark.asyncio
    async def test_unknown_host(self, tools_db, remote_config) -> None:
        result = await execute_tool_remote("nmap", "--version", tools_db, remote_config, "nonexistent")
        assert result["exit_code"] == -1
        assert "not found" in result["stderr"]
        assert result["remote"] is True

    @pytest.mark.asyncio
    async def test_non_executable_method_blocked(self, tools_db, remote_config) -> None:
        remote_config.add_host(name="kali", hostname="10.0.0.5")
        result = await execute_tool_remote("ghidra", "", tools_db, remote_config, "kali")
        assert result["exit_code"] == -1
        assert "not directly executable" in result["stderr"]
        assert result["remote"] is True

    @pytest.mark.asyncio
    async def test_remote_execution_blocked_by_allowlist(self, tools_db, remote_config) -> None:
        remote_config.add_host(name="kali", hostname="10.0.0.5", tool_allowlist=["gobuster"])
        result = await execute_tool_remote("nmap", "--version", tools_db, remote_config, "kali")
        assert result["exit_code"] == -1
        assert "not in the allowlist" in result["stderr"]
        assert result["remote"] is True


# ---------------------------------------------------------------------------
# Output sanitization integration
# ---------------------------------------------------------------------------
class TestOutputSanitization:
    @pytest.mark.asyncio
    async def test_execute_tool_output_sanitized(self, tools_db) -> None:
        """ANSI codes in stdout are stripped after execute_tool."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"\x1b[31mresults\x1b[0m\n", b"")
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("mcp_server.security.log_execution"),
        ):
            result = await execute_tool("nmap", "--version", tools_db)

        assert "\x1b[" not in result["stdout"]
        assert "results" in result["stdout"]

    @pytest.mark.asyncio
    async def test_execute_tool_remote_output_sanitized(self, tools_db, remote_config) -> None:
        """ANSI codes in remote stdout are stripped after execute_tool_remote."""
        remote_config.add_host(name="kali", hostname="10.0.0.5")
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"\x1b[32mremote\x1b[0m\n", b"")
        mock_proc.returncode = 0

        with (
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
            patch("mcp_server.security.log_execution"),
        ):
            result = await execute_tool_remote("nmap", "-sV 10.0.0.1", tools_db, remote_config, "kali")

        assert "\x1b[" not in result["stdout"]
        assert "remote" in result["stdout"]


# ---------------------------------------------------------------------------
# System utility validation
# ---------------------------------------------------------------------------
class TestSystemUtilityValidation:
    """System utilities bypass registry but still need PATH."""

    def test_system_utility_validates_without_registry(self, tools_db) -> None:
        """'cat' is not in tools_config.json but is in SYSTEM_UTILITIES — OK if in PATH."""
        with patch("shutil.which", return_value="/bin/cat"):
            binary = validate_tool_for_execution("cat", tools_db)
        assert binary == "cat"

    def test_system_utility_not_in_path_rejected(self, tools_db) -> None:
        """System utility not found in PATH raises ValueError."""
        with patch("shutil.which", return_value=None):
            with pytest.raises(ValueError, match="not installed or not in PATH"):
                validate_tool_for_execution("xxd", tools_db)

    def test_unknown_tool_still_rejected(self, tools_db) -> None:
        """'evil_tool' not in registry or SYSTEM_UTILITIES → ValueError."""
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("evil_tool", tools_db)

    def test_dangerous_command_not_in_system_utilities(self) -> None:
        """Dangerous commands must never appear in SYSTEM_UTILITIES."""
        dangerous = {"rm", "rmdir", "dd", "mkfs", "kill", "pkill", "killall",
                      "chmod", "chown", "chgrp", "shutdown", "reboot", "halt",
                      "poweroff", "fdisk", "wipefs", "shred", "su", "sudo",
                      "mount", "umount", "iptables", "useradd", "userdel",
                      "passwd", "crontab"}
        for cmd in dangerous:
            assert cmd not in SYSTEM_UTILITIES, f"{cmd} should NOT be in SYSTEM_UTILITIES"

    def test_interpreters_not_in_system_utilities(self) -> None:
        """Scripting interpreters must not be in SYSTEM_UTILITIES — they allow arbitrary code exec."""
        interpreters = {"python3", "python", "perl", "ruby", "node", "php",
                        "bash", "sh", "zsh"}
        for cmd in interpreters:
            assert cmd not in SYSTEM_UTILITIES, f"{cmd} should NOT be in SYSTEM_UTILITIES"

    def test_meta_exec_not_in_system_utilities(self) -> None:
        """Meta-execution tools must not be in SYSTEM_UTILITIES — they run other commands."""
        meta_exec = {"timeout", "xargs", "parallel", "find"}
        for cmd in meta_exec:
            assert cmd not in SYSTEM_UTILITIES, f"{cmd} should NOT be in SYSTEM_UTILITIES"


class TestSystemUtilityExecution:
    """System utilities can be executed through execute_tool."""

    @pytest.mark.asyncio
    async def test_execute_system_utility(self, tools_db) -> None:
        """Mock PATH + subprocess, verify 'cat' executes."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"hello world\n", b"")
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/bin/cat"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await execute_tool("cat", "/dev/null", tools_db)

        assert result["exit_code"] == 0
        assert "hello world" in result["stdout"]

    @pytest.mark.asyncio
    async def test_system_utility_policy_applied(self, tools_db) -> None:
        """check_policy still runs for system utilities — blocked flags caught."""
        with patch("shutil.which", return_value="/bin/cat"):
            result = await execute_tool("cat", "--delete", tools_db)
        assert result["exit_code"] == -1
        assert "Blocked by policy" in result["stderr"]


class TestSystemUtilityNetworkPolicy:
    """Network system utilities get target validation."""

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_curl_external_blocked(self) -> None:
        """curl http://evil.com → blocked (curl is in _NETWORK_TOOLS)."""
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("curl", ["http://example.com/"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_curl_local_allowed(self) -> None:
        """curl http://10.0.0.1/ → allowed."""
        check_policy("curl", ["http://10.0.0.1/"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_ping_external_blocked(self) -> None:
        """ping 8.8.8.8 → blocked."""
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("ping", ["8.8.8.8"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_ping_local_allowed(self) -> None:
        """ping 10.0.0.1 → allowed."""
        check_policy("ping", ["10.0.0.1"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_wget_external_blocked(self) -> None:
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("wget", ["http://example.com/file"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_dig_external_blocked(self) -> None:
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("dig", ["example.com"])


class TestSystemUtilityRemote:
    """System utilities validate for remote execution without PATH check."""

    def test_remote_system_utility_validates(self, tools_db) -> None:
        """validate_tool_for_remote_execution('cat', db) → 'cat' (no PATH check)."""
        binary = validate_tool_for_remote_execution("cat", tools_db)
        assert binary == "cat"

    def test_remote_system_utility_no_local_path_needed(self, tools_db) -> None:
        """Even with which returning None, remote validation succeeds for system utils."""
        with patch("shutil.which", return_value=None):
            binary = validate_tool_for_remote_execution("strings", tools_db)
        assert binary == "strings"

    def test_remote_unknown_tool_rejected(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_remote_execution("evil_tool", tools_db)


class TestDangerousCommandExclusion:
    """Dangerous commands must be rejected — not in SYSTEM_UTILITIES, not in registry."""

    def test_rm_not_allowed(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("rm", tools_db)

    def test_dd_not_allowed(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("dd", tools_db)

    def test_sudo_not_allowed(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("sudo", tools_db)

    def test_kill_not_allowed(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("kill", tools_db)

    def test_chmod_not_allowed(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("chmod", tools_db)

    def test_bash_not_allowed(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("bash", tools_db)

    def test_python3_not_allowed(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("python3", tools_db)

    def test_xargs_not_allowed(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("xargs", tools_db)

    def test_find_not_allowed(self, tools_db) -> None:
        with pytest.raises(ValueError, match="not found in tools_config.json"):
            validate_tool_for_execution("find", tools_db)


class TestBooleanFlagBypass:
    """Boolean flags must not consume the next token, hiding it from target validation."""

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_boolean_flag_does_not_hide_target(self) -> None:
        """nmap --open evil.com must still validate evil.com as a target."""
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("nmap", ["--open", "8.8.8.8"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_boolean_flag_silent_does_not_hide_target(self) -> None:
        """curl --silent evil.com must still validate evil.com."""
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("curl", ["--silent", "http://example.com/"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_boolean_flag_verbose_does_not_hide_target(self) -> None:
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("nmap", ["-sV", "--reason", "8.8.8.8"])

    @patch("mcp_server.security._ALLOW_EXTERNAL", False)
    def test_known_target_flag_still_works(self) -> None:
        """Explicit target flags like -u still consume their value correctly."""
        with pytest.raises(ValueError, match="not in a private/local"):
            check_policy("sqlmap", ["-u", "http://example.com/page?id=1"])


# ---------------------------------------------------------------------------
# execute_pipeline
# ---------------------------------------------------------------------------
class TestExecutePipeline:
    """Pipeline execution — safe stdin piping between tools."""

    @pytest.mark.asyncio
    async def test_two_step_pipeline(self, tools_db) -> None:
        """strings + grep pipeline returns filtered output."""
        mock_proc1 = AsyncMock()
        mock_proc1.communicate.return_value = (b"flag{abc}\nother\n", b"")
        mock_proc1.returncode = 0

        mock_proc2 = AsyncMock()
        mock_proc2.communicate.return_value = (b"flag{abc}\n", b"")
        mock_proc2.returncode = 0

        procs = [mock_proc1, mock_proc2]
        call_count = 0

        async def fake_exec(*args, **kwargs):
            nonlocal call_count
            p = procs[call_count]
            call_count += 1
            return p

        with (
            patch("shutil.which", return_value="/usr/bin/fake"),
            patch("asyncio.create_subprocess_exec", side_effect=fake_exec),
        ):
            result = await execute_pipeline(
                [{"tool": "strings", "args": "./binary"}, {"tool": "grep", "args": "flag"}],
                tools_db,
            )

        assert result["exit_code"] == 0
        assert "flag{abc}" in result["stdout"]
        assert result["step_count"] == 2
        assert len(result["commands"]) == 2

    @pytest.mark.asyncio
    async def test_empty_steps_rejected(self, tools_db) -> None:
        result = await execute_pipeline([], tools_db)
        assert result["exit_code"] == -1
        assert "at least 1 step" in result["stderr"]

    @pytest.mark.asyncio
    async def test_too_many_steps_rejected(self, tools_db) -> None:
        steps = [{"tool": "cat", "args": "/dev/null"}] * 11
        with patch("shutil.which", return_value="/usr/bin/fake"):
            result = await execute_pipeline(steps, tools_db)
        assert result["exit_code"] == -1
        assert "max 10 steps" in result["stderr"]

    @pytest.mark.asyncio
    async def test_invalid_tool_in_step_rejected(self, tools_db) -> None:
        """bash in step 2 is not in SYSTEM_UTILITIES → rejected before execution."""
        steps = [{"tool": "cat", "args": "/dev/null"}, {"tool": "bash", "args": "-c id"}]
        with patch("shutil.which", return_value="/usr/bin/fake"):
            result = await execute_pipeline(steps, tools_db)
        assert result["exit_code"] == -1
        assert "Step 2" in result["stderr"]

    @pytest.mark.asyncio
    async def test_shell_injection_in_step_blocked(self, tools_db) -> None:
        steps = [{"tool": "cat", "args": "file; rm -rf /"}]
        with patch("shutil.which", return_value="/usr/bin/fake"):
            result = await execute_pipeline(steps, tools_db)
        assert result["exit_code"] == -1
        assert "blocked shell metacharacters" in result["stderr"]

    @pytest.mark.asyncio
    async def test_policy_violation_in_step_blocked(self, tools_db) -> None:
        """nmap 8.8.8.8 in a pipeline step → blocked by policy."""
        steps = [{"tool": "nmap", "args": "8.8.8.8"}]
        with (
            patch("shutil.which", return_value="/usr/bin/nmap"),
            patch("mcp_server.security._ALLOW_EXTERNAL", False),
        ):
            result = await execute_pipeline(steps, tools_db)
        assert result["exit_code"] == -1
        assert "not in a private/local" in result["stderr"]

    @pytest.mark.asyncio
    async def test_step_failure_stops_pipeline(self, tools_db) -> None:
        """Step 1 exit=1 → step 2 is never started."""
        mock_proc1 = AsyncMock()
        mock_proc1.communicate.return_value = (b"", b"error\n")
        mock_proc1.returncode = 1

        with (
            patch("shutil.which", return_value="/usr/bin/fake"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc1),
        ):
            result = await execute_pipeline(
                [{"tool": "cat", "args": "missing"}, {"tool": "grep", "args": "x"}],
                tools_db,
            )

        assert result["exit_code"] == 1
        assert result["failed_step"] == 1
        assert result["step_count"] == 1

    @pytest.mark.asyncio
    async def test_pipeline_timeout(self, tools_db) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate.side_effect = asyncio.TimeoutError()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with (
            patch("shutil.which", return_value="/usr/bin/fake"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await execute_pipeline(
                [{"tool": "cat", "args": "bigfile"}],
                tools_db,
                timeout=1,
            )

        assert result["exit_code"] == -1
        assert "timed out" in result["stderr"]

    @pytest.mark.asyncio
    async def test_stdin_passed_to_second_step(self, tools_db) -> None:
        """Verify second step receives first step's stdout via communicate(input=data)."""
        first_output = b"hello from step 1\n"

        mock_proc1 = AsyncMock()
        mock_proc1.communicate.return_value = (first_output, b"")
        mock_proc1.returncode = 0

        mock_proc2 = AsyncMock()
        mock_proc2.communicate.return_value = (b"filtered\n", b"")
        mock_proc2.returncode = 0

        call_count = 0

        async def fake_exec(*args, **kwargs):
            nonlocal call_count
            p = [mock_proc1, mock_proc2][call_count]
            call_count += 1
            return p

        with (
            patch("shutil.which", return_value="/usr/bin/fake"),
            patch("asyncio.create_subprocess_exec", side_effect=fake_exec),
        ):
            await execute_pipeline(
                [{"tool": "echo", "args": "hello"}, {"tool": "grep", "args": "hello"}],
                tools_db,
            )

        # Second process should have been called with input=first_output
        mock_proc2.communicate.assert_called_once_with(input=first_output)

    @pytest.mark.asyncio
    async def test_first_step_uses_devnull_stdin(self, tools_db) -> None:
        """First step must use DEVNULL for stdin, not PIPE."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"output\n", b"")
        mock_proc.returncode = 0

        exec_kwargs = {}

        async def fake_exec(*args, **kwargs):
            exec_kwargs.update(kwargs)
            return mock_proc

        with (
            patch("shutil.which", return_value="/usr/bin/fake"),
            patch("asyncio.create_subprocess_exec", side_effect=fake_exec),
        ):
            await execute_pipeline(
                [{"tool": "cat", "args": "/dev/null"}],
                tools_db,
            )

        assert exec_kwargs.get("stdin") == asyncio.subprocess.DEVNULL
        # communicate should be called without input (None)
        mock_proc.communicate.assert_called_once_with(input=None)

    @pytest.mark.asyncio
    async def test_output_truncation(self, tools_db) -> None:
        """Final output > 200K gets truncated."""
        big_output = b"A" * 250000
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (big_output, b"")
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/fake"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await execute_pipeline(
                [{"tool": "cat", "args": "bigfile"}],
                tools_db,
                max_output=200000,
            )

        assert result["truncated"] is True
        assert len(result["stdout"]) <= 200000

    @pytest.mark.asyncio
    async def test_output_sanitized(self, tools_db) -> None:
        """ANSI codes in final output are stripped."""
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"\x1b[31mresults\x1b[0m\n", b"")
        mock_proc.returncode = 0

        with (
            patch("shutil.which", return_value="/usr/bin/fake"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await execute_pipeline(
                [{"tool": "cat", "args": "file"}],
                tools_db,
            )

        assert "\x1b[" not in result["stdout"]
        assert "results" in result["stdout"]

    @pytest.mark.asyncio
    async def test_missing_tool_key_rejected(self, tools_db) -> None:
        result = await execute_pipeline([{"args": "hello"}], tools_db)
        assert result["exit_code"] == -1
        assert "missing required 'tool' key" in result["stderr"]

    @pytest.mark.asyncio
    async def test_all_steps_validated_before_execution(self, tools_db) -> None:
        """Step 2 invalid → no subprocess should be created at all."""
        steps = [{"tool": "cat", "args": "/dev/null"}, {"tool": "bash", "args": "-c id"}]

        with (
            patch("shutil.which", return_value="/usr/bin/fake"),
            patch("asyncio.create_subprocess_exec") as mock_exec,
        ):
            result = await execute_pipeline(steps, tools_db)

        assert result["exit_code"] == -1
        assert "Step 2" in result["stderr"]
        mock_exec.assert_not_called()


# ---------------------------------------------------------------------------
# Default value tests
# ---------------------------------------------------------------------------
class TestDefaultValues:
    """Verify defaults were updated for CTF workflow."""

    def test_default_timeout_is_120(self) -> None:
        import inspect
        sig = inspect.signature(execute_tool)
        assert sig.parameters["timeout"].default == 120

    def test_default_max_output_is_200k(self) -> None:
        import inspect
        sig = inspect.signature(execute_tool)
        assert sig.parameters["max_output"].default == 200000

    def test_default_rate_limits(self) -> None:
        limiter = _RateLimiter()
        assert limiter._semaphore._value == 10
        assert limiter._max_per_minute == 60
