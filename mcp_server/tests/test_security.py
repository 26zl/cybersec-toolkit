"""Tests for mcp_server.security — argument sanitization, policy, and execution."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.security import (
    _is_safe_target,
    check_policy,
    execute_tool,
    sanitize_args,
    validate_tool_for_execution,
)


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
        assert sanitize_args(None) == []

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
