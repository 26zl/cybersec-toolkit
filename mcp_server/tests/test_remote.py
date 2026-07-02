"""Tests for mcp_server.remote — SSH host config, connection testing, and remote execution."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.remote import (
    RemoteHostConfig,
    check_ssh_connection,
    execute_remote_command,
)


# RemoteHostConfig
class TestRemoteHostConfig:
    def test_add_host(self, remote_config: RemoteHostConfig) -> None:
        entry = remote_config.add_host(
            name="kali-vm",
            hostname="192.168.1.50",
            user="kali",
            port=22,
            ssh_key="~/.ssh/id_kali",
            description="Lokal Kali VM",
        )
        assert entry["hostname"] == "192.168.1.50"
        assert entry["user"] == "kali"
        assert entry["port"] == 22
        assert entry["ssh_key"] == "~/.ssh/id_kali"
        assert entry["description"] == "Lokal Kali VM"

    def test_add_host_persists(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="box1", hostname="10.0.0.5")
        # Reload from disk
        reloaded = RemoteHostConfig(config_path=remote_config._path)
        hosts = reloaded.list_hosts()
        assert "box1" in hosts
        assert hosts["box1"]["hostname"] == "10.0.0.5"

    def test_save_uses_mode_0600(self, remote_config: RemoteHostConfig) -> None:
        """Config file must not be world/group-readable — it holds hostnames and key paths."""
        import stat

        remote_config.add_host(name="box1", hostname="10.0.0.5", ssh_key="~/.ssh/id_kali")
        mode = remote_config._path.stat().st_mode & 0o777
        # Owner rw only; no group/other read. (Skipped on Windows where POSIX modes don't apply.)
        if hasattr(stat, "S_IRWXG"):
            import sys as _sys

            if not _sys.platform.startswith("win"):
                assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_save_is_atomic_no_tmp_leftover(self, remote_config: RemoteHostConfig) -> None:
        """After a successful save, the config dir contains only the target file."""
        remote_config.add_host(name="box1", hostname="10.0.0.5")
        # Any leftover .tmp files would indicate a non-atomic write that crashed.
        leftovers = [p for p in remote_config._path.parent.iterdir() if p.name.endswith(".tmp")]
        assert leftovers == [], f"unexpected tmp files: {leftovers}"

    def test_save_does_not_lose_data_on_rename_race(self, remote_config: RemoteHostConfig) -> None:
        """Back-to-back saves don't corrupt the file (os.replace is atomic)."""
        for i in range(10):
            remote_config.add_host(name=f"box{i}", hostname=f"10.0.0.{i + 1}")
        reloaded = RemoteHostConfig(config_path=remote_config._path)
        assert len(reloaded.list_hosts()) == 10

    def test_add_host_empty_name_raises(self, remote_config: RemoteHostConfig) -> None:
        with pytest.raises(ValueError, match="name must not be empty"):
            remote_config.add_host(name="", hostname="10.0.0.1")

    def test_add_host_empty_hostname_raises(self, remote_config: RemoteHostConfig) -> None:
        with pytest.raises(ValueError, match="Hostname must not be empty"):
            remote_config.add_host(name="box1", hostname="")

    def test_add_host_invalid_port_raises(self, remote_config: RemoteHostConfig) -> None:
        with pytest.raises(ValueError, match="Port must be"):
            remote_config.add_host(name="box1", hostname="10.0.0.1", port=99999)

    def test_remove_host(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="box1", hostname="10.0.0.5")
        assert remote_config.remove_host("box1") is True
        assert "box1" not in remote_config.list_hosts()

    def test_remove_nonexistent_host(self, remote_config: RemoteHostConfig) -> None:
        assert remote_config.remove_host("nonexistent") is False

    def test_list_hosts_empty(self, remote_config: RemoteHostConfig) -> None:
        assert remote_config.list_hosts() == {}

    def test_list_hosts(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="box1", hostname="10.0.0.5")
        remote_config.add_host(name="box2", hostname="10.0.0.6")
        hosts = remote_config.list_hosts()
        assert len(hosts) == 2
        assert "box1" in hosts
        assert "box2" in hosts

    def test_get_host_not_found(self, remote_config: RemoteHostConfig) -> None:
        assert "nonexistent" not in remote_config.list_hosts()

    def test_get_ssh_base_args(self, remote_config: RemoteHostConfig, tmp_path: Path) -> None:
        key_file = tmp_path / "id_kali"
        key_file.write_text("fake-key")
        remote_config.add_host(
            name="kali-vm",
            hostname="192.168.1.50",
            user="kali",
            port=2222,
            ssh_key=str(key_file),
        )
        args = remote_config.get_ssh_base_args("kali-vm")

        assert "-o" in args
        assert "BatchMode=yes" in args
        assert "ConnectTimeout=10" in args
        assert "StrictHostKeyChecking=accept-new" in args
        assert "-p" in args
        assert "2222" in args
        assert "-i" in args
        assert "kali@192.168.1.50" in args

    def test_get_ssh_base_args_no_key(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="box1", hostname="10.0.0.5", user="root", port=22)
        args = remote_config.get_ssh_base_args("box1")
        assert "-i" not in args
        assert "root@10.0.0.5" in args

    def test_external_host_blocked_by_default(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="public", hostname="8.8.8.8")
        with patch("mcp_server.security._allow_external", return_value=False):
            with pytest.raises(ValueError, match="Blocked by policy"):
                remote_config.get_ssh_base_args("public")

    def test_external_hostname_blocked_by_default(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="public", hostname="example.com")
        with (
            patch("mcp_server.security._allow_external", return_value=False),
            patch("mcp_server.security._is_safe_target", return_value=False),
        ):
            with pytest.raises(ValueError, match="Blocked by policy"):
                remote_config.get_ssh_base_args("public")

    def test_external_host_allowed_after_opt_in(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="public", hostname="8.8.8.8")
        with patch("mcp_server.security._allow_external", return_value=True):
            args = remote_config.get_ssh_base_args("public")
        assert "kali@8.8.8.8" in args

    def test_get_ssh_base_args_unknown_host(self, remote_config: RemoteHostConfig) -> None:
        with pytest.raises(ValueError, match="not found"):
            remote_config.get_ssh_base_args("nonexistent")

    def test_add_host_without_ssh_key(self, remote_config: RemoteHostConfig) -> None:
        entry = remote_config.add_host(name="box1", hostname="10.0.0.5")
        assert "ssh_key" not in entry

    def test_add_host_with_allowlist(self, remote_config: RemoteHostConfig) -> None:
        entry = remote_config.add_host(
            name="kali-vm",
            hostname="192.168.1.50",
            tool_allowlist=["nmap", "gobuster", "sqlmap"],
        )
        assert entry["tool_allowlist"] == ["nmap", "gobuster", "sqlmap"]

    def test_check_tool_allowed(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="box1", hostname="10.0.0.5", tool_allowlist=["nmap", "gobuster"])
        assert remote_config.check_tool_allowed("box1", "nmap") is True

    def test_check_tool_not_allowed(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="box1", hostname="10.0.0.5", tool_allowlist=["nmap", "gobuster"])
        assert remote_config.check_tool_allowed("box1", "sqlmap") is False

    def test_check_tool_allowed_no_list(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(name="box1", hostname="10.0.0.5")
        assert remote_config.check_tool_allowed("box1", "anything") is True

    def test_check_tool_allowed_unknown_host(self, remote_config: RemoteHostConfig) -> None:
        with pytest.raises(ValueError, match="not found"):
            remote_config.check_tool_allowed("nonexistent", "nmap")

    def test_add_host_invalid_hostname_chars(self, remote_config: RemoteHostConfig) -> None:
        with pytest.raises(ValueError, match="Hostname contains invalid characters"):
            remote_config.add_host(name="evil", hostname="-oProxyCommand=evil")

    def test_add_host_invalid_user_chars(self, remote_config: RemoteHostConfig) -> None:
        with pytest.raises(ValueError, match="Username contains invalid characters"):
            remote_config.add_host(name="evil", hostname="10.0.0.1", user="kali -o Evil")

    def test_add_host_valid_ipv6_hostname(self, remote_config: RemoteHostConfig) -> None:
        entry = remote_config.add_host(name="ipv6box", hostname="::1")
        assert entry["hostname"] == "::1"

    def test_ssh_key_not_found_raises(self, remote_config: RemoteHostConfig) -> None:
        remote_config.add_host(
            name="bad-key",
            hostname="10.0.0.1",
            ssh_key="/nonexistent/key_file",
        )
        with pytest.raises(ValueError, match="SSH key file not found") as exc_info:
            remote_config.get_ssh_base_args("bad-key")
        # The configured key path must NOT leak into the error string: it
        # propagates into the audit log and a key path is treated as sensitive.
        assert "/nonexistent/key_file" not in str(exc_info.value)

    def test_corrupt_json_raises_and_backs_up(self, tmp_path: Path) -> None:
        """Corrupt config must fail loudly and preserve the bad file for recovery."""
        config_path = tmp_path / "remote_hosts.json"
        config_path.write_text("NOT VALID JSON {{{", encoding="utf-8")

        with pytest.raises(ValueError, match="not valid JSON"):
            RemoteHostConfig(config_path=config_path)

        # The corrupt file is preserved as a .corrupt.* sibling.
        assert not config_path.exists()
        backups = list(tmp_path.glob("remote_hosts.json.corrupt.*"))
        assert len(backups) == 1
        assert backups[0].read_text() == "NOT VALID JSON {{{"

    def test_non_object_top_level_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / "remote_hosts.json"
        config_path.write_text('["not", "an", "object"]', encoding="utf-8")
        with pytest.raises(ValueError, match="must be a JSON object"):
            RemoteHostConfig(config_path=config_path)

    def test_non_object_hosts_key_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / "remote_hosts.json"
        config_path.write_text('{"hosts": ["a", "b"]}', encoding="utf-8")
        with pytest.raises(ValueError, match="must be an object"):
            RemoteHostConfig(config_path=config_path)

    def test_missing_hosts_key_is_empty(self, tmp_path: Path) -> None:
        """Valid JSON without a 'hosts' key is treated as an empty host table."""
        config_path = tmp_path / "remote_hosts.json"
        config_path.write_text('{"version": 1}', encoding="utf-8")
        cfg = RemoteHostConfig(config_path=config_path)
        assert cfg.list_hosts() == {}


# check_ssh_connection (async, mocked subprocess)
class TestCheckSshConnection:
    @pytest.mark.asyncio
    async def test_successful_connection(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"ok\n", b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await check_ssh_connection(["user@host"])

        assert result["success"] is True
        assert "successful" in result["message"]

    @pytest.mark.asyncio
    async def test_failed_connection(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"Connection refused")
        mock_proc.returncode = 255

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await check_ssh_connection(["user@host"])

        assert result["success"] is False
        assert "failed" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_connection_timeout(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate.side_effect = asyncio.TimeoutError()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await check_ssh_connection(["user@host"], timeout=5)

        assert result["success"] is False
        assert "timed out" in result["message"]

    @pytest.mark.asyncio
    async def test_ssh_not_found(self) -> None:
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
            result = await check_ssh_connection(["user@host"])

        assert result["success"] is False
        assert "not found" in result["message"].lower()


# execute_remote_command (async, mocked subprocess)
class TestExecuteRemoteCommand:
    @pytest.mark.asyncio
    async def test_successful_execution(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"scan results\n", b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await execute_remote_command(["user@host"], ["nmap", "-sV", "10.0.0.1"])

        assert result["exit_code"] == 0
        assert result["stdout"] == "scan results\n"
        assert result["stderr"] == ""
        assert result["truncated"] is False
        assert result["remote"] is True
        assert result["command"] == "nmap -sV 10.0.0.1"

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate.side_effect = asyncio.TimeoutError()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await execute_remote_command(["user@host"], ["nmap", "10.0.0.1"], timeout=1)

        assert result["exit_code"] == -1
        assert "timed out" in result["stderr"]
        assert result["remote"] is True

    @pytest.mark.asyncio
    async def test_output_truncation(self) -> None:
        big_output = b"A" * 60000
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (big_output, b"")
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await execute_remote_command(["user@host"], ["nmap", "10.0.0.1"], max_output=50000)

        assert result["truncated"] is True
        assert len(result["stdout"]) <= 50000
        assert result["remote"] is True

    @pytest.mark.asyncio
    async def test_nonzero_exit_code(self) -> None:
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (b"", b"nmap: command not found\n")
        mock_proc.returncode = 127

        with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
            result = await execute_remote_command(["user@host"], ["nmap", "--version"])

        assert result["exit_code"] == 127
        assert "command not found" in result["stderr"]
        assert result["remote"] is True

    @pytest.mark.asyncio
    async def test_ssh_not_found(self) -> None:
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
            result = await execute_remote_command(["user@host"], ["nmap", "--version"])

        assert result["exit_code"] == -1
        assert "not found" in result["stderr"].lower()
        assert result["remote"] is True


class TestExecuteRemoteCommandOutputBounds:
    """execute_remote_command routes through _bounded_communicate, so remote
    output is memory-capped the same way local execute_tool is."""

    @pytest.mark.asyncio
    async def test_huge_remote_output_truncated(self) -> None:
        """A remote tool producing ~500 KB caps at max_output with the standard marker."""
        import sys as _sys

        # Run python directly (no SSH) — the bridge fixture won't route this
        # through the real bounded reader unless process.stdout is a real stream,
        # so we bypass create_subprocess_exec's patching and call execute_remote_command
        # with ssh args that resolve to local python via side_effect.
        mock_process = await asyncio.create_subprocess_exec(
            _sys.executable,
            "-c",
            "print('A' * 500000, end='')",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def _fake_exec(*args, **kwargs):
            return mock_process

        with patch("asyncio.create_subprocess_exec", side_effect=_fake_exec):
            result = await execute_remote_command(
                ["user@host"],
                ["cat", "bigfile"],
                timeout=10,
                max_output=4096,
            )

        assert result["exit_code"] == 0
        assert result["truncated"] is True
        assert len(result["stdout"].encode("utf-8")) <= 4096 + 64
        assert "[truncated at 4096 bytes]" in result["stdout"]
