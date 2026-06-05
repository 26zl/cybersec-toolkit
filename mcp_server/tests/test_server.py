"""Tests for mcp_server.server tool-level wiring."""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import pytest

from mcp_server import server


@pytest.mark.asyncio
async def test_manage_remote_hosts_test_logs_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful SSH test returns ``success`` and must log success too."""
    remote = Mock()
    remote.get_ssh_base_args.return_value = ["kali@10.0.0.5"]
    monkeypatch.setattr(server, "_remote", remote)
    monkeypatch.setattr(
        server,
        "check_ssh_connection",
        AsyncMock(return_value={"success": True, "message": "SSH connection successful"}),
    )

    with (
        patch("mcp_server.server.log_remote_op") as log_remote_op,
        patch("mcp_server.server.log_tool_result") as log_tool_result,
    ):
        result = await server.manage_remote_hosts("test", name="kali-vm")

    assert result["success"] is True
    log_remote_op.assert_called_once_with("test", host="kali-vm", detail="connected")
    assert log_tool_result.call_args.args[2] is True
