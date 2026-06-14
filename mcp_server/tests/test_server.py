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


# ---- C2 gating reflected in MCP output (uses the real registry) ----


def test_get_tool_info_c2_tool_gated_install_and_whole_system_update() -> None:
    info = server.get_tool_info("gophish")
    assert info["requires_include_c2"] is True
    assert "--include-c2" in info["commands"]["install"]
    # update.sh is whole-system — must NOT carry an unsupported --module flag
    assert "--module" not in info["commands"]["update"]
    assert info["commands"]["update"].endswith("./scripts/update.sh")


def test_get_tool_info_c2_docker_needs_enable_docker() -> None:
    info = server.get_tool_info("empire")
    assert info["requires_include_c2"] is True
    assert "--include-c2" in info["commands"]["install"]
    assert "--enable-docker" in info["commands"]["install"]


def test_get_tool_info_non_c2_tool_not_gated() -> None:
    info = server.get_tool_info("nmap")
    assert info["requires_include_c2"] is False
    assert "--include-c2" not in info["commands"]["install"]


def test_get_profile_tools_excludes_c2_when_disabled() -> None:
    from mcp_server.tools_db import C2_TOOLS

    result = server.get_profile_tools("web")  # include_c2 = false
    listed = {t["name"] for m in result["modules"] for t in m["tools"]}
    assert not (listed & C2_TOOLS), f"C2 tools leaked into web profile: {listed & C2_TOOLS}"


def test_get_profile_tools_includes_c2_for_redteam() -> None:
    result = server.get_profile_tools("redteam")  # include_c2 = true
    listed = {t["name"] for m in result["modules"] for t in m["tools"]}
    assert "gophish" in listed and "Caldera" in listed


def test_get_module_info_update_command_whole_system() -> None:
    info = server.get_module_info("misc")
    assert "--module" not in info["commands"]["update"]
    # C2 tools in misc are flagged
    c2_flagged = [t for t in info["tools"] if t.get("requires_include_c2")]
    assert any(t["name"] == "gophish" for t in c2_flagged)
