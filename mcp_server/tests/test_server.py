"""Tests for mcp_server.server tool-level wiring."""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import pytest

from mcp_server import server


def test_main_disables_banner_and_update_check() -> None:
    with patch.object(server.mcp, "run") as run:
        server.main()
    run.assert_called_once_with(show_banner=False)


@pytest.mark.asyncio
async def test_every_tool_has_behavior_annotations() -> None:
    # A new @mcp.tool without annotations would leave clients unable to reason
    # about its side effects; every registered tool must carry a readOnly hint.
    tools = await server.mcp._list_tools()
    assert tools, "no MCP tools registered"
    missing = [t.name for t in tools if t.annotations is None or t.annotations.readOnlyHint is None]
    assert not missing, f"tools missing behavior annotations: {missing}"


@pytest.mark.asyncio
async def test_executors_marked_not_read_only() -> None:
    tools = {t.name: t.annotations for t in await server.mcp._list_tools()}
    for name in ("run_tool", "run_pipeline", "run_script"):
        assert tools[name].readOnlyHint is False and tools[name].destructiveHint is True, name
    for name in ("list_tools", "get_tool_info", "list_profiles"):
        assert tools[name].readOnlyHint is True, name


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


@pytest.mark.asyncio
async def test_run_script_reports_unsandboxed_security_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        server,
        "_execute_script",
        AsyncMock(return_value={"exit_code": 0, "stdout": "ok", "stderr": "", "truncated": False}),
    )
    with patch("mcp_server.server.log_tool_result"):
        result = await server.run_script("print('ok')")

    assert result["security_scope"]["sandboxed"] is False
    assert result["security_scope"]["external_network_policy_enforced"] is False


# C2 gating reflected in MCP output (uses the real registry)


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


@pytest.mark.asyncio
async def test_get_profile_tools_excludes_c2_when_disabled() -> None:
    from mcp_server.tools_db import C2_TOOLS

    result = await server.get_profile_tools("web")  # include_c2 = false
    listed = {t["name"] for m in result["modules"] for t in m["tools"]}
    assert not (listed & C2_TOOLS), f"C2 tools leaked into web profile: {listed & C2_TOOLS}"


@pytest.mark.asyncio
async def test_get_profile_tools_includes_c2_for_redteam() -> None:
    result = await server.get_profile_tools("redteam")  # include_c2 = true
    listed = {t["name"] for m in result["modules"] for t in m["tools"]}
    assert "gophish" in listed and "Caldera" in listed


def test_get_module_info_update_command_whole_system() -> None:
    info = server.get_module_info("misc")
    assert "--module" not in info["commands"]["update"]
    # C2 tools in misc are flagged
    c2_flagged = [t for t in info["tools"] if t.get("requires_include_c2")]
    assert any(t["name"] == "gophish" for t in c2_flagged)


# Advisor docstrings stay in sync with the category maps


def test_suggest_for_ctf_docstring_count_and_llm_listed() -> None:
    from mcp_server.ctf_advisor import CTF_CATEGORY_MAP

    doc = server.suggest_for_ctf.__doc__
    assert doc is not None
    assert f"{len(CTF_CATEGORY_MAP)} challenge types" in doc
    assert len(CTF_CATEGORY_MAP) == 14
    assert "llm" in doc
    assert "llm" in CTF_CATEGORY_MAP


def test_suggest_for_bounty_docstring_count_and_llm_listed() -> None:
    from mcp_server.bounty_advisor import BOUNTY_TARGET_MAP

    doc = server.suggest_for_bounty.__doc__
    assert doc is not None
    assert f"{len(BOUNTY_TARGET_MAP)} target types" in doc
    assert len(BOUNTY_TARGET_MAP) == 7
    assert "llm" in doc
    assert "llm" in BOUNTY_TARGET_MAP


# A snapshot of the public tool surface: tool names plus each tool's parameter
# names and which are required. A rename, a new/removed tool, or a newly-required
# parameter changes this and fails the test — update it deliberately when the API
# changes on purpose (API-4: schema-level breaking-change detection).
EXPECTED_TOOL_SCHEMA = {
    "check_installed": {"required": ["tool_name"], "params": ["host", "tool_name"]},
    "get_cve_info": {"required": ["cve"], "params": ["cve"]},
    "get_module_info": {"required": ["module"], "params": ["module"]},
    "get_profile_tools": {"required": ["profile"], "params": ["counts_only", "profile"]},
    "get_tool_info": {"required": ["tool_name"], "params": ["tool_name"]},
    "guided_assessment": {
        "required": ["target"],
        "params": [
            "authorization_confirmed",
            "finding",
            "intensity",
            "max_steps",
            "mode",
            "target",
            "target_type",
            "workflow",
        ],
    },
    "list_profiles": {"required": [], "params": []},
    "list_tools": {"required": [], "params": ["installed_only", "limit", "method", "module", "offset"]},
    "manage_remote_hosts": {
        "required": ["action"],
        "params": [
            "action",
            "description",
            "hostname",
            "name",
            "port",
            "ssh_key",
            "tool_allowlist",
            "user",
        ],
    },
    "recommend_install": {"required": ["task"], "params": ["task"]},
    "run_pipeline": {"required": ["steps"], "params": ["host", "steps", "timeout"]},
    "run_script": {"required": ["code"], "params": ["code", "language", "timeout", "venv", "working_dir"]},
    "run_tool": {"required": ["tool_name"], "params": ["args", "host", "timeout", "tool_name"]},
    "suggest_for_bounty": {"required": ["target_type"], "params": ["target_type"]},
    "suggest_for_ctf": {"required": ["challenge_type"], "params": ["challenge_type"]},
}


@pytest.mark.asyncio
async def test_tool_schema_matches_snapshot() -> None:
    tools = await server.mcp._list_tools()
    actual = {}
    for t in tools:
        schema = getattr(t, "parameters", None) or {}
        actual[t.name] = {
            "required": sorted(schema.get("required") or []),
            "params": sorted((schema.get("properties") or {}).keys()),
        }
    assert actual == EXPECTED_TOOL_SCHEMA
