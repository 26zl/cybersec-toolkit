"""Scoped operator opt-ins for host-control tools, using synthetic launchers only."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.security import check_policy, execute_pipeline, execute_tool, execute_tool_remote
from mcp_server.tools_db import ToolsDatabase

OPT_INS = {"usbkill": "CYBERSEC_MCP_ALLOW_USBKILL", "nipe": "CYBERSEC_MCP_ALLOW_NIPE"}


@pytest.fixture(autouse=True)
def isolated_host_control_flags(monkeypatch):
    for variable in OPT_INS.values():
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")


@pytest.fixture
def host_control_db(tmp_path):
    tools = [{"name": name, "method": "git", "module": "misc", "url": ""} for name in OPT_INS]
    (tmp_path / "tools_config.json").write_text(json.dumps(tools))
    return ToolsDatabase(project_root=tmp_path)


@pytest.mark.parametrize("name", OPT_INS)
@pytest.mark.parametrize("value", [None, "", "0", "true", "yes", "on", "2", "01"])
def test_host_control_requires_strict_tool_specific_opt_in(name, value, monkeypatch):
    if value is not None:
        monkeypatch.setenv(OPT_INS[name], value)
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    args = [] if name == "usbkill" else ["start"]
    with pytest.raises(ValueError, match=OPT_INS[name]):
        check_policy(name, args)


@pytest.mark.parametrize("name", OPT_INS)
@pytest.mark.parametrize("args", [["-h"], ["--help"], ["--version"], ["-V"]])
def test_informational_host_control_calls_remain_available(name, args):
    check_policy(name, args)


@pytest.mark.parametrize("args", [[], ["help"]])
def test_nipe_help_forms_do_not_require_opt_in_or_external_network(args):
    check_policy("nipe", args)


@pytest.mark.parametrize("args", [[], ["--cs"], ["--no-shut-down"], ["--cs", "--no-shut-down"]])
@pytest.mark.parametrize("value", ["1", " 1 "])
def test_usbkill_documented_operational_modes_are_enabled(args, value, monkeypatch):
    monkeypatch.setenv(OPT_INS["usbkill"], value)
    check_policy("usbkill", args)


@pytest.mark.parametrize("name", OPT_INS)
def test_one_host_control_opt_in_does_not_enable_the_other_tool(name, monkeypatch):
    other = "nipe" if name == "usbkill" else "usbkill"
    monkeypatch.setenv(OPT_INS[other], "1")
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    with pytest.raises(ValueError, match=OPT_INS[name]):
        check_policy(name, [] if name == "usbkill" else ["start"])


@pytest.mark.parametrize(
    ("name", "alias", "args"), [("usbkill", "usbkill.py", ["--cs"]), ("nipe", "nipe.pl", ["start"])]
)
def test_native_host_control_aliases_use_the_owning_tools_opt_in(name, alias, args, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    with pytest.raises(ValueError, match=OPT_INS[name]):
        check_policy(alias, args)
    monkeypatch.setenv(OPT_INS[name], "1")
    check_policy(alias, args)


@pytest.mark.parametrize("command", ["start", "restart", "install", "status"])
def test_nipe_network_commands_require_external_opt_in(command, monkeypatch):
    monkeypatch.setenv(OPT_INS["nipe"], "1")
    with patch("mcp_server.security._is_safe_target", side_effect=AssertionError("not an argv target")):
        with pytest.raises(ValueError, match="CYBERSEC_MCP_ALLOW_EXTERNAL=1"):
            check_policy("nipe", [command])
        monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
        check_policy("nipe", [command])


def test_nipe_stop_can_restore_local_network_rules_without_external_opt_in(monkeypatch):
    monkeypatch.setenv(OPT_INS["nipe"], "1")
    with patch("mcp_server.security._is_safe_target", side_effect=AssertionError("stop is local")):
        check_policy("nipe", ["stop"])


def test_host_control_opt_ins_do_not_disable_other_tools_argument_policies(monkeypatch):
    for variable in OPT_INS.values():
        monkeypatch.setenv(variable, "1")
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy("commix", ["--oob"])


@pytest.mark.parametrize(
    ("name", "invocation", "args"),
    [
        ("usbkill", "usbkill", "--cs"),
        ("nipe", "nipe", "start"),
        ("usbkill", "usbkill.py", "--cs"),
        ("nipe", "nipe.pl", "start"),
    ],
)
async def test_opt_in_rejection_precedes_local_pipeline_and_ssh_execution(
    name, invocation, args, host_control_db, monkeypatch
):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    remote = MagicMock()
    remote.check_tool_allowed.return_value = True
    with (
        patch("shutil.which", return_value=f"/synthetic/bin/{name}"),
        patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn,
        patch("mcp_server.remote.execute_remote_command", new_callable=AsyncMock) as ssh,
    ):
        local = await execute_tool(invocation, args, host_control_db)
        pipeline = await execute_pipeline([{"tool": invocation, "args": args}], host_control_db)
        distant = await execute_tool_remote(invocation, args, host_control_db, remote, "synthetic-host")
    for result in (local, pipeline, distant):
        assert result["exit_code"] == -1
        assert OPT_INS[name] in result["stderr"]
    spawn.assert_not_called()
    ssh.assert_not_called()
    remote.get_ssh_base_args.assert_not_called()


@pytest.mark.parametrize(
    ("name", "invocation", "args"),
    [
        ("usbkill", "usbkill", "--cs"),
        ("nipe", "nipe", "start"),
        ("usbkill", "usbkill.py", "--cs"),
        ("nipe", "nipe.pl", "start"),
    ],
)
async def test_enabled_host_control_routes_dispatch_only_synthetic_commands(
    name, invocation, args, host_control_db, tmp_path, monkeypatch
):
    launcher = tmp_path / invocation
    launcher.write_text('#!/bin/sh\nprintf "synthetic:%s\\n" "$1"\n')
    launcher.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":/usr/bin:/bin")
    monkeypatch.setenv(OPT_INS[name], "1")
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    local = await execute_tool(invocation, args, host_control_db)
    pipeline = await execute_pipeline(
        [{"tool": "printf", "args": "ignored"}, {"tool": invocation, "args": args}], host_control_db
    )
    assert local["exit_code"] == pipeline["exit_code"] == 0
    assert local["stdout"] == pipeline["stdout"] == f"synthetic:{args}\n"

    remote = MagicMock()
    remote.check_tool_allowed.return_value = True
    remote.get_ssh_base_args.return_value = ["tester@10.0.0.8"]

    async def synthetic_ssh(_ssh, command, **_kwargs):
        return {
            "exit_code": 0,
            "stdout": f"/synthetic/{name}\n" if command[0] == "which" else "synthetic remote\n",
            "stderr": "",
            "truncated": False,
            "command": " ".join(command),
        }

    with patch("mcp_server.remote.execute_remote_command", new_callable=AsyncMock) as ssh:
        ssh.side_effect = synthetic_ssh
        distant = await execute_tool_remote(invocation, args, host_control_db, remote, "synthetic-host")
    assert distant["exit_code"] == 0
    assert any(call.args[1] == [invocation, args] for call in ssh.call_args_list)
