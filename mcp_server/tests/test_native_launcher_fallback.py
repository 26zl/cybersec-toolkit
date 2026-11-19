"""Registry requests select available native launchers; explicit aliases stay exact."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server import security
from mcp_server.tools_db import ToolsDatabase


@pytest.fixture
def launcher_db(tmp_path, monkeypatch):
    tools = [
        {"name": "netexec", "method": "pipx", "module": "enterprise"},
        {"name": "usbkill", "method": "git", "module": "misc"},
    ]
    (tmp_path / "tools_config.json").write_text(json.dumps(tools))
    monkeypatch.setattr(security, "_rate_limiter", security._RateLimiter(max_per_minute=1000))
    monkeypatch.setattr(security, "_sandbox_wrap", lambda command, **_kwargs: command)
    return ToolsDatabase(tmp_path)


@pytest.mark.parametrize("native", ["netexec", "NetExec"])
@pytest.mark.parametrize("route", ["local", "pipeline", "remote"])
async def test_primary_native_fallback_is_runnable(native, route, launcher_db, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda binary: f"/synthetic/{native}" if binary == native else None)
    process = AsyncMock(returncode=0)
    process.pid = None
    process.communicate.return_value = (b"synthetic result", b"")
    config = MagicMock()

    async def remote(_ssh, command, **_kwargs):
        found = command[-1] == native if command[0] == "which" else command[0] == native
        return {"exit_code": 0 if found else 127, "stdout": f"/synthetic/{native}" if found else "", "stderr": ""}

    with (
        patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=process) as spawn,
        patch("mcp_server.remote.execute_remote_command", new_callable=AsyncMock, side_effect=remote),
    ):
        if route == "local":
            result = await security.execute_tool("netexec", "--help", launcher_db)
        elif route == "pipeline":
            result = await security.execute_pipeline([{"tool": "netexec", "args": "--help"}], launcher_db)
        else:
            result = await security.execute_tool_remote("netexec", "--help", launcher_db, config, "synthetic")
        assert result["exit_code"] == 0
        if route != "remote":
            assert spawn.call_args.args[0] == native


@pytest.mark.parametrize(("alias", "primary"), [("NetExec", "nxc"), ("usbkill.py", "usbkill")])
async def test_remote_explicit_alias_does_not_fall_back_to_primary(alias, primary, launcher_db):
    async def remote(_ssh, command, **_kwargs):
        found = command[-1] == primary if command[0] == "which" else command[0] == primary
        return {"exit_code": 0 if found else 127, "stdout": f"/synthetic/{primary}" if found else "", "stderr": ""}

    with patch("mcp_server.remote.execute_remote_command", new_callable=AsyncMock, side_effect=remote) as ssh:
        result = await security.execute_tool_remote(alias, "--help", launcher_db, MagicMock(), "synthetic")
    assert result["exit_code"] == 127
    assert ssh.call_args.args[1] == [alias, "--help"]
