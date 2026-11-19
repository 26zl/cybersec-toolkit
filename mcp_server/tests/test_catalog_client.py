"""Exercise catalog discovery through an in-process MCP client."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp import Client

from mcp_server import server


@pytest.mark.asyncio
async def test_mcp_client_can_retrieve_and_use_the_complete_catalog(monkeypatch, tmp_path):
    monkeypatch.setattr("shutil.which", lambda _binary: None)
    monkeypatch.setenv("GITHUB_TOOL_DIR", str(tmp_path / "installed-tools"))
    monkeypatch.delenv("TERMUX_VERSION", raising=False)
    registry_path = Path(__file__).resolve().parents[2] / "tools_config.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    expected_names = {tool["name"] for tool in registry}

    async with Client(server.mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
        parameters = tools["list_tools"].input_schema["properties"]
        assert {"limit", "offset", "query", "executable_only"} <= parameters.keys()

        names = []
        offset = 0
        while True:
            response = await client.call_tool("list_tools", {"limit": 50, "offset": offset})
            assert response.is_error is False
            assert response.structured_content is not None
            page = response.data
            assert isinstance(page, dict)
            assert page["total_in_registry"] == page["total_matched"] == len(registry)
            assert page["count"] == len(page["tools"]) <= 50
            names.extend(tool["name"] for tool in page["tools"])
            if not page["has_more"]:
                break
            assert page["next_offset"] == offset + page["count"] > offset
            offset = page["next_offset"]
        assert len(names) == len(set(names)) == len(registry)
        assert set(names) == expected_names

        matching = await client.call_tool("list_tools", {"query": "XSSTRIKE", "executable_only": True})
        assert [tool["name"] for tool in matching.data["tools"]] == ["XSStrike"]
        capability = matching.data["tools"][0]["execution"]
        assert capability["executable"] is True
        assert capability["binary"] == "xsstrike"
        assert capability["network"] is True

        filtered_resource = await client.call_tool("list_tools", {"query": "SecLists", "executable_only": True})
        assert filtered_resource.data["tools"] == []
        resource = (await client.call_tool("get_tool_info", {"tool_name": "SecLists"})).data
        assert resource["execution"]["kind"] == "resource"
        assert resource["execution"]["executable"] is False
        assert "run_tool" in resource["execution"]["access"]
        assert resource["execution"]["location_candidates"] == [str(tmp_path / "installed-tools" / "SecLists")]

        cli = (await client.call_tool("get_tool_info", {"tool_name": "xsstrike"})).data
        assert cli["name"] == "XSStrike"
        assert cli["execution"]["executable"] is True
        assert cli["execution"]["binary"] == "xsstrike"
        assert cli["execution"]["ready"] is False
        assert "CLI launcher is not in PATH" in cli["execution"]["readiness_reason"]
