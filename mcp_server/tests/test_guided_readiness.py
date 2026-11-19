"""Guided plans distinguish recorded installs from available launchers."""

from __future__ import annotations

import json
from unittest.mock import patch

from mcp_server.guided_assessment import _tool_status, build_guided_plan
from mcp_server.tools_db import ToolsDatabase


def test_tracked_tool_without_launcher_is_not_an_autonomous_candidate(tmp_path):
    (tmp_path / "tools_config.json").write_text(
        json.dumps([{"name": "nmap", "method": "apt", "module": "networking", "url": ""}])
    )
    (tmp_path / ".versions").write_text("nmap|apt|7.94|2026-01-01\n")
    with patch("shutil.which", return_value=None):
        result = build_guided_plan(
            target="10.0.0.1",
            target_type="network",
            workflow="bounty",
            mode="autonomous",
            intensity="medium",
            authorization_confirmed=True,
            max_steps=10,
            external_enabled=False,
            tools_db=ToolsDatabase(project_root=tmp_path),
        )
    nmap = next(step for step in result["plan"]["steps"] if step["tool"] == "nmap")
    assert nmap["installed"] is True
    assert result["plan"]["execution_candidates"] == []
    assert nmap["ready"] is False


def test_recommendation_prefers_ready_tool_over_tracked_install(tmp_path):
    (tmp_path / "tools_config.json").write_text(
        json.dumps([{"name": "dig", "method": "apt", "module": "networking", "url": ""}])
    )
    (tmp_path / ".versions").write_text("dig|apt|1.0|2026-01-01\n")
    with patch("shutil.which", side_effect=lambda name: "/usr/bin/curl" if name == "curl" else None):
        result = build_guided_plan(
            target="http://10.0.0.1",
            target_type="web_app",
            workflow="bounty",
            mode="companion",
            intensity="low",
            authorization_confirmed=True,
            max_steps=4,
            external_enabled=False,
            tools_db=ToolsDatabase(project_root=tmp_path),
        )
    assert result["plan"]["recommended_next_command"]["tool"] == "curl"
    assert result["plan"]["recommended_next_command"]["ready"] is True


def test_guided_status_resolves_package_executable_alias(tmp_path):
    (tmp_path / "tools_config.json").write_text(
        json.dumps([{"name": "dnsutils", "method": "apt", "module": "networking", "url": ""}])
    )
    with patch("shutil.which", side_effect=lambda name: "/usr/bin/dig" if name == "dig" else None):
        result = _tool_status("dig", ToolsDatabase(project_root=tmp_path))
    assert result["in_registry"] is True
    assert result["registry_name"] == "dnsutils"
    assert result["ready"] is True
