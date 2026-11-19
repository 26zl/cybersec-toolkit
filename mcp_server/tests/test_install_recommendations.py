"""Install advice must enable the installer gates required by the requested tools."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from mcp_server import server
from mcp_server.profiles import _match_individual_tools, recommend_install
from mcp_server.tools_db import ToolsDatabase


@pytest.mark.parametrize(
    ("name", "method", "module", "flags"),
    [
        ("bloodhound-ce", "docker", "enterprise", {"--enable-docker"}),
        ("SET", "git", "misc", {"--include-c2"}),
        ("empire", "docker", "misc", {"--include-c2", "--enable-docker"}),
        ("gophish", "binary", "misc", {"--include-c2"}),
    ],
)
def test_named_tool_recommendations_include_required_install_switches(tmp_path, name, method, module, flags):
    (tmp_path / "tools_config.json").write_text(
        json.dumps([{"name": name, "method": method, "module": module, "url": ""}])
    )
    db = ToolsDatabase(project_root=tmp_path)
    result = recommend_install(f"install {name}", db)
    command = result["install_commands"][0]
    assert flags <= set(command.split())


def test_mixed_request_preserves_required_docker_switch_in_its_separate_module_command(tmp_path):
    (tmp_path / "tools_config.json").write_text(
        json.dumps(
            [
                {"name": "lynis", "method": "apt", "module": "blueteam", "url": ""},
                {"name": "bloodhound-ce", "method": "docker", "module": "enterprise", "url": ""},
            ]
        )
    )
    result = recommend_install("install lynis and bloodhound-ce", ToolsDatabase(project_root=tmp_path))
    assert "--enable-docker" in result["alternative_module_install"]["commands"][0].split()
    assert "--enable-docker" not in result["install_commands"][0].split()


@pytest.mark.parametrize("name", ["bloodhound-ce", "kics", "empire"])
def test_docker_tool_details_always_include_docker_opt_in(name):
    with patch.object(server._db, "check_installed", return_value={"installed": False, "details": "synthetic"}):
        result = server.get_tool_info(name)
    assert "--enable-docker" in result["commands"]["install"].split()


@pytest.mark.parametrize(
    "name",
    ["bloodhound-ce", "rusthound-ce", "yara-x-cli", "crytic-medusa", "medusa-frida", "Loki-C2", "pentagi-docker"],
)
def test_a_specific_tool_name_does_not_request_a_different_tool_with_a_shared_component(name):
    db = ToolsDatabase()
    assert [tool["name"] for tool in _match_individual_tools(f"install {name}", db)] == [name]


def test_sentence_punctuation_after_a_tool_name_remains_accepted():
    assert [tool["name"] for tool in _match_individual_tools("Please install bloodhound-ce.", ToolsDatabase())] == [
        "bloodhound-ce"
    ]
