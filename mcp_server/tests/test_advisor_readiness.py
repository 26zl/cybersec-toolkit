"""Advisor metadata names the executable whose readiness was checked."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from mcp_server.advisor_utils import build_tool_status_list
from mcp_server.tools_db import ToolsDatabase


@pytest.mark.parametrize(
    ("name", "method", "requested", "binary"),
    [
        ("sleuthkit", "apt", "icat", "icat"),
        ("netexec", "pipx", "netexec", "NetExec"),
        ("yara-x-cli", "cargo", "yr", "yr"),
    ],
)
def test_advisor_reports_the_available_requested_or_fallback_binary(tmp_path, name, method, requested, binary):
    (tmp_path / "tools_config.json").write_text(
        json.dumps([{"name": name, "method": method, "module": "misc", "url": ""}])
    )
    db = ToolsDatabase(project_root=tmp_path)
    with patch("shutil.which", side_effect=lambda value: f"/synthetic/{binary}" if value == binary else None):
        entries, installed_count = build_tool_status_list([(requested, "Synthetic tool.")], db)
    assert installed_count == 1
    assert entries[0]["execution"]["ready"] is True
    assert entries[0]["execution"]["binary"] == binary


@pytest.mark.parametrize(
    ("name", "method", "requested", "other_binary"),
    [("netexec", "pipx", "nxc", "NetExec"), ("usbkill", "git", "usbkill.py", "usbkill")],
)
def test_explicit_native_name_is_not_reported_ready_through_a_different_launcher(
    tmp_path, name, method, requested, other_binary
):
    (tmp_path / "tools_config.json").write_text(
        json.dumps([{"name": name, "method": method, "module": "misc", "url": ""}])
    )
    (tmp_path / ".versions").write_text(f"{name}|{method}|1.0|2026-01-01\n")
    db = ToolsDatabase(project_root=tmp_path)
    with patch(
        "shutil.which", side_effect=lambda value: f"/synthetic/{other_binary}" if value == other_binary else None
    ):
        status = db.execution_status(requested)
        installed = db.check_installed(requested)
    assert status["ready"] is False
    assert status["binary"] == requested
    assert installed["installed"] is False
