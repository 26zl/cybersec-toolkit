"""Tests for mcp_server.bounty_advisor — target type resolution and tool suggestions."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mcp_server.bounty_advisor import (
    BOUNTY_TARGET_MAP,
    TARGET_ALIASES,
    resolve_target_type,
    suggest_for_bounty,
)
from mcp_server.tools_db import ToolsDatabase


# resolve_target_type
class TestResolveTargetType:
    @pytest.mark.parametrize("target", list(BOUNTY_TARGET_MAP.keys()))
    def test_canonical_names(self, target: str) -> None:
        assert resolve_target_type(target) == target

    def test_case_insensitive(self) -> None:
        assert resolve_target_type("Web_App") == "web_app"
        assert resolve_target_type("CLOUD") == "cloud"

    def test_whitespace_stripped(self) -> None:
        assert resolve_target_type("  api  ") == "api"

    @pytest.mark.parametrize("alias,expected", list(TARGET_ALIASES.items()))
    def test_aliases(self, alias: str, expected: str) -> None:
        assert resolve_target_type(alias) == expected

    def test_invalid_target_type(self) -> None:
        assert resolve_target_type("nonexistent") is None

    def test_empty_string(self) -> None:
        assert resolve_target_type("") is None


# suggest_for_bounty
class TestSuggestForBounty:
    def test_valid_target(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_bounty("web_app", tools_db)
        assert result["target_type"] == "web_app"
        assert "description" in result
        assert "modules" in result
        assert "tools" in result
        assert "summary" in result
        assert len(result["tools"]) > 0

    def test_invalid_target(self, tools_db: ToolsDatabase) -> None:
        result = suggest_for_bounty("nonexistent", tools_db)
        assert "error" in result
        assert "available_target_types" in result
        assert "available_aliases" in result

    def test_tool_status_fields(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_bounty("api", tools_db)
        for tool in result["tools"]:
            assert "name" in tool
            assert "description" in tool
            assert "installed" in tool
            assert "in_registry" in tool

    def test_alias_resolves(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_bounty("android", tools_db)
        assert result["target_type"] == "mobile_app"

    def test_summary_format(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_bounty("web_app", tools_db)
        assert "/" in result["summary"]
        assert "tools installed" in result["summary"]

    def test_scope_warning_present(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_bounty("web_app", tools_db)
        assert "scope_warning" in result
        assert "scope" in result["scope_warning"].lower()

    def test_installed_tool_counted(self, tools_db: ToolsDatabase) -> None:
        def mock_which(name: str):
            return "/usr/bin/nmap" if name == "nmap" else None

        with patch("shutil.which", side_effect=mock_which):
            result = suggest_for_bounty("network", tools_db)
        nmap_entry = next((t for t in result["tools"] if t["name"] == "nmap"), None)
        if nmap_entry:
            assert nmap_entry["installed"] is True


# Methodology, quick_wins, and common_vulns
class TestMethodologyAndVulns:
    @pytest.mark.parametrize("target", list(BOUNTY_TARGET_MAP.keys()))
    def test_methodology_exists(self, target: str) -> None:
        assert "methodology" in BOUNTY_TARGET_MAP[target]
        assert len(BOUNTY_TARGET_MAP[target]["methodology"]) >= 5

    @pytest.mark.parametrize("target", list(BOUNTY_TARGET_MAP.keys()))
    def test_quick_wins_exists(self, target: str) -> None:
        assert "quick_wins" in BOUNTY_TARGET_MAP[target]
        assert len(BOUNTY_TARGET_MAP[target]["quick_wins"]) >= 3

    @pytest.mark.parametrize("target", list(BOUNTY_TARGET_MAP.keys()))
    def test_common_vulns_exists(self, target: str) -> None:
        assert "common_vulns" in BOUNTY_TARGET_MAP[target]
        assert len(BOUNTY_TARGET_MAP[target]["common_vulns"]) >= 5

    @pytest.mark.parametrize("target", list(BOUNTY_TARGET_MAP.keys()))
    def test_methodology_starts_with_scope(self, target: str) -> None:
        first_step = BOUNTY_TARGET_MAP[target]["methodology"][0]
        assert first_step.startswith("0. SCOPE:")

    def test_suggest_includes_methodology(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_bounty("web_app", tools_db)
        assert "methodology" in result
        assert len(result["methodology"]) > 0

    def test_suggest_includes_quick_wins(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_bounty("web_app", tools_db)
        assert "quick_wins" in result
        assert len(result["quick_wins"]) > 0

    def test_suggest_includes_common_vulns(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_bounty("web_app", tools_db)
        assert "common_vulns" in result
        assert len(result["common_vulns"]) > 0
