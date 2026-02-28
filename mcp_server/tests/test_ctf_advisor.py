"""Tests for mcp_server.ctf_advisor — category resolution and tool suggestions."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mcp_server.ctf_advisor import (
    CATEGORY_ALIASES,
    CTF_CATEGORY_MAP,
    resolve_category,
    suggest_for_ctf,
)
from mcp_server.tools_db import ToolsDatabase


# resolve_category
class TestResolveCategory:
    @pytest.mark.parametrize("cat", list(CTF_CATEGORY_MAP.keys()))
    def test_canonical_names(self, cat: str) -> None:
        assert resolve_category(cat) == cat

    def test_case_insensitive(self) -> None:
        assert resolve_category("Web") == "web"
        assert resolve_category("FORENSICS") == "forensics"

    def test_whitespace_stripped(self) -> None:
        assert resolve_category("  pwn  ") == "pwn"

    @pytest.mark.parametrize("alias,expected", list(CATEGORY_ALIASES.items()))
    def test_aliases(self, alias: str, expected: str) -> None:
        assert resolve_category(alias) == expected

    def test_invalid_category(self) -> None:
        assert resolve_category("nonexistent") is None

    def test_empty_string(self) -> None:
        assert resolve_category("") is None


# suggest_for_ctf
class TestSuggestForCtf:
    def test_valid_category(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("web", tools_db)
        assert result["category"] == "web"
        assert "description" in result
        assert "modules" in result
        assert "tools" in result
        assert "summary" in result
        assert len(result["tools"]) > 0

    def test_invalid_category(self, tools_db: ToolsDatabase) -> None:
        result = suggest_for_ctf("nonexistent", tools_db)
        assert "error" in result
        assert "available_categories" in result
        assert "available_aliases" in result

    def test_tool_status_fields(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("crypto", tools_db)
        for tool in result["tools"]:
            assert "name" in tool
            assert "description" in tool
            assert "installed" in tool
            assert "in_registry" in tool

    def test_alias_resolves(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("re", tools_db)
        assert result["category"] == "reversing"

    def test_summary_format(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("web", tools_db)
        # Summary should be "N/M tools installed"
        assert "/" in result["summary"]
        assert "tools installed" in result["summary"]

    def test_installed_tool_counted(self, tools_db: ToolsDatabase) -> None:
        def mock_which(name: str):
            return "/usr/bin/nmap" if name == "nmap" else None

        with patch("shutil.which", side_effect=mock_which):
            result = suggest_for_ctf("networking", tools_db)
        nmap_entry = next((t for t in result["tools"] if t["name"] == "nmap"), None)
        if nmap_entry:
            assert nmap_entry["installed"] is True


# Methodology and quick_wins
class TestMethodology:
    @pytest.mark.parametrize("cat", list(CTF_CATEGORY_MAP.keys()))
    def test_methodology_exists(self, cat: str) -> None:
        assert "methodology" in CTF_CATEGORY_MAP[cat]
        assert len(CTF_CATEGORY_MAP[cat]["methodology"]) >= 3

    @pytest.mark.parametrize("cat", list(CTF_CATEGORY_MAP.keys()))
    def test_quick_wins_exists(self, cat: str) -> None:
        assert "quick_wins" in CTF_CATEGORY_MAP[cat]
        assert len(CTF_CATEGORY_MAP[cat]["quick_wins"]) >= 2

    def test_suggest_includes_methodology(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("web", tools_db)
        assert "methodology" in result
        assert len(result["methodology"]) > 0

    def test_suggest_includes_quick_wins(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("web", tools_db)
        assert "quick_wins" in result
        assert len(result["quick_wins"]) > 0
