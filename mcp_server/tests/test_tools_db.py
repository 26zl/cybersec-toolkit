"""Tests for mcp_server.tools_db — tool loading, filtering, install checks."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server.tools_db import ToolsDatabase

from .conftest import SAMPLE_TOOLS


# ---------------------------------------------------------------------------
# _load_tools
# ---------------------------------------------------------------------------
class TestLoadTools:
    def test_loads_all_tools(self, tools_db: ToolsDatabase) -> None:
        assert tools_db.total_tools == len(SAMPLE_TOOLS)

    def test_tools_by_name_populated(self, tools_db: ToolsDatabase) -> None:
        assert "nmap" in tools_db.tools_by_name
        assert "sqlmap" in tools_db.tools_by_name

    def test_missing_config_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ToolsDatabase(project_root=tmp_path)

    def test_tool_fields(self, tools_db: ToolsDatabase) -> None:
        tool = tools_db.tools_by_name["nmap"]
        assert tool["method"] == "apt"
        assert tool["module"] == "networking"


# ---------------------------------------------------------------------------
# list_tools
# ---------------------------------------------------------------------------
class TestListTools:
    def test_list_all(self, tools_db: ToolsDatabase) -> None:
        assert len(tools_db.list_tools()) == len(SAMPLE_TOOLS)

    def test_filter_by_module(self, tools_db: ToolsDatabase) -> None:
        web_tools = tools_db.list_tools(module="web")
        assert all(t["module"] == "web" for t in web_tools)
        assert len(web_tools) == 2  # sqlmap, gobuster

    def test_filter_by_method(self, tools_db: ToolsDatabase) -> None:
        apt_tools = tools_db.list_tools(method="apt")
        assert all(t["method"] == "apt" for t in apt_tools)

    def test_filter_by_module_and_method(self, tools_db: ToolsDatabase) -> None:
        results = tools_db.list_tools(module="web", method="pipx")
        assert len(results) == 1
        assert results[0]["name"] == "sqlmap"

    def test_installed_only_none_installed(self, tools_db: ToolsDatabase) -> None:
        with (
            patch("shutil.which", return_value=None),
            patch.object(tools_db, "_docker_image_exists", return_value=False),
        ):
            results = tools_db.list_tools(installed_only=True)
        assert len(results) == 0

    def test_modules_property(self, tools_db: ToolsDatabase) -> None:
        modules = tools_db.modules
        assert "web" in modules
        assert "networking" in modules
        assert modules == sorted(modules)

    def test_methods_property(self, tools_db: ToolsDatabase) -> None:
        methods = tools_db.methods
        assert "apt" in methods
        assert "pipx" in methods


# ---------------------------------------------------------------------------
# _find_docker_image
# ---------------------------------------------------------------------------
class TestFindDockerImage:
    def test_exact_label_match(self, tools_db: ToolsDatabase) -> None:
        assert tools_db._find_docker_image("BeEF") == "beefproject/beef"

    def test_case_insensitive_label(self, tools_db: ToolsDatabase) -> None:
        assert tools_db._find_docker_image("beef") == "beefproject/beef"
        assert tools_db._find_docker_image("BEEF") == "beefproject/beef"

    def test_image_name_match(self, tools_db: ToolsDatabase) -> None:
        assert tools_db._find_docker_image("empire") == "bcsecurity/empire"

    def test_no_match(self, tools_db: ToolsDatabase) -> None:
        assert tools_db._find_docker_image("nonexistent") is None


# ---------------------------------------------------------------------------
# check_installed
# ---------------------------------------------------------------------------
class TestCheckInstalled:
    def test_unknown_tool(self, tools_db: ToolsDatabase) -> None:
        result = tools_db.check_installed("nonexistent")
        assert result["installed"] is False
        assert "not found" in result["details"].lower()

    def test_found_in_versions_file(self, tmp_tools_config: Path) -> None:
        versions = tmp_tools_config / ".versions"
        versions.write_text("nmap|apt|7.94|2024-01-01T00:00:00\n", encoding="utf-8")
        db = ToolsDatabase(project_root=tmp_tools_config)
        result = db.check_installed("nmap")
        assert result["installed"] is True
        assert result["method"] == "versions_tracked"

    def test_found_in_path(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/nmap" if x == "nmap" else None):
            result = tools_db.check_installed("nmap")
        assert result["installed"] is True
        assert result["method"] == "path"

    def test_pipx_binary_fallback(self, tools_db: ToolsDatabase) -> None:
        def mock_which(name: str):
            return "/usr/local/bin/sherlock" if name == "sherlock" else None

        with patch("shutil.which", side_effect=mock_which):
            result = tools_db.check_installed("sherlock-project")
        assert result["installed"] is True
        assert result["method"] == "pipx_binary"

    def test_not_installed(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = tools_db.check_installed("nmap")
        assert result["installed"] is False


# ---------------------------------------------------------------------------
# reload_versions
# ---------------------------------------------------------------------------
class TestReloadVersions:
    def test_parse_versions_file(self, tmp_tools_config: Path) -> None:
        versions = tmp_tools_config / ".versions"
        versions.write_text(
            "nmap|apt|7.94|2024-01-01T00:00:00\nsqlmap|pipx|1.8|2024-02-15T12:00:00\n# comment line\n\n",
            encoding="utf-8",
        )
        db = ToolsDatabase(project_root=tmp_tools_config)
        vers = db.reload_versions()
        assert "nmap" in vers
        assert vers["nmap"]["version"] == "7.94"
        assert vers["nmap"]["method"] == "apt"
        assert "sqlmap" in vers
        assert vers["sqlmap"]["version"] == "1.8"

    def test_missing_versions_file(self, tools_db: ToolsDatabase) -> None:
        vers = tools_db.reload_versions()
        assert vers == {}

    def test_permission_denied_versions_file(self, tmp_tools_config: Path) -> None:
        versions = tmp_tools_config / ".versions"
        versions.write_text("nmap|apt|7.94|2024-01-01T00:00:00\n", encoding="utf-8")
        db = ToolsDatabase(project_root=tmp_tools_config)
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            vers = db.reload_versions()
        assert vers == {}

    def test_ttl_caching(self, tmp_tools_config: Path) -> None:
        versions = tmp_tools_config / ".versions"
        versions.write_text("nmap|apt|7.94|2024-01-01T00:00:00\n", encoding="utf-8")
        db = ToolsDatabase(project_root=tmp_tools_config)

        v1 = db.reload_versions(ttl=60.0)
        assert "nmap" in v1

        # Modify file — but TTL should return cached version
        versions.write_text("sqlmap|pipx|1.8|2024-02-15T12:00:00\n", encoding="utf-8")
        v2 = db.reload_versions(ttl=60.0)
        assert "nmap" in v2  # still cached
        assert "sqlmap" not in v2

    def test_short_lines_skipped(self, tmp_tools_config: Path) -> None:
        versions = tmp_tools_config / ".versions"
        versions.write_text("short|line\nnmap|apt|7.94|2024-01-01T00:00:00\n", encoding="utf-8")
        db = ToolsDatabase(project_root=tmp_tools_config)
        vers = db.reload_versions()
        assert "short" not in vers
        assert "nmap" in vers
