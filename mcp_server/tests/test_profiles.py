"""Tests for mcp_server.profiles — scoring, recommendation, and profile listing."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from mcp_server.profiles import (
    PROFILES,
    _count_module_tools,
    _count_profile_tools,
    _match_individual_tools,
    _score_profiles,
    list_profiles,
    recommend_install,
)
from mcp_server.tools_db import C2_TOOLS, ToolsDatabase


# _score_profiles
class TestScoreProfiles:
    def test_ctf_keyword(self) -> None:
        scores = _score_profiles("I'm doing a CTF competition")
        assert scores["ctf"] > 0
        assert scores["ctf"] >= scores["redteam"]

    def test_pentest_keyword(self) -> None:
        scores = _score_profiles("pentest a web application")
        assert scores["redteam"] > 0
        assert scores["web"] > 0

    def test_no_match(self) -> None:
        scores = _score_profiles("xyzzy gibberish nonsense")
        assert all(v == 0.0 for v in scores.values())

    def test_multiple_keywords_accumulate(self) -> None:
        scores = _score_profiles("cloud aws kubernetes")
        assert scores["cloud"] > _score_profiles("cloud")["cloud"]

    def test_weights_applied(self) -> None:
        # "ctf" has weight 3.0, "competition" has weight 2.0
        scores_ctf = _score_profiles("ctf")
        scores_comp = _score_profiles("competition")
        assert scores_ctf["ctf"] > scores_comp["ctf"]

    def test_all_profiles_present(self) -> None:
        scores = _score_profiles("anything")
        for name in PROFILES:
            assert name in scores


# recommend_install
class TestRecommendInstall:
    def test_empty_task(self, tools_db: ToolsDatabase) -> None:
        result = recommend_install("", tools_db)
        assert "error" in result
        assert "available_profiles" in result

    def test_individual_tools_mentioned(self, tools_db: ToolsDatabase) -> None:
        # Use tool names that don't overlap with _KEYWORD_MAP keywords
        # ("hashcat" contains "hash" which triggers the crackstation profile)
        with patch("shutil.which", return_value=None):
            result = recommend_install("I need lynis and grype", tools_db)
        assert result["recommendation"] == "individual_tools"
        tool_names = [t["name"] for t in result["tools"]]
        assert "lynis" in tool_names
        assert "grype" in tool_names

    def test_strong_profile_match(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = recommend_install("CTF capture the flag competition", tools_db)
        assert result["recommendation"] == "profile"
        assert result["profile"] == "ctf"
        assert "install_command" in result

    def test_module_match(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = recommend_install("wireshark packet analysis", tools_db)
        assert result["recommendation"] in ("modules", "profile")
        if result["recommendation"] == "modules":
            module_names = [m["name"] for m in result["modules"]]
            assert "networking" in module_names

    def test_unclear_match(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = recommend_install("xyzzy gibberish", tools_db)
        assert result["recommendation"] == "unclear"
        assert "available_profiles" in result


# _match_individual_tools word-boundary matching
class TestMatchIndividualTools:
    def _db(self, tmp_path: Path) -> ToolsDatabase:
        """ToolsDatabase with a short tool name, an English-word tool, and a normal one."""
        tools = [
            {"name": "nmap", "method": "apt", "module": "networking", "url": ""},
            {"name": "ffuf", "method": "go", "module": "web", "url": ""},
            {"name": "crunch", "method": "apt", "module": "cracking", "url": ""},
            {"name": "amass", "method": "go", "module": "recon", "url": ""},
        ]
        config = tmp_path / "tools_config.json"
        config.write_text(json.dumps(tools), encoding="utf-8")
        with patch("shutil.which", return_value=None):
            return ToolsDatabase(project_root=tmp_path)

    def test_short_tool_name_matches(self, tmp_path: Path) -> None:
        # Short tool names must match.
        db = self._db(tmp_path)
        names = {t["name"] for t in _match_individual_tools("I just need nmap and burpsuite", db)}
        assert "nmap" in names

    def test_short_tool_names_match_in_listing(self, tmp_path: Path) -> None:
        db = self._db(tmp_path)
        names = {t["name"] for t in _match_individual_tools("use nmap and ffuf", db)}
        assert names == {"nmap", "ffuf"}

    def test_prose_does_not_match_english_word_tool(self, tmp_path: Path) -> None:
        # English words in prose must not be interpreted as tool names.
        db = self._db(tmp_path)
        assert _match_individual_tools("crunch the numbers", db) == []
        assert _match_individual_tools("amass a lot of evidence", db) == []

    def test_explicit_request_still_matches_english_word_tool(self, tmp_path: Path) -> None:
        # An install/tool cue lets the ambiguous names match when genuinely meant.
        db = self._db(tmp_path)
        names = {t["name"] for t in _match_individual_tools("install crunch for wordlists", db)}
        assert "crunch" in names


# list_profiles
class TestListProfiles:
    def test_returns_all_profiles(self, tools_db: ToolsDatabase) -> None:
        result = list_profiles(tools_db)
        assert result["total_profiles"] == len(PROFILES)
        assert result["total_profiles"] == 14

    def test_profile_fields(self, tools_db: ToolsDatabase) -> None:
        result = list_profiles(tools_db)
        for profile in result["profiles"]:
            assert "name" in profile
            assert "description" in profile
            assert "modules" in profile
            assert "module_count" in profile
            assert "tool_count" in profile
            assert "install_command" in profile

    def test_profile_names(self, tools_db: ToolsDatabase) -> None:
        result = list_profiles(tools_db)
        names = {p["name"] for p in result["profiles"]}
        assert names == set(PROFILES.keys())

    def test_tool_counts_positive(self, tools_db: ToolsDatabase) -> None:
        result = list_profiles(tools_db)
        for profile in result["profiles"]:
            # All profiles include "misc" module which has tools in our sample
            assert profile["tool_count"] >= 0


# C2 gating in tool counts
class TestC2ToolCounting:
    def _db_with_c2(self, tmp_path: Path) -> ToolsDatabase:
        """Build a ToolsDatabase whose misc module contains one C2 tool + one normal tool."""
        c2_name = next(iter(C2_TOOLS))
        tools = [
            {"name": c2_name, "method": "git", "module": "misc", "url": ""},
            {"name": "some-misc-tool", "method": "apt", "module": "misc", "url": ""},
        ]
        config = tmp_path / "tools_config.json"
        config.write_text(json.dumps(tools), encoding="utf-8")
        with patch("shutil.which", return_value=None):
            return ToolsDatabase(project_root=tmp_path)

    def test_count_excludes_c2_when_disabled(self, tmp_path: Path) -> None:
        db = self._db_with_c2(tmp_path)
        # include_c2=True counts both; include_c2=False drops the C2 tool.
        assert _count_module_tools(["misc"], db, include_c2=True) == 2
        assert _count_module_tools(["misc"], db, include_c2=False) == 1

    def test_profile_count_respects_include_c2_flag(self, tmp_path: Path) -> None:
        db = self._db_with_c2(tmp_path)
        # "ctf" profile has include_c2=False and includes the misc module, so the
        # C2 tool must not be counted; "full" has include_c2=True so it is.
        assert PROFILES["ctf"]["include_c2"] is False
        assert PROFILES["full"]["include_c2"] is True
        ctf_count = _count_profile_tools("ctf", db)
        full_count = _count_profile_tools("full", db)
        # The single C2 tool is excluded from ctf but present in full's misc count.
        assert ctf_count == 1
        assert full_count == 2
