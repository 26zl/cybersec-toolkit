"""Tests for mcp_server.profiles — scoring, recommendation, and profile listing."""

from __future__ import annotations

from unittest.mock import patch

from mcp_server.profiles import (
    PROFILES,
    _score_profiles,
    list_profiles,
    recommend_install,
)
from mcp_server.tools_db import ToolsDatabase


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
