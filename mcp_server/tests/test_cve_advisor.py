"""Tests for mcp_server.cve_advisor — CVE resolution and toolkit mapping."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server.cve_advisor import (
    _FALLBACK_SKILLS,
    KNOWN_CVES,
    NAME_ALIASES,
    get_cve_info,
    resolve_cve,
)
from mcp_server.tools_db import ToolsDatabase

ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_DIR = ROOT / ".claude" / "skills"


# resolve_cve
class TestResolveCve:
    @pytest.mark.parametrize("cve", list(KNOWN_CVES.keys()))
    def test_canonical_ids(self, cve: str) -> None:
        assert resolve_cve(cve) == cve

    def test_case_insensitive_id(self) -> None:
        assert resolve_cve("cve-2021-44228") == "CVE-2021-44228"

    def test_whitespace_stripped(self) -> None:
        assert resolve_cve("  CVE-2020-1472  ") == "CVE-2020-1472"

    @pytest.mark.parametrize("alias,expected", list(NAME_ALIASES.items()))
    def test_nicknames(self, alias: str, expected: str) -> None:
        assert resolve_cve(alias) == expected

    def test_nickname_case_insensitive(self) -> None:
        assert resolve_cve("Log4Shell") == "CVE-2021-44228"

    def test_unknown_returns_none(self) -> None:
        assert resolve_cve("not-a-cve") is None
        assert resolve_cve("") is None
        assert resolve_cve("CVE-21-1") is None  # too few digits


# get_cve_info
class TestGetCveInfo:
    def test_known_cve(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = get_cve_info("log4shell", tools_db)
        assert result["cve"] == "CVE-2021-44228"
        assert result["known"] is True
        assert result["name"] == "Log4Shell"
        assert "severity" in result and "summary" in result
        assert result["recommended_skills"]
        assert "next_steps" in result

    def test_known_cve_by_id(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = get_cve_info("CVE-2017-0144", tools_db)
        assert result["cve"] == "CVE-2017-0144"
        assert result["known"] is True
        # nmap is in the sample registry; mapped tools carry install status
        assert any(t["name"] == "nmap" for t in result["tools"])
        assert all("installed" in t and "in_registry" in t for t in result["tools"])

    def test_valid_but_unknown_cve(self, tools_db: ToolsDatabase) -> None:
        result = get_cve_info("CVE-1999-0001", tools_db)
        assert result["cve"] == "CVE-1999-0001"
        assert result["known"] is False
        assert result["recommended_skills"] == _FALLBACK_SKILLS
        assert result["tools"] == []

    def test_invalid_input_returns_error(self, tools_db: ToolsDatabase) -> None:
        result = get_cve_info("definitely-not-a-cve", tools_db)
        assert "error" in result
        assert "known_nicknames" in result

    def test_live_lookup_disabled_by_default(self, tools_db: ToolsDatabase) -> None:
        result = get_cve_info("zerologon", tools_db)
        lookup = result["live_lookup"]
        assert lookup["external_enabled"] is False
        assert "CYBERSEC_MCP_ALLOW_EXTERNAL=0" in lookup["note"]
        assert "services.nvd.nist.gov" in lookup["nvd_cvss_and_refs"]

    def test_live_lookup_enabled(self, tools_db: ToolsDatabase) -> None:
        result = get_cve_info("zerologon", tools_db, external_enabled=True)
        assert result["live_lookup"]["external_enabled"] is True
        assert "enabled" in result["live_lookup"]["note"].lower()


# Data integrity — referenced skills/modules must exist in the repo
class TestCuratedDataIntegrity:
    VALID_MODULES = {
        "blockchain",
        "blueteam",
        "cloud",
        "containers",
        "cracking",
        "crypto",
        "enterprise",
        "forensics",
        "llm",
        "misc",
        "mobile",
        "networking",
        "pwn",
        "recon",
        "reversing",
        "stego",
        "web",
        "wireless",
    }

    def _all_referenced_skills(self) -> set[str]:
        skills = set(_FALLBACK_SKILLS)
        for entry in KNOWN_CVES.values():
            skills.update(entry["skills"])
        return skills

    @pytest.mark.skipif(not SKILLS_DIR.is_dir(), reason="skills dir not present")
    def test_referenced_skills_exist(self) -> None:
        for skill in sorted(self._all_referenced_skills()):
            assert (SKILLS_DIR / skill / "SKILL.md").is_file(), f"missing skill: {skill}"

    def test_referenced_modules_valid(self) -> None:
        for entry in KNOWN_CVES.values():
            for module in entry["modules"]:
                assert module in self.VALID_MODULES, f"unknown module: {module}"

    def test_name_aliases_resolve_to_known_cves(self) -> None:
        # Every nickname should point at a CVE we actually curate.
        for alias, cve in NAME_ALIASES.items():
            assert cve in KNOWN_CVES, f"alias {alias!r} → {cve} not in KNOWN_CVES"
