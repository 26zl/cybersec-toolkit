"""Tests for mcp_server.ctf_advisor — category resolution and tool suggestions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server.advisor_utils import TOOL_ALIASES
from mcp_server.ctf_advisor import (
    CATEGORY_ALIASES,
    CTF_CATEGORY_MAP,
    resolve_category,
    suggest_for_ctf,
)
from mcp_server.tools_db import ToolsDatabase


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

    @pytest.mark.parametrize(
        "phrase,expected",
        [
            ("crypto rsa", "crypto"),
            ("rsa crypto", "crypto"),
            ("web sqli", "web"),
            ("reversing / crypto", "reversing"),
            ("pwn (heap)", "pwn"),
        ],
    )
    def test_multi_word_input(self, phrase: str, expected: str) -> None:
        assert resolve_category(phrase) == expected

    def test_multi_word_alias_still_exact(self) -> None:
        # "prompt injection" is itself an alias — the whole string wins over its words
        assert resolve_category("prompt injection") == "llm"

    def test_no_word_matches(self) -> None:
        assert resolve_category("something entirely unrelated") is None


class TestAdvisorNotices:
    def test_missing_tools_listed_with_install_commands(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("crypto", tools_db)
        notice = result["missing_tools"]
        assert notice["missing"], "nothing installed in the test env — everything should be listed"
        assert notice["install_modules"].startswith("./install.sh --module crypto")
        # z3 is the first curated crypto tool the sample registry knows by an
        # install.sh --tool-resolvable method (pipx, under its registry name).
        assert notice["install_single_tool"] == "./install.sh --tool z3-solver"
        assert "agent_action" in notice

    def test_no_single_tool_command_when_only_venv_libraries_are_missing(
        self, tools_db: ToolsDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`--tool ctf-crypto-venv` is not a thing install.sh can do — don't print it.

        Crypto tools on PATH, venv libraries missing.
        """
        (tmp_path / "crypto" / "bin").mkdir(parents=True)
        (tmp_path / "crypto" / "bin" / "python").write_text("", encoding="utf-8")
        monkeypatch.setenv("CYBERSEC_MCP_VENVS_DIR", str(tmp_path))
        with patch("shutil.which", return_value="/usr/bin/anything"):
            result = suggest_for_ctf("crypto", tools_db)
        notice = result["missing_tools"]
        assert notice["missing"] == ["pycryptodome", "sympy", "fpylll", "cypari2"]
        assert "install_single_tool" not in notice
        assert "plan_install" not in notice
        assert notice["install_modules"].startswith("./install.sh --module crypto")

    def test_no_missing_notice_when_all_installed(self, tools_db: ToolsDatabase) -> None:
        # "web" has no venv-backed entries, so PATH alone can satisfy every tool
        with patch("shutil.which", return_value="/usr/bin/anything"):
            result = suggest_for_ctf("web", tools_db)
        assert "missing_tools" not in result

    def test_venv_library_needs_the_library_not_just_the_venv(
        self, tools_db: ToolsDatabase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A half-built crypto venv must not report every library it stands for."""
        site = tmp_path / "crypto" / "lib" / "python3.13" / "site-packages"
        (site / "sympy").mkdir(parents=True)
        (tmp_path / "crypto" / "bin").mkdir(parents=True)
        (tmp_path / "crypto" / "bin" / "python").write_text("", encoding="utf-8")
        monkeypatch.setenv("CYBERSEC_MCP_VENVS_DIR", str(tmp_path))
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("crypto", tools_db)
        status = {tool["name"]: tool["installed"] for tool in result["tools"]}
        assert status["sympy"] is True
        assert status["fpylll"] is False

    def test_script_gate_surfaced_when_disabled(self, tools_db: ToolsDatabase, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CYBERSEC_MCP_ALLOW_SCRIPTS", raising=False)
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("crypto", tools_db)
        assert result["script_execution"]["enable_with"] == "CYBERSEC_MCP_ALLOW_SCRIPTS=1"

    def test_script_gate_silent_when_enabled(self, tools_db: ToolsDatabase, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CYBERSEC_MCP_ALLOW_SCRIPTS", "1")
        with patch("shutil.which", return_value=None):
            result = suggest_for_ctf("crypto", tools_db)
        assert "script_execution" not in result


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


class TestNaturalPhrasings:
    @pytest.mark.parametrize(
        "phrase,expected",
        [
            ("web3", "blockchain"),
            ("smart contract", "blockchain"),
            ("reverse engineering", "reversing"),
            ("steg", "stego"),
            ("rsa", "crypto"),
            ("sql injection", "web"),
            ("xss", "web"),
        ],
    )
    def test_phrasing_resolves(self, phrase: str, expected: str) -> None:
        assert resolve_category(phrase) == expected

    def test_reverse_shell_phrase_still_routes_to_pwn(self) -> None:
        assert resolve_category("reverse shell pwn") == "pwn"


class TestCuratedDataIntegrity:
    def test_tools_resolve_to_registry_or_system_utility(self) -> None:
        from mcp_server.security import SYSTEM_UTILITIES

        registry = set(ToolsDatabase().tools_by_name)
        missing = [
            (cat, name)
            for cat, info in CTF_CATEGORY_MAP.items()
            for name, _desc in info["tools"]
            if TOOL_ALIASES.get(name, name) not in registry and name not in SYSTEM_UTILITIES
        ]
        assert missing == []

    def test_modules_exist(self) -> None:
        from mcp_server.tools_db import MODULE_DESCRIPTIONS

        missing = [
            (cat, m) for cat, info in CTF_CATEGORY_MAP.items() for m in info["modules"] if m not in MODULE_DESCRIPTIONS
        ]
        assert missing == []

    def test_alias_targets_are_canonical(self) -> None:
        assert [a for a, t in CATEGORY_ALIASES.items() if t not in CTF_CATEGORY_MAP] == []


class TestAdvisorExecutionCapabilities:
    @pytest.mark.parametrize("extra_present", [False, True])
    def test_extra_cli_advice_uses_its_own_launcher(self, extra_present):
        from mcp_server.advisor_utils import build_tool_status_list

        db = ToolsDatabase()
        available = "icat" if extra_present else "fls"
        with patch("shutil.which", side_effect=lambda name: f"/synthetic/{name}" if name == available else None):
            entries, _ = build_tool_status_list([("icat", "Extract a file from a forensic image")], db)
        entry = entries[0]
        assert entry["in_registry"] is True
        assert entry["registry_name"] == "sleuthkit"
        assert entry["installed"] is extra_present
        assert entry["execution"]["ready"] is extra_present

    def test_cloned_resource_and_cli_have_distinct_capability(self):
        from mcp_server.advisor_utils import build_tool_status_list

        db = ToolsDatabase()
        with patch("shutil.which", return_value=None):
            entries, _ = build_tool_status_list(
                [("SecLists", "Wordlist data"), ("commix", "Command injection testing")], db
            )
        resource, cli = entries
        assert resource["execution"]["kind"] == "resource"
        assert resource["execution"]["executable"] is False
        assert cli["execution"]["executable"] is True
        assert cli["execution"]["ready"] is False
