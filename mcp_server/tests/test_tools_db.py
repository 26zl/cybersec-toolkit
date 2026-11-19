"""Tests for mcp_server.tools_db — root discovery, loading, filtering, install checks."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server.tools_db import ToolsDatabase, _discover_project_root, resolve_binary_name

from .conftest import SAMPLE_TOOLS


class TestProjectRootDiscovery:
    def test_finds_repo_root_from_cwd_parents(self, tmp_tools_config: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        workdir = tmp_tools_config / "mcp_server"
        workdir.mkdir()
        monkeypatch.chdir(workdir)
        monkeypatch.delenv("CYBERSEC_INSTALLER_ROOT", raising=False)
        assert _discover_project_root() == tmp_tools_config.resolve()


class TestLoadTools:
    def test_loads_all_tools(self, tools_db: ToolsDatabase) -> None:
        assert tools_db.total_tools == len(SAMPLE_TOOLS)

    def test_tools_by_name_populated(self, tools_db: ToolsDatabase) -> None:
        assert "nmap" in tools_db.tools_by_name
        assert "sqlmap" in tools_db.tools_by_name

    def test_missing_config_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ToolsDatabase(project_root=tmp_path)

    @pytest.mark.parametrize("content", ["{bad", '[{"nome": "x"}]', '{"a": 1}', '["x"]'])
    def test_malformed_registry_raises_value_error_with_path(self, tmp_path: Path, content: str) -> None:
        (tmp_path / "tools_config.json").write_text(content, encoding="utf-8")
        with pytest.raises(ValueError, match="invalid registry") as excinfo:
            ToolsDatabase(project_root=tmp_path)
        assert "tools_config.json" in str(excinfo.value)

    def test_tool_fields(self, tools_db: ToolsDatabase) -> None:
        tool = tools_db.tools_by_name["nmap"]
        assert tool["method"] == "apt"
        assert tool["module"] == "networking"


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

    def test_every_registry_docker_tool_resolves_to_an_image(self) -> None:
        db = ToolsDatabase()
        unresolved = [t["name"] for t in db._tools if t["method"] == "docker" and not db._find_docker_image(t["name"])]
        assert unresolved == []

    def test_label_mapped_tools(self, tools_db: ToolsDatabase) -> None:
        assert tools_db._find_docker_image("bloodhound-ce") == "specterops/bloodhound"
        assert tools_db._find_docker_image("pentagi-docker") == "vxcontrol/pentagi:latest"


class TestDockerImageExists:
    _LISTING = "beefproject/beef:latest\nsagemath/sagemath:10.4\nlocalhost:5000/mirror:dev\n"

    def _run(self, calls: list) -> object:
        def fake_run(cmd, **kwargs):
            calls.append(cmd)

            class Result:
                stdout = TestDockerImageExists._LISTING

            return Result()

        return fake_run

    def test_untagged_ref_matches_any_tag(self, tools_db: ToolsDatabase) -> None:
        with patch("mcp_server.tools_db.subprocess.run", self._run([])):
            assert tools_db._docker_image_exists("beefproject/beef") is True
            assert tools_db._docker_image_exists("sagemath/sagemath") is True

    def test_tagged_ref_is_exact(self, tools_db: ToolsDatabase) -> None:
        with patch("mcp_server.tools_db.subprocess.run", self._run([])):
            assert tools_db._docker_image_exists("sagemath/sagemath:10.4") is True
            assert tools_db._docker_image_exists("sagemath/sagemath:latest") is False

    def test_registry_port_is_not_a_tag(self, tools_db: ToolsDatabase) -> None:
        with patch("mcp_server.tools_db.subprocess.run", self._run([])):
            assert tools_db._docker_image_exists("localhost:5000/mirror") is True

    def test_one_docker_call_per_scan(self, tools_db: ToolsDatabase) -> None:
        calls: list = []
        with patch("mcp_server.tools_db.subprocess.run", self._run(calls)):
            for image in ("beefproject/beef", "sagemath/sagemath:10.4", "missing/image"):
                tools_db._docker_image_exists(image)
        assert len(calls) == 1
        assert calls[0][:2] == ["docker", "images"]

    def test_docker_missing_is_not_installed(self, tools_db: ToolsDatabase) -> None:
        with patch("mcp_server.tools_db.subprocess.run", side_effect=FileNotFoundError):
            assert tools_db._docker_image_exists("beefproject/beef") is False


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

    def test_docker_tool_tracked_under_label(self, tmp_path: Path) -> None:
        registry = [{"name": "bloodhound-ce", "method": "docker", "module": "enterprise", "url": "x"}]
        (tmp_path / "tools_config.json").write_text(json.dumps(registry), encoding="utf-8")
        (tmp_path / ".versions").write_text("BloodHound CE|docker|latest|2024-01-01T00:00:00\n", encoding="utf-8")
        result = ToolsDatabase(project_root=tmp_path).check_installed("bloodhound-ce")
        assert result["installed"] is True
        assert result["method"] == "versions_tracked"

    def test_path_check_scans_once(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value="/usr/bin/nmap") as which:
            result = tools_db.check_installed("nmap")
        assert which.call_count == 1
        assert "/usr/bin/nmap" in result["details"]

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

    def test_ctf_venv_detected(self, tools_db: ToolsDatabase, tmp_path: Path, monkeypatch) -> None:
        """ctf-<name>-venv resolves to the run_script venv interpreter, not PATH."""
        venvs = tmp_path / "venvs"
        (venvs / "crypto" / "bin").mkdir(parents=True)
        (venvs / "crypto" / "bin" / "python").write_text("", encoding="utf-8")
        monkeypatch.setenv("CYBERSEC_MCP_VENVS_DIR", str(venvs))
        with patch("shutil.which", return_value=None):
            result = tools_db.check_installed("ctf-crypto-venv")
        assert result["installed"] is True
        assert result["method"] == "venv"

    def test_ctf_venv_missing(self, tools_db: ToolsDatabase, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("CYBERSEC_MCP_VENVS_DIR", str(tmp_path / "empty"))
        with patch("shutil.which", return_value=None):
            result = tools_db.check_installed("ctf-crypto-venv")
        assert result["installed"] is False

    def test_special_binary_fallback(self, tmp_tools_config: Path) -> None:
        """special-method tools (metasploit->msfconsole) found via binary fallback."""
        # Add a special-method tool to the sample registry on disk.
        import json

        config = tmp_tools_config / "tools_config.json"
        tools = json.loads(config.read_text(encoding="utf-8"))
        tools = [t for t in tools if t["name"] != "metasploit"]
        tools.append({"name": "metasploit", "method": "special", "module": "pwn", "url": ""})
        config.write_text(json.dumps(tools), encoding="utf-8")
        db = ToolsDatabase(project_root=tmp_tools_config)

        def mock_which(name: str):
            # The registry name (metasploit) is NOT on PATH; only its binary is.
            return "/usr/bin/msfconsole" if name == "msfconsole" else None

        with patch("shutil.which", side_effect=mock_which):
            result = db.check_installed("metasploit")
        assert result["installed"] is True
        assert result["method"] == "special_binary"
        assert "msfconsole" in result["details"]

    def test_special_binary_fallback_not_installed(self, tmp_tools_config: Path) -> None:
        """special-method tool reports not installed when its binary is absent."""
        import json

        config = tmp_tools_config / "tools_config.json"
        tools = json.loads(config.read_text(encoding="utf-8"))
        tools.append({"name": "foundry", "method": "special", "module": "blockchain", "url": ""})
        config.write_text(json.dumps(tools), encoding="utf-8")
        db = ToolsDatabase(project_root=tmp_tools_config)
        with patch("shutil.which", return_value=None):
            result = db.check_installed("foundry")
        assert result["installed"] is False

    def test_not_installed(self, tools_db: ToolsDatabase) -> None:
        with patch("shutil.which", return_value=None):
            result = tools_db.check_installed("nmap")
        assert result["installed"] is False


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
        # A present-but-unreadable file must warn, not silently degrade,
        # and only once across repeated reads.
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with pytest.warns(RuntimeWarning, match="not readable"):
                assert db.reload_versions(ttl=0) == {}
            import warnings as _w

            with _w.catch_warnings():
                _w.simplefilter("error")
                assert db.reload_versions(ttl=0) == {}

    def test_missing_versions_file_does_not_warn(self, tmp_tools_config: Path) -> None:
        db = ToolsDatabase(project_root=tmp_tools_config)
        import warnings as _w

        with _w.catch_warnings():
            _w.simplefilter("error")
            assert db.reload_versions(ttl=0) == {}

    def test_corrupt_non_utf8_versions_file(self, tmp_tools_config: Path) -> None:
        """A non-UTF-8/torn .versions file must degrade gracefully, not crash."""
        versions = tmp_tools_config / ".versions"
        versions.write_bytes(b"\xff\xfe\x00bad\n")
        db = ToolsDatabase(project_root=tmp_tools_config)
        # reload_versions tolerates the garbage and returns a dict, and
        # check_installed (which calls it) must not raise.
        assert isinstance(db.reload_versions(), dict)
        result = db.check_installed("nmap")
        assert "installed" in result

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


class TestResolveBinaryName:
    """Registry tool name -> executable name, per install method."""

    def test_npm_package_names_resolve_to_their_binaries(self) -> None:
        assert resolve_binary_name("npm", "rea-agents") == "rea"
        assert resolve_binary_name("npm", "rms-runtime-mobile-security") == "rms"

    def test_cargo_crate_names_resolve_to_their_binaries(self) -> None:
        assert resolve_binary_name("cargo", "yara-x-cli") == "yr"

    def test_unmapped_names_pass_through_unchanged(self) -> None:
        assert resolve_binary_name("npm", "apk-mitm") == "apk-mitm"
        assert resolve_binary_name("cargo", "ripgrep") == "ripgrep"
        assert resolve_binary_name("go", "nuclei") == "nuclei"


class TestExecutionMetadata:
    def test_git_cli_has_resolved_binary_and_network_classification(self):
        from mcp_server.tools_db import execution_metadata

        result = execution_metadata({"name": "XSStrike", "method": "git"})
        assert result["executable"] is True
        assert result["binary"] == "xsstrike"
        assert result["network"] is True

    def test_git_resource_is_discoverable_without_claiming_cli_support(self):
        from mcp_server.tools_db import execution_metadata

        result = execution_metadata({"name": "SecLists", "method": "git"})
        assert result["executable"] is False
        assert result["kind"] == "resource"
        assert "run_tool" in result["access"]

    def test_unknown_git_project_fails_closed(self):
        from mcp_server.tools_db import execution_metadata

        result = execution_metadata({"name": "unreviewed-example", "method": "git"})
        assert result["executable"] is False
        assert "review" in result["reason"].lower()

    def test_every_registry_git_tool_has_explicit_classification(self):
        from mcp_server.tools_db import GIT_BIN_NAMES, GIT_NON_EXECUTABLE

        names = {tool["name"] for tool in ToolsDatabase()._tools if tool["method"] == "git"}
        assert names == set(GIT_BIN_NAMES) | set(GIT_NON_EXECUTABLE)
        assert not (set(GIT_BIN_NAMES) & set(GIT_NON_EXECUTABLE))

    def test_git_alias_uses_owning_registry_tool(self):
        from mcp_server.tools_db import package_for_extra_binary

        assert resolve_binary_name("git", "XSStrike") == "xsstrike"
        assert package_for_extra_binary("xsstrike") == "XSStrike"
        assert package_for_extra_binary("msfconsole") == "metasploit"

    def test_duplicate_registry_names_fail_instead_of_shadowing(self, tmp_path):
        entries = [{"name": "example", "method": "git", "module": "web"}] * 2
        (tmp_path / "tools_config.json").write_text(json.dumps(entries))
        with pytest.raises(ValueError, match="duplicate"):
            ToolsDatabase(project_root=tmp_path)

    def test_search_matches_registry_and_binary_names(self):
        db = ToolsDatabase()
        assert [t["name"] for t in db.list_tools(query="XSSTRIKE")] == ["XSStrike"]
        assert "metasploit" in {t["name"] for t in db.list_tools(query="msfconsole")}

    def test_execution_filter_keeps_resources_available_by_default(self):
        db = ToolsDatabase()
        assert "SecLists" in {t["name"] for t in db.list_tools()}
        assert "SecLists" not in {t["name"] for t in db.list_tools(executable_only=True)}
        assert "commix" in {t["name"] for t in db.list_tools(executable_only=True)}

    def test_native_binary_installation_and_readiness_agree(self):
        db = ToolsDatabase()
        with patch("shutil.which", side_effect=lambda name: "/usr/bin/qltool" if name == "qltool" else None):
            assert db.check_installed("Qiling")["installed"] is True
            status = db.execution_status("Qiling")
        assert status["ready"] is True
        assert status["binary"] == "qltool"

    def test_known_native_alias_is_searchable(self):
        result = ToolsDatabase().list_tools(query="rsacrack")
        assert [t["name"] for t in result] == ["RsaCtfTool"]

    def test_suites_with_verified_primary_cli_remain_executable(self):
        from mcp_server.tools_db import execution_metadata

        for name in (
            "dnscat2",
            "firmware-mod-kit",
            "pkinittools",
            "libnfc-crypto1-crack",
            "USB-HID-decoders",
            "libc-database",
        ):
            assert execution_metadata({"name": name, "method": "git"})["executable"] is True

    def test_libc_database_does_not_take_over_system_find(self):
        from mcp_server.tools_db import package_for_extra_binary

        assert resolve_binary_name("git", "libc-database") == "libc-database"
        assert package_for_extra_binary("find") is None


class TestPackageLaunchers:
    @pytest.mark.parametrize(
        ("method", "name", "binary"),
        [
            ("source", "AFLplusplus", "afl-fuzz"),
            ("source", "ELFkickers", "sstrip"),
            ("source", "PkCrack", "pkcrack"),
            ("source", "Donut", "donut"),
            ("binary", "dex2jar", "d2j-dex2jar"),
            ("binary", "osquery", "osqueryi"),
            ("binary", "heimdall-rs", "heimdall"),
            ("pipx", "netexec", "nxc"),
            ("apt", "snmp", "snmpwalk"),
            ("apt", "poppler-utils", "pdftotext"),
            ("apt", "zbar-tools", "zbarimg"),
            ("apt", "ewf-tools", "ewfinfo"),
            ("apt", "binutils", "readelf"),
        ],
    )
    def test_package_aliases_select_the_real_cli(self, method, name, binary):
        from mcp_server.tools_db import package_for_extra_binary

        assert resolve_binary_name(method, name) == binary
        assert package_for_extra_binary(binary) == name

    def test_every_source_row_has_explicit_binary_metadata(self):
        from mcp_server.tools_db import SOURCE_BIN_NAMES

        names = {tool["name"] for tool in ToolsDatabase()._tools if tool["method"] == "source"}
        assert names == set(SOURCE_BIN_NAMES)

    @pytest.mark.parametrize("name", ["forensics-extra", "libnfc-dev"])
    def test_non_cli_packages_remain_visible_with_correct_capability(self, name):
        from mcp_server.tools_db import execution_metadata

        tool = ToolsDatabase().get_tool(name)
        assert tool is not None
        assert execution_metadata(tool)["executable"] is False

    def test_binary_label_tracking_matches_registry_package(self, tmp_path):
        config = [{"name": "osquery", "method": "binary", "module": "blueteam"}]
        (tmp_path / "tools_config.json").write_text(json.dumps(config))
        (tmp_path / ".versions").write_text("osqueryi|binary|1.2.3|2000-01-01\n")
        with patch("shutil.which", return_value=None):
            db = ToolsDatabase(project_root=tmp_path)
            assert db.check_installed("osquery")["installed"] is True
            assert db.execution_status("osquery")["ready"] is False

    def test_suite_extra_binary_resolves_to_registry_owner(self):
        from mcp_server.tools_db import package_for_extra_binary

        assert package_for_extra_binary("elfls") == "ELFkickers"
        assert package_for_extra_binary("pycdas") == "pycdc"


@pytest.mark.parametrize(("extra", "primary"), [("icat", "fls"), ("pycdas", "pycdc"), ("elfls", "sstrip")])
@pytest.mark.parametrize("extra_present", [False, True])
def test_extra_binary_readiness_checks_requested_executable(extra, primary, extra_present):
    db = ToolsDatabase()
    available = extra if extra_present else primary
    with patch("shutil.which", side_effect=lambda binary: f"/usr/bin/{binary}" if binary == available else None):
        status = db.execution_status(extra)
        installed = db.check_installed(extra)
    assert status["binary"] == extra
    assert status["ready"] is extra_present
    assert installed["installed"] is extra_present


@pytest.mark.parametrize(
    ("owner", "native"),
    [
        ("SET", "setoolkit"),
        ("wifite2", "wifite"),
        ("RegRipper", "rip"),
        ("RegRipper", "rip.pl"),
        ("nikto", "nikto.pl"),
        ("PCredz", "Pcredz"),
    ],
)
def test_verified_native_git_launchers_resolve_without_toolkit_wrapper(owner, native):
    db = ToolsDatabase()
    with patch("shutil.which", side_effect=lambda binary: f"/usr/bin/{binary}" if binary == native else None):
        status = db.execution_status(owner)
        assert db.check_installed(owner)["installed"] is True
    assert status["ready"] is True
    assert status["binary"] == native
    assert db.get_tool(native)["name"] == owner


@pytest.mark.parametrize("name", ["usbkill", "nipe"])
@pytest.mark.parametrize("value", [None, "0", "true", "yes", "1"])
def test_host_control_discovery_reports_the_specific_activation(name, value, monkeypatch):
    from mcp_server.tools_db import HOST_CONTROL_OPT_INS, execution_metadata, execution_summary

    variable = HOST_CONTROL_OPT_INS[name]
    if value is None:
        monkeypatch.delenv(variable, raising=False)
    else:
        monkeypatch.setenv(variable, value)
    tool = ToolsDatabase().get_tool(name)
    metadata = execution_metadata(tool)
    activation = metadata["activation"]
    assert activation["environment_variable"] == variable
    assert activation["enabled"] is (value == "1")
    assert execution_summary(tool)["activation"] == activation
    assert ("stop" in activation["requires_external_for"]) is False
    if name == "nipe":
        assert set(activation["requires_external_for"]) == {"install", "start", "restart", "status"}
