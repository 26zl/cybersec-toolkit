"""Tests for guided_assessment orchestration."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from mcp_server import server
from mcp_server.guided_assessment import _recommended_next_command, build_guided_plan


def test_companion_web_includes_advisor_commands_and_recommendation() -> None:
    result = build_guided_plan(
        target="http://10.0.0.1",
        target_type="web_app",
        workflow="bounty",
        mode="companion",
        intensity="low",
        authorization_confirmed=False,
        max_steps=4,
        external_enabled=False,
        tools_db=server._db,
    )

    assert "error" not in result
    assert result["workflow"] == "bounty"
    assert result["target_type"] == "web_app"
    assert result["execution"]["status"] == "not_started"
    assert result["advisor"]["target_type"] == "web_app"
    assert any(step["tool"] == "curl" for step in result["plan"]["steps"])
    assert result["companion"]["recommended_next_command"] == result["plan"]["recommended_next_command"]
    assert "I recommend running run_tool" in result["plan"]["recommended_next_command"]["recommendation"]
    assert all(not step.get("requires_include_c2") for step in result["plan"]["steps"])
    assert result["classification"]["workflow"] == "bounty"
    assert result["triage_gate"]["status"] == "blocked"
    assert "evidence-hygiene" in {skill["name"] for skill in result["recommended_skills"]}
    assert any("evidence-hygiene" in step for step in result["reporting_next_steps"])


def test_finding_classification_routes_triage_and_reporting_without_echoing_raw_secret() -> None:
    result = build_guided_plan(
        target="http://10.0.0.1/profile",
        finding="Stored XSS in profile display leaks SESSIONID=abc123",
        target_type="web_app",
        workflow="bounty",
        mode="companion",
        intensity="low",
        authorization_confirmed=True,
        max_steps=4,
        external_enabled=False,
        tools_db=server._db,
    )

    assert result["classification"]["finding"]["provided"] is True
    assert result["classification"]["finding"]["type"] == "xss"
    assert result["triage_gate"]["status"] == "needs_validation"
    assert result["triage_gate"]["report_ready"] is False
    skill_names = {skill["name"] for skill in result["recommended_skills"]}
    assert {"web2-vuln-classes", "security-arsenal", "triage-validation", "evidence-hygiene"} <= skill_names
    assert "abc123" not in json.dumps(result["classification"])
    assert "abc123" not in json.dumps(result["recommended_skills"])
    assert "abc123" not in json.dumps(result["reporting_next_steps"])


def test_recommended_next_command_escapes_display_call_arguments() -> None:
    result = _recommended_next_command(
        [
            {
                "tool": "file",
                "args": './weird "name".bin',
                "command": "file './weird \"name\".bin'",
                "installed": True,
                "auto_safe": True,
                "risk": "low",
                "rationale": "Identify file type.",
            }
        ]
    )

    assert result["run_tool_call"] == 'run_tool("file", "./weird \\"name\\".bin")'


@pytest.mark.asyncio
async def test_companion_never_auto_executes_even_when_authorized() -> None:
    with patch("mcp_server.server._execute_tool", new_callable=AsyncMock) as execute_tool:
        result = await server.guided_assessment(
            target="http://10.0.0.1",
            target_type="web_app",
            authorization_confirmed=True,
        )

    execute_tool.assert_not_called()
    assert result["mode"] == "companion"
    assert result["execution"]["status"] == "not_started"
    assert "no automatic execution" in result["execution"]["reason"]


def test_autonomous_medium_intensity_can_select_nmap_but_low_does_not() -> None:
    with (
        patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"),
        patch("mcp_server.tools_db.shutil.which", return_value="/usr/bin/tool"),
    ):
        low = build_guided_plan(
            target="10.0.0.1",
            target_type="network",
            workflow="bounty",
            mode="autonomous",
            intensity="low",
            authorization_confirmed=True,
            max_steps=10,
            external_enabled=False,
            tools_db=server._db,
        )
        medium = build_guided_plan(
            target="10.0.0.1",
            target_type="network",
            workflow="bounty",
            mode="autonomous",
            intensity="medium",
            authorization_confirmed=True,
            max_steps=10,
            external_enabled=False,
            tools_db=server._db,
        )

    low_tools = [step["tool"] for step in low["plan"]["execution_candidates"]]
    medium_tools = [step["tool"] for step in medium["plan"]["execution_candidates"]]
    assert "nmap" not in low_tools
    assert "nmap" in medium_tools


def test_autonomous_mode_emits_solver_contract_and_model_driven_steps() -> None:
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target="http://10.0.0.1",
            target_type="web_app",
            workflow="bounty",
            mode="autonomous",
            intensity="low",
            authorization_confirmed=True,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert result["mode"] == "autonomous"
    assert result["autonomous"] is not None
    assert "AUTONOMOUS SOLVER MODE" in result["autonomous"]["directive"]
    assert "full MCP toolchain" in result["autonomous"]["directive"]
    assert result["autonomous"]["default_contract"].startswith("Default guided_assessment mode is companion")
    assert "module/profile" in result["toolchain_scope"]["selection"]
    assert result["toolchain_scope"]["mcp_tools"] == [
        "list_tools",
        "check_installed",
        "get_tool_info",
        "get_module_info",
        "get_profile_tools",
        "suggest_for_ctf",
        "suggest_for_bounty",
        "guided_assessment",
        "get_cve_info",
        "recommend_install",
        "list_profiles",
        "run_tool",
        "run_pipeline",
        "run_script",
        "manage_remote_hosts",
    ]
    assert "run_tool" in result["autonomous"]["use_mcp_tools"]
    assert "run_pipeline" in result["autonomous"]["use_mcp_tools"]
    assert "run_script" in result["autonomous"]["use_mcp_tools"]
    assert result["autonomous"]["script_fallback"]["persistent_directory"] == "manual_scripts/"
    assert result["autonomous"]["script_fallback"]["created_by"] == "AI/client agent, not the user"
    assert (
        "autonomous may create, save, and run scoped scripts" in result["autonomous"]["script_fallback"]["mode_policy"]
    )
    assert "create persistent helper scripts under manual_scripts/" in result["autonomous"]["directive"]
    assert "model_driven_steps" in result["plan"]
    # ready to bootstrap recon for a private, authorized target
    assert result["execution"]["reason"] == "ready"


def test_companion_has_no_autonomous_block() -> None:
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target="./challenge.bin",
            target_type="reversing",
            workflow="ctf",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=3,
            external_enabled=False,
            tools_db=server._db,
        )
    assert result["autonomous"] is None


def test_companion_exposes_manual_script_fallback_without_autonomous_execution() -> None:
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target="./challenge.bin",
            target_type="reversing",
            workflow="ctf",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=3,
            external_enabled=False,
            tools_db=server._db,
        )

    fallback = result["manual_script_fallback"]
    assert fallback["created_by"] == "AI/client agent, not the user"
    assert fallback["persistent_directory"] == "manual_scripts/"
    assert fallback["requires_env"] == "CYBERSEC_MCP_ALLOW_SCRIPTS=1"
    assert "companion proposes the script and writes/runs it only after user approval" in fallback["mode_policy"]
    assert any("keep simple HTTP/recon commands in run_tool" in rule for rule in fallback["rules"])
    assert fallback == result["companion"]["script_fallback"]


@pytest.mark.asyncio
async def test_default_mode_is_companion_and_does_not_auto_execute() -> None:
    with patch("mcp_server.server._execute_tool", new_callable=AsyncMock) as execute_tool:
        # No mode passed -> companion is the default; autonomous is opt-in.
        result = await server.guided_assessment(
            target="http://10.0.0.1",
            target_type="web_app",
            authorization_confirmed=True,
            max_steps=2,
        )

    execute_tool.assert_not_called()
    assert result["mode"] == "companion"
    assert result["companion"] is not None
    assert "full registry/modules/profiles" in result["companion"]["directive"]
    assert "get_profile_tools" in result["toolchain_scope"]["mcp_tools"]
    assert result["autonomous"] is None


def test_auto_detection_infers_workflow_and_type() -> None:
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        url_plan = build_guided_plan(
            target="http://10.0.0.1/login",
            target_type="auto",
            workflow="auto",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )
        file_plan = build_guided_plan(
            target="./chal.pcap",
            target_type="auto",
            workflow="auto",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert url_plan["auto_detected"]["workflow"] == "bounty"
    assert url_plan["workflow"] == "bounty"
    assert url_plan["target_type"] == "web_app"
    assert file_plan["auto_detected"]["workflow"] == "ctf"
    assert file_plan["target"]["kind"] == "file"
    assert file_plan["target_type"] == "forensics"


def test_auto_detection_never_dead_ends_on_unknown_input() -> None:
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        weird_file = build_guided_plan(
            target="./mystery.zzz",  # unknown extension → universal file triage
            target_type="auto",
            workflow="auto",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )
        bare_host = build_guided_plan(
            target="weird-internal-host",  # bare token → network recon
            target_type="auto",
            workflow="auto",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert "error" not in weird_file
    assert weird_file["target"]["kind"] == "file"
    assert [s["tool"] for s in weird_file["plan"]["steps"][:3]] == ["file", "strings", "xxd"]
    assert "error" not in bare_host


def test_auto_resolution_failure_falls_back_to_generic() -> None:
    # Even if inference yields a bogus type, auto must degrade to a valid generic plan.
    with (
        patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"),
        patch("mcp_server.guided_assessment._infer_workflow_type", return_value=("ctf", "not-a-real-category")),
    ):
        result = build_guided_plan(
            target="./x",
            target_type="auto",
            workflow="auto",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert "error" not in result
    assert result["workflow"] == "generic"
    assert result["auto_detected"]["fallback"] == "generic"


@pytest.mark.asyncio
async def test_autonomous_mode_is_opt_in_and_starts_solver_loop() -> None:
    async_result = {"exit_code": 0, "stdout": "ok\n", "stderr": "", "truncated": False, "command": "tool args"}
    with (
        patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"),
        patch("mcp_server.server._execute_tool", new_callable=AsyncMock, return_value=async_result) as execute_tool,
    ):
        result = await server.guided_assessment(
            target="http://10.0.0.1",
            target_type="web_app",
            mode="autonomous",  # explicit opt-in
            authorization_confirmed=True,
            max_steps=2,
        )

    assert result["mode"] == "autonomous"
    assert execute_tool.await_count == 2  # bootstrap ran
    assert result["execution"]["status"] == "completed"
    assert "continue the user-approved auto-solver loop" in result["execution"]["reason"]
    assert result["autonomous"]["directive"]


@pytest.mark.asyncio
async def test_autonomous_ready_with_no_candidates_does_not_claim_completed() -> None:
    with (
        patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"),
        patch("mcp_server.server._execute_tool", new_callable=AsyncMock) as execute_tool,
    ):
        result = await server.guided_assessment(
            target="http://10.0.0.1",
            target_type="web_app",
            mode="autonomous",
            authorization_confirmed=True,
            max_steps=0,
        )

    execute_tool.assert_not_called()
    assert result["execution"]["status"] == "not_started"
    assert "no installed execution candidates" in result["execution"]["reason"]


@pytest.mark.asyncio
async def test_autonomous_network_requires_authorization() -> None:
    with patch("mcp_server.server._execute_tool", new_callable=AsyncMock) as execute_tool:
        result = await server.guided_assessment(
            target="http://10.0.0.1",
            target_type="web_app",
            mode="autonomous",
            authorization_confirmed=False,
        )
    execute_tool.assert_not_called()
    assert "authorization_confirmed=false" in result["execution"]["reason"]
    # the directive is still returned so the agent knows what to do once authorized
    assert result["autonomous"] is not None


def test_ctf_file_plan_uses_local_triage_tools_without_network_auth() -> None:
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target="./challenge.bin",
            target_type="reversing",
            workflow="ctf",
            mode="autonomous",
            intensity="low",
            authorization_confirmed=False,
            max_steps=3,
            external_enabled=False,
            tools_db=server._db,
        )

    assert result["target"]["kind"] == "file"
    assert result["authorization"]["required_for_execution"] is False
    assert [step["tool"] for step in result["plan"]["execution_candidates"]] == ["file", "strings", "xxd"]


def test_explicit_ctf_workflow_with_auto_type_stays_in_ctf_taxonomy() -> None:
    # C4: explicit workflow='ctf' + target_type='auto' on a .bin file must infer a
    # CTF category (pwn), resolve successfully, and yield a non-empty tool list —
    # NOT silently degrade to the empty generic plan.
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target="./challenge.bin",
            target_type="auto",
            workflow="ctf",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert "error" not in result
    assert result["workflow"] == "ctf"
    assert result["target_type"] == "pwn"
    assert result["auto_detected"].get("fallback") != "generic"
    assert len(result["advisor"]["tools"]) > 0


def test_explicit_ctf_workflow_with_auto_type_on_host_resolves() -> None:
    # C4: a bare host under explicit workflow='ctf' must infer the CTF "networking"
    # category (not bounty's "network"), so _resolve_workflow does not fail.
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target="10.0.0.5",
            target_type="auto",
            workflow="ctf",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert "error" not in result
    assert result["workflow"] == "ctf"
    assert result["target_type"] == "networking"
    assert len(result["advisor"]["tools"]) > 0


@pytest.mark.parametrize(
    "filename,expected_category",
    [
        ("./dump.mem", "forensics"),
        ("./crash.dmp", "forensics"),
        ("./capture.vmem", "forensics"),
        ("./image.raw", "forensics"),
        ("./disk.img", "forensics"),
        ("./live.iso", "forensics"),
        ("./app.jar", "reversing"),
        ("./service.war", "reversing"),
        ("./Main.class", "reversing"),
        ("./classes.dex", "reversing"),
        ("./server.crt", "crypto"),
        ("./key.der", "crypto"),
        ("./request.csr", "crypto"),
    ],
)
def test_file_extension_category_covers_common_types(filename, expected_category) -> None:
    # C5: extensions that previously fell through to 'misc' now map to a category.
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target=filename,
            target_type="auto",
            workflow="auto",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert result["target"]["kind"] == "file"
    assert result["workflow"] == "ctf"
    assert result["target_type"] == expected_category


def test_bare_hostname_not_misclassified_as_file_when_cwd_file_exists(tmp_path, monkeypatch) -> None:
    # C6: a bare network hostname must be classified as a host (network recon,
    # auth required) even if a same-named file happens to exist in the CWD.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "internal-host").write_text("not a real target")

    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target="internal-host",
            target_type="network",
            workflow="bounty",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert result["target"]["kind"] == "host"
    assert result["target"]["network"] is True
    assert result["authorization"]["required_for_execution"] is True


@pytest.mark.parametrize(
    "filename,expected_category",
    [
        ("challenge.bin", "pwn"),
        ("secret.png", "stego"),
        ("app.apk", "mobile"),
    ],
)
def test_bare_challenge_filename_in_default_auto_mode_is_a_ctf_file(filename, expected_category) -> None:
    # F7: in default companion mode (workflow=auto, target_type=auto) a bare
    # filename with no path separator but a known extension must be a CTF file
    # (local triage: file/strings/xxd), not a host routed to bounty/network.
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target=filename,
            target_type="auto",
            workflow="auto",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert "error" not in result
    assert result["target"]["kind"] == "file"
    assert result["workflow"] == "ctf"
    assert result["target_type"] == expected_category
    assert [s["tool"] for s in result["plan"]["steps"][:3]] == ["file", "strings", "xxd"]
    assert all(s["tool"] != "dig" for s in result["plan"]["steps"])
    # File triage needs no network authorization floor.
    assert result["authorization"]["required_for_execution"] is False


def test_url_with_multiple_query_params_is_accepted_and_planned() -> None:
    # F10: '&' and ';' are legal in URL query strings and the execution path uses
    # create_subprocess_exec + shlex.quote (no shell), so a multi-param URL must
    # plan instead of being rejected as containing shell metacharacters.
    with patch("mcp_server.guided_assessment.shutil.which", return_value="/usr/bin/tool"):
        result = build_guided_plan(
            target="http://10.0.0.1/api?id=1&x=2;y=3",
            target_type="web_app",
            workflow="bounty",
            mode="companion",
            intensity="low",
            authorization_confirmed=False,
            max_steps=4,
            external_enabled=False,
            tools_db=server._db,
        )

    assert "error" not in result
    assert result["target"]["kind"] == "url"
    assert any(step["tool"] == "curl" for step in result["plan"]["steps"])
    # The full multi-param URL is preserved (shlex-quoted) in the planned command.
    assert any("id=1&x=2;y=3" in step["args"] for step in result["plan"]["steps"])
