"""Git CLI capability, argument policy and local/remote execution parity."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.security import (
    check_policy,
    execute_pipeline,
    execute_tool,
    execute_tool_remote,
    sanitize_args,
    validate_tool_for_execution,
    validate_tool_for_remote_execution,
)
from mcp_server.tools_db import EXECUTABLE_GIT, GIT_BIN_NAMES, ToolsDatabase, execution_metadata


@pytest.fixture(autouse=True)
def isolated_host_control_opt_ins(monkeypatch):
    monkeypatch.delenv("CYBERSEC_MCP_ALLOW_USBKILL", raising=False)
    monkeypatch.delenv("CYBERSEC_MCP_ALLOW_NIPE", raising=False)


@pytest.fixture
def git_db(tmp_path):
    registry = Path(__file__).resolve().parents[2] / "tools_config.json"
    tools = json.loads(registry.read_text())
    (tmp_path / "tools_config.json").write_text(json.dumps(tools))
    return ToolsDatabase(project_root=tmp_path)


@pytest.mark.parametrize("name", sorted(EXECUTABLE_GIT))
def test_git_cli_resolves_identically_locally_and_remotely(name, git_db):
    with patch("mcp_server.security.shutil.which", return_value="/synthetic/bin/tool"):
        assert validate_tool_for_execution(name, git_db) == GIT_BIN_NAMES[name]
    assert validate_tool_for_remote_execution(name, git_db) == GIT_BIN_NAMES[name]


@pytest.mark.parametrize("name", ["XSStrike", "Responder", "CMSmap", "RsaCtfTool", "exploitdb"])
def test_primary_binary_alias_resolves_registry_owner(name, git_db):
    launcher = GIT_BIN_NAMES[name]
    with patch("mcp_server.security.shutil.which", return_value="/synthetic/bin/tool"):
        assert validate_tool_for_execution(launcher, git_db) == launcher
    assert validate_tool_for_remote_execution(launcher, git_db) == launcher


@pytest.mark.parametrize("name", ["SecLists", "CyberChef", "PEASS-ng", "stegsolve", "Mythic"])
def test_resources_and_services_have_explicit_non_cli_reason(name, git_db):
    metadata = execution_metadata(git_db.tools_by_name[name])
    assert not metadata["executable"]
    assert metadata["reason"]
    for validate in [validate_tool_for_execution, validate_tool_for_remote_execution]:
        with pytest.raises(ValueError, match="not directly executable"):
            validate(name, git_db)


@pytest.mark.parametrize(
    "tool,args",
    [
        ("commix", "--url http://10.0.0.5/item?id=1 --batch --data id=1 --cookie sid=synthetic"),
        ("XSStrike", "-u http://127.0.0.1/?q=test --data q=test --skip --log-file /tmp/xss.log"),
        ("xsstrike", "--url=http://127.0.0.1/?q=test --skip"),
        ("ghauri", "-u http://10.0.0.5/item?id=1 --batch --dbs --dbms MySQL"),
        ("tplmap", "-u http://10.0.0.5/?name=test --level 1"),
        ("nikto", "-h http://10.0.0.5 -Tuning 123"),
        ("testssl.sh", "--quiet --jsonfile /tmp/tls.json 10.0.0.5:443"),
        ("enum4linux-ng", "-A 10.0.0.5 -u synthetic -p synthetic -oA /tmp/enum"),
        ("jwt_tool", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzeW50aGV0aWMifQ."),
        ("RsaCtfTool", "--publickey /tmp/synthetic.pub --attack wiener --private"),
        ("RsaCtfTool", "--publickey /tmp/synthetic.pub --att wiener fermat --private"),
        ("RsaCtfTool", "--createpub -n 3233 -e 17"),
        ("RsaCtfTool", "--dumpkey --publickey /tmp/synthetic.pub"),
        ("RsaCtfTool", "--dumpkey --key /tmp/synthetic.pem"),
        ("searchsploit", "-j apache"),
        ("Gopherus", "--exploit mysql"),
        ("gopherus", "--exploit=redis"),
        ("USB-HID-decoders", "/tmp/keyboard.txt --mode raw"),
        ("usb-hid-decoders", "/tmp/keyboard.txt --mode simulate"),
        ("Qiling", "run -f /tmp/rootfs/bin/synthetic --rootfs /tmp/rootfs"),
        ("firefox_decrypt", "--format json /tmp/synthetic-profile"),
        ("ShellNoob", "--from-hex /tmp/synthetic.hex --to-python /tmp/synthetic.py"),
        ("LaZagne", "all -oA -output /tmp/synthetic-output"),
    ],
)
def test_documented_private_or_offline_git_cli_shapes_pass(tool, args, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    check_policy(tool, sanitize_args(args), GIT_BIN_NAMES.get(tool, tool))


@pytest.mark.parametrize("external", ["0", "1"])
@pytest.mark.parametrize(
    "args",
    [
        "--oob",
        "--oob-server=http://127.0.0.1",
        "--oob-domain=127.0.0.1",
        "--oob-custom=synthetic",
        "--oo",
        "--os-cmd=id",
        "--file-write=/tmp/synthetic",
        "--reg-add",
        "--tamper=synthetic",
        "--tamp=synthetic",
        "--alter-shell=python",
        "--config-file=/tmp/synthetic.ini",
        "--conf=/tmp/a",
    ],
)
def test_commix_dangerous_options_blocked_with_external_opt_in(args, external, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", external)
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy("commix", sanitize_args("--url http://10.0.0.5 " + args))


@pytest.mark.parametrize(
    "tool,args",
    [
        ("commix", "--url=https://8.8.8.8/"),
        ("xsstrike", "--url https://8.8.8.8/"),
        ("nosqlmap", "--victim=8.8.8.8"),
        ("tplmap", "-uhttps://8.8.8.8/"),
        ("graphw00f", "-t https://8.8.8.8/"),
        ("jwt_tool", "-t https://8.8.8.8/"),
        ("commix", "--url http://10.0.0.5/ --proxy http://8.8.8.8:8080"),
        ("XSStrike", "--seeds /tmp/seeds.txt"),
        ("ghauri", "-r/tmp/request.txt"),
        ("SSRFmap", "-r /tmp/request.txt -p url -m portscan"),
        ("Responder", "-I eth0"),
        ("theHarvester", "-d example.org -b all"),
        ("RsaCtfTool", "--publickey /tmp/synthetic.pub --private"),
        ("RsaCtfTool", "--publickey /tmp/synthetic.pub --attack all --private"),
        ("RsaCtfTool", "--sendtofdb --publickey /tmp/synthetic.pub --attack wiener"),
        ("RsaCtfTool", "--publickey /tmp/synthetic.pub --attack wiener --atta=factordb"),
        ("RsaCtfTool", "--publickey /tmp/synthetic.pub --attack wiener --att factordb"),
        ("RsaCtfTool", "--dumpkey --decrypt 1234 --publickey /tmp/synthetic.pub"),
        ("RsaCtfTool", "--dumpkey -n 3233 -e 17 --attack factordb"),
        ("RsaCtfTool", "--dumpkey -n 3233 -e 17"),
        ("RsaCtfTool", "--tests --dumpkey"),
        ("exploitdb", "-u"),
        ("searchsploit", "-u"),
        ("searchsploit", "-ju apache"),
    ],
)
def test_git_targets_and_implicit_external_access_are_checked(tool, args, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy(tool, sanitize_args(args), GIT_BIN_NAMES.get(tool, tool))


@pytest.mark.parametrize("tool", ["azurehound", "gosecretsdump", "GoExec", "GoMapEnum", "rusthound", "rusthound-ce"])
def test_enterprise_source_clis_apply_network_preflight(tool, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy(tool, ["--target", "203.0.113.10"], tool)


def test_azurehound_requires_opt_in_for_implicit_graph_access(monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    with pytest.raises(ValueError, match="implicit external service"):
        check_policy("azurehound", ["list"], "azurehound")


@pytest.mark.parametrize("external", ["0", "1"])
@pytest.mark.parametrize(
    "tool,args",
    [
        ("commix", "--url http://10.0.0.5/ --output-dir /etc/cron.d"),
        ("XSStrike", "-u http://10.0.0.5/ --log-file /etc/profile"),
        ("ghauri", "--output-dir=/etc/cron.d"),
        ("xsstrike", "--log-f=/etc/profile"),
        ("rsatool", "-o/etc/profile -p 61 -q 53"),
        ("recon-ng", "-r /tmp/synthetic.rc"),
        ("bettercap", "-eval synthetic"),
        ("phpggc", "--test-payload"),
        ("SSRFmap", "-r /tmp/request.txt -l 4444"),
        ("testssl.sh", "--openssl=/tmp/unreviewed 10.0.0.5:443"),
        ("testssl.sh", "--jsonfile=/etc/profile 10.0.0.5:443"),
        ("USB-HID-decoders", "/tmp/keyboard.txt --mode replay"),
        ("usb-hid-decoders", "/tmp/keyboard.txt --mod=replay"),
        ("USB-HID-decoders", "/tmp/keyboard.txt -mreplay"),
        ("pp-finder", "run -- /tmp/synthetic-command"),
        ("Qiling", "run -f /tmp/synthetic --rootfs /tmp/rootfs --env /tmp/untrusted.pickle"),
        ("qltool", "run -f /tmp/synthetic --rootfs /tmp/rootfs --en=/tmp/untrusted.pickle"),
        ("Qiling", "run -f /tmp/synthetic --rootfs /"),
        ("Qiling", "run -f /tmp/synthetic --rootfs /tmp/rootfs --qdb"),
        ("usbkill", ""),
        ("usbkill", "--no-shut-down"),
        ("usbkill", "--cs"),
        ("nipe", "start"),
        ("nipe", "install"),
        ("nipe", "restart"),
        ("firefox_decrypt", "--pass-cmd /tmp/synthetic-command --format pass"),
        ("firefox_decrypt", "--pass-c=/tmp/synthetic-command"),
        ("firefox_decrypt", "-m /tmp/synthetic-command"),
        ("firefox_decrypt", "--format pass"),
        ("firefox_decrypt", "--format=pass"),
        ("firefox_decrypt", "--for=pass"),
        ("firefox_decrypt", "-fpass"),
        ("ShellNoob", "--to-strace"),
        ("ShellNoob", "--to-gdb"),
        ("ShellNoob", "--uninstall"),
        ("PRET", "-i /tmp/synthetic-commands"),
        ("PRET", "--load=/tmp/synthetic-commands"),
        ("nmapAutomator", "--host 127.0.0.1 --type Basic --static-nmap /tmp/synthetic-nmap"),
        ("LaZagne", "all -oA -output /etc/cron.d"),
        ("ShellNoob", "--from-hex /tmp/synthetic.hex --to-python /etc/profile"),
        ("ShellNoob", "--file-patch /etc/profile 0 4141"),
        ("sstrip", "/etc/profile"),
        ("rebind", "/etc/profile"),
        ("infect", "/etc/profile"),
    ],
)
def test_git_host_execution_and_sensitive_writes_stay_blocked(tool, args, external, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", external)
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy(tool, sanitize_args(args), GIT_BIN_NAMES.get(tool, tool))


@pytest.mark.parametrize("name", sorted(EXECUTABLE_GIT))
def test_git_help_does_not_require_external_opt_in(name, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    check_policy(name, ["--help"], GIT_BIN_NAMES[name])


async def test_real_synthetic_git_launcher_is_executable(git_db, tmp_path, monkeypatch):
    launcher = tmp_path / "commix"
    launcher.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    launcher.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":/usr/bin:/bin")
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    result = await execute_tool("commix", "--url http://127.0.0.1/ --batch", git_db)
    assert result["exit_code"] == 0
    assert result["stdout"] == "--url\nhttp://127.0.0.1/\n--batch\n"


async def test_git_policy_rejected_before_any_local_pipeline_or_remote_process(git_db, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    remote = MagicMock()
    remote.check_tool_allowed.return_value = True
    with (
        patch("mcp_server.security.shutil.which", return_value="/synthetic/bin/commix"),
        patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn,
        patch("mcp_server.remote.execute_remote_command", new_callable=AsyncMock) as ssh,
    ):
        local = await execute_tool("commix", "--oob", git_db)
        pipeline = await execute_pipeline([{"tool": "commix", "args": "--oob-domain=synthetic"}], git_db)
        distant = await execute_tool_remote("commix", "--oob-server=synthetic", git_db, remote, "synthetic")
    assert local["exit_code"] == pipeline["exit_code"] == distant["exit_code"] == -1
    spawn.assert_not_called()
    ssh.assert_not_called()
    remote.get_ssh_base_args.assert_not_called()


@pytest.mark.parametrize("external", ["0", "1"])
@pytest.mark.parametrize(
    "args",
    [
        "-cmd -script /tmp/synthetic.js",
        "-cmd -configfile /tmp/synthetic.properties",
        "-addoninstallall",
        "-daemon",
        "-cmd -quickurl http://127.0.0.1 -quickout /etc/profile",
    ],
)
def test_zaproxy_snap_cli_rejects_unreviewed_code_and_output(args, external, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", external)
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy("zaproxy", sanitize_args(args))


def test_zaproxy_snap_cli_supports_explicit_private_scans(git_db, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    with patch("mcp_server.security.shutil.which", return_value="/snap/bin/zaproxy"):
        assert validate_tool_for_execution("zaproxy", git_db) == "zaproxy"
    assert validate_tool_for_remote_execution("zaproxy", git_db) == "zaproxy"
    check_policy("zaproxy", sanitize_args("-cmd -quickurl http://127.0.0.1 -quickout /tmp/zap.html"))
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy("zaproxy", sanitize_args("-cmd -quickurl https://8.8.8.8"))


async def test_remote_git_cli_finds_native_binary_without_shell_interpolation(git_db, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    remote = MagicMock()
    remote.check_tool_allowed.return_value = True
    remote.get_ssh_base_args.return_value = ["ssh", "synthetic"]
    responses = [
        {"exit_code": 1, "stdout": "", "stderr": ""},
        {"exit_code": 0, "stdout": "/synthetic/bin/RsaCtfTool\n", "stderr": ""},
        {"exit_code": 0, "stdout": "synthetic result\n", "stderr": "", "command": "RsaCtfTool --help"},
    ]
    with patch("mcp_server.remote.execute_remote_command", new_callable=AsyncMock, side_effect=responses) as ssh:
        result = await execute_tool_remote("RsaCtfTool", "--help", git_db, remote, "synthetic")
    assert result["exit_code"] == 0
    assert [call.args[1] for call in ssh.call_args_list] == [
        ["which", "rsactftool"],
        ["which", "RsaCtfTool"],
        ["RsaCtfTool", "--help"],
    ]


@pytest.mark.parametrize(
    "tool,args",
    [
        ("snmp", "-v2c -c synthetic 10.0.0.5 1.3.6.1.2.1"),
        ("snmpwalk", "-v 2c -c synthetic udp:10.0.0.5:161 1.3.6.1"),
        ("bluez", "devices"),
        ("bluetoothctl", "show"),
        ("iwconfig", "wlan0"),
        ("osquery", '--json "SELECT name FROM os_version"'),
        ("osqueryi", '".schema os_version"'),
        ("nxc", "smb 10.0.0.5 -u synthetic -p synthetic --shares"),
        ("impacket-secretsdump", "synthetic/user:synthetic@10.0.0.5"),
        ("certipy", "find -u synthetic -p synthetic -dc-ip 10.0.0.5"),
    ],
)
def test_other_method_primary_aliases_keep_useful_private_or_local_cli(tool, args, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    check_policy(tool, sanitize_args(args))


@pytest.mark.parametrize("external", ["0", "1"])
@pytest.mark.parametrize(
    "tool,args",
    [
        ("bluetoothctl", "pair 00:11:22:33:44:55"),
        ("iwconfig", "wlan0 mode monitor"),
        ("osqueryi", '".shell /tmp/synthetic"'),
        ("osquery", "\"SELECT load_extension('synthetic')\""),
        ("osqueryi", "--flagfile=/tmp/synthetic.conf"),
        ("osqueryi", '"SELECT name FROM os_version; CREATE TABLE synthetic(x)"'),
        ("snmpwalk", "-v2c -c synthetic -Lf /etc/profile 10.0.0.5"),
        ("snmpwalk", "--defSecurityModel=tsm ssh:10.0.0.5"),
        ("nxc", "smb 10.0.0.5 -M /tmp/synthetic.py"),
        ("netexec", "smb 10.0.0.5 --log=/etc/profile"),
    ],
)
def test_new_primary_alias_adapters_reject_host_mutation_code_and_configuration(tool, args, external, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", external)
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy(tool, sanitize_args(args))


@pytest.mark.parametrize(
    "tool,args",
    [
        ("snmpwalk", "-v2c -c synthetic 8.8.8.8 1.3.6.1"),
        ("osqueryi", "\"SELECT * FROM curl WHERE url='http://8.8.8.8'\""),
        ("nxc", "smb 8.8.8.8 -u synthetic -p synthetic --shares"),
        ("impacket-secretsdump", "synthetic/user:synthetic@8.8.8.8"),
    ],
)
def test_new_primary_alias_network_operations_still_require_scope_opt_in(tool, args, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy(tool, sanitize_args(args))


@pytest.mark.parametrize(
    "tool", ["recon-ng", "phpsploit", "bettercap", "dnscat2", "ropium", "osqueryi", "bluetoothctl"]
)
async def test_pipeline_console_stdin_is_rejected_before_any_process(tool, git_db, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    args = '"SELECT name FROM os_version"' if tool == "osqueryi" else ""
    with (
        patch("mcp_server.security.shutil.which", return_value="/synthetic/bin/tool"),
        patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn,
    ):
        result = await execute_pipeline([{"tool": "printf", "args": "synthetic"}, {"tool": tool, "args": args}], git_db)
    assert result["exit_code"] == -1
    assert "piped stdin" in result["stderr"]
    spawn.assert_not_called()


@pytest.mark.parametrize("external", ["0", "1"])
@pytest.mark.parametrize(
    "tool,args",
    [
        ("commix", "-u http://127.0.0.1/?id=1 -c /tmp/synthetic.ini"),
        ("smuggler", "-u http://127.0.0.1/ --configfile ../../../../tmp/synthetic.py"),
        ("smuggler", "-u http://127.0.0.1/ --conf ../synthetic.py"),
        ("deepce", "-cmd id"),
        ("deepce", "-x /tmp/synthetic"),
        ("deepce", "--payload /tmp/synthetic"),
        ("deepce", "-ex SOCK"),
        ("deepce", "-l"),
        ("deepce", "-s"),
        ("deepce", "-doc"),
        ("RegRipper", "-r /tmp/hive -p ../../../../tmp/synthetic"),
        ("RegRipper", "-r /tmp/hive /plugin ../synthetic"),
        ("RegRipper", "-r /tmp/hive -PLUG=../synthetic"),
        ("RegRipper", "-r /tmp/hive -f ../../tmp/list"),
        ("RegRipper", "-uP"),
        ("PhpSploit", "--source /tmp/synthetic"),
        ("PhpSploit", "-l /tmp/synthetic"),
        ("cupp", "-l"),
        ("testssl.sh", "-oL /etc/cron.d/synthetic 127.0.0.1"),
        ("testssl.sh", "--outfile /etc/cron.d/synthetic 127.0.0.1"),
        ("CMSmap", "-U PC"),
        ("crowbar", "-b openvpn -s 127.0.0.1 -u u -C p -m /tmp/synthetic.ovpn"),
    ],
)
def test_short_and_alternate_spellings_of_blocked_options_are_refused(tool, args, external, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", external)
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy(tool, sanitize_args(args), GIT_BIN_NAMES.get(tool, tool))


@pytest.mark.parametrize(
    "tool,args",
    [
        ("RegRipper", "-r /tmp/NTUSER.DAT -p userassist"),
        ("RegRipper", "-r /p/hive -p run"),
        ("RegRipper", "-r /tmp/SOFTWARE -f software"),
        ("RegRipper", "-l"),
        ("smuggler", "-u http://127.0.0.1/ -l /tmp/synthetic.log"),
        ("testssl.sh", "-oL /tmp/synthetic.log 127.0.0.1"),
        ("deepce", "-nn"),
    ],
)
def test_ordinary_spellings_next_to_the_blocked_ones_still_pass(tool, args, monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    check_policy(tool, sanitize_args(args), GIT_BIN_NAMES.get(tool, tool))
