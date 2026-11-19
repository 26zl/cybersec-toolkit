"""Policy gaps found in review: each case was accepted by check_policy before the fix."""

from __future__ import annotations

import pytest

from mcp_server.security import check_policy, sanitize_args


@pytest.fixture(autouse=True)
def default_safe_scope(monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")
    monkeypatch.delenv("CYBERSEC_MCP_ALLOW_SCRIPTS", raising=False)


def _policy(tool: str, args: str) -> None:
    check_policy(tool, sanitize_args(args), tool)


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("curl", "8.8.8.8/x@127.0.0.1"),
        ("curl", "8.8.8.8/x?u=a@10.0.0.1"),
        ("wget", "8.8.8.8/p@127.0.0.1"),
    ],
)
def test_scheme_less_url_with_an_at_sign_after_the_host_is_validated_by_its_real_host(tool, args):
    """curl and wget read ``host/path@x`` as host ``host``; the text after ``@`` is only a path."""
    with pytest.raises(ValueError, match="not in a private/local network range"):
        _policy(tool, args)


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("curl", "user:pw@10.0.0.1"),
        ("impacket-secretsdump", "synthetic/user:synthetic@10.0.0.5"),
    ],
)
def test_credentials_before_a_private_host_still_pass(tool, args):
    _policy(tool, args)


@pytest.mark.parametrize(
    "expression",
    [
        r"s/a\//\/etc\/cron.d\//",
        r"s,^,\/etc\/,",
        "s,^,/etc/,",
        "s/x/y/;s,^,/etc/,",
        "s/x/..\\/y/",
        "s/unterminated",
    ],
)
def test_tar_transform_to_an_absolute_or_parent_path_is_blocked_however_it_is_spelled(expression):
    with pytest.raises(ValueError, match="--transform"):
        _policy("tar", f"-xf a.tar --transform='{expression}'")


@pytest.mark.parametrize("expression", [r"s,^,sub/,", r"s/\.log$//", "s/a/b/g"])
def test_tar_transform_that_stays_relative_is_allowed(expression):
    _policy("tar", f"-xf a.tar --transform='{expression}'")


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("nikto", "-h /tmp/hosts.txt"),
        ("nikto", "-host hosts.txt"),
        ("nikto", "-h./hosts.txt"),
        ("CMSmap", "-i /tmp/hosts.txt"),
        ("h2csmuggler", "--scan-list /tmp/urls.txt"),
    ],
)
def test_git_tools_that_read_a_target_list_from_a_file_are_blocked_in_default_safe_mode(tool, args):
    with pytest.raises(ValueError, match="CYBERSEC_MCP_ALLOW_EXTERNAL=1"):
        _policy(tool, args)


def test_nikto_with_a_private_host_is_allowed():
    _policy("nikto", "-h http://10.0.0.1")


@pytest.mark.parametrize("args", ["-Ei p f", "-nEi p f", "-ni.bak p f", "-e p -ni f", "-zi p f", "-i p f"])
def test_sed_in_place_is_blocked_inside_a_short_option_bundle(args):
    with pytest.raises(ValueError, match="in-place"):
        _policy("sed", args)


@pytest.mark.parametrize("args", ["-n p f", "-nE p f", "-ne p f", "-e p f", "-l 5 p f", "-nl5 p f", "-s -n 1p a b"])
def test_sed_options_without_in_place_are_allowed(args):
    _policy("sed", args)


@pytest.mark.parametrize(
    "command",
    [
        "sa breakpoints /tmp/x",
        "set lo on",
        "set hi save on",
        "she id",
        "server she id",
        "thread apply all she id",
        "thread apply 1 2 -q sa x",
        "frame apply all sa x",
        "taas she id",
        "faas call f()",
    ],
)
def test_gdb_abbreviated_and_wrapped_commands_are_blocked(command):
    with pytest.raises(ValueError, match="Blocked by policy: gdb"):
        _policy("gdb", f"-batch -ex '{command}' ./bin")


@pytest.mark.parametrize(
    "command",
    ["thread apply all bt", "thread apply 1 2 info registers", "frame 1", "thread 1", "info line main", "x/4i $pc"],
)
def test_gdb_inspection_commands_stay_allowed(command):
    _policy("gdb", f"-batch -ex '{command}' ./bin")
