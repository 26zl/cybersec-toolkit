"""Tools that run programs, machine images or console commands keep run_tool to inspection."""

from __future__ import annotations

import shlex
import socket

import pytest

from mcp_server.security import check_policy
from mcp_server.tools_db import execution_metadata

# (registry name, launcher binary)
BINARIES = {
    "valgrind": "valgrind",
    "rr": "rr",
    "qemu-user-static": "qemu-x86_64-static",
    "qemu-system-x86": "qemu-system-x86_64",
    "proxychains4": "proxychains4",
    "honggfuzz": "honggfuzz",
    "AFLplusplus": "afl-fuzz",
    "metasploit": "msfconsole",
    "pwntools": "pwn",
    "volatility3": "vol",
    "frida-tools": "frida",
    "radare2": "radare2",
    "rizin": "rizin",
}

REFUSED = [
    ("valgrind", "/bin/sh -c id"),
    ("valgrind", "--tool=none /bin/ls"),
    ("rr", "record /bin/sh"),
    ("rr", "/bin/sh"),
    ("rr", "replay"),
    ("rr", "-M record /bin/sh"),
    ("qemu-user-static", "/bin/sh -c id"),
    ("qemu-user-static", "-L / /bin/sh"),
    ("qemu-user-static", "help"),
    ("qemu-system-x86", "-serial file:/etc/cron.d/x"),
    ("qemu-system-x86", "-netdev user,id=n"),
    ("qemu-system-x86", "-drive file=/etc/shadow"),
    ("proxychains4", "-q nmap 10.0.0.1"),
    ("honggfuzz", "-i in -- /bin/sh"),
    ("AFLplusplus", "-i in -o out -- /bin/sh"),
    ("metasploit", "-q -x 'irb -e 1'"),
    ("metasploit", "-r /tmp/synthetic.rc"),
    ("metasploit", "-x 'use auxiliary/scanner/portscan/tcp; set RHOSTS 8.8.8.8; run'"),
    ("pwntools", "debug --exec /bin/sh"),
    ("pwntools", "template ./chal"),
    ("pwntools", "template --template /tmp/synthetic.mako"),
    ("pwntools", "update"),
    ("pwntools", "asm -r nop"),
    ("pwntools", "asm nop --ru"),
    ("pwntools", "asm -nzr nop"),
    ("pwntools", "shellcraft -d amd64.linux.sh"),
    ("pwntools", "scramble -d"),
    ("pwntools", "asm -o /etc/cron.d/x nop"),
    ("pwntools", "shellcraft --out=/etc/cron.d/x amd64.linux.sh"),
    ("pwntools", "disablenx /usr/bin/ls"),
    ("pwntools", "libcdb lookup puts 0x420"),
    ("pwntools", "libcdb hash -d abc --offline-only"),
    ("volatility3", "-p /tmp/plugins -f mem.raw windows.info"),
    ("volatility3", "--plug /tmp/plugins -f mem.raw windows.info"),
    ("volatility3", "-vqp /tmp/plugins -f mem.raw windows.info"),
    ("volatility3", "-o /etc/cron.d -f mem.raw windows.dumpfiles"),
    ("volatility3", "-u http://8.8.8.8/isf -f mem.raw windows.info"),
    ("frida-tools", "-n bash -e Process.id"),
    ("frida-tools", "-f /bin/sh"),
    ("frida-tools", "-D local -n bash"),
    ("frida-tools", "-R -n bash"),
    ("frida-tools", "-H 127.0.0.1 -n bash"),
    ("frida-tools", "-H localhost:27042 -n bash"),
    ("frida-tools", "-H 0.0.0.0 -n bash"),
    ("frida-tools", "-H [::] -n bash"),
    ("frida-tools", "-H [::ffff:127.0.0.1]:27042 -n bash"),
    ("frida-tools", "-H 8.8.8.8 -n app"),
    ("frida-tools", "-U -O /tmp/options.txt"),
    ("frida-tools", "-U -c user/script -f com.example.app"),
    ("frida-tools", "-U -f com.example.app -o /etc/cron.d/x"),
    ("radare2", "-d /bin/sh"),
    ("radare2", "-qd /bin/sh"),
    ("radare2", "-R program=/bin/sh /bin/ls"),
    ("radare2", "-w /etc/passwd"),
    ("radare2", "-l /tmp/plugin.so /bin/ls"),
    ("radare2", "-qc ood /bin/sh"),
    ("radare2", "-qc 'wx 90' /tmp/chal"),
    ("radare2", "-qc 'o gdb://8.8.8.8:1234' /bin/ls"),
    ("radare2", "rap://8.8.8.8:9090//bin/ls"),
    ("radare2", "-qc 'pd 10 | sh' /bin/ls"),
    ("radare2", "-qc 'pd 10 > /tmp/out' /bin/ls"),
    ("radare2", "-qc '$alias=wx 90' /bin/ls"),
    ("radare2", "-qc 'pd 1 @@c:wx 90' /bin/ls"),
    ("radare2", "-qc '?t wx 90' /bin/ls"),
    ("radare2", "-qc 'e scr.pager=sh' /bin/ls"),
    ("radare2", "-e cfg.sandbox=false /bin/ls"),
    ("radare2", "-qc 'iO d/S/.text' /bin/ls"),
    ("radare2", "-qc 'agw /tmp/graph.png' /bin/ls"),
    ("radare2", "-qc 'agfw /tmp/graph.png' /bin/ls"),
    ("radare2", "-qc 'agcw' /bin/ls"),
    ("radare2", "-qc '?? wx 90' /bin/ls"),
    ("rizin", "-d /bin/sh"),
    ("rizin", "-qc '\"(x) !id\"' /bin/ls"),
    ("rizin", "-qc 'q; wt /tmp/out' /bin/ls"),
]

PERMITTED = [
    ("valgrind", "--version"),
    ("rr", "ps"),
    ("rr", "dump /tmp/trace"),
    ("qemu-user-static", "-version"),
    ("qemu-user-static", "-cpu help"),
    ("qemu-system-x86", "-machine help"),
    ("metasploit", "--version"),
    ("pwntools", "checksec /tmp/chal"),
    ("pwntools", "cyclic -l 0x61616162"),
    ("pwntools", "asm -c amd64 'mov eax, 1'"),
    ("pwntools", "asm -f hex -o /tmp/sc.bin nop"),
    ("pwntools", "shellcraft --delim + -f raw amd64.linux.sh"),
    ("pwntools", "disablenx /tmp/chal"),
    ("pwntools", "libcdb file /tmp/libc.so.6"),
    ("pwntools", "libcdb lookup puts 0x420 --offline-only"),
    ("volatility3", "-f /tmp/mem.raw windows.pslist --pid 4"),
    ("volatility3", "-fp.raw windows.info"),
    ("volatility3", "-o /tmp/out -s /tmp/symbols -f /tmp/mem.raw windows.dumpfiles"),
    ("frida-tools", "-U -f com.example.app -l /tmp/hook.js"),
    ("frida-tools", "-Uf com.example.app -l /tmp/hook.js -o /tmp/frida.log"),
    ("frida-tools", "-D emulator-5554 -n Gadget -e Process.id -q"),
    ("frida-tools", "-H 10.0.0.7:27042 -n app"),
    ("radare2", "-qc 'aaa; afl' /tmp/chal"),
    ("radare2", "-A -qc 'pdf @ main' /tmp/chal"),
    ("radare2", "-e asm.arch=arm -e asm.bits=32 -qc 'pd 20; iz~flag' /tmp/fw.bin"),
    ("radare2", "-qc 'axt @ sym.imp.system; pd 1 @@ sym.*' /tmp/chal"),
    ("radare2", "malloc://512"),
    ("radare2", "-qc 'agf; agfd' /tmp/chal"),
    ("rizin", "-e analysis.depth=64 -qc 'aaa; pdf @ main' /tmp/chal"),
]


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "0")


@pytest.mark.parametrize(("tool", "args"), REFUSED)
def test_launching_writing_and_remote_uses_are_refused(offline, tool, args):
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy(tool, shlex.split(args), BINARIES[tool])


@pytest.mark.parametrize(("tool", "args"), PERMITTED)
def test_inspection_uses_still_run(offline, tool, args):
    check_policy(tool, shlex.split(args), BINARIES[tool])


@pytest.mark.parametrize(("name", "args"), [("msfconsole", "-x version"), ("afl-fuzz", "-i in -o out -- /bin/sh")])
def test_launcher_names_get_their_package_policy(offline, name, args):
    with pytest.raises(ValueError, match="Blocked by policy"):
        check_policy(name, shlex.split(args), name)


def test_external_libc_lookups_follow_the_external_switch(monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_EXTERNAL", "1")
    check_policy("pwntools", ["libcdb", "lookup", "puts", "0x420"], "pwn")


@pytest.mark.parametrize(
    ("tool", "method", "expected"),
    [
        ("metasploit", "special", "help and version output only"),
        ("AFLplusplus", "source", "help and version output only"),
        ("radare2", "apt", "read-only analysis commands"),
        ("frida-tools", "pipx", "USB (-U)"),
    ],
)
def test_tool_metadata_names_the_route_run_tool_leaves(tool, method, expected):
    access = execution_metadata({"name": tool, "method": method, "module": "misc", "url": ""})["access"]
    assert expected in access


def _own_address() -> str | None:
    """An address this host carries, from the route to a private destination (nothing is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("10.255.255.255", 1))
            return probe.getsockname()[0]
    except OSError:
        return None


def test_frida_refuses_an_address_of_this_machine(offline):
    address = _own_address()
    if address is None or address.startswith("127."):
        pytest.skip("no non-loopback interface address")
    with pytest.raises(ValueError, match="this machine"):
        check_policy("frida-tools", ["-H", f"{address}:27042", "-n", "app"], "frida")


def test_frida_takes_ip_addresses_only(offline):
    with pytest.raises(ValueError, match="IP address"):
        check_policy("frida-tools", ["-H", "lab-device.example:27042", "-n", "app"], "frida")
