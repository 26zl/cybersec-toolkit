"""Tests for the bubblewrap wrapper used in host mode."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_server import local_sandbox


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home directory with a few of the things the sandbox is about."""
    home = tmp_path / "home"
    for directory in (
        ".ssh",
        ".aws",
        ".config/gcloud",
        ".claude",
        ".mozilla",
        ".cache/tool",
        ".local/state/cybersec-tools-mcp",
    ):
        (home / directory).mkdir(parents=True)
    (home / ".ssh" / "id_ed25519").write_text("synthetic private key\n")
    (home / ".aws" / "credentials").write_text("synthetic cloud credential\n")
    (home / ".netrc").write_text("synthetic login\n")
    (home / ".bashrc").write_text("# shell startup\n")
    (home / ".local/state/cybersec-tools-mcp/audit.log").write_text("{}\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.delenv(local_sandbox.LOCAL_SANDBOX_EXPOSE_ENV, raising=False)
    return home


def _pairs(args: list[str], flag: str) -> list[str]:
    return [args[index + 1] for index, arg in enumerate(args) if arg == flag]


class TestSwitch:
    def test_off_by_default_and_the_command_is_untouched(self, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(local_sandbox.LOCAL_SANDBOX_ENV, raising=False)
        assert local_sandbox.wrap(["nmap", "-sT", "10.0.0.5"]) == ["nmap", "-sT", "10.0.0.5"]
        assert local_sandbox.startup_check() == "off"

    def test_on_prefixes_the_command(self, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(local_sandbox.LOCAL_SANDBOX_ENV, "1")
        wrapped = local_sandbox.wrap(["nmap", "-sT", "10.0.0.5"])
        assert wrapped[0] == "bwrap"
        assert wrapped[-4:] == ["--", "nmap", "-sT", "10.0.0.5"]

    def test_asked_for_without_bubblewrap_stops_the_server(self, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(local_sandbox.LOCAL_SANDBOX_ENV, "1")
        monkeypatch.setattr(shutil, "which", lambda name: None)
        with pytest.raises(RuntimeError, match="needs bubblewrap"):
            local_sandbox.startup_check()


class TestArguments:
    def test_credential_stores_are_hidden_and_startup_files_read_only(self, home: Path) -> None:
        args = local_sandbox.build_args()
        hidden = _pairs(args, "--tmpfs")
        for directory in (".ssh", ".aws", ".config/gcloud", ".claude", ".mozilla", ".local/state/cybersec-tools-mcp"):
            assert str(home / directory) in hidden, directory
        # A file is replaced by an empty one.
        assert ["--dev-bind", "/dev/null", str(home / ".netrc")] == args[args.index(str(home / ".netrc")) - 2 :][:3]
        assert str(home / ".bashrc") in _pairs(args, "--ro-bind")
        # Nothing else in the home directory is touched, and a path that does not exist is not created.
        assert str(home / ".cache") not in " ".join(args)
        assert str(home / ".gnupg") not in args

    def test_the_checkout_code_and_client_settings_are_read_only(self, home: Path) -> None:
        read_only = _pairs(local_sandbox.build_args(), "--ro-bind")
        checkout = Path(local_sandbox.__file__).resolve().parent.parent
        for relative in ("mcp_server", "scripts", ".claude", ".mcp.json", "AGENTS.md"):
            assert str(checkout / relative) in read_only, relative
        assert str(checkout / "writeups") not in read_only

    def test_cloud_modules_keep_cloud_credentials_only(self, home: Path) -> None:
        hidden = _pairs(local_sandbox.build_args(module="cloud"), "--tmpfs")
        assert str(home / ".aws") not in hidden
        assert str(home / ".config/gcloud") not in hidden
        assert str(home / ".ssh") in hidden
        assert str(home / ".aws") in _pairs(local_sandbox.build_args(module="web"), "--tmpfs")

    def test_the_operator_can_expose_a_path(self, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(local_sandbox.LOCAL_SANDBOX_EXPOSE_ENV, f"{home / '.aws'}:relative/ignored")
        hidden = _pairs(local_sandbox.build_args(), "--tmpfs")
        assert str(home / ".aws") not in hidden
        assert str(home / ".ssh") in hidden

    def test_the_runtime_directory_with_the_session_bus_is_hidden(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runtime = tmp_path / "run-user"
        runtime.mkdir()
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
        assert str(runtime) in _pairs(local_sandbox.build_args(), "--tmpfs")


def _mount(args: list[str], path: Path) -> list[str]:
    """The option and source that precede *path* where it is a mount destination."""
    target = str(path)
    for index, arg in enumerate(args):
        if arg == target and args[index - 1] == "--tmpfs":
            return ["--tmpfs"]
        if arg == target and index >= 2 and args[index - 2] in {"--bind", "--ro-bind", "--dev-bind"}:
            return args[index - 2 : index]
    return []


class TestLinks:
    """A protected name that is a link is protected where it leads."""

    def test_a_linked_credential_store_is_hidden_at_its_target(self, home: Path, tmp_path: Path) -> None:
        real = tmp_path / "elsewhere" / "keys"
        real.mkdir(parents=True)
        (home / ".gnupg").symlink_to(real)
        args = local_sandbox.build_args()
        assert _mount(args, real) == ["--tmpfs"]
        assert str(home / ".gnupg") not in args

    def test_a_linked_startup_file_is_read_only_at_its_target(self, home: Path) -> None:
        (home / "dotfiles").mkdir()
        (home / "dotfiles" / "zshrc").write_text("# zsh\n")
        (home / ".zshrc").symlink_to(home / "dotfiles" / "zshrc")
        args = local_sandbox.build_args()
        assert _mount(args, home / "dotfiles" / "zshrc") == ["--ro-bind", str(home / "dotfiles" / "zshrc")]

    def test_a_link_higher_up_the_path_is_followed_too(self, home: Path, tmp_path: Path) -> None:
        shutil.rmtree(home / ".config")
        real = tmp_path / "dotfiles" / "config"
        (real / "gcloud").mkdir(parents=True)
        (home / ".config").symlink_to(real)
        assert _mount(local_sandbox.build_args(), real / "gcloud") == ["--tmpfs"]

    def test_a_link_to_nothing_is_skipped_and_a_loop_stops_everything(self, home: Path) -> None:
        (home / ".kube").symlink_to(home / "missing")
        assert str(home / "missing") not in local_sandbox.build_args()

        (home / ".docker").symlink_to(home / ".oci")
        (home / ".oci").symlink_to(home / ".docker")
        with pytest.raises(RuntimeError, match="cannot resolve the protected path"):
            local_sandbox.build_args()

    @pytest.mark.parametrize("target", ["/", "home"])
    def test_a_link_to_the_whole_home_or_root_is_refused(self, home: Path, target: str) -> None:
        (home / ".docker").symlink_to(home if target == "home" else Path("/"))
        with pytest.raises(RuntimeError, match="cannot protect"):
            local_sandbox.build_args()


class TestPins:
    """Directories above a read-only path are mount points, so they cannot be moved aside."""

    def test_parents_are_bound_onto_themselves_before_what_they_hold(self, home: Path) -> None:
        (home / ".config" / "autostart").mkdir()
        (home / ".local" / "share" / "systemd").mkdir(parents=True)
        args = local_sandbox.build_args()
        for parent in (home / ".config", home / ".local", home / ".local" / "share"):
            assert _mount(args, parent) == ["--bind", str(parent)], parent
        assert args.index(str(home / ".config")) < args.index(str(home / ".config" / "autostart"))
        # The home directory itself is never rebound.
        assert _mount(args, home) == []

    def test_a_hidden_file_inside_a_read_only_directory_stays_hidden(self, home: Path) -> None:
        (home / ".config" / "git").mkdir()
        (home / ".config" / "git" / "credentials").write_text("synthetic token\n")
        args = local_sandbox.build_args()
        directory, secret = str(home / ".config" / "git"), str(home / ".config" / "git" / "credentials")
        assert _mount(args, home / ".config" / "git") == ["--ro-bind", directory]
        assert _mount(args, home / ".config" / "git" / "credentials") == ["--dev-bind", "/dev/null"]
        # The directory is mounted first; mounted second it would cover the empty file again.
        assert max(i for i, a in enumerate(args) if a == directory) < args.index(secret)

    def test_the_checkout_and_the_directories_above_it_are_pinned(
        self, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        checkout = home / "projects" / "toolkit"
        (checkout / "mcp_server").mkdir(parents=True)
        (checkout / ".mcp.json").write_text("{}\n")
        monkeypatch.setattr(local_sandbox, "_CHECKOUT", checkout)
        args = local_sandbox.build_args()
        assert _mount(args, checkout / ".mcp.json") == ["--ro-bind", str(checkout / ".mcp.json")]
        assert _mount(args, checkout) == ["--bind", str(checkout)]
        assert _mount(args, home / "projects") == ["--bind", str(home / "projects")]


def _bwrap_works() -> bool:
    if shutil.which("bwrap") is None:
        return False
    probe = subprocess.run(
        ["bwrap", "--bind", "/", "/", "--unshare-pid", "--proc", "/proc", "true"], capture_output=True
    )
    return probe.returncode == 0


@pytest.mark.skipif(not _bwrap_works(), reason="bubblewrap cannot create namespaces here")
class TestRealSandbox:
    """What a tool actually sees from inside."""

    @pytest.fixture(autouse=True)
    def _on(self, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(local_sandbox.LOCAL_SANDBOX_ENV, "1")
        self.home = home

    def _run(self, code: str, module: str | None = None) -> subprocess.CompletedProcess:
        command = local_sandbox.wrap([sys.executable, "-c", code], module=module)
        return subprocess.run(command, capture_output=True, text=True, timeout=30)

    def test_startup_check_passes(self) -> None:
        assert local_sandbox.startup_check() == "bwrap"

    def test_keys_credentials_and_the_audit_log_are_not_readable(self) -> None:
        code = (
            "import os\n"
            "home = os.environ['HOME']\n"
            "for name in ('.ssh/id_ed25519', '.aws/credentials', '.local/state/cybersec-tools-mcp/audit.log'):\n"
            "    print(name, os.path.exists(os.path.join(home, name)))\n"
            "print('netrc', repr(open(os.path.join(home, '.netrc')).read()))\n"
        )
        out = self._run(code).stdout
        assert ".ssh/id_ed25519 False" in out
        assert ".aws/credentials False" in out
        assert "audit.log False" in out
        assert "netrc ''" in out
        # The real files are untouched.
        assert (self.home / ".ssh" / "id_ed25519").read_text() == "synthetic private key\n"

    def test_a_cloud_tool_still_reads_cloud_credentials(self) -> None:
        code = "import os; print(open(os.path.join(os.environ['HOME'], '.aws/credentials')).read().strip())"
        assert self._run(code, module="cloud").stdout.strip() == "synthetic cloud credential"

    def test_startup_files_cannot_be_changed_but_ordinary_output_can_be_written(self) -> None:
        code = (
            "import os\n"
            "home = os.environ['HOME']\n"
            "try:\n"
            "    open(os.path.join(home, '.bashrc'), 'a').write('planted\\n'); print('bashrc written')\n"
            "except OSError as error:\n"
            "    print('bashrc refused', error.errno)\n"
            "open(os.path.join(home, '.cache/tool/out.txt'), 'w').write('result\\n'); print('output written')\n"
        )
        out = self._run(code).stdout
        assert "bashrc refused" in out
        assert "output written" in out
        assert (self.home / ".bashrc").read_text() == "# shell startup\n"
        assert (self.home / ".cache/tool/out.txt").read_text() == "result\n"

    def test_a_linked_store_is_empty_through_the_link_and_at_its_target(self, tmp_path: Path) -> None:
        real = tmp_path / "elsewhere" / "keys"
        real.mkdir(parents=True)
        (real / "secret.key").write_text("synthetic key\n")
        (self.home / ".gnupg").symlink_to(real)
        code = f"import os; print(os.listdir(os.path.join(os.environ['HOME'], '.gnupg')), os.listdir({str(real)!r}))"
        assert self._run(code).stdout.strip() == "[] []"
        assert (real / "secret.key").read_text() == "synthetic key\n"

    def test_a_linked_startup_file_cannot_be_written_through_the_link(self) -> None:
        (self.home / "dotfiles").mkdir()
        (self.home / "dotfiles" / "zshrc").write_text("# zsh\n")
        (self.home / ".zshrc").symlink_to(self.home / "dotfiles" / "zshrc")
        code = (
            "import os\n"
            "try:\n"
            "    open(os.path.join(os.environ['HOME'], '.zshrc'), 'a').write('planted\\n'); print('written')\n"
            "except OSError as error:\n"
            "    print('refused', error.errno)\n"
        )
        assert self._run(code).stdout.startswith("refused")
        assert (self.home / "dotfiles" / "zshrc").read_text() == "# zsh\n"

    def test_the_parent_of_a_protected_directory_cannot_be_moved_aside(self) -> None:
        (self.home / ".config" / "autostart").mkdir()
        code = (
            "import os\n"
            "home = os.environ['HOME']\n"
            "try:\n"
            "    os.rename(home + '/.config', home + '/.config.moved'); print('moved')\n"
            "except OSError as error:\n"
            "    print('refused', error.errno)\n"
            "open(home + '/.config/tool.conf', 'w').write('ok\\n'); print('still writable')\n"
        )
        out = self._run(code).stdout
        assert "refused" in out and "moved" not in out.replace("refused", "")
        assert "still writable" in out
        assert (self.home / ".config" / "autostart").is_dir()

    def test_the_checkout_cannot_be_swapped_and_its_output_directories_stay_writable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        checkout = self.home / "projects" / "toolkit"
        (checkout / "mcp_server").mkdir(parents=True)
        (checkout / "writeups").mkdir()
        (checkout / ".mcp.json").write_text("{}\n")
        monkeypatch.setattr(local_sandbox, "_CHECKOUT", checkout)
        code = (
            "import os, sys\n"
            "root = sys.argv[1]\n"
            "for label, action in (\n"
            "    ('move checkout', lambda: os.rename(root, root + '.moved')),\n"
            "    ('move parent', lambda: os.rename(os.path.dirname(root), os.path.dirname(root) + '.moved')),\n"
            "    ('edit settings', lambda: open(root + '/.mcp.json', 'w').write('planted')),\n"
            "    ('add server code', lambda: open(root + '/mcp_server/evil.py', 'w').write('x')),\n"
            "    ('write output', lambda: open(root + '/writeups/notes.md', 'w').write('ok')),\n"
            "):\n"
            "    try:\n"
            "        action(); print(label, 'allowed')\n"
            "    except OSError:\n"
            "        print(label, 'refused')\n"
        )
        command = local_sandbox.wrap([sys.executable, "-c", code, str(checkout)])
        out = subprocess.run(command, capture_output=True, text=True, timeout=30).stdout
        assert "move checkout refused" in out
        assert "move parent refused" in out
        assert "edit settings refused" in out
        assert "add server code refused" in out
        assert "write output allowed" in out
        assert (checkout / ".mcp.json").read_text() == "{}\n"

    def test_a_program_cannot_be_dropped_on_the_path(self) -> None:
        (self.home / ".local" / "bin").mkdir(parents=True)
        code = (
            "import os\n"
            "try:\n"
            "    open(os.path.join(os.environ['HOME'], '.local/bin/ls'), 'w').write('#!/bin/sh\\n'); print('dropped')\n"
            "except OSError:\n"
            "    print('refused')\n"
        )
        assert self._run(code).stdout.strip() == "refused"

    def test_other_processes_are_out_of_sight(self) -> None:
        code = "import os; print(sorted(int(p) for p in os.listdir('/proc') if p.isdigit()))"
        visible = self._run(code).stdout.strip()
        # Inside its own process namespace the tool sees itself and the sandbox's init, not this test.
        assert str(os.getpid()) not in visible.strip("[]").split(", ")
        assert len(visible.strip("[]").split(", ")) <= 3
