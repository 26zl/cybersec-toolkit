"""A bubblewrap wrapper for the tools and scripts the server starts in host mode.

Host mode has no VM, so a tool runs as the operator. With CYBERSEC_LOCAL_SANDBOX=1
each tool and script starts inside bubblewrap instead, away from what a hostile
sample or a misled agent reaches for first: credential stores, browser profiles,
the agent's own configuration, this checkout's code and settings, the audit log,
the session bus, and every other process of the account.

It is a narrower boundary than the Kata VM. The tool keeps the operator's uid,
the kernel and the network; everything not listed below stays as it was, so tools
keep their caches and write their output where they always did.

Hiding is exact: the data a protected name leads to is out of reach, links
followed. Write protection covers what exists when a tool starts. The home
directory stays writable, so a tool can still create a file that was not there,
or put a file where a protected name was only a link; that is why this is not a
guarantee against persistence.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

LOCAL_SANDBOX_ENV = "CYBERSEC_LOCAL_SANDBOX"
# Operator override: extra absolute paths, separated by ':', that stay visible.
LOCAL_SANDBOX_EXPOSE_ENV = "CYBERSEC_LOCAL_SANDBOX_EXPOSE"

# Replaced by an empty directory or an empty file. Relative to the home directory.
_HIDDEN_IN_HOME = (
    # Keys and credential stores
    ".ssh", ".gnupg", ".password-store", ".local/share/keyrings", ".netrc", ".git-credentials",
    ".config/git/credentials", ".vault-token", ".config/op", ".config/1Password", ".config/Bitwarden",
    ".config/gh", ".config/hub", ".config/rclone", ".config/sops", ".terraform.d", ".npmrc", ".pypirc",
    ".cargo/credentials", ".cargo/credentials.toml", ".gem/credentials",
    # Cloud and cluster credentials (kept for the cloud and containers modules, see _MODULE_NEEDS)
    ".aws", ".azure", ".config/gcloud", ".kube", ".docker", ".oci", ".config/doctl",
    # Browser profiles and mail: cookies, saved logins, session tokens
    ".mozilla", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware",
    ".config/microsoft-edge", ".config/vivaldi", ".thunderbird",
    # The agent's own configuration: tokens to read, and settings, hooks and memory to plant
    ".claude", ".claude.json", ".codex", ".gemini", ".config/opencode", ".cursor", ".continue",
    ".config/goose", ".hermes", ".openclaw", ".config/github-copilot", ".config/Claude",
)  # fmt: skip
_CLOUD_PATHS = frozenset({".aws", ".azure", ".config/gcloud", ".kube", ".docker", ".oci", ".config/doctl"})
# Tools of these modules exist to use those credentials on an authorized account.
_MODULE_NEEDS = {"cloud": _CLOUD_PATHS, "containers": _CLOUD_PATHS}

# Stays readable, cannot be written: what runs at the operator's next login or commit.
_READ_ONLY_IN_HOME = (
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zshenv",
    ".zprofile", ".zlogin", ".config/fish", ".config/autostart", ".config/systemd", ".local/share/systemd",
    ".config/environment.d", ".pam_environment", ".xprofile", ".xinitrc", ".gitconfig", ".config/git",
    # Directories on PATH: a program dropped here runs the next time its name is typed.
    ".local/bin", "bin",
)  # fmt: skip
# The checkout the server runs from: its code, its client settings and its git metadata.
# Output directories such as writeups/ and manual_scripts/ are not listed and stay writable.
_READ_ONLY_IN_CHECKOUT = (
    ".git", ".github", ".claude", ".agents", ".codex", ".gemini", ".mcp.json", "opencode.jsonc",
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", "mcp_server", "sandbox", "scripts", "lib", "modules",
    "profiles", "install.sh", "tools_config.json",
)  # fmt: skip

_CHECKOUT = Path(__file__).resolve().parent.parent


def enabled() -> bool:
    return os.environ.get(LOCAL_SANDBOX_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _state_dir() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return base / "cybersec-tools-mcp"


def _exposed() -> set[str]:
    raw = os.environ.get(LOCAL_SANDBOX_EXPOSE_ENV, "")
    return {os.path.realpath(item) for item in raw.split(":") if item.startswith("/")}


def _resolve(path: Path) -> Path | None:
    """The file or directory *path* leads to, with every link followed; None when nothing is there.

    Mounts go on this path, not on the name: a protected name that is a link would
    otherwise leave the data it points to in plain view.
    """
    try:
        return Path(os.path.realpath(path, strict=True))
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        # A link loop: there is no telling what the name stands for, so nothing may run.
        raise RuntimeError(f"The host sandbox cannot resolve the protected path {path}: {exc.strerror or exc}") from exc


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _plan(module: str | None = None) -> list[tuple[str, Path]]:
    """The mounts that make up the sandbox, as (kind, real path), outermost path first.

    Kinds: "hide-dir" and "hide-file" replace a path with something empty, "ro"
    makes it read-only, and "pin" binds a directory onto itself unchanged. A pin
    turns the directory into a mount point, which cannot be renamed: without it a
    tool could move the parent of a read-only directory aside and put its own in
    that place.
    """
    home = Path(os.path.realpath(Path.home()))
    checkout = Path(os.path.realpath(_CHECKOUT))
    exposed = _exposed()
    keep = _MODULE_NEEDS.get(module or "", frozenset())
    # Strongest wins when two entries name one path.
    rank = {"pin": 0, "ro": 1, "hide-file": 2, "hide-dir": 2}
    mounts: dict[Path, str] = {}

    def add(kind: str, real: Path) -> None:
        if real not in mounts or rank[kind] >= rank[mounts[real]]:
            mounts[real] = kind

    def protect(path: Path, hide: bool) -> None:
        real = _resolve(path)
        if real is None or str(real) in exposed:
            return
        if real == Path("/") or _is_within(home, real) or _is_within(checkout, real):
            raise RuntimeError(
                f"The host sandbox cannot protect {path}: it leads to {real}, which holds your home directory "
                f"or this checkout. Point it somewhere narrower or list it in {LOCAL_SANDBOX_EXPOSE_ENV}."
            )
        if hide:
            add("hide-dir" if real.is_dir() else "hide-file", real)
            return
        add("ro", real)
        # Every directory between the read-only path and the home directory has to stay where it is.
        if _is_within(real, home):
            for parent in real.parents:
                if parent == home:
                    break
                add("pin", parent)

    for relative in _HIDDEN_IN_HOME:
        if relative not in keep:
            protect(home / relative, hide=True)
    # The audit log and the remote-host list belong to the server, not to what it runs.
    protect(_state_dir(), hide=True)
    # The session bus can start programs outside the sandbox; agent and keyring sockets live here too.
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if runtime_dir.startswith("/"):
        protect(Path(runtime_dir), hide=True)

    for relative in _READ_ONLY_IN_HOME:
        protect(home / relative, hide=False)
    for relative in _READ_ONLY_IN_CHECKOUT:
        protect(checkout / relative, hide=False)
    # The checkout itself must not be moved aside and replaced either.
    if str(checkout) not in exposed and any(_is_within(real, checkout) for real in mounts):
        add("pin", checkout)
        if _is_within(checkout, home):
            for parent in checkout.parents:
                if parent == home:
                    break
                add("pin", parent)

    # A mount on a directory covers what was mounted inside it before, so parents come first,
    # and nothing is mounted inside a directory that is already replaced by an empty one.
    hidden_dirs = [real for real, kind in mounts.items() if kind == "hide-dir"]
    ordered = sorted(mounts.items(), key=lambda item: (len(item[0].parts), str(item[0])))
    return [
        (kind, real) for real, kind in ordered if not any(real != top and top in real.parents for top in hidden_dirs)
    ]


def build_args(module: str | None = None, cwd: str | None = None) -> list[str]:
    """The bubblewrap argument vector that precedes a command.

    Only paths that exist are mentioned: bubblewrap would otherwise create the
    mount point, and with it an empty directory in the operator's real home.
    """
    args = [
        "bwrap",
        "--die-with-parent",
        # Other processes of the account, their memory and their environments are out of reach.
        "--unshare-pid", "--unshare-ipc", "--unshare-uts",
        "--bind", "/", "/",
        "--dev-bind", "/dev", "/dev",
        "--proc", "/proc",
    ]  # fmt: skip
    for kind, real in _plan(module):
        if kind == "hide-dir":
            args.extend(["--tmpfs", str(real)])
        elif kind == "hide-file":
            # The null device reads as an empty file; a plain bind would make it unreadable
            # instead, and a tool that merely looks for its settings there would fail.
            args.extend(["--dev-bind", "/dev/null", str(real)])
        elif kind == "ro":
            args.extend(["--ro-bind", str(real), str(real)])
        else:
            args.extend(["--bind", str(real), str(real)])

    if cwd:
        args.extend(["--chdir", cwd])
    args.append("--")
    return args


def wrap(command: list[str], module: str | None = None, cwd: str | None = None) -> list[str]:
    """Return *command* prefixed with the sandbox when it is switched on, else unchanged."""
    if not enabled():
        return command
    return [*build_args(module=module, cwd=cwd), *command]


def startup_check() -> str:
    """Return the mode for the start record; raise when the sandbox was asked for and cannot start.

    Asked for and unusable has to stop the server: carrying on would run every
    tool without the protection the operator believes is there.
    """
    if not enabled():
        return "off"
    if shutil.which("bwrap") is None:
        raise RuntimeError(f"{LOCAL_SANDBOX_ENV}=1 needs bubblewrap (bwrap), which is not installed.")
    try:
        probe = subprocess.run([*build_args(), "true"], capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"{LOCAL_SANDBOX_ENV}=1 but bubblewrap could not be started: {exc}") from exc
    if probe.returncode != 0:
        reason = probe.stderr.strip().splitlines()[-1] if probe.stderr.strip() else f"exit status {probe.returncode}"
        raise RuntimeError(
            f"{LOCAL_SANDBOX_ENV}=1 but bubblewrap cannot create its namespaces here ({reason}). "
            "Unprivileged user namespaces may be disabled; unset the variable to run without the sandbox."
        )
    return "bwrap"
