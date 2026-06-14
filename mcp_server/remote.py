"""Remote SSH execution — host config, connection testing, and remote command execution."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server import security as _security  # noqa: E402

# Default path for remote hosts configuration.
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "remote_hosts.json"

# Safe character patterns for SSH hostname and user — prevent option injection.
_SAFE_HOST_RE = re.compile(r"^[a-zA-Z0-9._:\-]+$")
_SAFE_USER_RE = re.compile(r"^[a-zA-Z0-9._\-]+$")

# SSH options applied to every connection.
_SSH_BASE_OPTIONS = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "StrictHostKeyChecking=accept-new",
]


class RemoteHostConfig:
    """Load, save, and query SSH remote host configurations."""

    def __init__(self, config_path: Path | str | None = None) -> None:
        self._path = Path(config_path) if config_path else _DEFAULT_CONFIG_PATH
        self._hosts: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        """Load the host table, failing loudly on corrupt config.

        Previously a malformed ``remote_hosts.json`` was silently reset to an
        empty host table — an operator could lose every registered host (and
        the subsequent ``_save`` would persist the empty state) without ever
        seeing an error. Now:

        - Corrupt JSON raises :class:`ValueError` with a message pointing at
          the offending file and, when possible, the byte offset.
        - The corrupt file is renamed to ``<path>.corrupt.<epoch>`` so the
          operator can recover state or inspect what went wrong.
        - Type mismatches (non-object top level, non-object ``hosts`` key)
          also raise rather than fall through to an empty dict.
        """
        if not self._path.exists():
            self._hosts = {}
            return
        raw = self._path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            backup = self._path.with_suffix(self._path.suffix + f".corrupt.{int(time.time())}")
            backup_note = ""
            try:
                os.replace(self._path, backup)
                backup_note = f" Corrupt file moved to {backup}."
            except OSError:
                pass
            raise ValueError(
                f"Remote host config at {self._path} is not valid JSON "
                f"({e.msg} at line {e.lineno}, column {e.colno})."
                f"{backup_note} Fix the JSON or delete the file to start fresh."
            ) from e
        if not isinstance(data, dict):
            raise ValueError(f"Remote host config at {self._path} must be a JSON object, got {type(data).__name__}.")
        hosts = data.get("hosts", {})
        if not isinstance(hosts, dict):
            raise ValueError(f"'hosts' key in {self._path} must be an object, got {type(hosts).__name__}.")
        self._hosts = hosts

    def _save(self) -> None:
        """Atomically persist the host table with 0600 permissions.

        Writes to a temp file in the same directory, fsyncs, chmods, and
        renames over the target. ``os.replace`` is atomic on POSIX and Windows
        (Python 3.3+), so a crash mid-write leaves either the previous file
        or the fully-written new one — never a truncated/corrupt file that
        would be silently loaded as an empty host table by ``_load``.

        Concurrent savers race at the rename step; last writer wins without
        interleaved writes, making the old advisory flock unnecessary. The
        0600 mode keeps hostnames, IPs, and SSH key paths out of reach of
        other local users.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps({"hosts": self._hosts}, indent=2) + "\n"

        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._path.parent),
            prefix=f".{self._path.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    # fsync is best-effort on some filesystems (e.g. tmpfs)
                    pass
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                # Windows/NTFS may not support POSIX modes; replace still works
                pass
            os.replace(tmp_path, self._path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise

    def add_host(
        self,
        name: str,
        hostname: str,
        user: str = "kali",
        port: int = 22,
        ssh_key: str | None = None,
        description: str = "",
        tool_allowlist: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add or update a remote host. Returns the host entry."""
        if not name or not name.strip():
            raise ValueError("Host name must not be empty")
        if not hostname or not hostname.strip():
            raise ValueError("Hostname must not be empty")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError(f"Port must be an integer between 1 and 65535, got {port!r}")
        if not _SAFE_HOST_RE.match(hostname.strip()):
            raise ValueError(f"Hostname contains invalid characters: {hostname!r}")
        if not _SAFE_USER_RE.match(user.strip()):
            raise ValueError(f"Username contains invalid characters: {user!r}")

        entry: dict[str, Any] = {
            "hostname": hostname.strip(),
            "user": user.strip(),
            "port": port,
            "description": description,
        }
        if ssh_key:
            entry["ssh_key"] = ssh_key.strip()
        if tool_allowlist is not None:
            entry["tool_allowlist"] = list(tool_allowlist)

        self._hosts[name.strip()] = entry
        self._save()
        return entry

    def check_tool_allowed(self, name: str, tool_name: str) -> bool:
        """Check if *tool_name* is permitted on host *name*.

        Returns True when the host has no allowlist (all tools allowed)
        or *tool_name* is in the allowlist.

        Raises ValueError if the host does not exist.
        """
        host = self._hosts.get(name)
        if host is None:
            raise ValueError(f"Remote host '{name}' not found. Use manage_remote_hosts to add it.")
        allowlist = host.get("tool_allowlist")
        if allowlist is None:
            return True
        return tool_name in allowlist

    def remove_host(self, name: str) -> bool:
        """Remove a host by name. Returns True if it existed."""
        if name in self._hosts:
            del self._hosts[name]
            self._save()
            return True
        return False

    def list_hosts(self) -> dict[str, dict[str, Any]]:
        """Return all hosts."""
        return dict(self._hosts)

    def get_ssh_base_args(self, name: str) -> list[str]:
        """Build base SSH command arguments for a named host.

        Returns: list like ["-o", "BatchMode=yes", ..., "-p", "22", "-i", "key", "user@host"]
        Raises ValueError if host not found.
        """
        host = self._hosts.get(name)
        if not host:
            raise ValueError(f"Remote host '{name}' not found. Use manage_remote_hosts to add it.")

        args = list(_SSH_BASE_OPTIONS)
        args += ["-p", str(host["port"])]

        ssh_key = host.get("ssh_key")
        if ssh_key:
            key_path = os.path.expanduser(ssh_key)
            if not os.path.isfile(key_path):
                # Don't echo the configured key path back into the error: it
                # propagates into str(e) and the audit log, and a key path is
                # treated as sensitive. The host name already gives the caller
                # enough context to find the offending ssh_key entry.
                raise ValueError("SSH key file not found for this host; verify its configured ssh_key path")
            args += ["-i", key_path]

        args.append(f"{host['user']}@{host['hostname']}")
        return args


async def check_ssh_connection(ssh_args: list[str], timeout: int = 15) -> dict[str, Any]:
    """Test SSH connectivity by running 'echo ok' on the remote host.

    Args:
        ssh_args: Base SSH args from RemoteHostConfig.get_ssh_base_args().
        timeout: Connection timeout in seconds.

    Returns:
        Dict with success, message, and optionally error details.
    """
    command = ["ssh"] + ssh_args + ["echo", "ok"]

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            # 64 KB cap — a healthy "echo ok" returns 3 bytes; anything larger is
            # noise (or malicious) and we don't need to read past the cap.
            stdout_bytes, _t1, stderr_bytes, _t2 = await asyncio.wait_for(
                _security._bounded_communicate(process, max_stream_bytes=65536),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass  # Process may be in D state; leave as zombie rather than hang
            return {
                "success": False,
                "message": f"SSH connection timed out after {timeout} seconds",
            }

        stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

        if process.returncode == 0 and stdout == "ok":
            return {"success": True, "message": "SSH connection successful"}

        return {
            "success": False,
            "message": f"SSH connection failed (exit code {process.returncode})",
            "stderr": stderr,
        }

    except FileNotFoundError:
        return {
            "success": False,
            "message": "SSH client not found. Ensure 'ssh' is installed and in PATH.",
        }
    except OSError as e:
        return {
            "success": False,
            "message": f"SSH connection failed: {e}",
        }


async def execute_remote_command(
    ssh_args: list[str],
    command: list[str],
    timeout: int = 120,
    max_output: int = 200000,
) -> dict[str, Any]:
    """Execute a command on a remote host via SSH.

    Args:
        ssh_args: Base SSH args from RemoteHostConfig.get_ssh_base_args().
        command: Command as a list of strings (e.g. ["nmap", "-sV", "10.0.0.1"]).
        timeout: Execution timeout in seconds.
        max_output: Maximum output size in bytes before truncation.

    Returns:
        Dict with exit_code, stdout, stderr, truncated, command, remote.
    """
    # Build the remote command as a single shell-safe string
    remote_cmd_str = shlex.join(command)
    full_command = ["ssh"] + ssh_args + [remote_cmd_str]

    # Clamp timeout
    timeout = max(1, min(timeout, 300))

    try:
        process = await asyncio.create_subprocess_exec(
            *full_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, t_read_stdout, stderr_bytes, t_read_stderr = await asyncio.wait_for(
                _security._bounded_communicate(process, max_stream_bytes=max_output),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass  # Process may be in D state; leave as zombie rather than hang
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Remote process timed out after {timeout} seconds",
                "truncated": False,
                "command": remote_cmd_str,
                "remote": True,
            }

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if t_read_stdout:
            stdout = _security._append_truncation_marker(stdout, max_output)
        if t_read_stderr:
            stderr = _security._append_truncation_marker(stderr, max_output)
        truncated = t_read_stdout or t_read_stderr

        return {
            "exit_code": process.returncode if process.returncode is not None else -1,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": truncated,
            "command": remote_cmd_str,
            "remote": True,
        }

    except FileNotFoundError:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "SSH client not found. Ensure 'ssh' is installed and in PATH.",
            "truncated": False,
            "command": shlex.join(command),
            "remote": True,
        }
    except OSError as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Failed to execute remote command: {e}",
            "truncated": False,
            "command": shlex.join(command),
            "remote": True,
        }
