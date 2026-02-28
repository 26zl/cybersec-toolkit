"""Remote SSH execution — host config, connection testing, and remote command execution."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]  # unavailable on Windows

_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server.sanitize import truncate_output  # noqa: E402

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
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                self._hosts = data.get("hosts", {})
            except (json.JSONDecodeError, KeyError):
                self._hosts = {}
        else:
            self._hosts = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps({"hosts": self._hosts}, indent=2) + "\n"
        if fcntl is not None:
            with open(self._path, "w", encoding="utf-8") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(data)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        else:
            # fcntl unavailable on Windows — fallback to simple write
            self._path.write_text(data, encoding="utf-8")

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
                raise ValueError(f"SSH key file not found: {key_path}")
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
            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
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
            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
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

        stdout, t1 = truncate_output(stdout, max_output)
        stderr, t2 = truncate_output(stderr, max_output)
        truncated = t1 or t2

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
