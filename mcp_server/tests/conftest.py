"""Shared fixtures for MCP server tests."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server.remote import RemoteHostConfig
from mcp_server.tools_db import ToolsDatabase


@pytest.fixture(autouse=True)
def _bounded_communicate_mock_bridge(monkeypatch):
    """Route _bounded_communicate through process.communicate() for mock processes.

    Existing tests mock asyncio.create_subprocess_exec to return an AsyncMock with
    mock_proc.communicate.return_value = (stdout, stderr). The production path now
    streams from process.stdout/stderr via _bounded_communicate(), which those mocks
    don't provide. Rather than rewrite every test, this fixture transparently falls
    back to the mock's .communicate() when the process isn't a real StreamReader —
    so tests keep asserting on mock_proc.communicate while the bounded path still
    runs unchanged for real subprocesses (see TestBoundedCommunicate).
    """
    import mcp_server.security as mod

    original = mod._bounded_communicate

    async def _bridge(process, *, input_bytes=None, max_stream_bytes):
        stdout = getattr(process, "stdout", None)
        if not isinstance(stdout, asyncio.StreamReader):
            stdout_bytes, stderr_bytes = await process.communicate(input=input_bytes)
            return (
                stdout_bytes[:max_stream_bytes],
                len(stdout_bytes) > max_stream_bytes,
                stderr_bytes[:max_stream_bytes],
                len(stderr_bytes) > max_stream_bytes,
            )
        return await original(process, input_bytes=input_bytes, max_stream_bytes=max_stream_bytes)

    monkeypatch.setattr(mod, "_bounded_communicate", _bridge)


SAMPLE_TOOLS = [
    {"name": "nmap", "method": "apt", "module": "networking", "url": ""},
    {"name": "sqlmap", "method": "pipx", "module": "web", "url": ""},
    {"name": "gobuster", "method": "go", "module": "web", "url": "https://github.com/OJ/gobuster"},
    {
        "name": "ghidra",
        "method": "git",
        "module": "reversing",
        "url": "https://github.com/NationalSecurityAgency/ghidra",
    },
    {"name": "BeEF", "method": "docker", "module": "misc", "url": ""},
    {"name": "hashcat", "method": "apt", "module": "cracking", "url": ""},
    {"name": "sherlock-project", "method": "pipx", "module": "recon", "url": ""},
    {"name": "z3-solver", "method": "pipx", "module": "crypto", "url": ""},
    {"name": "volatility3", "method": "pipx", "module": "forensics", "url": ""},
    {"name": "steghide", "method": "apt", "module": "stego", "url": ""},
    {"name": "prowler", "method": "pipx", "module": "cloud", "url": ""},
    {"name": "grype", "method": "apt", "module": "containers", "url": ""},
    {"name": "lynis", "method": "apt", "module": "blueteam", "url": ""},
    {"name": "apktool", "method": "apt", "module": "mobile", "url": ""},
    {"name": "slither-analyzer", "method": "pipx", "module": "blockchain", "url": ""},
    {"name": "impacket", "method": "pipx", "module": "enterprise", "url": ""},
    {"name": "aircrack-ng", "method": "apt", "module": "wireless", "url": ""},
    {"name": "pwntools", "method": "pipx", "module": "pwn", "url": ""},
    {"name": "garak", "method": "pipx", "module": "llm", "url": ""},
    {"name": "libimage-exiftool-perl", "method": "apt", "module": "forensics", "url": ""},
    {"name": "metasploit", "method": "special", "module": "pwn", "url": ""},
]


@pytest.fixture()
def tmp_tools_config(tmp_path: Path) -> Path:
    """Write sample tools_config.json and return the project root."""
    config = tmp_path / "tools_config.json"
    config.write_text(json.dumps(SAMPLE_TOOLS), encoding="utf-8")
    return tmp_path


@pytest.fixture()
def tools_db(tmp_tools_config: Path) -> ToolsDatabase:
    """ToolsDatabase backed by the sample config (no real filesystem checks)."""
    with patch("shutil.which", return_value=None):
        return ToolsDatabase(project_root=tmp_tools_config)


@pytest.fixture()
def remote_config(tmp_path: Path) -> RemoteHostConfig:
    """RemoteHostConfig backed by a temporary config file."""
    config_path = tmp_path / "remote_hosts.json"
    return RemoteHostConfig(config_path=config_path)
