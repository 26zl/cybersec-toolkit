"""Shared fixtures for MCP server tests."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server.remote import RemoteHostConfig
from mcp_server.tools_db import ToolsDatabase

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
    {"name": "trivy", "method": "apt", "module": "containers", "url": ""},
    {"name": "lynis", "method": "apt", "module": "blueteam", "url": ""},
    {"name": "apktool", "method": "apt", "module": "mobile", "url": ""},
    {"name": "slither-analyzer", "method": "pipx", "module": "blockchain", "url": ""},
    {"name": "impacket", "method": "pipx", "module": "enterprise", "url": ""},
    {"name": "aircrack-ng", "method": "apt", "module": "wireless", "url": ""},
    {"name": "pwntools", "method": "pipx", "module": "pwn", "url": ""},
    {"name": "gpt-researcher", "method": "pipx", "module": "llm", "url": ""},
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
