#!/usr/bin/env bash
#
# mcp-launch.sh — root-aware MCP server launcher for the Cybersec Toolkit.
#
# Determines the repository root from its own location, then starts the
# FastMCP server over stdio via uv. Once the script is addressed by a valid
# relative or absolute path, the caller's working directory does not matter.
#
# Usage:
#   bash scripts/mcp-launch.sh                         # repository root
#   bash /absolute/path/to/scripts/mcp-launch.sh       # any directory
#
# Clients that cannot resolve project-relative paths should use this launcher
# instead of a bare `uv run --directory mcp_server ...` command.
#
# Environment:
#   CYBERSEC_MCP_ALLOW_EXTERNAL  (default: 0)  — allow external network targets
#   CYBERSEC_MCP_ALLOW_SCRIPTS   (default: 0)  — enable unsandboxed script execution
#   CYBERSEC_INSTALLER_ROOT      (optional)     — override repo root for tools_config.json
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export CYBERSEC_MCP_ALLOW_EXTERNAL="${CYBERSEC_MCP_ALLOW_EXTERNAL:-0}"
export CYBERSEC_MCP_ALLOW_SCRIPTS="${CYBERSEC_MCP_ALLOW_SCRIPTS:-0}"

exec uv run --directory "$REPO_ROOT/mcp_server" fastmcp run server.py \
    --transport stdio --no-banner
