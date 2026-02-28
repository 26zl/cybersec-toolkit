#!/bin/bash
# Sync MCP server files from Windows source to WSL-local copy.
# The WSL copy is needed because uv can't create .venv on NTFS from WSL.
#
# Usage (from Windows/Git Bash):
#   ./scripts/sync-wsl.sh                  # sync to default distro
#   ./scripts/sync-wsl.sh kali-linux       # sync to specific distro

set -uo pipefail

DISTRO="${1:-}"
WSL_DISTRO_FLAG=()
if [[ -n "$DISTRO" ]]; then
    WSL_DISTRO_FLAG=(-d "$DISTRO")
fi

# Convert Git Bash path (C:/Users/...) to WSL path (/mnt/c/Users/...)
WIN_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -W 2>/dev/null || pwd)"
DRIVE="${WIN_PATH%%:*}"
DRIVE_LOWER="$(echo "$DRIVE" | tr '[:upper:]' '[:lower:]')"
SRC="/mnt/${DRIVE_LOWER}${WIN_PATH#*:}"
DEST="\$HOME/cybersec-toolkit"

echo "Syncing MCP server to WSL (${DISTRO:-default distro})..."

wsl.exe "${WSL_DISTRO_FLAG[@]}" bash -c "mkdir -p ${DEST}/mcp_server/tests && cp ${SRC}/mcp_server/*.py ${DEST}/mcp_server/ && cp ${SRC}/mcp_server/tests/*.py ${DEST}/mcp_server/tests/ 2>/dev/null; cp ${SRC}/mcp_server/pyproject.toml ${DEST}/mcp_server/ && cp ${SRC}/mcp_server/uv.lock ${DEST}/mcp_server/ 2>/dev/null; ln -sf ${SRC}/tools_config.json ${DEST}/tools_config.json 2>/dev/null; echo Done"
