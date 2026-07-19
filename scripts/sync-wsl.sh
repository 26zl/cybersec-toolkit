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
    # Restrict to safe distro name (no path/shell metacharacters)
    if [[ "$DISTRO" =~ [^a-zA-Z0-9_.-] ]]; then
        echo "Invalid distro name (use only letters, numbers, underscore, hyphen, dot): $DISTRO" >&2
        exit 1
    fi
    WSL_DISTRO_FLAG=(-d "$DISTRO")
fi

# Convert Git Bash path (C:/Users/...) to WSL path (/mnt/c/Users/...)
WIN_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -W 2>/dev/null || pwd)"
DRIVE="${WIN_PATH%%:*}"
DRIVE_LOWER="$(echo "$DRIVE" | tr '[:upper:]' '[:lower:]')"
SRC="/mnt/${DRIVE_LOWER}${WIN_PATH#*:}"
echo "Syncing MCP server to WSL (${DISTRO:-default distro})..."

# SRC is passed as a positional arg (not interpolated) so a checkout path with
# spaces, quotes, or $ can't break out of the inner shell; DEST expands $HOME
# inside WSL so it stays inner-side. Errors are surfaced (no 2>/dev/null) so
# symlink/copy failures aren't hidden — silent failure here is what produces the
# "tools_config.json not found" error at MCP server startup.
wsl.exe "${WSL_DISTRO_FLAG[@]}" bash -c '
set -e
src="$1"
dest="$HOME/cybersec-toolkit"
mkdir -p "$dest/mcp_server/tests"
cp "$src"/mcp_server/*.py "$dest/mcp_server/"
if compgen -G "$src/mcp_server/tests/*.py" > /dev/null; then
    cp "$src"/mcp_server/tests/*.py "$dest/mcp_server/tests/"
fi
cp "$src"/mcp_server/pyproject.toml "$dest/mcp_server/"
if [ -f "$src/mcp_server/uv.lock" ]; then
    cp "$src"/mcp_server/uv.lock "$dest/mcp_server/"
fi
# tools_config.json must be reachable from the WSL project root — symlink to
# the Windows source so registry edits do not need re-syncing. Force-replace
# any existing file/symlink. Verify the link resolves before exiting.
ln -sfn "$src"/tools_config.json "$dest/tools_config.json"
if [ ! -f "$dest/tools_config.json" ]; then
    echo "ERROR: tools_config.json symlink at $dest/tools_config.json is broken" >&2
    echo "       (target: $src/tools_config.json)" >&2
    exit 1
fi
echo Done' wsl-sync "$SRC"
