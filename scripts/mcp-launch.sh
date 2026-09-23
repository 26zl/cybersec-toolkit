#!/usr/bin/env bash
#
# mcp-launch.sh — root-aware MCP server launcher for the Cybersec Toolkit.
#
# Determines the repository root from its own location, then starts the MCP
# server inside a Kata Containers VM (sandbox/mcp.mjs). Tools therefore run
# behind a hardware-virtualized boundary rather than as the host user. Sandbox
# startup fails closed: --local is the explicit opt-out.
#
# Usage:
#   bash scripts/mcp-launch.sh                         # sandboxed (default)
#   bash scripts/mcp-launch.sh --local                 # host execution
#   bash /absolute/path/to/scripts/mcp-launch.sh       # any directory
#
# Clients that cannot resolve project-relative paths should use this launcher
# instead of a bare `uv run --directory mcp_server ...` command.
#
# Environment:
#   CYBERSEC_SANDBOX_MODE        (default: kata) — kata | local
#   CYBERSEC_MCP_ALLOW_EXTERNAL  (default: 0)    — allow external network targets
#   CYBERSEC_MCP_ALLOW_SCRIPTS   (default: 0)    — enable unsandboxed script execution
#   CYBERSEC_INSTALLER_ROOT      (optional)      — override repo root for tools_config.json
#
# See docs/SANDBOX.md for host prerequisites and sandbox configuration.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export CYBERSEC_MCP_ALLOW_EXTERNAL="${CYBERSEC_MCP_ALLOW_EXTERNAL:-0}"
export CYBERSEC_MCP_ALLOW_SCRIPTS="${CYBERSEC_MCP_ALLOW_SCRIPTS:-0}"

usage_error() {
    echo "Usage: mcp-launch.sh [--kata|--local]" >&2
    exit 2
}

launch_local() {
    echo "MCP local mode: tools execute with this host user's permissions." >&2
    exec uv run --directory "$REPO_ROOT/mcp_server" fastmcp run server.py \
        --transport stdio --no-banner
}

launch_kata() {
    local node_major
    # Kata needs KVM, so a non-Linux host can never satisfy the default mode.
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "Kata sandbox requires a Linux host with KVM (found: $(uname -s))." >&2
        echo "Run 'bash scripts/mcp-launch.sh --local' to execute on this host, or set" >&2
        echo "CYBERSEC_SANDBOX_MODE=local in the client's MCP config. See docs/SANDBOX.md." >&2
        exit 1
    fi
    command -v node >/dev/null 2>&1 || {
        echo "Kata sandbox requires Node.js 22+; see docs/SANDBOX.md." >&2
        exit 1
    }
    node_major="$(node --version 2>/dev/null | sed 's/^v//; s/\..*$//')"
    if [[ ! "$node_major" =~ ^[0-9]+$ ]] || (( node_major < 22 )); then
        echo "Kata sandbox requires Node.js 22+, found $(node --version 2>/dev/null)." >&2
        exit 1
    fi
    [[ -f "$REPO_ROOT/sandbox/node_modules/@ai-hero/sandcastle/package.json" ]] || {
        echo "Install sandbox dependencies: npm --prefix \"$REPO_ROOT/sandbox\" ci --ignore-scripts" >&2
        exit 1
    }
    exec node "$REPO_ROOT/sandbox/mcp.mjs"
}

MODE="${CYBERSEC_SANDBOX_MODE:-kata}"
case "${1:-}" in
    --local) MODE="local"; shift ;;
    --kata)  MODE="kata";  shift ;;
    "")      ;;
    *)       usage_error ;;
esac
[[ $# -eq 0 ]] || usage_error

case "$MODE" in
    kata)  launch_kata ;;
    local) launch_local ;;
    *)     echo "Unknown CYBERSEC_SANDBOX_MODE '$MODE' (expected: kata or local)." >&2; exit 2 ;;
esac
