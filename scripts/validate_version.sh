#!/usr/bin/env bash
# Assert the installer VERSION file and mcp_server/pyproject.toml version agree,
# so a release can't ship with a drifted self-reported version.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

v_file="$(tr -d '[:space:]' < VERSION)"
v_py="$(grep -m1 '^version' mcp_server/pyproject.toml | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"

if [[ "$v_file" != "$v_py" ]]; then
    echo "::error::VERSION ($v_file) != mcp_server/pyproject.toml version ($v_py)" >&2
    exit 1
fi
echo "version OK: $v_file (VERSION == mcp_server/pyproject.toml)"
