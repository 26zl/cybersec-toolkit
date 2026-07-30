#!/usr/bin/env bash
# Assert every release surface reports the same version.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

v_file="$(tr -d '[:space:]' < VERSION)"
v_py="$(grep -m1 '^version' mcp_server/pyproject.toml | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"

if ! json_versions="$(
    python3 - <<'PY'
import json
import sys
from pathlib import Path

try:
    plugin = json.loads(Path(".claude-plugin/plugin.json").read_text())
    marketplace = json.loads(Path(".claude-plugin/marketplace.json").read_text())
    plugin_version = plugin["version"]
    matches = [
        entry
        for entry in marketplace["plugins"]
        if entry.get("name") == "cybersec-toolkit"
    ]
    if len(matches) != 1:
        raise ValueError("marketplace must contain exactly one cybersec-toolkit plugin")
    marketplace_version = matches[0]["version"]
    if not isinstance(plugin_version, str) or not isinstance(marketplace_version, str):
        raise TypeError("plugin versions must be strings")
except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
    print(f"plugin metadata error: {exc}", file=sys.stderr)
    raise SystemExit(1)

print(plugin_version, marketplace_version, sep="\t")
PY
)"; then
    echo "::error::Unable to read plugin release versions" >&2
    exit 1
fi

IFS=$'\t' read -r v_plugin v_marketplace <<< "$json_versions"

if ! [[ "$v_file" == "$v_py" && "$v_file" == "$v_plugin" && "$v_file" == "$v_marketplace" ]]; then
    echo "::error::Release version mismatch: VERSION=$v_file, pyproject=$v_py, plugin=$v_plugin, marketplace=$v_marketplace" >&2
    exit 1
fi
echo "version OK: $v_file (VERSION, pyproject, plugin, marketplace)"
