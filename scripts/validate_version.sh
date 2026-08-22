#!/usr/bin/env bash
# Assert every release surface reports the same version.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

v_file="$(tr -d '[:space:]' < VERSION)"
v_py="$(grep -m1 '^version' mcp_server/pyproject.toml | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"
v_cff="$(grep -m1 '^version:' CITATION.cff | sed -E 's/^version:[[:space:]]*"([^"]+)".*/\1/')"

if ! json_versions="$(
    python3 - <<'PY'
import json
import sys
from pathlib import Path

try:
    plugin = json.loads(Path(".claude-plugin/plugin.json").read_text())
    marketplace = json.loads(Path(".claude-plugin/marketplace.json").read_text())
    server = json.loads(Path("server.json").read_text())
    plugin_version = plugin["version"]
    matches = [
        entry
        for entry in marketplace["plugins"]
        if entry.get("name") == "cybersec-toolkit"
    ]
    if len(matches) != 1:
        raise ValueError("marketplace must contain exactly one cybersec-toolkit plugin")
    marketplace_version = matches[0]["version"]
    pkg = server["packages"][0]
    server_top = server["version"]
    server_pkg = pkg["version"]
    server_tag = pkg["identifier"].rsplit(":", 1)[1]
    vals = [plugin_version, marketplace_version, server_top, server_pkg, server_tag]
    if not all(isinstance(x, str) for x in vals):
        raise TypeError("versions must be strings")
except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError) as exc:
    print(f"release metadata error: {exc}", file=sys.stderr)
    raise SystemExit(1)

print(plugin_version, marketplace_version, server_top, server_pkg, server_tag, sep="\t")
PY
)"; then
    echo "::error::Unable to read plugin/server release versions" >&2
    exit 1
fi

IFS=$'\t' read -r v_plugin v_marketplace v_server v_server_pkg v_server_tag <<< "$json_versions"

if ! [[ "$v_file" == "$v_py" && "$v_file" == "$v_cff" && "$v_file" == "$v_plugin" \
     && "$v_file" == "$v_marketplace" && "$v_file" == "$v_server" \
     && "$v_file" == "$v_server_pkg" && "$v_file" == "$v_server_tag" ]]; then
    echo "::error::Release version mismatch: VERSION=$v_file pyproject=$v_py CITATION=$v_cff plugin=$v_plugin marketplace=$v_marketplace server.json=$v_server pkg=$v_server_pkg image-tag=$v_server_tag" >&2
    exit 1
fi
echo "version OK: $v_file (VERSION, pyproject, CITATION, plugin, marketplace, server.json + image tag)"
