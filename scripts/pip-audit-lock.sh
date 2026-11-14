#!/usr/bin/env bash
#
# pip-audit-lock.sh — audit every version pinned in mcp_server/uv.lock.
#
# pip-audit evaluates environment markers for the interpreter it runs on, so a
# version locked only for another Python is never checked, while the GitHub
# dependency graph still reports it. This audits each pinned version regardless
# of its marker, including the ctf-core and ctf-extra extras.
#
# Usage: scripts/pip-audit-lock.sh
#
# PIP_AUDIT_VERSION (env, default 2.10.1) — pip-audit release run through uvx.
# IDs listed in mcp_server/known-vulnerabilities.txt are ignored.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIP_AUDIT_VERSION="${PIP_AUDIT_VERSION:-2.10.1}"

cd "$SCRIPT_DIR/../mcp_server" || exit 1
command -v uv >/dev/null || { echo "error: uv not found" >&2; exit 1; }

ignore_args=()
while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs)"
    [[ -z "$line" ]] && continue
    ignore_args+=(--ignore-vuln "$line")
done < known-vulnerabilities.txt

work="$(mktemp -d)" || exit 1
trap 'rm -rf "$work"' EXIT

uv export --all-extras --no-hashes --frozen --no-emit-project \
    | sed -E 's/[[:space:]]*;.*$//' | grep -E '^[A-Za-z0-9_.-]+==' | sort -u > "$work/rest.txt"
[[ -s "$work/rest.txt" ]] || { echo "error: uv export produced no pinned versions" >&2; exit 1; }

# pip-audit rejects a file that names one package twice, so a package locked at
# several versions is spread over several passes.
rc=0 pass=0
while [[ -s "$work/rest.txt" ]]; do
    pass=$((pass + 1))
    awk -F'==' -v keep="$work/pass.txt" -v rest="$work/next.txt" '
        BEGIN { printf "" > keep; printf "" > rest }
        { if (seen[tolower($1)]++) print > rest; else print > keep }' "$work/rest.txt"
    mv "$work/next.txt" "$work/rest.txt"
    echo "== pass $pass: $(wc -l < "$work/pass.txt") pinned versions =="
    # The release is pinned; the cooldown covers the dependencies uvx resolves for it.
    uvx --exclude-newer "5 days" "pip-audit@${PIP_AUDIT_VERSION}" --no-deps --disable-pip -r "$work/pass.txt" \
        ${ignore_args[@]+"${ignore_args[@]}"} || rc=1
done
exit "$rc"
