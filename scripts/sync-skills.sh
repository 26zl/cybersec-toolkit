#!/usr/bin/env bash
#
# sync-skills.sh — mirror the Claude Code skills into a vendor-neutral location
# so non-Claude agents (Codex and other tools that read .agents/skills/) can use them.
#
# .claude/skills/ is the single source of truth. .agents/skills/ is a generated mirror
# and is git-ignored. Re-run this after editing skills.
#
# Usage:
#   scripts/sync-skills.sh            mirror .claude/skills/ -> .agents/skills/
#   scripts/sync-skills.sh --check    report whether the mirror is out of date (exit 1 if so)
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$REPO_ROOT/.claude/skills"
DST="$REPO_ROOT/.agents/skills"

CHECK=0
if [[ "${1:-}" == "--check" ]]; then
    CHECK=1
elif [[ -n "${1:-}" ]]; then
    echo "usage: $(basename "$0") [--check]" >&2
    exit 2
fi

if [[ ! -d "$SRC" ]]; then
    echo "error: source skills directory not found: $SRC" >&2
    exit 1
fi

if [[ "$CHECK" -eq 1 ]]; then
    if [[ ! -d "$DST" ]]; then
        echo "out of date: $DST does not exist (run: scripts/sync-skills.sh)" >&2
        exit 1
    fi
    if command -v rsync >/dev/null 2>&1; then
        # Dry-run; any itemized line means the mirror differs from the source.
        if rsync -a --delete --dry-run --itemize-changes "$SRC/" "$DST/" | grep -q .; then
            echo "out of date: .agents/skills/ differs from .claude/skills/ (run: scripts/sync-skills.sh)" >&2
            exit 1
        fi
    elif ! diff -r -q "$SRC" "$DST" >/dev/null 2>&1; then
        echo "out of date: .agents/skills/ differs from .claude/skills/ (run: scripts/sync-skills.sh)" >&2
        exit 1
    fi
    echo "up to date: .agents/skills/ matches .claude/skills/"
    exit 0
fi

mkdir -p "$DST"

if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$SRC/" "$DST/"
else
    # Portable fallback: clear the destination, then copy everything across.
    find "$DST" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    cp -a "$SRC/." "$DST/"
fi

count="$(find "$DST" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
echo "synced $count skill directories: .claude/skills/ -> .agents/skills/"
