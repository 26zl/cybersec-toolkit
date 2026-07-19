#!/usr/bin/env bash
#
# update-skills.sh — check every vendored skill in .claude/skills/ against its pinned
# upstream source. Reports drift only; never fetches (re-vendoring is manual).
#
# Usage:
#   scripts/update-skills.sh              report drift for all sources
#   scripts/update-skills.sh --check      as above; exit 1 if any drift found
#   scripts/update-skills.sh --check-pins offline pin-consistency check; exit 1 on mismatch
#
# MIN_AGE_DAYS (env, default 3) — cooldown before an upstream advance is flagged as UPDATE.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SKILLS="$REPO_ROOT/.claude/skills"
SKILLS_MD="$SKILLS/SKILLS.md"
TPN="$REPO_ROOT/THIRD_PARTY_NOTICES.md"

# Cooldown before an upstream advance is flagged, matching the deps 3-day policy.
MIN_AGE_DAYS="${MIN_AGE_DAYS:-3}"

# name|git-url|pinned-commit — canonical pin list (--check-pins validates docs + frontmatter against it).
SOURCES=(
  "mukul975-apache|https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git|673da1f3b0b7be34ffc9624ef3858fe45f1c3bed"
  "trailofbits|https://github.com/trailofbits/skills.git|cfe5d7b1619e47fb5b38b7e2561dad7e5f1e89af"
  "transilience|https://github.com/transilienceai/communitytools.git|58b552ef35029814b95fa53924790e3546a4a146"
  "karpathy|https://github.com/multica-ai/andrej-karpathy-skills.git|2c606141936f1eeef17fa3043a72095b4765b9c2"
  "bughunter|https://github.com/shuvonsec/claude-bug-bounty.git|22ea70b763618984a08d6f601bb2e3e079e86a15"
  "claude-red|https://github.com/SnailSploit/Claude-Red.git|aeb41eca7088a703c3a35fbcba3086d4a6c1aa4e"
)

MODE=report
case "${1:-}" in
  "")           MODE=report ;;
  --check)      MODE=check ;;
  --check-pins) MODE=pins ;;
  *) echo "usage: $(basename "$0") [--check | --check-pins]" >&2; exit 2 ;;
esac

command -v git >/dev/null || { echo "error: git not found" >&2; exit 1; }
[[ -d "$SKILLS" ]] || { echo "error: $SKILLS not found" >&2; exit 1; }

# Assert each pin also appears in both docs and matches every upstream_commit in frontmatter.
verify_pins() {
  local bad=0 name url pin doc pins=" " fc
  echo "== pin consistency (offline) =="
  for entry in "${SOURCES[@]}"; do
    IFS='|' read -r name url pin <<<"$entry"
    pins+="$pin "
    for doc in "$SKILLS_MD" "$TPN"; do
      grep -q "$pin" "$doc" || { echo "  MISSING: $name pin $pin not in $(basename "$doc")"; bad=1; }
    done
  done
  # Every distinct upstream_commit recorded in skill frontmatter must be a known pin.
  while IFS= read -r fc; do
    [[ -z "$fc" ]] && continue
    case "$pins" in *" $fc "*) : ;; *) echo "  ORPHAN: frontmatter upstream_commit $fc is not a known pin"; bad=1 ;; esac
  done < <(git -C "$REPO_ROOT" grep -h -E '^upstream_commit:' -- '.claude/skills/*/SKILL.md' 2>/dev/null | awk '{print $2}' | sort -u)
  [[ $bad -eq 0 ]] && echo "  OK: all ${#SOURCES[@]} pins consistent across SKILLS.md + THIRD_PARTY_NOTICES.md + frontmatter"
  return $bad
}

verify_pins; pins_bad=$?
echo
if [[ "$MODE" == "pins" ]]; then
  [[ $pins_bad -eq 0 ]] || { echo "pin inconsistency (see above)" >&2; exit 1; }
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# maps each vendored skill to the source that claims it; unclaimed = project-authored
declare -A CLAIMED=()

total_synced=0 total_modified=0 total_upstream_only=0 drift=$pins_bad

for entry in "${SOURCES[@]}"; do
  IFS='|' read -r name url pin <<<"$entry"
  echo "== $name ($url) =="

  clone="$WORK/$name"
  if ! git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 clone --quiet --filter=blob:none "$url" "$clone" 2>/dev/null; then
    echo "  ERROR: clone failed (unreachable?) — skipping"
    drift=1
    echo
    continue
  fi

  remote_head="$(git -C "$clone" rev-parse HEAD)"
  head_epoch="$(git -C "$clone" log -1 --format=%ct "$remote_head" 2>/dev/null || echo 0)"
  head_age_days=$(( ( $(date +%s) - head_epoch ) / 86400 ))
  if ! git -C "$clone" checkout --quiet "$pin" 2>/dev/null; then
    echo "  ERROR: pinned commit $pin not found upstream — skipping"
    drift=1
    echo
    continue
  fi

  if [[ "$remote_head" == "$pin" ]]; then
    echo "  pin is at upstream HEAD"
  elif (( head_age_days >= MIN_AGE_DAYS )); then
    echo "  UPDATE: upstream HEAD advanced past pin (HEAD ${head_age_days}d old ≥ ${MIN_AGE_DAYS}d cooldown): $pin -> $remote_head"
    # Diff pin..HEAD to name the exact skills that changed — the actual re-merge list.
    remerge=() newup=()
    while IFS=$'\t' read -r st path _; do
      case "$path" in */SKILL.md) ;; *) continue ;; esac
      sk="$(basename "$(dirname "$path")")"
      case "$st" in
        A*) newup+=("$sk") ;;
        *)  [[ -d "$SKILLS/$sk" ]] && remerge+=("$sk") ;;
      esac
    done < <(git -C "$clone" diff --name-status "$pin" "$remote_head" 2>/dev/null)
    [[ ${#remerge[@]} -gt 0 ]] && echo "  re-merge (upstream changed our vendored skills): ${remerge[*]}"
    [[ ${#newup[@]} -gt 0 ]]   && echo "  new upstream skills since pin (optional to vendor): ${newup[*]}"
    echo "  (re-vendor, then bump the pin in SKILLS.md + THIRD_PARTY_NOTICES.md + this script)"
    drift=1
  else
    echo "  upstream HEAD advanced but within ${MIN_AGE_DAYS}d cooldown (${head_age_days}d old) — holding"
  fi

  synced=0 modified=0 upstream_only=0
  modified_list=() upstream_only_list=()

  # Every dir containing a SKILL.md upstream is one skill; match by dir name.
  while IFS= read -r skmd; do
    sk="$(basename "$(dirname "$skmd")")"
    up="$(dirname "$skmd")"
    ours="$SKILLS/$sk"
    if [[ ! -d "$ours" ]]; then
      upstream_only=$((upstream_only + 1))
      upstream_only_list+=("$sk")
      continue
    fi
    CLAIMED["$sk"]="$name"
    # -x LICENSE: the identical vendored per-skill LICENSE would flag every skill as differing
    if diff -rq -x LICENSE "$up" "$ours" >/dev/null 2>&1; then
      synced=$((synced + 1))
    else
      modified=$((modified + 1))
      modified_list+=("$sk")
    fi
  done < <(find "$clone" -name SKILL.md -type f)

  echo "  in sync:        $synced"
  echo "  locally modified: $modified"
  if [[ $modified -gt 0 ]]; then printf '    - %s\n' "${modified_list[@]}"; fi
  echo "  upstream-only (not vendored): $upstream_only"
  if [[ $upstream_only -gt 0 ]]; then printf '    + %s\n' "${upstream_only_list[@]}"; fi
  echo

  total_synced=$((total_synced + synced))
  total_modified=$((total_modified + modified))
  total_upstream_only=$((total_upstream_only + upstream_only))
  [[ $modified -gt 0 || $upstream_only -gt 0 ]] && drift=1
done

# Vendored skills no source accounted for: project-authored or orphaned.
local_only=()
while IFS= read -r skmd; do
  sk="$(basename "$(dirname "$skmd")")"
  [[ -z "${CLAIMED[$sk]:-}" ]] && local_only+=("$sk")
done < <(find "$SKILLS" -mindepth 2 -maxdepth 2 -name SKILL.md -type f)

echo "== summary =="
echo "  (note: 'modified' bundles our vendoring transforms with real edits — diff each before re-vendoring)"
echo "  in sync with pin:  $total_synced"
echo "  locally modified:  $total_modified"
echo "  upstream-only:     $total_upstream_only"
echo "  local-only (no source): ${#local_only[@]}  (project-authored or orphaned)"
if [[ ${#local_only[@]} -gt 0 ]]; then printf '    * %s\n' "${local_only[@]}"; fi

if [[ "$MODE" == "check" && $drift -ne 0 ]]; then
  echo "drift detected (see above)" >&2
  exit 1
fi
