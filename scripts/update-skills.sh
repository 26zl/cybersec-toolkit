#!/usr/bin/env bash
#
# update-skills.sh — keep the vendored skills in .claude/skills/ in step with their
# pinned upstream sources.
#
# Usage:
#   scripts/update-skills.sh                 report drift and upstream health
#   scripts/update-skills.sh --check         as above; exit 1 if anything needs attention
#   scripts/update-skills.sh --check-pins    offline pin-consistency check; exit 1 on mismatch
#   scripts/update-skills.sh --local-edits   list vendored files that match no upstream version
#   scripts/update-skills.sh --apply [SOURCE...]
#       merge upstream into the vendored copies and bump the pins; exit 3 when a
#       source needs a hand merge (that source is left untouched)
#   scripts/update-skills.sh --apply --mark-conflicts SOURCE
#       write the merge with conflict markers so it can be resolved by hand
#   scripts/update-skills.sh --apply --finalize --target SHA SOURCE
#       accept the hand-resolved skills and bump the pin
#
# --apply options: --prune deletes skills upstream removed; --target SHA moves one
# source to that commit instead of the newest one past the cooldown.
#
# MIN_AGE_DAYS   (env, default 5)   cooldown before an upstream commit is eligible.
# MAX_STALE_DAYS (env, default 180) upstream inactivity reported as a note.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SKILLS="$REPO_ROOT/.claude/skills"
SKILLS_MD="$SKILLS/SKILLS.md"
TPN="$REPO_ROOT/THIRD_PARTY_NOTICES.md"

# Cooldown before an upstream commit is eligible, matching the deps 5-day policy. It uses
# the committer date, which the pusher controls, so it does not stop a backdated push;
# the scanner and human review of the update PR remain the control.
MIN_AGE_DAYS="${MIN_AGE_DAYS:-5}"
MAX_STALE_DAYS="${MAX_STALE_DAYS:-180}"
# A non-numeric value would evaluate to 0 in arithmetic and silently disable the cooldown.
if [[ ! "$MIN_AGE_DAYS" =~ ^[0-9]+$ || ! "$MAX_STALE_DAYS" =~ ^[0-9]+$ ]]; then
  echo "error: MIN_AGE_DAYS and MAX_STALE_DAYS must be non-negative integers" >&2
  exit 2
fi
for day_limit_name in MIN_AGE_DAYS MAX_STALE_DAYS; do
  day_limit="${!day_limit_name}"
  day_limit="${day_limit#"${day_limit%%[!0]*}"}"
  day_limit="${day_limit:-0}"
  if [[ ${#day_limit} -gt 15 || ( ${#day_limit} -eq 15 && "$day_limit" -gt 106751991167300 ) ]]; then
    echo "error: $day_limit_name exceeds the supported seconds range" >&2
    exit 2
  fi
  printf -v "$day_limit_name" '%s' "$day_limit"
done

# name|git-url|pinned-commit — canonical pin list (--check-pins validates docs + frontmatter against it).
SOURCES=(
  "mukul975-apache|https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git|54a798831d2266a3ca61ce68a7acb80b81160d57"
  "trailofbits|https://github.com/trailofbits/skills.git|149d7b21f4067765b82e67029730b42d228ef4b4"
  "transilience|https://github.com/transilienceai/communitytools.git|95fdc128af4ca1ae16b3226f9430f1bad97b0656"
  "karpathy|https://github.com/multica-ai/andrej-karpathy-skills.git|2c606141936f1eeef17fa3043a72095b4765b9c2"
  "bughunter|https://github.com/awarexone/Agentic-Bug-Hunter.git|82f4512ec432765297c36e6b3ef7dc3fe5a58be2"
  "claude-red|https://github.com/SnailSploit/Claude-Red.git|fd81441b613c7d4fab39256720a31c96859d138b"
  "ctf-skills|https://github.com/ljagiello/ctf-skills.git|20d182d9377f0467830f314bb0f843cae4dbf55e"
)

# skill|source — project-authored skills that share a name with a skill the source ships; they are
# never merged with or claimed by that source.
NOT_VENDORED=(
  "ctf-crypto|ctf-skills"
  "ctf-forensics|ctf-skills"
  "ctf-pwn|ctf-skills"
  "ctf-web|ctf-skills"
)

# skill|source|last-upstream-commit — skills kept after upstream stopped shipping them.
RETAINED=(
  "insecure-defaults|trailofbits|cfe5d7b1619e47fb5b38b7e2561dad7e5f1e89af"
)

usage() {
  awk '/^# Usage:/{p=1} /^set -uo/{exit} p' "$SCRIPT_PATH" | sed 's/^# \{0,1\}//'
}

MODE=report
MARK=false FINALIZE=false PRUNE=false TARGET_OVERRIDE=""
SELECTED=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)          MODE=check ;;
    --check-pins)     MODE=pins ;;
    --local-edits)    MODE=edits ;;
    --apply)          MODE=apply ;;
    --mark-conflicts) MARK=true ;;
    --finalize)       FINALIZE=true ;;
    --prune)          PRUNE=true ;;
    --target)         [[ $# -ge 2 ]] || { usage >&2; exit 2; }; TARGET_OVERRIDE="$2"; shift ;;
    -h|--help)        usage; exit 0 ;;
    -*)               usage >&2; exit 2 ;;
    *)                SELECTED+=("$1") ;;
  esac
  shift
done

if [[ "$MODE" != apply ]] && { $MARK || $FINALIZE || $PRUNE || [[ -n "$TARGET_OVERRIDE" || ${#SELECTED[@]} -gt 0 ]]; }; then
  echo "error: source names and --mark-conflicts/--finalize/--prune/--target need --apply" >&2
  exit 2
fi
if $MARK && $FINALIZE; then
  echo "error: --mark-conflicts and --finalize are separate steps" >&2
  exit 2
fi
if { $MARK || $FINALIZE || [[ -n "$TARGET_OVERRIDE" ]]; } && [[ ${#SELECTED[@]} -ne 1 ]]; then
  echo "error: --mark-conflicts, --finalize and --target take exactly one SOURCE" >&2
  exit 2
fi
if $FINALIZE && [[ -z "$TARGET_OVERRIDE" ]]; then
  echo "error: --finalize needs --target SHA, the commit the hand merge was made against" >&2
  exit 2
fi
if [[ -n "$TARGET_OVERRIDE" && ! "$TARGET_OVERRIDE" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: --target takes a full 40-character commit" >&2
  exit 2
fi
for want in ${SELECTED[@]+"${SELECTED[@]}"}; do
  known=false
  for entry in "${SOURCES[@]}"; do [[ "${entry%%|*}" == "$want" ]] && known=true; done
  $known || { echo "error: unknown source '$want'" >&2; exit 2; }
done

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

is_selected() {
  [[ ${#SELECTED[@]} -eq 0 ]] && return 0
  local want
  for want in "${SELECTED[@]}"; do [[ "$want" == "$1" ]] && return 0; done
  return 1
}

# clone_source <name> <url> <pin> <full|blobless> — clone into $WORK/<name> and make sure the pin is there.
clone_source() {
  local name="$1" url="$2" pin="$3" depth="$4" clone="$WORK/$1"
  local -a opts=(--quiet)
  [[ "$depth" == blobless ]] && opts+=(--filter=blob:none)
  if ! git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 clone "${opts[@]}" "$url" "$clone" 2>/dev/null; then
    echo "  ERROR: clone failed (unreachable?) — skipping"
    return 1
  fi
  # A pin dropped from every branch by an upstream history rewrite can still be fetched by id.
  if ! git -C "$clone" cat-file -e "$pin^{commit}" 2>/dev/null; then
    git -C "$clone" fetch --quiet origin "$pin" 2>/dev/null || true
  fi
  if ! git -C "$clone" cat-file -e "$pin^{commit}" 2>/dev/null; then
    echo "  ERROR: pinned commit $pin not found upstream — skipping"
    return 1
  fi
}

# cooled_target <clone> — newest first-parent commit on the default branch older than the cooldown.
cooled_target() {
  local cutoff=$(( $(date +%s) - MIN_AGE_DAYS * 86400 ))
  git -C "$1" rev-list --first-parent -1 --before="@$cutoff" HEAD 2>/dev/null
}

# skill_names <clone> <commit> — names of the directories holding a SKILL.md, one per line.
skill_names() {
  git -C "$1" ls-tree -r --name-only "$2" | sed -n 's#/SKILL\.md$##p' | sed 's#.*/##' | sort -u
}

# upstream_health <url> <clone> <pin> — one line per condition; returns 1 when one needs attention.
upstream_health() {
  local url="${1%.git}" clone="$2" pin="$3" attention=0 effective slug head_age
  if command -v curl >/dev/null 2>&1 && [[ "$url" == https://github.com/* ]]; then
    effective="$(curl -fsSL -o /dev/null --max-time 20 -w '%{url_effective}' "$url" 2>/dev/null || true)"
    if [[ -n "$effective" && "${effective,,}" != "${url,,}" ]]; then
      echo "  MOVED: upstream now redirects to $effective — update the URL here before the old name is reused"
      attention=1
    fi
    slug="${url#https://github.com/}"
    local -a auth=()
    [[ -n "${GITHUB_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
    if curl -fsS --max-time 20 ${auth[@]+"${auth[@]}"} "https://api.github.com/repos/$slug" 2>/dev/null \
        | grep -Eq '"archived":[[:space:]]*true'; then
      echo "  ARCHIVED: upstream repository is archived"
      attention=1
    fi
  fi
  if ! git -C "$clone" merge-base --is-ancestor "$pin" HEAD 2>/dev/null \
      && [[ -z "$(git -C "$clone" branch -r --contains "$pin" 2>/dev/null)" ]]; then
    echo "  REWRITTEN: the pin is on no upstream branch (history rewritten); review the next update in full"
    attention=1
  fi
  head_age=$(( ( $(date +%s) - $(git -C "$clone" log -1 --format=%ct HEAD) ) / 86400 ))
  (( head_age > MAX_STALE_DAYS )) && echo "  note: no upstream commit for ${head_age} days"
  return $attention
}

# replace_in_file <file> <old> <new> — rewrite through a temp file, so a running script is never edited in place.
replace_in_file() {
  local file="$1" tmp
  tmp="$(mktemp "${file}.XXXXXX")" || return 1
  cp -p "$file" "$tmp" && sed "s/$2/$3/g" "$file" > "$tmp" && mv "$tmp" "$file"
}

# maps each vendored skill to the source that claims it; unclaimed = project-authored
declare -A CLAIMED=()
for entry in "${RETAINED[@]}"; do
  IFS='|' read -r r_skill r_source _ <<<"$entry"
  [[ -d "$SKILLS/$r_skill" ]] && CLAIMED["$r_skill"]="$r_source (retained)"
done

attention=$pins_bad
manual=0 failed=0
bumps=()

for entry in "${SOURCES[@]}"; do
  IFS='|' read -r name url pin <<<"$entry"
  is_selected "$name" || continue
  echo "== $name ($url) =="
  excluded=()
  for nv in ${NOT_VENDORED[@]+"${NOT_VENDORED[@]}"}; do
    [[ "${nv#*|}" == "$name" ]] && excluded+=(--exclude "${nv%%|*}")
  done

  depth=blobless
  [[ "$MODE" == apply || "$MODE" == edits ]] && depth=full
  if ! clone_source "$name" "$url" "$pin" "$depth"; then
    attention=1 failed=1
    echo
    continue
  fi
  clone="$WORK/$name"

  if [[ "$MODE" == edits ]]; then
    python3 "$SCRIPT_DIR/revendor_skills.py" --clone "$clone" --pin "$pin" --target "$pin" \
      --skills-dir "$SKILLS" --name "$name" ${excluded[@]+"${excluded[@]}"} --dry-run --list-local-edits | grep -E 'LOCAL-EDIT|local edits' || echo "  no local edits"
    echo
    continue
  fi

  target="${TARGET_OVERRIDE:-$(cooled_target "$clone")}"
  if [[ -n "$TARGET_OVERRIDE" ]] && ! git -C "$clone" cat-file -e "$target^{commit}" 2>/dev/null; then
    git -C "$clone" fetch --quiet origin "$target" 2>/dev/null || true
    if ! git -C "$clone" cat-file -e "$target^{commit}" 2>/dev/null; then
      echo "  ERROR: target $target not found upstream"
      failed=1
      echo
      continue
    fi
  fi
  head="$(git -C "$clone" rev-parse HEAD)"
  pending=$(git -C "$clone" rev-list --count "${target:-$head}..$head" 2>/dev/null || echo 0)

  upstream_health "$url" "$clone" "$pin" || attention=1

  # Nothing to move to when no commit is past the cooldown, or the pin already contains the target.
  if [[ -z "$target" ]] || git -C "$clone" merge-base --is-ancestor "$target" "$pin" 2>/dev/null; then
    target="$pin"
  fi

  if [[ "$target" == "$pin" ]]; then
    if (( pending > 0 )); then
      echo "  up to date; $pending newer upstream commit(s) are inside the ${MIN_AGE_DAYS}d cooldown"
    else
      echo "  up to date"
    fi
  elif [[ "$MODE" != apply ]]; then
    echo "  UPDATE: $pin -> $target ($(git -C "$clone" log -1 --format=%cs "$target"))"
    attention=1
  fi

  if [[ "$MODE" == apply ]]; then
    if [[ "$target" != "$pin" ]] || $FINALIZE; then
      flags=()
      $MARK && flags+=(--mark-conflicts)
      $FINALIZE && flags+=(--finalize)
      $PRUNE && flags+=(--prune)
      python3 "$SCRIPT_DIR/revendor_skills.py" --clone "$clone" --pin "$pin" --target "$target" \
        --skills-dir "$SKILLS" --name "$name" ${excluded[@]+"${excluded[@]}"} ${flags[@]+"${flags[@]}"} | sed '1d'
      case "${PIPESTATUS[0]}" in
        0) [[ "$target" != "$pin" ]] && bumps+=("$pin|$target") ;;
        3) manual=1
           $MARK && echo "  next: resolve the markers, then: scripts/update-skills.sh --apply --finalize --target $target $name" ;;
        *) failed=1 ;;
      esac
    fi
    echo
    continue
  fi

  # Report mode: describe what the update would touch.
  mapfile -t at_pin < <(skill_names "$clone" "$pin")
  mapfile -t at_target < <(skill_names "$clone" "$target")
  declare -A in_target=()
  for sk in ${at_target[@]+"${at_target[@]}"}; do in_target["$sk"]=1; done
  declare -A in_pin=()
  vendored=0 not_vendored=0
  removed=() newup=()
  for sk in ${at_pin[@]+"${at_pin[@]}"}; do
    [[ " ${excluded[*]-} " == *" $sk "* ]] && continue
    in_pin["$sk"]=1
    if [[ -d "$SKILLS/$sk" ]]; then
      vendored=$((vendored + 1))
      CLAIMED["$sk"]="$name"
      [[ -n "${in_target[$sk]:-}" ]] || removed+=("$sk")
    else
      not_vendored=$((not_vendored + 1))
    fi
  done
  for sk in ${at_target[@]+"${at_target[@]}"}; do
    [[ -z "${in_pin[$sk]:-}" && ! -d "$SKILLS/$sk" ]] && newup+=("$sk")
  done
  if [[ "$target" != "$pin" ]]; then
    declare -A changed=()
    while IFS= read -r path; do
      dir="$path"
      while [[ "$dir" == */* ]]; do
        dir="${dir%/*}"
        sk="${dir##*/}"
        if [[ -n "${in_pin[$sk]:-}" && -d "$SKILLS/$sk" ]]; then changed["$sk"]=1; break; fi
      done
    done < <(git -C "$clone" diff --name-only "$pin" "$target" 2>/dev/null)
    [[ ${#changed[@]} -gt 0 ]] && echo "  changed upstream (${#changed[@]} vendored): $(printf '%s\n' "${!changed[@]}" | sort | tr '\n' ' ')"
    unset changed
  fi
  [[ ${#removed[@]} -gt 0 ]] && echo "  removed upstream: ${removed[*]}"
  [[ ${#newup[@]} -gt 0 ]] && echo "  new upstream skills since pin (optional to vendor): ${newup[*]}"
  echo "  vendored: $vendored   not vendored at pin: $not_vendored"
  unset in_target in_pin
  echo
done

if [[ "$MODE" == edits ]]; then
  exit $failed
fi

if [[ "$MODE" == apply ]]; then
  for bump in ${bumps[@]+"${bumps[@]}"}; do
    for file in "$SCRIPT_PATH" "$SKILLS_MD" "$TPN"; do
      replace_in_file "$file" "${bump%%|*}" "${bump##*|}" || failed=1
    done
  done
  if [[ ${#bumps[@]} -gt 0 ]]; then
    python3 "$SCRIPT_DIR/curate_claude_skills.py" --write >/dev/null || failed=1
    python3 "$SCRIPT_DIR/audit_skill_dependencies.py" --write-requirements >/dev/null || failed=1
    echo "bumped ${#bumps[@]} pin(s); run 'make validate' before committing"
  fi
  [[ $failed -eq 0 ]] || { echo "re-vendoring failed (see above)" >&2; exit 1; }
  [[ $manual -eq 0 ]] || { echo "some sources need a hand merge (see BLOCKED above)" >&2; exit 3; }
  exit 0
fi

# Vendored skills no source accounted for: project-authored or orphaned.
local_only=()
retained=()
while IFS= read -r skmd; do
  sk="$(basename "$(dirname "$skmd")")"
  case "${CLAIMED[$sk]:-}" in
    "")            local_only+=("$sk") ;;
    *"(retained)") retained+=("$sk") ;;
  esac
done < <(find "$SKILLS" -mindepth 2 -maxdepth 2 -name SKILL.md -type f | sort)

echo "== summary =="
echo "  local-only (no source): ${#local_only[@]}  (project-authored or orphaned)"
if [[ ${#local_only[@]} -gt 0 ]]; then printf '    * %s\n' "${local_only[@]}"; fi
if [[ ${#retained[@]} -gt 0 ]]; then echo "  retained after upstream removal: ${retained[*]}"; fi

if [[ "$MODE" == "check" && $attention -ne 0 ]]; then
  echo "attention needed (see above)" >&2
  exit 1
fi
