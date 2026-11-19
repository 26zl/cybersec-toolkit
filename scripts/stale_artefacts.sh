#!/usr/bin/env bash
# Sourced by install.sh and remove.sh: artefacts left by tools that changed install
# method. Each row is "tool|old method|kind:name"; it applies only when .versions
# records that tool with that old method, i.e. the toolkit installed it that way.
#   pipx:<package>  pipx venv and its links
#   git:<dir>       clone under $GITHUB_TOOL_DIR and its PATH links

STALE_ARTEFACTS=(
    "commix|pipx|pipx:commix"
    "manspider|pipx|pipx:manspider"
    "apktool|git|git:apktool"
)

# _stale_row_matches TOOL METHOD — the record row is one a method change left behind.
_stale_row_matches() {
    local entry tool method
    for entry in "${STALE_ARTEFACTS[@]}"; do
        IFS='|' read -r tool method _ <<< "$entry"
        [[ "$tool" == "$1" && "$method" == "$2" ]] && return 0
    done
    return 1
}

# _stale_drop_row VERSIONS_FILE TOOL METHOD
_stale_drop_row() {
    local file="$1" tmp
    tmp=$(mktemp "${file}.XXXXXX") || return 1
    if awk -F'|' -v t="$2" -v m="$3" '!($1==t && $2==m)' "$file" > "$tmp"; then
        chmod 644 "$tmp" 2>/dev/null || true
        mv -f "$tmp" "$file"
    else
        rm -f "$tmp"
        return 1
    fi
}

# _stale_remove_links NAME DIR — drop PATH links or wrappers that point into DIR.
_stale_remove_links() {
    local lower="${1,,}" link
    for link in "$PIPX_BIN_DIR/$1" "$PIPX_BIN_DIR/$lower" "$PIPX_BIN_DIR/${lower//-/_}"; do
        if _git_launcher_is_managed "$link" "$2"; then
            rm -f "$link"
        fi
    done
}

# _stale_remove_artefact TOOL KIND:NAME — 0 when the artefact is gone.
_stale_remove_artefact() {
    local tool="$1" kind="${2%%:*}" name="${2#*:}" venv dir listed git_status
    case "$kind" in
        pipx)
            venv="$PIPX_HOME/venvs/$(_pipx_venv_name "$name")"
            _stale_remove_links "$tool" "$venv/bin"
            listed=""
            command_exists pipx && listed=$(pipx list --short 2>/dev/null \
                | while read -r _sl_name _; do _pipx_venv_name "$_sl_name"; done || true)
            if grep -qxF -- "$(_pipx_venv_name "$name")" <<< "$listed"; then
                pipx uninstall "$name" >> "$LOG_FILE" 2>&1 || true
            fi
            [[ -d "$venv" && ! -L "$venv" ]] && rm -rf "$venv"
            [[ ! -e "$venv" ]]
            ;;
        git)
            dir="$GITHUB_TOOL_DIR/$name"
            [[ -d "$dir" && ! -L "$dir" ]] || return 0
            if [[ -e "$dir/.git" || -L "$dir/.git" ]]; then
                if ! git_status=$(git -C "$dir" status --porcelain 2>/dev/null); then
                    log_warn "Keeping $dir: cannot inspect its Git working tree"
                    return 1
                fi
                if [[ -n "$git_status" ]]; then
                    log_warn "Keeping $dir: it has uncommitted changes"
                    return 1
                fi
            fi
            _stale_remove_links "$tool" "$dir"
            rm -rf "$dir"
            [[ ! -e "$dir" ]]
            ;;
        *) return 1 ;;
    esac
}

# _cleanup_stale_artefacts VERSIONS_FILE [SUCCESSOR] — remove matching artefacts
# and their rows, optionally restricted to one successor tool.
_cleanup_stale_artefacts() {
    local file="$1" successor="${2:-}" entry tool method artefact failures=0
    [[ -f "$file" ]] || return 0
    for entry in "${STALE_ARTEFACTS[@]}"; do
        IFS='|' read -r tool method artefact <<< "$entry"
        if [[ -n "$successor" && "$successor" != "$tool" ]] \
            && [[ "$successor" != man-spider || "$tool" != manspider ]]; then
            continue
        fi
        awk -F'|' -v t="$tool" -v m="$method" '$1==t && $2==m && $3!="existing"{f=1} END{exit !f}' "$file" || continue
        if _stale_remove_artefact "$tool" "$artefact"; then
            if _stale_drop_row "$file" "$tool" "$method"; then
                log_success "Removed stale $method artefact of $tool ($artefact) and dropped its install record; re-run install.sh to reinstall it"
            else
                log_warn "Removed stale $method artefact of $tool ($artefact), but could not update its install record"
                failures=$((failures + 1))
            fi
        else
            log_warn "Could not remove stale $method artefact of $tool ($artefact)"
            failures=$((failures + 1))
        fi
    done
    return "$failures"
}
