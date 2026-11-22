#!/usr/bin/env bash
# Sourced by install.sh and remove.sh: artefacts left by tools that changed install
# method. Each row is "tool|old method|kind:name|successor module|method:successor";
# it applies only when .versions records that tool with that old method, i.e. the
# toolkit installed it that way.
#   pipx:<package>  pipx venv and its links
#   git:<dir>       clone under $GITHUB_TOOL_DIR and its PATH links
# The successor is the tool that replaces it: git:<name>, pipx:<name> or pkg:<package>.

STALE_ARTEFACTS=(
    "commix|pipx|pipx:commix|web|git:commix"
    "manspider|pipx|pipx:manspider|enterprise|pipx:man-spider"
    "apktool|git|git:apktool|mobile|pkg:apktool"
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

# _stale_successor_ready METHOD:NAME — this host can install the successor.
_stale_successor_ready() {
    local -a packages=()
    case "${1%%:*}" in
        git|pipx) return 0 ;;
        pkg)
            packages=("${1#*:}")
            fixup_package_names packages
            [[ ${#packages[@]} -gt 0 ]]
            ;;
        *) return 1 ;;
    esac
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

# _stale_remove_artefact TOOL KIND:NAME — 0 when the artefact is gone, 1 when it is
# kept for a later retry, 2 when what is there now is not the toolkit's artefact.
_stale_remove_artefact() {
    local tool="$1" kind="${2%%:*}" name="${2#*:}" venv dir dir_esc listed git_status unpushed
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
            if [[ ! -e "$dir/.git" && ! -L "$dir/.git" ]]; then
                log_warn "Leaving $dir alone: it is not a Git clone"
                return 2
            fi
            # As the builder: git applies the clone's own config, which must not run as root.
            dir_esc="$(_escape_single_quoted "$dir")"
            if ! git_status=$(_as_builder "git -C '$dir_esc' status --porcelain --untracked-files=normal --ignored" 2>/dev/null); then
                log_warn "Keeping $dir: cannot inspect its Git working tree"
                return 1
            fi
            # A clone without any commit has nothing unpushed.
            unpushed=0
            if _as_builder "git -C '$dir_esc' rev-parse -q --verify HEAD" >/dev/null 2>&1 \
                && ! unpushed=$(_as_builder "git -C '$dir_esc' rev-list --count HEAD --not --remotes" 2>/dev/null); then
                log_warn "Keeping $dir: cannot inspect its Git working tree"
                return 1
            fi
            # Stashed edits and commits on no remote live only in .git, so they count as local data.
            if [[ -n "$git_status" || "$unpushed" != 0 ]] \
                || _as_builder "git -C '$dir_esc' rev-parse -q --verify refs/stash" >/dev/null 2>&1; then
                log_warn "Keeping $dir: it holds uncommitted changes, stashed edits or commits on no remote"
                return 1
            fi
            _stale_remove_links "$tool" "$dir"
            rm -rf "$dir"
            [[ ! -e "$dir" ]]
            ;;
        *) return 1 ;;
    esac
}

# _cleanup_stale_artefacts VERSIONS_FILE [SUCCESSOR] — remove matching artefacts
# and their rows, optionally only the one the named successor tool replaces.
_cleanup_stale_artefacts() {
    local file="$1" successor="${2:-}" entry tool method artefact next failures=0 rc
    [[ -f "$file" ]] || return 0
    for entry in "${STALE_ARTEFACTS[@]}"; do
        IFS='|' read -r tool method artefact _ next <<< "$entry"
        [[ -z "$successor" || "$successor" == "${next#*:}" ]] || continue
        awk -F'|' -v t="$tool" -v m="$method" '$1==t && $2==m && $3!="existing"{f=1} END{exit !f}' "$file" || continue
        _stale_remove_artefact "$tool" "$artefact"
        rc=$?
        if [[ "$rc" -eq 1 ]]; then
            log_warn "Could not remove stale $method artefact of $tool ($artefact)"
            failures=$((failures + 1))
        elif ! _stale_drop_row "$file" "$tool" "$method"; then
            log_warn "Handled stale $method artefact of $tool ($artefact), but could not update its install record"
            failures=$((failures + 1))
        elif [[ "$rc" -eq 2 ]]; then
            log_info "Dropped the stale $method install record of $tool; what is there now is not the toolkit's"
        else
            log_success "Removed stale $method artefact of $tool ($artefact) and dropped its install record; re-run install.sh to reinstall it"
        fi
    done
    return "$failures"
}
