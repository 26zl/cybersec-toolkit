#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# CyberSec Tools — Update Script (Modular)
# Sources all modules and updates all installed tools across all methods.
# Supports Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE, Termux/Android.
#
# Usage:
#   sudo ./scripts/update.sh                    # Full update (Linux)
#   ./scripts/update.sh                         # Full update (Termux)
#   sudo ./scripts/update.sh --skip-system      # Skip apt/dnf/pacman update
#   sudo ./scripts/update.sh --skip-go          # Skip Go tools

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/installers.sh"
source "$SCRIPT_DIR/lib/shared.sh"
_source_all_modules "$SCRIPT_DIR"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << 'EOF'
CyberSec Tools — Update Script

Usage: sudo ./scripts/update.sh [OPTIONS]    # Linux (requires root)
       ./scripts/update.sh [OPTIONS]          # Termux (no root needed)

Options:
  --skip-system    Skip system package update/upgrade
  --skip-pipx      Skip pipx tool update
  --skip-go        Skip Go tool update
  --skip-git       Skip Git repo update
  --skip-gems      Skip Ruby gem update
  --skip-cargo     Skip Cargo tool update
  --skip-binary    Skip binary release update
  --skip-special   Skip Metasploit/ZAP update
  --skip-docker    Skip Docker image update
  --require-checksums  Fail if a binary release has no checksum file
  -v, --verbose    Enable debug logging and system environment dump
  -h, --help       Show this help and exit
EOF
    exit 0
fi

# Parse args
SKIP_SYSTEM=false
SKIP_PIPX=false
SKIP_GO=false
SKIP_GIT=false
SKIP_GEMS=false
SKIP_CARGO=false
SKIP_BINARY=false
SKIP_SPECIAL=false
SKIP_DOCKER=false
REQUIRE_CHECKSUMS="${REQUIRE_CHECKSUMS:-false}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-system)  SKIP_SYSTEM=true; shift ;;
        --skip-pipx)    SKIP_PIPX=true; shift ;;
        --skip-go)      SKIP_GO=true; shift ;;
        --skip-git)     SKIP_GIT=true; shift ;;
        --skip-gems)    SKIP_GEMS=true; shift ;;
        --skip-cargo)   SKIP_CARGO=true; shift ;;
        --skip-binary)  SKIP_BINARY=true; shift ;;
        --skip-special) SKIP_SPECIAL=true; shift ;;
        --skip-docker)  SKIP_DOCKER=true; shift ;;
        --require-checksums) REQUIRE_CHECKSUMS=true; shift ;;
        -v|--verbose)   VERBOSE=true; shift ;;
        -h|--help)      exec "$0" --help ;;
        *)              log_error "Unknown option: $1"; exit 1 ;;
    esac
done

_init_log_file "$SCRIPT_DIR/tool_update.log"

check_root
print_banner

_check_pkg_manager
_setup_verbose

START_TIME=$(date +%s)
UPDATE_FAILURES=0

# 1) System packages
if [[ "$SKIP_SYSTEM" == "false" ]]; then
    log_info "Updating system packages..."
    if pkg_update >> "$LOG_FILE" 2>&1 && pkg_upgrade >> "$LOG_FILE" 2>&1; then
        log_success "System packages updated"
    else
        log_warn "System package update had errors (check log) — continuing"
        UPDATE_FAILURES=$((UPDATE_FAILURES + 1))
    fi
else
    log_warn "Skipping system package update"
fi
echo ""

# 2) pipx packages
if [[ "$SKIP_PIPX" == "false" ]]; then
    if command_exists pipx; then
        log_info "Updating pipx packages..."
        if pipx upgrade-all >> "$LOG_FILE" 2>&1; then
            log_success "pipx packages updated"
        else
            log_warn "Some pipx packages failed to update (check log)"
            UPDATE_FAILURES=$((UPDATE_FAILURES + 1))
        fi
    else
        log_warn "pipx not found — skipping Python tool updates"
    fi
else
    log_warn "Skipping pipx update"
fi
echo ""

# 3) Go tools
if [[ "$SKIP_GO" == "false" ]]; then
    # Ensure Go is modern enough (>= 1.21) before updating Go tools
    ensure_go
    if command_exists go; then
        # GOPATH and GOBIN are set in common.sh (system-wide: /opt/go, /usr/local/bin)
        log_info "Updating Go tools..."

        # Aggregate all Go install paths from all modules
        ALL_GO_TOOLS=()
        _collect_module_arrays "GO" ALL_GO_TOOLS

        GO_TOTAL=${#ALL_GO_TOOLS[@]}
        GO_CURRENT=0
        GO_UPDATED=0
        GO_LATEST=0
        GO_NOT_INSTALLED=0
        GO_FAILED=0

        if [[ "$GO_TOTAL" -eq 0 ]]; then
            log_info "No Go tools found to update"
        fi

        # Use staging GOBIN + _as_builder (consistent with batch installer)
        _gobin_stage=""
        if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER:-}" != "root" ]] && [[ "$PKG_MANAGER" != "pkg" ]]; then
            _gobin_stage=$(mktemp -d "/tmp/cybersec-gobin.XXXXXX")
            _register_cleanup "$_gobin_stage"
            _chown_for_builder "$_gobin_stage"
            chown -R "$SUDO_USER" "$GOPATH" 2>/dev/null || true
        fi
        _effective_gobin="${_gobin_stage:-$GOBIN}"

        for tool in "${ALL_GO_TOOLS[@]}"; do
            GO_CURRENT=$((GO_CURRENT + 1))
            tool_name=$(_go_bin_name "$tool")
            show_progress "$GO_CURRENT" "$GO_TOTAL" "$tool_name"

            # Only update tools that are already installed
            if ! command_exists "$tool_name"; then
                log_debug "Skipping $tool_name (not installed)"
                GO_NOT_INSTALLED=$((GO_NOT_INSTALLED + 1))
                continue
            fi

            # Record checksum before install to detect actual binary changes
            # (mtime is unreliable: staging mv always updates it)
            old_sum=""
            bin_path=$(command -v "$tool_name" 2>/dev/null || echo "")
            [[ -n "$bin_path" ]] && old_sum=$(sha256sum "$bin_path" 2>/dev/null | cut -d' ' -f1)

            _upd_go_gopath="$(_escape_single_quoted "$GOPATH")"
            _upd_go_gobin="$(_escape_single_quoted "$_effective_gobin")"
            _upd_go_tool="$(_escape_single_quoted "$tool")"
            if _as_builder "GOPATH='$_upd_go_gopath' GOBIN='$_upd_go_gobin' $(command -v go) install $_upd_go_tool" >> "$LOG_FILE" 2>&1; then
                # Compare checksums before moving — detect real changes
                new_sum=""
                if [[ -n "$_gobin_stage" ]] && [[ -f "$_gobin_stage/$tool_name" ]]; then
                    new_sum=$(sha256sum "$_gobin_stage/$tool_name" 2>/dev/null | cut -d' ' -f1)
                    if [[ "$new_sum" == "$old_sum" ]]; then
                        log_debug "Already latest: $tool_name"
                        GO_LATEST=$((GO_LATEST + 1))
                        rm -f "$_gobin_stage/$tool_name"
                    else
                        mv "$_gobin_stage/$tool_name" "$GOBIN/$tool_name" && chmod +x "$GOBIN/$tool_name"
                        log_success "Updated: $tool_name"
                        GO_UPDATED=$((GO_UPDATED + 1))
                        track_version "$tool_name" "go" "latest"
                    fi
                else
                    # No staging (Termux or direct GOBIN) — compare installed binary
                    [[ -n "$bin_path" ]] && new_sum=$(sha256sum "$bin_path" 2>/dev/null | cut -d' ' -f1)
                    if [[ "$new_sum" == "$old_sum" ]]; then
                        log_debug "Already latest: $tool_name"
                        GO_LATEST=$((GO_LATEST + 1))
                    else
                        log_success "Updated: $tool_name"
                        GO_UPDATED=$((GO_UPDATED + 1))
                        track_version "$tool_name" "go" "latest"
                    fi
                fi
            else
                log_warn "Failed: $tool_name"
                GO_FAILED=$((GO_FAILED + 1))
            fi
        done
        [[ -n "$_gobin_stage" ]] && rm -rf "$_gobin_stage"
        echo ""
        log_success "Go tools: $GO_UPDATED updated, $GO_LATEST already latest, $GO_NOT_INSTALLED skipped (not installed), $GO_FAILED failed"
        UPDATE_FAILURES=$((UPDATE_FAILURES + GO_FAILED))
    else
        log_warn "Go not found — skipping Go tool updates"
    fi
else
    log_warn "Skipping Go tool update"
fi
echo ""

# 4) GitHub repos
if [[ "$SKIP_GIT" == "false" ]]; then
    log_info "Updating GitHub repositories in $GITHUB_TOOL_DIR..."
    if [[ -d "$GITHUB_TOOL_DIR" ]]; then
        GIT_TOTAL=0
        GIT_UPDATED=0
        GIT_SKIPPED=0
        GIT_FAILED=0
        for dir in "$GITHUB_TOOL_DIR"/*/; do
            [[ -d "$dir/.git" ]] || continue
            name="$(basename "$dir")"
            GIT_TOTAL=$((GIT_TOTAL + 1))

            pull_output=""
            _dir_escaped="$(_escape_single_quoted "$dir")"
            if pull_output=$(_as_builder "git -C '$_dir_escaped' pull" 2>>"$LOG_FILE"); then
                if echo "$pull_output" | grep -q "Already up to date"; then
                    log_debug "Already latest: $name"
                    GIT_SKIPPED=$((GIT_SKIPPED + 1))
                else
                    log_success "Updated: $name"
                    GIT_UPDATED=$((GIT_UPDATED + 1))
                    track_version "$name" "git" "HEAD"

                    # Reinstall Python deps if present — only into existing venvs to
                    # avoid polluting system Python.
                    if [[ -f "$dir/requirements.txt" ]]; then
                        if [[ -d "$dir/venv" ]]; then
                            "$dir/venv/bin/pip" install -q -r "$dir/requirements.txt" >> "$LOG_FILE" 2>&1 || true
                        elif [[ -d "$dir/.venv" ]]; then
                            "$dir/.venv/bin/pip" install -q -r "$dir/requirements.txt" >> "$LOG_FILE" 2>&1 || true
                        else
                            log_warn "$name has requirements.txt but no venv — skipping pip install (create venv to enable)"
                        fi
                    fi
                fi
            else
                # Retry: reset to remote HEAD and pull again (handles dirty trees, e.g. SecLists)
                log_debug "git pull failed for $name — resetting to remote HEAD..."
                _remote_branch=""
                _remote_branch=$(_as_builder "git -C '$_dir_escaped' symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|refs/remotes/origin/||'") || true
                _remote_branch="${_remote_branch%%[[:space:]]*}"
                [[ -z "$_remote_branch" ]] && _remote_branch="main"
                _branch_escaped="$(_escape_single_quoted "origin/$_remote_branch")"
                if _as_builder "git -C '$_dir_escaped' fetch origin" >> "$LOG_FILE" 2>&1 \
                    && _as_builder "git -C '$_dir_escaped' reset --hard '$_branch_escaped'" >> "$LOG_FILE" 2>&1; then
                    log_success "Updated: $name (reset to origin/$_remote_branch)"
                    GIT_UPDATED=$((GIT_UPDATED + 1))
                    track_version "$name" "git" "HEAD"
                else
                    log_warn "Failed: $name"
                    GIT_FAILED=$((GIT_FAILED + 1))
                fi
            fi
        done
        log_success "Git repos: $GIT_UPDATED updated, $GIT_SKIPPED already latest, $GIT_FAILED failed ($GIT_TOTAL total)"
    else
        log_warn "$GITHUB_TOOL_DIR not found — skipping"
    fi
else
    log_warn "Skipping Git repo update"
fi
echo ""

# 5) Ruby gems
if [[ "$SKIP_GEMS" == "false" ]]; then
    if command_exists gem; then
        # Aggregate all gems from modules
        ALL_GEMS=()
        _collect_module_arrays "GEMS" ALL_GEMS

        if [[ ${#ALL_GEMS[@]} -gt 0 ]]; then
            # Only update gems that are already installed
            installed_gems=$(gem list --no-details 2>/dev/null || true)
            GEMS_TO_UPDATE=()
            for _gem in "${ALL_GEMS[@]}"; do
                if echo "$installed_gems" | grep -q "^${_gem} "; then
                    GEMS_TO_UPDATE+=("$_gem")
                else
                    log_debug "Skipping gem $_gem (not installed)"
                fi
            done
            if [[ ${#GEMS_TO_UPDATE[@]} -gt 0 ]]; then
                log_info "Updating Ruby gems (${GEMS_TO_UPDATE[*]})..."
                _gem_update_args=""
                for _g in "${GEMS_TO_UPDATE[@]}"; do
                    _gem_update_args+=" '$(_escape_single_quoted "$_g")'"
                done
                if _as_builder "$(command -v gem) update $_gem_update_args --no-document" >> "$LOG_FILE" 2>&1; then
                    log_success "Ruby gems updated"
                    # Refresh symlinks (new version may have new binary paths)
                    _gem_bin_dir="$(_builder_home)/.local/share/gem/ruby/*/bin" 2>/dev/null
                    for _gem in "${GEMS_TO_UPDATE[@]}"; do
                        # shellcheck disable=SC2086  # glob expansion intentional
                        for _gbin in $_gem_bin_dir/$_gem; do
                            [[ -f "$_gbin" ]] && ln -sf "$_gbin" "$PIPX_BIN_DIR/$(basename "$_gbin")" 2>/dev/null || true
                        done
                    done
                else
                    log_warn "Ruby gem update failed"
                    UPDATE_FAILURES=$((UPDATE_FAILURES + 1))
                fi
            else
                log_info "No installed Ruby gems to update"
            fi
        fi
    else
        log_warn "gem not found — skipping Ruby gem updates"
    fi
else
    log_warn "Skipping Ruby gem update"
fi
echo ""

# 6) Cargo tools
if [[ "$SKIP_CARGO" == "false" ]]; then
    if command_exists cargo; then
        _cargo_bin_dir="$(_builder_home)/.cargo/bin"
        export PATH="$_cargo_bin_dir:$HOME/.cargo/bin:$PATH"
        ALL_CARGO=()
        _collect_module_arrays "CARGO" ALL_CARGO

        if [[ ${#ALL_CARGO[@]} -gt 0 ]]; then
            CARGO_UPDATED=0
            CARGO_LATEST=0
            CARGO_NOT_INSTALLED=0
            CARGO_FAILED=0

            log_info "Updating Cargo tools (${ALL_CARGO[*]})..."
            for crate in "${ALL_CARGO[@]}"; do
                # Only update crates that are already installed
                if ! command_exists "$crate" && [[ ! -f "$_cargo_bin_dir/$crate" ]]; then
                    log_debug "Skipping cargo $crate (not installed)"
                    CARGO_NOT_INSTALLED=$((CARGO_NOT_INSTALLED + 1))
                    continue
                fi
                # Without --force, cargo skips if the installed version matches latest
                cargo_output=""
                _upd_crate_esc="$(_escape_single_quoted "$crate")"
                if cargo_output=$(_as_builder "$(command -v cargo) install $_upd_crate_esc" 2>&1); then
                    if echo "$cargo_output" | grep -q "already installed"; then
                        log_debug "Already latest: $crate"
                        CARGO_LATEST=$((CARGO_LATEST + 1))
                    else
                        log_success "Updated cargo: $crate"
                        CARGO_UPDATED=$((CARGO_UPDATED + 1))
                        if [[ -f "$_cargo_bin_dir/$crate" ]]; then
                            ln -sf "$_cargo_bin_dir/$crate" "$PIPX_BIN_DIR/$crate" 2>/dev/null || true
                        fi
                        track_version "$crate" "cargo" "latest"
                    fi
                else
                    # cargo install exits non-zero for "already installed" on some versions
                    if echo "$cargo_output" | grep -q "already installed"; then
                        log_debug "Already latest: $crate"
                        CARGO_LATEST=$((CARGO_LATEST + 1))
                    else
                        log_warn "Failed cargo: $crate"
                        CARGO_FAILED=$((CARGO_FAILED + 1))
                    fi
                fi
                echo "$cargo_output" >> "$LOG_FILE"
            done
            log_success "Cargo tools: $CARGO_UPDATED updated, $CARGO_LATEST already latest, $CARGO_NOT_INSTALLED skipped (not installed), $CARGO_FAILED failed"
            UPDATE_FAILURES=$((UPDATE_FAILURES + CARGO_FAILED))
        fi
    else
        log_warn "cargo not found — skipping Cargo tool updates"
    fi
else
    log_warn "Skipping Cargo tool update"
fi
echo ""

# 7) Binary releases (GitHub release assets)
if [[ "$SKIP_BINARY" == "false" ]]; then
    log_info "Updating binary releases..."
    BIN_TOTAL=0
    BIN_UPDATED=0
    BIN_SKIPPED=0
    BIN_FAILED=0

    # Re-download only if the binary is already installed and a new version exists
    update_binary() {
        local repo="$1" binary="$2" pattern="$3" dest="${4:-$PIPX_BIN_DIR}"

        # Skip if not installed
        command_exists "$binary" || [[ -f "$dest/$binary" ]] || [[ -f "$dest/bin/$binary" ]] || return 0

        BIN_TOTAL=$((BIN_TOTAL + 1))

        # Get installed version from .versions file
        local installed_ver=""
        installed_ver=$(grep "^${binary}|" "$VERSION_FILE" 2>/dev/null | cut -d'|' -f3)

        # Get latest release tag from GitHub
        local api_url="https://api.github.com/repos/$repo/releases/latest"
        local latest_tag=""
        local _api_response=""
        _api_response=$(_gh_api_get "$api_url" 2>/dev/null) || true
        latest_tag=$(echo "$_api_response" \
            | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null)

        if [[ -n "$latest_tag" && -n "$installed_ver" && "$latest_tag" == "$installed_ver" ]]; then
            log_debug "Already latest: $binary ($latest_tag)"
            BIN_SKIPPED=$((BIN_SKIPPED + 1))
            return 0
        fi

        # Version differs or unknown — re-download
        local old_ver="${installed_ver:-unknown}"

        # Checksum before download to detect actual changes
        local _bin_path="" _old_bin_sum=""
        _bin_path=$(command -v "$binary" 2>/dev/null || echo "")
        [[ -z "$_bin_path" ]] && [[ -f "$dest/$binary" ]] && _bin_path="$dest/$binary"
        [[ -z "$_bin_path" ]] && [[ -f "$dest/bin/$binary" ]] && _bin_path="$dest/bin/$binary"
        [[ -n "$_bin_path" ]] && _old_bin_sum=$(sha256sum "$_bin_path" 2>/dev/null | cut -d' ' -f1)

        if download_github_release_update "$repo" "$binary" "$pattern" "$dest" >> "$LOG_FILE" 2>&1; then
            local tag="${_RELEASE_TAG:-$latest_tag}"
            track_version "$binary" "binary" "$tag"

            # Compare checksum to detect if binary actually changed
            local _new_bin_sum=""
            _bin_path=$(command -v "$binary" 2>/dev/null || echo "")
            [[ -z "$_bin_path" ]] && [[ -f "$dest/$binary" ]] && _bin_path="$dest/$binary"
            [[ -z "$_bin_path" ]] && [[ -f "$dest/bin/$binary" ]] && _bin_path="$dest/bin/$binary"
            [[ -n "$_bin_path" ]] && _new_bin_sum=$(sha256sum "$_bin_path" 2>/dev/null | cut -d' ' -f1)

            if [[ -n "$_old_bin_sum" && "$_old_bin_sum" == "$_new_bin_sum" ]]; then
                log_debug "Already latest: $binary ($tag)"
                BIN_SKIPPED=$((BIN_SKIPPED + 1))
            elif [[ "$old_ver" == "unknown" || "$old_ver" == "existing" || "$old_ver" == "latest" ]]; then
                log_success "Updated: $binary (→ $tag)"
                BIN_UPDATED=$((BIN_UPDATED + 1))
            else
                log_success "Updated: $binary ($old_ver → $tag)"
                BIN_UPDATED=$((BIN_UPDATED + 1))
            fi
        else
            log_warn "Failed: $binary"
            BIN_FAILED=$((BIN_FAILED + 1))
        fi
    }

    # Iterate all BINARY_RELEASES_* registry arrays (defined in lib/installers.sh)
    _ALL_BIN_RELEASES=()
    for _br_mod in "${ALL_MODULES[@]}"; do
        _append_module_array _ALL_BIN_RELEASES "BINARY_RELEASES_${_br_mod^^}"
    done
    for _entry in "${_ALL_BIN_RELEASES[@]}"; do
        IFS='|' read -r _repo _binary _pattern _dest <<< "$_entry"
        update_binary "$_repo" "$_binary" "$_pattern" "${_dest:-$PIPX_BIN_DIR}"
    done

    if [[ "$BIN_TOTAL" -gt 0 ]]; then
        log_success "Binary releases: $BIN_UPDATED updated, $BIN_SKIPPED already latest, $BIN_FAILED failed ($BIN_TOTAL total)"
        UPDATE_FAILURES=$((UPDATE_FAILURES + BIN_FAILED))
    else
        log_info "No binary releases found to update"
    fi
else
    log_warn "Skipping binary release update"
fi
echo ""

# 8) Special tools
if [[ "$SKIP_SPECIAL" == "false" ]]; then
    log_info "Updating special tools..."

    # Metasploit (snap takes priority, then msfupdate for Rapid7/apt installs)
    if snap_available && snap list metasploit-framework &>/dev/null 2>&1; then
        log_info "Updating Metasploit (snap)..."
        snap refresh metasploit-framework >> "$LOG_FILE" 2>&1 && \
            log_success "Metasploit updated" || \
            log_warn "Metasploit update failed"
    elif command_exists msfupdate; then
        log_info "Updating Metasploit..."
        msfupdate >> "$LOG_FILE" 2>&1 && \
            log_success "Metasploit updated" || \
            log_warn "Metasploit update failed"
    fi

    # npm tools (promptfoo)
    if command_exists npm && command_exists promptfoo; then
        log_info "Updating promptfoo (npm)..."
        if npm install -g "promptfoo@latest" >> "$LOG_FILE" 2>&1; then
            _pf_ver=$(promptfoo --version 2>/dev/null || echo "latest")
            log_success "promptfoo updated ($_pf_ver)"
            track_version "promptfoo" "npm" "$_pf_ver"
        else
            log_warn "promptfoo update failed"
        fi
    fi

    # OWASP ZAP (snap)
    if command_exists zaproxy && snap_available; then
        log_info "Updating OWASP ZAP..."
        snap refresh zaproxy >> "$LOG_FILE" 2>&1 && \
            log_success "OWASP ZAP updated" || \
            log_warn "OWASP ZAP update failed"
    fi

    # Foundry (foundryup)
    if command_exists foundryup; then
        log_info "Updating Foundry toolchain..."
        foundryup >> "$LOG_FILE" 2>&1 && \
            log_success "Foundry updated" || \
            log_warn "Foundry update failed"
    fi

    # Steampipe (re-install = self-update) — verify script content before executing
    if command_exists steampipe; then
        log_info "Updating Steampipe..."
        _sp_tmp=$(mktemp)
        _register_cleanup "$_sp_tmp"
        if curl -fsSL "https://raw.githubusercontent.com/turbot/steampipe/main/scripts/install.sh" -o "$_sp_tmp" 2>>"$LOG_FILE" \
                && _validate_curl_pipe "$_sp_tmp" "steampipe" "install" "github"; then
            if bash "$_sp_tmp" -y >> "$LOG_FILE" 2>&1; then
                log_success "Steampipe updated"
            else
                log_warn "Steampipe update failed"
            fi
        else
            log_warn "Steampipe update script verification failed — skipping"
        fi
        rm -f "$_sp_tmp"
    fi
else
    log_warn "Skipping special tool updates"
fi
echo ""

# 9) Docker images
if [[ "$SKIP_DOCKER" == "false" ]]; then
    if command_exists docker; then
        log_info "Updating Docker images..."
        DOCKER_UPDATED=0
        for _docker_entry in "${ALL_DOCKER_IMAGES[@]}"; do
            IFS='|' read -r _docker_img _docker_label <<< "$_docker_entry"
            if docker images "${_docker_img%%:*}" -q 2>/dev/null | grep -q .; then
                if docker pull "$_docker_img" >> "$LOG_FILE" 2>&1; then
                    log_success "Updated Docker: $_docker_label"
                    DOCKER_UPDATED=$((DOCKER_UPDATED + 1))
                else
                    log_warn "Failed Docker: $_docker_label"
                    UPDATE_FAILURES=$((UPDATE_FAILURES + 1))
                fi
            fi
        done
        [[ "$DOCKER_UPDATED" -gt 0 ]] && log_success "Docker images: $DOCKER_UPDATED updated"
    fi
else
    log_warn "Skipping Docker image update"
fi

echo ""

# 10) Build-from-source tools (git pull + rebuild)
log_info "Updating build-from-source tools..."
BUILD_UPDATED=0
BUILD_SKIPPED=0
BUILD_FAILED=0
for _bmod in "${ALL_MODULES[@]}"; do
    _bpfx=$(_module_prefix "$_bmod")
    _bnames_var="${_bpfx}_BUILD_NAMES"
    declare -p "$_bnames_var" &>/dev/null || continue
    declare -n _bnames="$_bnames_var"
    for _bname in "${_bnames[@]}"; do
        _bdir="$GITHUB_TOOL_DIR/$_bname"
        [[ -d "$_bdir/.git" ]] || { log_debug "Skipping build $_bname (not cloned)"; BUILD_SKIPPED=$((BUILD_SKIPPED + 1)); continue; }
        _bdir_escaped="$(_escape_single_quoted "$_bdir")"
        _pull_out=""
        if _pull_out=$(_as_builder "git -C '$_bdir_escaped' pull" 2>>"$LOG_FILE"); then
            if echo "$_pull_out" | grep -q "Already up to date"; then
                log_debug "Already latest: $_bname"
                BUILD_SKIPPED=$((BUILD_SKIPPED + 1))
            else
                log_success "Updated source: $_bname — attempting rebuild..."
                # Try common build patterns (use _as_builder for consistent ownership)
                if [[ -f "$_bdir/Makefile" ]]; then
                    if _as_builder "make -C '$_bdir_escaped' -j$(nproc 2>/dev/null || echo 2)" >> "$LOG_FILE" 2>&1; then
                        log_success "Rebuilt: $_bname"
                    else
                        log_warn "Rebuild failed for $_bname (make failed) — source updated"
                    fi
                elif [[ -f "$_bdir/Cargo.toml" ]]; then
                    if _as_builder "cd '$_bdir_escaped' && $(command -v cargo) build --release" >> "$LOG_FILE" 2>&1; then
                        log_success "Rebuilt: $_bname"
                    else
                        log_warn "Rebuild failed for $_bname (cargo build failed) — source updated"
                    fi
                fi
                BUILD_UPDATED=$((BUILD_UPDATED + 1))
                track_version "$_bname" "source" "HEAD"
            fi
        else
            log_warn "Failed to update: $_bname"
            BUILD_FAILED=$((BUILD_FAILED + 1))
        fi
    done
done
if [[ "$BUILD_UPDATED" -gt 0 || "$BUILD_FAILED" -gt 0 || "$BUILD_SKIPPED" -gt 0 ]]; then
    log_success "Build-from-source: $BUILD_UPDATED updated, $BUILD_SKIPPED already latest, $BUILD_FAILED failed"
    UPDATE_FAILURES=$((UPDATE_FAILURES + BUILD_FAILED))
fi
echo ""

# Done
disable_debug_trace

_print_completion_banner "$START_TIME" "$UPDATE_FAILURES" \
    "$(if [[ "$UPDATE_FAILURES" -gt 0 ]]; then echo "Update finished with $UPDATE_FAILURES failure(s)"; else echo "Update complete!"; fi)"
log_info "Log file: $LOG_FILE"
log_info "Run ./scripts/verify.sh to confirm all tools are working"

# Clean up GitHub API cache
_gh_api_cache_cleanup 2>/dev/null || true

[[ "$UPDATE_FAILURES" -gt 0 ]] && exit 1
exit 0
