#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# CyberSec Tools — Removal Script (Modular)
# Sources all modules and removes all installed tools across all methods.
# Supports Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE, Termux/Android.
#
# Usage:
#   sudo ./scripts/remove.sh                      # Remove everything (Linux)
#   ./scripts/remove.sh                           # Remove everything (Termux)
#   sudo ./scripts/remove.sh --module web          # Remove web module only
#   sudo ./scripts/remove.sh --remove-deps          # Also remove base packages (dangerous)
#   sudo ./scripts/remove.sh --yes                 # Skip confirmation

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/installers.sh"
source "$SCRIPT_DIR/lib/shared.sh"
_source_all_modules "$SCRIPT_DIR"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << EOF
CyberSec Tools — Removal Script

Usage: sudo ./scripts/remove.sh [OPTIONS]    # Linux (requires root)
       ./scripts/remove.sh [OPTIONS]          # Termux (no root needed)

Options:
  --module <name>    Remove specific module only (can be repeated)
  --remove-deps      Also remove base dependencies (python3, openssl, git,
                       build-essential, etc.) — DANGEROUS, may break system
  --deep-clean       Remove all caches, module caches, build artifacts, and
                       stale symlinks (Go cache, Cargo registry, pip/pipx
                       cache, npm cache, rustup toolchains, log files)
  --yes              Skip confirmation prompt
  -v, --verbose      Enable debug logging and system environment dump
  -h, --help         Show this help and exit

Modules: $(IFS=', '; echo "${ALL_MODULES[*]}")

By default, base dependencies are preserved.  Use --remove-deps explicitly
to include them in the removal (not recommended on production systems).
EOF
    exit 0
fi

# Parse args
REMOVE_MODULES=()
REMOVE_DEPS=false
DEEP_CLEAN=false
AUTO_YES=false
REMOVAL_FAILURES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --module)      [[ $# -lt 2 ]] && { log_error "--module requires an argument"; exit 1; }
                       REMOVE_MODULES+=("$2"); shift 2 ;;
        --remove-deps) REMOVE_DEPS=true; shift ;;
        --deep-clean)  DEEP_CLEAN=true; shift ;;
        --yes)         AUTO_YES=true; shift ;;
        -v|--verbose)  VERBOSE=true; shift ;;
        -h|--help)     exec "$0" --help ;;
        *)             log_error "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ ${#REMOVE_MODULES[@]} -eq 0 ]]; then
    REMOVE_MODULES=("${ALL_MODULES[@]}")
fi

_init_log_file "$SCRIPT_DIR/tool_removal.log"

check_root
print_banner

# When disk space is critically low, free package cache FIRST so that
# subsequent pkg_remove calls have enough room for dpkg temp files.
_avail_mb=0
if [[ "$PKG_MANAGER" == "pkg" ]]; then
    _avail_mb=$(df -Pm "$PREFIX" 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
else
    _avail_mb=$(df -Pm / 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
fi
if [[ "$_avail_mb" =~ ^[0-9]+$ ]] && [[ "$_avail_mb" -lt 100 ]]; then
    log_warn "Very low disk space (${_avail_mb}MB free) — clearing package cache first"
    case "$PKG_MANAGER" in
        apt)     maybe_sudo apt-get clean 2>/dev/null || true ;;
        dnf)     maybe_sudo dnf clean all 2>/dev/null || true ;;
        pacman)  maybe_sudo pacman -Sc --noconfirm 2>/dev/null || true ;;
        zypper)  maybe_sudo zypper clean 2>/dev/null || true ;;
        pkg)     pkg clean 2>/dev/null || true ;;
    esac
    # Re-check — if log file was /dev/null due to full disk, try again
    if [[ "$LOG_FILE" == "/dev/null" ]]; then
        if : > "$SCRIPT_DIR/tool_removal.log" 2>/dev/null; then
            LOG_FILE="$SCRIPT_DIR/tool_removal.log"
            chmod 644 "$LOG_FILE" 2>/dev/null || true
            log_info "Disk space freed — logging to $LOG_FILE"
        fi
    fi
fi

_check_pkg_manager
_setup_verbose

# Confirmation
if [[ "$AUTO_YES" == "false" ]]; then
    log_warn "This will remove cybersecurity tools and their configurations."
    log_warn "Modules to remove: ${REMOVE_MODULES[*]}"
    if [[ "$REMOVE_DEPS" == "true" ]]; then
        log_error "--remove-deps: Base dependencies (python3, openssl, git, etc.) WILL be removed!"
    else
        log_success "Base dependencies will be preserved (use --remove-deps to include)"
    fi
    if [[ "$DEEP_CLEAN" == "true" ]]; then
        log_warn "--deep-clean: All caches, build artifacts, and stale files WILL be purged!"
    fi
    echo ""
    read -rp "Proceed with removal? (y/N) " confirm
    echo ""
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_warn "Removal cancelled by user"
        exit 0
    fi
fi

START_TIME=$(date +%s)

# shellcheck disable=SC2076  # Intentional literal match, not regex
should_remove() { [[ " ${REMOVE_MODULES[*]} " =~ " $1 " ]]; }

# Build aggregate removal lists from module arrays
PKGS_TO_REMOVE=()
PIPX_TO_REMOVE=()
GO_BINS_TO_REMOVE=()
GIT_NAMES_TO_REMOVE=()
GEMS_TO_REMOVE=()
CARGO_TO_REMOVE=()

# Shared base deps: only remove with --remove-deps
if [[ "$REMOVE_DEPS" == "true" ]]; then
    _append_module_array PKGS_TO_REMOVE "SHARED_BASE_PACKAGES"
else
    log_info "Preserving shared base dependencies (--remove-deps not set)"
fi

for _mod in "${REMOVE_MODULES[@]}"; do
    should_remove "$_mod" || continue
    _pfx=$(_module_prefix "$_mod")

    _append_module_array PKGS_TO_REMOVE "${_pfx}_PACKAGES"
    _append_module_array PKGS_TO_REMOVE "${_pfx}_HEAVY_PACKAGES"

    _append_module_array PIPX_TO_REMOVE      "${_pfx}_PIPX"
    _append_module_array GO_BINS_TO_REMOVE   "${_pfx}_GO_BINS"
    _append_module_array GIT_NAMES_TO_REMOVE "${_pfx}_GIT_NAMES"
    _append_module_array GIT_NAMES_TO_REMOVE "${_pfx}_BUILD_NAMES"
    _append_module_array GEMS_TO_REMOVE      "${_pfx}_GEMS"
    _append_module_array CARGO_TO_REMOVE     "${_pfx}_CARGO"
done

# Execute removal
# ORDER: Tools that need runtime commands (pipx, gem, cargo) are removed FIRST,
# before system packages which may remove those runtimes.

# 1) pipx tools — must run BEFORE system packages remove python3-pipx
if [[ ${#PIPX_TO_REMOVE[@]} -gt 0 ]]; then
    if command_exists pipx; then
        # Cache installed list once, normalized to underscores for PEP 503 matching
        installed_pipx=$(pipx list --short 2>/dev/null | sed 's/-/_/g' || true)
        pipx_removed=0
        pipx_skipped=0
        for tool in "${PIPX_TO_REMOVE[@]}"; do
            # Normalize hyphens → underscores (PEP 503: pip/pipx normalize package names)
            _norm="${tool//-/_}"
            if echo "$installed_pipx" | grep -qi "^${_norm} "; then
                pipx_remove "$tool" >> "$LOG_FILE" 2>&1
                log_success "Removed pipx: $tool"
                pipx_removed=$((pipx_removed + 1))
            else
                log_debug "Skipping pipx $tool (not installed)"
                pipx_skipped=$((pipx_skipped + 1))
            fi
        done
        log_info "pipx: $pipx_removed removed, $pipx_skipped already removed"
    else
        # Fallback: pipx command not available — clean up files directly
        log_warn "pipx not found — removing pipx tools by cleaning up files directly"
        pipx_removed=0
        for tool in "${PIPX_TO_REMOVE[@]}"; do
            _removed=false
            # Try exact name, then normalized (hyphens → underscores, and vice versa)
            for _variant in "$tool" "${tool//-/_}" "${tool//_/-}"; do
                if [[ -f "$PIPX_BIN_DIR/$_variant" ]] || [[ -L "$PIPX_BIN_DIR/$_variant" ]]; then
                    rm -f "$PIPX_BIN_DIR/$_variant"
                    log_success "Removed: $PIPX_BIN_DIR/$_variant"
                    _removed=true
                fi
                if [[ -d "$PIPX_HOME/venvs/$_variant" ]]; then
                    rm -rf "$PIPX_HOME/venvs/$_variant"
                    log_debug "Removed venv: $PIPX_HOME/venvs/$_variant"
                    _removed=true
                fi
            done
            [[ "$_removed" == "true" ]] && pipx_removed=$((pipx_removed + 1))
        done
        log_info "pipx (file cleanup): $pipx_removed tools removed"
    fi
else
    log_info "No pipx tools to remove"
fi
echo ""

# 2) Ruby gems — must run BEFORE system packages remove ruby
if [[ ${#GEMS_TO_REMOVE[@]} -gt 0 ]] && command_exists gem; then
    installed_gems=$(gem list --no-details 2>/dev/null || true)
    gems_removed=0
    gems_skipped=0
    for gem_name in "${GEMS_TO_REMOVE[@]}"; do
        if echo "$installed_gems" | grep -q "^${gem_name} "; then
            gem uninstall -x "$gem_name" >> "$LOG_FILE" 2>&1 && gems_removed=$((gems_removed + 1)) || true
        else
            log_debug "Skipping gem $gem_name (not installed)"
            gems_skipped=$((gems_skipped + 1))
        fi
    done
    log_info "Gems: $gems_removed removed, $gems_skipped already removed"
elif [[ ${#GEMS_TO_REMOVE[@]} -gt 0 ]]; then
    log_warn "gem not found — skipping Ruby gem removal"
fi
echo ""

# 3) Cargo tools — must run BEFORE system packages (cargo is from rustup, not apt, but be safe)
if [[ ${#CARGO_TO_REMOVE[@]} -gt 0 ]]; then
    _cargo_home="$(_builder_home)/.cargo/bin"
    log_info "Removing ${#CARGO_TO_REMOVE[@]} Cargo tools..."
    for crate in "${CARGO_TO_REMOVE[@]}"; do
        if ! command_exists "$crate" && [[ ! -f "$_cargo_home/$crate" ]]; then
            log_debug "Skipping cargo $crate (not installed)"
            continue
        fi
        if command_exists cargo; then
            cargo uninstall "$crate" >> "$LOG_FILE" 2>&1 && \
                log_success "Removed cargo: $crate" || true
        fi
        # Clean up binary and symlink regardless of cargo uninstall result
        [[ -f "$_cargo_home/$crate" ]] && rm -f "$_cargo_home/$crate"
        [[ -L "$PIPX_BIN_DIR/$crate" ]] && rm -f "$PIPX_BIN_DIR/$crate"
    done
fi
echo ""

# 4) System packages — AFTER tools that need runtime commands
if [[ ${#PKGS_TO_REMOVE[@]} -gt 0 ]]; then
    # Apply distro-specific package name translation (same as install path)
    fixup_package_names PKGS_TO_REMOVE

    # Filter to only installed packages
    PKGS_INSTALLED=()
    pkgs_skipped=0
    for pkg in "${PKGS_TO_REMOVE[@]}"; do
        if pkg_is_installed "$pkg"; then
            PKGS_INSTALLED+=("$pkg")
        else
            log_debug "Skipping $pkg (not installed)"
            pkgs_skipped=$((pkgs_skipped + 1))
        fi
    done

    if [[ ${#PKGS_INSTALLED[@]} -gt 0 ]]; then
        log_info "Removing ${#PKGS_INSTALLED[@]} system packages (${pkgs_skipped} already removed)..."
        if pkg_remove "${PKGS_INSTALLED[@]}" >> "$LOG_FILE" 2>&1; then
            log_success "System packages: ${#PKGS_INSTALLED[@]} removed"
        else
            log_warn "Some packages failed to remove (check log)"
            REMOVAL_FAILURES=$((REMOVAL_FAILURES + 1))
        fi
    else
        log_info "All ${#PKGS_TO_REMOVE[@]} system packages already removed"
    fi
else
    log_info "No system packages to remove"
fi
echo ""

# 5) Go binaries
# Go binaries are installed to $GOBIN (GOBIN) system-wide
if [[ ${#GO_BINS_TO_REMOVE[@]} -gt 0 ]]; then
    go_removed=0
    go_skipped=0
    for bin in "${GO_BINS_TO_REMOVE[@]}"; do
        if [[ -f "$GOBIN/$bin" ]]; then
            rm -f "$GOBIN/$bin"
            log_success "Removed: $GOBIN/$bin"
            go_removed=$((go_removed + 1))
        else
            log_debug "Skipping Go binary $bin (not installed)"
            go_skipped=$((go_skipped + 1))
        fi
    done
    log_info "Go binaries: $go_removed removed, $go_skipped already removed"
fi
echo ""

# 6) GitHub repos
if [[ ${#GIT_NAMES_TO_REMOVE[@]} -gt 0 ]]; then
    git_removed=0
    git_skipped=0
    for name in "${GIT_NAMES_TO_REMOVE[@]}"; do
        repo_path="$GITHUB_TOOL_DIR/$name"
        if [[ -d "$repo_path" ]]; then
            rm -rf "$repo_path"
            log_success "Removed: $repo_path"
            git_removed=$((git_removed + 1))
        else
            log_debug "Skipping git repo $name (not present)"
            git_skipped=$((git_skipped + 1))
        fi
    done
    log_info "Git repos: $git_removed removed, $git_skipped already removed"
fi

# 6b) Build-from-source binaries — installed to /usr/local/bin via make install
for _bmod in "${REMOVE_MODULES[@]}"; do
    _bpfx=$(_module_prefix "$_bmod")
    _bnames_var="${_bpfx}_BUILD_NAMES"
    declare -p "$_bnames_var" &>/dev/null || continue
    declare -n _bnames="$_bnames_var"
    for _bname in "${_bnames[@]}"; do
        [[ -f "/usr/local/bin/$_bname" ]] && rm -f "/usr/local/bin/$_bname" && \
            log_success "Removed build-from-source binary: /usr/local/bin/$_bname"
    done
done
echo ""

# 7) Binary releases
log_info "Removing binary releases from $PIPX_BIN_DIR..."
# Build BINARY_TOOLS dynamically from BINARY_RELEASES_* arrays in installers.sh
# (single source of truth — no hardcoded list to maintain)
_extract_binary_names() {
    local -n _br_ref="$1"
    for _br_entry in "${_br_ref[@]}"; do
        IFS='|' read -r _br_repo _br_binary _br_rest <<< "$_br_entry"
        BINARY_TOOLS+=("$_br_binary")
    done
}
BINARY_TOOLS=()
for _br_mod in "${REMOVE_MODULES[@]}"; do
    _br_arr="BINARY_RELEASES_${_br_mod^^}"
    declare -p "$_br_arr" &>/dev/null || continue
    _extract_binary_names "$_br_arr"
done
bin_removed=0
bin_skipped=0
for bin in "${BINARY_TOOLS[@]}"; do
    if [[ -f "$PIPX_BIN_DIR/$bin" ]]; then
        rm -f "$PIPX_BIN_DIR/$bin"
        log_success "Removed: $PIPX_BIN_DIR/$bin"
        bin_removed=$((bin_removed + 1))
    else
        log_debug "Skipping binary $bin (not present)"
        bin_skipped=$((bin_skipped + 1))
    fi
done
log_info "Binary releases: $bin_removed removed, $bin_skipped already removed"
# Jar wrappers and custom dest directories used by binary releases
for jar_bin in ysoserial jd-gui; do
    [[ -f "$PIPX_BIN_DIR/$jar_bin" ]] && rm -f "$PIPX_BIN_DIR/$jar_bin" 2>/dev/null || true
done
# Clean up custom destination directories from BINARY_RELEASES_* entries
for _br_mod in "${REMOVE_MODULES[@]}"; do
    _br_arr="BINARY_RELEASES_${_br_mod^^}"
    declare -p "$_br_arr" &>/dev/null || continue
    declare -n _br_ref="$_br_arr"
    for _br_entry in "${_br_ref[@]}"; do
        IFS='|' read -r _br_repo _br_binary _br_pattern _br_dest <<< "$_br_entry"
        if [[ -n "${_br_dest:-}" ]] && [[ "$_br_dest" != "$PIPX_BIN_DIR" ]] && [[ -d "$_br_dest" ]]; then
            rm -rf "$_br_dest" 2>/dev/null
            log_success "Removed: $_br_dest"
        fi
    done
done
echo ""

# 8) Special tools
log_info "Removing special tools..."

# Searchsploit symlink
[[ -L "$PIPX_BIN_DIR/searchsploit" ]] && rm -f "$PIPX_BIN_DIR/searchsploit" 2>/dev/null && \
    log_success "Removed searchsploit symlink"

# Metasploit (snap or system package)
if should_remove "pwn" && command_exists msfconsole; then
    log_info "Removing Metasploit..."
    if snap_available && snap list metasploit-framework &>/dev/null 2>&1; then
        snap remove metasploit-framework >> "$LOG_FILE" 2>&1 || true
    else
        pkg_remove metasploit-framework >> "$LOG_FILE" 2>&1 || true
    fi
    log_success "Metasploit removed"
fi

# OWASP ZAP (snap)
if should_remove "web" && snap_available && snap list zaproxy &>/dev/null; then
    log_info "Removing OWASP ZAP..."
    snap remove zaproxy >> "$LOG_FILE" 2>&1
    log_success "OWASP ZAP removed"
fi


# Foundry (forge, cast, anvil, chisel — installed by blockchain module)
if should_remove "blockchain"; then
    _foundry_dir="$HOME/.foundry"
    if [[ -d "$_foundry_dir" ]]; then
        # Remove symlinks from PIPX_BIN_DIR
        for _fbin in foundryup forge cast anvil chisel; do
            [[ -L "$PIPX_BIN_DIR/$_fbin" ]] && rm -f "$PIPX_BIN_DIR/$_fbin" 2>/dev/null
        done
        rm -rf "$_foundry_dir"
        log_success "Removed Foundry ($HOME/.foundry)"
    fi
fi

# Steampipe (curl-pipe installer — installed by cloud module)
if should_remove "cloud" && command_exists steampipe; then
    log_info "Removing Steampipe..."
    rm -f /usr/local/bin/steampipe 2>/dev/null
    [[ -d "$HOME/.steampipe" ]] && rm -rf "$HOME/.steampipe"
    log_success "Steampipe removed"
fi

# uv + theHarvester wrapper (installed by recon module)
if should_remove "recon"; then
    # theHarvester wrapper script (not cleaned by git repo removal)
    [[ -f "$PIPX_BIN_DIR/theHarvester" ]] && rm -f "$PIPX_BIN_DIR/theHarvester" 2>/dev/null && \
        log_success "Removed theHarvester wrapper"
    # uv (Python package manager — installed for theHarvester)
    if command_exists uv; then
        rm -f "$HOME/.local/bin/uv" "$HOME/.local/bin/uvx" 2>/dev/null
        [[ -d "$HOME/.local/share/uv" ]] && rm -rf "$HOME/.local/share/uv"
        log_success "Removed uv"
    fi
fi

# npm tools (promptfoo)
if should_remove "llm" && command_exists npm; then
    if npm list -g promptfoo &>/dev/null; then
        log_info "Removing promptfoo (npm)..."
        npm uninstall -g promptfoo >> "$LOG_FILE" 2>&1 && \
            log_success "Removed npm: promptfoo" || \
            log_warn "Failed to remove promptfoo via npm"
    fi
fi
echo ""

# Docker images (only on full removal)
if command_exists docker && [[ ${#REMOVE_MODULES[@]} -eq ${#ALL_MODULES[@]} ]]; then
    log_info "Removing Docker images..."
    for _docker_entry in "${ALL_DOCKER_IMAGES[@]}"; do
        IFS='|' read -r _docker_img _docker_label <<< "$_docker_entry"
        if docker images "${_docker_img%%:*}" -q 2>/dev/null | grep -q .; then
            docker rmi "$_docker_img" >> "$LOG_FILE" 2>&1 && \
                log_success "Removed Docker: $_docker_label" || true
        fi
    done
fi

# Go SDK installed by ensure_go (only with --remove-deps)
if [[ "$REMOVE_DEPS" == "true" ]]; then
    _go_root=""
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        _go_root="$PREFIX/lib/go"
    else
        _go_root="/usr/local/go"
    fi
    if [[ -d "$_go_root" ]]; then
        rm -rf "$_go_root"
        log_success "Removed Go SDK from $_go_root"
    fi
fi
echo ""

# 9) Cleanup
log_info "Cleaning up..."

# Clean up empty PIPX_HOME on full removal
if [[ ${#REMOVE_MODULES[@]} -eq ${#ALL_MODULES[@]} ]] && [[ -d "$PIPX_HOME/venvs" ]]; then
    # Count remaining venvs — if none left, remove PIPX_HOME
    _remaining=$(find "$PIPX_HOME/venvs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [[ "$_remaining" -eq 0 ]]; then
        rm -rf "$PIPX_HOME"
        log_success "Removed empty PIPX_HOME ($PIPX_HOME)"
    fi
fi

# Skip pkg_cleanup if we already ran it early due to low disk space
if [[ "${_avail_mb:-999}" -ge 100 ]]; then
    if pkg_cleanup >> "$LOG_FILE" 2>&1; then
        log_success "System cleaned"
    else
        log_warn "Cleanup had errors (check log)"
    fi
else
    log_info "Package cache already cleaned (low disk space path)"
fi

# Remove version tracking file on full removal
if [[ ${#REMOVE_MODULES[@]} -eq ${#ALL_MODULES[@]} ]]; then
    [[ -f "$SCRIPT_DIR/.versions" ]] && rm -f "$SCRIPT_DIR/.versions"
    [[ -f "$SCRIPT_DIR/.versions.lock" ]] && rm -f "$SCRIPT_DIR/.versions.lock"
fi

# 10) Deep clean — purge all caches, build artifacts, stale symlinks
if [[ "$DEEP_CLEAN" == "true" ]]; then
    echo ""
    log_info "Deep clean: purging caches and build artifacts..."
    _deep_freed=0
    _user_home="$(_builder_home)"

    # --- Go caches ---
    # Go module cache (downloaded module source)
    if [[ -d "$GOPATH/pkg" ]]; then
        _sz=$(du -sm "$GOPATH/pkg" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$GOPATH/pkg"
        log_success "Removed Go module cache ($GOPATH/pkg — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi
    # Go build cache
    _go_cache="${_user_home}/.cache/go-build"
    if [[ -d "$_go_cache" ]]; then
        _sz=$(du -sm "$_go_cache" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$_go_cache"
        log_success "Removed Go build cache ($_go_cache — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi
    # Empty GOPATH dir after cache removal
    if [[ -d "$GOPATH" ]]; then
        _gopath_remaining=$(find "$GOPATH" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
        if [[ "$_gopath_remaining" -eq 0 ]]; then
            rmdir "$GOPATH" 2>/dev/null && log_success "Removed empty GOPATH ($GOPATH)"
        fi
    fi

    # --- Cargo / Rust caches ---
    # Cargo registry (crate source downloads)
    if [[ -d "$_user_home/.cargo/registry" ]]; then
        _sz=$(du -sm "$_user_home/.cargo/registry" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$_user_home/.cargo/registry"
        log_success "Removed Cargo registry cache (~/.cargo/registry — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi
    # Cargo git checkouts
    if [[ -d "$_user_home/.cargo/git" ]]; then
        _sz=$(du -sm "$_user_home/.cargo/git" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$_user_home/.cargo/git"
        log_success "Removed Cargo git cache (~/.cargo/git — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi
    # Rustup toolchains (only with --remove-deps — these are runtimes)
    if [[ "$REMOVE_DEPS" == "true" ]] && [[ -d "$_user_home/.rustup" ]]; then
        _sz=$(du -sm "$_user_home/.rustup" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$_user_home/.rustup"
        log_success "Removed Rustup toolchains (~/.rustup — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi
    # Empty .cargo dir if nothing useful remains
    if [[ -d "$_user_home/.cargo" ]]; then
        _cargo_bins=$(find "$_user_home/.cargo/bin" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
        if [[ "$_cargo_bins" -eq 0 ]]; then
            rm -rf "$_user_home/.cargo"
            log_success "Removed empty ~/.cargo"
        fi
    fi

    # --- pipx / pip caches ---
    # pipx remaining venvs (orphaned after tool removal)
    if [[ -d "$PIPX_HOME/venvs" ]]; then
        _remaining=$(find "$PIPX_HOME/venvs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
        if [[ "$_remaining" -gt 0 ]]; then
            _sz=$(du -sm "$PIPX_HOME/venvs" 2>/dev/null | cut -f1 || echo 0)
            rm -rf "$PIPX_HOME/venvs"
            log_success "Removed $_remaining orphaned pipx venvs ($PIPX_HOME/venvs — ${_sz}MB)"
            _deep_freed=$((_deep_freed + _sz))
        fi
    fi
    # pipx shared libraries
    if [[ -d "$PIPX_HOME/shared" ]]; then
        _sz=$(du -sm "$PIPX_HOME/shared" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$PIPX_HOME/shared"
        log_success "Removed pipx shared libs ($PIPX_HOME/shared — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi
    # pipx bootstrap venv
    [[ -d "$PIPX_HOME/.pipx-bootstrap" ]] && rm -rf "$PIPX_HOME/.pipx-bootstrap"
    # Remove PIPX_HOME if now empty
    if [[ -d "$PIPX_HOME" ]]; then
        _ph_remaining=$(find "$PIPX_HOME" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
        if [[ "$_ph_remaining" -eq 0 ]]; then
            rmdir "$PIPX_HOME" 2>/dev/null && log_success "Removed empty PIPX_HOME ($PIPX_HOME)"
        fi
    fi
    # pip download cache
    _pip_cache="${_user_home}/.cache/pip"
    if [[ -d "$_pip_cache" ]]; then
        _sz=$(du -sm "$_pip_cache" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$_pip_cache"
        log_success "Removed pip cache (~/.cache/pip — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi
    # pipx download cache
    _pipx_cache="${_user_home}/.cache/pipx"
    if [[ -d "$_pipx_cache" ]]; then
        _sz=$(du -sm "$_pipx_cache" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$_pipx_cache"
        log_success "Removed pipx cache (~/.cache/pipx — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi

    # --- npm cache ---
    if command_exists npm; then
        _npm_cache=$(npm config get cache 2>/dev/null || echo "$_user_home/.npm")
        if [[ -d "$_npm_cache" ]]; then
            _sz=$(du -sm "$_npm_cache" 2>/dev/null | cut -f1 || echo 0)
            npm cache clean --force >> "$LOG_FILE" 2>&1 || rm -rf "$_npm_cache"
            log_success "Removed npm cache (${_sz}MB)"
            _deep_freed=$((_deep_freed + _sz))
        fi
    fi

    # --- Gem cache ---
    _gem_cache="${_user_home}/.gem"
    if [[ -d "$_gem_cache/specs" ]] || [[ -d "$_gem_cache/ruby" ]]; then
        _sz=$(du -sm "$_gem_cache" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$_gem_cache"
        log_success "Removed gem cache (~/.gem — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi

    # --- Stale symlinks in bin dirs ---
    _stale=0
    for _bindir in "$PIPX_BIN_DIR" "$GOBIN"; do
        [[ -d "$_bindir" ]] || continue
        while IFS= read -r -d '' _link; do
            rm -f "$_link"
            _stale=$((_stale + 1))
        done < <(find "$_bindir" -maxdepth 1 -xtype l -print0 2>/dev/null)
    done
    [[ "$_stale" -gt 0 ]] && log_success "Removed $_stale stale symlinks"

    # --- Log files ---
    for _logfile in "$SCRIPT_DIR/cybersec_install.log" \
                    "$SCRIPT_DIR/tool_verification.log" \
                    "$SCRIPT_DIR/tool_update.log" \
                    "$SCRIPT_DIR/tool_removal.log"; do
        [[ -f "$_logfile" ]] && rm -f "$_logfile"
    done
    log_success "Removed log files"

    echo ""
    log_info "Deep clean complete — ~${_deep_freed}MB freed"
fi

disable_debug_trace

_print_completion_banner "$START_TIME" "$REMOVAL_FAILURES" \
    "$(if [[ "$REMOVAL_FAILURES" -gt 0 ]]; then echo "Removal finished with $REMOVAL_FAILURES failure(s)"; else echo "Removal complete!"; fi)"
log_info "Modules removed: ${REMOVE_MODULES[*]}"
[[ "$DEEP_CLEAN" == "true" ]] && log_info "Deep clean: enabled"
log_info "Log file: $LOG_FILE"
log_info "Run ./scripts/verify.sh to see remaining tools"

[[ "$REMOVAL_FAILURES" -gt 0 ]] && exit 1
exit 0
