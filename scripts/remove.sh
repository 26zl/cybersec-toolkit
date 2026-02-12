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

# Source all modules to get tool arrays (ALL_MODULES defined in lib/common.sh)
for mod in "${ALL_MODULES[@]}"; do
    source "$SCRIPT_DIR/modules/${mod}.sh"
done

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << 'EOF'
CyberSec Tools — Removal Script

Usage: sudo ./scripts/remove.sh [OPTIONS]    # Linux (requires root)
       ./scripts/remove.sh [OPTIONS]          # Termux (no root needed)

Options:
  --module <name>    Remove specific module only (can be repeated)
  --remove-deps      Also remove base dependencies (python3, openssl, git,
                       build-essential, etc.) — DANGEROUS, may break system
  --yes              Skip confirmation prompt
  -v, --verbose      Enable debug logging and system environment dump
  -h, --help         Show this help and exit

Modules: misc, networking, recon, web, crypto, pwn, reversing, forensics,
         malware, enterprise, wireless, cracking, stego, cloud, containers,
         blueteam, mobile, blockchain

By default, base dependencies are preserved.  Use --remove-deps explicitly
to include them in the removal (not recommended on production systems).
EOF
    exit 0
fi

# Parse args
REMOVE_MODULES=()
REMOVE_DEPS=false
AUTO_YES=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --module)      [[ $# -lt 2 ]] && { log_error "--module requires an argument"; exit 1; }
                       REMOVE_MODULES+=("$2"); shift 2 ;;
        --remove-deps) REMOVE_DEPS=true; shift ;;
        --yes)         AUTO_YES=true; shift ;;
        -v|--verbose)  VERBOSE=true; shift ;;
        -h|--help)     exec "$0" --help ;;
        *)             shift ;;
    esac
done

if [[ ${#REMOVE_MODULES[@]} -eq 0 ]]; then
    REMOVE_MODULES=("${ALL_MODULES[@]}")
fi

LOG_FILE="$SCRIPT_DIR/tool_removal.log"
: > "$LOG_FILE"

check_root
print_banner

if [[ "$PKG_MANAGER" == "unknown" ]]; then
    log_error "Unsupported distribution — could not detect package manager"
    log_error "Supported: apt (Debian/Ubuntu/Kali), dnf (Fedora/RHEL), pacman (Arch), zypper (openSUSE), pkg (Termux/Android)"
    exit 1
fi

if [[ "$VERBOSE" == "true" ]]; then
    log_info "Verbose mode enabled"
    log_system_environment
    enable_debug_trace
fi

# Confirmation
if [[ "$AUTO_YES" == "false" ]]; then
    echo -e "${YELLOW}${BOLD}WARNING:${NC} This will remove cybersecurity tools and their configurations."
    echo -e "${YELLOW}[!]${NC} Modules to remove: ${REMOVE_MODULES[*]}"
    if [[ "$REMOVE_DEPS" == "true" ]]; then
        echo -e "${RED}${BOLD}[!] --remove-deps: Base dependencies (python3, openssl, git, etc.) WILL be removed!${NC}"
    else
        echo -e "${GREEN}[+]${NC} Base dependencies will be preserved (use --remove-deps to include)"
    fi
    echo ""
    read -rp "Proceed with removal? (y/N) " confirm
    echo ""
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_warn "Removal cancelled by user"
        exit 0
    fi
fi

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
        # Cache installed list once
        installed_pipx=$(pipx list --short 2>/dev/null || true)
        pipx_removed=0
        pipx_skipped=0
        for tool in "${PIPX_TO_REMOVE[@]}"; do
            if echo "$installed_pipx" | grep -qi "^${tool} "; then
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
            # Remove binary from PIPX_BIN_DIR
            if [[ -f "$PIPX_BIN_DIR/$tool" ]] || [[ -L "$PIPX_BIN_DIR/$tool" ]]; then
                rm -f "$PIPX_BIN_DIR/$tool"
                log_success "Removed: $PIPX_BIN_DIR/$tool"
                pipx_removed=$((pipx_removed + 1))
            fi
            # Remove venv from PIPX_HOME
            if [[ -d "$PIPX_HOME/venvs/$tool" ]]; then
                rm -rf "$PIPX_HOME/venvs/$tool"
                log_debug "Removed venv: $PIPX_HOME/venvs/$tool"
            fi
        done
        log_info "pipx (file cleanup): $pipx_removed binaries removed"
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
    log_info "Removing ${#CARGO_TO_REMOVE[@]} Cargo tools..."
    for crate in "${CARGO_TO_REMOVE[@]}"; do
        if ! command_exists "$crate" && [[ ! -f "$HOME/.cargo/bin/$crate" ]]; then
            log_debug "Skipping cargo $crate (not installed)"
            continue
        fi
        if command_exists cargo; then
            cargo uninstall "$crate" >> "$LOG_FILE" 2>&1 && \
                log_success "Removed cargo: $crate" || true
        fi
        # Clean up binary and symlink regardless of cargo uninstall result
        [[ -f "$HOME/.cargo/bin/$crate" ]] && rm -f "$HOME/.cargo/bin/$crate"
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
for _br_mod in "${ALL_MODULES[@]}"; do
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
# Jar wrappers and directories
for jar_bin in ysoserial jd-gui; do
    [[ -f "$PIPX_BIN_DIR/$jar_bin" ]] && rm -f "$PIPX_BIN_DIR/$jar_bin" 2>/dev/null || true
done
rm -rf "$GITHUB_TOOL_DIR/cybersec-jars" 2>/dev/null
rm -rf "$GITHUB_TOOL_DIR/jadx" 2>/dev/null
rm -rf "$GITHUB_TOOL_DIR/dex2jar" 2>/dev/null
echo ""

# 8) Special tools
log_info "Removing special tools..."

# Searchsploit symlink
[[ -L "$PIPX_BIN_DIR/searchsploit" ]] && rm -f "$PIPX_BIN_DIR/searchsploit" 2>/dev/null && \
    log_success "Removed searchsploit symlink"

# Metasploit
if should_remove "pwn" && command_exists msfconsole; then
    log_info "Removing Metasploit..."
    pkg_remove metasploit-framework >> "$LOG_FILE" 2>&1 || true
    log_success "Metasploit removed"
fi

# OWASP ZAP (snap)
if should_remove "web" && snap_available && snap list zaproxy &>/dev/null; then
    log_info "Removing OWASP ZAP..."
    snap remove zaproxy >> "$LOG_FILE" 2>&1
    log_success "OWASP ZAP removed"
fi

# solc (snap — installed by blockchain module)
if should_remove "blockchain" && snap_available && snap list solc &>/dev/null; then
    log_info "Removing solc..."
    snap remove solc >> "$LOG_FILE" 2>&1
    log_success "solc removed"
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

# Burp Suite installer cleanup (deterministic path only)
if [[ -d "$GITHUB_TOOL_DIR/burpsuite-installer" ]]; then
    rm -rf "$GITHUB_TOOL_DIR/burpsuite-installer"
    log_success "Removed Burp Suite installer directory"
fi

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
    local_go_root=""
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        local_go_root="$PREFIX/lib/go"
    else
        local_go_root="/usr/local/go"
    fi
    if [[ -d "$local_go_root" ]]; then
        rm -rf "$local_go_root"
        log_success "Removed Go SDK from $local_go_root"
    fi
fi
echo ""

# 9) Cleanup
log_info "Cleaning up..."

# Clean up empty PIPX_HOME on full removal
if [[ ${#REMOVE_MODULES[@]} -eq ${#ALL_MODULES[@]} ]] && [[ -d "$PIPX_HOME/venvs" ]]; then
    # Count remaining venvs — if none left, remove PIPX_HOME
    local_remaining=$(find "$PIPX_HOME/venvs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [[ "$local_remaining" -eq 0 ]]; then
        rm -rf "$PIPX_HOME"
        log_success "Removed empty PIPX_HOME ($PIPX_HOME)"
    fi
fi

if pkg_cleanup >> "$LOG_FILE" 2>&1; then
    log_success "System cleaned"
else
    log_warn "Cleanup had errors (check log)"
fi

# Remove version tracking file on full removal
if [[ ${#REMOVE_MODULES[@]} -eq ${#ALL_MODULES[@]} ]]; then
    [[ -f "$SCRIPT_DIR/.versions" ]] && rm -f "$SCRIPT_DIR/.versions"
fi

disable_debug_trace

echo ""
echo -e "${GREEN}${BOLD}=============================================${NC}"
log_success "Removal complete!"
echo -e "${GREEN}${BOLD}=============================================${NC}"
log_info "Modules removed: ${REMOVE_MODULES[*]}"
log_info "Log file: $LOG_FILE"
