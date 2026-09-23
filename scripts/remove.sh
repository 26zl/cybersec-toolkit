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

Only tools that .versions records as installed by this toolkit are removed;
tools you installed yourself stay in place.
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

export VERBOSE

if [[ ${#REMOVE_MODULES[@]} -eq 0 ]]; then
    REMOVE_MODULES=("${ALL_MODULES[@]}")
else
    # Validate each --module argument is a known module (prevent path traversal / typos)
    _validate_module_names "use --help to see available modules" "${REMOVE_MODULES[@]}"
fi

_init_log_file "$SCRIPT_DIR/tool_removal.log"

check_root
print_banner

# When disk space is critically low, free package cache FIRST so that
# subsequent pkg_remove calls have enough room for dpkg temp files.
_avail_mb=$(_avail_disk_mb)
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
            chmod 600 "$LOG_FILE" 2>/dev/null || true
            log_info "Disk space freed — logging to $LOG_FILE"
        fi
    fi
fi

_check_pkg_manager
_setup_verbose

# Provenance: with an install record present, only what it lists as installed by
# this toolkit is removed. Modules that were never installed and the user's own
# same-named tools under /opt or /usr/local/bin are left alone.
_VERSIONS_FILE="${VERSION_FILE:-$SCRIPT_DIR/.versions}"
declare -A _TOOLKIT_INSTALLED=()
if [[ -f "$_VERSIONS_FILE" ]]; then
    while IFS='|' read -r _vt _ _vv _; do
        [[ -z "$_vt" || "$_vt" == \#* || "$_vv" == "existing" ]] && continue
        _TOOLKIT_INSTALLED["$_vt"]=1
    done < "$_VERSIONS_FILE"
else
    log_warn "No install record at $_VERSIONS_FILE — every listed tool found on this system will be removed, including copies this toolkit did not install"
fi

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

# _removable NAME — this toolkit installed NAME, or there is no install record to
# tell (installs that predate .versions).
_removable() {
    [[ ! -f "$_VERSIONS_FILE" || -n "${_TOOLKIT_INSTALLED[$1]:-}" ]]
}

# filter_untracked ARRAY LABEL — drop entries this toolkit did not install.
filter_untracked() {
    local -n __fu_arr=$1
    local label="$2" _fu_item _fu_skipped=0
    local -a _fu_kept=()
    for _fu_item in "${__fu_arr[@]}"; do
        if _removable "$_fu_item"; then
            _fu_kept+=("$_fu_item")
        else
            _fu_skipped=$((_fu_skipped + 1))
        fi
    done
    [[ "$_fu_skipped" -gt 0 ]] && log_info "Skipping $_fu_skipped ${label} not installed by this toolkit"
    if [[ ${#_fu_kept[@]} -gt 0 ]]; then
        __fu_arr=("${_fu_kept[@]}")
    else
        __fu_arr=()
    fi
}

# Build aggregate removal lists from module arrays
PKGS_TO_REMOVE=()
PIPX_TO_REMOVE=()
GO_BINS_TO_REMOVE=()
GIT_NAMES_TO_REMOVE=()
GEMS_TO_REMOVE=()
CARGO_TO_REMOVE=()
NPM_TO_REMOVE=()

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
    _append_module_array GIT_NAMES_TO_REMOVE "${_pfx}_C2_GIT_NAMES"
    _append_module_array GIT_NAMES_TO_REMOVE "${_pfx}_BUILD_NAMES"
    _append_module_array GEMS_TO_REMOVE      "${_pfx}_GEMS"
    _append_module_array CARGO_TO_REMOVE     "${_pfx}_CARGO"
    _append_module_array NPM_TO_REMOVE       "${_pfx}_NPM"
done

# Never remove a tool the installer found already on the system. PKGS_TO_REMOVE is
# filtered further down, after fixup_package_names (.versions stores the
# distro-specific name).
filter_preexisting PIPX_TO_REMOVE      "pipx tools"
filter_preexisting GO_BINS_TO_REMOVE   "Go binaries"
filter_preexisting GIT_NAMES_TO_REMOVE "Git/source trees"
filter_preexisting GEMS_TO_REMOVE      "gems"
filter_preexisting CARGO_TO_REMOVE     "cargo crates"
filter_preexisting NPM_TO_REMOVE       "npm packages"
filter_untracked PIPX_TO_REMOVE        "pipx tools"
filter_untracked GO_BINS_TO_REMOVE     "Go binaries"
filter_untracked GIT_NAMES_TO_REMOVE   "Git/source trees"
filter_untracked GEMS_TO_REMOVE        "gems"
filter_untracked CARGO_TO_REMOVE       "cargo crates"
filter_untracked NPM_TO_REMOVE         "npm packages"

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
            if echo "$installed_pipx" | awk -v t="$_norm" 'tolower($1)==tolower(t){f=1} END{exit !f}'; then
                if pipx_remove "$tool" >> "$LOG_FILE" 2>&1; then
                    log_success "Removed pipx: $tool"
                    pipx_removed=$((pipx_removed + 1))
                else
                    log_warn "Failed to remove pipx: $tool"
                    REMOVAL_FAILURES=$((REMOVAL_FAILURES + 1))
                fi
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
    # Query and uninstall in the builder's gem store (install runs as $SUDO_USER),
    # not root's — otherwise nothing is detected or removed under sudo.
    installed_gems=$(_as_builder "$(_builder_cmd gem) list --no-details" 2>/dev/null || true)
    gems_removed=0
    gems_skipped=0
    for gem_name in "${GEMS_TO_REMOVE[@]}"; do
        if echo "$installed_gems" | awk -v t="$gem_name" '$1==t{f=1} END{exit !f}'; then
            if _as_builder "$(_builder_cmd gem) uninstall -x --force '$(_escape_single_quoted "$gem_name")'" >> "$LOG_FILE" 2>&1; then
                gems_removed=$((gems_removed + 1))
            else
                log_warn "Failed to remove gem: $gem_name"
                REMOVAL_FAILURES=$((REMOVAL_FAILURES + 1))
            fi
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

# 2b) npm packages — must run BEFORE system packages remove nodejs
if [[ ${#NPM_TO_REMOVE[@]} -gt 0 ]]; then
    remove_npm_packages "${NPM_TO_REMOVE[@]}"
fi
echo ""

# _CARGO_BIN_NAMES (crate→binary exceptions) is defined in lib/installers.sh.

# 3) Cargo tools — must run BEFORE system packages (cargo is from rustup, not apt, but be safe)
if [[ ${#CARGO_TO_REMOVE[@]} -gt 0 ]]; then
    _cargo_home="$(_builder_home)/.cargo/bin"
    # Crates were installed into the builder's CARGO_HOME, which root's cargo does not see.
    _cargo_cmd=$(_builder_cmd cargo 2>/dev/null) || _cargo_cmd=""
    log_info "Removing ${#CARGO_TO_REMOVE[@]} Cargo tools..."
    for crate in "${CARGO_TO_REMOVE[@]}"; do
        # Probe the installed BINARY name (which may differ from the crate name)
        # so the install-status guard doesn't skip e.g. yara-x-cli (binary 'yr').
        _cargo_bin="${_CARGO_BIN_NAMES[$crate]:-$crate}"
        if ! command_exists "$_cargo_bin" && [[ ! -f "$_cargo_home/$_cargo_bin" ]]; then
            log_debug "Skipping cargo $crate (not installed)"
            continue
        fi
        if [[ -n "$_cargo_cmd" ]]; then
            # cargo uninstalls by CRATE name, not binary name.
            if _as_builder "$_cargo_cmd uninstall '$(_escape_single_quoted "$crate")'" >> "$LOG_FILE" 2>&1; then
                log_success "Removed cargo: $crate"
            else
                log_warn "Failed to remove cargo: $crate"
                REMOVAL_FAILURES=$((REMOVAL_FAILURES + 1))
            fi
        fi
        # Clean up binary and symlink regardless of cargo uninstall result
        [[ -f "$_cargo_home/$_cargo_bin" ]] && rm -f "$_cargo_home/$_cargo_bin"
        [[ -L "$PIPX_BIN_DIR/$_cargo_bin" ]] && rm -f "$PIPX_BIN_DIR/$_cargo_bin"
    done
fi
echo ""

# 4) System packages — AFTER tools that need runtime commands
if [[ ${#PKGS_TO_REMOVE[@]} -gt 0 ]]; then
    # Translate per package so a row under either the Debian name (install.sh --tool)
    # or the distro-specific name (batch installs) counts as installed by this toolkit.
    _pkgs_fixed=()
    _pkgs_untracked=0
    for _pkg_generic in "${PKGS_TO_REMOVE[@]}"; do
        _pkg_fx=("$_pkg_generic")
        fixup_package_names _pkg_fx
        for _pkg_name in "${_pkg_fx[@]}"; do
            if _removable "$_pkg_generic" || _removable "$_pkg_name"; then
                _pkgs_fixed+=("$_pkg_name")
            else
                _pkgs_untracked=$((_pkgs_untracked + 1))
            fi
        done
    done
    [[ "$_pkgs_untracked" -gt 0 ]] && log_info "Skipping $_pkgs_untracked system packages not installed by this toolkit"
    if [[ ${#_pkgs_fixed[@]} -gt 0 ]]; then
        PKGS_TO_REMOVE=("${_pkgs_fixed[@]}")
    else
        PKGS_TO_REMOVE=()
    fi
    # Then drop the ones that were already installed before this toolkit ran
    filter_preexisting PKGS_TO_REMOVE "system packages"

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

# _remove_repo_links NAME REPO — drop the PATH entry setup_git_repo made for a
# cloned repo: a symlink into REPO or a wrapper script that execs a file in it.
_remove_repo_links() {
    local lower="${1,,}" link
    for link in "$PIPX_BIN_DIR/$1" "$PIPX_BIN_DIR/$lower" "$PIPX_BIN_DIR/${lower//-/_}"; do
        if [[ -L "$link" ]]; then
            [[ "$(readlink "$link")" == "$2/"* ]] && rm -f "$link"
        elif [[ -f "$link" && "$(head -c 2 "$link" 2>/dev/null)" == "#!" ]] \
            && grep -qF -e "$2/" -e "$2\"" "$link" 2>/dev/null; then
            rm -f "$link"
        fi
    done
}

# 6) GitHub repos (build-from-source trees are listed here too; they build in place)
if [[ ${#GIT_NAMES_TO_REMOVE[@]} -gt 0 ]]; then
    git_removed=0
    git_skipped=0
    for name in "${GIT_NAMES_TO_REMOVE[@]}"; do
        repo_path="$GITHUB_TOOL_DIR/$name"
        if [[ -d "$repo_path" ]]; then
            rm -rf "$repo_path"
            _remove_repo_links "$name" "$repo_path"
            log_success "Removed: $repo_path"
            git_removed=$((git_removed + 1))
        else
            log_debug "Skipping git repo $name (not present)"
            git_skipped=$((git_skipped + 1))
        fi
    done
    log_info "Git repos: $git_removed removed, $git_skipped already removed"
fi

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
    for _br_arr in "BINARY_RELEASES_${_br_mod^^}" "BINARY_RELEASES_${_br_mod^^}_C2"; do
        declare -p "$_br_arr" &>/dev/null || continue
        _extract_binary_names "$_br_arr"
    done
done
filter_preexisting BINARY_TOOLS "binary releases"
filter_untracked BINARY_TOOLS "binary releases"
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
    # Clean up the version sidecar written by download_github_release (default dest).
    rm -f "$PIPX_BIN_DIR/.$bin.vtag" 2>/dev/null || true
done
log_info "Binary releases: $bin_removed removed, $bin_skipped already removed"
# A custom dest dir survives when a module that is not being removed still uses it
# (cybersec-jars holds ysoserial from web and jd-gui from reversing) or when any
# release in it was not installed by this toolkit.
declare -A _KEEP_DESTS=()
for _sv_mod in "${ALL_MODULES[@]}"; do
    for _sv_arr in "BINARY_RELEASES_${_sv_mod^^}" "BINARY_RELEASES_${_sv_mod^^}_C2"; do
        declare -p "$_sv_arr" &>/dev/null || continue
        declare -n _sv_ref="$_sv_arr"
        for _sv_entry in "${_sv_ref[@]}"; do
            IFS='|' read -r _ _sv_binary _ _sv_dest _ <<< "$_sv_entry"
            [[ -n "${_sv_dest:-}" ]] || continue
            if ! should_remove "$_sv_mod" || ! _removable "$_sv_binary"; then
                _KEEP_DESTS["$_sv_dest"]=1
            fi
        done
    done
done

# Clean up custom destination directories from BINARY_RELEASES_* entries
for _br_mod in "${REMOVE_MODULES[@]}"; do
    for _br_arr in "BINARY_RELEASES_${_br_mod^^}" "BINARY_RELEASES_${_br_mod^^}_C2"; do
        declare -p "$_br_arr" &>/dev/null || continue
        declare -n _br_ref="$_br_arr"
        for _br_entry in "${_br_ref[@]}"; do
            IFS='|' read -r _br_repo _br_binary _br_pattern _br_dest _ <<< "$_br_entry"
            if [[ -n "${_br_dest:-}" ]] && [[ "$_br_dest" != "$PIPX_BIN_DIR" ]] && [[ -d "$_br_dest" ]]; then
                if [[ -n "${_KEEP_DESTS[$_br_dest]:-}" ]]; then
                    log_info "Keeping $_br_dest — in use by another module or not installed by this toolkit"
                else
                    rm -rf "$_br_dest" 2>/dev/null
                    log_success "Removed: $_br_dest"
                fi
            fi
        done
    done
done
echo ""

# 8) Special tools
log_info "Removing special tools..."

# Searchsploit symlink into the toolkit's exploitdb clone (pwn module)
if should_remove "pwn" && _removable exploitdb && [[ -L "$PIPX_BIN_DIR/searchsploit" ]] \
    && [[ "$(readlink "$PIPX_BIN_DIR/searchsploit")" == "$GITHUB_TOOL_DIR/exploitdb/"* ]]; then
    rm -f "$PIPX_BIN_DIR/searchsploit" 2>/dev/null && log_success "Removed searchsploit symlink"
fi

# Special tools are removed only when this toolkit recorded installing them and
# they were not present beforehand, so a user's own copy is never uninstalled.
_toolkit_installed() { _version_known "$1" && ! _is_preexisting "$1"; }

# Metasploit (snap or system package)
if should_remove "pwn" && command_exists msfconsole && _toolkit_installed metasploit; then
    log_info "Removing Metasploit..."
    remove_snap_tool metasploit
    log_success "Metasploit removed"
fi

# OWASP ZAP (snap)
if should_remove "web" && snap_available && snap list zaproxy &>/dev/null && _toolkit_installed zaproxy; then
    log_info "Removing OWASP ZAP..."
    remove_snap_tool zaproxy
    log_success "OWASP ZAP removed"
fi

# Foundry (forge, cast, anvil, chisel — installed by blockchain module)
if should_remove "blockchain" && _toolkit_installed foundry; then
    remove_special_tool foundry && log_success "Removed Foundry"
fi

# Steampipe (curl-pipe installer — installed by cloud module)
if should_remove "cloud" && command_exists steampipe && _toolkit_installed steampipe; then
    log_info "Removing Steampipe..."
    remove_special_tool steampipe && log_success "Steampipe removed"
fi

# NetExec (pipx from git, tracked as nxc — installed outside ENTERPRISE_PIPX, modules/enterprise.sh)
if should_remove "enterprise" && command_exists pipx && _toolkit_installed nxc; then
    if pipx list --short 2>/dev/null | grep -qi '^netexec '; then
        log_info "Removing NetExec (pipx)..."
        if pipx_remove netexec >> "$LOG_FILE" 2>&1; then
            log_success "Removed pipx: netexec"
        else
            log_warn "Failed to remove pipx: netexec"
            REMOVAL_FAILURES=$((REMOVAL_FAILURES + 1))
        fi
    fi
fi

# ctf-crypto venv (Python libraries pipx cannot install, modules/crypto.sh)
if should_remove "crypto"; then
    _crypto_venv="${CYBERSEC_MCP_VENVS_DIR:-$(_builder_home)/.ctf-venvs}/crypto"
    if [[ -d "$_crypto_venv" ]]; then
        # A venv the user built themselves was only added to, never installed by
        # us — removing it would take their other packages with it.
        if _is_preexisting ctf-crypto-venv || ! _removable ctf-crypto-venv; then
            log_info "Preserving venv not installed by this toolkit: ctf-crypto-venv"
        else
            log_info "Removing ctf-crypto venv..."
            remove_special_tool ctf-crypto-venv && log_success "Removed venv: ctf-crypto-venv"
        fi
    fi
fi

# patator (dedicated venv — installed outside CRACKING_PIPX, modules/cracking.sh)
if should_remove "cracking" && _removable patator; then
    if [[ -d "$GITHUB_TOOL_DIR/patator" ]]; then
        log_info "Removing patator (venv)..."
        remove_special_tool patator && log_success "Removed venv: patator"
    fi
    # Installs predating the venv switch put patator under pipx — clean those too
    if command_exists pipx && pipx list --short 2>/dev/null | grep -qi '^patator '; then
        log_info "Removing patator (pipx)..."
        if pipx_remove patator >> "$LOG_FILE" 2>&1; then
            log_success "Removed pipx: patator"
        else
            log_warn "Failed to remove pipx: patator"
            REMOVAL_FAILURES=$((REMOVAL_FAILURES + 1))
        fi
    fi
fi

# uv + theHarvester wrapper (installed by recon module)
if should_remove "recon"; then
    if _removable theHarvester && [[ -f "$PIPX_BIN_DIR/theHarvester" ]]; then
        rm -f "$PIPX_BIN_DIR/theHarvester" 2>/dev/null && log_success "Removed theHarvester wrapper"
    fi
    # uv (installed for theHarvester) is also the MCP server's runtime, so only remove it under --remove-deps, and via _builder_home() (not $HOME, which is /root under sudo) to target the real user's install.
    if [[ "$REMOVE_DEPS" == "true" ]]; then
        _uv_home="$(_builder_home)"
        _uv_removed=false
        for _uv_bin in "$_uv_home/.local/bin/uv" "$_uv_home/.local/bin/uvx"; do
            if [[ -e "$_uv_bin" || -L "$_uv_bin" ]] && rm -f "$_uv_bin" 2>/dev/null; then
                _uv_removed=true
            fi
        done
        if [[ -d "$_uv_home/.local/share/uv" ]] && rm -rf "$_uv_home/.local/share/uv" 2>/dev/null; then
            _uv_removed=true
        fi
        [[ "$_uv_removed" == "true" ]] && log_success "Removed uv"
    fi
fi

# npm tools (promptfoo)
if should_remove "llm" && command_exists npm && _toolkit_installed promptfoo; then
    if npm list -g promptfoo &>/dev/null; then
        log_info "Removing promptfoo (npm)..."
        if npm uninstall -g promptfoo >> "$LOG_FILE" 2>&1; then
            log_success "Removed npm: promptfoo"
        else
            log_warn "Failed to remove promptfoo via npm"
            REMOVAL_FAILURES=$((REMOVAL_FAILURES + 1))
        fi
    fi
fi
echo ""

# Docker images (only on full removal)
if command_exists docker && [[ ${#REMOVE_MODULES[@]} -eq ${#ALL_MODULES[@]} ]]; then
    log_info "Removing Docker images..."
    for _docker_entry in "${ALL_DOCKER_IMAGES[@]}"; do
        IFS='|' read -r _docker_img _docker_label <<< "$_docker_entry"
        _removable "$_docker_label" || continue
        if docker images "${_docker_img%%:*}" -q 2>/dev/null | grep -q .; then
            docker rmi "$_docker_img" >> "$LOG_FILE" 2>&1 && \
                log_success "Removed Docker: $_docker_label" || true
        fi
    done
fi

# Go SDK installed by ensure_go (only with --remove-deps). On Termux ensure_go never
# installs one; $PREFIX/lib/go there belongs to the golang package.
if [[ "$REMOVE_DEPS" == "true" ]] && [[ "$PKG_MANAGER" != "pkg" ]]; then
    _go_root="/usr/local/go"
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

# Remove the install record on a clean full removal; after a failure it is the only
# thing that tells a retry which tools are ours.
if [[ ${#REMOVE_MODULES[@]} -eq ${#ALL_MODULES[@]} ]]; then
    if [[ "$REMOVAL_FAILURES" -eq 0 ]]; then
        [[ -f "$_VERSIONS_FILE" ]] && rm -f "$_VERSIONS_FILE"
        [[ -f "$_VERSIONS_FILE.lock" ]] && rm -f "$_VERSIONS_FILE.lock"
    else
        log_warn "Keeping $_VERSIONS_FILE because some removals failed — re-run to retry"
    fi
fi

# 10) Deep clean — purge all caches, build artifacts, stale symlinks
if [[ "$DEEP_CLEAN" == "true" ]]; then
    echo ""
    log_info "Deep clean: purging caches and build artifacts..."
    _deep_freed=0
    _user_home="$(_builder_home)"

    # Go caches
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

    # Cargo / Rust caches
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
    # Drop ~/.cargo only when no binaries are left, and never its config.toml,
    # credentials.toml or env: rmdir fails while any of those remain.
    if [[ -d "$_user_home/.cargo" ]]; then
        _cargo_bins=$(find "$_user_home/.cargo/bin" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
        if [[ "$_cargo_bins" -eq 0 ]]; then
            rmdir "$_user_home/.cargo/bin" 2>/dev/null || true
            rm -rf "$_user_home/.cargo/.crates.toml" "$_user_home/.cargo/.crates2.json" \
                "$_user_home/.cargo/.package-cache" "$_user_home/.cargo/.package-cache-mutate" \
                "$_user_home/.cargo/.global-cache" 2>/dev/null || true
            rmdir "$_user_home/.cargo" 2>/dev/null && log_success "Removed empty ~/.cargo"
        fi
    fi

    # pipx / pip caches
    # pipx remaining venvs (orphaned after tool removal). On Linux PIPX_HOME is
    # /opt/pipx (toolkit-owned), but on Termux it is the user's own pipx home, so
    # wiping the whole venvs dir there would delete the user's unrelated tools.
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        log_info "Skipping pipx venvs purge on Termux (shared user pipx home)"
    elif [[ -d "$PIPX_HOME/venvs" ]]; then
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

    # npm cache
    if command_exists npm; then
        _npm_cache=$(npm config get cache 2>/dev/null || echo "$_user_home/.npm")
        if [[ -d "$_npm_cache" ]]; then
            _sz=$(du -sm "$_npm_cache" 2>/dev/null | cut -f1 || echo 0)
            npm cache clean --force >> "$LOG_FILE" 2>&1 || rm -rf "$_npm_cache"
            log_success "Removed npm cache (${_sz}MB)"
            _deep_freed=$((_deep_freed + _sz))
        fi
    fi

    # Gem spec cache only: the rest of ~/.gem is user-installed gems and RubyGems credentials.
    _gem_cache="${_user_home}/.gem/specs"
    if [[ -d "$_gem_cache" ]]; then
        _sz=$(du -sm "$_gem_cache" 2>/dev/null | cut -f1 || echo 0)
        rm -rf "$_gem_cache"
        log_success "Removed gem cache (~/.gem/specs — ${_sz}MB)"
        _deep_freed=$((_deep_freed + _sz))
    fi

    # Stale symlinks in bin dirs
    _stale=0
    for _bindir in "$PIPX_BIN_DIR" "$GOBIN"; do
        [[ -d "$_bindir" ]] || continue
        while IFS= read -r -d '' _link; do
            rm -f "$_link"
            _stale=$((_stale + 1))
        done < <(find "$_bindir" -maxdepth 1 -xtype l -print0 2>/dev/null)
    done
    [[ "$_stale" -gt 0 ]] && log_success "Removed $_stale stale symlinks"

    # Log files
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
