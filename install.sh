#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# CyberSec Tools Installer — Modular, Profile-Based, Production-Grade
#
# The most comprehensive cybersecurity tool installer for Linux.
# Supports Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE.
#
# Usage:
#   sudo ./install.sh                        # Full install (default)
#   sudo ./install.sh --profile ctf          # Install CTF tools only
#   sudo ./install.sh --profile redteam      # Red team tools
#   sudo ./install.sh --module web --module enterprise  # Specific modules
#   sudo ./install.sh --upgrade-system        # Also upgrade system packages
#   sudo ./install.sh --list-profiles        # Show available profiles
#   sudo ./install.sh --list-modules         # Show available modules
#   sudo ./install.sh --dry-run              # Show what would install
#   sudo ./install.sh --skip-heavy           # Skip large packages
#   sudo ./install.sh --enable-docker        # Pull Docker images for C2/etc

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/installers.sh"
source "$SCRIPT_DIR/lib/shared.sh"

# ALL_MODULES is defined in lib/common.sh

# Argument parsing
PROFILE=""
SELECTED_MODULES=()
SELECTED_TOOLS=()
DRY_RUN=false
UPGRADE_SYSTEM=false
SKIP_HEAVY="${SKIP_HEAVY:-false}"
SKIP_PIPX="${SKIP_PIPX:-false}"
SKIP_GO="${SKIP_GO:-false}"
SKIP_CARGO="${SKIP_CARGO:-false}"
SKIP_GEMS="${SKIP_GEMS:-false}"
SKIP_GIT="${SKIP_GIT:-false}"
SKIP_BINARY="${SKIP_BINARY:-false}"
SKIP_SOURCE="${SKIP_SOURCE:-false}"
ENABLE_DOCKER="${ENABLE_DOCKER:-false}"
INCLUDE_C2="${INCLUDE_C2:-false}"
REQUIRE_CHECKSUMS="${REQUIRE_CHECKSUMS:-false}"
# Track which flags were explicitly set on the CLI (for profile override logic)
_CLI_SET_SKIP_HEAVY=false
_CLI_SET_ENABLE_DOCKER=false
_CLI_SET_INCLUDE_C2=false
FAST_MODE="${FAST_MODE:-false}"
ROLLBACK_TARGET=""

usage() {
    # Build profile and module lists dynamically from filesystem / registry
    local _profiles=""
    for _pf in "$SCRIPT_DIR"/profiles/*.conf; do
        [[ -f "$_pf" ]] || continue
        local _pn; _pn=$(basename "$_pf" .conf)
        [[ -n "$_profiles" ]] && _profiles+=", "
        _profiles+="$_pn"
    done
    local _modules="${ALL_MODULES[*]}"
    _modules="${_modules// /, }"

    cat << EOF
CyberSec Tools Installer — Production-Grade Security Toolkit

Usage: sudo ./install.sh [OPTIONS]        # Linux (requires root)
       ./install.sh [OPTIONS]              # Termux (no root needed)

Options:
  --profile <name>     Install a predefined tool profile:
                         ${_profiles}
  --module <name>      Install specific module(s). Can be repeated.
                         Modules: ${_modules}
  --tool <name>        Install a single tool by name. Can be repeated.
                         Searches all modules for a matching package,
                         pipx tool, Go binary, cargo crate, gem, or repo.
                         Note: --skip-* flags are ignored (forces install).
  --upgrade-system     Upgrade all system packages before installing
                         (apt upgrade / dnf upgrade / pacman -Syu)
  --skip-heavy         Skip large/slow packages defined in HEAVY_PACKAGES arrays
  --skip-pipx          Skip all pipx (Python) tool installs
  --skip-go            Skip all Go tool installs
  --skip-cargo         Skip all Cargo (Rust) tool installs
  --skip-gems          Skip all Ruby gem installs
  --skip-git           Skip all git clone installs
  --skip-binary        Skip all binary release downloads
  --skip-source        Skip build-from-source, snap, npm, and curl-pipe installs
  --fast               Skip checksum verification for faster binary downloads
                         (mutually exclusive with --require-checksums)
  --require-checksums  Fail if a binary release has no checksum file
  --enable-docker      Pull Docker images (C2 frameworks, IR platforms, MobSF, etc.)
  --include-c2         Enable C2 frameworks (requires --enable-docker)
  --dry-run            Show what would be installed without installing
  -j, --parallel <N>   Number of parallel install jobs (default: 4, 1=sequential)
  -v, --verbose        Enable debug logging and system environment dump
  --list-profiles      List available profiles and exit
  --list-modules       List available modules and exit
  --list-sessions      List install sessions and exit
  --rollback <id|last> Rollback tools installed in a session
  --version            Show installer version and exit
  -h, --help           Show this help and exit

All runtimes (Python, Go, Ruby, Rust, Java) and dev libraries are
installed automatically. Only Docker requires manual installation.

Environment variables:
  GITHUB_TOOL_DIR      Where to clone GitHub repos (default: /opt)
  GITHUB_TOKEN         GitHub personal access token for API requests
                         (avoids rate limits on binary downloads)
  GO_MIN_VERSION       Minimum Go version before auto-upgrade (default: 1.21)
  VERBOSE              Enable verbose/debug output (default: false)
  PARALLEL_JOBS        Number of parallel install jobs (default: 4)

Examples (Linux):
  sudo ./install.sh                              # Full install
  sudo ./install.sh --profile ctf                # CTF tools
  sudo ./install.sh --module web --module recon   # Web + recon only
  sudo ./install.sh --profile redteam --enable-docker  # Red team + Docker C2
  sudo ./install.sh --upgrade-system             # Full install + system upgrade
  sudo ./install.sh --tool sqlmap --tool nmap     # Install individual tools

Examples (Termux/Android — no sudo):
  ./install.sh --profile lightweight             # Recommended for Termux
  ./install.sh --module recon --module web        # Specific modules
EOF
    exit 0
}

_installation_failed() {
    [[ "${TOTAL_TOOL_FAILURES:-0}" -gt 0 || "${TOTAL_MODULE_FAILURES:-0}" -gt 0 ]]
}

list_profiles() {
    echo "Available profiles:"
    echo ""
    for f in "$SCRIPT_DIR"/profiles/*.conf; do
        local name
        name=$(basename "$f" .conf)
        local desc
        desc=$(head -1 "$f" | sed 's/^# Profile: //')
        printf "  %-16s %s\n" "$name" "$desc"
    done
    echo ""
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        echo "Usage: ./install.sh --profile <name>"
    else
        echo "Usage: sudo ./install.sh --profile <name>"
    fi
    exit 0
}

list_modules() {
    echo "Available modules:"
    echo ""
    for mod in "${ALL_MODULES[@]}"; do
        printf "  %-16s %s\n" "$mod" "${MODULE_DESCRIPTIONS[$mod]:-}"
    done
    echo ""
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        echo "Usage: ./install.sh --module <name> [--module <name> ...]"
    else
        echo "Usage: sudo ./install.sh --module <name> [--module <name> ...]"
    fi
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)         usage ;;
        --profile)         [[ $# -lt 2 ]] && { log_error "--profile requires an argument"; exit 1; }
                           PROFILE="$2"; shift 2 ;;
        --module)          [[ $# -lt 2 ]] && { log_error "--module requires an argument"; exit 1; }
                           SELECTED_MODULES+=("$2"); shift 2 ;;
        --tool)            [[ $# -lt 2 ]] && { log_error "--tool requires a name"; exit 1; }
                           SELECTED_TOOLS+=("$2"); shift 2 ;;
        --upgrade-system)  UPGRADE_SYSTEM=true; shift ;;
        --skip-heavy)      SKIP_HEAVY=true; _CLI_SET_SKIP_HEAVY=true; shift ;;
        --skip-pipx)       SKIP_PIPX=true; shift ;;
        --skip-go)         SKIP_GO=true; shift ;;
        --skip-cargo)      SKIP_CARGO=true; shift ;;
        --skip-gems)       SKIP_GEMS=true; shift ;;
        --skip-git)        SKIP_GIT=true; shift ;;
        --skip-binary)     SKIP_BINARY=true; shift ;;
        --skip-source)     SKIP_SOURCE=true; shift ;;
        --fast)            FAST_MODE=true; shift ;;
        --require-checksums) REQUIRE_CHECKSUMS=true; shift ;;
        --enable-docker)   ENABLE_DOCKER=true; _CLI_SET_ENABLE_DOCKER=true; shift ;;
        --include-c2)      INCLUDE_C2=true; _CLI_SET_INCLUDE_C2=true; shift ;;
        --dry-run)         DRY_RUN=true; shift ;;
        -j|--parallel)     [[ $# -lt 2 ]] && { log_error "-j/--parallel requires a number"; exit 1; }
                           PARALLEL_JOBS="$2"
                           # Validation handled by lib/common.sh on next source
                           if [[ ! "$PARALLEL_JOBS" =~ ^[0-9]+$ ]] || [[ "$PARALLEL_JOBS" -lt 1 ]]; then
                               PARALLEL_JOBS=4
                           elif [[ "$PARALLEL_JOBS" -gt 16 ]]; then
                               PARALLEL_JOBS=16
                           fi
                           shift 2 ;;
        -v|--verbose)      VERBOSE=true; shift ;;
        --list-profiles)   list_profiles ;;
        --list-modules)    list_modules ;;
        --list-sessions)   _list_sessions; exit 0 ;;
        --rollback)        [[ $# -lt 2 ]] && { log_error "--rollback requires a session ID or 'last'"; exit 1; }
                           ROLLBACK_TARGET="$2"; shift 2 ;;
        --version)         echo "cybersec-toolkit ${INSTALLER_VERSION:-unknown}"; exit 0 ;;
        *)                 log_error "Unknown option: $1"; usage ;;
    esac
done

# --fast and --require-checksums are mutually exclusive
if [[ "$FAST_MODE" == "true" && "$REQUIRE_CHECKSUMS" == "true" ]]; then
    log_error "--fast and --require-checksums are mutually exclusive"
    exit 1
fi

# Single-tool install (--tool)
# shellcheck disable=SC2034  # Arrays read via nameref
install_single_tool() {
    local tool="$1"

    # Helper: check if a named array contains a value
    _arr_has() {
        local arr_name=$1 val=$2
        declare -p "$arr_name" &>/dev/null || return 1
        local -n _ref="$arr_name"
        [[ ${#_ref[@]} -eq 0 ]] && return 1
        for item in "${_ref[@]}"; do
            [[ "$item" == "$val" ]] && return 0
        done
        return 1
    }

    # APT packages
    local pkg_arrs=(
        SHARED_BASE_PACKAGES
        MISC_PACKAGES MISC_HEAVY_PACKAGES
        NET_PACKAGES RECON_PACKAGES WEB_PACKAGES PWN_PACKAGES RE_PACKAGES
        FORENSICS_PACKAGES WIRELESS_PACKAGES WIRELESS_HEAVY_PACKAGES
        CRACKING_PACKAGES STEGO_PACKAGES BLUETEAM_PACKAGES MOBILE_PACKAGES
        ENTERPRISE_PACKAGES CRYPTO_PACKAGES CLOUD_PACKAGES CONTAINER_PACKAGES
        BLOCKCHAIN_PACKAGES LLM_PACKAGES
    )
    for a in "${pkg_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            local _tmp_pkg=("$tool")
            fixup_package_names _tmp_pkg
            if [[ ${#_tmp_pkg[@]} -eq 0 ]]; then
                log_warn "$tool is not available on this distro — skipped"
                return 0
            fi
            log_info "Installing ${_tmp_pkg[*]} via $PKG_MANAGER..."
            if pkg_install "${_tmp_pkg[@]}" >> "$LOG_FILE" 2>&1; then
                log_success "Installed: ${_tmp_pkg[*]}"
                track_version "$tool" "$PKG_MANAGER" "latest"
            else
                log_error "Failed: ${_tmp_pkg[*]}"
                return 1
            fi
            return 0
        fi
    done

    # pipx
    local pipx_arrs=(
        MISC_PIPX NET_PIPX RECON_PIPX WEB_PIPX CRYPTO_PIPX PWN_PIPX RE_PIPX
        FORENSICS_PIPX ENTERPRISE_PIPX WIRELESS_PIPX CRACKING_PIPX
        STEGO_PIPX CLOUD_PIPX CONTAINER_PIPX BLUETEAM_PIPX MOBILE_PIPX
        BLOCKCHAIN_PIPX LLM_PIPX
    )
    for a in "${pipx_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via pipx..."
            ensure_pipx
            if pipx_install "$tool" >> "$LOG_FILE" 2>&1; then
                log_success "Installed: $tool"
                track_version "$tool" "pipx" "latest"
            else
                log_error "Failed: $tool"
                return 1
            fi
            return 0
        fi
    done

    # Go (match binary name from full import path)
    local go_arrs=(
        MISC_GO NET_GO RECON_GO WEB_GO PWN_GO
        ENTERPRISE_GO CLOUD_GO
    )
    for a in "${go_arrs[@]}"; do
        declare -p "$a" &>/dev/null || continue
        local -n _goref="$a"
        [[ ${#_goref[@]} -eq 0 ]] && continue
        for gopkg in "${_goref[@]}"; do
            local goname
            goname=$(_go_bin_name "$gopkg")
            if [[ "$goname" == "$tool" ]]; then
                ensure_go || { log_error "Go not available — cannot install $tool"; return 1; }
                log_info "Installing $tool via go install..."
                # Use _as_builder + staging GOBIN (consistent with batch installer)
                local _gobin_stage _go_gopath_esc _go_gobin_esc _go_pkg_esc
                _gobin_stage=$(mktemp -d "/tmp/cybersec-gobin.XXXXXX")
                _register_cleanup "$_gobin_stage"
                if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER:-}" != "root" ]]; then
                    _chown_for_builder "$_gobin_stage"
                    chown -R "$SUDO_USER" "$GOPATH" 2>/dev/null || true
                fi
                _go_gopath_esc="$(_escape_single_quoted "$GOPATH")"
                _go_gobin_esc="$(_escape_single_quoted "$_gobin_stage")"
                _go_pkg_esc="$(_escape_single_quoted "$gopkg")"
                if _as_builder "GOPATH='$_go_gopath_esc' GOBIN='$_go_gobin_esc' $(command -v go) install $_go_pkg_esc" >> "$LOG_FILE" 2>&1; then
                    [[ -f "$_gobin_stage/$tool" ]] && mv "$_gobin_stage/$tool" "$GOBIN/$tool" && chmod +x "$GOBIN/$tool"
                    log_success "Installed: $tool"
                    track_version "$tool" "go" "latest"
                else
                    log_error "Failed: $tool"
                    rm -rf "$_gobin_stage"
                    return 1
                fi
                rm -rf "$_gobin_stage"
                return 0
            fi
        done
    done

    # Cargo
    local cargo_arrs=(
        WEB_CARGO NET_CARGO PWN_CARGO BLUETEAM_CARGO BLOCKCHAIN_CARGO
    )
    for a in "${cargo_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            ensure_cargo || { log_error "Cargo not available — cannot install $tool"; return 1; }
            log_info "Installing $tool via cargo..."
            local _tool_esc; _tool_esc="$(_escape_single_quoted "$tool")"
            if _as_builder "$(command -v cargo) install $_tool_esc" >> "$LOG_FILE" 2>&1; then
                log_success "Installed: $tool"
                track_version "$tool" "cargo" "latest"
            else
                log_error "Failed: $tool"
                return 1
            fi
            local _cargo_bin_dir; _cargo_bin_dir="$(_builder_home)/.cargo/bin"
            if [[ -f "$_cargo_bin_dir/$tool" ]]; then
                ln -sf "$_cargo_bin_dir/$tool" "$PIPX_BIN_DIR/$tool" 2>/dev/null || true
            fi
            return 0
        fi
    done

    # Gems
    local gem_arrs=(WEB_GEMS PWN_GEMS STEGO_GEMS ENTERPRISE_GEMS)
    for a in "${gem_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via gem..."
            local _tool_esc; _tool_esc="$(_escape_single_quoted "$tool")"
            if _as_builder "$(command -v gem) install $_tool_esc --no-document" >> "$LOG_FILE" 2>&1; then
                # Symlink gem binary to PIPX_BIN_DIR (consistent with batch installer)
                local _gem_bin_dir
                _gem_bin_dir="$(_builder_home)/.local/share/gem/ruby/*/bin" 2>/dev/null
                # shellcheck disable=SC2086  # glob expansion intentional
                for _gbin in $_gem_bin_dir/$tool; do
                    [[ -f "$_gbin" ]] && ln -sf "$_gbin" "$PIPX_BIN_DIR/$(basename "$_gbin")" 2>/dev/null || true
                done
                log_success "Installed: $tool"
                track_version "$tool" "gem" "latest"
            else
                log_error "Failed: $tool"
                return 1
            fi
            return 0
        fi
    done

    # Git repos (match name= prefix)
    local git_arrs=(
        MISC_GIT NET_GIT RECON_GIT WEB_GIT CRYPTO_GIT PWN_GIT RE_GIT
        FORENSICS_GIT ENTERPRISE_GIT WIRELESS_GIT CRACKING_GIT
        STEGO_GIT CLOUD_GIT CONTAINER_GIT BLUETEAM_GIT MOBILE_GIT
        BLOCKCHAIN_GIT LLM_GIT
    )
    for a in "${git_arrs[@]}"; do
        declare -p "$a" &>/dev/null || continue
        local -n _gitref="$a"
        [[ ${#_gitref[@]} -eq 0 ]] && continue
        for entry in "${_gitref[@]}"; do
            local gname="${entry%%=*}"
            if [[ "$gname" == "$tool" ]]; then
                local url="${entry#*=}"
                local dest="$GITHUB_TOOL_DIR/$gname"
                log_info "Cloning $tool..."
                if git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1; then
                    setup_git_repo "$dest" >> "$LOG_FILE" 2>&1 || log_warn "setup_git_repo failed for $tool"
                    log_success "Installed: $tool → $dest"
                    track_version "$tool" "git" "HEAD"
                else
                    log_error "Failed: $tool"
                    return 1
                fi
                return 0
            fi
        done
    done

    # npm tools (promptfoo)
    if [[ "$tool" == "promptfoo" ]]; then
        ensure_node || { log_error "Node.js/npm not available — cannot install $tool"; return 1; }
        log_info "Installing $tool via npm..."
        if npm install -g "$tool@latest" >> "$LOG_FILE" 2>&1; then
            local _pf_ver; _pf_ver=$(promptfoo --version 2>/dev/null || echo "latest")
            log_success "Installed: $tool ($_pf_ver)"
            track_version "$tool" "npm" "$_pf_ver"
        else
            log_error "Failed: $tool"
            return 1
        fi
        return 0
    fi

    log_error "Tool '$tool' not found in any module array."
    log_info "Use --list-modules to see available modules, or check tool names with:"
    log_info "  grep -r '$tool' modules/"
    return 1
}

if [[ ${#SELECTED_TOOLS[@]} -gt 0 ]]; then
    # Source ALL modules to search all arrays
    for mod in "${ALL_MODULES[@]}"; do
        source "$SCRIPT_DIR/modules/${mod}.sh"
    done
    LOG_FILE="$SCRIPT_DIR/cybersec_install.log"
    check_root
    log_info "Installing ${#SELECTED_TOOLS[@]} individual tool(s)..."
    TOOL_FAILED=0
    for tool in "${SELECTED_TOOLS[@]}"; do
        install_single_tool "$tool" || TOOL_FAILED=$((TOOL_FAILED + 1))
    done
    if [[ "$TOOL_FAILED" -gt 0 ]]; then
        log_warn "$TOOL_FAILED tool(s) failed"
        exit 1
    fi
    exit 0
fi

# Rollback a previous install session
if [[ -n "$ROLLBACK_TARGET" ]]; then
    # Sanitize rollback target: only "last" or session ID (no path traversal)
    if [[ "$ROLLBACK_TARGET" != "last" ]] && [[ "$ROLLBACK_TARGET" == */* || "$ROLLBACK_TARGET" == *..* ]]; then
        log_error "Invalid rollback target (no path components allowed): $ROLLBACK_TARGET"
        exit 1
    fi
    check_root
    LOG_FILE="$SCRIPT_DIR/cybersec_install.log"
    _init_log_file "$LOG_FILE"

    local_session_dir="$SCRIPT_DIR/.install_sessions"

    if [[ "$ROLLBACK_TARGET" == "last" ]]; then
        # Find the most recent manifest
        # shellcheck disable=SC2012  # Filenames are controlled (timestamp_pid.manifest)
        ROLLBACK_FILE=$(ls -1t "$local_session_dir"/*.manifest 2>/dev/null | head -1)
        if [[ -z "$ROLLBACK_FILE" ]]; then
            log_error "No install sessions found"
            exit 1
        fi
    else
        ROLLBACK_FILE="$local_session_dir/${ROLLBACK_TARGET}.manifest"
        if [[ ! -f "$ROLLBACK_FILE" ]]; then
            log_error "Session not found: $ROLLBACK_TARGET"
            log_info "Use --list-sessions to see available sessions"
            exit 1
        fi
    fi

    ROLLBACK_SESSION=$(basename "$ROLLBACK_FILE" .manifest)
    log_info "Rolling back session: $ROLLBACK_SESSION"

    # Parse installed tools from manifest (skip comments and failed entries)
    declare -a RB_TOOLS=()
    declare -a RB_METHODS=()
    while IFS='|' read -r rb_tool rb_method rb_action _; do
        [[ "$rb_tool" == \#* ]] && continue
        [[ "$rb_action" == "installed" ]] || continue
        RB_TOOLS+=("$rb_tool")
        RB_METHODS+=("$rb_method")
    done < "$ROLLBACK_FILE"

    if [[ ${#RB_TOOLS[@]} -eq 0 ]]; then
        log_warn "No installed tools found in session $ROLLBACK_SESSION"
        exit 0
    fi

    echo ""
    log_info "Tools to remove (${#RB_TOOLS[@]}):"
    for i in "${!RB_TOOLS[@]}"; do
        echo "  - ${RB_TOOLS[$i]} (${RB_METHODS[$i]})"
    done
    echo ""

    # Confirm
    if [[ -t 0 ]]; then
        read -rp "$(echo -e "${YELLOW}[!]${NC} Proceed with rollback? [y/N] ")" _rb_answer
        case "$_rb_answer" in
            [yY]|[yY][eE][sS]) ;;
            *) log_info "Rollback cancelled."; exit 0 ;;
        esac
    fi

    # Remove in reverse dependency order: gems → cargo → go → pipx → git → binary
    # APT packages are skipped (too risky — use scripts/remove.sh)
    rb_removed=0
    rb_skipped=0
    for i in "${!RB_TOOLS[@]}"; do
        rb_tool="${RB_TOOLS[$i]}"
        rb_method="${RB_METHODS[$i]}"
        case "$rb_method" in
            pipx)
                if command_exists pipx; then
                    pipx uninstall "$rb_tool" >> "$LOG_FILE" 2>&1 && rb_removed=$((rb_removed + 1)) || true
                fi
                ;;
            go)
                rb_bin="$GOBIN/$rb_tool"
                if [[ -f "$rb_bin" ]]; then
                    rm -f "$rb_bin" && rb_removed=$((rb_removed + 1))
                fi
                ;;
            cargo)
                if command_exists cargo; then
                    cargo uninstall "$rb_tool" >> "$LOG_FILE" 2>&1 || true
                fi
                rm -f "$PIPX_BIN_DIR/$rb_tool" 2>/dev/null || true
                rm -f "$(_builder_home)/.cargo/bin/$rb_tool" 2>/dev/null || true
                rb_removed=$((rb_removed + 1))
                ;;
            gem)
                if command_exists gem; then
                    gem uninstall "$rb_tool" -x --force >> "$LOG_FILE" 2>&1 && rb_removed=$((rb_removed + 1)) || true
                fi
                ;;
            git)
                rb_dir="$GITHUB_TOOL_DIR/$rb_tool"
                if [[ -d "$rb_dir" ]]; then
                    rm -rf "$rb_dir" && rb_removed=$((rb_removed + 1))
                fi
                # Remove symlink/wrapper
                rm -f "$PIPX_BIN_DIR/$rb_tool" 2>/dev/null || true
                rm -f "$PIPX_BIN_DIR/${rb_tool,,}" 2>/dev/null || true
                ;;
            binary)
                rm -f "$PIPX_BIN_DIR/$rb_tool" 2>/dev/null || true
                rb_removed=$((rb_removed + 1))
                ;;
            apt|dnf|pacman|zypper|pkg)
                log_info "  Skipping APT package: $rb_tool (use scripts/remove.sh)"
                rb_skipped=$((rb_skipped + 1))
                continue
                ;;
            *)
                log_info "  Skipping $rb_tool ($rb_method — unknown method)"
                rb_skipped=$((rb_skipped + 1))
                continue
                ;;
        esac

        # Remove from .versions file (use flock for parallel safety, matching track_version)
        if [[ -f "$SCRIPT_DIR/.versions" ]]; then
            _rb_versions_write() {
                local _tmp_ver
                _tmp_ver=$(mktemp "${SCRIPT_DIR}/.versions.XXXXXX")
                grep -v "^${rb_tool}|" "$SCRIPT_DIR/.versions" > "$_tmp_ver" 2>/dev/null || true
                mv -f "$_tmp_ver" "$SCRIPT_DIR/.versions"
            }
            if command -v flock &>/dev/null; then
                (
                    flock -x 200
                    _rb_versions_write
                ) 200>"${SCRIPT_DIR}/.versions.lock"
            else
                _rb_versions_write
            fi
        fi
        log_success "Removed: $rb_tool ($rb_method)"
    done

    echo ""
    log_success "Rollback complete: $rb_removed removed, $rb_skipped skipped (APT/unknown)"

    # Rename the manifest to indicate it was rolled back
    mv "$ROLLBACK_FILE" "${ROLLBACK_FILE%.manifest}.rolled_back" 2>/dev/null || true
    exit 0
fi

# Resolve modules to install
MODULES_TO_INSTALL=()

# Sanitize profile name: no path components (prevent path traversal)
if [[ -n "$PROFILE" ]]; then
    if [[ "$PROFILE" == */* || "$PROFILE" == *..* ]]; then
        log_error "Invalid profile name (no path components allowed): $PROFILE"
        exit 1
    fi
    local_profile="$SCRIPT_DIR/profiles/${PROFILE}.conf"
    if [[ ! -f "$local_profile" ]]; then
        log_error "Profile not found: $PROFILE"
        log_info "Available: $(find "$SCRIPT_DIR/profiles" -maxdepth 1 -name '*.conf' -print0 2>/dev/null | xargs -0 -I{} basename {} .conf | tr '\n' ' ')"
        exit 1
    fi
    # Save CLI flag values before sourcing profile
    _cli_skip_heavy="$SKIP_HEAVY"
    _cli_enable_docker="$ENABLE_DOCKER"
    _cli_include_c2="$INCLUDE_C2"
    # Source profile config
    source "$local_profile"
    # Explicit CLI flags override profile defaults (in both directions)
    [[ "$_CLI_SET_SKIP_HEAVY" == "true" ]]     && SKIP_HEAVY="$_cli_skip_heavy"
    [[ "$_CLI_SET_ENABLE_DOCKER" == "true" ]]  && ENABLE_DOCKER="$_cli_enable_docker"
    [[ "$_CLI_SET_INCLUDE_C2" == "true" ]]     && INCLUDE_C2="$_cli_include_c2"
    # MODULES variable set by profile
    read -ra MODULES_TO_INSTALL <<< "${MODULES:-}"
    # Validate profile module names
    for mod in "${MODULES_TO_INSTALL[@]}"; do
        if [[ " ${ALL_MODULES[*]} " != *" $mod "* ]]; then
            log_error "Profile '$PROFILE' references unknown module: $mod"
            exit 1
        fi
    done
elif [[ ${#SELECTED_MODULES[@]} -gt 0 ]]; then
    # Validate each --module argument is a known module (prevent path traversal)
    for mod in "${SELECTED_MODULES[@]}"; do
        if [[ "$mod" == */* || "$mod" == *..* ]]; then
            log_error "Invalid module name (no path components allowed): $mod"
            exit 1
        fi
        if [[ " ${ALL_MODULES[*]} " != *" $mod "* ]]; then
            log_error "Unknown module: $mod (use --list-modules to see available modules)"
            exit 1
        fi
    done
    MODULES_TO_INSTALL=("${SELECTED_MODULES[@]}")
else
    # Default: full install
    MODULES_TO_INSTALL=("${ALL_MODULES[@]}")
fi

# Export flags for modules
export SKIP_HEAVY SKIP_PIPX SKIP_GO SKIP_CARGO SKIP_GEMS SKIP_GIT SKIP_BINARY SKIP_SOURCE
export ENABLE_DOCKER INCLUDE_C2 REQUIRE_CHECKSUMS FAST_MODE UPGRADE_SYSTEM VERBOSE PARALLEL_JOBS

# Source selected modules
for mod in "${MODULES_TO_INSTALL[@]}"; do
    local_mod="$SCRIPT_DIR/modules/${mod}.sh"
    if [[ -f "$local_mod" ]]; then
        source "$local_mod"
    else
        log_error "Module not found: $mod"
        exit 1
    fi
done

# Time estimate helper
# _count_array — returns the length of a named array, or 0 if it doesn't exist.
_count_array() {
    local arr_name="$1"
    declare -p "$arr_name" &>/dev/null || { echo 0; return; }
    local -n _ref="$arr_name"
    echo "${#_ref[@]}"
}

# estimate_install_time — counts tools per install method from sourced module
# arrays and displays a range-based time estimate.
estimate_install_time() {
    local apt_count=0 pipx_count=0 go_count=0 cargo_count=0 gem_count=0
    local git_count=0 binary_count=0 build_count=0

    # Shared base dependencies (always installed)
    apt_count=$((apt_count + $(_count_array SHARED_BASE_PACKAGES)))

    for mod in "${MODULES_TO_INSTALL[@]}"; do
        local prefix
        prefix=$(_module_prefix "$mod")
        local mod_upper="${mod^^}"

        # APT packages
        apt_count=$((apt_count + $(_count_array "${prefix}_PACKAGES")))
        if [[ "$SKIP_HEAVY" != "true" ]]; then
            apt_count=$((apt_count + $(_count_array "${prefix}_HEAVY_PACKAGES")))
        fi

        # pipx / Go / Cargo / Gems
        pipx_count=$((pipx_count + $(_count_array "${prefix}_PIPX")))
        go_count=$((go_count + $(_count_array "${prefix}_GO")))
        cargo_count=$((cargo_count + $(_count_array "${prefix}_CARGO")))
        gem_count=$((gem_count + $(_count_array "${prefix}_GEMS")))

        # Git repos
        git_count=$((git_count + $(_count_array "${prefix}_GIT")))

        # Binary releases (BINARY_RELEASES_<MODULE_UPPER> in installers.sh)
        binary_count=$((binary_count + $(_count_array "BINARY_RELEASES_${mod_upper}")))

        # Build from source (PREFIX_BUILD_NAMES)
        build_count=$((build_count + $(_count_array "${prefix}_BUILD_NAMES")))
    done

    # Count snap/special/docker tools from tools_config.json for selected modules
    local snap_count=0 special_count=0 docker_count=0
    local _config="${SCRIPT_DIR:-.}/tools_config.json"
    if [[ -f "$_config" ]]; then
        # Build "|"-separated module pattern for awk
        local _mod_list
        _mod_list=$(IFS='|'; echo "${MODULES_TO_INSTALL[*]}")
        # tools_config.json has consistent field order: name, method, module, url
        read -r snap_count special_count docker_count < <(awk -v mods="$_mod_list" '
            /"method"/ { gsub(/[",]/, ""); method=$2 }
            /"module"/ {
                gsub(/[",]/, ""); mod=$2
                if (mod ~ "^(" mods ")$") {
                    if (method == "snap")    snap++
                    if (method == "special") special++
                    if (method == "docker")  docker++
                }
            }
            END { printf "%d %d %d\n", snap+0, special+0, docker+0 }
        ' "$_config")
        # Exclude docker tools when Docker is disabled
        [[ "${ENABLE_DOCKER:-false}" != "true" ]] && docker_count=0
    fi

    local total=$((apt_count + pipx_count + go_count + cargo_count + gem_count + git_count + binary_count + build_count + snap_count + special_count + docker_count))

    # ── Stage 2: APT (sequential, single batch install) ──
    local apt_min=0 apt_max=0
    if [[ "$apt_count" -gt 0 ]]; then
        apt_min=$((60 + apt_count * 2))      # dep resolution + download + unpack
        apt_max=$((120 + apt_count * 4))
    fi

    # ── Stage 3: Non-APT batches (run in PARALLEL when PARALLEL_JOBS > 1) ──
    # Per-method benchmarks (seconds per tool).  pipx and Cargo run
    # sequentially within their batch; Go/Git/Binary use a shared semaphore.
    local pipx_min=$((pipx_count * 8))       pipx_max=$((pipx_count * 20))
    local go_min=$((go_count * 5))           go_max=$((go_count * 15))
    local cargo_min=$((cargo_count * 25))    cargo_max=$((cargo_count * 75))
    local gem_min=$((gem_count * 3))         gem_max=$((gem_count * 8))
    local git_min=$((git_count * 5))         git_max=$((git_count * 15))
    local binary_min=$((binary_count * 3))   binary_max=$((binary_count * 10))

    # Go/Git/Binary share the global semaphore — divide by PARALLEL_JOBS
    local pj=${PARALLEL_JOBS:-4}
    if [[ "$pj" -gt 1 ]]; then
        go_min=$(( (go_min + pj - 1) / pj ))
        go_max=$(( (go_max + pj - 1) / pj ))
        git_min=$(( (git_min + pj - 1) / pj ))
        git_max=$(( (git_max + pj - 1) / pj ))
        binary_min=$(( (binary_min + pj - 1) / pj ))
        binary_max=$(( (binary_max + pj - 1) / pj ))
    fi

    # Stage 3 methods run concurrently — wall-clock is the slowest batch
    local stage3_min stage3_max
    stage3_min=$pipx_min
    for v in $go_min $cargo_min $gem_min $git_min $binary_min; do
        (( v > stage3_min )) && stage3_min=$v
    done
    stage3_max=$pipx_max
    for v in $go_max $cargo_max $gem_max $git_max $binary_max; do
        (( v > stage3_max )) && stage3_max=$v
    done

    # When PARALLEL_JOBS=1, batches run sequentially — sum them instead
    if [[ "$pj" -le 1 ]]; then
        stage3_min=$((pipx_min + go_min + cargo_min + gem_min + git_min + binary_min))
        stage3_max=$((pipx_max + go_max + cargo_max + gem_max + git_max + binary_max))
    fi

    # ── Stage 4: Custom installers + build-from-source (sequential) ──
    # Build from source: compile time per tool
    local stage4_min=$((build_count * 15))     stage4_max=$((build_count * 45))
    # Snap installs: snapd bootstrap + each snap is slow
    stage4_min=$((stage4_min + snap_count * 30))   stage4_max=$((stage4_max + snap_count * 120))
    # Special installers: multi-method fallbacks, curl|bash builds, complex setup
    stage4_min=$((stage4_min + special_count * 60))  stage4_max=$((stage4_max + special_count * 300))
    # Docker pulls: image download + extract
    stage4_min=$((stage4_min + docker_count * 30))   stage4_max=$((stage4_max + docker_count * 120))

    local total_min_s=$((apt_min + stage3_min + stage4_min))
    local total_max_s=$((apt_max + stage3_max + stage4_max))

    # Round up to minutes
    local min_minutes=$(( (total_min_s + 59) / 60 ))
    local max_minutes=$(( (total_max_s + 59) / 60 ))

    log_warn "Estimated install time: ~${min_minutes}-${max_minutes} minutes (${#MODULES_TO_INSTALL[@]} modules, ${total}+ install entries)"
    log_info "  Breakdown: ${apt_count} apt, ${pipx_count} pipx, ${go_count} go, ${cargo_count} cargo, ${gem_count} gem, ${git_count} git, ${binary_count} binary, ${build_count} source"
    [[ $((snap_count + special_count + docker_count)) -gt 0 ]] && \
        log_info "  Custom: ${snap_count} snap, ${special_count} special, ${docker_count} docker"
    log_info "  Speed depends on network bandwidth, disk I/O, and CPU cores"
    echo ""
}

# Dry run
if [[ "$DRY_RUN" == "true" ]]; then
    echo ""
    _separator_line "$CYAN"
    echo -e "  ${CYAN}${BOLD}DRY RUN${NC}"
    _separator_line "$CYAN"
    echo ""
    echo "Profile:        ${PROFILE:-custom}"
    echo "Modules:        ${MODULES_TO_INSTALL[*]}"
    echo "Skip heavy:     $SKIP_HEAVY"
    # Show active skip flags
    _skip_flags=()
    [[ "$SKIP_PIPX"   == "true" ]] && _skip_flags+=(pipx)
    [[ "$SKIP_GO"     == "true" ]] && _skip_flags+=(go)
    [[ "$SKIP_CARGO"  == "true" ]] && _skip_flags+=(cargo)
    [[ "$SKIP_GEMS"   == "true" ]] && _skip_flags+=(gems)
    [[ "$SKIP_GIT"    == "true" ]] && _skip_flags+=(git)
    [[ "$SKIP_BINARY" == "true" ]] && _skip_flags+=(binary)
    [[ "$SKIP_SOURCE" == "true" ]] && _skip_flags+=(source)
    if [[ ${#_skip_flags[@]} -gt 0 ]]; then
        echo "Skipping:       ${_skip_flags[*]}"
    fi
    echo "Fast mode:      $FAST_MODE"
    echo "Docker:         $ENABLE_DOCKER"
    echo "C2:             $INCLUDE_C2"
    echo "System upgrade: $UPGRADE_SYSTEM"
    echo "Parallel jobs:  $PARALLEL_JOBS"
    echo "Verbose:        $VERBOSE"
    echo "WSL:            $IS_WSL"
    echo "ARM:            $IS_ARM"
    echo ""
    echo "The following module install functions would run:"
    for mod in "${MODULES_TO_INSTALL[@]}"; do
        echo "  - install_module_${mod}"
    done
    echo ""
    estimate_install_time
    exit 0
fi

# Main installation
LOG_FILE="$SCRIPT_DIR/cybersec_install.log"
if : > "$LOG_FILE" 2>/dev/null; then
    chmod 600 "$LOG_FILE" 2>/dev/null || true
else
    LOG_FILE="/dev/null"
fi
VERSION_FILE="$SCRIPT_DIR/.versions"

main() {
    check_root
    trap '_global_cleanup; exit 130' INT TERM
    print_banner

    _check_pkg_manager
    _setup_verbose

    # Termux: Docker and snap are not available
    if [[ "$PKG_MANAGER" == "pkg" ]] && [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        log_warn "Docker is not available on Termux/Android — skipping Docker tools"
        ENABLE_DOCKER="false"
    fi

    # WSL: wireless module requires hardware access not available under WSL
    if [[ "$IS_WSL" == "true" ]]; then
        local _wsl_filtered=()
        for _mod in "${MODULES_TO_INSTALL[@]}"; do
            if [[ "$_mod" == "wireless" ]]; then
                log_warn "Skipping wireless module on WSL (no hardware access)"
            else
                _wsl_filtered+=("$_mod")
            fi
        done
        MODULES_TO_INSTALL=("${_wsl_filtered[@]}")
    fi

    # Docker is the only prerequisite users must install themselves
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]] && ! command_exists docker; then
        log_error "MISSING: docker — --enable-docker was set but Docker is not installed"
        log_error "Install Docker: https://docs.docker.com/engine/install/"
        exit 1
    fi

    log_info "Profile: ${PROFILE:-full}"
    log_info "Modules: ${MODULES_TO_INSTALL[*]}"
    estimate_install_time

    # Pre-flight disk space check
    check_disk_space "${#MODULES_TO_INSTALL[@]}"

    # Initialize session tracking for rollback support
    _init_session "${PROFILE:-full}" "${MODULES_TO_INSTALL[*]}"
    log_info "Session: $_SESSION_ID"
    log_info "Starting installation..."
    echo ""

    local start_time
    start_time=$(date +%s)

    # Refresh package lists (required for installing packages)
    log_info "Refreshing package lists..."
    if pkg_update >> "$LOG_FILE" 2>&1; then
        log_success "Package lists refreshed"
    else
        log_warn "Package list refresh had errors (check log) — continuing"
    fi

    # Optional: full system upgrade (only with --upgrade-system)
    if [[ "$UPGRADE_SYSTEM" == "true" ]]; then
        log_info "Upgrading system packages (--upgrade-system)..."
        if pkg_upgrade >> "$LOG_FILE" 2>&1; then
            log_success "System packages upgraded"
        else
            log_warn "System upgrade had errors (check log) — continuing"
        fi
    fi
    echo ""

    # Install shared base dependencies (runtimes, compilers, dev libs)
    install_shared_deps
    echo ""

    # Ensure additional toolchains are available
    ensure_python_modern
    ensure_pipx
    ensure_go
    ensure_cargo
    echo ""

    # Install modules
    install_modules

    # Disable debug trace before summary output
    disable_debug_trace

    # Final summary
    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$(( end_time - start_time ))
    local minutes=$(( elapsed / 60 ))
    local seconds=$(( elapsed % 60 ))

    echo ""
    if _installation_failed; then
        _separator_line "$YELLOW"
        log_warn "Installation finished with errors (${minutes}m ${seconds}s)"
        _separator_line "$YELLOW"
    else
        _separator_line "$GREEN"
        log_success "Installation complete! (${minutes}m ${seconds}s)"
        _separator_line "$GREEN"
    fi
    log_info "Profile: ${PROFILE:-full}"
    log_info "Modules installed: ${MODULES_TO_INSTALL[*]}"
    # Count tools tracked in .versions file (excludes header/comment lines)
    local tools_installed=0
    if [[ -f "$VERSION_FILE" ]]; then
        tools_installed=$(grep -cv '^#' "$VERSION_FILE" 2>/dev/null) || tools_installed=0
    fi
    log_info "Tools installed: $tools_installed"
    if _installation_failed; then
        [[ "$TOTAL_MODULE_FAILURES" -gt 0 ]] && log_error "Modules with failures: $TOTAL_MODULE_FAILURES"
        log_error "Total tool failures: $TOTAL_TOOL_FAILURES"
    fi
    log_info "Log file: $LOG_FILE"
    log_info "Version tracking: $VERSION_FILE"
    echo ""
    log_info "Tool locations:"
    log_info "  System packages:  managed by $PKG_MANAGER"
    log_info "  pipx tools:       $PIPX_BIN_DIR/ (PIPX_HOME=$PIPX_HOME)"
    log_info "  Go tools:         $GOBIN/ (GOBIN)"
    log_info "  Cargo tools:      $PIPX_BIN_DIR/ (symlinked)"
    log_info "  GitHub repos:     $GITHUB_TOOL_DIR/"
    log_info "  Binary releases:  $PIPX_BIN_DIR/"
    echo ""
    [[ -n "${_SESSION_ID:-}" ]] && log_info "Session ID: $_SESSION_ID"
    log_info "Next steps:"
    log_info "  Verify installation:  sudo ./scripts/verify.sh"
    log_info "  Update tools later:   sudo ./scripts/update.sh"
    log_info "  Backup configs:       sudo ./scripts/backup.sh"
    log_info "  MCP server (AI):      See mcp_server/README.md"
    log_info "  Rollback this run:    sudo ./install.sh --rollback $_SESSION_ID"
    echo ""

    # Clean up GitHub API cache
    _gh_api_cache_cleanup 2>/dev/null || true

    # Finalize session manifest
    if _installation_failed; then
        _finalize_session "partial"
        exit 1
    else
        _finalize_session "complete"
    fi
}

# Module installation
TOTAL_MODULE_FAILURES=0

install_modules() {
    # Stage 1/4: Aggregate all tool arrays from selected modules ──
    log_info "Stage 1/4: Aggregating tool lists from ${#MODULES_TO_INSTALL[@]} modules..."

    local -a _ALL_APT=() _ALL_PIPX=() _ALL_GO=() _ALL_CARGO=() _ALL_GEMS=()
    local -a _ALL_GIT=() _ALL_BINARY=()

    for _mod in "${MODULES_TO_INSTALL[@]}"; do
        local _pfx
        _pfx=$(_module_prefix "$_mod")
        local _mod_upper="${_mod^^}"

        # APT packages
        _append_module_array _ALL_APT "${_pfx}_PACKAGES"
        if [[ "${SKIP_HEAVY:-false}" != "true" ]]; then
            _append_module_array _ALL_APT "${_pfx}_HEAVY_PACKAGES"
        fi

        # Other batch methods
        _append_module_array _ALL_PIPX  "${_pfx}_PIPX"
        _append_module_array _ALL_GO    "${_pfx}_GO"
        _append_module_array _ALL_CARGO "${_pfx}_CARGO"
        _append_module_array _ALL_GEMS  "${_pfx}_GEMS"
        _append_module_array _ALL_GIT   "${_pfx}_GIT"

        # Binary releases (BINARY_RELEASES_<MODULE_UPPER> in installers.sh)
        _append_module_array _ALL_BINARY "BINARY_RELEASES_${_mod_upper}"
    done

    log_info "  APT: ${#_ALL_APT[@]}, pipx: ${#_ALL_PIPX[@]}, Go: ${#_ALL_GO[@]}, Cargo: ${#_ALL_CARGO[@]}, Gems: ${#_ALL_GEMS[@]}, Git: ${#_ALL_GIT[@]}, Binary: ${#_ALL_BINARY[@]}"
    # Stage 2/4: Single APT transaction for ALL packages ──
    echo ""
    log_info "Stage 2/4: Installing all system packages in one transaction..."
    if [[ ${#_ALL_APT[@]} -gt 0 ]]; then
        install_apt_batch "All modules - Packages" "${_ALL_APT[@]}"
    fi

    # Stage 3/4: Non-APT batch installs ──
    echo ""

    # Save APT failure count so parallel subshell totals don't double-count
    local _apt_failures=$TOTAL_TOOL_FAILURES

    if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
        # --- Parallel: launch all batches as concurrent subshells ---
        log_info "Stage 3/4: Installing non-APT tools in parallel (pipx, Go, Cargo, Gems, Git, Binary)..."
        local _fail_dir
        _fail_dir=$(mktemp -d); _register_cleanup "$_fail_dir"

        # Initialise global concurrency semaphore (shared across all batch methods)
        _init_global_semaphore

        # Initialise progress display IPC directory
        _init_progress_dir

        # Clean up child processes, semaphore, and progress on interrupt (Ctrl+C / kill)
        # shellcheck disable=SC2046  # Word splitting on jobs -rp is intentional (PIDs)
        trap 'log_warn "Interrupted — killing background jobs..."; kill $(jobs -rp) 2>/dev/null; _stop_progress_display; _global_cleanup; exit 130' INT TERM

        # Subshells redirect stdout to /dev/null so their log_message() output
        # doesn't interleave on the terminal.  The log file still gets everything
        # because log_message() opens it explicitly via >> "$LOG_FILE".
        # Progress reporting writes to PROGRESS_DIR files, not stdout.
        local _method_names=()
        local _job_pids=()

        # Pre-write method totals from the main process so the progress display
        # has immediate access.  Subshell > /dev/null redirects prevent the batch
        # functions' _report_method_total writes from reaching PROGRESS_DIR.
        if [[ ${#_ALL_PIPX[@]} -gt 0 ]];   then _method_names+=("pipx");   _report_method_total "pipx"   "${#_ALL_PIPX[@]}";   fi
        if [[ ${#_ALL_GO[@]} -gt 0 ]];     then _method_names+=("Go");     _report_method_total "Go"     "${#_ALL_GO[@]}";     fi
        if [[ ${#_ALL_CARGO[@]} -gt 0 ]];  then _method_names+=("Cargo");  _report_method_total "Cargo"  "${#_ALL_CARGO[@]}";  fi
        if [[ ${#_ALL_GEMS[@]} -gt 0 ]];   then _method_names+=("Gems");   _report_method_total "Gems"   "${#_ALL_GEMS[@]}";   fi
        if [[ ${#_ALL_GIT[@]} -gt 0 ]];    then _method_names+=("Git");    _report_method_total "Git"    "${#_ALL_GIT[@]}";    fi
        if [[ ${#_ALL_BINARY[@]} -gt 0 ]]; then _method_names+=("Binary"); _report_method_total "Binary" "${#_ALL_BINARY[@]}"; fi

        # pipx (sequential within — venv lock)
        if [[ ${#_ALL_PIPX[@]} -gt 0 ]]; then
            (
                trap '[[ -f "$_fail_dir/pipx.cnt" ]] || echo 1 > "$_fail_dir/pipx.cnt"' EXIT
                TOTAL_TOOL_FAILURES=0
                install_pipx_batch "All modules - Python" "${_ALL_PIPX[@]}"
                echo "$TOTAL_TOOL_FAILURES" > "$_fail_dir/pipx.cnt"
            ) > /dev/null 2>>"$LOG_FILE" &
            _job_pids+=($!)
        fi

        # Go (parallelized within via global semaphore)
        if [[ ${#_ALL_GO[@]} -gt 0 ]]; then
            (
                trap '[[ -f "$_fail_dir/go.cnt" ]] || echo 1 > "$_fail_dir/go.cnt"' EXIT
                TOTAL_TOOL_FAILURES=0
                install_go_batch "All modules - Go" "${_ALL_GO[@]}"
                echo "$TOTAL_TOOL_FAILURES" > "$_fail_dir/go.cnt"
            ) > /dev/null 2>>"$LOG_FILE" &
            _job_pids+=($!)
        fi

        # Cargo (sequential within — registry lock)
        if [[ ${#_ALL_CARGO[@]} -gt 0 ]]; then
            (
                trap '[[ -f "$_fail_dir/cargo.cnt" ]] || echo 1 > "$_fail_dir/cargo.cnt"' EXIT
                TOTAL_TOOL_FAILURES=0
                install_cargo_batch "All modules - Rust" "${_ALL_CARGO[@]}"
                echo "$TOTAL_TOOL_FAILURES" > "$_fail_dir/cargo.cnt"
            ) > /dev/null 2>>"$LOG_FILE" &
            _job_pids+=($!)
        fi

        # Gems (sequential within — gem dir lock)
        if [[ ${#_ALL_GEMS[@]} -gt 0 ]]; then
            (
                trap '[[ -f "$_fail_dir/gems.cnt" ]] || echo 1 > "$_fail_dir/gems.cnt"' EXIT
                TOTAL_TOOL_FAILURES=0
                install_gem_batch "All modules - Ruby" "${_ALL_GEMS[@]}"
                echo "$TOTAL_TOOL_FAILURES" > "$_fail_dir/gems.cnt"
            ) > /dev/null 2>>"$LOG_FILE" &
            _job_pids+=($!)
        fi

        # Git repos (parallelized within via global semaphore)
        if [[ ${#_ALL_GIT[@]} -gt 0 ]]; then
            (
                trap '[[ -f "$_fail_dir/git.cnt" ]] || echo 1 > "$_fail_dir/git.cnt"' EXIT
                TOTAL_TOOL_FAILURES=0
                install_git_batch "All modules - Git" "${_ALL_GIT[@]}"
                echo "$TOTAL_TOOL_FAILURES" > "$_fail_dir/git.cnt"
            ) > /dev/null 2>>"$LOG_FILE" &
            _job_pids+=($!)
        fi

        # Binary releases (parallelized within via global semaphore)
        if [[ ${#_ALL_BINARY[@]} -gt 0 ]]; then
            (
                trap '[[ -f "$_fail_dir/binary.cnt" ]] || echo 1 > "$_fail_dir/binary.cnt"' EXIT
                TOTAL_TOOL_FAILURES=0
                install_binary_releases "${_ALL_BINARY[@]}"
                echo "$TOTAL_TOOL_FAILURES" > "$_fail_dir/binary.cnt"
            ) > /dev/null 2>>"$LOG_FILE" &
            _job_pids+=($!)
        fi

        # Launch live multi-line progress display
        if [[ ${#_method_names[@]} -gt 0 ]]; then
            _start_progress_display "${_method_names[@]}"
        fi
        # Wait only for install jobs, not the display background process
        for _pid in "${_job_pids[@]}"; do
            wait "$_pid" 2>/dev/null || true
        done
        _stop_progress_display

        # Clean up global semaphore and restore main signal handler
        _cleanup_global_semaphore
        trap '_global_cleanup; exit 130' INT TERM

        # Sum failures from all parallel methods and print clean summary
        local _stage3_failures=0
        for _f in "$_fail_dir"/*.cnt; do
            [[ -f "$_f" ]] || continue
            local _cnt _method
            _cnt=$(< "$_f")
            _method=$(basename "$_f" .cnt)
            _stage3_failures=$((_stage3_failures + _cnt))
            if [[ "$_cnt" -gt 0 ]]; then
                log_warn "  ${_method}: ${_cnt} failure(s)"
            else
                log_success "  ${_method}: OK"
            fi
        done
        TOTAL_TOOL_FAILURES=$((_apt_failures + _stage3_failures))
        rm -rf "$_fail_dir"

        if [[ "$_stage3_failures" -gt 0 ]]; then
            log_warn "Stage 3/4 complete: ${_stage3_failures} tool(s) failed (see log for details)"
        else
            log_success "Stage 3/4 complete: all tools installed"
        fi
    else
        # --- Sequential: PARALLEL_JOBS=1, run each batch inline ---
        log_info "Stage 3/4: Installing non-APT tools sequentially (pipx, Go, Cargo, Gems, Git, Binary)..."
        [[ ${#_ALL_PIPX[@]}   -gt 0 ]] && install_pipx_batch    "All modules - Python" "${_ALL_PIPX[@]}"
        [[ ${#_ALL_GO[@]}     -gt 0 ]] && install_go_batch      "All modules - Go"     "${_ALL_GO[@]}"
        [[ ${#_ALL_CARGO[@]}  -gt 0 ]] && install_cargo_batch   "All modules - Rust"   "${_ALL_CARGO[@]}"
        [[ ${#_ALL_GEMS[@]}   -gt 0 ]] && install_gem_batch     "All modules - Ruby"   "${_ALL_GEMS[@]}"
        [[ ${#_ALL_GIT[@]}    -gt 0 ]] && install_git_batch     "All modules - Git"    "${_ALL_GIT[@]}"
        [[ ${#_ALL_BINARY[@]} -gt 0 ]] && install_binary_releases "${_ALL_BINARY[@]}"
    fi

    # Track batch-stage failures (not counted as a module — tools span multiple modules)
    local _batch_failures=$TOTAL_TOOL_FAILURES
    local _batch_stage_failed=false
    if [[ "$_batch_failures" -gt 0 ]]; then
        _batch_stage_failed=true
        log_warn "Batch install stages: $_batch_failures tool(s) failed (see log for details)"
    fi

    # Stage 4/4: Module-specific custom logic ──
    # Set _SKIP_BATCH_REINSTALL so batch functions (apt, pipx, go, cargo, gems,
    # git, binary) return immediately — only custom logic runs (Docker, builds,
    # special installers like ZAP/Metasploit, direct download_github_release calls).
    echo ""
    log_info "Stage 4/4: Running module-specific setup (Docker, builds, special installers)..."
    _SKIP_BATCH_REINSTALL=true

    for mod in "${MODULES_TO_INSTALL[@]}"; do
        local func_name="install_module_${mod}"

        if declare -f "$func_name" > /dev/null 2>&1; then
            local _mod_start; _mod_start=$(date +%s)
            log_debug "install_modules: starting module '$mod' (custom logic)"
            local _pre_failures=$TOTAL_TOOL_FAILURES

            echo ""
            log_info "━━━━━ Module: $mod ━━━━━"

            # Batch tools (apt/pipx/go/cargo/gems/git/binary) were already installed
            # in Stage 3 — show confirmation, then run module-specific custom logic.
            if [[ "$_batch_stage_failed" == "true" ]]; then
                log_warn "Batch install phase had prior failures; running custom setup only"
            else
                log_success "Batch install phase completed successfully"
            fi
            "$func_name" 2>&1 || true

            if [[ $TOTAL_TOOL_FAILURES -gt $_pre_failures ]]; then
                local _mod_fails=$((TOTAL_TOOL_FAILURES - _pre_failures))
                log_warn "Module $mod: $_mod_fails tool(s) failed"
                TOTAL_MODULE_FAILURES=$((TOTAL_MODULE_FAILURES + 1))
            fi
            local _mod_elapsed=$(( $(date +%s) - _mod_start ))
            log_debug "install_modules: module '$mod' completed in ${_mod_elapsed}s"
        else
            log_warn "No install function for module: $mod"
        fi
    done

    _SKIP_BATCH_REINSTALL=false
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
