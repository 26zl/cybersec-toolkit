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
#   ./install.sh --doctor                    # Check environment readiness
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
PRODUCTION_MODE="${PRODUCTION_MODE:-false}"
# Track which flags were explicitly set on the CLI (for profile override logic)
_CLI_SET_SKIP_HEAVY=false
_CLI_SET_ENABLE_DOCKER=false
_CLI_SET_INCLUDE_C2=false
FAST_MODE="${FAST_MODE:-false}"
ROLLBACK_TARGET=""
FORCE_YES="${FORCE_YES:-false}"

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
  --skip-go            Skip all Go tool installs (and the Go SDK bootstrap)
  --skip-cargo         Skip all Cargo (Rust) tool installs (and the rustup bootstrap)
  --skip-gems          Skip all Ruby gem installs
  --skip-git           Skip all git clone installs
  --skip-binary        Skip all binary release downloads
  --skip-source        Skip build-from-source, snap, npm, and curl-pipe installs
  --fast               Skip checksum verification for faster binary downloads
                         (mutually exclusive with --require-checksums)
  --require-checksums  Fail if a binary release has no checksum file
  --production         Security preset: require available upstream checksums
                         and reject unverified binary/Go release downloads.
                         Rolling source installs are still upstream-latest.
  --enable-docker      Pull Docker images (C2 frameworks, IR platforms, MobSF, etc.)
  --include-c2         Install C2 + phishing frameworks (Sliver, Caldera, Loki-C2,
                         gophish, evilginx, SET, …; Empire also needs --enable-docker)
  --dry-run            Show what would be installed without installing
  -j, --parallel <N>   Number of parallel install jobs (default: 4, 1=sequential)
  -v, --verbose        Enable debug logging and system environment dump
  --list-profiles      List available profiles and exit
  --list-modules       List available modules and exit
  --list-sessions      List install sessions and exit
  --rollback <id|last> Rollback tools installed in a session
  -y, --yes, --force   Assume "yes" for destructive prompts (e.g. --rollback);
                         required to run --rollback non-interactively
  --version            Show installer version and exit
  --doctor             Check environment readiness (distro, prerequisites,
                         MCP server, skills, tool registry) and exit
  -h, --help           Show this help and exit

All runtimes (Python, Go, Ruby, Rust, Java) and dev libraries are
installed automatically. Only Docker requires manual installation.

Environment variables:
  GITHUB_TOOL_DIR      Where to clone GitHub repos (default: /opt)
  GITHUB_TOKEN         GitHub personal access token for API requests
                         (avoids rate limits on binary downloads)
  GO_MIN_VERSION       Minimum Go version before auto-upgrade (default: 1.21)
  VERBOSE              Enable verbose/debug output (default: false)
  NO_COLOR             Disable ANSI colors and use ASCII separators
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

# Read-only environment readiness report. Reuses the sourced distro detection,
# color, and command_exists helpers; points at verify.sh for the installed-tool
# census instead of duplicating it. Exits 1 only when a required prerequisite is
# missing on a supported host, so it is usable as a CI/preflight gate.
run_doctor() {
    local _req_missing=0 _warns=0
    local _sep="  ------------------------------------------------"

    _doctor_row() { # label  detail  status(ok|info|warn|missing)
        local _c _tag
        case "$3" in
            ok)      _c="$GREEN";  _tag="ok" ;;
            info)    _c="$BLUE";   _tag="info" ;;
            warn)    _c="$YELLOW"; _tag="warn" ;;
            missing) _c="$RED";    _tag="fail" ;;
            *)       _c="$NC";     _tag="$3" ;;
        esac
        # Status tag leads so the free-form detail column can be any length
        # without colliding with it.
        # %b renders the color escapes on the tag only; label and detail print
        # as literal %s so a path containing a backslash is never interpreted.
        printf '  %b %-13s %s\n' "${_c}$(printf '%-6s' "[${_tag}]")${NC}" "$1" "$2"
    }

    _doctor_req() { # cmd  hint
        if command_exists "$1"; then
            _doctor_row "$1" "$(command -v "$1")" ok
        else
            _doctor_row "$1" "REQUIRED — $2" missing
            _req_missing=$((_req_missing + 1))
        fi
    }

    echo ""
    printf '%b\n' "  ${BOLD}cybersec-toolkit doctor${NC}${INSTALLER_VERSION:+  v${INSTALLER_VERSION}}"
    echo "$_sep"

    if [[ -n "${UNSUPPORTED_HOST_OS:-}" ]]; then
        _doctor_row "Host" "$DISTRO_NAME — installer targets Linux/Termux" warn
        _warns=$((_warns + 1))
    elif [[ "$PKG_MANAGER" == "unknown" ]]; then
        _doctor_row "Host" "$DISTRO_NAME — no supported package manager" missing
        _req_missing=$((_req_missing + 1))
    else
        _doctor_row "Host" "$DISTRO_NAME ($PKG_MANAGER)" ok
    fi

    echo "$_sep"

    _doctor_req git "install git"
    if command_exists curl || command_exists wget; then
        _doctor_row "curl/wget" "$(command -v curl || command -v wget)" ok
    else
        _doctor_row "curl/wget" "REQUIRED — install curl or wget" missing
        _req_missing=$((_req_missing + 1))
    fi
    _doctor_req python3 "install python3"

    echo "$_sep"

    if command_exists uv; then
        if [[ -f "$SCRIPT_DIR/mcp_server/server.py" ]]; then
            _doctor_row "MCP server" "ready — 'make mcp' or /mcp" ok
        else
            _doctor_row "MCP server" "uv ok, mcp_server/ missing" warn
            _warns=$((_warns + 1))
        fi
    else
        _doctor_row "MCP server" "install 'uv' to enable" warn
        _warns=$((_warns + 1))
    fi

    local _rt
    for _rt in go cargo pipx gem npm docker; do
        if command_exists "$_rt"; then
            _doctor_row "$_rt" "$(command -v "$_rt")" ok
        else
            _doctor_row "$_rt" "bootstrapped on demand" info
        fi
    done

    echo "$_sep"

    local _skills
    _skills=$(find "$SCRIPT_DIR/.claude/skills" -maxdepth 2 -name SKILL.md 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${_skills:-0}" -gt 0 ]]; then
        _doctor_row "Skills" "$_skills discoverable" ok
    else
        _doctor_row "Skills" "none found under .claude/skills" info
    fi

    local _tools=""
    if command_exists python3 && [[ -f "$SCRIPT_DIR/tools_config.json" ]]; then
        _tools=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d) if isinstance(d,list) else len(d.get("tools",d)) if isinstance(d,dict) else 0)' "$SCRIPT_DIR/tools_config.json" 2>/dev/null)
    fi
    if [[ -n "$_tools" ]]; then
        _doctor_row "Registry" "$_tools tools — installed: verify.sh --summary" ok
    else
        _doctor_row "Registry" "tools_config.json unreadable" warn
        _warns=$((_warns + 1))
    fi

    echo "$_sep"

    if [[ -n "${UNSUPPORTED_HOST_OS:-}" ]]; then
        printf '%b\n' "  ${BLUE}note${NC}: the installer targets Linux/Termux; the MCP server and skills work on any OS."
        exit 0
    elif [[ "$_req_missing" -gt 0 ]]; then
        printf '%b\n' "  ${RED}not ready${NC}: ${_req_missing} required prerequisite(s) missing (see REQUIRED above)."
        exit 1
    elif [[ "$_warns" -gt 0 ]]; then
        printf '%b\n' "  ${YELLOW}ready with warnings${NC}: ${_warns} item(s) to review; core install will work."
        exit 0
    else
        printf '%b\n' "  ${GREEN}ready${NC}: environment looks good for installation."
        exit 0
    fi
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
        --production)      PRODUCTION_MODE=true; shift ;;
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
        --doctor)          run_doctor ;;
        --rollback)        [[ $# -lt 2 ]] && { log_error "--rollback requires a session ID or 'last'"; exit 1; }
                           ROLLBACK_TARGET="$2"; shift 2 ;;
        -y|--yes|--force)  FORCE_YES=true; shift ;;
        --version)         echo "cybersec-toolkit ${INSTALLER_VERSION:-unknown}"; exit 0 ;;
        *)                 log_error "Unknown option: $1"; usage ;;
    esac
done

[[ "$PRODUCTION_MODE" == "true" ]] && REQUIRE_CHECKSUMS=true

if [[ "$FAST_MODE" == "true" && "$REQUIRE_CHECKSUMS" == "true" ]]; then
    log_error "--fast is mutually exclusive with --require-checksums/--production"
    exit 1
fi

# Single-tool install (--tool)
# shellcheck disable=SC2034  # Arrays read via nameref
install_single_tool() {
    local tool="$1"
    # An explicit --tool request overrides method-wide skip flags.
    local SKIP_PIPX=false SKIP_GO=false SKIP_CARGO=false SKIP_GEMS=false
    local SKIP_GIT=false SKIP_BINARY=false SKIP_SOURCE=false

    # Provenance: was the tool already on the system before we touched it? If so it
    # is recorded "existing" so --rollback/remove never uninstall what the user had.
    # command_exists covers the command-producing methods; the pkg branch overrides
    # this with pkg_is_installed (a library package is not a command), and git/source
    # use _tree_provenance on their dest dir.
    # Present AND not something a previous run of ours installed — otherwise a
    # second --tool run would see our own install and mark it unremovable (the same
    # sticky rule the batch installers use via _is_preexisting).
    local _pre=false
    if command_exists "$tool" && { ! _version_known "$tool" || _is_preexisting "$tool"; }; then
        _pre=true
    fi
    _track_single() {  # $1=method  $2=version when newly installed (default: latest)
        if [[ "$_pre" == true ]]; then
            track_version "$tool" "$1" "existing"
        else
            track_version "$tool" "$1" "${2:-latest}"
        fi
    }

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

    # APT packages — array names derived from ALL_MODULES so new modules are
    # picked up automatically (nonexistent arrays are skipped by _arr_has).
    local pkg_arrs=(SHARED_BASE_PACKAGES)
    _module_array_names PACKAGES pkg_arrs
    _module_array_names HEAVY_PACKAGES pkg_arrs
    for a in "${pkg_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            local _tmp_pkg=("$tool")
            fixup_package_names _tmp_pkg
            if [[ ${#_tmp_pkg[@]} -eq 0 ]]; then
                log_warn "$tool is not available on this distro — skipped"
                return 0
            fi
            # A library package is not a command, so re-derive provenance by query.
            if pkg_is_installed "${_tmp_pkg[0]}" && { ! _version_known "$tool" || _is_preexisting "$tool"; }; then
                _pre=true
            else
                _pre=false
            fi
            log_info "Installing ${_tmp_pkg[*]} via $PKG_MANAGER..."
            if pkg_install "${_tmp_pkg[@]}" >> "$LOG_FILE" 2>&1; then
                log_success "Installed: ${_tmp_pkg[*]}"
                _track_single "$PKG_MANAGER"
            else
                log_error "Failed: ${_tmp_pkg[*]}"
                return 1
            fi
            return 0
        fi
    done

    # pipx
    local pipx_arrs=(); _module_array_names PIPX pipx_arrs
    for a in "${pipx_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via pipx..."
            ensure_pipx
            if pipx_install "$tool" >> "$LOG_FILE" 2>&1; then
                log_success "Installed: $tool"
                _track_single "pipx"
            else
                log_error "Failed: $tool"
                return 1
            fi
            return 0
        fi
    done

    # Go (match binary name from full import path)
    local go_arrs=(); _module_array_names GO go_arrs
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
                _gobin_stage=$(mktemp -d "${TMPDIR:-/tmp}/cybersec-gobin.XXXXXX")
                _register_cleanup "$_gobin_stage"
                if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER:-}" != "root" ]]; then
                    _chown_for_builder "$_gobin_stage"
                    chown -R "$SUDO_USER" "$GOPATH" 2>/dev/null || true
                fi
                _go_gopath_esc="$(_escape_single_quoted "$GOPATH")"
                _go_gobin_esc="$(_escape_single_quoted "$_gobin_stage")"
                _go_pkg_esc="$(_escape_single_quoted "$gopkg")"
                if _as_builder "GOPATH='$_go_gopath_esc' GOBIN='$_go_gobin_esc' $(_builder_cmd go) install $_go_pkg_esc" >> "$LOG_FILE" 2>&1 \
                    && [[ -f "$_gobin_stage/$tool" ]] && mv "$_gobin_stage/$tool" "$GOBIN/$tool" && chmod +x "$GOBIN/$tool"; then
                    log_success "Installed: $tool"
                    _track_single "go"
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
    local cargo_arrs=(); _module_array_names CARGO cargo_arrs
    for a in "${cargo_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            ensure_cargo || { log_error "Cargo not available — cannot install $tool"; return 1; }
            log_info "Installing $tool via cargo..."
            local _tool_esc; _tool_esc="$(_escape_single_quoted "$tool")"
            if _as_builder "$(_builder_cmd cargo) install $_tool_esc" >> "$LOG_FILE" 2>&1; then
                log_success "Installed: $tool"
                _track_single "cargo"
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
    local gem_arrs=(); _module_array_names GEMS gem_arrs
    for a in "${gem_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via gem..."
            local _tool_esc; _tool_esc="$(_escape_single_quoted "$tool")"
            if _as_builder "$(_builder_cmd gem) install $_tool_esc --no-document" >> "$LOG_FILE" 2>&1; then
                # Symlink gem binary to PIPX_BIN_DIR (consistent with batch installer).
                # Glob the ruby-version dir directly — do not store a literal '*'.
                local _gdir
                for _gdir in "$(_builder_home)/.local/share/gem/ruby"/*/bin; do
                    [[ -f "$_gdir/$tool" ]] && ln -sf "$_gdir/$tool" "$PIPX_BIN_DIR/$tool" 2>/dev/null || true
                done
                log_success "Installed: $tool"
                _track_single "gem"
            else
                log_error "Failed: $tool"
                return 1
            fi
            return 0
        fi
    done

    # Git repos (match name= prefix)
    local git_arrs=(); _module_array_names GIT git_arrs
    for a in "${git_arrs[@]}"; do
        declare -p "$a" &>/dev/null || continue
        local -n _gitref="$a"
        [[ ${#_gitref[@]} -eq 0 ]] && continue
        for entry in "${_gitref[@]}"; do
            local gname="${entry%%=*}"
            if [[ "$gname" == "$tool" ]]; then
                local url="${entry#*=}"
                local dest="$GITHUB_TOOL_DIR/$gname"
                local _gver; _gver=$(_tree_provenance "$gname" "$dest/.git")
                log_info "Cloning $tool..."
                if git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1; then
                    setup_git_repo "$dest" >> "$LOG_FILE" 2>&1 || log_warn "setup_git_repo failed for $tool"
                    log_success "Installed: $tool → $dest"
                    track_version "$tool" "git" "$_gver"
                else
                    log_error "Failed: $tool"
                    return 1
                fi
                return 0
            fi
        done
    done

    # GitHub binary releases
    local binary_arr
    while IFS= read -r binary_arr; do
        declare -p "$binary_arr" &>/dev/null || continue
        local -n _binary_ref="$binary_arr"
        [[ ${#_binary_ref[@]} -eq 0 ]] && continue
        for entry in "${_binary_ref[@]}"; do
            IFS='|' read -r _repo _binary _pattern _dest _archive_binary <<< "$entry"
            local _registry_name="$_binary"
            case "$_binary" in
                d2j-dex2jar) _registry_name="dex2jar" ;;
                heimdall) _registry_name="heimdall-rs" ;;
            esac
            if [[ "$tool" == "$_binary" || "$tool" == "$_registry_name" ]]; then
                log_info "Installing $tool from GitHub releases..."
                download_github_release \
                    "$_repo" "$_binary" "$_pattern" "${_dest:-$PIPX_BIN_DIR}" "${_archive_binary:-$_binary}"
                return $?
            fi
        done
    done < <(compgen -A variable BINARY_RELEASES_ | sort)

    # Build-from-source registries
    local mod prefix names_var
    for mod in "${ALL_MODULES[@]}"; do
        prefix="$(_module_prefix "$mod")"
        names_var="${prefix}_BUILD_NAMES"
        declare -p "$names_var" &>/dev/null || continue
        local -n _build_names="$names_var"
        for _build_name in "${_build_names[@]}"; do
            if [[ "$_build_name" == "$tool" ]]; then
                local -n _build_urls="${prefix}_BUILD_URLS"
                local -n _build_cmds="${prefix}_BUILD_CMDS"
                log_info "Building $tool from source..."
                build_from_source "$tool" "${_build_urls[$tool]:-}" "${_build_cmds[$tool]:-}"
                return $?
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
            _track_single "npm" "$_pf_ver"
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
    _init_log_file "$SCRIPT_DIR/cybersec_install.log"
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

    RB_SCHEMA=$(sed -n 's/^# Schema: \([0-9]\{1,\}\).*/\1/p' "$ROLLBACK_FILE" | head -1)
    RB_SCHEMA="${RB_SCHEMA:-1}"

    # Parse installed tools from manifest (skip comments and failed entries)
    declare -a RB_TOOLS=()
    declare -a RB_METHODS=()
    while IFS='|' read -r rb_tool rb_method rb_action _; do
        [[ "$rb_tool" == \#* ]] && continue
        [[ "$rb_action" == "installed" ]] || continue
        # Reject empty or path-bearing names before destructive rm/uninstall.
        if [[ -z "$rb_tool" || "$rb_tool" == */* || "$rb_tool" == *..* ]]; then
            log_warn "Skipping invalid rollback entry: '${rb_tool}'"
            continue
        fi
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
    log_info "Tools already present before this session are not listed — they stay."
    echo ""

    # Confirm — rollback is destructive (uninstalls, rm -rf of cloned/built trees,
    # pkg_remove of this session's system packages). Require an interactive
    # confirmation, or an explicit --yes/--force when non-interactive (pipe/CI/cron).
    if [[ -t 0 ]]; then
        read -rp "$(echo -e "${YELLOW}[!]${NC} Proceed with rollback? [y/N] ")" _rb_answer
        case "$_rb_answer" in
            [yY]|[yY][eE][sS]) ;;
            *) log_info "Rollback cancelled."; exit 0 ;;
        esac
    elif [[ "$FORCE_YES" != "true" ]]; then
        log_error "Refusing to run destructive rollback non-interactively without confirmation."
        log_error "Re-run with --yes (or --force) to proceed unattended."
        exit 1
    fi

    # _rb_forget_version — drop a tool's row from .versions.
    _rb_forget_version() {
        local _tool="$1"
        [[ -f "$SCRIPT_DIR/.versions" ]] || return 0
        _rb_versions_write() {
            local _tmp_ver
            _tmp_ver=$(mktemp "${SCRIPT_DIR}/.versions.XXXXXX")
            grep -v "^${_tool}|" "$SCRIPT_DIR/.versions" > "$_tmp_ver" 2>/dev/null || true
            mv -f "$_tmp_ver" "$SCRIPT_DIR/.versions"
        }
        if command -v flock &>/dev/null; then
            ( flock -x 200; _rb_versions_write ) 200>"${SCRIPT_DIR}/.versions.lock"
        else
            _rb_versions_write
        fi
    }

    # System packages are collected and removed LAST: they provide the runtimes
    # (python3, ruby, go) every step above needs. Only packages this run installed
    # reach that list — pre-existing ones are recorded "existing", not "installed".
    rb_removed=0
    rb_skipped=0
    rb_failed=0
    declare -a RB_SYS_PKGS=()
    declare -A RB_SYS_SEEN=()
    for i in "${!RB_TOOLS[@]}"; do
        rb_tool="${RB_TOOLS[$i]}"
        rb_method="${RB_METHODS[$i]}"
        # _rb_ok is the post-condition, not the exit code: `rm -f` succeeds on a
        # file that was never there, and `cargo uninstall` fails for a crate that
        # was binstalled rather than compiled. What matters is whether the artifact
        # is actually gone afterwards.
        _rb_ok=true
        case "$rb_method" in
            pipx)
                if command_exists pipx; then
                    pipx uninstall "$rb_tool" >> "$LOG_FILE" 2>&1 || true
                    pipx list --short 2>/dev/null |
                        awk -v t="$rb_tool" 'tolower($1)==tolower(t){f=1} END{exit !f}' && _rb_ok=false
                fi
                ;;
            go)
                rm -f "$GOBIN/$rb_tool" 2>/dev/null || true
                [[ -e "$GOBIN/$rb_tool" ]] && _rb_ok=false
                ;;
            cargo)
                if command_exists cargo; then
                    cargo uninstall "$rb_tool" >> "$LOG_FILE" 2>&1 || true
                fi
                rm -f "$PIPX_BIN_DIR/$rb_tool" 2>/dev/null || true
                rm -f "$(_builder_home)/.cargo/bin/$rb_tool" 2>/dev/null || true
                { [[ -e "$PIPX_BIN_DIR/$rb_tool" ]] || [[ -e "$(_builder_home)/.cargo/bin/$rb_tool" ]]; } && _rb_ok=false
                ;;
            gem)
                if command_exists gem; then
                    # Gems install into the invoking user's store; uninstall as that user, not root.
                    _as_builder "$(_builder_cmd gem) uninstall '$(_escape_single_quoted "$rb_tool")' -x --force" \
                        >> "$LOG_FILE" 2>&1 || _rb_ok=false
                fi
                ;;
            git)
                rb_dir="$GITHUB_TOOL_DIR/$rb_tool"
                [[ -d "$rb_dir" ]] && { rm -rf "$rb_dir" 2>/dev/null || true; }
                rm -f "$PIPX_BIN_DIR/$rb_tool" 2>/dev/null || true
                rm -f "$PIPX_BIN_DIR/${rb_tool,,}" 2>/dev/null || true
                [[ -e "$rb_dir" ]] && _rb_ok=false
                ;;
            binary)
                rm -f "$PIPX_BIN_DIR/$rb_tool" 2>/dev/null || true
                [[ -e "$PIPX_BIN_DIR/$rb_tool" ]] && _rb_ok=false
                ;;
            source)
                remove_source_build "$rb_tool" || _rb_ok=false
                ;;
            special)
                remove_special_tool "$rb_tool"
                case $? in
                    0) ;;
                    2) _rb_ok=false ;;
                    *) log_info "  Skipping $rb_tool (special — no known uninstaller)"
                       rb_skipped=$((rb_skipped + 1))
                       continue ;;
                esac
                ;;
            snap)
                if remove_snap_tool "$rb_tool"; then
                    :
                else
                    log_info "  Skipping $rb_tool (snap — no known uninstaller)"
                    rb_skipped=$((rb_skipped + 1))
                    continue
                fi
                ;;
            docker)
                if remove_docker_tool "$rb_tool"; then
                    :
                else
                    log_info "  Skipping $rb_tool (docker — image not in registry)"
                    rb_skipped=$((rb_skipped + 1))
                    continue
                fi
                ;;
            apt|dnf|pacman|zypper|pkg)
                # Schema 1 manifests predate provenance tracking: every package in
                # them looks self-installed, so removing one could take out
                # something the user already had. Skip system packages for them.
                if [[ "$RB_SCHEMA" -lt 2 ]]; then
                    log_info "  Skipping system package: $rb_tool (pre-provenance manifest)"
                    rb_skipped=$((rb_skipped + 1))
                    continue
                fi
                # Deferred to a single pkg_remove after the loop — see above.
                if [[ -z "${RB_SYS_SEEN[$rb_tool]:-}" ]]; then
                    RB_SYS_SEEN["$rb_tool"]=1
                    RB_SYS_PKGS+=("$rb_tool")
                fi
                continue
                ;;
            *)
                log_info "  Skipping $rb_tool ($rb_method — unknown method)"
                rb_skipped=$((rb_skipped + 1))
                continue
                ;;
        esac

        # Only drop the .versions row once the tool is actually gone. Forgetting it
        # after a failed removal leaves an installed tool with no record, which the
        # next run reads as pre-existing and then refuses to ever remove.
        if [[ "$_rb_ok" != "true" ]]; then
            log_warn "Still present after removal attempt: $rb_tool ($rb_method) — keeping its .versions entry"
            rb_failed=$((rb_failed + 1))
            continue
        fi
        _rb_forget_version "$rb_tool"
        rb_removed=$((rb_removed + 1))
        log_success "Removed: $rb_tool ($rb_method)"
    done

    # One transaction so the package manager resolves dependencies once.
    if [[ ${#RB_SYS_PKGS[@]} -gt 0 ]]; then
        echo ""
        log_info "Removing ${#RB_SYS_PKGS[@]} system package(s) this session installed..."
        if pkg_remove "${RB_SYS_PKGS[@]}" >> "$LOG_FILE" 2>&1; then
            for rb_tool in "${RB_SYS_PKGS[@]}"; do
                _rb_forget_version "$rb_tool"
            done
            rb_removed=$((rb_removed + ${#RB_SYS_PKGS[@]}))
            log_success "System packages: ${#RB_SYS_PKGS[@]} removed ($PKG_MANAGER)"
        else
            log_warn "Some system packages failed to remove — see $LOG_FILE"
            rb_failed=$((rb_failed + ${#RB_SYS_PKGS[@]}))
        fi
    fi

    echo ""
    if [[ "$rb_failed" -gt 0 ]]; then
        log_warn "Rollback incomplete: $rb_removed removed, $rb_skipped skipped, $rb_failed still present"
    else
        log_success "Rollback complete: $rb_removed removed, $rb_skipped skipped"
    fi

    # Keep the manifest when anything survived, so the run can be retried after the
    # cause is fixed. Renaming it regardless would strand those tools: still
    # installed, no .versions row, and no manifest left to roll back from.
    if [[ "$rb_failed" -eq 0 ]]; then
        mv "$ROLLBACK_FILE" "${ROLLBACK_FILE%.manifest}.rolled_back" 2>/dev/null || true
    else
        log_info "Manifest kept — re-run --rollback $ROLLBACK_SESSION once the failures above are resolved"
    fi
    exit "$([[ "$rb_failed" -eq 0 ]] && echo 0 || echo 1)"
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
    _validate_module_names "use --list-modules to see available modules" "${SELECTED_MODULES[@]}"
    MODULES_TO_INSTALL=("${SELECTED_MODULES[@]}")
else
    # Default: full install
    MODULES_TO_INSTALL=("${ALL_MODULES[@]}")
fi

# Export flags for modules
export SKIP_HEAVY SKIP_PIPX SKIP_GO SKIP_CARGO SKIP_GEMS SKIP_GIT SKIP_BINARY SKIP_SOURCE
export ENABLE_DOCKER INCLUDE_C2 REQUIRE_CHECKSUMS PRODUCTION_MODE FAST_MODE UPGRADE_SYSTEM VERBOSE PARALLEL_JOBS

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
        # tools_config.json is compact (one JSON object per line), so method and
        # module live on the same record. Extract both with match() per line.
        read -r snap_count special_count docker_count < <(awk -v mods="$_mod_list" '
            {
                method = ""; mod = ""
                if (match($0, /"method"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
                    method = substr($0, RSTART, RLENGTH)
                    sub(/.*"method"[[:space:]]*:[[:space:]]*"/, "", method)
                    sub(/".*/, "", method)
                }
                if (match($0, /"module"[[:space:]]*:[[:space:]]*"[^"]*"/)) {
                    mod = substr($0, RSTART, RLENGTH)
                    sub(/.*"module"[[:space:]]*:[[:space:]]*"/, "", mod)
                    sub(/".*/, "", mod)
                }
                if (mod != "" && mod ~ "^(" mods ")$") {
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

# _apply_platform_module_filters — apply host-specific module/flag overrides to
# MODULES_TO_INSTALL and ENABLE_DOCKER. Called from BOTH the dry-run preview and
# main() so the preview reflects what a real run actually does on Termux/WSL.
# (The ARM x86-only binary-release filter lives in install_binary_releases,
# which operates on per-module binary arrays, not on MODULES_TO_INSTALL.)
_apply_platform_module_filters() {
    # Termux: Docker and snap are not available
    if [[ "$PKG_MANAGER" == "pkg" ]] && [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        log_warn "Docker is not available on Termux/Android — skipping Docker tools"
        ENABLE_DOCKER="false"
    fi

    # WSL: wireless module requires hardware access not available under WSL
    if [[ "$IS_WSL" == "true" ]]; then
        local _wsl_filtered=()
        local _mod
        for _mod in "${MODULES_TO_INSTALL[@]}"; do
            if [[ "$_mod" == "wireless" ]]; then
                log_warn "Skipping wireless module on WSL (no hardware access)"
            else
                _wsl_filtered+=("$_mod")
            fi
        done
        # Guard empty-array expansion under set -u (bash 4.3) — matches the ARM
        # filter in lib/installers.sh. Reachable via `--module wireless` on WSL.
        if [[ ${#_wsl_filtered[@]} -gt 0 ]]; then
            MODULES_TO_INSTALL=("${_wsl_filtered[@]}")
        else
            MODULES_TO_INSTALL=()
        fi
    fi
}

# Dry run
if [[ "$DRY_RUN" == "true" ]]; then
    # Apply the same host filters main() would, so the preview doesn't overstate
    # what runs on Termux/WSL (e.g. the wireless module under WSL).
    _apply_platform_module_filters
    echo ""
    _separator_line "$RED"
    echo -e "  ${RED}${BOLD}DRY RUN${NC}"
    _separator_line "$RED"
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
    echo "Production:     $PRODUCTION_MODE"
    echo "Checksums req.: $REQUIRE_CHECKSUMS"
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

    # Termux Docker override + WSL wireless filter (shared with the dry-run path)
    _apply_platform_module_filters

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
    ensure_uv
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
    # Tools tracked in .versions, minus the ones that were already on the system.
    # Counting those too would both overstate the run and break the invariant that
    # this matches the manifest total reported by --list-sessions.
    local tools_installed=0 tools_existing=0
    if [[ -f "$VERSION_FILE" ]]; then
        tools_installed=$(awk -F'|' '!/^#/ && $3 != "existing"' "$VERSION_FILE" 2>/dev/null | wc -l) || tools_installed=0
        tools_existing=$(awk -F'|' '!/^#/ && $3 == "existing"' "$VERSION_FILE" 2>/dev/null | wc -l) || tools_existing=0
    fi
    log_info "Tools installed: $tools_installed"
    [[ "$tools_existing" -gt 0 ]] && log_info "Already present (left alone): $tools_existing"
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

        # Include gated C2 registries in the normal batch flow.
        if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
            _append_module_array _ALL_GIT    "${_pfx}_C2_GIT"
            _append_module_array _ALL_BINARY "BINARY_RELEASES_${_mod_upper}_C2"
        fi
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
        # Parallel: launch all batches as concurrent subshells
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

        # Subshells redirect stdout to /dev/null so log_message() output doesn't interleave on the terminal; the log file and PROGRESS_DIR still get everything via their own explicit redirects.
        local _method_names=()
        local _job_pids=()

        # Pre-write method totals from the main process so the progress display has them immediately; batch subshells later re-write the same values idempotently via a direct PROGRESS_DIR redirect (unaffected by `> /dev/null`).
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
        # Sequential: PARALLEL_JOBS=1, run each batch inline
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
