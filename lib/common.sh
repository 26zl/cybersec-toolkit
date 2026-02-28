#!/bin/bash
# common.sh — Shared library for cybersec-tools-installer
# Source this file: source "$SCRIPT_DIR/lib/common.sh"

# Bash 4.3+ required for local -n (nameref) used throughout the codebase
if [[ -z "${BASH_VERSION:-}" ]] || [[ "${BASH_VERSINFO[0]}" -lt 4 ]] || \
   [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -lt 3 ]]; then
    echo "ERROR: bash 4.3+ is required (found: ${BASH_VERSION:-none})" >&2
    echo "  On macOS: brew install bash" >&2
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configurable defaults (GITHUB_TOOL_DIR set after distro detection — see path block below)
VERSION_FILE="${VERSION_FILE:-${SCRIPT_DIR:-.}/.versions}"
LOG_FILE="${LOG_FILE:-/dev/null}"
VERBOSE="${VERBOSE:-false}"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"
# Installer version (read from VERSION file at repo root)
INSTALLER_VERSION=""
if [[ -f "${SCRIPT_DIR:-.}/VERSION" ]]; then
    INSTALLER_VERSION=$(< "${SCRIPT_DIR:-.}/VERSION")
    INSTALLER_VERSION="${INSTALLER_VERSION%%[[:space:]]}"  # strip trailing whitespace/newline
fi
# Validate PARALLEL_JOBS: must be a positive integer, clamped to 1-16
if [[ ! "$PARALLEL_JOBS" =~ ^[0-9]+$ ]] || [[ "$PARALLEL_JOBS" -lt 1 ]]; then
    PARALLEL_JOBS=4
elif [[ "$PARALLEL_JOBS" -gt 16 ]]; then
    PARALLEL_JOBS=16
fi

# Temp file cleanup registry — tracks all mktemp paths for SIGINT/SIGTERM cleanup.
# Every mktemp call should be followed by: _register_cleanup "$var"
_CLEANUP_PATHS=()

_register_cleanup() { _CLEANUP_PATHS+=("$1"); }

_global_cleanup() {
    for p in "${_CLEANUP_PATHS[@]+"${_CLEANUP_PATHS[@]}"}"; do
        [[ -e "$p" ]] && { rm -rf "$p" 2>/dev/null || true; }
    done
    _cleanup_global_semaphore 2>/dev/null || true
    _cleanup_progress_dir 2>/dev/null || true
    type -t _gh_api_cache_cleanup &>/dev/null && _gh_api_cache_cleanup 2>/dev/null || true
}

# ── Session tracking for rollback ──
# Each install run creates a manifest in .install_sessions/<id>.manifest
# Used by --rollback and --list-sessions.
_SESSION_FILE=""
_SESSION_ID=""

_init_session() {
    local profile="${1:-full}"
    local modules="${2:-}"
    local session_dir="${SCRIPT_DIR:-.}/.install_sessions"
    mkdir -p "$session_dir" 2>/dev/null || true
    _SESSION_ID="$(date '+%Y%m%d_%H%M%S')_$$"
    _SESSION_FILE="$session_dir/${_SESSION_ID}.manifest"
    {
        echo "# Session: $_SESSION_ID"
        echo "# Started: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Version: ${INSTALLER_VERSION:-unknown}"
        echo "# Profile: $profile"
        echo "# Modules: $modules"
        echo "# tool|method|action|timestamp"
    } > "$_SESSION_FILE"
    chmod 644 "$_SESSION_FILE" 2>/dev/null || true
}

_finalize_session() {
    local status="${1:-complete}"
    [[ -n "$_SESSION_FILE" && -f "$_SESSION_FILE" ]] || return 0
    {
        echo "# Finished: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Status: $status"
    } >> "$_SESSION_FILE"
}

# track_session — record a tool action (installed/failed) in the current session manifest.
# Usage: track_session "nmap" "apt" "installed"
track_session() {
    [[ -n "$_SESSION_FILE" && -f "$_SESSION_FILE" ]] || return 0
    local tool="$1" method="$2" action="$3"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    if command -v flock &>/dev/null; then
        (
            flock -x 200
            printf '%s|%s|%s|%s\n' "$tool" "$method" "$action" "$timestamp" >> "$_SESSION_FILE"
        ) 200>"${_SESSION_FILE}.lock"
    else
        printf '%s|%s|%s|%s\n' "$tool" "$method" "$action" "$timestamp" >> "$_SESSION_FILE"
    fi
}

_list_sessions() {
    local session_dir="${SCRIPT_DIR:-.}/.install_sessions"
    if [[ ! -d "$session_dir" ]] || [[ -z "$(ls -A "$session_dir" 2>/dev/null)" ]]; then
        echo "No install sessions found."
        return 0
    fi
    echo "Install sessions:"
    echo ""
    printf "  %-26s %-10s %-14s %-8s %s\n" "SESSION ID" "STATUS" "PROFILE" "TOOLS" "STARTED"
    printf "  %-26s %-10s %-14s %-8s %s\n" "--------------------------" "----------" "--------------" "--------" "-------------------"
    for f in "$session_dir"/*.manifest; do
        [[ -f "$f" ]] || continue
        local sid started profile status tool_count
        sid=$(basename "$f" .manifest)
        started=$(sed -n 's/^# Started: //p' "$f")
        profile=$(sed -n 's/^# Profile: //p' "$f")
        status=$(sed -n 's/^# Status: //p' "$f")
        [[ -z "$status" ]] && status="interrupted"
        tool_count=$(grep -cv '^#' "$f" 2>/dev/null) || tool_count=0
        printf "  %-26s %-10s %-14s %-8s %s\n" "$sid" "$status" "$profile" "$tool_count" "$started"
    done
    echo ""
}

# Logging
log_message() {
    echo -e "$1"
    if [[ -n "$LOG_FILE" && "$LOG_FILE" != "/dev/null" ]]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE"
    fi
}

log_success() { log_message "${GREEN}[+]${NC} $1"; }
log_info()    { log_message "${BLUE}[*]${NC} $1"; }
log_warn()    { log_message "${YELLOW}[!]${NC} $1"; }
log_error()   { log_message "${RED}[-]${NC} $1"; }
log_debug() {
    [[ "$VERBOSE" == "true" ]] || return 0
    log_message "${CYAN}[D]${NC} $1"
}

# Debug trace (set -x to log file)
enable_debug_trace() {
    [[ "$VERBOSE" == "true" ]] || return 0
    [[ "$LOG_FILE" == "/dev/null" ]] && return 0
    exec {BASH_XTRACEFD}>>"$LOG_FILE"
    export BASH_XTRACEFD
    PS4='+ ${BASH_SOURCE[0]##*/}:${LINENO} (${FUNCNAME[0]:-main}): '
    set -x
}

disable_debug_trace() {
    [[ "$VERBOSE" == "true" ]] || return 0
    set +x 2>/dev/null || true
    if [[ -n "${BASH_XTRACEFD:-}" ]] && [[ "$BASH_XTRACEFD" -gt 2 ]]; then
        exec {BASH_XTRACEFD}>&- 2>/dev/null || true
        unset BASH_XTRACEFD
    fi
}

# _init_log_file — safely initialize a log file with disk-full fallback.
# Sets LOG_FILE to /dev/null if the file cannot be created.
# Usage: _init_log_file "/path/to/logfile.log"
_init_log_file() {
    local path="$1"
    if : > "$path" 2>/dev/null; then
        chmod 600 "$path" 2>/dev/null || true
        LOG_FILE="$path"
    else
        LOG_FILE="/dev/null"
    fi
}

# _setup_verbose — common verbose mode setup (log environment + enable trace).
# Usage: _setup_verbose
_setup_verbose() {
    [[ "$VERBOSE" == "true" ]] || return 0
    log_info "Verbose mode enabled"
    log_system_environment
    enable_debug_trace
}

# Reusable UI primitives
# _separator_line — print a colored horizontal rule using Unicode box-drawing ━
# Usage: _separator_line "$GREEN"   or   _separator_line "$YELLOW"
_separator_line() {
    local _color="${1:-}"
    local _hl=$'\xe2\x94\x81'  # ━ U+2501 BOX DRAWINGS HEAVY HORIZONTAL
    local _line=""
    local _i
    for ((_i = 0; _i < 45; _i++)); do _line+="$_hl"; done
    printf '%b\n' "${_color}${BOLD}${_line}${NC}"
}

# _print_completion_banner — print elapsed time and success/failure banner.
# Usage: _print_completion_banner "$START_TIME" "$FAILURE_COUNT" "Verification"
_print_completion_banner() {
    local start_time="$1" failure_count="$2" label="$3"
    local end_time elapsed minutes seconds_r
    end_time=$(date +%s)
    elapsed=$(( end_time - start_time ))
    minutes=$(( elapsed / 60 ))
    seconds_r=$(( elapsed % 60 ))

    echo ""
    if [[ "$failure_count" -gt 0 ]]; then
        _separator_line "$YELLOW"
        log_warn "$label (${minutes}m ${seconds_r}s)"
        _separator_line "$YELLOW"
    else
        _separator_line "$GREEN"
        log_success "$label (${minutes}m ${seconds_r}s)"
        _separator_line "$GREEN"
    fi
}

# System environment logging
log_system_environment() {
    log_info "━━━━━ System Environment ━━━━━"
    log_info "  Hostname: $(hostname 2>/dev/null || echo unknown)"
    log_info "  Kernel:   $(uname -r 2>/dev/null || echo unknown)"
    log_info "  Arch:     $(uname -m 2>/dev/null || echo unknown)"
    log_info "  Distro:   ${DISTRO_NAME:-unknown} (${DISTRO_ID:-unknown})"
    log_info "  WSL:      $IS_WSL"
    log_info "  ARM:      $IS_ARM"
    log_info "  Shell:    BASH ${BASH_VERSION:-unknown}"
    log_info "  Disk:     $(df -h / 2>/dev/null | awk 'NR==2{print $4 " free of " $2}' || echo unknown)"
    log_info "  Memory:   $(free -h 2>/dev/null | awk '/^Mem:/{print $7 " free of " $2}' || echo unknown)"
    log_info "━━━━━ Runtime Versions ━━━━━"
    local -a _cmds=(python3 pipx go cargo ruby gem git docker curl make gcc java)
    for _cmd in "${_cmds[@]}"; do
        if command -v "$_cmd" &>/dev/null; then
            local _ver=""
            case "$_cmd" in
                python3) _ver=$(python3 --version 2>&1) ;;
                pipx)    _ver=$(pipx --version 2>&1) ;;
                go)      _ver=$(go version 2>&1) ;;
                cargo)   _ver=$(cargo --version 2>&1) ;;
                ruby)    _ver=$(ruby --version 2>&1) ;;
                gem)     _ver=$(gem --version 2>&1) ;;
                git)     _ver=$(git --version 2>&1) ;;
                docker)  _ver=$(docker --version 2>&1) ;;
                curl)    _ver=$(curl --version 2>&1 | head -1) ;;
                make)    _ver=$(make --version 2>&1 | head -1) ;;
                gcc)     _ver=$(gcc --version 2>&1 | head -1) ;;
                java)    _ver=$(java -version 2>&1 | head -1) ;;
            esac
            log_info "  $_cmd: $_ver"
        else
            log_info "  $_cmd: NOT FOUND"
        fi
    done
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# _avail_disk_mb — outputs available disk space in MB on the install partition.
# Returns 0 on success, 1 if unavailable. Used by check_disk_space and
# low-disk-space hints in error messages.
_avail_disk_mb() {
    local check_path="/"
    [[ "$PKG_MANAGER" == "pkg" ]] && check_path="${PREFIX:-$HOME}"
    local avail_kb
    avail_kb=$(df -Pk "$check_path" 2>/dev/null | awk 'NR==2{print $4}')
    if [[ -z "$avail_kb" || ! "$avail_kb" =~ ^[0-9]+$ ]]; then
        echo 0; return 1
    fi
    echo $(( avail_kb / 1024 ))
}

# _disk_hint — if available disk < 100MB, returns a hint string for error messages.
# Usage: log_error "Download failed: $binary$(_disk_hint)"
_disk_hint() {
    local mb
    mb=$(_avail_disk_mb 2>/dev/null) || mb=0
    if [[ "$mb" -lt 100 ]]; then
        echo " (disk full — only ${mb}MB free)"
    fi
}

# Disk space check — warns if available space is below estimated requirement.
# Args: $1 = number of modules to install
# Returns 0 always (non-blocking), but prompts user to abort if critically low.
check_disk_space() {
    local num_modules="${1:-18}"

    local avail_mb
    avail_mb=$(_avail_disk_mb 2>/dev/null) || avail_mb=0
    if [[ "$avail_mb" -eq 0 ]]; then
        log_warn "Could not determine available disk space — skipping check"
        return 0
    fi
    local avail_kb=$(( avail_mb * 1024 ))

    # WSL fix: df / shows the virtual ext4 disk (up to 1TB), not actual free
    # space on the Windows host drive. Check /mnt/c and use the lower value.
    if [[ "${IS_WSL:-false}" == "true" ]]; then
        local host_kb
        host_kb=$(df -Pk /mnt/c 2>/dev/null | awk 'NR==2{print $4}')
        if [[ -n "$host_kb" && "$host_kb" =~ ^[0-9]+$ && "$host_kb" -gt 0 ]]; then
            if [[ "$host_kb" -lt "$avail_kb" ]]; then
                avail_kb="$host_kb"
            fi
        fi
    fi
    local avail_gb=$(( avail_kb / 1048576 ))
    local avail_mb=$(( avail_kb / 1024 ))

    # Estimate required space based on module count
    # Base: ~2GB for shared deps + runtimes (Go, Rust, Python venvs, etc.)
    # Per module: ~1.5GB average (packages + git repos + compiled tools)
    # Full install (18 modules): ~25-30GB; lightweight (5 modules): ~8-10GB
    local base_gb=2
    local per_module_mb=1500
    local required_mb=$(( base_gb * 1024 + num_modules * per_module_mb ))
    local required_gb=$(( (required_mb + 1023) / 1024 ))

    # Add extra for Docker images if enabled
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        required_mb=$(( required_mb + 5120 ))  # ~5GB for Docker images
        required_gb=$(( (required_mb + 1023) / 1024 ))
    fi

    log_info "Disk space: ${avail_gb}GB available, ~${required_gb}GB estimated required"

    if [[ "$avail_mb" -lt "$required_mb" ]]; then
        echo ""
        log_warn "Low disk space detected!"
        log_warn "  Available: ${avail_gb}GB (${avail_mb}MB)"
        log_warn "  Estimated: ~${required_gb}GB for ${num_modules} module(s)"
        log_warn "  Tip: Use --profile lightweight or --skip-heavy to reduce disk usage"
        echo ""

        # Critical: less than half the estimated requirement
        local half_required=$(( required_mb / 2 ))
        if [[ "$avail_mb" -lt "$half_required" ]]; then
            log_error "Critically low disk space — installation will likely fail"
        fi

        # Interactive prompt (skip if stdin is not a terminal, e.g. piped/CI)
        if [[ -t 0 ]]; then
            read -rp "$(echo -e "${YELLOW}[!]${NC} Continue anyway? [y/N] ")" _answer
            case "$_answer" in
                [yY]|[yY][eE][sS]) log_info "Continuing despite low disk space..." ;;
                *) log_info "Aborted by user."; exit 0 ;;
            esac
        else
            log_warn "Non-interactive mode — continuing despite low disk space"
        fi
    fi
}

# Go binary name helper

# _go_bin_name — extract the actual binary name from a `go install` path.
# Handles /v2, /v3 module versions and /... wildcard suffixes.
# Examples:
#   github.com/d3mondev/puredns/v2@latest          → puredns
#   github.com/owasp-amass/amass/v4/...@latest      → amass
#   github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest → subfinder
#   github.com/tomnomnom/assetfinder@latest         → assetfinder
_go_bin_name() {
    local path="${1%%@*}"    # strip @latest / @version
    path="${path%/...}"      # strip trailing /...
    local base="${path##*/}" # last path component
    # If it's a Go module version (v2, v3, ...), use the parent component
    if [[ "$base" =~ ^v[0-9]+$ ]]; then
        path="${path%/*}"
        base="${path##*/}"
    fi
    echo "$base"
}

# Enable pacman ParallelDownloads (persistent, one-time)
_PACMAN_PARALLEL_DONE=false
_enable_pacman_parallel_downloads() {
    [[ "$_PACMAN_PARALLEL_DONE" == "true" ]] && return 0
    _PACMAN_PARALLEL_DONE=true
    if [[ -f /etc/pacman.conf ]] && ! grep -q '^ParallelDownloads' /etc/pacman.conf; then
        sed -i 's/^#ParallelDownloads/ParallelDownloads/' /etc/pacman.conf 2>/dev/null || true
    fi
}

# Global concurrency semaphore (FIFO-based)
# Limits total parallel jobs across ALL batch methods to PARALLEL_JOBS.
_GLOBAL_SEM_DIR=""
_GLOBAL_SEM_FIFO=""
_GLOBAL_SEM_FD=""

_init_global_semaphore() {
    _GLOBAL_SEM_DIR=$(mktemp -d "${TMPDIR:-/tmp}/cybersec_sem.XXXXXX")
    _register_cleanup "$_GLOBAL_SEM_DIR"
    _GLOBAL_SEM_FIFO="$_GLOBAL_SEM_DIR/fifo"
    mkfifo "$_GLOBAL_SEM_FIFO"
    exec {_GLOBAL_SEM_FD}<>"$_GLOBAL_SEM_FIFO"
    # Fill with N tokens
    local i
    for ((i = 0; i < PARALLEL_JOBS; i++)); do
        echo "x" >&${_GLOBAL_SEM_FD}
    done
}

_cleanup_global_semaphore() {
    if [[ -n "${_GLOBAL_SEM_FD:-}" ]]; then
        exec {_GLOBAL_SEM_FD}>&- 2>/dev/null || true
        _GLOBAL_SEM_FD=""
    fi
    [[ -n "${_GLOBAL_SEM_DIR:-}" ]] && rm -rf "$_GLOBAL_SEM_DIR" 2>/dev/null || true
    _GLOBAL_SEM_DIR=""
    _GLOBAL_SEM_FIFO=""
}

# Parallel install helpers

# _wait_for_job_slot — acquires a token from the global semaphore (blocks until available).
# Falls back to job-count polling when the semaphore is not initialised.
_wait_for_job_slot() {
    if [[ -n "${_GLOBAL_SEM_FD:-}" ]]; then
        read -r _ <&${_GLOBAL_SEM_FD}
    else
        while [[ $(jobs -rp | wc -l) -ge $PARALLEL_JOBS ]]; do
            wait -n 2>/dev/null || sleep 0.1
        done
    fi
}

# _release_job_slot — returns a token to the global semaphore.
# Must be called when a parallel job finishes (use trap EXIT in subshells).
_release_job_slot() {
    [[ -n "${_GLOBAL_SEM_FD:-}" ]] && { echo "x" >&"${_GLOBAL_SEM_FD}"; } 2>/dev/null || true
}

# _collect_parallel_results — reads temp result files, calls track_version,
# sets _par_failed and _par_skipped for the caller.
# Result file format: line 1 = "ok"/"skip"/"fail", line 2 = version string
_collect_parallel_results() {
    local rdir="$1" method="$2"
    _par_failed=0; _par_skipped=0; _par_dep_warns=0
    for _rf in "$rdir"/*; do
        [[ -f "$_rf" ]] || continue
        local _rname _rstatus _rver
        _rname=$(basename "$_rf")
        _rstatus=$(head -1 "$_rf")
        _rver=$(sed -n '2p' "$_rf")
        case "$_rstatus" in
            ok)            track_version "$_rname" "$method" "$_rver" ;;
            ok:depwarn)    track_version "$_rname" "$method" "$_rver"
                           _par_dep_warns=$((_par_dep_warns + 1)) ;;
            skip)          _par_skipped=$((_par_skipped + 1))
                           track_version "$_rname" "$method" "$_rver" ;;
            skip:depwarn)  _par_skipped=$((_par_skipped + 1))
                           _par_dep_warns=$((_par_dep_warns + 1))
                           track_version "$_rname" "$method" "$_rver" ;;
            fail)          _par_failed=$((_par_failed + 1)) ;;
        esac
    done
    rm -rf "$rdir"
}

# Distro detection
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID,,}"
        DISTRO_ID_LIKE="${ID_LIKE:-}"
        DISTRO_ID_LIKE="${DISTRO_ID_LIKE,,}"
        DISTRO_NAME="${PRETTY_NAME:-$ID}"
    elif command -v lsb_release &>/dev/null; then
        DISTRO_ID="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
        DISTRO_NAME="$(lsb_release -sd)"
        DISTRO_ID_LIKE=""
    else
        DISTRO_ID="unknown"
        DISTRO_NAME="Unknown"
        DISTRO_ID_LIKE=""
    fi
    export DISTRO_ID DISTRO_ID_LIKE DISTRO_NAME
}

# Determine the package-manager family: apt | dnf | pacman | zypper | pkg | unknown
detect_pkg_manager() {
    # Unsupported OS — hard stop on Windows and macOS
    local _kernel
    _kernel="$(uname -s 2>/dev/null || echo unknown)"
    case "$_kernel" in
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            echo ""
            log_error "Windows is not supported."
            log_info "  This installer requires Linux or Termux (Android)."
            log_info "  Use WSL (Windows Subsystem for Linux) instead:"
            log_info "    https://learn.microsoft.com/en-us/windows/wsl/install"
            exit 1
            ;;
        Darwin)
            echo ""
            log_error "macOS is not supported."
            log_info "  This installer requires Linux or Termux (Android)."
            log_info "  On macOS, use a Linux VM or Docker container:"
            log_info "    docker build -t cybersec-installer . && docker run cybersec-installer"
            exit 1
            ;;
    esac

    # Termux on Android — detect before os-release (Termux always sets TERMUX_VERSION)
    if [[ -n "${TERMUX_VERSION:-}" ]]; then
        DISTRO_ID="android"
        DISTRO_ID_LIKE=""
        DISTRO_NAME="Termux"
        export DISTRO_ID DISTRO_ID_LIKE DISTRO_NAME
        PKG_MANAGER="pkg"
        export PKG_MANAGER
        return
    fi

    detect_distro
    case "$DISTRO_ID" in
        debian|ubuntu|kali|parrot|linuxmint|pop|elementary|zorin|mx)
            PKG_MANAGER="apt" ;;
        fedora|rhel|centos|rocky|alma|nobara)
            PKG_MANAGER="dnf" ;;
        arch|manjaro|endeavouros|garuda|artix)
            PKG_MANAGER="pacman" ;;
        opensuse*|sles)
            PKG_MANAGER="zypper" ;;
        *)
            # Fallback: check ID_LIKE
            if [[ "$DISTRO_ID_LIKE" == *"debian"* ]] || [[ "$DISTRO_ID_LIKE" == *"ubuntu"* ]]; then
                PKG_MANAGER="apt"
            elif [[ "$DISTRO_ID_LIKE" == *"fedora"* ]] || [[ "$DISTRO_ID_LIKE" == *"rhel"* ]]; then
                PKG_MANAGER="dnf"
            elif [[ "$DISTRO_ID_LIKE" == *"arch"* ]]; then
                PKG_MANAGER="pacman"
            elif [[ "$DISTRO_ID_LIKE" == *"suse"* ]]; then
                PKG_MANAGER="zypper"
            else
                PKG_MANAGER="unknown"
            fi
            ;;
    esac
    export PKG_MANAGER
}

# Conditional sudo — no-op when already root (EUID=0).
# Prevents failures in minimal containers and environments without sudo.
# Uses env(1) so VAR=val arguments (e.g. DEBIAN_FRONTEND=noninteractive)
# are interpreted correctly in both paths.
maybe_sudo() {
    if [[ $EUID -eq 0 ]]; then
        env "$@"
    else
        sudo env "$@"
    fi
}

# Package manager abstraction
pkg_update() {
    case "$PKG_MANAGER" in
        apt)     maybe_sudo apt-get update -qq ;;
        dnf)     maybe_sudo dnf check-update --setopt=max_parallel_downloads=10 -q || true ;;
        pacman)  _enable_pacman_parallel_downloads; maybe_sudo pacman -Sy --noconfirm ;;
        zypper)  maybe_sudo zypper --non-interactive refresh ;;
        pkg)     pkg update -y ;;
        *)       log_error "Unsupported package manager: $PKG_MANAGER"; return 1 ;;
    esac
}

pkg_install() {
    case "$PKG_MANAGER" in
        apt)     maybe_sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" ;;
        dnf)
            # Handle @group entries separately, then install remaining packages
            local -a _dnf_groups=() _dnf_pkgs=()
            local _arg
            for _arg in "$@"; do
                if [[ "$_arg" == @* ]]; then
                    _dnf_groups+=("${_arg#@}")
                else
                    _dnf_pkgs+=("$_arg")
                fi
            done
            if [[ ${#_dnf_groups[@]} -gt 0 ]]; then
                for _arg in "${_dnf_groups[@]}"; do
                    maybe_sudo dnf group install --setopt=max_parallel_downloads=10 -y -q "$_arg"
                done
            fi
            if [[ ${#_dnf_pkgs[@]} -gt 0 ]]; then
                maybe_sudo dnf install --setopt=max_parallel_downloads=10 -y -q "${_dnf_pkgs[@]}"
            fi
            ;;
        pacman)  maybe_sudo pacman -S --noconfirm --needed "$@" ;;
        zypper)  maybe_sudo zypper --non-interactive install "$@" ;;
        pkg)     pkg install -y "$@" ;;
        *)       log_error "Unsupported package manager: $PKG_MANAGER"; return 1 ;;
    esac
}

pkg_remove() {
    case "$PKG_MANAGER" in
        apt)     maybe_sudo apt-get remove -y "$@" && maybe_sudo apt-get autoremove -y ;;
        dnf)     maybe_sudo dnf remove -y "$@" ;;
        pacman)  maybe_sudo pacman -Rns --noconfirm "$@" 2>/dev/null || true ;;
        zypper)  maybe_sudo zypper --non-interactive remove "$@" ;;
        pkg)     pkg uninstall -y "$@" ;;
        *)       log_error "Unsupported package manager: $PKG_MANAGER"; return 1 ;;
    esac
}

pkg_upgrade() {
    case "$PKG_MANAGER" in
        apt)     maybe_sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq ;;
        dnf)     maybe_sudo dnf upgrade -y -q ;;
        pacman)  maybe_sudo pacman -Syu --noconfirm ;;
        zypper)  maybe_sudo zypper --non-interactive update ;;
        pkg)     pkg upgrade -y ;;
        *)       log_error "Unsupported package manager: $PKG_MANAGER"; return 1 ;;
    esac
}

pkg_cleanup() {
    case "$PKG_MANAGER" in
        apt)     maybe_sudo apt-get autoremove -y && maybe_sudo apt-get clean && maybe_sudo apt-get autoclean ;;
        dnf)     maybe_sudo dnf autoremove -y && maybe_sudo dnf clean all ;;
        pacman)  maybe_sudo pacman -Sc --noconfirm ;;
        zypper)  maybe_sudo zypper clean ;;
        pkg)     pkg clean ;;
        *)       log_error "Unsupported package manager: $PKG_MANAGER"; return 1 ;;
    esac
}

# Package installed check
pkg_is_installed() {
    local pkg="$1"
    case "$PKG_MANAGER" in
        apt)    dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" ;;
        dnf)    rpm -q "$pkg" &>/dev/null ;;
        pacman) pacman -Q "$pkg" &>/dev/null ;;
        zypper) rpm -q "$pkg" &>/dev/null ;;
        pkg)    dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" ;;
        *)      return 1 ;;
    esac
}

# Snap support
snap_available() {
    command -v snap &>/dev/null
}

# ensure_snap — install snapd if not present (apt-based distros only).
# Other distros (Fedora/Arch/openSUSE) require manual snapd setup with
# systemd service activation, so we skip auto-install there.
ensure_snap() {
    if snap_available; then
        # Even if snap binary exists, snapd daemon can't run in Docker (needs systemd)
        if [[ "$IS_DOCKER" == "true" ]]; then
            log_warn "snap cannot work inside Docker (no systemd) — skipping"
            return 1
        fi
        return 0
    fi

    # Termux: snap not supported
    [[ "$PKG_MANAGER" == "pkg" ]] && return 1

    # Docker: snapd requires systemd — don't waste time installing it
    if [[ "$IS_DOCKER" == "true" ]]; then
        return 1
    fi

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        log_info "snapd not found — installing..."
        if pkg_install snapd >> "$LOG_FILE" 2>&1; then
            log_success "snapd installed"
            return 0
        fi
        log_warn "Failed to install snapd"
    fi

    return 1
}

snap_install() {
    if snap_available; then
        maybe_sudo snap install "$@"
    else
        log_warn "snap not available — skipping snap install for: $*"
        return 1
    fi
}

# Command / tool helpers
command_exists() {
    command -v "$1" &>/dev/null
}

check_root() {
    # Termux doesn't use root — runs in its own user sandbox
    [[ "$PKG_MANAGER" == "pkg" ]] && return 0
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo."
        exit 1
    fi
}

# _as_builder — run a command as $SUDO_USER instead of root (privilege dropping).
# Build/download steps run as the original user; install/symlink steps stay as root.
# Falls back to running as root when:
#   - SUDO_USER is not set (direct root login / Docker)
#   - Running on Termux (no root)
# Usage: _as_builder "go install github.com/foo/bar@latest"
_as_builder() {
    if [[ "$PKG_MANAGER" == "pkg" ]] || [[ -z "${SUDO_USER:-}" ]] || [[ "${SUDO_USER:-}" == "root" ]]; then
        bash -c "$1"; return $?
    fi
    sudo -H -u "$SUDO_USER" bash -c "export PATH=\"\$HOME/.cargo/bin:/usr/local/bin:\$PATH\"; $1"
}

# _chown_for_builder — make directories writable by $SUDO_USER before privilege-dropped operations.
# Root creates system directories (/opt, /usr/local/bin) but _as_builder runs as $SUDO_USER,
# who cannot write to root-owned dirs.  Call this after mkdir to hand ownership to the builder.
# No-op when not privilege-dropping (Termux, direct root login, Docker).
# Usage: _chown_for_builder /opt/toolname [/opt/go ...]
_chown_for_builder() {
    [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER:-}" != "root" ]] && [[ "$PKG_MANAGER" != "pkg" ]] || return 0
    chown "$SUDO_USER" "$@" 2>/dev/null || true
}

# _builder_home — resolve $SUDO_USER's home directory (not root's $HOME).
# Returns root's $HOME when not privilege-dropping.
_builder_home() {
    if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER:-}" != "root" ]] && [[ "$PKG_MANAGER" != "pkg" ]]; then
        getent passwd "$SUDO_USER" | cut -d: -f6
    else
        echo "$HOME"
    fi
}

# _check_pkg_manager — fail early if the distro/package manager is unsupported.
# Usage: _check_pkg_manager
_check_pkg_manager() {
    if [[ "$PKG_MANAGER" == "unknown" ]]; then
        log_error "Unsupported distribution — could not detect package manager"
        log_error "Supported: apt (Debian/Ubuntu/Kali), dnf (Fedora/RHEL), pacman (Arch), zypper (openSUSE), pkg (Termux/Android)"
        exit 1
    fi
}

# pipx — auto-install if not present
# Install order: system package (multiple names per distro) → venv bootstrap.
# Does NOT use pip3 install — blocked by PEP 668 on modern distros (Ubuntu 23.04+).
ensure_pipx() {
    command_exists pipx && return 0

    log_info "pipx not found — installing..."

    # Try system package — package name varies by distro
    # apt: python3-pipx or pipx   dnf: pipx or python3-pipx
    # pacman: python-pipx          zypper: python3-pipx   pkg: pipx
    local -a _pipx_names
    case "$PKG_MANAGER" in
        apt)    _pipx_names=(pipx python3-pipx) ;;
        dnf)    _pipx_names=(pipx python3-pipx) ;;
        pacman) _pipx_names=(python-pipx) ;;
        zypper) _pipx_names=(python3-pipx pipx) ;;
        pkg)    _pipx_names=(pipx) ;;
        *)      _pipx_names=(pipx python3-pipx) ;;
    esac

    for _pipx_pkg in "${_pipx_names[@]}"; do
        if pkg_install "$_pipx_pkg" >> "$LOG_FILE" 2>&1 && command_exists pipx; then
            pipx ensurepath >> "$LOG_FILE" 2>&1 || true
            log_success "pipx installed via $PKG_MANAGER ($_pipx_pkg)"
            return 0
        fi
    done

    # Fallback: bootstrap pipx via an isolated venv.
    # Works around missing packages (WSL minimal repos) and PEP 668.
    # Requires python3-venv which is in SHARED_BASE_PACKAGES.
    if command_exists python3; then
        log_info "Bootstrapping pipx via isolated venv..."
        local _bootstrap_venv="$PIPX_HOME/.pipx-bootstrap"
        mkdir -p "$PIPX_HOME" 2>/dev/null || true
        if python3 -m venv "$_bootstrap_venv" >> "$LOG_FILE" 2>&1; then
            "$_bootstrap_venv/bin/pip" install --upgrade pip >> "$LOG_FILE" 2>&1 || true
            if "$_bootstrap_venv/bin/pip" install pipx >> "$LOG_FILE" 2>&1; then
                ln -sf "$_bootstrap_venv/bin/pipx" "$PIPX_BIN_DIR/pipx" 2>/dev/null || true
                export PIPX_HOME PIPX_BIN_DIR
            fi
        fi
    fi

    if command_exists pipx; then
        log_success "pipx installed via venv bootstrap"
        return 0
    fi

    log_error "Failed to install pipx — Python security tools will not be available"
    return 1
}

pipx_install() {
    local pkg="$1"
    ensure_pipx || return 1
    if ! command_exists pipx; then
        log_error "pipx unavailable — cannot install $pkg (install pipx first)"
        return 1
    fi
    if pipx list --short 2>/dev/null | grep -qi "^${pkg} "; then
        return 0
    fi
    local -a _py_flag=()
    if [[ -n "${PIPX_DEFAULT_PYTHON:-}" ]] && [[ "$PIPX_DEFAULT_PYTHON" != "python3" ]]; then
        _py_flag=(--python "$PIPX_DEFAULT_PYTHON")
    fi
    if ! pipx install "${_py_flag[@]}" "$pkg" >> "$LOG_FILE" 2>&1; then
        # Retry 1: --force in case of stale venvs
        if ! pipx install "${_py_flag[@]}" "$pkg" --force >> "$LOG_FILE" 2>&1; then
            # Retry 2: allow pip to upgrade transitive deps (fixes lxml/Python 3.13 etc.)
            if pipx install "${_py_flag[@]}" "$pkg" --force --pip-args='--upgrade' >> "$LOG_FILE" 2>&1; then
                return 0
            fi
            # Retry 3: older Python versions (if available)
            local _alt
            for _alt in python3.12 python3.11 python3.10; do
                command -v "$_alt" &>/dev/null || continue
                log_debug "Retrying pipx install $pkg with $_alt..."
                if pipx install --python "$_alt" "$pkg" --force >> "$LOG_FILE" 2>&1; then
                    return 0
                fi
            done
            return 1
        fi
    fi
}

pipx_remove() {
    local pkg="$1"
    if command_exists pipx; then
        pipx uninstall "$pkg" 2>/dev/null || true
    fi
}

# Git clone helper — clones/pulls as $SUDO_USER when available (privilege dropping)
# Creates the destination directory as root, then chowns it to $SUDO_USER so the
# privilege-dropped git clone can write into it.
git_clone_or_pull() {
    local repo_url="$1"
    local dest="$2"
    if [[ -d "$dest/.git" ]]; then
        log_info "Updating $(basename "$dest")..."
        if ! _as_builder "git -C '$dest' pull -q" >> "$LOG_FILE" 2>&1; then
            log_debug "git pull failed for $(basename "$dest") — resetting to remote HEAD..."
            local _remote_branch=""
            _remote_branch=$(_as_builder "git -C '$dest' symbolic-ref refs/remotes/origin/HEAD 2>/dev/null \
                | sed 's|refs/remotes/origin/||'") || true
            [[ -z "$_remote_branch" ]] && _remote_branch="main"
            _as_builder "git -C '$dest' fetch origin" >> "$LOG_FILE" 2>&1 \
                && _as_builder "git -C '$dest' reset --hard 'origin/$_remote_branch'" >> "$LOG_FILE" 2>&1 \
                || log_warn "git update failed for $(basename "$dest")"
        fi
    else
        mkdir -p "$dest" 2>/dev/null || true
        _chown_for_builder "$dest"
        log_info "Cloning $(basename "$dest")..."
        _as_builder "git clone --depth 1 -q '$repo_url' '$dest'" >> "$LOG_FILE" 2>&1
    fi
}

# Progress bar — Unicode block style matching Stage 3/4 display.
# Uses █ (filled) and ░ (empty) with count/total format.
show_progress() {
    local current=$1
    local total=$2
    local label="${3:-}"

    [[ "$total" -le 0 ]] && return

    # Non-interactive terminal (Docker, piped output): skip animated progress bar
    if [[ ! -t 1 ]]; then
        return
    fi

    local _bf=$'\xe2\x96\x88'  # █ U+2588
    local _be=$'\xe2\x96\x91'  # ░ U+2591

    # Fixed 20-char bar (matches Stage 3/4 progress display)
    local bar_width=20
    local filled=$((current * bar_width / total))
    [[ "$filled" -gt "$bar_width" ]] && filled=$bar_width
    local empty=$((bar_width - filled))
    local bar="" i
    for ((i = 0; i < filled; i++)); do bar+="$_bf"; done
    for ((i = 0; i < empty; i++)); do bar+="$_be"; done

    # Truncate label to avoid wrapping
    [[ ${#label} -gt 25 ]] && label="${label:0:24}~"

    printf '\r\033[K  %s %3d/%-3d  %s' "$bar" "$current" "$total" "$label"
}

# Activity spinner — braille dot spinner with elapsed time for
# long-running operations that redirect output to the log file.
# Uses the same braille characters as the Stage 3/4 progress display.
# Usage:
#   _start_spinner "Building AFLplusplus..."
#   some_command >> "$LOG_FILE" 2>&1
#   _stop_spinner
_SPINNER_PID=""

_start_spinner() {
    local label="$1"
    # Kill any previous spinner (safety — shouldn't happen in practice)
    _stop_spinner

    # Non-interactive terminal (Docker, piped output): print one static line instead
    # of the animated spinner which would spam hundreds of lines in the log.
    if [[ ! -t 1 ]]; then
        printf '  ... %s\n' "$label"
        _SPINNER_PID=""
        return
    fi

    (
        local -a _spin=(
            $'\xe2\xa0\x8b' $'\xe2\xa0\x99' $'\xe2\xa0\xb9' $'\xe2\xa0\xb8' $'\xe2\xa0\xbc'
            $'\xe2\xa0\xb4' $'\xe2\xa0\xa6' $'\xe2\xa0\xa7' $'\xe2\xa0\x87' $'\xe2\xa0\x8f'
        )
        local i=0
        local s0=$SECONDS
        while true; do
            local elapsed=$(( SECONDS - s0 ))
            printf '\r\033[K  %s %s \033[2m(%ds)\033[0m' "${_spin[$((i%10))]}" "$label" "$elapsed"
            i=$((i + 1))
            sleep 0.3
        done
    ) &
    _SPINNER_PID=$!
}

_stop_spinner() {
    if [[ -n "${_SPINNER_PID:-}" ]] && kill -0 "$_SPINNER_PID" 2>/dev/null; then
        kill "$_SPINNER_PID" 2>/dev/null
        wait "$_SPINNER_PID" 2>/dev/null || true
        printf '\r\033[K'
    fi
    _SPINNER_PID=""
}

# ── Live progress display for parallel Stage 3/4 ──
# IPC via temp files in PROGRESS_DIR: <method>.total, <method>.done, <method>.current
# Each parallel subshell writes status; a background display loop reads and renders.

_PROGRESS_DISPLAY_PID=""

# _init_progress_dir — create tmpdir for IPC between batch subshells and display loop
_init_progress_dir() {
    PROGRESS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/cybersec_progress.XXXXXX")
    _register_cleanup "$PROGRESS_DIR"
    export PROGRESS_DIR
}

_cleanup_progress_dir() {
    [[ -n "${PROGRESS_DIR:-}" ]] && { rm -rf "$PROGRESS_DIR" 2>/dev/null || true; }
    PROGRESS_DIR=""
    export PROGRESS_DIR
}

# _report_method_total — write total tool count for a method
# Usage: _report_method_total "pipx" 43
_report_method_total() {
    [[ -n "${PROGRESS_DIR:-}" ]] || return 0
    echo "$2" > "$PROGRESS_DIR/$1.total"
}

# _report_tool_start — write currently installing tool name (overwritten per tool)
# Usage: _report_tool_start "pipx" "dirsearch"
_report_tool_start() {
    [[ -n "${PROGRESS_DIR:-}" ]] || return 0
    echo "$2" > "$PROGRESS_DIR/$1.current"
}

# _report_tool_done — append completed tool to done log (atomic for small writes)
# Usage: _report_tool_done "pipx" "dirsearch" "ok|fail|skip" ["error msg"]
_report_tool_done() {
    [[ -n "${PROGRESS_DIR:-}" ]] || return 0
    printf '%s|%s|%s\n' "$2" "$3" "${4:-}" >> "$PROGRESS_DIR/$1.done"
}

# _start_progress_display — launch background multi-line progress display
# Args: method_name1 method_name2 ...  (e.g. "pipx" "Go" "Cargo" "Gems" "Git" "Binary")
_start_progress_display() {
    # Kill previous display loop if running (re-entry safety), but do NOT
    # call _stop_progress_display — that would _cleanup_progress_dir and
    # destroy .total files already written by the main process.
    if [[ -n "${_PROGRESS_DISPLAY_PID:-}" ]] && kill -0 "$_PROGRESS_DISPLAY_PID" 2>/dev/null; then
        kill "$_PROGRESS_DISPLAY_PID" 2>/dev/null
        wait "$_PROGRESS_DISPLAY_PID" 2>/dev/null || true
    fi
    _PROGRESS_DISPLAY_PID=""

    # Store ordered method list for _stop_progress_display
    printf '%s\n' "$@" > "$PROGRESS_DIR/.methods"

    # Non-interactive terminal: skip ANSI display
    if ! [[ -t 1 ]]; then
        return 0
    fi

    local _check=$'\xe2\x9c\x93'      # ✓ U+2713
    local _pd="$PROGRESS_DIR"

    # Single-line spinner — updates in place with \r, no cursor movement.
    # Avoids scrollback pollution that multi-line \033[%dA causes in
    # ConPTY / Windows Terminal / WSL terminals.
    (
        local -a methods=("$@")
        local -a _spin=(
            $'\xe2\xa0\x8b' $'\xe2\xa0\x99' $'\xe2\xa0\xb9' $'\xe2\xa0\xb8' $'\xe2\xa0\xbc'
            $'\xe2\xa0\xb4' $'\xe2\xa0\xa6' $'\xe2\xa0\xa7' $'\xe2\xa0\x87' $'\xe2\xa0\x8f'
        )
        local spin_idx=0
        local s0=$SECONDS
        local cols
        cols=$(tput cols 2>/dev/null) || cols=${COLUMNS:-80}
        [[ "$cols" =~ ^[0-9]+$ ]] || cols=80

        while true; do
            [[ -f "$_pd/.stop" ]] && break

            local elapsed=$(( SECONDS - s0 ))
            spin_idx=$(( (spin_idx + 1) % 10 ))

            # Build compact status: "pipx 43/109 · Go ✓ · Cargo 2/4 ..."
            local parts=""
            for method in "${methods[@]}"; do
                local total=0 done_count=0
                [[ -f "$_pd/$method.total" ]] && read -r total < "$_pd/$method.total" 2>/dev/null
                if [[ -f "$_pd/$method.done" ]]; then
                    done_count=$(wc -l < "$_pd/$method.done" 2>/dev/null)
                    done_count=${done_count//[[:space:]]/}
                fi
                [[ "$total" =~ ^[0-9]+$ ]] || total=0
                [[ "$done_count" =~ ^[0-9]+$ ]] || done_count=0

                local part=""
                if [[ "$total" -eq 0 ]] && [[ -f "$_pd/$method.total" ]]; then
                    part="$method skip"
                elif [[ "$total" -eq 0 ]]; then
                    part="$method ..."
                elif [[ "$done_count" -ge "$total" ]]; then
                    part="$method $_check"
                else
                    part="$method ${done_count}/${total}"
                fi

                [[ -n "$parts" ]] && parts+=" | "
                parts+="$part"
            done

            local line="  ${_spin[$spin_idx]} ${parts}  (${elapsed}s)"
            # Truncate to terminal width
            [[ ${#line} -gt $cols ]] && line="${line:0:$((cols - 1))}"

            printf '\r\033[K%s' "$line"
            sleep 0.3
        done
        # Clear the spinner line on exit
        printf '\r\033[K'
    ) &
    _PROGRESS_DISPLAY_PID=$!
}

# _stop_progress_display — stop spinner, render final static summary
_stop_progress_display() {
    # Cooperative shutdown: signal the display loop to exit cleanly
    [[ -n "${PROGRESS_DIR:-}" && -d "$PROGRESS_DIR" ]] && touch "$PROGRESS_DIR/.stop"

    if [[ -n "${_PROGRESS_DISPLAY_PID:-}" ]] && kill -0 "$_PROGRESS_DISPLAY_PID" 2>/dev/null; then
        local _i=0
        while kill -0 "$_PROGRESS_DISPLAY_PID" 2>/dev/null && [[ $_i -lt 15 ]]; do
            sleep 0.1
            _i=$((_i + 1))
        done
        if kill -0 "$_PROGRESS_DISPLAY_PID" 2>/dev/null; then
            kill "$_PROGRESS_DISPLAY_PID" 2>/dev/null
        fi
        wait "$_PROGRESS_DISPLAY_PID" 2>/dev/null || true
    fi
    _PROGRESS_DISPLAY_PID=""

    [[ -n "${PROGRESS_DIR:-}" && -d "$PROGRESS_DIR" ]] || return 0

    local _bar_full=$'\xe2\x96\x88'   # █
    local _bar_empty=$'\xe2\x96\x91'  # ░
    local _check=$'\xe2\x9c\x93'      # ✓
    local _cross=$'\xe2\x9c\x97'      # ✗
    local _dash=$'\xe2\x80\x94'       # —

    local -a methods=()
    [[ -f "$PROGRESS_DIR/.methods" ]] && mapfile -t methods < "$PROGRESS_DIR/.methods"
    [[ ${#methods[@]} -gt 0 ]] || { _cleanup_progress_dir; return 0; }

    if [[ -t 1 ]]; then
        # Clear spinner line (in case the loop didn't clean up)
        printf '\r\033[K'

        # Print final multi-line summary (no cursor movement — just normal output)
        printf '  Stage 3/4 %s Installing tools (complete)\n\n' "$_dash"

        for method in "${methods[@]}"; do
            local total=0 done_count=0
            [[ -f "$PROGRESS_DIR/$method.total" ]] && read -r total < "$PROGRESS_DIR/$method.total" 2>/dev/null
            if [[ -f "$PROGRESS_DIR/$method.done" ]]; then
                done_count=$(wc -l < "$PROGRESS_DIR/$method.done" 2>/dev/null)
                done_count=${done_count//[[:space:]]/}
            fi
            [[ "$total" =~ ^[0-9]+$ ]] || total=0
            [[ "$done_count" =~ ^[0-9]+$ ]] || done_count=0

            if [[ "$total" -gt 0 ]] && [[ "$done_count" -eq 0 ]]; then
                done_count=$total
            fi

            local bar_width=20 bar="" i
            local filled=$bar_width
            [[ "$total" -eq 0 ]] && filled=0
            for ((i = 0; i < filled; i++)); do bar+="$_bar_full"; done
            for ((i = filled; i < bar_width; i++)); do bar+="$_bar_empty"; done

            local fc=0
            [[ -f "$PROGRESS_DIR/$method.done" ]] && fc=$(grep -c '|fail|' "$PROGRESS_DIR/$method.done" 2>/dev/null || true)
            [[ "$fc" =~ ^[0-9]+$ ]] || fc=0
            local status_str="$_check done"
            [[ "$fc" -gt 0 ]] && status_str="$_check done ($fc failed)"
            [[ "$total" -eq 0 ]] && status_str="skipped"

            printf '  %-8s %s %3d/%-3d  %s\n' \
                "$method" "$bar" "$done_count" "$total" "$status_str"
        done

        # Failure summary
        local has_fails=false
        for method in "${methods[@]}"; do
            [[ -f "$PROGRESS_DIR/$method.done" ]] || continue
            while IFS='|' read -r _ft _fs _fe; do
                if [[ "$_fs" == "fail" ]]; then
                    if [[ "$has_fails" == "false" ]]; then
                        echo ""
                        has_fails=true
                    fi
                    printf '  %s %s%s\n' "$_cross" "$_ft" "${_fe:+ ($_fe)}"
                fi
            done < <(grep '|fail|' "$PROGRESS_DIR/$method.done" 2>/dev/null)
        done

        echo ""
    else
        # Non-interactive: print plain-text summary
        echo ""
        echo "  Stage 3/4 -- Installing tools (complete)"
        for method in "${methods[@]}"; do
            local total=0 done_count=0
            [[ -f "$PROGRESS_DIR/$method.total" ]] && read -r total < "$PROGRESS_DIR/$method.total" 2>/dev/null
            if [[ -f "$PROGRESS_DIR/$method.done" ]]; then
                done_count=$(wc -l < "$PROGRESS_DIR/$method.done" 2>/dev/null)
                done_count=${done_count//[[:space:]]/}
            fi
            [[ "$total" =~ ^[0-9]+$ ]] || total=0
            [[ "$done_count" =~ ^[0-9]+$ ]] || done_count=0
            [[ "$total" -eq 0 ]] && { printf '  %-8s  skipped\n' "$method"; continue; }
            local fc=0
            [[ -f "$PROGRESS_DIR/$method.done" ]] && fc=$(grep -c '|fail|' "$PROGRESS_DIR/$method.done" 2>/dev/null || true)
            [[ "$fc" =~ ^[0-9]+$ ]] || fc=0
            local status_str="done"
            [[ "$fc" -gt 0 ]] && status_str="done ($fc failed)"
            printf '  %-8s %3d/%-3d  %s\n' "$method" "$done_count" "$total" "$status_str"
        done
        echo ""
    fi

    _cleanup_progress_dir
}

# Banner
print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'BANNER'
   ______      __              _____
  / ____/_  __/ /_  ___  _____/ ___/___  _____
 / /   / / / / __ \/ _ \/ ___/\__ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /   ___/ /  __/ /__
\____/\__, /_.___/\___/_/   /____/\___/\___/
     /____/                          by 26zl
BANNER
    echo "              Tools Installer${INSTALLER_VERSION:+  v${INSTALLER_VERSION}}"
    echo -e "${NC}"
    log_info "Distro: $DISTRO_NAME ($DISTRO_ID)"
    log_info "Package manager: $PKG_MANAGER"
    [[ "$IS_WSL" == "true" ]] && log_warn "WSL detected — wireless module and kernel-level tools will be skipped"
    [[ "$IS_ARM" == "true" ]] && log_warn "ARM architecture detected — x86-only binary releases and tools will be skipped"
    echo ""
}

# Module registry (single source of truth)
# shellcheck disable=SC2034  # Used by all scripts that source this file
ALL_MODULES=(misc networking recon web crypto pwn reversing forensics enterprise wireless cracking stego cloud containers blueteam mobile blockchain llm)

# Module descriptions (single source of truth for --list-modules and help text)
# shellcheck disable=SC2034  # Used by install.sh list_modules()
declare -A MODULE_DESCRIPTIONS=(
    [misc]="Security tools, utilities, resources, C2, social engineering"
    [networking]="Port scanning, packet capture, tunneling, MITM"
    [recon]="Subdomain enum, OSINT, intelligence gathering"
    [web]="Web app testing, fuzzing, scanning"
    [crypto]="Cryptography analysis, cipher cracking"
    [pwn]="Binary exploitation, shellcode, fuzzers"
    [reversing]="Disassembly, debugging, binary analysis"
    [forensics]="Disk/memory forensics, file carving"
    [enterprise]="AD, Kerberos, LDAP, Azure AD, lateral movement"
    [wireless]="WiFi, Bluetooth, SDR"
    [cracking]="Hash cracking, brute force, wordlists"
    [stego]="Steganography tools"
    [cloud]="AWS/Azure/GCP security"
    [containers]="Docker/Kubernetes security"
    [blueteam]="Defensive security, IDS/IPS, SIEM, IR, malware analysis"
    [mobile]="Android/iOS app testing, APK analysis"
    [blockchain]="Smart contract auditing, analysis, reversing"
    [llm]="LLM red teaming, prompt injection, AI security"
)

# Module name → array prefix mapping
_module_prefix() {
    case "$1" in
        networking) echo "NET" ;;
        reversing)  echo "RE" ;;
        containers) echo "CONTAINER" ;;
        *)          echo "${1^^}" ;;
    esac
}

# _append_module_array — append contents of a named array to a destination array.
# Usage: _append_module_array DEST_ARRAY "SOURCE_ARRAY_NAME"
# No-op if SOURCE_ARRAY_NAME doesn't exist or is empty.
_append_module_array() {
    local -n _ama_dest="$1"
    local _arr_name="$2"
    declare -p "$_arr_name" &>/dev/null || return 0
    local -n _ama_src="$_arr_name"
    [[ ${#_ama_src[@]} -gt 0 ]] && _ama_dest+=("${_ama_src[@]}")
}

# _collect_module_arrays — aggregate arrays from all modules by suffix.
# Usage: _collect_module_arrays "GO" dest_array
# Iterates all module prefixes and appends PREFIX_SUFFIX to dest_array.
_collect_module_arrays() {
    local _suffix="$1"
    local -n _cma_dest="$2"
    local _mod _prefix
    for _mod in "${ALL_MODULES[@]}"; do
        _prefix=$(_module_prefix "$_mod")
        _append_module_array _cma_dest "${_prefix}_${_suffix}"
    done
}

# _source_all_modules — source every module file listed in ALL_MODULES.
# Usage: _source_all_modules "$SCRIPT_DIR"
_source_all_modules() {
    local _sam_dir="$1"
    for _sam_mod in "${ALL_MODULES[@]}"; do
        # shellcheck source=/dev/null
        source "$_sam_dir/modules/${_sam_mod}.sh"
    done
}

# Architecture detection
detect_arch() {
    local machine
    machine=$(uname -m)
    IS_ARM=false
    case "$machine" in
        x86_64)       SYS_ARCH="amd64";  SYS_ARCH_ALT="x86_64"  ;;
        aarch64)      SYS_ARCH="arm64";  SYS_ARCH_ALT="aarch64"; IS_ARM=true ;;
        armv7l|armhf) SYS_ARCH="armv7";  SYS_ARCH_ALT="armv7l";  IS_ARM=true ;;
        *)            SYS_ARCH="$machine"; SYS_ARCH_ALT="$machine" ;;
    esac
    export SYS_ARCH SYS_ARCH_ALT IS_ARM
}

detect_wsl() {
    IS_WSL=false
    IS_DOCKER=false
    # Docker containers on WSL2 inherit "microsoft" in /proc/version
    # but are not actually WSL — skip the check inside containers
    if [[ -f /.dockerenv ]] || [[ -f /.containerenv ]] \
       || grep -qsw docker /proc/1/cgroup 2>/dev/null \
       || grep -qs 'docker\|containerd' /proc/1/mountinfo 2>/dev/null \
       || [[ -n "${container:-}" ]]; then
        IS_DOCKER=true
        export IS_WSL IS_DOCKER
        return
    fi
    if [[ -f /proc/version ]] && grep -qi "microsoft" /proc/version 2>/dev/null; then
        IS_WSL=true
    fi
    export IS_WSL IS_DOCKER
}

# Auto-init on source (skip detect_pkg_manager if pre-set — e.g. by test harness)
[[ -z "${PKG_MANAGER:-}" ]] && detect_pkg_manager
detect_arch
detect_wsl

# Tool paths — Termux uses $PREFIX/bin and user-local dirs; Linux uses system-wide /usr/local/bin
if [[ "$PKG_MANAGER" == "pkg" ]]; then
    # Termux: $PREFIX is /data/data/com.termux/files/usr (always set by Termux)
    GITHUB_TOOL_DIR="${GITHUB_TOOL_DIR:-$HOME/tools}"
    export GITHUB_TOOL_DIR
    export GOPATH="${GOPATH:-$HOME/.go}"
    export GOBIN="$PREFIX/bin"
    export PIPX_HOME="$HOME/.local/pipx"
    export PIPX_BIN_DIR="$PREFIX/bin"
    export PATH="$PREFIX/bin:$HOME/.cargo/bin:$PATH"
else
    # Linux: system-wide install
    GITHUB_TOOL_DIR="${GITHUB_TOOL_DIR:-/opt}"
    export GITHUB_TOOL_DIR
    # Go: GOBIN puts binaries directly in /usr/local/bin (accessible to all users)
    export GOPATH="${GOPATH:-/opt/go}"
    export GOBIN="/usr/local/bin"
    # pipx: install venvs to /opt/pipx, binaries to /usr/local/bin
    export PIPX_HOME="/opt/pipx"
    export PIPX_BIN_DIR="/usr/local/bin"
    # Cargo: rustup installs to $SUDO_USER's home via _as_builder, but $HOME is root's.
    # Include both so command_exists cargo works regardless of who installed rustup.
    _BUILDER_CARGO="$(_builder_home)/.cargo/bin"
    export PATH="/usr/local/bin:$HOME/.cargo/bin:${_BUILDER_CARGO}:$PATH"
fi
