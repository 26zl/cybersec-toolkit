#!/bin/bash
# common.sh — Shared library for cybersec-tools-installer
# Source this file: source "$SCRIPT_DIR/lib/common.sh"

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

# Logging
log_message() {
    echo -e "$1"
    if [[ -n "$LOG_FILE" ]]; then
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

# System environment logging
log_system_environment() {
    log_info "=== System Environment ==="
    log_info "  Hostname: $(hostname 2>/dev/null || echo unknown)"
    log_info "  Kernel:   $(uname -r 2>/dev/null || echo unknown)"
    log_info "  Arch:     $(uname -m 2>/dev/null || echo unknown)"
    log_info "  Distro:   ${DISTRO_NAME:-unknown} (${DISTRO_ID:-unknown})"
    log_info "  WSL:      $IS_WSL"
    log_info "  ARM:      $IS_ARM"
    log_info "  Shell:    BASH ${BASH_VERSION:-unknown}"
    log_info "  Disk:     $(df -h / 2>/dev/null | awk 'NR==2{print $4 " free of " $2}' || echo unknown)"
    log_info "  Memory:   $(free -h 2>/dev/null | awk '/^Mem:/{print $7 " free of " $2}' || echo unknown)"
    log_info "=== Runtime Versions ==="
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
    log_info "=========================="
}

# Disk space check — warns if available space is below estimated requirement.
# Args: $1 = number of modules to install
# Returns 0 always (non-blocking), but prompts user to abort if critically low.
check_disk_space() {
    local num_modules="${1:-19}"

    # Determine check path: Termux uses $HOME, Linux uses /
    local check_path="/"
    [[ "$PKG_MANAGER" == "pkg" ]] && check_path="$HOME"

    # Get available space in GB (compatible with Linux and Termux)
    local avail_kb
    avail_kb=$(df -k "$check_path" 2>/dev/null | awk 'NR==2{print $4}')
    if [[ -z "$avail_kb" || "$avail_kb" -le 0 ]] 2>/dev/null; then
        log_warn "Could not determine available disk space — skipping check"
        return 0
    fi
    local avail_gb=$(( avail_kb / 1048576 ))
    local avail_mb=$(( avail_kb / 1024 ))

    # Estimate required space based on module count
    # Base: ~2GB for shared deps + runtimes (Go, Rust, Python venvs, etc.)
    # Per module: ~1.5GB average (packages + git repos + compiled tools)
    # Full install (19 modules): ~25-30GB; lightweight (4 modules): ~5-8GB
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

# Parallel install helpers

# _wait_for_job_slot — blocks until fewer than PARALLEL_JOBS background jobs are running
_wait_for_job_slot() {
    while [[ $(jobs -rp | wc -l) -ge $PARALLEL_JOBS ]]; do
        wait -n 2>/dev/null || sleep 0.1
    done
}

# _collect_parallel_results — reads temp result files, calls track_version,
# sets _par_failed and _par_skipped for the caller.
# Result file format: line 1 = "ok"/"skip"/"fail", line 2 = version string
_collect_parallel_results() {
    local rdir="$1" method="$2"
    _par_failed=0; _par_skipped=0
    for _rf in "$rdir"/*; do
        [[ -f "$_rf" ]] || continue
        local _rname _rstatus _rver
        _rname=$(basename "$_rf")
        _rstatus=$(head -1 "$_rf")
        _rver=$(sed -n '2p' "$_rf")
        case "$_rstatus" in
            ok)   track_version "$_rname" "$method" "$_rver" ;;
            skip) _par_skipped=$((_par_skipped + 1))
                  track_version "$_rname" "$method" "$_rver" ;;
            fail) _par_failed=$((_par_failed + 1)) ;;
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
        DISTRO_VERSION="${VERSION_ID:-}"
    elif command -v lsb_release &>/dev/null; then
        DISTRO_ID="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
        DISTRO_NAME="$(lsb_release -sd)"
        DISTRO_VERSION="$(lsb_release -sr)"
        DISTRO_ID_LIKE=""
    else
        DISTRO_ID="unknown"
        DISTRO_NAME="Unknown"
        DISTRO_VERSION=""
        DISTRO_ID_LIKE=""
    fi
    export DISTRO_ID DISTRO_ID_LIKE DISTRO_NAME DISTRO_VERSION
}

# Determine the package-manager family: apt | dnf | pacman | zypper | pkg | unknown
detect_pkg_manager() {
    # Unsupported OS — hard stop on Windows and macOS
    local _kernel
    _kernel="$(uname -s 2>/dev/null || echo unknown)"
    case "$_kernel" in
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            echo -e "\n${RED}[-] ERROR: Windows is not supported.${NC}"
            echo "    This installer requires Linux or Termux (Android)."
            echo "    Use WSL (Windows Subsystem for Linux) instead:"
            echo "      https://learn.microsoft.com/en-us/windows/wsl/install"
            exit 1
            ;;
        Darwin)
            echo -e "\n${RED}[-] ERROR: macOS is not supported.${NC}"
            echo "    This installer requires Linux or Termux (Android)."
            echo "    On macOS, use a Linux VM or Docker container:"
            echo "      docker build -t cybersec-installer . && docker run cybersec-installer"
            exit 1
            ;;
    esac

    # Termux on Android — detect before os-release (Termux always sets TERMUX_VERSION)
    if [[ -n "${TERMUX_VERSION:-}" ]]; then
        DISTRO_ID="android"
        DISTRO_ID_LIKE=""
        DISTRO_NAME="Termux"
        DISTRO_VERSION="${TERMUX_VERSION}"
        export DISTRO_ID DISTRO_ID_LIKE DISTRO_NAME DISTRO_VERSION
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

# Package manager abstraction
pkg_update() {
    case "$PKG_MANAGER" in
        apt)     sudo apt-get update -qq ;;
        dnf)     sudo dnf check-update -q || true ;;
        pacman)  sudo pacman -Sy --noconfirm ;;
        zypper)  sudo zypper refresh -q ;;
        pkg)     pkg update -y ;;
        *)       log_error "Unsupported package manager: $PKG_MANAGER"; return 1 ;;
    esac
}

pkg_install() {
    case "$PKG_MANAGER" in
        apt)     sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
        dnf)
            if [[ "$1" == @* ]]; then
                sudo dnf group install -y -q "${1#@}"
            else
                sudo dnf install -y -q "$@"
            fi
            ;;
        pacman)  sudo pacman -S --noconfirm --needed "$@" ;;
        zypper)  sudo zypper install -y -q "$@" ;;
        pkg)     pkg install -y "$@" ;;
        *)       log_error "Unsupported package manager: $PKG_MANAGER"; return 1 ;;
    esac
}

pkg_remove() {
    case "$PKG_MANAGER" in
        apt)     sudo apt-get remove -y "$@" && sudo apt-get autoremove -y ;;
        dnf)     sudo dnf remove -y "$@" ;;
        pacman)  sudo pacman -Rns --noconfirm "$@" 2>/dev/null || true ;;
        zypper)  sudo zypper remove -y "$@" ;;
        pkg)     pkg uninstall -y "$@" ;;
        *)       log_error "Unsupported package manager: $PKG_MANAGER"; return 1 ;;
    esac
}

pkg_upgrade() {
    case "$PKG_MANAGER" in
        apt)     sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq ;;
        dnf)     sudo dnf upgrade -y -q ;;
        pacman)  sudo pacman -Syu --noconfirm ;;
        zypper)  sudo zypper update -y -q ;;
        pkg)     pkg upgrade -y ;;
        *)       log_error "Unsupported package manager: $PKG_MANAGER"; return 1 ;;
    esac
}

pkg_cleanup() {
    case "$PKG_MANAGER" in
        apt)     sudo apt-get autoremove -y && sudo apt-get clean && sudo apt-get autoclean ;;
        dnf)     sudo dnf autoremove -y && sudo dnf clean all ;;
        pacman)  sudo pacman -Sc --noconfirm ;;
        zypper)  sudo zypper clean ;;
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

snap_install() {
    if snap_available; then
        sudo snap install "$@"
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
    pipx install "$pkg" 2>>"$LOG_FILE" || pipx install "$pkg" --force 2>>"$LOG_FILE"
}

pipx_remove() {
    local pkg="$1"
    if command_exists pipx; then
        pipx uninstall "$pkg" 2>/dev/null || true
    fi
}

# Git clone helper
git_clone_or_pull() {
    local repo_url="$1"
    local dest="$2"
    if [[ -d "$dest/.git" ]]; then
        log_info "Updating $(basename "$dest")..."
        git -C "$dest" pull -q 2>>"$LOG_FILE" || true
    else
        mkdir -p "$(dirname "$dest")" 2>/dev/null || true
        log_info "Cloning $(basename "$dest")..."
        git clone --depth 1 -q "$repo_url" "$dest" 2>>"$LOG_FILE"
    fi
}

# Progress bar
show_progress() {
    local current=$1
    local total=$2
    local label="${3:-}"
    local width=40

    [[ "$total" -le 0 ]] && return

    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    local bar=""

    local i
    for ((i = 0; i < filled; i++)); do bar+="="; done
    for ((i = 0; i < empty; i++)); do bar+=" "; done

    # %-25s pads with spaces to 25 chars — ensures shorter labels overwrite
    # longer previous ones. Works on all terminals (no ANSI escape needed).
    local display_label=""
    [[ -n "$label" ]] && display_label="($label)"
    printf "\r  ${BLUE}[${NC}%s${BLUE}]${NC} %3d%% %-25s" "$bar" "$percentage" "$display_label"
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
     /____/
              Tools Installer
BANNER
    echo -e "${NC}"
    log_info "Distro: $DISTRO_NAME ($DISTRO_ID)"
    log_info "Package manager: $PKG_MANAGER"
    [[ "$IS_WSL" == "true" ]] && log_warn "WSL detected — wireless module and kernel-level tools will be skipped"
    [[ "$IS_ARM" == "true" ]] && log_warn "ARM architecture detected — x86-only binary releases and tools will be skipped"
    echo ""
}

# Module registry (single source of truth) 
# shellcheck disable=SC2034  # Used by all scripts that source this file
ALL_MODULES=(misc networking recon web crypto pwn reversing forensics malware enterprise wireless cracking stego cloud containers blueteam mobile blockchain llm)

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
    # Docker containers on WSL2 inherit "microsoft" in /proc/version
    # but are not actually WSL — skip the check inside containers
    if [[ -f /.dockerenv ]]; then
        export IS_WSL
        return
    fi
    if [[ -f /proc/version ]] && grep -qi "microsoft" /proc/version 2>/dev/null; then
        IS_WSL=true
    fi
    export IS_WSL
}

# Auto-init on source
detect_pkg_manager
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
    # Cargo: keep in root's home but symlink to /usr/local/bin after install
    export PATH="/usr/local/bin:$HOME/.cargo/bin:$PATH"
fi
