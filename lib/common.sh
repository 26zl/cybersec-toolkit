#!/bin/bash
# =============================================================================
# common.sh — Shared library for cybersec-tools-installer
# Source this file: source "$SCRIPT_DIR/lib/common.sh"
# =============================================================================

# ----- Colors ----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ----- Configurable defaults -------------------------------------------------
GITHUB_TOOL_DIR="${GITHUB_TOOL_DIR:-/opt}"
BURP_VERSION="${BURP_VERSION:-2024.10.1}"
VERSION_FILE="${VERSION_FILE:-${SCRIPT_DIR:-.}/.versions}"
LOG_FILE="${LOG_FILE:-/dev/null}"

# ----- Logging ---------------------------------------------------------------
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

# ----- Distro detection -------------------------------------------------------
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

# Determine the package-manager family: apt | dnf | pacman | zypper | unknown
detect_pkg_manager() {
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

# ----- Package manager abstraction -------------------------------------------
pkg_update() {
    case "$PKG_MANAGER" in
        apt)     sudo apt-get update -qq ;;
        dnf)     sudo dnf check-update -q || true ;;
        pacman)  sudo pacman -Sy --noconfirm ;;
        zypper)  sudo zypper refresh -q ;;
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
    esac
}

pkg_remove() {
    case "$PKG_MANAGER" in
        apt)     sudo apt-get remove -y "$@" && sudo apt-get autoremove -y ;;
        dnf)     sudo dnf remove -y "$@" ;;
        pacman)  sudo pacman -Rns --noconfirm "$@" 2>/dev/null || true ;;
        zypper)  sudo zypper remove -y "$@" ;;
    esac
}

pkg_upgrade() {
    case "$PKG_MANAGER" in
        apt)     sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq ;;
        dnf)     sudo dnf upgrade -y -q ;;
        pacman)  sudo pacman -Syu --noconfirm ;;
        zypper)  sudo zypper update -y -q ;;
    esac
}

pkg_cleanup() {
    case "$PKG_MANAGER" in
        apt)     sudo apt-get autoremove -y && sudo apt-get clean && sudo apt-get autoclean ;;
        dnf)     sudo dnf autoremove -y && sudo dnf clean all ;;
        pacman)  sudo pacman -Sc --noconfirm ;;
        zypper)  sudo zypper clean ;;
    esac
}

# ----- Snap support -----------------------------------------------------------
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

# ----- Command / tool helpers ------------------------------------------------
command_exists() {
    command -v "$1" &>/dev/null
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo."
        exit 1
    fi
}

# ----- pipx ------------------------------------------------------------------
ensure_pipx() {
    if ! command_exists pipx; then
        log_info "Installing pipx via package manager..."
        if ! pkg_install pipx >> "$LOG_FILE" 2>&1; then
            log_error "Failed to install pipx — Python tools will NOT be installed"
            log_error "Install pipx manually: https://pipx.pypa.io/stable/installation/"
            return 1
        fi
    fi
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
    pipx install "$pkg" 2>/dev/null || pipx install "$pkg" --force 2>/dev/null
}

pipx_remove() {
    local pkg="$1"
    if command_exists pipx; then
        pipx uninstall "$pkg" 2>/dev/null || true
    fi
}

# ----- Git clone helper -------------------------------------------------------
git_clone_or_pull() {
    local repo_url="$1"
    local dest="$2"
    if [[ -d "$dest/.git" ]]; then
        log_info "Updating $(basename "$dest")..."
        git -C "$dest" pull -q 2>/dev/null || true
    else
        log_info "Cloning $(basename "$dest")..."
        git clone --depth 1 -q "$repo_url" "$dest" 2>/dev/null
    fi
}

# ----- Progress bar -----------------------------------------------------------
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

    printf "\r  ${BLUE}[${NC}%s${BLUE}]${NC} %3d%% " "$bar" "$percentage"
    [[ -n "$label" ]] && printf "(%s)" "$label"
}

# ----- Banner ----------------------------------------------------------------
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
    echo ""
}

# ----- Module registry (single source of truth) -----------------------------
# shellcheck disable=SC2034  # Used by all scripts that source this file
ALL_MODULES=(misc networking recon web crypto pwn reversing forensics malware ad wireless password stego cloud containers blueteam mobile)

# ----- Auto-init on source ---------------------------------------------------
detect_pkg_manager

# ----- Tool paths (system-wide install) --------------------------------------
# Go: GOBIN puts binaries directly in /usr/local/bin (accessible to all users)
export GOPATH="${GOPATH:-/opt/go}"
export GOBIN="/usr/local/bin"
# pipx: install venvs to /opt/pipx, binaries to /usr/local/bin
export PIPX_HOME="/opt/pipx"
export PIPX_BIN_DIR="/usr/local/bin"
# Cargo: keep in root's home but symlink to /usr/local/bin after install
export PATH="/usr/local/bin:$HOME/.cargo/bin:$PATH"
