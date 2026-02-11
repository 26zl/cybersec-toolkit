#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# =============================================================================
# CyberSec Tools Installer — Modular, Profile-Based, Production-Grade
#
# The most comprehensive cybersecurity tool installer for Linux.
# Supports Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE.
#
# Usage:
#   sudo ./install.sh                        # Full install (default)
#   sudo ./install.sh --profile ctf          # Install CTF tools only
#   sudo ./install.sh --profile redteam      # Red team tools
#   sudo ./install.sh --module web --module ad  # Specific modules
#   sudo ./install.sh --upgrade-system        # Also upgrade system packages
#   sudo ./install.sh --list-profiles        # Show available profiles
#   sudo ./install.sh --list-modules         # Show available modules
#   sudo ./install.sh --dry-run              # Show what would install
#   sudo ./install.sh --skip-heavy           # Skip large packages
#   sudo ./install.sh --enable-docker        # Pull Docker images for C2/etc
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/installers.sh"

# ALL_MODULES is defined in lib/common.sh

# =============================================================================
# Argument parsing
# =============================================================================
PROFILE=""
SELECTED_MODULES=()
DRY_RUN=false
UPGRADE_SYSTEM=false
SKIP_HEAVY="${SKIP_HEAVY:-false}"
ENABLE_DOCKER="${ENABLE_DOCKER:-false}"
INCLUDE_C2="${INCLUDE_C2:-false}"

usage() {
    cat << 'EOF'
CyberSec Tools Installer — Production-Grade Security Toolkit

Usage: sudo ./install.sh [OPTIONS]

Options:
  --profile <name>     Install a predefined tool profile:
                         full, ctf, redteam, web, malware, osint,
                         crackstation, lightweight, blueteam
  --module <name>      Install specific module(s). Can be repeated.
                         Modules: misc, networking, recon, web, crypto,
                         pwn, reversing, forensics, malware, ad,
                         wireless, password, stego, cloud, containers,
                         blueteam
  --upgrade-system     Upgrade all system packages before installing
                         (apt upgrade / dnf upgrade / pacman -Syu)
  --skip-heavy         Skip large packages (sagemath, gnuradio, etc.)
  --enable-docker      Pull Docker images for C2 frameworks and complex tools
  --include-c2         Include C2 framework git clones (if Docker disabled)
  --dry-run            Show what would be installed without installing
  --list-profiles      List available profiles and exit
  --list-modules       List available modules and exit
  -h, --help           Show this help and exit

Environment variables:
  INSTALL_DIR          Base install directory (default: /opt)
  GITHUB_TOOL_DIR      Where to clone GitHub repos (default: /opt)
  BURP_VERSION         Burp Suite version (default: 2024.10.1)

Examples:
  sudo ./install.sh                              # Full install
  sudo ./install.sh --profile ctf                # CTF tools
  sudo ./install.sh --module web --module recon   # Web + recon only
  sudo ./install.sh --profile redteam --enable-docker  # Red team + Docker C2
  sudo ./install.sh --upgrade-system             # Full install + system upgrade
EOF
    exit 0
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
    echo "Usage: sudo ./install.sh --profile <name>"
    exit 0
}

list_modules() {
    echo "Available modules:"
    echo ""
    printf "  %-16s %s\n" "misc"       "Base dependencies, utilities, resources, C2, social engineering"
    printf "  %-16s %s\n" "networking" "Port scanning, packet capture, tunneling, MITM"
    printf "  %-16s %s\n" "recon"      "Subdomain enum, OSINT, intelligence gathering"
    printf "  %-16s %s\n" "web"        "Web app testing, fuzzing, scanning"
    printf "  %-16s %s\n" "crypto"     "Cryptography analysis, cipher cracking"
    printf "  %-16s %s\n" "pwn"        "Binary exploitation, shellcode, fuzzers"
    printf "  %-16s %s\n" "reversing"  "Disassembly, debugging, binary analysis"
    printf "  %-16s %s\n" "forensics"  "Disk/memory forensics, file carving"
    printf "  %-16s %s\n" "malware"    "Malware analysis, AV, YARA"
    printf "  %-16s %s\n" "ad"         "Active Directory attacks, Kerberos"
    printf "  %-16s %s\n" "wireless"   "WiFi, Bluetooth, SDR"
    printf "  %-16s %s\n" "password"   "Hash cracking, brute force, wordlists"
    printf "  %-16s %s\n" "stego"      "Steganography tools"
    printf "  %-16s %s\n" "cloud"      "AWS/Azure/GCP security"
    printf "  %-16s %s\n" "containers" "Docker/Kubernetes security"
    printf "  %-16s %s\n" "blueteam"   "Defensive security, IDS/IPS, SIEM, IR"
    echo ""
    echo "Usage: sudo ./install.sh --module <name> [--module <name> ...]"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)         usage ;;
        --profile)         [[ $# -lt 2 ]] && { log_error "--profile requires an argument"; exit 1; }
                           PROFILE="$2"; shift 2 ;;
        --module)          [[ $# -lt 2 ]] && { log_error "--module requires an argument"; exit 1; }
                           SELECTED_MODULES+=("$2"); shift 2 ;;
        --upgrade-system)  UPGRADE_SYSTEM=true; shift ;;
        --skip-heavy)      SKIP_HEAVY=true; shift ;;
        --enable-docker)   ENABLE_DOCKER=true; shift ;;
        --include-c2)      INCLUDE_C2=true; shift ;;
        --dry-run)         DRY_RUN=true; shift ;;
        --list-profiles)   list_profiles ;;
        --list-modules)    list_modules ;;
        *)                 log_error "Unknown option: $1"; usage ;;
    esac
done

# =============================================================================
# Resolve modules to install
# =============================================================================
MODULES_TO_INSTALL=()

if [[ -n "$PROFILE" ]]; then
    local_profile="$SCRIPT_DIR/profiles/${PROFILE}.conf"
    if [[ ! -f "$local_profile" ]]; then
        log_error "Profile not found: $PROFILE"
        log_info "Available: $(find "$SCRIPT_DIR/profiles" -maxdepth 1 -name '*.conf' -print0 2>/dev/null | xargs -0 -I{} basename {} .conf | tr '\n' ' ')"
        exit 1
    fi
    # Source profile config
    source "$local_profile"
    # MODULES variable set by profile
    read -ra MODULES_TO_INSTALL <<< "$MODULES"
    # Validate profile module names
    for mod in "${MODULES_TO_INSTALL[@]}"; do
        # shellcheck disable=SC2076  # Intentional literal match
        if [[ ! " ${ALL_MODULES[*]} " =~ " $mod " ]]; then
            log_error "Profile '$PROFILE' references unknown module: $mod"
            exit 1
        fi
    done
elif [[ ${#SELECTED_MODULES[@]} -gt 0 ]]; then
    # Always include misc for base dependencies
    # shellcheck disable=SC2076
    if [[ ! " ${SELECTED_MODULES[*]} " =~ " misc " ]]; then
        MODULES_TO_INSTALL=(misc)
    fi
    MODULES_TO_INSTALL+=("${SELECTED_MODULES[@]}")
else
    # Default: full install
    MODULES_TO_INSTALL=("${ALL_MODULES[@]}")
fi

# Export flags for modules
export SKIP_HEAVY ENABLE_DOCKER INCLUDE_C2 UPGRADE_SYSTEM

# =============================================================================
# Source selected modules
# =============================================================================
for mod in "${MODULES_TO_INSTALL[@]}"; do
    local_mod="$SCRIPT_DIR/modules/${mod}.sh"
    if [[ -f "$local_mod" ]]; then
        source "$local_mod"
    else
        log_error "Module not found: $mod"
        exit 1
    fi
done

# =============================================================================
# Dry run
# =============================================================================
if [[ "$DRY_RUN" == "true" ]]; then
    echo ""
    echo -e "${CYAN}${BOLD}=== DRY RUN ===${NC}"
    echo ""
    echo "Profile:        ${PROFILE:-custom}"
    echo "Modules:        ${MODULES_TO_INSTALL[*]}"
    echo "Skip heavy:     $SKIP_HEAVY"
    echo "Docker:         $ENABLE_DOCKER"
    echo "C2:             $INCLUDE_C2"
    echo "System upgrade: $UPGRADE_SYSTEM"
    echo ""
    echo "The following module install functions would run:"
    for mod in "${MODULES_TO_INSTALL[@]}"; do
        echo "  - install_module_${mod}"
    done
    echo ""
    exit 0
fi

# =============================================================================
# Main installation
# =============================================================================
LOG_FILE="$SCRIPT_DIR/cybersec_install.log"
: > "$LOG_FILE"
VERSION_FILE="$SCRIPT_DIR/.versions"

main() {
    check_root
    print_banner

    log_info "Profile: ${PROFILE:-full}"
    log_info "Modules: ${MODULES_TO_INSTALL[*]}"
    log_info "Starting installation..."
    echo ""

    local start_time
    start_time=$(date +%s)

    # Stage 1: Refresh package lists (required for installing packages)
    log_info "Refreshing package lists..."
    pkg_update >> "$LOG_FILE" 2>&1
    log_success "Package lists refreshed"

    # Optional: full system upgrade (only with --upgrade-system)
    if [[ "$UPGRADE_SYSTEM" == "true" ]]; then
        log_info "Upgrading system packages (--upgrade-system)..."
        pkg_upgrade >> "$LOG_FILE" 2>&1
        log_success "System packages upgraded"
    fi
    echo ""

    # Stage 2: Install modules
    install_modules

    # Final summary
    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$(( end_time - start_time ))
    local minutes=$(( elapsed / 60 ))
    local seconds=$(( elapsed % 60 ))

    echo ""
    echo -e "${GREEN}${BOLD}=============================================${NC}"
    log_success "Installation complete! (${minutes}m ${seconds}s)"
    echo -e "${GREEN}${BOLD}=============================================${NC}"
    log_info "Profile: ${PROFILE:-full}"
    log_info "Modules installed: ${MODULES_TO_INSTALL[*]}"
    log_info "Log file: $LOG_FILE"
    log_info "Version tracking: $VERSION_FILE"
    echo ""
    log_info "Tool locations:"
    log_info "  System packages:  managed by $PKG_MANAGER"
    log_info "  pipx tools:       $REAL_HOME/.local/bin/"
    log_info "  Go tools:         ${GOPATH:-$REAL_HOME/go}/bin/"
    [[ -d "$REAL_HOME/.cargo/bin" ]] && \
    log_info "  Cargo tools:      $REAL_HOME/.cargo/bin/"
    log_info "  GitHub repos:     $GITHUB_TOOL_DIR/"
    log_info "  Binary releases:  /usr/local/bin/"
    echo ""
    log_warn "Ensure these are in ${REAL_USER}'s PATH:"
    log_warn "  export PATH=\"\$HOME/.local/bin:\$HOME/go/bin:\$HOME/.cargo/bin:\$PATH\""
    log_warn "Some tools may require additional configuration"
    echo ""
}

# ----- Module installation ---------------------------------------------------
install_modules() {
    for mod in "${MODULES_TO_INSTALL[@]}"; do
        echo ""
        local func_name
        case "$mod" in
            networking) func_name="install_module_networking" ;;
            reversing)  func_name="install_module_reversing" ;;
            containers) func_name="install_module_containers" ;;
            *)          func_name="install_module_${mod}" ;;
        esac

        if declare -f "$func_name" > /dev/null 2>&1; then
            log_info "========== Module: $mod =========="
            "$func_name"
        else
            log_warn "No install function for module: $mod"
        fi
    done
}

main "$@"
