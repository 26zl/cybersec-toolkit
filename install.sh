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
SELECTED_TOOLS=()
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
                         blueteam, mobile
  --tool <name>        Install a single tool by name. Can be repeated.
                         Searches all modules for a matching package,
                         pipx tool, Go binary, cargo crate, gem, or repo.
  --upgrade-system     Upgrade all system packages before installing
                         (apt upgrade / dnf upgrade / pacman -Syu)
  --skip-heavy         Skip large packages (sagemath, gnuradio, etc.)
  --enable-docker      Pull Docker images (C2 frameworks, IR platforms, MobSF, etc.)
  --include-c2         Enable C2 frameworks (requires --enable-docker)
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
  sudo ./install.sh --tool sqlmap --tool nmap     # Install individual tools
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
    printf "  %-16s %s\n" "mobile"     "Android/iOS app testing, APK analysis"
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
        --tool)            [[ $# -lt 2 ]] && { log_error "--tool requires a name"; exit 1; }
                           SELECTED_TOOLS+=("$2"); shift 2 ;;
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
# Single-tool install (--tool)
# =============================================================================
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

    # --- APT packages ---
    local pkg_arrs=(
        MISC_BASE_PACKAGES MISC_SECURITY_PACKAGES MISC_HEAVY_PACKAGES
        NET_PACKAGES RECON_PACKAGES WEB_PACKAGES PWN_PACKAGES RE_PACKAGES
        FORENSICS_PACKAGES MALWARE_PACKAGES WIRELESS_PACKAGES PASSWORD_PACKAGES
        STEGO_PACKAGES BLUETEAM_PACKAGES MOBILE_PACKAGES AD_PACKAGES
        CRYPTO_PACKAGES CLOUD_PACKAGES CONTAINER_PACKAGES
    )
    for a in "${pkg_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via $PKG_MANAGER..."
            pkg_install "$tool" >> "$LOG_FILE" 2>&1 && log_success "Installed: $tool" || log_error "Failed: $tool"
            return 0
        fi
    done

    # --- pipx ---
    local pipx_arrs=(
        MISC_PIPX NET_PIPX RECON_PIPX WEB_PIPX CRYPTO_PIPX PWN_PIPX RE_PIPX
        FORENSICS_PIPX MALWARE_PIPX AD_PIPX WIRELESS_PIPX PASSWORD_PIPX
        STEGO_PIPX CLOUD_PIPX BLUETEAM_PIPX MOBILE_PIPX
    )
    for a in "${pipx_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via pipx..."
            ensure_pipx
            pipx_install "$tool" >> "$LOG_FILE" 2>&1 && log_success "Installed: $tool" || log_error "Failed: $tool"
            return 0
        fi
    done

    # --- Go (match binary name from full import path) ---
    local go_arrs=(
        MISC_GO NET_GO RECON_GO WEB_GO CRYPTO_GO PWN_GO RE_GO
        AD_GO CLOUD_GO CONTAINER_GO BLUETEAM_GO MOBILE_GO
        FORENSICS_GO MALWARE_GO WIRELESS_GO PASSWORD_GO STEGO_GO
    )
    for a in "${go_arrs[@]}"; do
        declare -p "$a" &>/dev/null || continue
        local -n _goref="$a"
        [[ ${#_goref[@]} -eq 0 ]] && continue
        for gopkg in "${_goref[@]}"; do
            local goname
            goname=$(echo "$gopkg" | rev | cut -d/ -f1 | rev | cut -d@ -f1)
            if [[ "$goname" == "$tool" ]]; then
                log_info "Installing $tool via go install..."
                go install "$gopkg" >> "$LOG_FILE" 2>&1 && log_success "Installed: $tool" || log_error "Failed: $tool"
                return 0
            fi
        done
    done

    # --- Cargo ---
    local known_cargo=(feroxbuster rustscan moonwalk pwninit)
    for crate in "${known_cargo[@]}"; do
        if [[ "$crate" == "$tool" ]]; then
            log_info "Installing $tool via cargo..."
            cargo install "$tool" >> "$LOG_FILE" 2>&1 && log_success "Installed: $tool" || log_error "Failed: $tool"
            if [[ -f "$HOME/.cargo/bin/$tool" ]]; then
                ln -sf "$HOME/.cargo/bin/$tool" "/usr/local/bin/$tool" 2>/dev/null || true
            fi
            return 0
        fi
    done

    # --- Gems ---
    local gem_arrs=(WEB_GEMS PWN_GEMS STEGO_GEMS AD_GEMS)
    for a in "${gem_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via gem..."
            gem install "$tool" --no-document >> "$LOG_FILE" 2>&1 && log_success "Installed: $tool" || log_error "Failed: $tool"
            return 0
        fi
    done

    # --- Git repos (match name= prefix) ---
    local git_arrs=(
        MISC_RESOURCES MISC_POSTEXPLOIT MISC_SOCIAL MISC_CTF
        NET_GIT RECON_GIT WEB_GIT CRYPTO_GIT PWN_GIT RE_GIT
        FORENSICS_GIT AD_GIT WIRELESS_GIT PASSWORD_GIT STEGO_GIT
        CLOUD_GIT CONTAINER_GIT BLUETEAM_GIT MOBILE_GIT
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
                git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1 || { log_error "Failed: $tool"; return 1; }
                setup_git_repo "$dest" >> "$LOG_FILE" 2>&1 || true
                log_success "Installed: $tool → $dest"
                return 0
            fi
        done
    done

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
    [[ "$TOOL_FAILED" -gt 0 ]] && log_warn "$TOOL_FAILED tool(s) failed"
    exit 0
fi

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
    # Save CLI flags before sourcing profile (profile must not overwrite explicit CLI flags)
    CLI_SKIP_HEAVY="$SKIP_HEAVY"
    CLI_ENABLE_DOCKER="$ENABLE_DOCKER"
    CLI_INCLUDE_C2="$INCLUDE_C2"
    # Source profile config
    source "$local_profile"
    # CLI flags override profile defaults
    [[ "$CLI_SKIP_HEAVY" == "true" ]]     && SKIP_HEAVY=true
    [[ "$CLI_ENABLE_DOCKER" == "true" ]]  && ENABLE_DOCKER=true
    [[ "$CLI_INCLUDE_C2" == "true" ]]     && INCLUDE_C2=true
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

    # =========================================================================
    # Prerequisite check — verify required tools before starting
    # =========================================================================
    log_info "Checking prerequisites..."
    local prereq_fail=0

    # Hard requirements — abort if missing
    for req in git curl; do
        if ! command_exists "$req"; then
            log_error "MISSING (required): $req — install it first"
            prereq_fail=1
        fi
    done

    if ! command_exists python3; then
        log_error "MISSING (required): python3 — needed for pipx, venvs, and ~157 Python tools"
        prereq_fail=1
    fi

    if [[ "$prereq_fail" -eq 1 ]]; then
        echo ""
        log_error "Aborting: install the missing prerequisites above and re-run."
        exit 1
    fi

    # Soft requirements — warn which categories will be skipped
    local prereq_warns=0

    if ! command_exists pipx && ! command_exists pip3; then
        log_warn "pipx not found — will attempt to install via package manager"
    fi

    if ! command_exists go; then
        log_warn "Go not found — ~55 Go tools will be SKIPPED"
        prereq_warns=$((prereq_warns + 1))
    fi

    if ! command_exists cargo; then
        log_warn "Cargo/Rust not found — 4 Cargo tools will be SKIPPED (feroxbuster, RustScan, moonwalk, pwninit)"
        prereq_warns=$((prereq_warns + 1))
    fi

    if ! command_exists gem; then
        log_warn "Ruby/gem not found — 6 Ruby gems will be SKIPPED (wpscan, evil-winrm, etc.)"
        prereq_warns=$((prereq_warns + 1))
    fi

    if ! command_exists make && ! command_exists gcc; then
        log_warn "Build tools (make/gcc) not found — ~15 build-from-source tools will be SKIPPED"
        prereq_warns=$((prereq_warns + 1))
    fi

    if [[ "${ENABLE_DOCKER:-false}" == "true" ]] && ! command_exists docker; then
        log_error "MISSING: docker — --enable-docker was set but Docker is not installed"
        log_error "Install Docker first: https://docs.docker.com/engine/install/"
        log_error "All Docker images (C2, IR platforms, MobSF, BeEF) will be SKIPPED"
        prereq_warns=$((prereq_warns + 1))
    fi

    if [[ "$prereq_warns" -gt 0 ]]; then
        echo ""
        log_warn "$prereq_warns optional runtimes missing — some tools will be skipped (see warnings above)"
        log_info "The misc module will attempt to install runtimes via your package manager."
        echo ""
    else
        log_success "All prerequisites found"
    fi
    echo ""

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
    if [[ "$TOTAL_MODULE_FAILURES" -gt 0 ]]; then
        log_error "Module failures: $TOTAL_MODULE_FAILURES"
    fi
    log_info "Log file: $LOG_FILE"
    log_info "Version tracking: $VERSION_FILE"
    echo ""
    log_info "Tool locations:"
    log_info "  System packages:  managed by $PKG_MANAGER"
    log_info "  pipx tools:       /usr/local/bin/ (PIPX_HOME=/opt/pipx)"
    log_info "  Go tools:         /usr/local/bin/ (GOBIN)"
    log_info "  Cargo tools:      /usr/local/bin/ (symlinked)"
    log_info "  GitHub repos:     $GITHUB_TOOL_DIR/"
    log_info "  Binary releases:  /usr/local/bin/"
    echo ""

    if [[ "$TOTAL_MODULE_FAILURES" -gt 0 ]]; then
        exit 1
    fi
}

# ----- Module installation ---------------------------------------------------
TOTAL_MODULE_FAILURES=0

install_modules() {
    for mod in "${MODULES_TO_INSTALL[@]}"; do
        echo ""
        local func_name="install_module_${mod}"

        if declare -f "$func_name" > /dev/null 2>&1; then
            log_info "========== Module: $mod =========="
            if ! "$func_name"; then
                log_error "Module failed: $mod"
                TOTAL_MODULE_FAILURES=$((TOTAL_MODULE_FAILURES + 1))
            fi
        else
            log_warn "No install function for module: $mod"
        fi
    done
}

main "$@"
