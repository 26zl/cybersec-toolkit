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
ENABLE_DOCKER="${ENABLE_DOCKER:-false}"
INCLUDE_C2="${INCLUDE_C2:-false}"

usage() {
    cat << 'EOF'
CyberSec Tools Installer — Production-Grade Security Toolkit

Usage: sudo ./install.sh [OPTIONS]        # Linux (requires root)
       ./install.sh [OPTIONS]              # Termux (no root needed)

Options:
  --profile <name>     Install a predefined tool profile:
                         full, ctf, redteam, web, malware, osint,
                         crackstation, lightweight, blueteam
  --module <name>      Install specific module(s). Can be repeated.
                         Modules: misc, networking, recon, web, crypto,
                         pwn, reversing, forensics, malware, enterprise,
                         wireless, cracking, stego, cloud, containers,
                         blueteam, mobile, blockchain
  --tool <name>        Install a single tool by name. Can be repeated.
                         Searches all modules for a matching package,
                         pipx tool, Go binary, cargo crate, gem, or repo.
  --upgrade-system     Upgrade all system packages before installing
                         (apt upgrade / dnf upgrade / pacman -Syu)
  --skip-heavy         Skip large packages (sagemath, gimp, audacity, gnuradio, etc.)
  --enable-docker      Pull Docker images (C2 frameworks, IR platforms, MobSF, etc.)
  --include-c2         Enable C2 frameworks (requires --enable-docker)
  --dry-run            Show what would be installed without installing
  -j, --parallel <N>   Number of parallel install jobs (default: 4, 1=sequential)
  -v, --verbose        Enable debug logging and system environment dump
  --list-profiles      List available profiles and exit
  --list-modules       List available modules and exit
  -h, --help           Show this help and exit

All runtimes (Python, Go, Ruby, Rust, Java) and dev libraries are
installed automatically. Only Docker requires manual installation.

Environment variables:
  GITHUB_TOOL_DIR      Where to clone GitHub repos (default: /opt)
  GITHUB_TOKEN         GitHub personal access token for API requests
                         (avoids rate limits on binary downloads)
  BURP_VERSION         Burp Suite version (default: 2024.10.1)
  GO_INSTALL_VERSION   Go version to download from go.dev (default: 1.23.6)
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
    printf "  %-16s %s\n" "misc"       "Security tools, utilities, resources, C2, social engineering"
    printf "  %-16s %s\n" "networking" "Port scanning, packet capture, tunneling, MITM"
    printf "  %-16s %s\n" "recon"      "Subdomain enum, OSINT, intelligence gathering"
    printf "  %-16s %s\n" "web"        "Web app testing, fuzzing, scanning"
    printf "  %-16s %s\n" "crypto"     "Cryptography analysis, cipher cracking"
    printf "  %-16s %s\n" "pwn"        "Binary exploitation, shellcode, fuzzers"
    printf "  %-16s %s\n" "reversing"  "Disassembly, debugging, binary analysis"
    printf "  %-16s %s\n" "forensics"  "Disk/memory forensics, file carving"
    printf "  %-16s %s\n" "malware"    "Malware analysis, AV, YARA"
    printf "  %-16s %s\n" "enterprise" "AD, Kerberos, LDAP, Azure AD, lateral movement"
    printf "  %-16s %s\n" "wireless"   "WiFi, Bluetooth, SDR"
    printf "  %-16s %s\n" "cracking"   "Hash cracking, brute force, wordlists"
    printf "  %-16s %s\n" "stego"      "Steganography tools"
    printf "  %-16s %s\n" "cloud"      "AWS/Azure/GCP security"
    printf "  %-16s %s\n" "containers" "Docker/Kubernetes security"
    printf "  %-16s %s\n" "blueteam"   "Defensive security, IDS/IPS, SIEM, IR"
    printf "  %-16s %s\n" "mobile"     "Android/iOS app testing, APK analysis"
    printf "  %-16s %s\n" "blockchain" "Smart contract auditing, analysis, reversing"
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
        --skip-heavy)      SKIP_HEAVY=true; shift ;;
        --enable-docker)   ENABLE_DOCKER=true; shift ;;
        --include-c2)      INCLUDE_C2=true; shift ;;
        --dry-run)         DRY_RUN=true; shift ;;
        -j|--parallel)     [[ $# -lt 2 ]] && { log_error "-j/--parallel requires a number"; exit 1; }
                           PARALLEL_JOBS="$2"; shift 2 ;;
        -v|--verbose)      VERBOSE=true; shift ;;
        --list-profiles)   list_profiles ;;
        --list-modules)    list_modules ;;
        *)                 log_error "Unknown option: $1"; usage ;;
    esac
done

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
        FORENSICS_PACKAGES MALWARE_PACKAGES WIRELESS_PACKAGES WIRELESS_HEAVY_PACKAGES
        CRACKING_PACKAGES STEGO_PACKAGES BLUETEAM_PACKAGES MOBILE_PACKAGES
        ENTERPRISE_PACKAGES CRYPTO_PACKAGES CLOUD_PACKAGES BLOCKCHAIN_PACKAGES
    )
    for a in "${pkg_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            local _tmp_pkg=("$tool")
            fixup_package_names _tmp_pkg
            if [[ ${#_tmp_pkg[@]} -eq 0 ]]; then
                log_warn "$tool is not available on this distro — skipped"
                return 0
            fi
            log_info "Installing ${_tmp_pkg[0]} via $PKG_MANAGER..."
            pkg_install "${_tmp_pkg[0]}" >> "$LOG_FILE" 2>&1 && log_success "Installed: ${_tmp_pkg[0]}" || log_error "Failed: ${_tmp_pkg[0]}"
            return 0
        fi
    done

    # pipx
    local pipx_arrs=(
        MISC_PIPX NET_PIPX RECON_PIPX WEB_PIPX CRYPTO_PIPX PWN_PIPX RE_PIPX
        FORENSICS_PIPX MALWARE_PIPX ENTERPRISE_PIPX WIRELESS_PIPX CRACKING_PIPX
        STEGO_PIPX CLOUD_PIPX CONTAINER_PIPX BLUETEAM_PIPX MOBILE_PIPX
        BLOCKCHAIN_PIPX
    )
    for a in "${pipx_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via pipx..."
            ensure_pipx
            pipx_install "$tool" >> "$LOG_FILE" 2>&1 && log_success "Installed: $tool" || log_error "Failed: $tool"
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
                log_info "Installing $tool via go install..."
                go install "$gopkg" >> "$LOG_FILE" 2>&1 && log_success "Installed: $tool" || log_error "Failed: $tool"
                return 0
            fi
        done
    done

    # Cargo
    local cargo_arrs=(
        WEB_CARGO NET_CARGO PWN_CARGO
    )
    for a in "${cargo_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via cargo..."
            cargo install "$tool" >> "$LOG_FILE" 2>&1 && log_success "Installed: $tool" || log_error "Failed: $tool"
            if [[ -f "$HOME/.cargo/bin/$tool" ]]; then
                ln -sf "$HOME/.cargo/bin/$tool" "$PIPX_BIN_DIR/$tool" 2>/dev/null || true
            fi
            return 0
        fi
    done

    # Gems
    local gem_arrs=(WEB_GEMS PWN_GEMS STEGO_GEMS ENTERPRISE_GEMS)
    for a in "${gem_arrs[@]}"; do
        if _arr_has "$a" "$tool"; then
            log_info "Installing $tool via gem..."
            gem install "$tool" --no-document >> "$LOG_FILE" 2>&1 && log_success "Installed: $tool" || log_error "Failed: $tool"
            return 0
        fi
    done

    # Git repos (match name= prefix)
    local git_arrs=(
        MISC_GIT NET_GIT RECON_GIT WEB_GIT CRYPTO_GIT PWN_GIT RE_GIT
        FORENSICS_GIT MALWARE_GIT ENTERPRISE_GIT WIRELESS_GIT CRACKING_GIT
        STEGO_GIT CLOUD_GIT CONTAINER_GIT BLUETEAM_GIT MOBILE_GIT
        BLOCKCHAIN_GIT
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
    if [[ "$TOOL_FAILED" -gt 0 ]]; then
        log_warn "$TOOL_FAILED tool(s) failed"
        exit 1
    fi
    exit 0
fi

# Resolve modules to install
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
    MODULES_TO_INSTALL=("${SELECTED_MODULES[@]}")
else
    # Default: full install
    MODULES_TO_INSTALL=("${ALL_MODULES[@]}")
fi

# Export flags for modules
export SKIP_HEAVY ENABLE_DOCKER INCLUDE_C2 UPGRADE_SYSTEM VERBOSE PARALLEL_JOBS

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

    local total=$((apt_count + pipx_count + go_count + cargo_count + gem_count + git_count + binary_count + build_count))

    # Per-method time benchmarks (seconds) — min/max for range estimate
    local apt_min=0 apt_max=0
    if [[ "$apt_count" -gt 0 ]]; then
        apt_min=$((30 + apt_count / 10))    # batch install + resolution overhead
        apt_max=$((60 + apt_count / 5))
    fi
    local pipx_min=$((pipx_count * 3))      pipx_max=$((pipx_count * 6))
    local go_min=$((go_count * 4))           go_max=$((go_count * 8))
    local cargo_min=$((cargo_count * 10))    cargo_max=$((cargo_count * 25))
    local gem_min=$((gem_count * 2))         gem_max=$((gem_count * 5))
    local git_min=$((git_count * 2))         git_max=$((git_count * 5))
    local binary_min=$((binary_count * 3))   binary_max=$((binary_count * 8))
    local build_min=$((build_count * 8))     build_max=$((build_count * 20))

    local total_min_s=$((apt_min + pipx_min + go_min + cargo_min + gem_min + git_min + binary_min + build_min))
    local total_max_s=$((apt_max + pipx_max + go_max + cargo_max + gem_max + git_max + binary_max + build_max))

    # Round up to minutes
    local min_minutes=$(( (total_min_s + 59) / 60 ))
    local max_minutes=$(( (total_max_s + 59) / 60 ))

    log_warn "Estimated install time: ~${min_minutes}-${max_minutes} minutes (${#MODULES_TO_INSTALL[@]} modules, ${total}+ tools)"
    log_info "  Breakdown: ${apt_count} apt, ${pipx_count} pipx, ${go_count} go, ${cargo_count} cargo, ${gem_count} gem, ${git_count} git, ${binary_count} binary, ${build_count} source"
    log_info "  Speed depends on network bandwidth, disk I/O, and CPU cores"
    echo ""
}

# Dry run
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
    echo "Parallel jobs:  $PARALLEL_JOBS"
    echo "Verbose:        $VERBOSE"
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
: > "$LOG_FILE"
VERSION_FILE="$SCRIPT_DIR/.versions"

main() {
    check_root
    print_banner

    if [[ "$PKG_MANAGER" == "unknown" ]]; then
        log_error "Unsupported distribution — could not detect package manager"
        log_error "Supported: apt (Debian/Ubuntu/Kali), dnf (Fedora/RHEL), pacman (Arch), zypper (openSUSE), pkg (Termux/Android)"
        exit 1
    fi

    # Verbose mode: log system environment and enable bash trace
    if [[ "$VERBOSE" == "true" ]]; then
        log_info "Verbose mode enabled"
        log_system_environment
        enable_debug_trace
    fi

    # Termux: Docker and snap are not available
    if [[ "$PKG_MANAGER" == "pkg" ]] && [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        log_warn "Docker is not available on Termux/Android — skipping Docker tools"
        ENABLE_DOCKER="false"
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

    log_info "Starting installation..."
    echo ""

    local start_time
    start_time=$(date +%s)

    # Stage 1: Refresh package lists (required for installing packages)
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

    # Stage 2: Install shared base dependencies (runtimes, compilers, dev libs)
    install_shared_deps
    echo ""

    # Stage 3: Ensure additional toolchains are available
    ensure_pipx
    ensure_go
    ensure_cargo
    echo ""

    # Stage 4: Install modules
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
    if [[ "$TOTAL_MODULE_FAILURES" -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}=============================================${NC}"
        log_warn "Installation finished with errors (${minutes}m ${seconds}s)"
        echo -e "${YELLOW}${BOLD}=============================================${NC}"
    else
        echo -e "${GREEN}${BOLD}=============================================${NC}"
        log_success "Installation complete! (${minutes}m ${seconds}s)"
        echo -e "${GREEN}${BOLD}=============================================${NC}"
    fi
    log_info "Profile: ${PROFILE:-full}"
    log_info "Modules installed: ${MODULES_TO_INSTALL[*]}"
    if [[ "$TOTAL_MODULE_FAILURES" -gt 0 ]]; then
        log_error "Modules with failures: $TOTAL_MODULE_FAILURES"
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

    if [[ "$TOTAL_MODULE_FAILURES" -gt 0 ]]; then
        exit 1
    fi
}

# Module installation
TOTAL_MODULE_FAILURES=0

install_modules() {
    for mod in "${MODULES_TO_INSTALL[@]}"; do
        echo ""
        local func_name="install_module_${mod}"

        if declare -f "$func_name" > /dev/null 2>&1; then
            log_info "========== Module: $mod =========="
            local _mod_start; _mod_start=$(date +%s)
            log_debug "install_modules: starting module '$mod'"
            # Track failures via global counter (not return code — modules don't
            # aggregate sub-function failures without set -e)
            local _pre_failures=$TOTAL_TOOL_FAILURES
            "$func_name"
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
}

main "$@"
