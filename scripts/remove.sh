#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# =============================================================================
# CyberSec Tools — Removal Script (Modular)
# Sources all modules and removes all installed tools across all methods.
# Supports Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE.
#
# Usage:
#   sudo ./scripts/remove.sh                      # Remove everything
#   sudo ./scripts/remove.sh --module web          # Remove web module only
#   sudo ./scripts/remove.sh --remove-deps          # Also remove base packages (dangerous)
#   sudo ./scripts/remove.sh --yes                 # Skip confirmation
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Source all modules to get tool arrays (ALL_MODULES defined in lib/common.sh)
for mod in "${ALL_MODULES[@]}"; do
    source "$SCRIPT_DIR/modules/${mod}.sh"
done

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << 'EOF'
CyberSec Tools — Removal Script

Usage: sudo ./scripts/remove.sh [OPTIONS]

Options:
  --module <name>    Remove specific module only (can be repeated)
  --remove-deps      Also remove base dependencies (python3, openssl, git,
                       build-essential, etc.) — DANGEROUS, may break system
  --yes              Skip confirmation prompt
  -h, --help         Show this help and exit

Modules: misc, networking, recon, web, crypto, pwn, reversing, forensics,
         malware, ad, wireless, password, stego, cloud, containers, blueteam,
         mobile

By default, base dependencies are preserved.  Use --remove-deps explicitly
to include them in the removal (not recommended on production systems).
EOF
    exit 0
fi

# --- Parse args --------------------------------------------------------------
REMOVE_MODULES=()
REMOVE_DEPS=false
AUTO_YES=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --module)      [[ $# -lt 2 ]] && { log_error "--module requires an argument"; exit 1; }
                       REMOVE_MODULES+=("$2"); shift 2 ;;
        --remove-deps) REMOVE_DEPS=true; shift ;;
        --yes)         AUTO_YES=true; shift ;;
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

# --- Confirmation ------------------------------------------------------------
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

# =============================================================================
# Build aggregate removal lists from module arrays
# =============================================================================
PKGS_TO_REMOVE=()
PIPX_TO_REMOVE=()
GO_BINS_TO_REMOVE=()
GIT_NAMES_TO_REMOVE=()
GEMS_TO_REMOVE=()
CARGO_TO_REMOVE=()

# --- Misc ---
if should_remove "misc"; then
    if [[ "$REMOVE_DEPS" == "true" ]]; then
        [[ ${#MISC_BASE_PACKAGES[@]} -gt 0 ]]     && PKGS_TO_REMOVE+=("${MISC_BASE_PACKAGES[@]}")
    else
        log_info "Preserving base dependencies (--remove-deps not set)"
    fi
    [[ ${#MISC_SECURITY_PACKAGES[@]} -gt 0 ]] && PKGS_TO_REMOVE+=("${MISC_SECURITY_PACKAGES[@]}")
    [[ ${#MISC_HEAVY_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${MISC_HEAVY_PACKAGES[@]}")
    [[ ${#MISC_PIPX[@]} -gt 0 ]]      && PIPX_TO_REMOVE+=("${MISC_PIPX[@]}")
    [[ ${#MISC_GO_BINS[@]} -gt 0 ]]   && GO_BINS_TO_REMOVE+=("${MISC_GO_BINS[@]}")
    [[ ${#MISC_GIT_NAMES[@]} -gt 0 ]] && GIT_NAMES_TO_REMOVE+=("${MISC_GIT_NAMES[@]}")
fi

# --- Networking ---
if should_remove "networking"; then
    [[ ${#NET_PACKAGES[@]} -gt 0 ]]   && PKGS_TO_REMOVE+=("${NET_PACKAGES[@]}")
    [[ ${#NET_PIPX[@]} -gt 0 ]]      && PIPX_TO_REMOVE+=("${NET_PIPX[@]}")
    [[ ${#NET_GO_BINS[@]} -gt 0 ]]   && GO_BINS_TO_REMOVE+=("${NET_GO_BINS[@]}")
    [[ ${#NET_GIT_NAMES[@]} -gt 0 ]] && GIT_NAMES_TO_REMOVE+=("${NET_GIT_NAMES[@]}")
    CARGO_TO_REMOVE+=(rustscan)
fi

# --- Recon ---
if should_remove "recon"; then
    [[ ${#RECON_PACKAGES[@]} -gt 0 ]]   && PKGS_TO_REMOVE+=("${RECON_PACKAGES[@]}")
    [[ ${#RECON_PIPX[@]} -gt 0 ]]       && PIPX_TO_REMOVE+=("${RECON_PIPX[@]}")
    [[ ${#RECON_GO_BINS[@]} -gt 0 ]]    && GO_BINS_TO_REMOVE+=("${RECON_GO_BINS[@]}")
    [[ ${#RECON_GIT_NAMES[@]} -gt 0 ]]  && GIT_NAMES_TO_REMOVE+=("${RECON_GIT_NAMES[@]}")
fi

# --- Web ---
if should_remove "web"; then
    [[ ${#WEB_PACKAGES[@]} -gt 0 ]]   && PKGS_TO_REMOVE+=("${WEB_PACKAGES[@]}")
    [[ ${#WEB_PIPX[@]} -gt 0 ]]       && PIPX_TO_REMOVE+=("${WEB_PIPX[@]}")
    [[ ${#WEB_GO_BINS[@]} -gt 0 ]]    && GO_BINS_TO_REMOVE+=("${WEB_GO_BINS[@]}")
    [[ ${#WEB_GIT_NAMES[@]} -gt 0 ]]  && GIT_NAMES_TO_REMOVE+=("${WEB_GIT_NAMES[@]}")
    [[ ${#WEB_GEMS[@]} -gt 0 ]]       && GEMS_TO_REMOVE+=("${WEB_GEMS[@]}")
    [[ ${#WEB_CARGO[@]} -gt 0 ]]      && CARGO_TO_REMOVE+=("${WEB_CARGO[@]}")
fi

# --- Crypto ---
if should_remove "crypto"; then
    [[ ${#CRYPTO_PIPX[@]} -gt 0 ]]       && PIPX_TO_REMOVE+=("${CRYPTO_PIPX[@]}")
    [[ ${#CRYPTO_GIT_NAMES[@]} -gt 0 ]]  && GIT_NAMES_TO_REMOVE+=("${CRYPTO_GIT_NAMES[@]}")
fi

# --- Pwn ---
if should_remove "pwn"; then
    [[ ${#PWN_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${PWN_PACKAGES[@]}")
    [[ ${#PWN_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${PWN_PIPX[@]}")
    [[ ${#PWN_GO_BINS[@]} -gt 0 ]]     && GO_BINS_TO_REMOVE+=("${PWN_GO_BINS[@]}")
    [[ ${#PWN_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${PWN_GIT_NAMES[@]}")
    [[ ${#PWN_GEMS[@]} -gt 0 ]]        && GEMS_TO_REMOVE+=("${PWN_GEMS[@]}")
    CARGO_TO_REMOVE+=(moonwalk pwninit)
fi

# --- Reversing ---
if should_remove "reversing"; then
    [[ ${#RE_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${RE_PACKAGES[@]}")
    [[ ${#RE_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${RE_PIPX[@]}")
    [[ ${#RE_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${RE_GIT_NAMES[@]}")
fi

# --- Forensics ---
if should_remove "forensics"; then
    [[ ${#FORENSICS_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${FORENSICS_PACKAGES[@]}")
    [[ ${#FORENSICS_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${FORENSICS_PIPX[@]}")
    [[ ${#FORENSICS_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${FORENSICS_GIT_NAMES[@]}")
fi

# --- Malware ---
if should_remove "malware"; then
    [[ ${#MALWARE_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${MALWARE_PACKAGES[@]}")
    [[ ${#MALWARE_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${MALWARE_PIPX[@]}")
fi

# --- AD ---
if should_remove "ad"; then
    [[ ${#AD_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${AD_PIPX[@]}")
    [[ ${#AD_GO_BINS[@]} -gt 0 ]]     && GO_BINS_TO_REMOVE+=("${AD_GO_BINS[@]}")
    [[ ${#AD_GEMS[@]} -gt 0 ]]        && GEMS_TO_REMOVE+=("${AD_GEMS[@]}")
    [[ ${#AD_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${AD_GIT_NAMES[@]}")
fi

# --- Wireless ---
if should_remove "wireless"; then
    [[ ${#WIRELESS_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${WIRELESS_PACKAGES[@]}")
    [[ ${#WIRELESS_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${WIRELESS_PIPX[@]}")
    [[ ${#WIRELESS_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${WIRELESS_GIT_NAMES[@]}")
fi

# --- Password ---
if should_remove "password"; then
    [[ ${#PASSWORD_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${PASSWORD_PACKAGES[@]}")
    [[ ${#PASSWORD_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${PASSWORD_PIPX[@]}")
    [[ ${#PASSWORD_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${PASSWORD_GIT_NAMES[@]}")
fi

# --- Stego ---
if should_remove "stego"; then
    [[ ${#STEGO_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${STEGO_PACKAGES[@]}")
    [[ ${#STEGO_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${STEGO_PIPX[@]}")
    [[ ${#STEGO_GEMS[@]} -gt 0 ]]        && GEMS_TO_REMOVE+=("${STEGO_GEMS[@]}")
    [[ ${#STEGO_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${STEGO_GIT_NAMES[@]}")
fi

# --- Cloud ---
if should_remove "cloud"; then
    [[ ${#CLOUD_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${CLOUD_PIPX[@]}")
    [[ ${#CLOUD_GO_BINS[@]} -gt 0 ]]     && GO_BINS_TO_REMOVE+=("${CLOUD_GO_BINS[@]}")
    [[ ${#CLOUD_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${CLOUD_GIT_NAMES[@]}")
fi

# --- Containers ---
if should_remove "containers"; then
    [[ ${#CONTAINER_GIT_NAMES[@]} -gt 0 ]] && GIT_NAMES_TO_REMOVE+=("${CONTAINER_GIT_NAMES[@]}")
fi

# --- Mobile ---
if should_remove "mobile"; then
    [[ ${#MOBILE_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${MOBILE_PACKAGES[@]}")
    [[ ${#MOBILE_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${MOBILE_PIPX[@]}")
    [[ ${#MOBILE_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${MOBILE_GIT_NAMES[@]}")
fi

# --- Blue Team ---
if should_remove "blueteam"; then
    [[ ${#BLUETEAM_PACKAGES[@]} -gt 0 ]]    && PKGS_TO_REMOVE+=("${BLUETEAM_PACKAGES[@]}")
    [[ ${#BLUETEAM_PIPX[@]} -gt 0 ]]        && PIPX_TO_REMOVE+=("${BLUETEAM_PIPX[@]}")
    [[ ${#BLUETEAM_GIT_NAMES[@]} -gt 0 ]]   && GIT_NAMES_TO_REMOVE+=("${BLUETEAM_GIT_NAMES[@]}")
fi

# =============================================================================
# Execute removal
# =============================================================================

# --- 1) System packages ------------------------------------------------------
if [[ ${#PKGS_TO_REMOVE[@]} -gt 0 ]]; then
    log_info "Removing ${#PKGS_TO_REMOVE[@]} system packages..."
    for pkg in "${PKGS_TO_REMOVE[@]}"; do
        if pkg_remove "$pkg" >> "$LOG_FILE" 2>&1; then
            log_success "Removed: $pkg"
        else
            log_warn "Not found or failed: $pkg"
        fi
    done
else
    log_info "No system packages to remove"
fi
echo ""

# --- 2) pipx tools -----------------------------------------------------------
if [[ ${#PIPX_TO_REMOVE[@]} -gt 0 ]] && command_exists pipx; then
    log_info "Removing ${#PIPX_TO_REMOVE[@]} pipx tools..."
    for tool in "${PIPX_TO_REMOVE[@]}"; do
        pipx_remove "$tool" >> "$LOG_FILE" 2>&1 && \
            log_success "Removed pipx: $tool" || true
    done
else
    [[ ${#PIPX_TO_REMOVE[@]} -gt 0 ]] && log_warn "pipx not found — skipping"
fi
echo ""

# --- 3) Go binaries ----------------------------------------------------------
# Go binaries are installed to /usr/local/bin (GOBIN) system-wide
if [[ ${#GO_BINS_TO_REMOVE[@]} -gt 0 ]]; then
    log_info "Removing ${#GO_BINS_TO_REMOVE[@]} Go binaries..."
    for bin in "${GO_BINS_TO_REMOVE[@]}"; do
        if [[ -f "/usr/local/bin/$bin" ]]; then
            rm -f "/usr/local/bin/$bin"
            log_success "Removed: /usr/local/bin/$bin"
        fi
    done
fi
echo ""

# --- 4) GitHub repos ---------------------------------------------------------
if [[ ${#GIT_NAMES_TO_REMOVE[@]} -gt 0 ]]; then
    log_info "Removing ${#GIT_NAMES_TO_REMOVE[@]} GitHub repositories..."
    for name in "${GIT_NAMES_TO_REMOVE[@]}"; do
        repo_path="$GITHUB_TOOL_DIR/$name"
        if [[ -d "$repo_path" ]]; then
            sudo rm -rf "$repo_path"
            log_success "Removed: $repo_path"
        fi
    done
fi
echo ""

# --- 5) Ruby gems ------------------------------------------------------------
if [[ ${#GEMS_TO_REMOVE[@]} -gt 0 ]] && command_exists gem; then
    log_info "Removing ${#GEMS_TO_REMOVE[@]} Ruby gems..."
    for gem_name in "${GEMS_TO_REMOVE[@]}"; do
        gem uninstall -x "$gem_name" >> "$LOG_FILE" 2>&1 && \
            log_success "Removed gem: $gem_name" || true
    done
fi
echo ""

# --- 6) Cargo tools ----------------------------------------------------------
if [[ ${#CARGO_TO_REMOVE[@]} -gt 0 ]]; then
    log_info "Removing ${#CARGO_TO_REMOVE[@]} Cargo tools..."
    for crate in "${CARGO_TO_REMOVE[@]}"; do
        if command_exists cargo; then
            cargo uninstall "$crate" >> "$LOG_FILE" 2>&1 && \
                log_success "Removed cargo: $crate" || true
        elif [[ -f "$HOME/.cargo/bin/$crate" ]]; then
            rm -f "$HOME/.cargo/bin/$crate"
            log_success "Removed: $HOME/.cargo/bin/$crate"
        fi
    done
fi
echo ""

# --- 7) Binary releases ------------------------------------------------------
log_info "Removing binary releases from /usr/local/bin..."
BINARY_TOOLS=(findomain ligolo-proxy ligolo-agent frp chainsaw kerbrute trivy grype kubeaudit cdk pspy gophish trufflehog stegseek rp-lin d2j-dex2jar velociraptor laurel)
for bin in "${BINARY_TOOLS[@]}"; do
    if [[ -f "/usr/local/bin/$bin" ]]; then
        sudo rm -f "/usr/local/bin/$bin"
        log_success "Removed: /usr/local/bin/$bin"
    fi
done
# Jar wrappers and directories
for jar_bin in ysoserial jd-gui; do
    [[ -f "/usr/local/bin/$jar_bin" ]] && sudo rm -f "/usr/local/bin/$jar_bin"
done
sudo rm -rf /opt/cybersec-jars 2>/dev/null
sudo rm -rf /opt/jadx 2>/dev/null
sudo rm -rf /opt/dex2jar 2>/dev/null
echo ""

# --- 8) Special tools --------------------------------------------------------
log_info "Removing special tools..."

# Searchsploit symlink
[[ -L /usr/local/bin/searchsploit ]] && sudo rm -f /usr/local/bin/searchsploit && \
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
    # shellcheck disable=SC2024  # Script runs as root; redirect is fine
    sudo snap remove zaproxy >> "$LOG_FILE" 2>&1
    log_success "OWASP ZAP removed"
fi

# Burp Suite installer cleanup (deterministic path only)
if [[ -d "/opt/burpsuite-installer" ]]; then
    rm -rf "/opt/burpsuite-installer"
    log_success "Removed Burp Suite installer directory"
fi

# Docker images (only on full removal)
if command_exists docker && [[ ${#REMOVE_MODULES[@]} -eq ${#ALL_MODULES[@]} ]]; then
    log_info "Removing Docker images..."
    for img in "beefproject/beef" "bcsecurity/empire" "opensecurity/mobile-security-framework-mobsf" "spiderfoot/spiderfoot" "specterops/bloodhound" "strangebee/thehive" "thehiveproject/cortex"; do
        if docker images "$img" -q 2>/dev/null | grep -q .; then
            docker rmi "$img" >> "$LOG_FILE" 2>&1 && \
                log_success "Removed Docker: $img" || true
        fi
    done
fi
echo ""

# --- Cleanup ------------------------------------------------------------------
log_info "Cleaning up..."
pkg_cleanup >> "$LOG_FILE" 2>&1
log_success "System cleaned"

# Remove version tracking file on full removal
if [[ ${#REMOVE_MODULES[@]} -eq ${#ALL_MODULES[@]} ]]; then
    [[ -f "$SCRIPT_DIR/.versions" ]] && rm -f "$SCRIPT_DIR/.versions"
fi

echo ""
echo -e "${GREEN}${BOLD}=============================================${NC}"
log_success "Removal complete!"
echo -e "${GREEN}${BOLD}=============================================${NC}"
log_info "Modules removed: ${REMOVE_MODULES[*]}"
log_info "Log file: $LOG_FILE"
