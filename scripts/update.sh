#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# =============================================================================
# CyberSec Tools — Update Script (Modular)
# Sources all modules and updates all installed tools across all methods.
# Supports Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE.
#
# Usage:
#   sudo ./scripts/update.sh                    # Full update
#   sudo ./scripts/update.sh --skip-system      # Skip apt/dnf/pacman update
#   sudo ./scripts/update.sh --skip-go          # Skip Go tools
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/installers.sh"

# Source all modules to get tool arrays (ALL_MODULES defined in lib/common.sh)
for mod in "${ALL_MODULES[@]}"; do
    source "$SCRIPT_DIR/modules/${mod}.sh"
done

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << 'EOF'
CyberSec Tools — Update Script

Usage: sudo ./scripts/update.sh [OPTIONS]

Options:
  --skip-system    Skip system package update/upgrade
  --skip-pipx      Skip pipx tool update
  --skip-go        Skip Go tool update
  --skip-git       Skip Git repo update
  --skip-gems      Skip Ruby gem update
  --skip-cargo     Skip Cargo tool update
  --skip-binary    Skip binary release update
  --skip-special   Skip Metasploit/ZAP update
  --skip-docker    Skip Docker image update
  -v, --verbose    Enable debug logging and system environment dump
  -h, --help       Show this help and exit
EOF
    exit 0
fi

# --- Parse args --------------------------------------------------------------
SKIP_SYSTEM=false
SKIP_PIPX=false
SKIP_GO=false
SKIP_GIT=false
SKIP_GEMS=false
SKIP_CARGO=false
SKIP_BINARY=false
SKIP_SPECIAL=false
SKIP_DOCKER=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-system)  SKIP_SYSTEM=true; shift ;;
        --skip-pipx)    SKIP_PIPX=true; shift ;;
        --skip-go)      SKIP_GO=true; shift ;;
        --skip-git)     SKIP_GIT=true; shift ;;
        --skip-gems)    SKIP_GEMS=true; shift ;;
        --skip-cargo)   SKIP_CARGO=true; shift ;;
        --skip-binary)  SKIP_BINARY=true; shift ;;
        --skip-special) SKIP_SPECIAL=true; shift ;;
        --skip-docker)  SKIP_DOCKER=true; shift ;;
        -v|--verbose)   VERBOSE=true; shift ;;
        -h|--help)      exec "$0" --help ;;
        *)              shift ;;
    esac
done

LOG_FILE="$SCRIPT_DIR/tool_update.log"
: > "$LOG_FILE"

check_root
print_banner

if [[ "$PKG_MANAGER" == "unknown" ]]; then
    log_error "Unsupported distribution — could not detect package manager"
    log_error "Supported: apt (Debian/Ubuntu/Kali), dnf (Fedora/RHEL), pacman (Arch), zypper (openSUSE)"
    exit 1
fi

if [[ "$VERBOSE" == "true" ]]; then
    log_info "Verbose mode enabled"
    log_system_environment
    enable_debug_trace
fi

START_TIME=$(date +%s)

# =============================================================================
# 1) System packages
# =============================================================================
if [[ "$SKIP_SYSTEM" == "false" ]]; then
    log_info "Updating system packages..."
    pkg_update >> "$LOG_FILE" 2>&1
    pkg_upgrade >> "$LOG_FILE" 2>&1
    log_success "System packages updated"
else
    log_warn "Skipping system package update"
fi
echo ""

# =============================================================================
# 2) pipx packages
# =============================================================================
if [[ "$SKIP_PIPX" == "false" ]]; then
    if command_exists pipx; then
        log_info "Updating pipx packages..."
        pipx upgrade-all >> "$LOG_FILE" 2>&1 || true
        log_success "pipx packages updated"
    else
        log_warn "pipx not found — skipping Python tool updates"
    fi
else
    log_warn "Skipping pipx update"
fi
echo ""

# =============================================================================
# 3) Go tools
# =============================================================================
if [[ "$SKIP_GO" == "false" ]]; then
    if command_exists go; then
        # GOPATH and GOBIN are set in common.sh (system-wide: /opt/go, /usr/local/bin)
        log_info "Updating Go tools..."

        # Aggregate all Go install paths from all modules
        ALL_GO_TOOLS=()
        [[ ${#RECON_GO[@]} -gt 0 ]]     && ALL_GO_TOOLS+=("${RECON_GO[@]}")
        [[ ${#WEB_GO[@]} -gt 0 ]]       && ALL_GO_TOOLS+=("${WEB_GO[@]}")
        [[ ${#PWN_GO[@]} -gt 0 ]]       && ALL_GO_TOOLS+=("${PWN_GO[@]}")
        [[ ${#NET_GO[@]} -gt 0 ]]       && ALL_GO_TOOLS+=("${NET_GO[@]}")
        [[ ${#CLOUD_GO[@]} -gt 0 ]]     && ALL_GO_TOOLS+=("${CLOUD_GO[@]}")
        [[ ${#MISC_GO[@]} -gt 0 ]]      && ALL_GO_TOOLS+=("${MISC_GO[@]}")
        [[ ${#CRYPTO_GO[@]} -gt 0 ]]    && ALL_GO_TOOLS+=("${CRYPTO_GO[@]}")
        [[ ${#RE_GO[@]} -gt 0 ]]        && ALL_GO_TOOLS+=("${RE_GO[@]}")
        [[ ${#FORENSICS_GO[@]} -gt 0 ]] && ALL_GO_TOOLS+=("${FORENSICS_GO[@]}")
        [[ ${#MALWARE_GO[@]} -gt 0 ]]   && ALL_GO_TOOLS+=("${MALWARE_GO[@]}")
        [[ ${#AD_GO[@]} -gt 0 ]]        && ALL_GO_TOOLS+=("${AD_GO[@]}")
        [[ ${#WIRELESS_GO[@]} -gt 0 ]]  && ALL_GO_TOOLS+=("${WIRELESS_GO[@]}")
        [[ ${#PASSWORD_GO[@]} -gt 0 ]]  && ALL_GO_TOOLS+=("${PASSWORD_GO[@]}")
        [[ ${#STEGO_GO[@]} -gt 0 ]]     && ALL_GO_TOOLS+=("${STEGO_GO[@]}")
        [[ ${#CONTAINER_GO[@]} -gt 0 ]] && ALL_GO_TOOLS+=("${CONTAINER_GO[@]}")
        [[ ${#BLUETEAM_GO[@]} -gt 0 ]]   && ALL_GO_TOOLS+=("${BLUETEAM_GO[@]}")
        [[ ${#MOBILE_GO[@]} -gt 0 ]]    && ALL_GO_TOOLS+=("${MOBILE_GO[@]}")

        GO_TOTAL=${#ALL_GO_TOOLS[@]}
        GO_CURRENT=0
        GO_FAILED=0

        if [[ "$GO_TOTAL" -eq 0 ]]; then
            log_info "No Go tools found to update"
        fi

        for tool in "${ALL_GO_TOOLS[@]}"; do
            GO_CURRENT=$((GO_CURRENT + 1))
            tool_name=$(_go_bin_name "$tool")
            show_progress "$GO_CURRENT" "$GO_TOTAL" "$tool_name"
            if go install "$tool" >> "$LOG_FILE" 2>&1; then
                log_success "Updated: $tool_name"
            else
                log_warn "Failed: $tool_name"
                GO_FAILED=$((GO_FAILED + 1))
            fi
        done
        echo ""
        log_success "Go tools: $((GO_TOTAL - GO_FAILED))/$GO_TOTAL updated"
    else
        log_warn "Go not found — skipping Go tool updates"
    fi
else
    log_warn "Skipping Go tool update"
fi
echo ""

# =============================================================================
# 4) GitHub repos
# =============================================================================
if [[ "$SKIP_GIT" == "false" ]]; then
    log_info "Updating GitHub repositories in $GITHUB_TOOL_DIR..."
    if [[ -d "$GITHUB_TOOL_DIR" ]]; then
        GIT_COUNT=0
        GIT_UPDATED=0
        for dir in "$GITHUB_TOOL_DIR"/*/; do
            [[ -d "$dir/.git" ]] || continue
            name="$(basename "$dir")"
            GIT_COUNT=$((GIT_COUNT + 1))
            if git -C "$dir" pull -q >> "$LOG_FILE" 2>&1; then
                log_success "Updated: $name"
                GIT_UPDATED=$((GIT_UPDATED + 1))
            else
                log_warn "Failed: $name"
            fi
            # Reinstall Python deps if present — only into existing venvs to
            # avoid polluting system Python.
            if [[ -f "$dir/requirements.txt" ]]; then
                if [[ -d "$dir/venv" ]]; then
                    "$dir/venv/bin/pip" install -q -r "$dir/requirements.txt" >> "$LOG_FILE" 2>&1 || true
                elif [[ -d "$dir/.venv" ]]; then
                    "$dir/.venv/bin/pip" install -q -r "$dir/requirements.txt" >> "$LOG_FILE" 2>&1 || true
                else
                    log_warn "$name has requirements.txt but no venv — skipping pip install (create venv to enable)"
                fi
            fi
        done
        log_success "GitHub repos: $GIT_UPDATED/$GIT_COUNT updated"
    else
        log_warn "$GITHUB_TOOL_DIR not found — skipping"
    fi
else
    log_warn "Skipping Git repo update"
fi
echo ""

# =============================================================================
# 5) Ruby gems
# =============================================================================
if [[ "$SKIP_GEMS" == "false" ]]; then
    if command_exists gem; then
        # Aggregate all gems from modules
        ALL_GEMS=()
        [[ ${#PWN_GEMS[@]} -gt 0 ]]   && ALL_GEMS+=("${PWN_GEMS[@]}")
        [[ ${#WEB_GEMS[@]} -gt 0 ]]   && ALL_GEMS+=("${WEB_GEMS[@]}")
        [[ ${#STEGO_GEMS[@]} -gt 0 ]] && ALL_GEMS+=("${STEGO_GEMS[@]}")
        [[ ${#AD_GEMS[@]} -gt 0 ]]    && ALL_GEMS+=("${AD_GEMS[@]}")

        if [[ ${#ALL_GEMS[@]} -gt 0 ]]; then
            log_info "Updating Ruby gems (${ALL_GEMS[*]})..."
            gem update "${ALL_GEMS[@]}" --no-document >> "$LOG_FILE" 2>&1 && \
                log_success "Ruby gems updated" || \
                log_warn "Ruby gem update failed"
        fi
    else
        log_warn "gem not found — skipping Ruby gem updates"
    fi
else
    log_warn "Skipping Ruby gem update"
fi
echo ""

# =============================================================================
# 6) Cargo tools
# =============================================================================
if [[ "$SKIP_CARGO" == "false" ]]; then
    if command_exists cargo; then
        export PATH="$HOME/.cargo/bin:$PATH"
        ALL_CARGO=()
        [[ ${#WEB_CARGO[@]} -gt 0 ]] && ALL_CARGO+=("${WEB_CARGO[@]}")
        # RustScan from networking module (installed via cargo)
        command_exists rustscan && ALL_CARGO+=(rustscan)
        # Pwn module cargo tools
        command_exists pwninit && ALL_CARGO+=(pwninit)

        if [[ ${#ALL_CARGO[@]} -gt 0 ]]; then
            log_info "Updating Cargo tools (${ALL_CARGO[*]})..."
            for crate in "${ALL_CARGO[@]}"; do
                cargo install --force "$crate" >> "$LOG_FILE" 2>&1 && \
                    log_success "Updated cargo: $crate" || \
                    log_warn "Failed cargo: $crate"
            done
        fi
    else
        log_warn "cargo not found — skipping Cargo tool updates"
    fi
else
    log_warn "Skipping Cargo tool update"
fi
echo ""

# =============================================================================
# 7) Binary releases (GitHub release assets)
# =============================================================================
if [[ "$SKIP_BINARY" == "false" ]]; then
    log_info "Updating binary releases..."
    BIN_TOTAL=0
    BIN_UPDATED=0

    # Re-download only if the binary is already installed
    update_binary() {
        local repo="$1" binary="$2" pattern="$3" dest="${4:-/usr/local/bin}"
        if command_exists "$binary" || [[ -f "$dest/$binary" ]] || [[ -f "$dest/bin/$binary" ]]; then
            BIN_TOTAL=$((BIN_TOTAL + 1))
            if download_github_release "$repo" "$binary" "$pattern" "$dest" >> "$LOG_FILE" 2>&1; then
                log_success "Updated: $binary"
                BIN_UPDATED=$((BIN_UPDATED + 1))
            else
                log_warn "Failed: $binary"
            fi
        fi
    }

    # misc
    local pspy_pattern="pspy64$"
    local gophish_pattern="linux-64bit"
    if [[ "$SYS_ARCH" != "amd64" ]]; then
        pspy_pattern="pspy_${SYS_ARCH}$"
        gophish_pattern="linux-${SYS_ARCH}"
    fi
    update_binary "DominicBreuker/pspy" "pspy" "$pspy_pattern"
    update_binary "gophish/gophish" "gophish" "$gophish_pattern"
    update_binary "skylot/jadx" "jadx" "jadx.*\\.zip" "/opt/jadx"
    update_binary "pxb1988/dex2jar" "d2j-dex2jar" "dex2jar.*\\.zip" "/opt/dex2jar"
    update_binary "trufflesecurity/trufflehog" "trufflehog" "linux_amd64\\.tar\\.gz"
    update_binary "gitleaks/gitleaks" "gitleaks" "linux_amd64\\.tar\\.gz"
    # networking
    update_binary "nicocha30/ligolo-ng" "ligolo-proxy" "linux_amd64"
    update_binary "nicocha30/ligolo-ng" "ligolo-agent" "agent.*linux_amd64"
    update_binary "fatedier/frp" "frp" "linux_amd64\\.tar\\.gz"
    # recon
    update_binary "Findomain/Findomain" "findomain" "linux"
    # web
    update_binary "frohoff/ysoserial" "ysoserial" "ysoserial-all.jar" "/opt/cybersec-jars"
    # reversing
    update_binary "0vercl0k/rp" "rp-lin" "rp-lin"
    update_binary "java-decompiler/jd-gui" "jd-gui" "jd-gui.*\\.jar" "/opt/cybersec-jars"
    # forensics
    update_binary "WithSecureLabs/chainsaw" "chainsaw" "x86_64.*linux"
    # ad
    update_binary "ropnop/kerbrute" "kerbrute" "linux_amd64"
    # blueteam
    update_binary "Velocidex/velociraptor" "velociraptor" "linux-amd64$"
    update_binary "threathunters-io/laurel" "laurel" "x86_64-glibc"
    # containers
    local trivy_pattern="Linux-64bit\\.tar\\.gz"
    [[ "$SYS_ARCH" != "amd64" ]] && trivy_pattern="Linux-ARM64\\.tar\\.gz"
    update_binary "aquasecurity/trivy" "trivy" "$trivy_pattern"
    update_binary "anchore/grype" "grype" "linux_amd64\\.tar\\.gz"
    update_binary "Shopify/kubeaudit" "kubeaudit" "linux_amd64\\.tar\\.gz"
    update_binary "cdk-team/CDK" "cdk" "cdk_linux_amd64"
    # stego
    update_binary "RickdeJager/stegseek" "stegseek" "\\.deb"

    if [[ "$BIN_TOTAL" -gt 0 ]]; then
        log_success "Binary releases: $BIN_UPDATED/$BIN_TOTAL updated"
    else
        log_info "No binary releases found to update"
    fi
else
    log_warn "Skipping binary release update"
fi
echo ""

# =============================================================================
# 8) Special tools
# =============================================================================
if [[ "$SKIP_SPECIAL" == "false" ]]; then
    log_info "Updating special tools..."

    # Metasploit
    if command_exists msfupdate; then
        log_info "Updating Metasploit..."
        # shellcheck disable=SC2024  # Script runs as root; redirect is fine
        sudo msfupdate >> "$LOG_FILE" 2>&1 && \
            log_success "Metasploit updated" || \
            log_warn "Metasploit update failed"
    fi

    # OWASP ZAP (snap)
    if command_exists zaproxy && snap_available; then
        log_info "Updating OWASP ZAP..."
        # shellcheck disable=SC2024  # Script runs as root; redirect is fine
        sudo snap refresh zaproxy >> "$LOG_FILE" 2>&1 && \
            log_success "OWASP ZAP updated" || \
            log_warn "OWASP ZAP update failed"
    fi
else
    log_warn "Skipping special tool updates"
fi

# =============================================================================
# 9) Docker images
# =============================================================================
if [[ "$SKIP_DOCKER" == "false" ]]; then
    if command_exists docker; then
        log_info "Updating Docker images..."
        DOCKER_UPDATED=0
        for img in "beefproject/beef" "bcsecurity/empire" "opensecurity/mobile-security-framework-mobsf" "spiderfoot/spiderfoot" "specterops/bloodhound" "strangebee/thehive:latest" "thehiveproject/cortex:latest"; do
            if docker images "${img%%:*}" -q 2>/dev/null | grep -q .; then
                if docker pull "$img" >> "$LOG_FILE" 2>&1; then
                    log_success "Updated Docker: $img"
                    DOCKER_UPDATED=$((DOCKER_UPDATED + 1))
                else
                    log_warn "Failed Docker: $img"
                fi
            fi
        done
        [[ "$DOCKER_UPDATED" -gt 0 ]] && log_success "Docker images: $DOCKER_UPDATED updated"
    fi
else
    log_warn "Skipping Docker image update"
fi
echo ""

# =============================================================================
# Done
# =============================================================================
disable_debug_trace

echo ""
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
MINUTES=$(( ELAPSED / 60 ))
SECONDS_R=$(( ELAPSED % 60 ))

echo -e "${GREEN}${BOLD}=============================================${NC}"
log_success "Update complete! (${MINUTES}m ${SECONDS_R}s)"
echo -e "${GREEN}${BOLD}=============================================${NC}"
log_info "Log file: $LOG_FILE"
