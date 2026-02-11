#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# =============================================================================
# CyberSec Tools — Verification Script (Modular)
# Sources all modules and checks installation status of all tools.
# Supports Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE.
#
# Usage:
#   sudo ./scripts/verify.sh                      # Full verification
#   sudo ./scripts/verify.sh --module web          # Verify web module only
#   sudo ./scripts/verify.sh --module recon --module ad  # Multiple modules
#   sudo ./scripts/verify.sh --summary             # Summary only (no per-tool)
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
CyberSec Tools — Verification Script

Usage: sudo ./scripts/verify.sh [OPTIONS]

Options:
  --module <name>    Verify specific module only (can be repeated)
  --summary          Show only summary counts (no per-tool output)
  -h, --help         Show this help and exit

Modules: misc, networking, recon, web, crypto, pwn, reversing, forensics,
         malware, ad, wireless, password, stego, cloud, containers, blueteam,
         mobile
EOF
    exit 0
fi

# --- Parse args --------------------------------------------------------------
VERIFY_MODULES=()
SUMMARY_ONLY=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --module)  [[ $# -lt 2 ]] && { log_error "--module requires an argument"; exit 1; }
                   VERIFY_MODULES+=("$2"); shift 2 ;;
        --summary) SUMMARY_ONLY=true; shift ;;
        -h|--help) exec "$0" --help ;;
        *)         shift ;;
    esac
done

if [[ ${#VERIFY_MODULES[@]} -eq 0 ]]; then
    VERIFY_MODULES=("${ALL_MODULES[@]}")
fi

LOG_FILE="$SCRIPT_DIR/tool_verification.log"
: > "$LOG_FILE"

TOTAL_CHECKED=0
TOTAL_FOUND=0
TOTAL_MISSING=0

# --- Helpers -----------------------------------------------------------------
check_cmd() {
    local tool="$1"
    local version_cmd="${2:-}"
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))

    if command_exists "$tool"; then
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
        if [[ "$SUMMARY_ONLY" == "false" ]]; then
            if [[ -n "$version_cmd" ]]; then
                local ver
                ver=$($version_cmd 2>&1 | head -n 1) || ver="(version unknown)"
                log_success "$tool — $ver"
            else
                log_success "$tool — installed"
            fi
        fi
        return 0
    else
        TOTAL_MISSING=$((TOTAL_MISSING + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$tool — NOT installed"
        return 1
    fi
}

check_dir() {
    local name="$1"
    local path="$2"
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))

    if [[ -d "$path" ]]; then
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$name — $path"
        return 0
    else
        TOTAL_MISSING=$((TOTAL_MISSING + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$name — NOT found at $path"
        return 1
    fi
}

check_pipx() {
    local tool="$1"
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))

    if command_exists "$tool"; then
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$tool — installed (pipx/PATH)"
        return 0
    elif command_exists pipx && pipx list --short 2>/dev/null | grep -qi "^${tool} "; then
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$tool — installed (pipx)"
        return 0
    else
        TOTAL_MISSING=$((TOTAL_MISSING + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$tool — NOT installed"
        return 1
    fi
}

check_go_bin() {
    local bin="$1"
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))

    # Go binaries install to GOBIN=/usr/local/bin (system-wide)
    if command_exists "$bin"; then
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$bin — installed (Go)"
        return 0
    else
        TOTAL_MISSING=$((TOTAL_MISSING + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$bin — NOT installed"
        return 1
    fi
}

# Check any-of: passes if any of the given binary names exist (for distro-varying names)
check_cmd_any() {
    local label="$1"; shift
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))
    for candidate in "$@"; do
        if command_exists "$candidate"; then
            TOTAL_FOUND=$((TOTAL_FOUND + 1))
            [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$label — installed ($candidate)"
            return 0
        fi
    done
    TOTAL_MISSING=$((TOTAL_MISSING + 1))
    [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$label — NOT installed (tried: $*)"
    return 1
}

# Batch check helpers
check_cmds()      { for t in "$@"; do check_cmd "$t" || true; done; }
check_pipx_arr()  { for t in "$@"; do check_pipx "$t" || true; done; }
check_go_bins()   { for t in "$@"; do check_go_bin "$t" || true; done; }
check_git_repos() { for n in "$@"; do check_dir "$n" "$GITHUB_TOOL_DIR/$n" || true; done; }
check_gems()      { for g in "$@"; do check_cmd "$g" || true; done; }
check_cargo()     { for c in "$@"; do check_cmd "$c" || true; done; }

# shellcheck disable=SC2076  # Intentional literal match, not regex
should_verify() { [[ " ${VERIFY_MODULES[*]} " =~ " $1 " ]]; }

# --- System info -------------------------------------------------------------
print_banner
log_info "System Information:"
log_message "  OS: $(uname -a)"
log_message "  Kernel: $(uname -r)"
log_message "  Arch: $(uname -m)"
echo ""

# --- Runtime environments ----------------------------------------------------
log_info "Environments:"
check_cmd "python3" "python3 --version" || true
check_cmd "pip3" "pip3 --version" || true
check_cmd "pipx" "pipx --version" || true
check_cmd "go" "go version" || true
check_cmd "ruby" "ruby --version" || true
check_cmd "java" "java -version" || true
check_cmd "git" "git --version" || true
check_cmd "cargo" "cargo --version" || true
check_cmd "docker" "docker --version" || true
echo ""

# =============================================================================
# Per-module verification
# =============================================================================

if should_verify "misc"; then
    echo ""
    log_info "========== Module: misc =========="
    log_info "Base Dependencies:"
    check_cmds git curl wget openssl python3 pip3 ruby go java cmake dos2unix rlwrap
    check_cmd_any "imagemagick" convert magick || true
    log_info "Security Tools:"
    check_cmds lynis rkhunter chkrootkit
    log_info "Heavy Tools:"
    check_cmds gimp audacity sage
    log_info "Misc (pipx):"
    check_pipx_arr "${MISC_PIPX[@]}"
    log_info "Misc (Go):"
    check_go_bins "${MISC_GO_BINS[@]}"
    log_info "Misc (Git repos):"
    check_git_repos "${MISC_GIT_NAMES[@]}"
    log_info "Misc (Special):"
    check_cmd "msfconsole" "msfconsole --version" || true
    check_cmd "searchsploit" || true
    check_cmd "pspy" || true
    check_cmd "gophish" || true
    check_cmd "trufflehog" || true
fi

if should_verify "networking"; then
    echo ""
    log_info "========== Module: networking =========="
    log_info "Networking (packages):"
    check_cmds nmap masscan netdiscover tcpdump hping3 arp-scan \
        socat p0f ncrack sslscan nbtscan onesixtyone snmpwalk smbclient \
        iodine zmap ettercap mitmproxy tshark dsniff sslsplit \
        tor proxychains4 macchanger snort yersinia whois traceroute nc
    log_info "Networking (pipx):"
    check_pipx_arr "${NET_PIPX[@]}"
    log_info "Networking (Go):"
    check_go_bins "${NET_GO_BINS[@]}"
    log_info "Networking (Git):"
    check_git_repos "${NET_GIT_NAMES[@]}"
    log_info "Networking (Binary/Cargo):"
    check_cmd "rustscan" || true
    check_cmd "ligolo-proxy" || true
fi

if should_verify "recon"; then
    echo ""
    log_info "========== Module: recon =========="
    log_info "Recon (packages):"
    check_cmds dnsenum dmitry
    log_info "Recon (pipx):"
    check_pipx_arr "${RECON_PIPX[@]}"
    log_info "Recon (Go):"
    check_go_bins "${RECON_GO_BINS[@]}"
    log_info "Recon (Git):"
    check_git_repos "${RECON_GIT_NAMES[@]}"
    log_info "Recon (Binary):"
    check_cmd "findomain" || true
fi

if should_verify "web"; then
    echo ""
    log_info "========== Module: web =========="
    log_info "Web (packages):"
    check_cmds nikto whatweb
    log_info "Web (pipx):"
    check_pipx_arr "${WEB_PIPX[@]}"
    log_info "Web (Go):"
    check_go_bins "${WEB_GO_BINS[@]}"
    log_info "Web (Cargo):"
    check_cargo "${WEB_CARGO[@]}"
    log_info "Web (Gems):"
    check_gems "${WEB_GEMS[@]}"
    log_info "Web (Git):"
    check_git_repos "${WEB_GIT_NAMES[@]}"
    log_info "Web (Special):"
    check_cmd "burpsuite" || true
    check_cmd "zaproxy" || true
fi

if should_verify "crypto"; then
    echo ""
    log_info "========== Module: crypto =========="
    log_info "Crypto (pipx):"
    check_pipx_arr "${CRYPTO_PIPX[@]}"
    log_info "Crypto (Git):"
    check_git_repos "${CRYPTO_GIT_NAMES[@]}"
fi

if should_verify "pwn"; then
    echo ""
    log_info "========== Module: pwn =========="
    log_info "Pwn (packages):"
    check_cmds patchelf cmake searchsploit
    log_info "Pwn (pipx):"
    check_pipx_arr "${PWN_PIPX[@]}"
    log_info "Pwn (Go):"
    check_go_bins "${PWN_GO_BINS[@]}"
    log_info "Pwn (Gems):"
    check_gems "${PWN_GEMS[@]}"
    log_info "Pwn (Cargo):"
    check_cargo moonwalk pwninit
    log_info "Pwn (Git):"
    check_git_repos "${PWN_GIT_NAMES[@]}"
    log_info "Pwn (Special):"
    check_cmd "msfconsole" || true
fi

if should_verify "reversing"; then
    echo ""
    log_info "========== Module: reversing =========="
    log_info "RE (packages):"
    check_cmds r2 checksec rizin gdb binwalk ltrace strace hexedit upx valgrind
    check_cmd_any "ghidra" ghidra ghidraRun || true
    check_cmd_any "qemu-user" qemu-x86_64-static qemu-x86_64 || true
    log_info "RE (pipx):"
    check_pipx_arr "${RE_PIPX[@]}"
    log_info "RE (Git):"
    check_git_repos "${RE_GIT_NAMES[@]}"
    log_info "RE (Binary):"
    check_cmd "rp-lin" || true
    check_cmd "jd-gui" || true
fi

if should_verify "forensics"; then
    echo ""
    log_info "========== Module: forensics =========="
    log_info "Forensics (packages):"
    check_cmds autopsy mmls foremost scalpel dc3dd dcfldd testdisk bulk_extractor exiftool clamscan
    log_info "Forensics (pipx):"
    check_pipx_arr "${FORENSICS_PIPX[@]}"
    log_info "Forensics (Git):"
    check_git_repos "${FORENSICS_GIT_NAMES[@]}"
    log_info "Forensics (Binary):"
    check_cmd "chainsaw" || true
fi

if should_verify "malware"; then
    echo ""
    log_info "========== Module: malware =========="
    log_info "Malware (packages):"
    check_cmds yara clamscan
    log_info "Malware (pipx):"
    check_pipx_arr "${MALWARE_PIPX[@]}"
fi

if should_verify "ad"; then
    echo ""
    log_info "========== Module: ad =========="
    log_info "AD (pipx):"
    check_pipx_arr "${AD_PIPX[@]}"
    log_info "AD (Go):"
    check_go_bins "${AD_GO_BINS[@]}"
    log_info "AD (Gems):"
    check_gems "${AD_GEMS[@]}"
    log_info "AD (Git):"
    check_git_repos "${AD_GIT_NAMES[@]}"
    log_info "AD (Binary):"
    check_cmd "kerbrute" || true
fi

if should_verify "wireless"; then
    echo ""
    log_info "========== Module: wireless =========="
    log_info "Wireless (packages):"
    check_cmds aircrack-ng reaver kismet pixiewps bully iw horst gnuradio-companion gqrx
    check_cmd_any "bluetooth" hciconfig bluetoothctl || true
    log_info "Wireless (pipx):"
    check_pipx_arr "${WIRELESS_PIPX[@]}"
    log_info "Wireless (Git):"
    check_git_repos "${WIRELESS_GIT_NAMES[@]}"
fi

if should_verify "password"; then
    echo ""
    log_info "========== Module: password =========="
    log_info "Password (packages):"
    check_cmds john hashcat hydra medusa crunch ophcrack fcrackzip pdfcrack cewl hashid chntpw
    log_info "Password (pipx):"
    check_pipx_arr "${PASSWORD_PIPX[@]}"
    log_info "Password (Git):"
    check_git_repos "${PASSWORD_GIT_NAMES[@]}"
fi

if should_verify "stego"; then
    echo ""
    log_info "========== Module: stego =========="
    log_info "Stego (packages):"
    check_cmds steghide outguess pngcheck
    check_cmd_any "sonic-visualiser" sonic-visualiser sonic_visualiser || true
    log_info "Stego (pipx):"
    check_pipx_arr "${STEGO_PIPX[@]}"
    log_info "Stego (Gems):"
    check_gems "${STEGO_GEMS[@]}"
    log_info "Stego (Git):"
    check_git_repos "${STEGO_GIT_NAMES[@]}"
    log_info "Stego (Binary):"
    check_cmd "stegseek" || true
fi

if should_verify "cloud"; then
    echo ""
    log_info "========== Module: cloud =========="
    log_info "Cloud (pipx):"
    check_pipx_arr "${CLOUD_PIPX[@]}"
    log_info "Cloud (Go):"
    check_go_bins "${CLOUD_GO_BINS[@]}"
    log_info "Cloud (Git):"
    check_git_repos "${CLOUD_GIT_NAMES[@]}"
fi

if should_verify "containers"; then
    echo ""
    log_info "========== Module: containers =========="
    log_info "Containers (Git):"
    check_git_repos "${CONTAINER_GIT_NAMES[@]}"
    log_info "Containers (Binary):"
    check_cmds trivy grype kubeaudit cdk
fi

if should_verify "mobile"; then
    echo ""
    log_info "========== Module: mobile =========="
    log_info "Mobile (packages):"
    check_cmds adb smali scrcpy apksigner zipalign
    log_info "Mobile (pipx):"
    check_pipx_arr "${MOBILE_PIPX[@]}"
    log_info "Mobile (Git):"
    check_git_repos "${MOBILE_GIT_NAMES[@]}"
fi

if should_verify "blueteam"; then
    echo ""
    log_info "========== Module: blueteam =========="
    log_info "Blue Team (packages):"
    check_cmds suricata fail2ban aide auditctl zeek apparmor_parser ufw
    log_info "Blue Team (pipx):"
    check_pipx_arr "${BLUETEAM_PIPX[@]}"
    log_info "Blue Team (Git):"
    check_git_repos "${BLUETEAM_GIT_NAMES[@]}"
    log_info "Blue Team (Binary):"
    check_cmd "velociraptor" || true
    check_cmd "laurel" || true
    log_info "Blue Team (Docker):"
    if command_exists docker; then
        for img in "strangebee/thehive" "thehiveproject/cortex"; do
            TOTAL_CHECKED=$((TOTAL_CHECKED + 1))
            if docker images "$img" -q 2>/dev/null | grep -q .; then
                TOTAL_FOUND=$((TOTAL_FOUND + 1))
                [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$img — Docker image present"
            else
                TOTAL_MISSING=$((TOTAL_MISSING + 1))
                [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$img — Docker image NOT found"
            fi
        done
    fi
fi

# --- Summary -----------------------------------------------------------------
echo ""
echo -e "${BOLD}=============================================${NC}"
log_info "Verification Summary"
echo -e "  ${GREEN}Found:${NC}   $TOTAL_FOUND"
echo -e "  ${RED}Missing:${NC} $TOTAL_MISSING"
echo -e "  Total checked: $TOTAL_CHECKED"
local_pct=0
[[ "$TOTAL_CHECKED" -gt 0 ]] && local_pct=$((TOTAL_FOUND * 100 / TOTAL_CHECKED))
echo -e "  Coverage: ${local_pct}%"
echo -e "${BOLD}=============================================${NC}"
log_info "Details saved to: $LOG_FILE"
