#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# CyberSec Tools — Verification Script (Modular)
# Sources all modules and checks installation status of all tools.
# Supports Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE, Termux/Android.
#
# Usage:
#   sudo ./scripts/verify.sh                      # Full verification (Linux)
#   ./scripts/verify.sh                           # Full verification (Termux)
#   sudo ./scripts/verify.sh --module web          # Verify web module only
#   sudo ./scripts/verify.sh --summary             # Summary only (no per-tool)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/installers.sh"
source "$SCRIPT_DIR/lib/shared.sh"
_source_all_modules "$SCRIPT_DIR"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << EOF
CyberSec Tools — Verification Script

Usage: sudo ./scripts/verify.sh [OPTIONS]    # Linux
       ./scripts/verify.sh [OPTIONS]          # Termux

Options:
  --module <name>    Verify specific module only (can be repeated)
  --installed-only   Only check tools tracked in .versions (skip tools you never installed)
  --summary          Show only summary counts (no per-tool output)
  -v, --verbose      Enable debug logging and system environment dump
  -h, --help         Show this help and exit

Modules: $(IFS=', '; echo "${ALL_MODULES[*]}")
EOF
    exit 0
fi

# Parse args
VERIFY_MODULES=()
SUMMARY_ONLY=false
INSTALLED_ONLY=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --module)  [[ $# -lt 2 ]] && { log_error "--module requires an argument"; exit 1; }
                   VERIFY_MODULES+=("$2"); shift 2 ;;
        --installed-only) INSTALLED_ONLY=true; shift ;;
        --summary) SUMMARY_ONLY=true; shift ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -h|--help) exec "$0" --help ;;
        *)         log_error "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ ${#VERIFY_MODULES[@]} -eq 0 ]]; then
    VERIFY_MODULES=("${ALL_MODULES[@]}")
fi

# --installed-only: load tracked tools from .versions file
_INSTALLED_TOOLS=""
if [[ "$INSTALLED_ONLY" == "true" ]]; then
    _versions_file="$SCRIPT_DIR/.versions"
    if [[ -f "$_versions_file" ]]; then
        _INSTALLED_TOOLS=$(awk -F'|' '!/^#/{print $1}' "$_versions_file")
        log_info "Filtering by ${_versions_file} ($(echo "$_INSTALLED_TOOLS" | wc -l) tracked tools)"
    else
        log_warn "No .versions file found — running full verification"
        INSTALLED_ONLY=false
    fi
fi

# _is_tracked — returns 0 if tool is in .versions (or if --installed-only is off)
_is_tracked() {
    [[ "$INSTALLED_ONLY" == "false" ]] && return 0
    echo "$_INSTALLED_TOOLS" | grep -qx "$1" 2>/dev/null
}

_init_log_file "$SCRIPT_DIR/tool_verification.log"

TOTAL_CHECKED=0
TOTAL_FOUND=0
TOTAL_MISSING=0

# Helpers
check_cmd() {
    local tool="$1"
    local version_cmd="${2:-}"
    _is_tracked "$tool" || return 0
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
    _is_tracked "$name" || return 0
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

# Pipx package name → binary name mapping (only for tools where they differ).
# Most pipx packages install a binary with the same name — these are the exceptions.
declare -A _PIPX_BIN_NAMES=(
    [arsenal-cli]="arsenal"
    [sherlock-project]="sherlock"
    [osrframework]="usufy"
    [raccoon-scanner]="raccoon"
    [factordb-python]="factordb"
    [z3-solver]="z3"
    [pwntools]="pwn"
    [boofuzz]="boo"
    [frida-tools]="frida"
    [volatility3]="vol"
    [oletools]="olevba"
    [mvt]="mvt-android"
    [hachoir]="hachoir-metadata"
    [peepdf-3]="peepdf"
    [impacket]="impacket-secretsdump"
    [certipy-ad]="certipy"
    [bloodhound]="bloodhound-python"
    [ldapsearchad]="ldapsearch-ad.py"
    [sipvicious]="sipvicious_svmap"
    [scoutsuite]="scout"
    [sigma-cli]="sigma"
    [quark-engine]="quark"
    [slither-analyzer]="slither"
    [mythril]="myth"
)

check_pipx() {
    local tool="$1"
    _is_tracked "$tool" || return 0
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))

    # 1. Check if package name is a valid command
    if command_exists "$tool"; then
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$tool — installed (pipx/PATH)"
        return 0
    fi

    # 2. Check mapped binary name (many pipx packages install under a different name)
    local _bin="${_PIPX_BIN_NAMES[$tool]:-}"
    if [[ -n "$_bin" ]] && command_exists "$_bin"; then
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$tool — installed ($_bin)"
        return 0
    fi

    # 3. Fallback: check pipx package list (handles normalized names)
    if command_exists pipx; then
        # Normalize hyphens/underscores for PEP 503 compatibility
        local _norm="${tool//-/_}"
        if pipx list --short 2>/dev/null | sed 's/-/_/g' | grep -qi "^${_norm} "; then
            TOTAL_FOUND=$((TOTAL_FOUND + 1))
            [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$tool — installed (pipx)"
            return 0
        fi
    fi

    TOTAL_MISSING=$((TOTAL_MISSING + 1))
    [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$tool — NOT installed"
    return 1
}

# Check any-of: passes if any of the given binary names exist (for distro-varying names)
check_cmd_any() {
    local label="$1"; shift
    _is_tracked "$label" || return 0
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

# Check build-from-source: verifies a binary was actually built (not just cloned)
check_build() {
    local name="$1"
    local dir="$GITHUB_TOOL_DIR/$name"
    _is_tracked "$name" || return 0
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))

    if command_exists "$name"; then
        # Binary is in PATH (e.g. symlinked or installed to /usr/local/bin)
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$name — built & in PATH"
        return 0
    elif [[ -d "$dir" ]]; then
        # Directory exists — check for build artifacts (case-insensitive name, .so libs, or any ELF binary in bin/)
        # shellcheck disable=SC2044
        if find "$dir" -maxdepth 3 -type f \( -iname "$name" -o -name "*.so" -o -name "afl-fuzz" \) -executable 2>/dev/null | grep -q . \
           || find "$dir/bin" -maxdepth 1 -type f -executable 2>/dev/null | grep -q .; then
            TOTAL_FOUND=$((TOTAL_FOUND + 1))
            [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$name — built at $dir"
            return 0
        else
            TOTAL_MISSING=$((TOTAL_MISSING + 1))
            [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$name — cloned at $dir but build artifacts NOT found"
            return 1
        fi
    else
        TOTAL_MISSING=$((TOTAL_MISSING + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$name — NOT found at $dir"
        return 1
    fi
}
check_builds() { for n in "$@"; do check_build "$n" || true; done; }

# Batch check helpers
check_cmds()      { for t in "$@"; do check_cmd "$t" || true; done; }
check_pipx_arr()  { for t in "$@"; do check_pipx "$t" || true; done; }
check_git_repos() { for n in "$@"; do check_dir "$n" "$GITHUB_TOOL_DIR/$n" || true; done; }

# shellcheck disable=SC2076  # Intentional literal match, not regex
should_verify() { [[ " ${VERIFY_MODULES[*]} " =~ " $1 " ]]; }

# System info
print_banner
START_TIME=$(date +%s)

if [[ "$PKG_MANAGER" == "unknown" ]]; then
    log_warn "Unknown distribution — package-level checks may be inaccurate"
fi

_setup_verbose
log_info "System Information:"
log_info "  OS: $(uname -a)"
log_info "  Kernel: $(uname -r)"
log_info "  Arch: $(uname -m)"
echo ""

# Runtime environments
log_info "Environments:"
check_cmd "python3" "python3 --version" || true
check_cmd "pip3" "pip3 --version" || true
check_cmd "pipx" "pipx --version" || true
check_cmd "go" "go version" || true
check_cmd "ruby" "ruby --version" || true
check_cmd "java" "java -version" || true
check_cmd "git" "git --version" || true
check_cmd "cargo" "cargo --version" || true
check_cmd "node" "node --version" || true
check_cmd "npm" "npm --version" || true
check_cmd "docker" "docker --version" || true
echo ""

# Shared base dependencies (always checked regardless of module selection)
log_info "━━━━━ Shared Dependencies ━━━━━"
log_info "Base Dependencies:"
check_cmds git curl wget openssl python3 pip3 ruby go java cmake dos2unix rlwrap jq file
check_cmds autoconf automake pkg-config
check_cmd_any "libtool" libtool libtoolize || true
check_cmd_any "imagemagick" convert magick || true
echo ""

# Kali/Parrot flag — some packages are only available on these distros
_is_kali=false
[[ "$DISTRO_ID" == "kali" || "$DISTRO_ID" == "parrot" ]] && _is_kali=true

# Per-module verification
if should_verify "misc"; then
    echo ""
    log_info "━━━━━ Module: misc ━━━━━"
    log_info "Heavy Tools:"
    check_cmd "sage" || true
    log_info "Misc (pipx):"
    check_pipx_arr "${MISC_PIPX[@]}"
    log_info "Misc (Go):"
    check_cmds "${MISC_GO_BINS[@]}"
    log_info "Misc (Git repos):"
    check_git_repos "${MISC_GIT_NAMES[@]}"
    log_info "Misc (Special):"
    check_cmd "msfconsole" "msfconsole --version" || true
    check_cmd "searchsploit" || true
    check_cmd "pspy" || true
    check_cmd "gophish" || true
    check_cmd "trufflehog" || true
    check_cmd "gitleaks" || true
    check_cmd "sliver-server" || true
    check_cmd "sliver-client" || true
    check_cmd "evilginx" || true
fi

if should_verify "networking"; then
    echo ""
    log_info "━━━━━ Module: networking ━━━━━"
    log_info "Networking (packages):"
    check_cmds nmap masscan netdiscover tcpdump hping3 arp-scan \
        socat p0f ncrack sslscan nbtscan onesixtyone snmpwalk smbclient \
        iodine zmap mitmproxy tshark sslsplit \
        tor proxychains4 macchanger snort yersinia whois traceroute nc
    log_info "Networking (pipx):"
    check_pipx_arr "${NET_PIPX[@]}"
    log_info "Networking (Go):"
    check_cmds "${NET_GO_BINS[@]}"
    log_info "Networking (Git):"
    check_git_repos "${NET_GIT_NAMES[@]}"
    log_info "Networking (Cargo):"
    check_cmds "${NET_CARGO[@]}"
    log_info "Networking (Binary):"
    check_cmd "ligolo-proxy" || true
    check_cmd "ligolo-agent" || true
    check_cmd "frpc" || true
    check_cmd "frps" || true
    log_info "Networking (Snap):"
    check_cmd "ngrok" || true
fi

if should_verify "recon"; then
    echo ""
    log_info "━━━━━ Module: recon ━━━━━"
    log_info "Recon (packages):"
    check_cmds dnsenum
    log_info "Recon (pipx):"
    check_pipx_arr "${RECON_PIPX[@]}"
    log_info "Recon (Go):"
    check_cmds "${RECON_GO_BINS[@]}"
    log_info "Recon (Git):"
    check_git_repos "${RECON_GIT_NAMES[@]}"
    log_info "Recon (Build from source):"
    check_builds "${RECON_BUILD_NAMES[@]}"
    log_info "Recon (Binary):"
    check_cmd "findomain" || true
    check_cmd "phoneinfoga" || true
fi

if should_verify "web"; then
    echo ""
    log_info "━━━━━ Module: web ━━━━━"
    log_info "Web (packages):"
    check_cmds whatweb
    log_info "Web (pipx):"
    check_pipx_arr "${WEB_PIPX[@]}"
    log_info "Web (Go):"
    check_cmds "${WEB_GO_BINS[@]}"
    log_info "Web (Cargo):"
    check_cmds "${WEB_CARGO[@]}"
    log_info "Web (Gems):"
    check_cmds "${WEB_GEMS[@]}"
    log_info "Web (Git):"
    check_git_repos "${WEB_GIT_NAMES[@]}"
    log_info "Web (Binary):"
    check_cmd "ysoserial" || true
    check_cmd "kr" || true
    log_info "Web (Special):"
    check_cmd "zaproxy" || true
fi

if should_verify "crypto"; then
    echo ""
    log_info "━━━━━ Module: crypto ━━━━━"
    log_info "Crypto (pipx):"
    check_pipx_arr "${CRYPTO_PIPX[@]}"
    log_info "Crypto (Git):"
    check_git_repos "${CRYPTO_GIT_NAMES[@]}"
    log_info "Crypto (Build from source):"
    check_builds "${CRYPTO_BUILD_NAMES[@]}"
fi

if should_verify "pwn"; then
    echo ""
    log_info "━━━━━ Module: pwn ━━━━━"
    log_info "Pwn (packages):"
    check_cmds patchelf cmake searchsploit
    log_info "Pwn (pipx):"
    check_pipx_arr "${PWN_PIPX[@]}"
    log_info "Pwn (Go):"
    check_cmds "${PWN_GO_BINS[@]}"
    log_info "Pwn (Gems):"
    check_cmds "${PWN_GEMS[@]}"
    log_info "Pwn (Cargo):"
    check_cmds "${PWN_CARGO[@]}"
    log_info "Pwn (Git):"
    check_git_repos "${PWN_GIT_NAMES[@]}"
    log_info "Pwn (Build from source):"
    check_builds "${PWN_BUILD_NAMES[@]}"
    log_info "Pwn (Special):"
    check_cmd "msfconsole" || true
fi

if should_verify "reversing"; then
    echo ""
    log_info "━━━━━ Module: reversing ━━━━━"
    log_info "RE (packages):"
    check_cmds checksec gdb binwalk ltrace strace hexedit upx valgrind
    if [[ "$_is_kali" == "true" ]]; then
        check_cmd "r2" || true
        check_cmd "rizin" || true
        check_cmd_any "ghidra" ghidra ghidraRun || true
    fi
    check_cmd_any "qemu-user" qemu-x86_64-static qemu-x86_64 || true
    log_info "RE (pipx):"
    check_pipx_arr "${RE_PIPX[@]}"
    log_info "RE (Git):"
    check_git_repos "${RE_GIT_NAMES[@]}"
    log_info "RE (Build from source):"
    check_builds "${RE_BUILD_NAMES[@]}"
    log_info "RE (Binary):"
    check_cmd "rp-lin" || true
    check_cmd "jd-gui" || true
fi

if should_verify "forensics"; then
    echo ""
    log_info "━━━━━ Module: forensics ━━━━━"
    log_info "Forensics (packages):"
    check_cmds autopsy mmls foremost scalpel dc3dd dcfldd testdisk exiftool clamscan pdftotext zbarimg
    [[ "$_is_kali" == "true" ]] && { check_cmd "bulk_extractor" || true; }
    log_info "Forensics (pipx):"
    check_pipx_arr "${FORENSICS_PIPX[@]}"
    log_info "Forensics (Git):"
    check_git_repos "${FORENSICS_GIT_NAMES[@]}"
    log_info "Forensics (Binary):"
    check_cmd "chainsaw" || true
fi

if should_verify "enterprise"; then
    echo ""
    log_info "━━━━━ Module: enterprise ━━━━━"
    log_info "Enterprise (pipx):"
    check_pipx_arr "${ENTERPRISE_PIPX[@]}"
    log_info "Enterprise (Go):"
    check_cmds "${ENTERPRISE_GO_BINS[@]}"
    log_info "Enterprise (Gems):"
    check_cmds "${ENTERPRISE_GEMS[@]}"
    log_info "Enterprise (Git):"
    check_git_repos "${ENTERPRISE_GIT_NAMES[@]}"
    log_info "Enterprise (Binary):"
    check_cmd "kerbrute" || true
    log_info "Enterprise (Special):"
    check_cmd "nxc" || true
fi

if should_verify "wireless"; then
    if [[ "$IS_WSL" == "true" ]]; then
        echo ""
        log_info "━━━━━ Module: wireless ━━━━━"
        log_warn "Skipped on WSL (no wireless hardware access)"
    else
        echo ""
        log_info "━━━━━ Module: wireless ━━━━━"
        log_info "Wireless (packages):"
        check_cmds aircrack-ng reaver pixiewps bully iw horst gnuradio-companion gqrx
        [[ "$_is_kali" == "true" ]] && { check_cmd "kismet" || true; }
        check_cmd_any "bluetooth" hciconfig bluetoothctl || true
        log_info "Wireless (pipx):"
        check_pipx_arr "${WIRELESS_PIPX[@]}"
        log_info "Wireless (Git):"
        check_git_repos "${WIRELESS_GIT_NAMES[@]}"
    fi
fi

if should_verify "cracking"; then
    echo ""
    log_info "━━━━━ Module: cracking ━━━━━"
    log_info "Cracking (packages):"
    check_cmds john hashcat hydra medusa crunch ophcrack fcrackzip pdfcrack chntpw
    [[ "$_is_kali" == "true" ]] && { check_cmds cewl hashid || true; }
    log_info "Cracking (pipx):"
    check_pipx_arr "${CRACKING_PIPX[@]}"
    log_info "Cracking (Git):"
    check_git_repos "${CRACKING_GIT_NAMES[@]}"
    log_info "Cracking (Build from source):"
    check_builds "${CRACKING_BUILD_NAMES[@]}"
fi

if should_verify "stego"; then
    echo ""
    log_info "━━━━━ Module: stego ━━━━━"
    log_info "Stego (packages):"
    check_cmds steghide outguess pngcheck
    check_cmd_any "sonic-visualiser" sonic-visualiser sonic_visualiser || true
    log_info "Stego (pipx):"
    check_pipx_arr "${STEGO_PIPX[@]}"
    log_info "Stego (Gems):"
    check_cmds "${STEGO_GEMS[@]}"
    log_info "Stego (Git):"
    check_git_repos "${STEGO_GIT_NAMES[@]}"
    log_info "Stego (Binary):"
    check_cmd "stegseek" || true
fi

if should_verify "cloud"; then
    echo ""
    log_info "━━━━━ Module: cloud ━━━━━"
    log_info "Cloud (pipx):"
    check_pipx_arr "${CLOUD_PIPX[@]}"
    log_info "Cloud (Go):"
    check_cmds "${CLOUD_GO_BINS[@]}"
    log_info "Cloud (Git):"
    check_git_repos "${CLOUD_GIT_NAMES[@]}"
    log_info "Cloud (Special):"
    check_cmd "steampipe" || true
fi

if should_verify "containers"; then
    echo ""
    log_info "━━━━━ Module: containers ━━━━━"
    log_info "Containers (Git):"
    check_git_repos "${CONTAINER_GIT_NAMES[@]}"
    log_info "Containers (Binary):"
    check_cmds trivy grype kubeaudit cdk syft kubescape
fi

if should_verify "mobile"; then
    echo ""
    log_info "━━━━━ Module: mobile ━━━━━"
    log_info "Mobile (packages):"
    check_cmds adb scrcpy apksigner zipalign
    [[ "$_is_kali" == "true" ]] && { check_cmd "smali" || true; }
    log_info "Mobile (pipx):"
    check_pipx_arr "${MOBILE_PIPX[@]}"
    log_info "Mobile (Git):"
    check_git_repos "${MOBILE_GIT_NAMES[@]}"
    log_info "Mobile (Binary):"
    check_cmd "jadx" || true
    check_cmd "d2j-dex2jar" || true
fi

if should_verify "blueteam"; then
    echo ""
    log_info "━━━━━ Module: blueteam ━━━━━"
    log_info "Blue Team (packages):"
    check_cmds suricata fail2ban-client aide ufw lynis rkhunter chkrootkit yara clamscan
    if [[ "$IS_WSL" != "true" ]]; then
        check_cmd "auditctl" || true
        check_cmd "apparmor_parser" || true
    fi
    [[ "$_is_kali" == "true" ]] && { check_cmd "zeek" || true; }
    log_info "Blue Team (pipx):"
    check_pipx_arr "${BLUETEAM_PIPX[@]}"
    log_info "Blue Team (Cargo):"
    # yara-x-cli installs binary as 'yr'
    check_cmd "yr" || true
    log_info "Blue Team (Git):"
    check_git_repos "${BLUETEAM_GIT_NAMES[@]}"
    log_info "Blue Team (Binary):"
    check_cmd "velociraptor" || true
    check_cmd "laurel" || true
    check_cmd "floss" || true
    check_cmd "capa" || true
    check_cmd "loki" || true
fi

if should_verify "blockchain"; then
    echo ""
    log_info "━━━━━ Module: blockchain ━━━━━"
    log_info "Blockchain (pipx):"
    check_pipx_arr "${BLOCKCHAIN_PIPX[@]}"
    log_info "Blockchain (Git):"
    check_git_repos "${BLOCKCHAIN_GIT_NAMES[@]}"
    log_info "Blockchain (Special):"
    check_cmd "solc" || true
    check_cmd "foundryup" || true
    check_cmd "forge" || true
    check_cmd "cast" || true
    check_cmd "anvil" || true
    # Foundry chisel is NOT symlinked (collides with jpillora/chisel TCP tunnel)
    # Check at its native path instead
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))
    if [[ -x "$HOME/.foundry/bin/chisel" ]]; then
        TOTAL_FOUND=$((TOTAL_FOUND + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_success "chisel (foundry) — $HOME/.foundry/bin/chisel"
    else
        TOTAL_MISSING=$((TOTAL_MISSING + 1))
        [[ "$SUMMARY_ONLY" == "false" ]] && log_error "chisel (foundry) — NOT found at $HOME/.foundry/bin/chisel"
    fi
fi

if should_verify "llm"; then
    echo ""
    log_info "━━━━━ Module: llm ━━━━━"
    log_info "LLM (pipx):"
    check_pipx_arr "${LLM_PIPX[@]}"
    log_info "LLM (Git):"
    check_git_repos "${LLM_GIT_NAMES[@]}"
    log_info "LLM (npm):"
    check_cmd "promptfoo" "promptfoo --version" || true
fi

# Docker images (all modules — uses centralized registry)
if command_exists docker; then
    echo ""
    log_info "━━━━━ Docker Images ━━━━━"
    for _docker_entry in "${ALL_DOCKER_IMAGES[@]}"; do
        IFS='|' read -r _docker_img _docker_label <<< "$_docker_entry"
        TOTAL_CHECKED=$((TOTAL_CHECKED + 1))
        if docker images "${_docker_img%%:*}" -q 2>/dev/null | grep -q .; then
            TOTAL_FOUND=$((TOTAL_FOUND + 1))
            [[ "$SUMMARY_ONLY" == "false" ]] && log_success "$_docker_label ($_docker_img) — Docker image present"
        else
            TOTAL_MISSING=$((TOTAL_MISSING + 1))
            [[ "$SUMMARY_ONLY" == "false" ]] && log_error "$_docker_label ($_docker_img) — Docker image NOT found"
        fi
    done
fi

# Summary
disable_debug_trace

_pct=0
[[ "$TOTAL_CHECKED" -gt 0 ]] && _pct=$((TOTAL_FOUND * 100 / TOTAL_CHECKED))

_print_completion_banner "$START_TIME" "$TOTAL_MISSING" \
    "$(if [[ "$TOTAL_MISSING" -gt 0 ]]; then echo "Verification complete"; else echo "Verification complete!"; fi)"
log_success "Found:   $TOTAL_FOUND"
if [[ "$TOTAL_MISSING" -gt 0 ]]; then
    log_error "Missing: $TOTAL_MISSING"
else
    log_success "Missing: 0"
fi
log_info    "Total checked: $TOTAL_CHECKED"
# Color-code coverage percentage
if [[ "$_pct" -ge 80 ]]; then
    log_success "Coverage: ${_pct}%"
elif [[ "$_pct" -ge 50 ]]; then
    log_warn "Coverage: ${_pct}%"
else
    log_error "Coverage: ${_pct}%"
fi
# Actionable tips based on results
if [[ "$TOTAL_MISSING" -gt 0 ]] && [[ "$INSTALLED_ONLY" == "false" ]]; then
    log_info "Tip: Use --installed-only to only check tools you actually installed"
    log_info "     Use --module <name> to verify a specific module"
fi
log_info "Log file: $LOG_FILE"

# Exit with non-zero if any tools are missing (useful for CI)
[[ "$TOTAL_MISSING" -gt 0 ]] && exit 1
exit 0
