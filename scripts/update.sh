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
  --skip-special   Skip Metasploit/ZAP update
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
SKIP_SPECIAL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-system)  SKIP_SYSTEM=true; shift ;;
        --skip-pipx)    SKIP_PIPX=true; shift ;;
        --skip-go)      SKIP_GO=true; shift ;;
        --skip-git)     SKIP_GIT=true; shift ;;
        --skip-gems)    SKIP_GEMS=true; shift ;;
        --skip-cargo)   SKIP_CARGO=true; shift ;;
        --skip-special) SKIP_SPECIAL=true; shift ;;
        -h|--help)      exec "$0" --help ;;
        *)              shift ;;
    esac
done

LOG_FILE="$SCRIPT_DIR/tool_update.log"
: > "$LOG_FILE"

check_root
print_banner

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
        run_as_user pipx upgrade-all >> "$LOG_FILE" 2>&1 || true
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
        export GOPATH="${GOPATH:-$REAL_HOME/go}"
        export PATH="$GOPATH/bin:$PATH"
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

        GO_TOTAL=${#ALL_GO_TOOLS[@]}
        GO_CURRENT=0
        GO_FAILED=0

        if [[ "$GO_TOTAL" -eq 0 ]]; then
            log_info "No Go tools found to update"
        fi

        for tool in "${ALL_GO_TOOLS[@]}"; do
            GO_CURRENT=$((GO_CURRENT + 1))
            tool_name=$(echo "$tool" | rev | cut -d/ -f1 | rev | cut -d@ -f1)
            show_progress "$GO_CURRENT" "$GO_TOTAL" "$tool_name"
            if run_as_user env GOPATH="$GOPATH" PATH="$PATH" go install "$tool" >> "$LOG_FILE" 2>&1; then
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
        export PATH="$REAL_HOME/.cargo/bin:$PATH"
        ALL_CARGO=()
        [[ ${#WEB_CARGO[@]} -gt 0 ]] && ALL_CARGO+=("${WEB_CARGO[@]}")
        # RustScan from networking module (installed via cargo)
        command_exists rustscan && ALL_CARGO+=(rustscan)

        if [[ ${#ALL_CARGO[@]} -gt 0 ]]; then
            log_info "Updating Cargo tools (${ALL_CARGO[*]})..."
            for crate in "${ALL_CARGO[@]}"; do
                run_as_user env PATH="$PATH" cargo install "$crate" >> "$LOG_FILE" 2>&1 && \
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
# 7) Special tools
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
# Done
# =============================================================================
echo ""
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
MINUTES=$(( ELAPSED / 60 ))
SECONDS_R=$(( ELAPSED % 60 ))

echo -e "${GREEN}${BOLD}=============================================${NC}"
log_success "Update complete! (${MINUTES}m ${SECONDS_R}s)"
echo -e "${GREEN}${BOLD}=============================================${NC}"
log_info "Log file: $LOG_FILE"
