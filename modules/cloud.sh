#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Cloud Security
# AWS, Azure, GCP security testing and auditing

CLOUD_PACKAGES=()

CLOUD_PIPX=(
    kube-hunter pacu cloudsplaining prowler scoutsuite
    roadrecon checkov
)

CLOUD_GO=(
    "github.com/BishopFox/cloudfox@latest"
    "github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest"
    "github.com/sa7mon/s3scanner@latest"
)

CLOUD_GIT=(
    "CloudBrute=https://github.com/0xsha/CloudBrute.git"
    "enumerate-iam=https://github.com/andresriancho/enumerate-iam.git"
    "GCPBucketBrute=https://github.com/RhinoSecurityLabs/GCPBucketBrute.git"
    "cloud_enum=https://github.com/initstring/cloud_enum.git"
)

CLOUD_GO_BINS=(cloudfox cloudlist s3scanner)
CLOUD_GIT_NAMES=(CloudBrute enumerate-iam GCPBucketBrute cloud_enum)

install_module_cloud() {
    [[ ${#CLOUD_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Cloud - Packages" "${CLOUD_PACKAGES[@]}"
    install_pipx_batch "Cloud - Python" "${CLOUD_PIPX[@]}"
    install_go_batch "Cloud - Go" "${CLOUD_GO[@]}"
    install_git_batch "Cloud - Git" "${CLOUD_GIT[@]}"

    if [[ "${SKIP_SOURCE:-false}" != "true" ]] && [[ "$PKG_MANAGER" != "pkg" ]] && ! command_exists steampipe; then
        log_info "Installing Steampipe..."
        local _sp_installer
        _sp_installer=$(mktemp); _register_cleanup "$_sp_installer"
        if curl -L --proto '=https' --tlsv1.2 -fsSL "https://raw.githubusercontent.com/turbot/steampipe/v2.4.4/scripts/install.sh" -o "$_sp_installer" 2>>"$LOG_FILE" \
                && _validate_curl_pipe "$_sp_installer" 'steampipe' 'install'; then
            _start_spinner "Installing Steampipe..."
            if bash "$_sp_installer" >> "$LOG_FILE" 2>&1; then
                _stop_spinner
                log_success "Steampipe installed"
                track_version "steampipe" "special" "latest"
            else
                _stop_spinner
                log_error "Steampipe install failed"
                TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
            fi
        else
            log_error "Steampipe installer download or content verification failed"
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        fi
        rm -f "$_sp_installer"
    elif command_exists steampipe; then
        log_success "Steampipe already installed"
    fi
}
