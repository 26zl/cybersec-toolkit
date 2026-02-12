#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Cloud Security
# AWS, Azure, GCP security testing and auditing

CLOUD_PACKAGES=()

CLOUD_PIPX=(
    kube-hunter pacu cloudsplaining prowler scoutsuite
    s3scanner roadrecon checkov
)

CLOUD_GO=(
    "github.com/BishopFox/cloudfox@latest"
    "github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest"
)

CLOUD_GIT=(
    "CloudBrute=https://github.com/0xsha/CloudBrute.git"
    "enumerate-iam=https://github.com/andresriancho/enumerate-iam.git"
    "GCPBucketBrute=https://github.com/RhinoSecurityLabs/GCPBucketBrute.git"
    "cloud_enum=https://github.com/initstring/cloud_enum.git"
)

CLOUD_GO_BINS=(cloudfox cloudlist)
CLOUD_GIT_NAMES=(CloudBrute enumerate-iam GCPBucketBrute cloud_enum)

install_module_cloud() {
    [[ ${#CLOUD_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Cloud - Packages" "${CLOUD_PACKAGES[@]}"
    install_pipx_batch "Cloud - Python" "${CLOUD_PIPX[@]}"
    install_go_batch "Cloud - Go" "${CLOUD_GO[@]}"
    install_git_batch "Cloud - Git" "${CLOUD_GIT[@]}"

    # Steampipe (Linux only — curl-pipe installer)
    if [[ "${SKIP_SOURCE:-false}" != "true" ]] && [[ "$PKG_MANAGER" != "pkg" ]] && ! command_exists steampipe; then
        log_info "Installing Steampipe..."
        local _sp_installer
        _sp_installer=$(mktemp)
        if curl -fsSL "https://raw.githubusercontent.com/turbot/steampipe/main/install.sh" -o "$_sp_installer" 2>>"$LOG_FILE"; then
            if grep -q "steampipe" "$_sp_installer" 2>/dev/null; then
                if bash "$_sp_installer" >> "$LOG_FILE" 2>&1; then
                    log_success "Steampipe installed"
                    track_version "steampipe" "special" "latest"
                else
                    log_error "Steampipe install failed"
                    TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
                fi
            else
                log_error "Steampipe installer content verification failed"
            fi
        else
            log_error "Failed to download Steampipe installer"
        fi
        rm -f "$_sp_installer"
    elif command_exists steampipe; then
        log_success "Steampipe already installed"
    fi
}
