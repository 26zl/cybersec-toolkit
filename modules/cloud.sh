#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Cloud Security
# AWS, Azure, GCP security testing and auditing
# =============================================================================

CLOUD_PACKAGES=()

CLOUD_PIPX=(
    kube-hunter pacu cloudsplaining prowler scoutsuite
)

CLOUD_GO=(
    "github.com/BishopFox/cloudfox@latest"
    "github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest"
)

CLOUD_GIT=(
    "CloudBrute=https://github.com/0xsha/CloudBrute.git"
    "enumerate-iam=https://github.com/andresriancho/enumerate-iam.git"
    "WeirdAAL=https://github.com/carnal0wnage/weirdAAL.git"
    "s3reverse=https://github.com/hahwul/s3reverse.git"
)

CLOUD_GO_BINS=(cloudfox cloudlist)
CLOUD_GIT_NAMES=(CloudBrute enumerate-iam WeirdAAL s3reverse)

install_module_cloud() {
    [[ ${#CLOUD_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Cloud - Packages" "${CLOUD_PACKAGES[@]}"
    install_pipx_batch "Cloud - Python" "${CLOUD_PIPX[@]}"
    install_go_batch "Cloud - Go" "${CLOUD_GO[@]}"
    install_git_batch "Cloud - Git" "${CLOUD_GIT[@]}"
}
