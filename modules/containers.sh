#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Container Security
# Docker, Kubernetes security testing and auditing
# =============================================================================

CONTAINER_GO=()

CONTAINER_GIT=(
    "deepce=https://github.com/stealthcopter/deepce.git"
    "docker-bench-security=https://github.com/docker/docker-bench-security.git"
    "peirates=https://github.com/inguardians/peirates.git"
)

CONTAINER_GIT_NAMES=(deepce docker-bench-security peirates)

install_module_containers() {
    install_git_batch "Containers - Git" "${CONTAINER_GIT[@]}"

    # Binary releases (preferred over git clone)
    local trivy_pattern="Linux-64bit\\.tar\\.gz"
    [[ "$SYS_ARCH" != "amd64" ]] && trivy_pattern="Linux-ARM64\\.tar\\.gz"
    download_github_release "aquasecurity/trivy" "trivy" "$trivy_pattern" || true
    download_github_release "anchore/grype" "grype" "linux_amd64\\.tar\\.gz" || true
    download_github_release "Shopify/kubeaudit" "kubeaudit" "linux_amd64\\.tar\\.gz" || true
    download_github_release "cdk-team/CDK" "cdk" "cdk_linux_amd64" || true
}
