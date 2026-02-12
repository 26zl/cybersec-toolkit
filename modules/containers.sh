#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Container Security
# Docker, Kubernetes security testing and auditing

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
    install_binary_releases "${BINARY_RELEASES_CONTAINERS[@]}"
}
