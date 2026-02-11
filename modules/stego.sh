#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Steganography
# Image/audio steganography tools
# =============================================================================

STEGO_PACKAGES=(
    steghide stegsnow outguess pngcheck
    sonic-visualiser
)

STEGO_PIPX=(stegoveritas)

STEGO_GO=()

STEGO_GEMS=(zsteg)

STEGO_GIT=(
    "stegsolve=https://github.com/Giotino/stegsolve.git"
    "openstego=https://github.com/syvaidya/openstego.git"
)

STEGO_GIT_NAMES=(stegsolve openstego)

install_module_stego() {
    install_apt_batch "Stego - Packages" "${STEGO_PACKAGES[@]}"
    install_pipx_batch "Stego - Python" "${STEGO_PIPX[@]}"
    install_gem_batch "Stego - Ruby" "${STEGO_GEMS[@]}"
    install_git_batch "Stego - Git" "${STEGO_GIT[@]}"

    # Binary releases
    download_github_release "RickdeJager/stegseek" "stegseek" "\\.deb" || true
}
