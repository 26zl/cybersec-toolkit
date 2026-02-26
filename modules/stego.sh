#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Steganography
# Image/audio steganography tools

STEGO_PACKAGES=(
    steghide stegsnow pngcheck
    sonic-visualiser exiv2 pngtools
)

STEGO_PIPX=(stegoveritas)

STEGO_GEMS=(zsteg)

STEGO_GIT=(
    "stegsolve=https://github.com/Giotino/stegsolve.git"
    "openstego=https://github.com/syvaidya/openstego.git"
    "stegextract=https://github.com/evyatarmeged/stegextract.git"
    "stegosaurus=https://github.com/AngelKitty/stegosaurus.git"
)

STEGO_GIT_NAMES=(stegsolve openstego stegextract stegosaurus)
STEGO_BUILD_NAMES=()

install_module_stego() {
    install_apt_batch "Stego - Packages" "${STEGO_PACKAGES[@]}"
    install_pipx_batch "Stego - Python" "${STEGO_PIPX[@]}"
    install_gem_batch "Stego - Ruby" "${STEGO_GEMS[@]}"
    install_git_batch "Stego - Git" "${STEGO_GIT[@]}"

    # Binary releases
    install_binary_releases "${BINARY_RELEASES_STEGO[@]}"
}
