#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Password Cracking
# Hash cracking, brute force, wordlist generation
# =============================================================================

PASSWORD_PACKAGES=(
    john hashcat hydra medusa crunch
    ophcrack chntpw fcrackzip pdfcrack
    cewl hashid
    maskprocessor princeprocessor statsprocessor
    rsmangler rainbowcrack sucrack
)

PASSWORD_PIPX=(search-that-hash name-that-hash patator trevorspray)

PASSWORD_GO=()

PASSWORD_GIT=(
    "DefaultCreds-cheat-sheet=https://github.com/ihebski/DefaultCreds-cheat-sheet.git"
    "cupp=https://github.com/Mebus/cupp.git"
    "pipal=https://github.com/digininja/pipal.git"
)

PASSWORD_GIT_NAMES=(DefaultCreds-cheat-sheet cupp pipal duplicut)

install_module_password() {
    install_apt_batch "Password - Packages" "${PASSWORD_PACKAGES[@]}"
    install_pipx_batch "Password - Python" "${PASSWORD_PIPX[@]}"
    install_git_batch "Password - Git" "${PASSWORD_GIT[@]}"

    # Build from source
    build_from_source "duplicut" "https://github.com/nil0x42/duplicut.git" "make" || true
}
