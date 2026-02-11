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
)

PASSWORD_PIPX=(search-that-hash name-that-hash patator)

PASSWORD_GO=()

PASSWORD_GIT=(
    "DefaultCreds-cheat-sheet=https://github.com/ihebski/DefaultCreds-cheat-sheet.git"
)

PASSWORD_GIT_NAMES=(DefaultCreds-cheat-sheet)

install_module_password() {
    install_apt_batch "Password - Packages" "${PASSWORD_PACKAGES[@]}"
    install_pipx_batch "Password - Python" "${PASSWORD_PIPX[@]}"
    install_git_batch "Password - Git" "${PASSWORD_GIT[@]}"
}
