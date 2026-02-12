#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Cracking
# Hash cracking, brute force, wordlist generation

CRACKING_PACKAGES=(
    john hashcat hydra medusa crunch
    ophcrack chntpw fcrackzip pdfcrack
    cewl hashid bruteforce-luks
    maskprocessor princeprocessor statsprocessor
    rsmangler sucrack
)

CRACKING_PIPX=(search-that-hash name-that-hash trevorspray patator)

CRACKING_GIT=(
    "DefaultCreds-cheat-sheet=https://github.com/ihebski/DefaultCreds-cheat-sheet.git"
    "cupp=https://github.com/Mebus/cupp.git"
    "pipal=https://github.com/digininja/pipal.git"
    "Hob0Rules=https://github.com/praetorian-inc/Hob0Rules.git"
    "Pantagrule=https://github.com/rarecoil/pantagrule.git"
    "OneRuleToRuleThemStill=https://github.com/stealthsploit/OneRuleToRuleThemStill.git"
    "username-anarchy=https://github.com/urbanadventurer/username-anarchy.git"
    "gpp-decrypt=https://github.com/t0thkr1s/gpp-decrypt.git"
)

CRACKING_GIT_NAMES=(DefaultCreds-cheat-sheet cupp pipal Hob0Rules Pantagrule OneRuleToRuleThemStill username-anarchy gpp-decrypt)
CRACKING_BUILD_NAMES=(duplicut)

install_module_cracking() {
    install_apt_batch "Cracking - Packages" "${CRACKING_PACKAGES[@]}"
    install_pipx_batch "Cracking - Python" "${CRACKING_PIPX[@]}"

    # patator's cx-Oracle dependency needs setuptools at build time
    if command_exists pipx && pipx list --short 2>/dev/null | grep -qi "^patator "; then
        pipx inject patator setuptools >> "$LOG_FILE" 2>&1 || true
    fi

    install_git_batch "Cracking - Git" "${CRACKING_GIT[@]}"

    # Build from source
    build_from_source "duplicut" "https://github.com/nil0x42/duplicut.git" "make" || true
}
