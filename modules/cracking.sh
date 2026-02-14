#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Cracking
# Hash cracking, brute force, wordlist generation

CRACKING_PACKAGES=(
    john hashcat hydra medusa crunch
    ophcrack chntpw fcrackzip pdfcrack
    cewl hashid bruteforce-luks
    maskprocessor princeprocessor statsprocessor
    sucrack
)

CRACKING_PIPX=(search-that-hash name-that-hash trevorspray)

CRACKING_GIT=(
    "DefaultCreds-cheat-sheet=https://github.com/ihebski/DefaultCreds-cheat-sheet.git"
    "pipal=https://github.com/digininja/pipal.git"
    "Hob0Rules=https://github.com/praetorian-inc/Hob0Rules.git"
    "Pantagrule=https://github.com/rarecoil/pantagrule.git"
    "OneRuleToRuleThemStill=https://github.com/stealthsploit/OneRuleToRuleThemStill.git"
    "username-anarchy=https://github.com/urbanadventurer/username-anarchy.git"
    "gpp-decrypt=https://github.com/t0thkr1s/gpp-decrypt.git"
)

CRACKING_GIT_NAMES=(DefaultCreds-cheat-sheet pipal Hob0Rules Pantagrule OneRuleToRuleThemStill username-anarchy gpp-decrypt)
CRACKING_BUILD_NAMES=(duplicut)

install_module_cracking() {
    install_apt_batch "Cracking - Packages" "${CRACKING_PACKAGES[@]}"
    install_pipx_batch "Cracking - Python" "${CRACKING_PIPX[@]}"

    # patator: cx-Oracle dependency requires Oracle Instant Client headers (not
    # available) and setuptools (missing from pipx venvs on Python 3.12+).
    # Exclude cx-Oracle — Oracle DB brute-forcing is a niche use case.
    # Pre-install setuptools to fix build failures on Python 3.12+ (PEP 632).
    if [[ "${SKIP_PIPX:-false}" != "true" ]] && ! command_exists patator; then
        log_info "Installing patator (excluding cx-Oracle)..."
        local _constraint
        _constraint=$(mktemp)
        echo 'cx-Oracle>=999' > "$_constraint"
        # --preinstall requires pipx >= 1.4.0 (Ubuntu 22.04 ships older)
        local _pipx_args=(install patator --pip-args="--constraint $_constraint")
        if pipx --help 2>&1 | grep -q -- '--preinstall'; then
            _pipx_args+=(--preinstall setuptools)
        fi
        if pipx "${_pipx_args[@]}" >> "$LOG_FILE" 2>&1; then
            # On older pipx without --preinstall, inject setuptools into patator's venv
            if ! pipx --help 2>&1 | grep -q -- '--preinstall'; then
                pipx inject patator setuptools >> "$LOG_FILE" 2>&1 || true
            fi
        else
            log_error "Failed pipx: patator"
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        fi
        rm -f "$_constraint"
    fi

    install_git_batch "Cracking - Git" "${CRACKING_GIT[@]}"

    # Build from source
    build_from_source "duplicut" "https://github.com/nil0x42/duplicut.git" "make" || true
}
