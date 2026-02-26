#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Misc / Dependencies / Cross-domain tools
# Build deps, runtimes, utilities, C2 frameworks, social engineering,
# post-exploitation, mobile, resources
# =============================================================================

MISC_PACKAGES=()

# Heavy tools (skipped with --skip-heavy)
MISC_HEAVY_PACKAGES=()

MISC_PIPX=(arsenal-cli sploitscan faraday-cli)

MISC_GO=(
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
)

MISC_GIT=(
    # Resources
    "SecLists=https://github.com/danielmiessler/SecLists.git"
    "PayloadsAllTheThings=https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    "InternalAllTheThings=https://github.com/swisskyrepo/InternalAllTheThings.git"
    # Post-exploitation
    "PEASS-ng=https://github.com/peass-ng/PEASS-ng.git"
    "linux-smart-enumeration=https://github.com/diego-treitos/linux-smart-enumeration.git"
    "SUDO_KILLER=https://github.com/TH3xACE/SUDO_KILLER.git"
    "LaZagne=https://github.com/AlessandroZ/LaZagne.git"
    "mimipenguin=https://github.com/huntergregal/mimipenguin.git"
    "PyExfil=https://github.com/ytisf/PyExfil.git"
    "usbkill=https://github.com/hephaest0s/usbkill.git"
    # Social engineering
    "SET=https://github.com/trustedsec/social-engineer-toolkit.git"
    "Zphisher=https://github.com/htr-tech/zphisher.git"
    "EvilGoPhish=https://github.com/fin3ss3g0d/evilgophish.git"
    "SquarePhish=https://github.com/secureworks/squarephish.git"
    "CredMaster=https://github.com/knavesec/CredMaster.git"
    "Modlishka=https://github.com/drk1wi/Modlishka.git"
    # General
    "CyberChef=https://github.com/gchq/CyberChef.git"
    "Caldera=https://github.com/mitre/caldera.git"
    "RedEye=https://github.com/cisagov/RedEye.git"
)

# C2 Frameworks (Docker ONLY — these require complex multi-service setup)
# C2 frameworks are not runnable from a simple git clone; they need databases,
# listeners, agents, and service orchestration.  Docker is the only supported
# install method to ensure they work out-of-the-box.

# All git repo names for verify/remove
MISC_GIT_NAMES=(
    SecLists PayloadsAllTheThings InternalAllTheThings
    PEASS-ng linux-smart-enumeration SUDO_KILLER
    LaZagne mimipenguin
    PyExfil usbkill
    SET Zphisher EvilGoPhish SquarePhish CredMaster
    Modlishka
    CyberChef Caldera RedEye
)
MISC_GO_BINS=(gf anew qsreplace notify pdtm)

install_module_misc() {
    [[ ${#MISC_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Misc - Packages" "${MISC_PACKAGES[@]}"

    # Heavy packages (optional)
    if [[ "${SKIP_HEAVY:-false}" != "true" ]] && [[ ${#MISC_HEAVY_PACKAGES[@]} -gt 0 ]]; then
        install_apt_batch "Heavy tools" "${MISC_HEAVY_PACKAGES[@]}"
    fi

    # Python tools
    install_pipx_batch "Misc - Python" "${MISC_PIPX[@]}"

    # Go tools
    install_go_batch "Misc - Go" "${MISC_GO[@]}"

    # Git repos (resources, post-exploitation, social engineering, CTF)
    install_git_batch "Misc - Git" "${MISC_GIT[@]}"

    # Binary releases (skipped on Termux — Linux/glibc binaries)
    install_binary_releases "${BINARY_RELEASES_MISC[@]}"

    # Docker: C2 frameworks and OSINT (only if enabled — no git clone fallback)
    # C2 frameworks require Docker for full functionality (databases, listeners, etc.)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "spiderfoot/spiderfoot" "SpiderFoot" || true
        if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
            log_info "Installing C2 frameworks via Docker..."
            docker_pull "bcsecurity/empire" "Empire" || true
        fi
    else
        if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
            log_warn "C2 frameworks require --enable-docker. Skipping."
        fi
    fi
}
