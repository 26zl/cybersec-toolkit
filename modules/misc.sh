#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Misc / Dependencies / Cross-domain tools
# Build deps, runtimes, utilities, C2 frameworks, social engineering,
# post-exploitation, mobile, resources

MISC_PACKAGES=()

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
    # Enumeration
    "PEASS-ng=https://github.com/peass-ng/PEASS-ng.git"
    "linux-smart-enumeration=https://github.com/diego-treitos/linux-smart-enumeration.git"
    "SUDO_KILLER=https://github.com/TH3xACE/SUDO_KILLER.git"
    # General
    "CyberChef=https://github.com/gchq/CyberChef.git"
    "RedEye=https://github.com/cisagov/RedEye.git"
)

# Tools gated by INCLUDE_C2. Loki-C2 is cloned as a resource and requires manual setup.
MISC_C2_GIT=(
    # Social engineering / phishing
    "SET=https://github.com/trustedsec/social-engineer-toolkit.git"
    "Zphisher=https://github.com/htr-tech/zphisher.git"
    "EvilGoPhish=https://github.com/fin3ss3g0d/evilgophish.git"
    "SquarePhish=https://github.com/secureworks/squarephish.git"
    "CredMaster=https://github.com/knavesec/CredMaster.git"
    "Modlishka=https://github.com/drk1wi/Modlishka.git"
    # C2 / adversary emulation
    "Caldera=https://github.com/mitre/caldera.git"
    "Loki-C2=https://github.com/boku7/Loki.git"
    # Gated post-exploitation tools
    "LaZagne=https://github.com/AlessandroZ/LaZagne.git"
    "mimipenguin=https://github.com/huntergregal/mimipenguin.git"
    "PyExfil=https://github.com/ytisf/PyExfil.git"
    "usbkill=https://github.com/hephaest0s/usbkill.git"
)

# Git repo names for verify/remove (general). remove.sh removes both sets; verify.sh
# checks MISC_C2_GIT_NAMES only when INCLUDE_C2=true.
MISC_GIT_NAMES=(
    SecLists PayloadsAllTheThings InternalAllTheThings
    PEASS-ng linux-smart-enumeration SUDO_KILLER
    CyberChef RedEye
)
MISC_C2_GIT_NAMES=(
    SET Zphisher EvilGoPhish SquarePhish CredMaster Modlishka
    Caldera Loki-C2
    LaZagne mimipenguin PyExfil usbkill
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

    # Git repos (resources, post-exploitation, CTF)
    install_git_batch "Misc - Git" "${MISC_GIT[@]}"

    # Binary releases (skipped on Termux — Linux/glibc binaries)
    install_binary_releases "${BINARY_RELEASES_MISC[@]}"

    # C2 + credential-phishing/social-engineering frameworks — only with INCLUDE_C2.
    if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
        log_info "Installing C2 / phishing frameworks (INCLUDE_C2 enabled)..."
        [[ ${#MISC_C2_GIT[@]} -gt 0 ]] && install_git_batch "Misc - C2/Phishing (Git)" "${MISC_C2_GIT[@]}"
        [[ ${#BINARY_RELEASES_MISC_C2[@]} -gt 0 ]] && install_binary_releases "${BINARY_RELEASES_MISC_C2[@]}"
    else
        log_info "Skipping C2 / phishing frameworks (INCLUDE_C2 disabled — use --include-c2 or the redteam/full profile)"
    fi

    # Docker: OSINT + C2 frameworks that need multi-service orchestration.
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "spiderfoot/spiderfoot" "SpiderFoot" || true
        if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
            log_info "Installing C2 frameworks via Docker..."
            docker_pull "bcsecurity/empire" "Empire" || true
        fi
    else
        if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
            log_warn "Docker-based C2 frameworks (Empire) require --enable-docker. Skipping."
        fi
    fi
}
