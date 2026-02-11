#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Active Directory
# AD attacks, Kerberos, LDAP, Windows network pentesting
# =============================================================================

AD_PACKAGES=()

AD_PIPX=(
    impacket netexec certipy-ad coercer bloodhound mitm6
    lsassy sprayhound ldapdomaindump pypykatz
)

AD_GO=()

AD_GIT=(
    "Responder=https://github.com/lgandx/Responder.git"
    "Rubeus=https://github.com/GhostPack/Rubeus.git"
    "ADRecon=https://github.com/adrecon/ADRecon.git"
    "enum4linux-ng=https://github.com/cddmp/enum4linux-ng.git"
)

AD_GIT_NAMES=(Responder Rubeus ADRecon enum4linux-ng)

install_module_ad() {
    [[ ${#AD_PACKAGES[@]} -gt 0 ]] && install_apt_batch "AD - Packages" "${AD_PACKAGES[@]}"
    install_pipx_batch "AD - Python" "${AD_PIPX[@]}"
    install_git_batch "AD - Git" "${AD_GIT[@]}"

    # Binary releases
    download_github_release "ropnop/kerbrute" "kerbrute" "linux_amd64" || true

    # Docker: BloodHound (optional)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "specterops/bloodhound" "BloodHound CE" || true
    fi
}
