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
    adidnsdump dploot bloodyad hekatomb ldeep
    lapsdumper certi polenum
)

AD_GO=()

AD_GEMS=(evil-winrm)

AD_GIT=(
    "Responder=https://github.com/lgandx/Responder.git"
    "Rubeus=https://github.com/GhostPack/Rubeus.git"
    "ADRecon=https://github.com/adrecon/ADRecon.git"
    "enum4linux-ng=https://github.com/cddmp/enum4linux-ng.git"
    "linWinPwn=https://github.com/lefayjey/linWinPwn.git"
    "PCredz=https://github.com/lgandx/PCredz.git"
    "WMIOps=https://github.com/FortyNorthSecurity/WMIOps.git"
    "MailSniper=https://github.com/dafthack/MailSniper.git"
    "Invoke-Obfuscation=https://github.com/danielbohannon/Invoke-Obfuscation.git"
    "Snaffler=https://github.com/SnaffCon/Snaffler.git"
    "GraphRunner=https://github.com/dafthack/GraphRunner.git"
    "TokenTactics=https://github.com/rvrsh3ll/TokenTactics.git"
    "Invoke-TheHash=https://github.com/Kevin-Robertson/Invoke-TheHash.git"
    "SCShell=https://github.com/Mr-Un1k0d3r/SCShell.git"
    "krbrelayx=https://github.com/dirkjanm/krbrelayx.git"
    "nishang=https://github.com/samratashok/nishang.git"
    "redsnarf=https://github.com/nccgroup/redsnarf.git"
    "spraykatz=https://github.com/aas-n/spraykatz.git"
    "azurehound=https://github.com/BloodHoundAD/AzureHound.git"
)

AD_GIT_NAMES=(Responder Rubeus ADRecon enum4linux-ng linWinPwn PCredz WMIOps MailSniper Invoke-Obfuscation Snaffler GraphRunner TokenTactics Invoke-TheHash SCShell krbrelayx nishang redsnarf spraykatz azurehound)

install_module_ad() {
    [[ ${#AD_PACKAGES[@]} -gt 0 ]] && install_apt_batch "AD - Packages" "${AD_PACKAGES[@]}"
    install_pipx_batch "AD - Python" "${AD_PIPX[@]}"
    install_gem_batch "AD - Ruby" "${AD_GEMS[@]}"
    install_git_batch "AD - Git" "${AD_GIT[@]}"

    # Binary releases
    download_github_release "ropnop/kerbrute" "kerbrute" "linux_amd64" || true

    # Docker: BloodHound (optional)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "specterops/bloodhound" "BloodHound CE" || true
    fi
}
