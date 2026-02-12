#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Enterprise
# Active Directory, Kerberos, LDAP, Azure AD, Windows network pentesting,
# credential harvesting, lateral movement

ENTERPRISE_PACKAGES=()

ENTERPRISE_PIPX=(
    impacket certipy-ad coercer bloodhound mitm6
    lsassy sprayhound ldapdomaindump pypykatz
    adidnsdump dploot bloodyad hekatomb
    donpapi certsync masky pywhisker autobloody
    krbjack roadtx pywerview pysnaffler powerview aclpwn
    ldeep smbclientng ldapsearchad
)

ENTERPRISE_GO=(
    "github.com/Macmod/godap@latest"
    "github.com/RedTeamPentesting/pretender@latest"
)

ENTERPRISE_GEMS=(evil-winrm)

ENTERPRISE_GIT=(
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
    "dfscoerce=https://github.com/Wh04m1001/dfscoerce.git"
    "petitpotam=https://github.com/topotam/PetitPotam.git"
    "shadowcoerce=https://github.com/ShutdownRepo/shadowcoerce.git"
    "noPac=https://github.com/Ridter/noPac.git"
    "zerologon=https://github.com/SecuraBV/CVE-2020-1472.git"
    "ntlm_theft=https://github.com/Greenwolf/ntlm_theft.git"
    "ntlmv1-multi=https://github.com/evilmog/ntlmv1-multi.git"
    "PassTheCert=https://github.com/AlmondOffSec/PassTheCert.git"
    "pkinittools=https://github.com/dirkjanm/PKINITtools.git"
    "privexchange=https://github.com/dirkjanm/PrivExchange.git"
    "GPOddity=https://github.com/synacktiv/GPOddity.git"
    "gmsadumper=https://github.com/micahvandeusen/gMSADumper.git"
    "ExtractBitlockerKeys=https://github.com/p0dalirius/ExtractBitlockerKeys.git"
    "PXEThief=https://github.com/blurbdust/PXEThief.git"
    "sccmsecrets=https://github.com/synacktiv/SCCMSecrets.git"
    "sccmwtf=https://github.com/xpn/sccmwtf.git"
    "cmloot=https://github.com/shelltrail/cmloot.git"
    "pywsus=https://github.com/GoSecure/pywsus.git"
    "RemoteMonologue=https://github.com/3lp4tr0n/RemoteMonologue.git"
    "roastinthemiddle=https://github.com/Tw1sm/RITM.git"
    "lnkup=https://github.com/Plazmaz/lnkUp.git"
    "ruler=https://github.com/sensepost/ruler.git"
    "bloodhound-quickwin=https://github.com/kaluche/bloodhound-quickwin.git"
    "bqm=https://github.com/Acceis/bqm.git"
    "cyperoth=https://github.com/seajaysec/cypheroth.git"
    "abuseACL=https://github.com/AetherBlack/abuseACL.git"
    "asrepcatcher=https://github.com/Yaxxine7/ASRepCatcher.git"
    "conpass=https://github.com/login-securite/conpass.git"
    "freeipscanner=https://github.com/scrt/freeipscanner.git"
    "goldencopy=https://github.com/Dramelac/GoldenCopy.git"
    "keytabextract=https://github.com/sosdave/KeyTabExtract.git"
    "ldaprelayscan=https://github.com/zyn3rgy/LdapRelayScan.git"
    "LDAPWordlistHarvester=https://github.com/p0dalirius/pyLDAPWordlistHarvester.git"
    "rusthound=https://github.com/NH-RED-TEAM/RustHound.git"
    "rusthound-ce=https://github.com/g0h4n/RustHound-CE.git"
    "GoExec=https://github.com/FalconOpsLLC/goexec.git"
    "GoMapEnum=https://github.com/nodauf/GoMapEnum.git"
    "gosecretsdump=https://github.com/c-sto/gosecretsdump.git"
)

ENTERPRISE_GO_BINS=(godap pretender)
ENTERPRISE_GIT_NAMES=(Responder Rubeus ADRecon enum4linux-ng linWinPwn PCredz WMIOps MailSniper Invoke-Obfuscation Snaffler GraphRunner TokenTactics Invoke-TheHash SCShell krbrelayx nishang redsnarf spraykatz azurehound dfscoerce petitpotam shadowcoerce noPac zerologon ntlm_theft ntlmv1-multi PassTheCert pkinittools privexchange GPOddity gmsadumper ExtractBitlockerKeys PXEThief sccmsecrets sccmwtf cmloot pywsus RemoteMonologue roastinthemiddle lnkup ruler bloodhound-quickwin bqm cyperoth abuseACL asrepcatcher conpass freeipscanner goldencopy keytabextract ldaprelayscan LDAPWordlistHarvester rusthound rusthound-ce GoExec GoMapEnum gosecretsdump)

install_module_enterprise() {
    [[ ${#ENTERPRISE_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Enterprise - Packages" "${ENTERPRISE_PACKAGES[@]}"
    install_pipx_batch "Enterprise - Python" "${ENTERPRISE_PIPX[@]}"

    # NetExec — install from git (PyPI package 'nxc' was removed)
    if ! pipx list --short 2>/dev/null | grep -qi "^netexec "; then
        log_info "Installing NetExec from GitHub..."
        pipx install "git+https://github.com/Pennyw0rth/NetExec" 2>>"$LOG_FILE" || log_warn "Failed to install NetExec"
    fi
    install_go_batch "Enterprise - Go" "${ENTERPRISE_GO[@]}"
    install_gem_batch "Enterprise - Ruby" "${ENTERPRISE_GEMS[@]}"
    install_git_batch "Enterprise - Git" "${ENTERPRISE_GIT[@]}"

    # Binary releases
    install_binary_releases "${BINARY_RELEASES_ENTERPRISE[@]}"

    # Docker: BloodHound (optional)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "specterops/bloodhound" "BloodHound CE" || true
    fi
}
