#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Misc / Dependencies / Cross-domain tools
# Build deps, runtimes, utilities, C2 frameworks, social engineering,
# post-exploitation, mobile, resources
# =============================================================================

# --- Base dependencies (always installed first) ---
MISC_BASE_PACKAGES=(
    git curl wget openssl build-essential unzip
    python3 python3-pip python3-venv python3-dev
    ruby ruby-dev golang-go default-jdk
    libpcap-dev libssl-dev libffi-dev
    zlib1g-dev libxml2-dev libxslt1-dev
    dos2unix rlwrap adb imagemagick
)

# --- Security / detection tools ---
MISC_SECURITY_PACKAGES=(lynis rkhunter chkrootkit)

# --- Heavy tools (skipped with --skip-heavy) ---
MISC_HEAVY_PACKAGES=(gimp audacity sagemath)

MISC_PIPX=(
    arsenal-cli gittools objection frida-tools androguard apkleaks
)

MISC_GO=(
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/gitleaks/gitleaks/v8/cmd/gitleaks@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/kgretzky/evilginx2@latest"
)

# --- Reference repos / wordlists ---
MISC_RESOURCES=(
    "SecLists=https://github.com/danielmiessler/SecLists.git"
    "PayloadsAllTheThings=https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    "wordlists=https://github.com/kkrypt0nn/wordlists.git"
    "OneListForAll=https://github.com/six2dez/OneListForAll.git"
    "Auto_Wordlists=https://github.com/carlospolop/Auto_Wordlists.git"
    "FuzzDB=https://github.com/fuzzdb-project/fuzzdb.git"
    "InternalAllTheThings=https://github.com/swisskyrepo/InternalAllTheThings.git"
    "GTFOBins.github.io=https://github.com/GTFOBins/GTFOBins.github.io.git"
    "WADComs=https://github.com/WADComs/WADComs.github.io.git"
    "BlueTeam-Tools=https://github.com/A-poc/BlueTeam-Tools.git"
)

# --- Post-exploitation tools ---
MISC_POSTEXPLOIT=(
    "PEASS-ng=https://github.com/peass-ng/PEASS-ng.git"
    "linux-exploit-suggester=https://github.com/The-Z-Labs/linux-exploit-suggester.git"
    "linux-smart-enumeration=https://github.com/diego-treitos/linux-smart-enumeration.git"
    "SUDO_KILLER=https://github.com/TH3xACE/SUDO_KILLER.git"
    "BeRoot=https://github.com/AlessandroZ/BeRoot.git"
    "PrivescCheck=https://github.com/itm4n/PrivescCheck.git"
    "LaZagne=https://github.com/AlessandroZ/LaZagne.git"
    "mimipenguin=https://github.com/huntergregal/mimipenguin.git"
    "PowerSploit=https://github.com/PowerShellMafia/PowerSploit.git"
)

# --- Social engineering ---
MISC_SOCIAL=(
    "SET=https://github.com/trustedsec/social-engineer-toolkit.git"
    "Zphisher=https://github.com/htr-tech/zphisher.git"
    "SocialFish=https://github.com/UndeadSec/SocialFish.git"
)

# --- Mobile ---
MISC_MOBILE=(
    "apktool=https://github.com/iBotPeaches/Apktool.git"
)

# --- CTF / General ---
MISC_CTF=(
    "CyberChef=https://github.com/gchq/CyberChef.git"
    "ctf-tools=https://github.com/zardus/ctf-tools.git"
    "CTF-Katana=https://github.com/JohnHammond/ctf-katana.git"
)

# --- C2 Frameworks (Docker only, optional) ---
MISC_C2_DOCKER=(
    "bcsecurity/empire:Empire"
)
MISC_C2_GIT=(
    "Sliver=https://github.com/BishopFox/sliver.git"
    "Havoc=https://github.com/HavocFramework/Havoc.git"
    "Villain=https://github.com/t3l3machus/Villain.git"
    "PoshC2=https://github.com/nettitude/PoshC2.git"
    "Mythic=https://github.com/its-a-feature/Mythic.git"
    "Pupy=https://github.com/n1nj4sec/pupy.git"
)

# All git repo names for verify/remove
MISC_GIT_NAMES=(
    SecLists PayloadsAllTheThings wordlists OneListForAll Auto_Wordlists FuzzDB
    InternalAllTheThings GTFOBins.github.io WADComs BlueTeam-Tools
    PEASS-ng linux-exploit-suggester linux-smart-enumeration SUDO_KILLER
    BeRoot PrivescCheck LaZagne mimipenguin PowerSploit
    SET Zphisher SocialFish apktool CyberChef ctf-tools CTF-Katana
    Sliver Havoc Villain PoshC2 Mythic Pupy
)
MISC_GO_BINS=(gf anew qsreplace gitleaks notify evilginx2)

install_module_misc() {
    # Base dependencies (always first)
    install_apt_batch "Base dependencies" "${MISC_BASE_PACKAGES[@]}"
    install_apt_batch "Security tools" "${MISC_SECURITY_PACKAGES[@]}"

    # Heavy packages (optional)
    if [[ "${SKIP_HEAVY:-false}" != "true" ]]; then
        install_apt_batch "Heavy tools" "${MISC_HEAVY_PACKAGES[@]}"
    else
        log_warn "Skipping heavy packages (sagemath, gimp, audacity)"
    fi

    # Python tools
    install_pipx_batch "Misc - Python" "${MISC_PIPX[@]}"

    # Go tools
    install_go_batch "Misc - Go" "${MISC_GO[@]}"

    # Resources / wordlists
    install_git_batch "Resources & Wordlists"  "${MISC_RESOURCES[@]}"

    # Post-exploitation
    install_git_batch "Post-Exploitation" "${MISC_POSTEXPLOIT[@]}"

    # Social engineering
    install_git_batch "Social Engineering" "${MISC_SOCIAL[@]}"

    # Mobile
    install_git_batch "Mobile" "${MISC_MOBILE[@]}"

    # CTF general
    install_git_batch "CTF Tools" "${MISC_CTF[@]}"

    # Binary releases
    download_github_release "DominicBreuker/pspy" "pspy" "pspy64" || true
    download_github_release "gophish/gophish" "gophish" "linux-64bit" || true
    download_github_release "skylot/jadx" "jadx" "jadx.*\\.zip" "/opt/jadx" || true
    download_github_release "pxb1988/dex2jar" "d2j-dex2jar" "dex2jar.*\\.zip" "/opt/dex2jar" || true
    download_github_release "trufflesecurity/trufflehog" "trufflehog" "linux_amd64\\.tar\\.gz" || true
    # stegseek is installed by the stego module

    # Docker: C2 frameworks (only if enabled)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        log_info "Installing C2 frameworks via Docker..."
        for entry in "${MISC_C2_DOCKER[@]}"; do
            local image="${entry%%:*}"
            local name="${entry#*:}"
            docker_pull "$image" "$name" || true
        done

        docker_pull "opensecurity/mobile-security-framework-mobsf" "MobSF" || true
        docker_pull "spiderfoot/spiderfoot" "SpiderFoot" || true
    fi

    # C2 Git clones (fallback when Docker not available)
    if [[ "${ENABLE_DOCKER:-false}" != "true" && "${INCLUDE_C2:-false}" == "true" ]]; then
        install_git_batch "C2 Frameworks" "${MISC_C2_GIT[@]}"
    fi
}
