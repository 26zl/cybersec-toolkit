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
    dos2unix rlwrap imagemagick
)

# --- Security / detection tools ---
MISC_SECURITY_PACKAGES=(lynis rkhunter chkrootkit)

# --- Heavy tools (skipped with --skip-heavy) ---
MISC_HEAVY_PACKAGES=(gimp audacity sagemath)

MISC_PIPX=(arsenal-cli sploitscan faraday-cli)

MISC_GO=(
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
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
    "Cloakify=https://github.com/TryCatchHCF/Cloakify.git"
    "PyExfil=https://github.com/ytisf/PyExfil.git"
    "GD-Thief=https://github.com/antman1p/GD-Thief.git"
    "usbkill=https://github.com/hephaest0s/usbkill.git"
    "LinEnum=https://github.com/rebootuser/LinEnum.git"
    "Hwacha=https://github.com/n00py/Hwacha.git"
    "pivotsuite=https://github.com/RedTeamOperations/PivotSuite.git"
    "unix-privesc-check=https://github.com/pentestmonkey/unix-privesc-check.git"
    "LOLBAS=https://github.com/LOLBAS-Project/LOLBAS.git"
)

# --- Social engineering ---
MISC_SOCIAL=(
    "SET=https://github.com/trustedsec/social-engineer-toolkit.git"
    "Zphisher=https://github.com/htr-tech/zphisher.git"
    "SocialFish=https://github.com/UndeadSec/SocialFish.git"
    "EvilGoPhish=https://github.com/fin3ss3g0d/evilgophish.git"
    "SquarePhish=https://github.com/secureworks/squarephish.git"
    "CredMaster=https://github.com/knavesec/CredMaster.git"
    "king-phisher=https://github.com/rsmusllp/king-phisher.git"
    "Modlishka=https://github.com/drk1wi/Modlishka.git"
    "ReelPhish=https://github.com/mandiant/ReelPhish.git"
    "Catphish=https://github.com/ring0lab/catphish.git"
)

# --- CTF / General ---
MISC_CTF=(
    "CyberChef=https://github.com/gchq/CyberChef.git"
    "ctf-tools=https://github.com/zardus/ctf-tools.git"
    "CTF-Katana=https://github.com/JohnHammond/ctf-katana.git"
    "Caldera=https://github.com/mitre/caldera.git"
    "atomic-red-team=https://github.com/redcanaryco/atomic-red-team.git"
    "RedEye=https://github.com/cisagov/RedEye.git"
    "ibombshell=https://github.com/Telefonica/ibombshell.git"
    "powercat=https://github.com/besimorhino/powercat.git"
)

# --- C2 Frameworks (Docker ONLY — these require complex multi-service setup) ---
# C2 frameworks are not runnable from a simple git clone; they need databases,
# listeners, agents, and service orchestration.  Docker is the only supported
# install method to ensure they work out-of-the-box.

# All git repo names for verify/remove
MISC_GIT_NAMES=(
    SecLists PayloadsAllTheThings wordlists OneListForAll Auto_Wordlists FuzzDB
    InternalAllTheThings GTFOBins.github.io WADComs BlueTeam-Tools
    PEASS-ng linux-exploit-suggester linux-smart-enumeration SUDO_KILLER
    BeRoot PrivescCheck LaZagne mimipenguin PowerSploit
    Cloakify PyExfil GD-Thief usbkill
    LinEnum Hwacha pivotsuite unix-privesc-check LOLBAS
    SET Zphisher SocialFish EvilGoPhish SquarePhish CredMaster king-phisher
    Modlishka ReelPhish Catphish
    CyberChef ctf-tools CTF-Katana
    Caldera atomic-red-team RedEye
    ibombshell powercat
)
MISC_GO_BINS=(gf anew qsreplace notify gitleaks)

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

    # CTF general
    install_git_batch "CTF Tools" "${MISC_CTF[@]}"

    # Binary releases
    download_github_release "DominicBreuker/pspy" "pspy" "pspy64" || true
    download_github_release "gophish/gophish" "gophish" "linux-64bit" || true
    download_github_release "skylot/jadx" "jadx" "jadx.*\\.zip" "/opt/jadx" || true
    download_github_release "pxb1988/dex2jar" "d2j-dex2jar" "dex2jar.*\\.zip" "/opt/dex2jar" || true
    download_github_release "gitleaks/gitleaks" "gitleaks" "linux_amd64\\.tar\\.gz" || true
    download_github_release "trufflesecurity/trufflehog" "trufflehog" "linux_amd64\\.tar\\.gz" || true
    # stegseek is installed by the stego module

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
