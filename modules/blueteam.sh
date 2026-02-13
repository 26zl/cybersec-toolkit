#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Blue Team / Defensive Security
# IDS/IPS, SIEM, log analysis, file integrity, threat intelligence,
# incident response platforms, endpoint visibility, malware analysis,
# AV engines, YARA rules

BLUETEAM_PACKAGES=(suricata fail2ban aide auditd zeek apparmor-utils ufw tiger darkstat chaosreader sentrypeer lynis rkhunter chkrootkit yara clamav inetsim)

BLUETEAM_PIPX=(sigma-cli bandit quark-engine)

BLUETEAM_CARGO=(yara-x)

BLUETEAM_GIT=(
    "sigma-rules=https://github.com/SigmaHQ/sigma.git"
    "maltrail=https://github.com/stamparm/maltrail.git"
    "MISP-docker=https://github.com/MISP/misp-docker.git"
    "wazuh-docker=https://github.com/wazuh/wazuh-docker.git"
)

BLUETEAM_GIT_NAMES=(sigma-rules maltrail MISP-docker wazuh-docker)

install_module_blueteam() {
    install_apt_batch "Blue Team - Packages" "${BLUETEAM_PACKAGES[@]}"
    install_pipx_batch "Blue Team - Python" "${BLUETEAM_PIPX[@]}"
    install_cargo_batch "Blue Team - Cargo" "${BLUETEAM_CARGO[@]}"
    install_git_batch "Blue Team - Git" "${BLUETEAM_GIT[@]}"

    # Binary releases (Velociraptor, Laurel, FLOSS, Capa, Loki)
    install_binary_releases "${BINARY_RELEASES_BLUETEAM[@]}"

    # Docker: IR platforms (only if enabled)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        log_info "Installing Blue Team Docker platforms..."
        docker_pull "strangebee/thehive:latest" "TheHive" || true
        docker_pull "thehiveproject/cortex:latest" "Cortex" || true
    fi
}
