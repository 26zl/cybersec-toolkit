#!/usr/bin/env bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Blue Team / Defensive Security
# IDS/IPS, SIEM, log analysis, file integrity, threat intelligence,
# incident response platforms, endpoint visibility, malware analysis,
# AV engines, YARA rules

BLUETEAM_PACKAGES=(suricata fail2ban aide auditd apparmor-utils ufw tiger darkstat chaosreader sentrypeer lynis rkhunter chkrootkit yara clamav inetsim openscap-scanner)
declare -gA BLUETEAM_PACKAGE_BIN_NAMES=([openscap-scanner]=oscap)

BLUETEAM_PIPX=(sigma-cli bandit quark-engine)

BLUETEAM_GO=("github.com/VirusTotal/vt-cli/vt@latest")
BLUETEAM_GO_BINS=(vt)

BLUETEAM_CARGO=(yara-x-cli)

BLUETEAM_GIT=(
    "sigma-rules=https://github.com/SigmaHQ/sigma.git"
    "maltrail=https://github.com/stamparm/maltrail.git"
    "MISP-docker=https://github.com/MISP/misp-docker.git"
    "wazuh-docker=https://github.com/wazuh/wazuh-docker.git"
    "atomic-red-team=https://github.com/redcanaryco/atomic-red-team.git"
)

BLUETEAM_GIT_NAMES=(sigma-rules maltrail MISP-docker wazuh-docker atomic-red-team)

BLUETEAM_BUILD_NAMES=(kernel-hardening-checker)
declare -gA BLUETEAM_BUILD_URLS=(
    [kernel-hardening-checker]="https://github.com/a13xp0p0v/kernel-hardening-checker.git"
)
declare -gA BLUETEAM_BUILD_CMDS=(
    [kernel-hardening-checker]="python3 -m venv .venv && .venv/bin/python -m pip install --upgrade . && test -x .venv/bin/kernel-hardening-checker"
)
declare -gA BLUETEAM_BUILD_BINS=(
    [kernel-hardening-checker]=".venv/bin/kernel-hardening-checker|kernel-hardening-checker"
)
declare -gA BLUETEAM_BUILD_PACKAGES=(
    [kernel-hardening-checker]="git python3 python3-pip python3-venv"
)
declare -gA BLUETEAM_BINARY_ARCHITECTURES=([takajo]="amd64")
declare -gA BLUETEAM_BINARY_EXCLUSIVE_DIRS=([takajo]=true)
declare -gA BLUETEAM_BINARY_RUNTIME_RELEASES=([takajo]="v2.16.1")
declare -gA BLUETEAM_BINARY_DEPENDENCIES=(
    [takajo]='duckdb/duckdb|libduckdb.so|^libduckdb-linux-amd64\.zip$|.runtime|v1.4.4'
)

declare -gA BLUETEAM_BINARY_RUNTIME_CONFIGS=(
    [takajo]='{
  "working_directory": ".",
  "library_directories": [
    ".runtime"
  ],
  "required_files": [
    ".runtime/libduckdb.so"
  ],
  "commands": {
    "automagic": "help:h:b help-syntax:-:b version:-:b level:l:v skipProgressBar:s:b displayTable:d:b output:o:p quiet:q:b timeline:t:p",
    "convert-flatten-json": "help:h:b help-syntax:-:b version:-:b output:o:p quiet:q:b skipProgressBar:s:b timeline:t:p",
    "extract-credentials": "help:h:b help-syntax:-:b version:-:b output:o:p quiet:q:b skipProgressBar:s:b timeline:t:p",
    "extract-scriptblocks": "help:h:b help-syntax:-:b version:-:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "html-report": "help:h:b help-syntax:-:b version:-:b output:o:p quiet:q:b timeline:t:p rulepath:r:p clobber:C:b dboutput:s:p sqlite:-:b skipProgressBar:-:b",
    "html-server": "help:h:b help-syntax:-:b version:-:b port:p:v quiet:q:b timeline:t:p rulepath:r:p clobber:C:b dboutput:s:p sqlite:-:b skipProgressBar:-:b",
    "list-domains": "help:h:b help-syntax:-:b version:-:b includeSubdomains:d:b includeWorkstations:w:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "list-hashes": "help:h:b help-syntax:-:b version:-:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "list-ip-addresses": "help:h:b help-syntax:-:b version:-:b inbound:i:b outbound:O:b privateIp:p:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "list-undetected-evtx": "help:h:b help-syntax:-:b version:-:b columnName:c:v evtxDir:e:p output:o:p quiet:q:b timeline:t:p",
    "list-unused-rules": "help:h:b help-syntax:-:b version:-:b columnName:c:v rulesDir:r:p output:o:p quiet:q:b timeline:t:p",
    "split-csv-timeline": "help:h:b help-syntax:-:b version:-:b makeMultiline:m:b output:o:p quiet:q:b timeline:t:p",
    "metrics-computers": "help:h:b help-syntax:-:b version:-:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "metrics-users": "help:h:b help-syntax:-:b version:-:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "split-json-timeline": "help:h:b help-syntax:-:b version:-:b output:o:p quiet:q:b timeline:t:p",
    "stack-cmdlines": "help:h:b help-syntax:-:b version:-:b ignoreSysmon:y:b ignoreSecurity:e:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "stack-computers": "help:h:b help-syntax:-:b version:-:b sourceComputers:c:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "stack-dns": "help:h:b help-syntax:-:b version:-:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "stack-ip-addresses": "help:h:b help-syntax:-:b version:-:b targetIpAddresses:a:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "stack-logons": "help:h:b help-syntax:-:b version:-:b localSrcIpAddresses:l:b failedLogons:f:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "stack-processes": "help:h:b help-syntax:-:b version:-:b ignoreSysmon:y:b ignoreSecurity:e:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "stack-services": "help:h:b help-syntax:-:b version:-:b ignoreSystem:y:b ignoreSecurity:e:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "stack-tasks": "help:h:b help-syntax:-:b version:-:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "stack-users": "help:h:b help-syntax:-:b version:-:b level:l:v sourceUsers:s:b filterComputerAccounts:c:b filterSystemAccounts:f:b skipProgressBar:-:b output:o:p quiet:q:b timeline:t:p",
    "sysmon-process-tree": "help:h:b help-syntax:-:b version:-:b processGuid:p:v output:o:p quiet:q:b timeline:t:p",
    "timeline-logon": "help:h:b help-syntax:-:b version:-:b calculateElapsedTime:c:b outputLogoffEvents:l:b outputAdminLogonEvents:a:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "timeline-partition-diagnostic": "help:h:b help-syntax:-:b version:-:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "timeline-suspicious-processes": "help:h:b help-syntax:-:b version:-:b level:l:v skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "timeline-tasks": "help:h:b help-syntax:-:b version:-:b outputLogoffEvents:-:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "ttp-summary": "help:h:b help-syntax:-:b version:-:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "ttp-visualize": "help:h:b help-syntax:-:b version:-:b skipProgressBar:s:b output:o:p quiet:q:b timeline:t:p",
    "ttp-visualize-sigma": "help:h:b help-syntax:-:b version:-:b output:o:p quiet:q:b rulesDir:r:p",
    "vt-domain-lookup": "help:h:b help-syntax:-:b version:-:b apiKey:a:v domainList:d:p jsonOutput:j:p output:o:p rateLimit:r:v quiet:q:b",
    "vt-hash-lookup": "help:h:b help-syntax:-:b version:-:b apiKey:a:v hashList:H:p jsonOutput:j:p output:o:p rateLimit:r:v quiet:q:b",
    "vt-ip-lookup": "help:h:b help-syntax:-:b version:-:b apiKey:a:v ipList:i:p jsonOutput:j:p output:o:p rateLimit:r:v quiet:q:b"
  },
  "informational_options": [
    "help",
    "help-syntax",
    "version"
  ],
  "default_outputs": {
    "automagic": {
      "output": "case-1"
    },
    "extract-scriptblocks": {
      "output": "scriptblock-logs"
    },
    "split-csv-timeline": {
      "output": "output"
    },
    "split-json-timeline": {
      "output": "output"
    },
    "ttp-visualize": {
      "output": "mitre-ttp-heatmap.json"
    },
    "ttp-visualize-sigma": {
      "output": "mitre-attack-navigator.json"
    }
  },
  "conditional_defaults": {
    "html-report": {
      "option": "dboutput",
      "default": "html-report.duckdb",
      "boolean_option": "sqlite",
      "alternate": "html-report.sqlite"
    },
    "html-server": {
      "option": "dboutput",
      "default": "html-report.duckdb",
      "boolean_option": "sqlite",
      "alternate": "html-report.sqlite"
    }
  },
  "argument_style": "cligen"
}'
)
install_module_blueteam() {
    install_apt_batch "Blue Team - Packages" "${BLUETEAM_PACKAGES[@]}"
    install_pipx_batch "Blue Team - Python" "${BLUETEAM_PIPX[@]}"
    install_go_batch "Blue Team - Go" "${BLUETEAM_GO[@]}"
    install_cargo_batch "Blue Team - Cargo" "${BLUETEAM_CARGO[@]}"

    # yara-x-cli installs its binary as 'yr' — symlink to PATH
    local _yr_bin; _yr_bin="$(_builder_home)/.cargo/bin/yr"
    if [[ -f "$_yr_bin" ]] && [[ ! -f "$PIPX_BIN_DIR/yr" ]]; then
        ln -sf "$_yr_bin" "$PIPX_BIN_DIR/yr" 2>/dev/null || true
    fi

    install_git_batch "Blue Team - Git" "${BLUETEAM_GIT[@]}"

    build_module_from_source BLUETEAM

    # Binary releases (Velociraptor, Laurel, FLOSS, Capa, Loki, Hayabusa, Takajo)
    install_binary_releases "${BINARY_RELEASES_BLUETEAM[@]}"

    # Docker: IR platforms (only if enabled)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        log_info "Installing Blue Team Docker platforms..."
        docker_pull "strangebee/thehive:latest" "TheHive" || true
        docker_pull "thehiveproject/cortex:latest" "Cortex" || true
        docker_pull "zeek/zeek:latest" "Zeek" || true
        docker_pull "wagga40/zircolite:latest" "Zircolite" || true
    fi
}
