#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Recon / OSINT
# Subdomain enumeration, intelligence gathering, search engines, OSINT
# =============================================================================

RECON_PACKAGES=(dnsenum dmitry)

RECON_PIPX=(
    dnstwist fierce holehe h8mail social-analyzer maigret ghunt shodan
    socialscan metagoofil maltego-trx altdns dnsrecon raccoon-recon
    theHarvester sherlock-project recon-ng
)

RECON_GO=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v4/...@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/tomnomnom/httprobe@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/meg@latest"
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "github.com/gwen001/github-subdomains@latest"
    "github.com/hakluke/hakcheckurl@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/sundowndev/phoneinfoga/v2@latest"
)

RECON_GIT=(
    "reconftw=https://github.com/six2dez/reconftw.git"
    "nmapAutomator=https://github.com/21y4d/nmapAutomator.git"
    "axiom=https://github.com/pry0cc/axiom.git"
    "Sn1per=https://github.com/1N3/Sn1per.git"
)

# Binary names for verify/remove
RECON_GO_BINS=(subfinder amass assetfinder waybackurls gau hakrawler httprobe unfurl meg puredns shuffledns github-subdomains hakcheckurl chaos uncover asnmap mapcidr alterx dnsx gowitness naabu httpx phoneinfoga)
RECON_GIT_NAMES=(reconftw nmapAutomator massdns axiom Sn1per)

install_module_recon() {
    install_apt_batch "Recon / OSINT - Packages" "${RECON_PACKAGES[@]}"
    install_pipx_batch "Recon / OSINT - Python" "${RECON_PIPX[@]}"
    install_go_batch "Recon / OSINT - Go" "${RECON_GO[@]}"
    install_git_batch "Recon / OSINT - Git" "${RECON_GIT[@]}"

    # Build from source: massdns
    log_info "Building massdns from source..."
    build_from_source "massdns" "https://github.com/blechschmidt/massdns.git" "make" || true

    # Binary releases
    download_github_release "Findomain/Findomain" "findomain" "linux" || true
}
