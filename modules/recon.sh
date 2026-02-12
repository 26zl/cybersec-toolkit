#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Recon / OSINT
# Subdomain enumeration, intelligence gathering, search engines, OSINT

RECON_PACKAGES=(dnsenum dmitry dnsmap dnstracer dnswalk bing-ip2hosts)

RECON_PIPX=(
    dnstwist fierce holehe h8mail social-analyzer maigret ghunt shodan
    socialscan maltego-trx dnsrecon sherlock-project
    bbot onionsearch crosslinked toutatis
    ssh-audit parsero
    emailharvester maryam osrframework
    censys ignorant instaloader
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
    "github.com/x1sec/commit-stream@latest"
    "github.com/j3ssie/metabigor@latest"
    "github.com/sundowndev/phoneinfoga/v2@latest"
    "github.com/PentestPad/subzy@latest"
)

RECON_GIT=(
    "reconftw=https://github.com/six2dez/reconftw.git"
    "nmapAutomator=https://github.com/21y4d/nmapAutomator.git"
    "axiom=https://github.com/pry0cc/axiom.git"
    "Sn1per=https://github.com/1N3/Sn1per.git"
    "robin=https://github.com/apurvsinghgautam/robin.git"
    "stringcheese=https://github.com/MathisHammel/stringcheese.git"
    "blackbird=https://github.com/p1ngul1n0/blackbird.git"
    "GooFuzz=https://github.com/m3n0sd0n4ld/GooFuzz.git"
    "Telepathy=https://github.com/jordanwildon/Telepathy.git"
    "iKy=https://github.com/kennbroorg/iKy.git"
    "certSniff=https://github.com/A-poc/certSniff.git"
    "AWSBucketDump=https://github.com/jordanpotti/AWSBucketDump.git"
    "linkedin2username=https://github.com/initstring/linkedin2username.git"
    "LinkedInt=https://github.com/vysecurity/LinkedInt.git"
    "AttackSurfaceMapper=https://github.com/superhedgy/AttackSurfaceMapper.git"
    "WitnessMe=https://github.com/byt3bl33d3r/WitnessMe.git"
    "Gato=https://github.com/praetorian-inc/gato.git"
    "carbon14=https://github.com/Lazza/carbon14.git"
    "GeoPincer=https://github.com/tloja/GeoPincer.git"
    "pwndb=https://github.com/davidtavarez/pwndb.git"
    "SimplyEmail=https://github.com/SimplySecurity/SimplyEmail.git"
    "Yalis=https://github.com/EatonChips/yalis.git"
    "EyeWitness=https://github.com/FortyNorthSecurity/EyeWitness.git"
    "osmedeus=https://github.com/j3ssie/osmedeus.git"
    "recon-ng=https://github.com/lanmaster53/recon-ng.git"
)

# Binary names for verify/remove
RECON_GO_BINS=(subfinder amass assetfinder waybackurls gau hakrawler httprobe unfurl meg puredns shuffledns github-subdomains hakcheckurl chaos uncover asnmap mapcidr alterx dnsx gowitness naabu httpx commit-stream metabigor phoneinfoga subzy)
RECON_GIT_NAMES=(reconftw nmapAutomator axiom Sn1per robin stringcheese blackbird GooFuzz Telepathy iKy certSniff AWSBucketDump linkedin2username LinkedInt AttackSurfaceMapper WitnessMe Gato carbon14 GeoPincer pwndb SimplyEmail Yalis EyeWitness osmedeus recon-ng)
RECON_BUILD_NAMES=(massdns)

install_module_recon() {
    install_apt_batch "Recon / OSINT - Packages" "${RECON_PACKAGES[@]}"
    install_pipx_batch "Recon / OSINT - Python" "${RECON_PIPX[@]}"
    install_go_batch "Recon / OSINT - Go" "${RECON_GO[@]}"
    install_git_batch "Recon / OSINT - Git" "${RECON_GIT[@]}"

    # Build from source: massdns
    log_info "Building massdns from source..."
    build_from_source "massdns" "https://github.com/blechschmidt/massdns.git" "make" || true

    # Binary releases
    install_binary_releases "${BINARY_RELEASES_RECON[@]}"
}
