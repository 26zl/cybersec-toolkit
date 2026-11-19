#!/usr/bin/env bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Recon / OSINT
# Subdomain enumeration, intelligence gathering, search engines, OSINT

RECON_PACKAGES=(dnsenum)

RECON_PIPX=(
    dnstwist holehe h8mail social-analyzer maigret ghunt shodan
    socialscan maltego-trx dnsrecon sherlock-project
    bbot onionsearch crosslinked toutatis
    ssh-audit parsero
    emailharvester maryam osrframework
    censys ignorant instaloader
    sublist3r waymore dnsgen knock-subdomains
)

RECON_GO=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/owasp-amass/amass/v4/...@latest"
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
    "github.com/PentestPad/subzy@latest"
    "github.com/alpkeskin/mosint/v3/cmd/mosint@latest"
    "github.com/hakluke/hakrevdns@latest"
    "github.com/s0md3v/smap/cmd/smap@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/lc/subjs@latest"
)

RECON_GIT=(
    "reconftw=https://github.com/six2dez/reconftw.git"
    "nmapAutomator=https://github.com/21y4d/nmapAutomator.git"
    "axiom=https://github.com/pry0cc/axiom.git"
    "Sn1per=https://github.com/1N3/Sn1per.git"
    "robin=https://github.com/apurvsinghgautam/robin.git"
    "stringcheese=https://github.com/MathisHammel/stringcheese.git"
    "blackbird=https://github.com/antoniaci/blackbird.git"
    "GooFuzz=https://github.com/m3n0sd0n4ld/GooFuzz.git"
    "Telepathy=https://github.com/prose-intelligence-ltd/Telepathy-Community.git"
    "iKy=https://github.com/kennbroorg/iKy.git"
    "certSniff=https://github.com/A-poc/certSniff.git"
    "linkedin2username=https://github.com/initstring/linkedin2username.git"
    "EyeWitness=https://github.com/RedSiege/EyeWitness.git"
    "osmedeus=https://github.com/j3ssie/osmedeus.git"
    "recon-ng=https://github.com/lanmaster53/recon-ng.git"
    "vulscan=https://github.com/scipag/vulscan.git"
    "theHarvester=https://github.com/laramies/theHarvester.git"
    "LinkFinder=https://github.com/GerbenJavado/LinkFinder.git"
    "SecretFinder=https://github.com/m4ll0k/SecretFinder.git"
    "FavFreak=https://github.com/devanshbatham/FavFreak.git"
    "Photon=https://github.com/s0md3v/Photon.git"
    "spiderfoot=https://github.com/smicallef/spiderfoot.git"
)

# Binary names for verify/remove
RECON_GO_BINS=(subfinder amass waybackurls gau hakrawler httprobe unfurl meg puredns shuffledns github-subdomains hakcheckurl chaos uncover asnmap mapcidr alterx dnsx gowitness naabu httpx commit-stream metabigor subzy mosint hakrevdns smap assetfinder gospider subjs)
RECON_GIT_NAMES=(reconftw nmapAutomator axiom Sn1per robin stringcheese blackbird GooFuzz Telepathy iKy certSniff linkedin2username EyeWitness osmedeus recon-ng vulscan theHarvester LinkFinder SecretFinder FavFreak Photon spiderfoot)
RECON_BUILD_NAMES=(massdns)
# Source of truth for build-from-source url + command (install + update).
# -g: verify/update/remove source modules from inside a function.
declare -gA RECON_BUILD_URLS=(
    [massdns]="https://github.com/blechschmidt/massdns.git"
)
declare -gA RECON_BUILD_CMDS=(
    [massdns]="make"
)
declare -gA RECON_BUILD_BINS=(
    [massdns]="bin/massdns|massdns"
)

install_module_recon() {
    install_apt_batch "Recon / OSINT - Packages" "${RECON_PACKAGES[@]}"
    install_pipx_batch "Recon / OSINT - Python" "${RECON_PIPX[@]}"
    install_go_batch "Recon / OSINT - Go" "${RECON_GO[@]}"
    install_git_batch "Recon / OSINT - Git" "${RECON_GIT[@]}"

    # Preserve a manually prepared SpiderFoot command when the Git batch is skipped.
    local _sf_dir="$GITHUB_TOOL_DIR/spiderfoot" _sf_py _sf_py_q _sf_sf_q
    if [[ -f "$_sf_dir/sf.py" && ! -e "$PIPX_BIN_DIR/spiderfoot" ]]; then
        _sf_py="python3"
        [[ -x "$_sf_dir/venv/bin/python" ]] && _sf_py="$_sf_dir/venv/bin/python"
        printf -v _sf_py_q '%q' "$_sf_py"
        printf -v _sf_sf_q '%q' "$_sf_dir/sf.py"
        printf '#!/bin/bash\nexec %s %s "$@"\n' "$_sf_py_q" "$_sf_sf_q" > "$PIPX_BIN_DIR/spiderfoot" 2>/dev/null \
            && chmod +x "$PIPX_BIN_DIR/spiderfoot" 2>/dev/null || true
    fi

    # theHarvester (requires uv — not pipx compatible).
    local _th_dir="$GITHUB_TOOL_DIR/theHarvester"
    if [[ -f "$_th_dir/pyproject.toml" ]]; then
        ensure_uv || true
        if command_exists uv; then
            _start_spinner "Setting up theHarvester with uv..."
            if setup_git_repo "$_th_dir" >> "$LOG_FILE" 2>&1; then
                _stop_spinner
                log_success "theHarvester installed (uv)"
                # The git batch records provenance at clone time; a clone it never saw predates the toolkit.
                _version_known "theHarvester" || _track_already_present "theHarvester" "git"
            else
                _stop_spinner
                log_error "theHarvester uv sync failed"
                TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
            fi
        fi
    fi

    # Build from source: massdns (url + command from RECON_BUILD_URLS / RECON_BUILD_CMDS)
    log_info "Building massdns from source..."
    build_module_from_source RECON

    install_binary_releases "${BINARY_RELEASES_RECON[@]}"
}
