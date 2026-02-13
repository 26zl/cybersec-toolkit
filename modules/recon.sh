#!/bin/bash
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
    "github.com/alpkeskin/mosint/v3@latest"
    "github.com/hakluke/hakrevdns@latest"
    "github.com/s0md3v/smap/cmd/smap@latest"
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
    "linkedin2username=https://github.com/initstring/linkedin2username.git"
    "Gato=https://github.com/praetorian-inc/gato.git"
    "pwndb=https://github.com/davidtavarez/pwndb.git"
    "EyeWitness=https://github.com/FortyNorthSecurity/EyeWitness.git"
    "osmedeus=https://github.com/j3ssie/osmedeus.git"
    "recon-ng=https://github.com/lanmaster53/recon-ng.git"
    "vulscan=https://github.com/scipag/vulscan.git"
    "theHarvester=https://github.com/laramies/theHarvester.git"
)

# Binary names for verify/remove
RECON_GO_BINS=(subfinder amass waybackurls gau hakrawler httprobe unfurl meg puredns shuffledns github-subdomains hakcheckurl chaos uncover asnmap mapcidr alterx dnsx gowitness naabu httpx commit-stream metabigor subzy mosint hakrevdns smap)
RECON_GIT_NAMES=(reconftw nmapAutomator axiom Sn1per robin stringcheese blackbird GooFuzz Telepathy iKy certSniff linkedin2username Gato pwndb EyeWitness osmedeus recon-ng vulscan theHarvester)
RECON_BUILD_NAMES=(massdns)

install_module_recon() {
    install_apt_batch "Recon / OSINT - Packages" "${RECON_PACKAGES[@]}"
    install_pipx_batch "Recon / OSINT - Python" "${RECON_PIPX[@]}"
    install_go_batch "Recon / OSINT - Go" "${RECON_GO[@]}"
    install_git_batch "Recon / OSINT - Git" "${RECON_GIT[@]}"

    # theHarvester (requires uv — not pipx compatible)
    local _th_dir="$GITHUB_TOOL_DIR/theHarvester"
    if [[ -f "$_th_dir/pyproject.toml" ]]; then
        if ! command_exists uv; then
            if [[ "${SKIP_SOURCE:-false}" == "true" ]]; then
                log_warn "Skipping uv install (--skip-source) — theHarvester setup skipped"
            elif curl -LsSf https://astral.sh/uv/install.sh 2>>"$LOG_FILE" | sh >> "$LOG_FILE" 2>&1; then
                export PATH="$HOME/.local/bin:$PATH"
                log_success "uv installed"
            else
                log_error "Failed to install uv — theHarvester setup skipped"
            fi
        fi
        if command_exists uv; then
            log_info "Setting up theHarvester with uv..."
            if (cd "$_th_dir" && uv sync) >> "$LOG_FILE" 2>&1; then
                # Create wrapper script
                cat > "$PIPX_BIN_DIR/theHarvester" 2>/dev/null << THWRAP
#!/bin/bash
cd "$_th_dir" && exec uv run theHarvester "\$@"
THWRAP
                chmod +x "$PIPX_BIN_DIR/theHarvester" 2>/dev/null || true
                log_success "theHarvester installed (uv)"
                track_version "theHarvester" "git" "HEAD"
            else
                log_error "theHarvester uv sync failed"
                TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
            fi
        fi
    fi

    # Build from source: massdns
    log_info "Building massdns from source..."
    build_from_source "massdns" "https://github.com/blechschmidt/massdns.git" "make" || true

    # Binary releases
    install_binary_releases "${BINARY_RELEASES_RECON[@]}"
}
