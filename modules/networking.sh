#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Networking
# Port scanning, packet capture, tunneling, pivoting, MITM, protocol analysis

NET_PACKAGES=(
    nmap masscan netdiscover tcpdump hping3 arp-scan
    iftop iptraf-ng whois dnsutils traceroute
    netcat-openbsd socat p0f ncrack sslscan nbtscan
    onesixtyone snmp smbclient iodine redsocks stunnel4 zmap
    mitmproxy
    wireshark-common tshark sslsplit
    tor proxychains4 macchanger
    snort yersinia
    fping ngrep dns2tcp tcpflow tcpreplay
    netsniff-ng arping
)

NET_PIPX=(sshuttle smbmap)

NET_GO=(
    "github.com/jpillora/chisel@latest"
)

NET_GIT=(
    "bettercap=https://github.com/bettercap/bettercap.git"
    "dnscat2=https://github.com/iagox86/dnscat2.git"
    "nipe=https://github.com/htrgouvea/nipe.git"
    "PRET=https://github.com/RUB-NDS/PRET.git"
    "pwnat=https://github.com/samyk/pwnat.git"
    "dnschef=https://github.com/iphelix/dnschef.git"
)

NET_CARGO=(rustscan)
NET_GO_BINS=(chisel)
NET_GIT_NAMES=(bettercap dnscat2 nipe PRET pwnat dnschef)

install_module_networking() {
    install_apt_batch "Networking - Packages" "${NET_PACKAGES[@]}"
    install_pipx_batch "Networking - Python" "${NET_PIPX[@]}"
    install_go_batch "Networking - Go" "${NET_GO[@]}"
    install_git_batch "Networking - Git" "${NET_GIT[@]}"

    # Binary releases
    install_binary_releases "${BINARY_RELEASES_NETWORKING[@]}"

    # RustScan (Rust-based port scanner)
    install_cargo_batch "Networking - Rust" "${NET_CARGO[@]}" || true

    # ngrok (tunneling — snap; binary fallback in Docker)
    if [[ "${SKIP_SOURCE:-false}" != "true" ]]; then
        if ! command_exists ngrok; then
            if [[ "$IS_DOCKER" == "true" ]]; then
                log_warn "ngrok requires snap (unavailable in Docker) — install manually: https://ngrok.com/download"
            elif snap_available; then
                _start_spinner "Installing ngrok via snap..."
                if snap_install ngrok >> "$LOG_FILE" 2>&1; then
                    _stop_spinner
                    log_success "ngrok installed"
                    track_version "ngrok" "snap" "latest"
                else
                    _stop_spinner
                    log_error "ngrok snap install failed"
                    TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
                fi
            else
                log_warn "snap not available — install ngrok manually: https://ngrok.com/download"
            fi
        else
            log_success "Already installed: ngrok"
        fi
    fi

    # Wireshark non-interactive config (Debian/Ubuntu — not Termux)
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections 2>/dev/null || true
    fi
}
