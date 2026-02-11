#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Networking
# Port scanning, packet capture, tunneling, pivoting, MITM, protocol analysis
# =============================================================================

NET_PACKAGES=(
    nmap masscan netdiscover tcpdump hping3 arp-scan
    iftop iptraf-ng net-tools whois dnsutils traceroute
    netcat-openbsd socat p0f ncrack sslscan nbtscan
    onesixtyone snmp smbclient iodine redsocks stunnel4 zmap
    ettercap-graphical mitmproxy dsniff
    wireshark-common tshark sslsplit
    tor proxychains4 macchanger
    snort yersinia
)

NET_PIPX=(sshuttle)

NET_GO=(
    "github.com/jpillora/chisel@latest"
)

NET_GIT=(
    "bettercap=https://github.com/bettercap/bettercap.git"
    "dnscat2=https://github.com/iagox86/dnscat2.git"
)

NET_GO_BINS=(chisel)
NET_GIT_NAMES=(bettercap dnscat2)

install_module_networking() {
    install_apt_batch "Networking - Packages" "${NET_PACKAGES[@]}"
    install_pipx_batch "Networking - Python" "${NET_PIPX[@]}"
    install_go_batch "Networking - Go" "${NET_GO[@]}"
    install_git_batch "Networking - Git" "${NET_GIT[@]}"

    # Binary releases
    download_github_release "nicocha30/ligolo-ng" "ligolo-proxy" "linux_amd64" || true
    download_github_release "nicocha30/ligolo-ng" "ligolo-agent" "agent.*linux_amd64" || true

    # RustScan (Rust-based port scanner)
    install_cargo_batch "Networking - Rust" rustscan || true

    # Wireshark non-interactive config (Debian)
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        echo "wireshark-common wireshark-common/install-setuid boolean false" | sudo debconf-set-selections 2>/dev/null || true
    fi
}
