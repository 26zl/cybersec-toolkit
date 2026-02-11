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
    "MITMf=https://github.com/byt3bl33d3r/MITMf.git"
    "evilgrade=https://github.com/infobyte/evilgrade.git"
    "SigPloit=https://github.com/SigPloiter/SigPloit.git"
    "dnschef=https://github.com/iphelix/dnschef.git"
)

NET_GO_BINS=(chisel)
NET_GIT_NAMES=(bettercap dnscat2 nipe PRET pwnat MITMf evilgrade SigPloit dnschef)

install_module_networking() {
    install_apt_batch "Networking - Packages" "${NET_PACKAGES[@]}"
    install_pipx_batch "Networking - Python" "${NET_PIPX[@]}"
    install_go_batch "Networking - Go" "${NET_GO[@]}"
    install_git_batch "Networking - Git" "${NET_GIT[@]}"

    # Binary releases
    download_github_release "nicocha30/ligolo-ng" "ligolo-proxy" "linux_amd64" || true
    download_github_release "nicocha30/ligolo-ng" "ligolo-agent" "agent.*linux_amd64" || true
    download_github_release "fatedier/frp" "frp" "linux_amd64\\.tar\\.gz" || true

    # RustScan (Rust-based port scanner)
    install_cargo_batch "Networking - Rust" rustscan || true

    # Wireshark non-interactive config (Debian)
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        echo "wireshark-common wireshark-common/install-setuid boolean false" | sudo debconf-set-selections 2>/dev/null || true
    fi
}
