#!/usr/bin/env bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Wireless Security
# WiFi, Bluetooth, SDR

WIRELESS_PACKAGES=(
    aircrack-ng reaver kismet pixiewps bully
    iw wireless-tools rfkill
    horst bluez spooftooph
    mdk4 hcxtools cowpatty crackle asleap
    fern-wifi-cracker
    hackrf hcxdumptool mfcuk mfoc rtl-433
    libnfc-dev avrdude
)

# Heavy packages (skipped with --skip-heavy)
WIRELESS_HEAVY_PACKAGES=(gnuradio gqrx-sdr)

WIRELESS_PIPX=(sipvicious btlejack)

WIRELESS_GIT=(
    "wifite2=https://github.com/derv82/wifite2.git"
    "airgeddon=https://github.com/v1s1t0r1sh3r3/airgeddon.git"
    "hostapd-mana=https://github.com/sensepost/hostapd-mana.git"
    "PSKracker=https://github.com/soxrok2212/PSKracker.git"
    "proxmark3=https://github.com/RfidResearchGroup/proxmark3.git"
    "mousejack=https://github.com/BastilleResearch/mousejack.git"
    "mfdread=https://github.com/zhovner/mfdread.git"
    "libnfc-crypto1-crack=https://github.com/SnoopyTools/acr122uNFC.git"
)

# Rogue-AP credential-phishing frameworks — gated behind INCLUDE_C2 (redteam/full
# profiles or --include-c2), consistent with the gating in modules/misc.sh.
WIRELESS_C2_GIT=(
    "fluxion=https://github.com/FluxionNetwork/fluxion.git"
    "wifiphisher=https://github.com/wifiphisher/wifiphisher.git"
    "eaphammer=https://github.com/s0lst1c3/eaphammer.git"
    "wifipumpkin3=https://github.com/P0cL4bs/wifipumpkin3.git"
)

WIRELESS_GIT_NAMES=(wifite2 airgeddon hostapd-mana PSKracker proxmark3 mousejack mfdread libnfc-crypto1-crack)
WIRELESS_C2_GIT_NAMES=(fluxion wifiphisher eaphammer wifipumpkin3)

install_module_wireless() {
    install_apt_batch "Wireless - Packages" "${WIRELESS_PACKAGES[@]}"

    # Heavy packages (optional)
    if [[ "${SKIP_HEAVY:-false}" != "true" ]]; then
        install_apt_batch "Wireless - Heavy" "${WIRELESS_HEAVY_PACKAGES[@]}"
    else
        log_warn "Skipping heavy wireless packages (gnuradio, gqrx-sdr)"
    fi

    install_pipx_batch "Wireless - Python" "${WIRELESS_PIPX[@]}"
    install_git_batch "Wireless - Git" "${WIRELESS_GIT[@]}"

    # Rogue-AP phishing frameworks — only with INCLUDE_C2 (see modules/misc.sh).
    if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
        log_info "Installing wireless phishing frameworks (INCLUDE_C2 enabled)..."
        install_git_batch "Wireless - Phishing (Git)" "${WIRELESS_C2_GIT[@]}"
    else
        log_info "Skipping wireless phishing frameworks (INCLUDE_C2 disabled — use --include-c2 or the redteam/full profile)"
    fi

    # Binary releases (AngryOxide — skipped on Termux)
    install_binary_releases "${BINARY_RELEASES_WIRELESS[@]}"
}
