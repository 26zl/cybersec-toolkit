#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Wireless Security
# WiFi, Bluetooth, SDR
# =============================================================================

WIRELESS_PACKAGES=(
    aircrack-ng reaver kismet pixiewps bully
    iw wireless-tools rfkill
    horst bluez spooftooph gnuradio gqrx-sdr
    mdk4 hcxtools cowpatty crackle asleap
    fern-wifi-cracker
    hackrf hcxdumptool mfcuk mfoc rtl-433
    libnfc-dev avrdude
)

WIRELESS_PIPX=(jackit sipvicious)

WIRELESS_GO=()

WIRELESS_GIT=(
    "wifite2=https://github.com/derv82/wifite2.git"
    "fluxion=https://github.com/FluxionNetwork/fluxion.git"
    "airgeddon=https://github.com/v1s1t0r1sh3r3/airgeddon.git"
    "hostapd-mana=https://github.com/sensepost/hostapd-mana.git"
    "wifiphisher=https://github.com/wifiphisher/wifiphisher.git"
    "PSKracker=https://github.com/soxrok2212/PSKracker.git"
    "pwnagotchi=https://github.com/evilsocket/pwnagotchi.git"
    "eaphammer=https://github.com/s0lst1c3/eaphammer.git"
    "wifipumpkin3=https://github.com/P0cL4bs/wifipumpkin3.git"
    "proxmark3=https://github.com/RfidResearchGroup/proxmark3.git"
    "mousejack=https://github.com/BastilleResearch/mousejack.git"
    "mfdread=https://github.com/zhovner/mfdread.git"
    "libnfc-crypto1-crack=https://github.com/droidnewbie2/acr122uNFC.git"
)

WIRELESS_GIT_NAMES=(wifite2 fluxion airgeddon hostapd-mana wifiphisher PSKracker pwnagotchi eaphammer wifipumpkin3 proxmark3 mousejack mfdread libnfc-crypto1-crack)

install_module_wireless() {
    install_apt_batch "Wireless - Packages" "${WIRELESS_PACKAGES[@]}"
    install_pipx_batch "Wireless - Python" "${WIRELESS_PIPX[@]}"
    install_git_batch "Wireless - Git" "${WIRELESS_GIT[@]}"
}
