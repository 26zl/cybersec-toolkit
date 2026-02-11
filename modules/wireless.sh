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
)

WIRELESS_GO=()

WIRELESS_GIT=(
    "wifite2=https://github.com/derv82/wifite2.git"
    "fluxion=https://github.com/FluxionNetwork/fluxion.git"
    "airgeddon=https://github.com/v1s1t0r1sh3r3/airgeddon.git"
    "hostapd-mana=https://github.com/sensepost/hostapd-mana.git"
)

WIRELESS_GIT_NAMES=(wifite2 fluxion airgeddon hostapd-mana)

install_module_wireless() {
    install_apt_batch "Wireless - Packages" "${WIRELESS_PACKAGES[@]}"
    install_git_batch "Wireless - Git" "${WIRELESS_GIT[@]}"
}
