#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Forensics
# Disk forensics, memory forensics, file carving, incident response

FORENSICS_PACKAGES=(
    autopsy sleuthkit foremost scalpel
    dc3dd dcfldd testdisk extundelete
    bulk-extractor libimage-exiftool-perl
    forensics-extra samdump2 dislocker
    ssdeep unhide hashdeep recoverjpeg
    galleta pasco mac-robber vinetto
    guymager magicrescue memdump
    rifiuti2 scrounge-ntfs ext3grep ext4magic
    poppler-utils zbar-tools
    sigrok-cli pulseview gtkwave
)

FORENSICS_PIPX=(volatility3 oletools usbrip mvt hachoir unblob peepdf-3 vcdvcd)

FORENSICS_GIT=(
    "RegRipper=https://github.com/keydet89/RegRipper3.0.git"
    "Depix=https://github.com/spipm/Depix.git"
    "dvcs-ripper=https://github.com/kost/dvcs-ripper.git"
    "firefox_decrypt=https://github.com/unode/firefox_decrypt.git"
    "firmware-mod-kit=https://github.com/rampageX/firmware-mod-kit.git"
)

FORENSICS_GIT_NAMES=(RegRipper Depix dvcs-ripper firefox_decrypt firmware-mod-kit)

install_module_forensics() {
    install_apt_batch "Forensics - Packages" "${FORENSICS_PACKAGES[@]}"
    install_pipx_batch "Forensics - Python" "${FORENSICS_PIPX[@]}"
    install_git_batch "Forensics - Git" "${FORENSICS_GIT[@]}"

    # Binary releases
    install_binary_releases "${BINARY_RELEASES_FORENSICS[@]}"
}
