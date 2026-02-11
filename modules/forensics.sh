#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Forensics
# Disk forensics, memory forensics, file carving, incident response
# =============================================================================

FORENSICS_PACKAGES=(
    autopsy sleuthkit foremost scalpel
    dc3dd dcfldd testdisk extundelete
    bulk-extractor libimage-exiftool-perl
    forensics-extra
)

FORENSICS_PIPX=(volatility3 oletools pdf-parser plaso)

FORENSICS_GO=()

FORENSICS_GIT=(
    "RegRipper=https://github.com/keydet89/RegRipper3.0.git"
    "Depix=https://github.com/spipm/Depix.git"
)

FORENSICS_GIT_NAMES=(RegRipper Depix)

install_module_forensics() {
    install_apt_batch "Forensics - Packages" "${FORENSICS_PACKAGES[@]}"
    install_pipx_batch "Forensics - Python" "${FORENSICS_PIPX[@]}"
    install_git_batch "Forensics - Git" "${FORENSICS_GIT[@]}"

    # Binary releases
    download_github_release "WithSecureLabs/chainsaw" "chainsaw" "x86_64.*linux" || true
}
