#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Crypto
# Cryptography analysis, cipher cracking, hash attacks

CRYPTO_PACKAGES=()

CRYPTO_PIPX=(codext xortool factordb-python z3-solver lascar)

CRYPTO_GIT=(
    "RsaCtfTool=https://github.com/RsaCtfTool/RsaCtfTool.git"
    "rsatool=https://github.com/ius/rsatool.git"
    "cribdrag=https://github.com/SpiderLabs/cribdrag.git"
)

CRYPTO_GIT_NAMES=(RsaCtfTool rsatool cribdrag)
CRYPTO_BUILD_NAMES=(hash_extender PkCrack yafu fastcoll pemcrack)
# Source of truth for build-from-source url + command (used by install + update).
# yafu/pemcrack patches are idempotent (grep-guarded) so re-running on update does
# not double-apply: yafu strips hardcoded gmp/ecm/CUDA paths, adds -lpthread (modern
# GCC needs it for pthread_create) and -Wno-implicit-function-declaration (GCC 14+
# hard-errors); pemcrack.c is missing #include <ctype.h>.
declare -A CRYPTO_BUILD_URLS=(
    [hash_extender]="https://github.com/iagox86/hash_extender.git"
    [PkCrack]="https://github.com/keyunluo/pkcrack.git"
    [yafu]="https://github.com/bbuhrow/yafu.git"
    [fastcoll]="https://github.com/upbit/clone-fastcoll.git"
    [pemcrack]="https://github.com/robertdavidgraham/pemcrack.git"
)
declare -A CRYPTO_BUILD_CMDS=(
    [hash_extender]="make"
    [PkCrack]="cmake . && make"
    [yafu]="sed -i 's|-I\.\./gmp-install/[^ ]*||g; s|-L\.\./gmp-install/[^ ]*||g; s|-I\.\./ecm-install/[^ ]*||g; s|-L\.\./ecm-install/[^ ]*||g; s|-lcuda||g; s|-lcudart||g; s|-lrt||g; s|-Werror||g' Makefile.gcc && { grep -q -- '-lpthread' Makefile.gcc || sed -i '/^LIBS/s/\$/ -lpthread/' Makefile.gcc; } && { grep -q 'Wno-implicit-function-declaration' Makefile.gcc || sed -i '/^CFLAGS/s/\$/ -Wno-implicit-function-declaration/' Makefile.gcc; } && make -f Makefile.gcc yafu NFS=1 USE_CUDA=0"
    [fastcoll]="make"
    [pemcrack]="{ grep -q 'ctype.h' pemcrack.c || sed -i '1i #include <ctype.h>' pemcrack.c; } && make"
)

install_module_crypto() {
    [[ ${#CRYPTO_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Crypto - Packages" "${CRYPTO_PACKAGES[@]}"
    install_pipx_batch "Crypto - Python" "${CRYPTO_PIPX[@]}"
    install_git_batch "Crypto - Git" "${CRYPTO_GIT[@]}"

    # Build from source (url + command from CRYPTO_BUILD_URLS / CRYPTO_BUILD_CMDS)
    log_info "Building crypto tools from source..."
    build_module_from_source CRYPTO
}
