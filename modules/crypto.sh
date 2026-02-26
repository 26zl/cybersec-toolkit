#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Crypto
# Cryptography analysis, cipher cracking, hash attacks

CRYPTO_PACKAGES=()

CRYPTO_PIPX=(codext xortool factordb-python z3-solver)

CRYPTO_GIT=(
    "RsaCtfTool=https://github.com/RsaCtfTool/RsaCtfTool.git"
    "rsatool=https://github.com/ius/rsatool.git"
    "cribdrag=https://github.com/SpiderLabs/cribdrag.git"
)

CRYPTO_GIT_NAMES=(RsaCtfTool rsatool cribdrag)
CRYPTO_BUILD_NAMES=(hash_extender PkCrack yafu fastcoll pemcrack)

install_module_crypto() {
    [[ ${#CRYPTO_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Crypto - Packages" "${CRYPTO_PACKAGES[@]}"
    install_pipx_batch "Crypto - Python" "${CRYPTO_PIPX[@]}"
    install_git_batch "Crypto - Git" "${CRYPTO_GIT[@]}"

    # Build from source
    log_info "Building crypto tools from source..."
    build_from_source "hash_extender" "https://github.com/iagox86/hash_extender.git" "make" || true
    build_from_source "PkCrack" "https://github.com/keyunluo/pkcrack.git" "cmake . && make" || true
    # yafu: strip hardcoded gmp/ecm/CUDA paths, add -lpthread (required by
    # modern GCC — the build fails with 'implicit declaration of pthread_create'
    # without it), and suppress implicit-function-declaration errors (GCC 14+
    # treats these as hard errors by default).
    build_from_source "yafu" "https://github.com/bbuhrow/yafu.git" \
        "sed -i 's|-I\.\./gmp-install/[^ ]*||g; s|-L\.\./gmp-install/[^ ]*||g; s|-I\.\./ecm-install/[^ ]*||g; s|-L\.\./ecm-install/[^ ]*||g; s|-lcuda||g; s|-lcudart||g; s|-lrt||g; s|-Werror||g' Makefile.gcc && sed -i '/^LIBS/s/\$/ -lpthread/' Makefile.gcc && sed -i '/^CFLAGS/s/\$/ -Wno-implicit-function-declaration/' Makefile.gcc && make -f Makefile.gcc yafu NFS=1 USE_CUDA=0" || true
    build_from_source "fastcoll" "https://github.com/upbit/clone-fastcoll.git" "make" || true
    # Upstream pemcrack.c is missing #include <ctype.h> — GCC 14+ treats
    # implicit-function-declaration as a hard error, so patch before building
    build_from_source "pemcrack" "https://github.com/robertdavidgraham/pemcrack.git" \
        "sed -i '1i #include <ctype.h>' pemcrack.c && make" || true
}
