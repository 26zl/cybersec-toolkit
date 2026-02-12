#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Crypto
# Cryptography analysis, cipher cracking, hash attacks

CRYPTO_PACKAGES=()

CRYPTO_PIPX=(codext xortool factordb-python z3-solver)

CRYPTO_GIT=(
    "RsaCtfTool=https://github.com/RsaCtfTool/RsaCtfTool.git"
    "rsatool=https://github.com/ius/rsatool.git"
    "featherduster=https://github.com/nccgroup/featherduster.git"
    "cribdrag=https://github.com/SpiderLabs/cribdrag.git"
    "foresight=https://github.com/ALSchwalm/foresight.git"
    "nonce-disrespect=https://github.com/nonce-disrespect/nonce-disrespect.git"
)

CRYPTO_GIT_NAMES=(RsaCtfTool rsatool featherduster cribdrag foresight nonce-disrespect)
CRYPTO_BUILD_NAMES=(hash_extender PkCrack yafu fastcoll msieve pemcrack)

install_module_crypto() {
    [[ ${#CRYPTO_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Crypto - Packages" "${CRYPTO_PACKAGES[@]}"
    install_pipx_batch "Crypto - Python" "${CRYPTO_PIPX[@]}"
    install_git_batch "Crypto - Git" "${CRYPTO_GIT[@]}"

    # Build from source
    log_info "Building crypto tools from source..."
    build_from_source "hash_extender" "https://github.com/iagox86/hash_extender.git" "make" || true
    build_from_source "PkCrack" "https://github.com/keyunluo/pkcrack.git" "cmake . && make" || true
    build_from_source "yafu" "https://github.com/bbuhrow/yafu.git" "make" || true
    build_from_source "fastcoll" "https://github.com/upbit/clone-fastcoll.git" "make" || true
    build_from_source "msieve" "https://github.com/radii/msieve.git" "make all" || true
    build_from_source "pemcrack" "https://github.com/robertdavidgraham/pemcrack.git" "make" || true
}
