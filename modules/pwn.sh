#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Pwn / Exploit Dev
# Binary exploitation, shellcode, fuzzing, exploit frameworks, payload generation
# =============================================================================

PWN_PACKAGES=(exploitdb patchelf cmake)

PWN_PIPX=(
    pwntools ROPgadget ropper boofuzz pwncat-cs scapy manticore
)

PWN_GO=(
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
)

PWN_GEMS=(one_gadget seccomp-tools)

PWN_GIT=(
    "exploitdb=https://gitlab.com/exploit-database/exploitdb.git"
    "Veil=https://github.com/Veil-Framework/Veil.git"
    "RouterSploit=https://github.com/threat9/routersploit.git"
    "libc-database=https://github.com/niklasb/libc-database.git"
    "Penelope=https://github.com/brightio/penelope.git"
    "ShellNoob=https://github.com/reyammer/shellnoob.git"
    "unicorn=https://github.com/trustedsec/unicorn.git"
    "Donut=https://github.com/TheWover/donut.git"
    "ScareCrow=https://github.com/optiv/ScareCrow.git"
    "vulscan=https://github.com/scipag/vulscan.git"
)

PWN_GO_BINS=(interactsh-client)
PWN_GIT_NAMES=(exploitdb Veil RouterSploit libc-database Penelope ShellNoob unicorn Donut ScareCrow vulscan preeny AFLplusplus honggfuzz radamsa)

install_module_pwn() {
    install_apt_batch "Pwn - Packages" "${PWN_PACKAGES[@]}"
    install_pipx_batch "Pwn - Python" "${PWN_PIPX[@]}"
    install_go_batch "Pwn - Go" "${PWN_GO[@]}"
    install_gem_batch "Pwn - Ruby" "${PWN_GEMS[@]}"
    install_git_batch "Pwn - Git" "${PWN_GIT[@]}"

    # Build from source
    log_info "Building pwn tools from source..."
    build_from_source "preeny" "https://github.com/zardus/preeny.git" "make" || true
    build_from_source "AFLplusplus" "https://github.com/AFLplusplus/AFLplusplus.git" "make distrib" || true
    build_from_source "honggfuzz" "https://github.com/google/honggfuzz.git" "make" || true
    build_from_source "radamsa" "https://github.com/aoh/radamsa.git" "make" || true

    # Searchsploit symlink
    install_searchsploit_symlink

    # Metasploit
    install_metasploit
}
