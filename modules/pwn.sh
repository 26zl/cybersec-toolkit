#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Pwn / Exploit Dev
# Binary exploitation, shellcode, fuzzing, exploit frameworks, payload generation
# =============================================================================

PWN_PACKAGES=(patchelf cmake spike)

PWN_PIPX=(pwntools ROPgadget ropper boofuzz pwncat-cs scapy)

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
    "v0lt=https://github.com/P1kachu/v0lt.git"
    "Freeze=https://github.com/Tylous/Freeze.git"
    "nanodump=https://github.com/fortra/nanodump.git"
    "eviltree=https://github.com/t3l3machus/eviltree.git"
    "Hoaxshell=https://github.com/t3l3machus/hoaxshell.git"
    "Chimera=https://github.com/tokyoneon/Chimera.git"
    "demiguise=https://github.com/nccgroup/demiguise.git"
    "ShellPop=https://github.com/0x00-0x00/ShellPop.git"
    "TrevorC2=https://github.com/trustedsec/trevorc2.git"
    "DET=https://github.com/PaulSec/DET.git"
    "QueenSono=https://github.com/ariary/QueenSono.git"
    "ISF=https://github.com/dark-lbp/isf.git"
    "DNSExfiltrator=https://github.com/Arno0x/DNSExfiltrator.git"
    "Egress-Assess=https://github.com/FortyNorthSecurity/Egress-Assess.git"
    "Ivy=https://github.com/optiv/Ivy.git"
    "macro_pack=https://github.com/sevagas/macro_pack.git"
    "EvilClippy=https://github.com/outflanknl/EvilClippy.git"
    "inceptor=https://github.com/klezVirus/inceptor.git"
    "villoc=https://github.com/wapiflapi/villoc.git"
)

PWN_GO_BINS=(interactsh-client)
PWN_GIT_NAMES=(exploitdb Veil RouterSploit libc-database Penelope ShellNoob unicorn Donut ScareCrow vulscan v0lt Freeze nanodump eviltree Hoaxshell Chimera demiguise ShellPop TrevorC2 DET QueenSono ISF DNSExfiltrator Egress-Assess Ivy macro_pack EvilClippy inceptor villoc preeny AFLplusplus honggfuzz radamsa)

install_module_pwn() {
    install_apt_batch "Pwn - Packages" "${PWN_PACKAGES[@]}"
    install_pipx_batch "Pwn - Python" "${PWN_PIPX[@]}"
    install_go_batch "Pwn - Go" "${PWN_GO[@]}"
    install_gem_batch "Pwn - Ruby" "${PWN_GEMS[@]}"
    install_git_batch "Pwn - Git" "${PWN_GIT[@]}"

    # Rust tools
    install_cargo_batch "Pwn - Rust" pwninit || true

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
