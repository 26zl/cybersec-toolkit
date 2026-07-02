#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Pwn / Exploit Dev
# Binary exploitation, shellcode, fuzzing, exploit frameworks, payload generation

PWN_PACKAGES=(
    patchelf spike
)

PWN_PIPX=(pwntools ROPgadget ropper boofuzz pwncat-cs scapy)

PWN_GO=(
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
)

PWN_GEMS=(one_gadget seccomp-tools)

PWN_GIT=(
    "exploitdb=https://gitlab.com/exploit-database/exploitdb.git"
    "RouterSploit=https://github.com/threat9/routersploit.git"
    "libc-database=https://github.com/niklasb/libc-database.git"
    "Penelope=https://github.com/brightio/penelope.git"
    "ShellNoob=https://github.com/reyammer/shellnoob.git"
    "unicorn=https://github.com/trustedsec/unicorn.git"
    # Windows/BOF source; not a host binary
    "nanodump=https://github.com/fortra/nanodump.git"
    "eviltree=https://github.com/t3l3machus/eviltree.git"
    "Hoaxshell=https://github.com/t3l3machus/hoaxshell.git"
    "DNSExfiltrator=https://github.com/Arno0x/DNSExfiltrator.git"
    "Egress-Assess=https://github.com/FortyNorthSecurity/Egress-Assess.git"
    "Villain=https://github.com/t3l3machus/Villain.git"
)

PWN_CARGO=(pwninit)
PWN_GO_BINS=(interactsh-client)
PWN_GIT_NAMES=(exploitdb RouterSploit libc-database Penelope ShellNoob unicorn nanodump eviltree Hoaxshell DNSExfiltrator Egress-Assess Villain)
PWN_BUILD_NAMES=(AFLplusplus honggfuzz radamsa Donut ScareCrow Freeze QueenSono Ivy)
# Build metadata shared by install and update.
# AFL++ source-only excludes optional QEMU, FRIDA, and unicorn dependencies.
declare -A PWN_BUILD_URLS=(
    [AFLplusplus]="https://github.com/AFLplusplus/AFLplusplus.git"
    [honggfuzz]="https://github.com/google/honggfuzz.git"
    [radamsa]="https://gitlab.com/akihe/radamsa.git"
    [Donut]="https://github.com/TheWover/donut.git"
    [ScareCrow]="https://github.com/optiv/ScareCrow.git"
    [Freeze]="https://github.com/Tylous/Freeze.git"
    [QueenSono]="https://github.com/ariary/QueenSono.git"
    [Ivy]="https://github.com/optiv/Ivy.git"
)
declare -A PWN_BUILD_CMDS=(
    [AFLplusplus]="make source-only"
    [honggfuzz]="make"
    [radamsa]="make"
    [Donut]="make"
    [ScareCrow]="go build ScareCrow.go"
    [Freeze]="go build Freeze.go"
    [QueenSono]="go build -o QueenSono ./cmd/client"
    [Ivy]="go build Ivy.go"
)

install_module_pwn() {
    install_apt_batch "Pwn - Packages" "${PWN_PACKAGES[@]}"
    install_pipx_batch "Pwn - Python" "${PWN_PIPX[@]}"
    install_go_batch "Pwn - Go" "${PWN_GO[@]}"
    install_gem_batch "Pwn - Ruby" "${PWN_GEMS[@]}"
    install_git_batch "Pwn - Git" "${PWN_GIT[@]}"

    # Rust tools
    install_cargo_batch "Pwn - Rust" "${PWN_CARGO[@]}" || true

    # Build from source (url + command from PWN_BUILD_URLS / PWN_BUILD_CMDS)
    log_info "Building pwn tools from source..."
    build_module_from_source PWN

    # Searchsploit symlink
    install_searchsploit_symlink

    # Metasploit (Linux only — Rapid7 installer requires root/apt)
    if [[ "${SKIP_SOURCE:-false}" != "true" ]] && [[ "$PKG_MANAGER" != "pkg" ]]; then
        install_metasploit
    fi
}
