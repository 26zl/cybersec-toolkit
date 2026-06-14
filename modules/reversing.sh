#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Reverse Engineering
# Disassembly, decompilation, debugging, binary analysis, emulation

RE_PACKAGES=(
    radare2 ghidra checksec rizin gdb binwalk binutils
    qemu-user-static qemu-system-x86 valgrind rr
    ltrace strace hexedit upx-ucl
    nasm edb-debugger
)

RE_PIPX=(angr frida-tools uncompyle6)

RE_GIT=(
    "pwndbg=https://github.com/pwndbg/pwndbg.git"
    "GEF=https://github.com/hugsy/gef.git"
    "peda=https://github.com/longld/peda.git"
    "decomp2dbg=https://github.com/mahaloz/decomp2dbg.git"
    "Qiling=https://github.com/qilingframework/qiling.git"
    "Krakatau=https://github.com/Storyyeller/Krakatau.git"
    "pyinstxtractor=https://github.com/extremecoders-re/pyinstxtractor.git"
)

RE_GIT_NAMES=(pwndbg GEF peda decomp2dbg Qiling Krakatau pyinstxtractor)
RE_BUILD_NAMES=(ELFkickers rappel)
# Source of truth for build-from-source url + command (install + update). rappel is
# x86-only, so install gates it on !IS_ARM; update skips it on ARM (never cloned).
declare -A RE_BUILD_URLS=(
    [ELFkickers]="https://github.com/BR903/ELFkickers.git"
    [rappel]="https://github.com/yrp604/rappel.git"
)
declare -A RE_BUILD_CMDS=(
    [ELFkickers]="make"
    [rappel]="make"
)

install_module_reversing() {
    install_apt_batch "Reversing - Packages" "${RE_PACKAGES[@]}"
    install_pipx_batch "Reversing - Python" "${RE_PIPX[@]}"
    install_git_batch "Reversing - Git" "${RE_GIT[@]}"

    # Build from source (url + command from RE_BUILD_URLS / RE_BUILD_CMDS)
    log_info "Building RE tools from source..."
    build_from_source "ELFkickers" "${RE_BUILD_URLS[ELFkickers]}" "${RE_BUILD_CMDS[ELFkickers]}" || true
    if [[ "$IS_ARM" == "true" ]]; then
        log_warn "Skipping x86-only build-from-source tool on ARM: rappel"
    else
        build_from_source "rappel" "${RE_BUILD_URLS[rappel]}" "${RE_BUILD_CMDS[rappel]}" || true
    fi

    # Binary releases
    install_binary_releases "${BINARY_RELEASES_REVERSING[@]}"

    # Setup pwndbg (if cloned)
    if [[ -d "$GITHUB_TOOL_DIR/pwndbg" && -f "$GITHUB_TOOL_DIR/pwndbg/setup.sh" ]]; then
        _start_spinner "Setting up pwndbg..."
        if (cd "$GITHUB_TOOL_DIR/pwndbg" && ./setup.sh >> "$LOG_FILE" 2>&1); then
            _stop_spinner
            log_success "pwndbg setup complete"
        else
            _stop_spinner
            log_warn "pwndbg setup had errors (check log) — continuing"
        fi
    fi
}
