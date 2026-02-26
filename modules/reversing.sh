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
RE_BUILD_NAMES=(ELFkickers rappel xrop)

install_module_reversing() {
    install_apt_batch "Reversing - Packages" "${RE_PACKAGES[@]}"
    install_pipx_batch "Reversing - Python" "${RE_PIPX[@]}"
    install_git_batch "Reversing - Git" "${RE_GIT[@]}"

    # Build from source
    log_info "Building RE tools from source..."
    build_from_source "ELFkickers" "https://github.com/BR903/ELFkickers.git" "make" || true
    if [[ "$IS_ARM" == "true" ]]; then
        log_warn "Skipping x86-only build-from-source tools on ARM: rappel, xrop"
    else
        build_from_source "rappel" "https://github.com/yrp604/rappel.git" "make" || true
        build_from_source "xrop" "https://github.com/acama/xrop.git" "git submodule update --init --recursive && make" || true
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
