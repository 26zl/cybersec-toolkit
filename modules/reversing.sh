#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Reverse Engineering
# Disassembly, decompilation, debugging, binary analysis, emulation
# =============================================================================

RE_PACKAGES=(
    radare2 ghidra checksec rizin gdb binwalk binutils
    qemu-user-static qemu-system-x86 valgrind rr
    ltrace strace hexedit upx-ucl
    nasm edb-debugger
)

RE_PIPX=(angr frida-tools uncompyle6)

RE_GO=()

RE_GIT=(
    "pwndbg=https://github.com/pwndbg/pwndbg.git"
    "GEF=https://github.com/hugsy/gef.git"
    "peda=https://github.com/longld/peda.git"
    "decomp2dbg=https://github.com/mahaloz/decomp2dbg.git"
    "Qiling=https://github.com/qilingframework/qiling.git"
    "Krakatau=https://github.com/Storyyeller/Krakatau.git"
    "pyinstxtractor=https://github.com/extremecoders-re/pyinstxtractor.git"
)

RE_GIT_NAMES=(pwndbg GEF peda decomp2dbg Qiling Krakatau pyinstxtractor ELFkickers rappel xrop)

install_module_reversing() {
    install_apt_batch "Reversing - Packages" "${RE_PACKAGES[@]}"
    install_pipx_batch "Reversing - Python" "${RE_PIPX[@]}"
    install_git_batch "Reversing - Git" "${RE_GIT[@]}"

    # Build from source
    log_info "Building RE tools from source..."
    build_from_source "ELFkickers" "https://github.com/BR903/ELFkickers.git" "make" || true
    build_from_source "rappel" "https://github.com/yrp604/rappel.git" "make" || true
    build_from_source "xrop" "https://github.com/acama/xrop.git" "make" || true

    # Binary releases
    download_github_release "0vercl0k/rp" "rp-lin" "rp-lin" || true
    download_github_release "java-decompiler/jd-gui" "jd-gui" "jd-gui.*\\.jar" "/opt/cybersec-jars" || true

    # Setup pwndbg (if cloned)
    if [[ -d "$GITHUB_TOOL_DIR/pwndbg" && -f "$GITHUB_TOOL_DIR/pwndbg/setup.sh" ]]; then
        log_info "Setting up pwndbg..."
        (cd "$GITHUB_TOOL_DIR/pwndbg" && ./setup.sh >> "$LOG_FILE" 2>&1) || true
    fi
}
