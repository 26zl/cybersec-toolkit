#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Mobile Security
# Android/iOS application testing, APK analysis, device interaction

MOBILE_PACKAGES=(adb smali scrcpy apksigner zipalign)

MOBILE_PIPX=(androguard apkleaks objection)

MOBILE_GIT=(
    "apktool=https://github.com/iBotPeaches/Apktool.git"
)

MOBILE_GIT_NAMES=(apktool)

install_module_mobile() {
    install_apt_batch "Mobile - Packages" "${MOBILE_PACKAGES[@]}"
    install_pipx_batch "Mobile - Python" "${MOBILE_PIPX[@]}"
    install_git_batch "Mobile - Git" "${MOBILE_GIT[@]}"

    # Android RE tools (skipped on Termux — Linux/glibc binaries)
    if [[ "$PKG_MANAGER" != "pkg" ]]; then
        if ! download_github_release "skylot/jadx" "jadx" "jadx.*\\.zip" "$GITHUB_TOOL_DIR/jadx"; then
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        fi
        if ! download_github_release "pxb1988/dex2jar" "d2j-dex2jar" "dex-tools.*\\.zip" "$GITHUB_TOOL_DIR/dex2jar"; then
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        fi
    fi

    # Docker: MobSF (optional)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "opensecurity/mobile-security-framework-mobsf" "MobSF" || true
    fi
}
