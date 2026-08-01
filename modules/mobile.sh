#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Mobile Security
# Android/iOS application testing, APK analysis, device interaction

MOBILE_PACKAGES=(adb smali scrcpy apksigner zipalign)

MOBILE_PIPX=(androguard apkleaks objection drozer qark apkid)

MOBILE_GIT=(
    "apktool=https://github.com/iBotPeaches/Apktool.git"
    "medusa-frida=https://github.com/Ch0pin/medusa.git"
)

MOBILE_GIT_NAMES=(apktool medusa-frida)

MOBILE_NPM=(apk-mitm rms-runtime-mobile-security)

install_module_mobile() {
    install_apt_batch "Mobile - Packages" "${MOBILE_PACKAGES[@]}"
    install_pipx_batch "Mobile - Python" "${MOBILE_PIPX[@]}"
    install_git_batch "Mobile - Git" "${MOBILE_GIT[@]}"
    install_npm_batch "Mobile - npm" "${MOBILE_NPM[@]}"

    # Binary releases (jadx, dex2jar — skipped on Termux)
    install_binary_releases "${BINARY_RELEASES_MOBILE[@]}"

    # Docker: MobSF (optional)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "opensecurity/mobile-security-framework-mobsf" "MobSF" || true
    fi
}
