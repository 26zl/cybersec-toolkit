#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Web Security
# Web application testing, scanning, fuzzing, exploitation

WEB_PACKAGES=(whatweb)

WEB_PIPX=(
    sqlmap wafw00f sslyze arjun
    droopescan mitmproxy2swagger commix
    raccoon-scanner git-dumper corscanner xsrfprobe
)

WEB_GO=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/Emoe/kxss@latest"
    "github.com/edoardottt/cariddi/cmd/cariddi@latest"
    "github.com/KathanP19/Gxss@latest"
    "github.com/rverton/webanalyze/cmd/webanalyze@latest"
    "github.com/jaeles-project/jaeles@latest"
    "github.com/projectdiscovery/proxify/cmd/proxify@latest"
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    "github.com/BishopFox/jsluice/cmd/jsluice@latest"
)

WEB_CARGO=(feroxbuster)

WEB_GEMS=(wpscan brakeman)

WEB_GIT=(
    "XSStrike=https://github.com/s0md3v/XSStrike.git"
    "Corsy=https://github.com/s0md3v/Corsy.git"
    "jwt_tool=https://github.com/ticarpi/jwt_tool.git"
    "smuggler=https://github.com/defparam/smuggler.git"
    "NoSQLMap=https://github.com/codingo/NoSQLMap.git"
    "testssl.sh=https://github.com/drwetter/testssl.sh.git"
    "Gopherus=https://github.com/tarunkant/Gopherus.git"
    "CMSmap=https://github.com/dionach/CMSmap.git"
    "PhpSploit=https://github.com/nil0x42/phpsploit.git"
    "phpggc=https://github.com/ambionics/phpggc.git"
    "PadBuster=https://github.com/AonCyberLabs/PadBuster.git"
    "h2csmuggler=https://github.com/BishopFox/h2csmuggler.git"
    "pp-finder=https://github.com/yeswehack/pp-finder.git"
    "symfony-exploits=https://github.com/ambionics/symfony-exploits.git"
    "tomcatwardeployer=https://github.com/mgeeky/tomcatwardeployer.git"
    "XXEinjector=https://github.com/enjoiz/XXEinjector.git"
    "paramspider=https://github.com/devanshbatham/ParamSpider.git"
)

# Binary names for verify/remove
WEB_GO_BINS=(nuclei katana ffuf crlfuzz dalfox kxss cariddi Gxss webanalyze jaeles proxify tlsx jsluice)
WEB_GIT_NAMES=(XSStrike Corsy jwt_tool smuggler NoSQLMap testssl.sh Gopherus CMSmap PhpSploit phpggc PadBuster h2csmuggler pp-finder symfony-exploits tomcatwardeployer XXEinjector paramspider)

install_module_web() {
    install_apt_batch "Web - Packages" "${WEB_PACKAGES[@]}"
    install_pipx_batch "Web - Python" "${WEB_PIPX[@]}"
    install_go_batch "Web - Go" "${WEB_GO[@]}"
    install_cargo_batch "Web - Rust" "${WEB_CARGO[@]}"
    install_gem_batch "Web - Ruby" "${WEB_GEMS[@]}"
    install_git_batch "Web - Git" "${WEB_GIT[@]}"

    # Binary releases (skipped on Termux — Linux/glibc binaries)
    install_binary_releases "${BINARY_RELEASES_WEB[@]}"
    if [[ "$PKG_MANAGER" != "pkg" ]]; then
        if ! download_github_release "assetnote/kiterunner" "kr" "linux_amd64"; then
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        fi
    fi

    # Docker (optional) — BeEF is in ALL_DOCKER_IMAGES (centralized registry)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "beefproject/beef" "BeEF" || true
    fi

    # Special installs (Linux/GUI only — not available on Termux)
    if [[ "${SKIP_SOURCE:-false}" != "true" ]] && [[ "$PKG_MANAGER" != "pkg" ]]; then
        install_zap
    fi
}
