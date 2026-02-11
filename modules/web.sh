#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Web Security
# Web application testing, scanning, fuzzing, exploitation
# =============================================================================

WEB_PACKAGES=(nikto whatweb)

WEB_PIPX=(
    sqlmap wafw00f sslyze dirsearch arjun
    droopescan wapiti3 mitmproxy2swagger commix
    raccoon-scanner git-dumper corscanner xsrfprobe
)

WEB_GO=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/OJ/gobuster/v3@latest"
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
    "github.com/003random/getJS@latest"
)

WEB_CARGO=(feroxbuster)

WEB_GEMS=(wpscan XSpear)

WEB_GIT=(
    "XSStrike=https://github.com/s0md3v/XSStrike.git"
    "xsser=https://github.com/epsylon/xsser.git"
    "Corsy=https://github.com/s0md3v/Corsy.git"
    "jwt_tool=https://github.com/ticarpi/jwt_tool.git"
    "SSRFmap=https://github.com/swisskyrepo/SSRFmap.git"
    "GraphQLmap=https://github.com/swisskyrepo/GraphQLmap.git"
    "smuggler=https://github.com/defparam/smuggler.git"
    "NoSQLMap=https://github.com/codingo/NoSQLMap.git"
    "testssl.sh=https://github.com/drwetter/testssl.sh.git"
    "Gopherus=https://github.com/tarunkant/Gopherus.git"
    "oxml_xxe=https://github.com/BuffaloWill/oxml_xxe.git"
    "CMSmap=https://github.com/dionach/CMSmap.git"
    "weevely3=https://github.com/epinna/weevely3.git"
    "PhpSploit=https://github.com/nil0x42/phpsploit.git"
    "Kadimus=https://github.com/P0cL4bs/Kadimus.git"
    "LFISuite=https://github.com/D35m0nd142/LFISuite.git"
    "phpggc=https://github.com/ambionics/phpggc.git"
    "PadBuster=https://github.com/AonCyberLabs/PadBuster.git"
    "h2csmuggler=https://github.com/BishopFox/h2csmuggler.git"
    "joomscan=https://github.com/rezasp/joomscan.git"
    "bolt=https://github.com/s0md3v/bolt.git"
    "pp-finder=https://github.com/yeswehack/pp-finder.git"
    "symfony-exploits=https://github.com/ambionics/symfony-exploits.git"
    "tomcatwardeployer=https://github.com/mgeeky/tomcatwardeployer.git"
    "XXEinjector=https://github.com/enjoiz/XXEinjector.git"
    "paramspider=https://github.com/devanshbatham/ParamSpider.git"
)

WEB_DOCKER=("beefproject/beef:BeEF")

# Binary names for verify/remove
WEB_GO_BINS=(nuclei katana ffuf gobuster crlfuzz dalfox kxss cariddi Gxss webanalyze jaeles proxify tlsx jsluice getJS)
WEB_GIT_NAMES=(XSStrike xsser Corsy jwt_tool SSRFmap GraphQLmap smuggler NoSQLMap testssl.sh Gopherus oxml_xxe CMSmap weevely3 PhpSploit Kadimus LFISuite phpggc PadBuster h2csmuggler joomscan bolt pp-finder symfony-exploits tomcatwardeployer XXEinjector paramspider)

install_module_web() {
    install_apt_batch "Web - Packages" "${WEB_PACKAGES[@]}"
    install_pipx_batch "Web - Python" "${WEB_PIPX[@]}"
    install_go_batch "Web - Go" "${WEB_GO[@]}"
    install_cargo_batch "Web - Rust" "${WEB_CARGO[@]}"
    install_gem_batch "Web - Ruby" "${WEB_GEMS[@]}"
    install_git_batch "Web - Git" "${WEB_GIT[@]}"

    # Binary releases
    download_github_release "frohoff/ysoserial" "ysoserial" "ysoserial-all.jar" "/opt/cybersec-jars" || true
    download_github_release "assetnote/kiterunner" "kr" "linux_amd64" || true

    # Docker (optional)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        for entry in "${WEB_DOCKER[@]}"; do
            local image="${entry%%:*}"
            local name="${entry#*:}"
            docker_pull "$image" "$name" || true
        done
    fi

    # Special installs
    install_burpsuite
    install_zap
}
