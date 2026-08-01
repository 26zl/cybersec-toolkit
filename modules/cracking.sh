#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Cracking
# Hash cracking, brute force, wordlist generation

CRACKING_PACKAGES=(
    john hashcat hydra medusa crunch
    ophcrack chntpw fcrackzip pdfcrack
    cewl hashid bruteforce-luks
    maskprocessor princeprocessor statsprocessor
    sucrack
)

CRACKING_PIPX=(search-that-hash name-that-hash trevorspray)
# patator: handled via custom install below (dedicated venv, skips cx-Oracle)

CRACKING_GO=(
    "github.com/x90skysn3k/brutespray@latest"
)

CRACKING_CARGO=(legba)

CRACKING_GIT=(
    "DefaultCreds-cheat-sheet=https://github.com/ihebski/DefaultCreds-cheat-sheet.git"
    "pipal=https://github.com/digininja/pipal.git"
    "Hob0Rules=https://github.com/praetorian-inc/Hob0Rules.git"
    "Pantagrule=https://github.com/rarecoil/pantagrule.git"
    "OneRuleToRuleThemStill=https://github.com/stealthsploit/OneRuleToRuleThemStill.git"
    "username-anarchy=https://github.com/urbanadventurer/username-anarchy.git"
    "gpp-decrypt=https://github.com/t0thkr1s/gpp-decrypt.git"
    "cupp=https://github.com/Mebus/cupp.git"
    "changeme=https://github.com/ztgrace/changeme.git"
    "crowbar=https://github.com/galkan/crowbar.git"
    "kwprocessor=https://github.com/hashcat/kwprocessor.git"
)

CRACKING_GIT_NAMES=(DefaultCreds-cheat-sheet pipal Hob0Rules Pantagrule OneRuleToRuleThemStill username-anarchy gpp-decrypt cupp changeme crowbar kwprocessor)
CRACKING_GO_BINS=(brutespray)
CRACKING_BUILD_NAMES=(duplicut)
# Source of truth for build-from-source url + command (install + update).
declare -A CRACKING_BUILD_URLS=(
    [duplicut]="https://github.com/nil0x42/duplicut.git"
)
declare -A CRACKING_BUILD_CMDS=(
    [duplicut]="make"
)

install_module_cracking() {
    install_apt_batch "Cracking - Packages" "${CRACKING_PACKAGES[@]}"
    install_pipx_batch "Cracking - Python" "${CRACKING_PIPX[@]}"
    install_go_batch "Cracking - Go" "${CRACKING_GO[@]}"
    install_cargo_batch "Cracking - Rust" "${CRACKING_CARGO[@]}" || true

    # patator hard-depends on cx-Oracle (non-redistributable Oracle headers). pipx
    # cannot skip it — `--pip-args=--no-deps` makes pipx fail reading the skipped
    # deps' metadata — so drive the venv directly. setuptools is explicit because
    # venv stopped seeding it on Python 3.12+ (PEP 632).
    if [[ "${SKIP_PIPX:-false}" != "true" ]] && ! command_exists patator; then
        log_info "Installing patator (excluding cx-Oracle)..."
        local _pat_dir="$GITHUB_TOOL_DIR/patator"
        local _pat_esc; _pat_esc="$(_escape_single_quoted "$_pat_dir")"
        mkdir -p "$_pat_dir" && _chown_for_builder "$_pat_dir"
        if _as_builder "python3 -m venv '$_pat_esc/venv' \
                && '$_pat_esc/venv/bin/pip' install -q patator --no-deps \
                && '$_pat_esc/venv/bin/pip' install -q setuptools paramiko pycurl ajpy \
                   impacket psycopg2-binary pycryptodomex dnspython IPy pysnmp \
                   telnetlib-313-and-up" >> "$LOG_FILE" 2>&1; then
            # Optional dep that fails without system headers — not an error
            _as_builder "'$_pat_esc/venv/bin/pip' install -q mysqlclient" >> "$LOG_FILE" 2>&1 \
                || log_debug "patator: mysqlclient skipped (needs libmysqlclient-dev)"
            ln -sf "$_pat_dir/venv/bin/patator" "$PIPX_BIN_DIR/patator"
            log_success "patator installed"
            track_version "patator" "special" "latest"
        else
            log_error "Failed pipx: patator"
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        fi
    fi

    install_git_batch "Cracking - Git" "${CRACKING_GIT[@]}"

    # Build from source (url + command from CRACKING_BUILD_URLS / CRACKING_BUILD_CMDS)
    build_module_from_source CRACKING
}
