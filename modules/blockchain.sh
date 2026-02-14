#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Blockchain Security
# Smart contract auditing, fuzzing, and analysis

BLOCKCHAIN_PACKAGES=()

BLOCKCHAIN_PIPX=(
    slither-analyzer
    mythril
)

BLOCKCHAIN_GIT=()

BLOCKCHAIN_GIT_NAMES=()

install_module_blockchain() {
    [[ ${#BLOCKCHAIN_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Blockchain - Packages" "${BLOCKCHAIN_PACKAGES[@]}"
    install_pipx_batch "Blockchain - Python" "${BLOCKCHAIN_PIPX[@]}"

    # solc (Solidity compiler) — not in standard repos, use snap if available
    if [[ "${SKIP_SOURCE:-false}" != "true" ]] && ! command_exists solc; then
        if snap_available; then
            _start_spinner "Installing solc via snap..."
            if snap_install solc >> "$LOG_FILE" 2>&1; then
                _stop_spinner
                log_success "solc installed"
                track_version "solc" "snap" "latest"
            else
                _stop_spinner
                log_warn "Failed to install solc via snap"
            fi
        else
            log_warn "solc not available via apt or snap — install manually: https://docs.soliditylang.org/"
        fi
    fi
    [[ ${#BLOCKCHAIN_GIT[@]} -gt 0 ]] && install_git_batch "Blockchain - Git" "${BLOCKCHAIN_GIT[@]}"

    # Foundry (forge, cast, anvil, chisel) — installed via foundryup
    if [[ "${SKIP_SOURCE:-false}" == "true" ]]; then
        log_warn "Skipping Foundry (--skip-source)"
    elif command_exists foundryup; then
        log_success "Foundry already installed"
    else
        log_warn "Installing Foundry via curl | bash (review: https://foundry.paradigm.xyz)"
        local _foundry_tmp
        _foundry_tmp=$(mktemp)
        if curl -fsSL https://foundry.paradigm.xyz -o "$_foundry_tmp" 2>>"$LOG_FILE"; then
            if grep -q 'foundry' "$_foundry_tmp" && grep -q 'foundryup' "$_foundry_tmp"; then
                bash "$_foundry_tmp" >> "$LOG_FILE" 2>&1 || true
            else
                log_error "Foundry install script failed content verification — skipping"
                TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
            fi
        else
            log_error "Failed to download Foundry install script"
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        fi
        rm -f "$_foundry_tmp"
        if [[ -f "$HOME/.foundry/bin/foundryup" ]]; then
            _start_spinner "Running foundryup..."
            if "$HOME/.foundry/bin/foundryup" >> "$LOG_FILE" 2>&1; then
                _stop_spinner
                log_success "Foundry installed"
                track_version "foundry" "special" "latest"
            else
                _stop_spinner
                log_error "Foundry installation failed"
                TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
            fi
        fi
    fi

    # Symlink Foundry binaries to $PIPX_BIN_DIR for PATH access
    # NOTE: 'chisel' is skipped — it collides with jpillora/chisel (TCP tunnel)
    # from the networking module.  Access Foundry's chisel via ~/.foundry/bin/chisel.
    local _foundry_dir="$HOME/.foundry/bin"
    if [[ -d "$_foundry_dir" ]]; then
        local _linked=0
        for _bin in foundryup forge cast anvil; do
            if [[ -f "$_foundry_dir/$_bin" ]] && [[ ! -f "$PIPX_BIN_DIR/$_bin" ]]; then
                ln -sf "$_foundry_dir/$_bin" "$PIPX_BIN_DIR/$_bin" 2>/dev/null || true
                _linked=$((_linked + 1))
            fi
        done
        [[ "$_linked" -gt 0 ]] && log_success "Symlinked $_linked Foundry binaries to $PIPX_BIN_DIR"
    fi

    # Docker: Echidna fuzzer (optional)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "trailofbits/echidna" "Echidna" || true
    fi
}
