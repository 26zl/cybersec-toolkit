#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Blockchain Security
# Smart contract auditing, fuzzing, and analysis

BLOCKCHAIN_PACKAGES=()

BLOCKCHAIN_PIPX=(
    slither-analyzer
    mythril
)

BLOCKCHAIN_GIT=(
    "smart-contract-sanctuary=https://github.com/tintinweb/smart-contract-sanctuary.git"
    "openzeppelin-contracts=https://github.com/OpenZeppelin/openzeppelin-contracts.git"
)

BLOCKCHAIN_GIT_NAMES=(smart-contract-sanctuary openzeppelin-contracts)

install_module_blockchain() {
    [[ ${#BLOCKCHAIN_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Blockchain - Packages" "${BLOCKCHAIN_PACKAGES[@]}"
    install_pipx_batch "Blockchain - Python" "${BLOCKCHAIN_PIPX[@]}"

    # solc (Solidity compiler) — not in standard repos, use snap if available
    if ! command_exists solc; then
        if snap_available; then
            log_info "Installing solc via snap..."
            snap_install solc >> "$LOG_FILE" 2>&1 || log_warn "Failed to install solc via snap"
        else
            log_warn "solc not available via apt or snap — install manually: https://docs.soliditylang.org/"
        fi
    fi
    install_git_batch "Blockchain - Git" "${BLOCKCHAIN_GIT[@]}"

    # Foundry (forge, cast, anvil, chisel) — installed via foundryup
    if command_exists foundryup; then
        log_info "Foundry already installed"
    else
        log_warn "Installing Foundry via curl | bash (review: https://foundry.paradigm.xyz)"
        curl -L https://foundry.paradigm.xyz 2>/dev/null | bash >> "$LOG_FILE" 2>&1 || true
        if [[ -f "$HOME/.foundry/bin/foundryup" ]]; then
            "$HOME/.foundry/bin/foundryup" >> "$LOG_FILE" 2>&1 || true
        fi
    fi

    # Symlink Foundry binaries to /usr/local/bin for system-wide PATH access
    local _foundry_dir="$HOME/.foundry/bin"
    if [[ -d "$_foundry_dir" ]]; then
        for _bin in foundryup forge cast anvil chisel; do
            if [[ -f "$_foundry_dir/$_bin" ]] && [[ ! -f "/usr/local/bin/$_bin" ]]; then
                ln -sf "$_foundry_dir/$_bin" "/usr/local/bin/$_bin" 2>/dev/null || true
            fi
        done
        log_info "Foundry binaries symlinked to /usr/local/bin"
    fi

    # Docker: Echidna fuzzer (optional)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "trailofbits/echidna" "Echidna" || true
    fi
}
