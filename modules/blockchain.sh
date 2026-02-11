#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# =============================================================================
# Module: Blockchain Security
# Smart contract auditing, fuzzing, and analysis
# =============================================================================

BLOCKCHAIN_PACKAGES=(solc)

BLOCKCHAIN_PIPX=(
    slither-analyzer
    mythril
    manticore
)

BLOCKCHAIN_GIT=(
    "smart-contract-sanctuary=https://github.com/tintinweb/smart-contract-sanctuary.git"
    "openzeppelin-contracts=https://github.com/OpenZeppelin/openzeppelin-contracts.git"
)

BLOCKCHAIN_GIT_NAMES=(smart-contract-sanctuary openzeppelin-contracts)

install_module_blockchain() {
    install_apt_batch "Blockchain - Packages" "${BLOCKCHAIN_PACKAGES[@]}"
    install_pipx_batch "Blockchain - Python" "${BLOCKCHAIN_PIPX[@]}"
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

    # Docker: Echidna fuzzer (optional)
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        docker_pull "trailofbits/echidna" "Echidna" || true
    fi
}
