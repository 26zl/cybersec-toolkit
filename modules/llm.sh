#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: LLM Security
# LLM red teaming, prompt injection, jailbreak testing, AI vulnerability scanning

LLM_PACKAGES=()

LLM_PIPX=(garak)

LLM_GIT=(
    "FuzzyAI=https://github.com/cyberark/FuzzyAI.git"
    "pallms=https://github.com/mik0w/pallms.git"
    "Vigil=https://github.com/deadbits/vigil-llm.git"
    "shannon=https://github.com/KeygraphHQ/shannon.git"
)

LLM_GIT_NAMES=(FuzzyAI pallms Vigil shannon)

install_module_llm() {
    [[ ${#LLM_PACKAGES[@]} -gt 0 ]] && install_apt_batch "LLM - Packages" "${LLM_PACKAGES[@]}"
    install_pipx_batch "LLM - Python" "${LLM_PIPX[@]}"
    install_git_batch "LLM - Git" "${LLM_GIT[@]}"

    # promptfoo — LLM eval & red teaming (npm package)
    if [[ "${SKIP_SOURCE:-false}" != "true" ]]; then
        if ensure_node; then
            log_info "Installing promptfoo via npm..."
            npm install -g promptfoo >> "$LOG_FILE" 2>&1 \
                && log_success "promptfoo installed" \
                || log_warn "Failed to install promptfoo via npm"
        else
            log_warn "Skipping promptfoo — Node.js/npm not available"
        fi
    fi
}
