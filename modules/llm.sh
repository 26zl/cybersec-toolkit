#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: LLM Security
# LLM red teaming, prompt injection, jailbreak testing, AI vulnerability scanning

PROMPTFOO_VERSION="${PROMPTFOO_VERSION:-0.107.4}"

LLM_PACKAGES=()

LLM_PIPX=(garak cai-framework)

LLM_GIT=(
    "FuzzyAI=https://github.com/cyberark/FuzzyAI.git"
    "pallms=https://github.com/mik0w/pallms.git"
    "Vigil=https://github.com/deadbits/vigil-llm.git"
    "shannon=https://github.com/KeygraphHQ/shannon.git"
    "pentagi=https://github.com/vxcontrol/pentagi.git"
)

LLM_GIT_NAMES=(FuzzyAI pallms Vigil shannon pentagi)

install_module_llm() {
    [[ ${#LLM_PACKAGES[@]} -gt 0 ]] && install_apt_batch "LLM - Packages" "${LLM_PACKAGES[@]}"
    install_pipx_batch "LLM - Python" "${LLM_PIPX[@]}"
    install_git_batch "LLM - Git" "${LLM_GIT[@]}"

    # promptfoo — LLM red teaming & testing (npm package)
    if [[ "${SKIP_SOURCE:-false}" != "true" ]]; then
        if ensure_node; then
            _start_spinner "Installing promptfoo via npm..."
            if npm install -g "promptfoo@${PROMPTFOO_VERSION}" >> "$LOG_FILE" 2>&1; then
                _stop_spinner
                log_success "promptfoo installed"
                track_version "promptfoo" "npm" "$PROMPTFOO_VERSION"
            else
                _stop_spinner
                log_error "Failed npm: promptfoo"
                TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
            fi
        else
            log_warn "Skipping promptfoo — Node.js/npm not available"
        fi
    fi
}
