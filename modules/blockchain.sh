#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Blockchain Security
# Smart contract auditing, fuzzing, and analysis

BLOCKCHAIN_PACKAGES=()

BLOCKCHAIN_PIPX=(
    slither-analyzer
    mythril
    solc-select
    halmos
    crytic-compile
    eth-ape
)

BLOCKCHAIN_CARGO=(
    aderyn
)

BLOCKCHAIN_GIT=()

BLOCKCHAIN_GIT_NAMES=()

install_module_blockchain() {
    [[ ${#BLOCKCHAIN_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Blockchain - Packages" "${BLOCKCHAIN_PACKAGES[@]}"
    install_pipx_batch "Blockchain - Python" "${BLOCKCHAIN_PIPX[@]}"
    install_cargo_batch "Blockchain - Rust" "${BLOCKCHAIN_CARGO[@]}" || true

    [[ ${#BLOCKCHAIN_GIT[@]} -gt 0 ]] && install_git_batch "Blockchain - Git" "${BLOCKCHAIN_GIT[@]}"

    # Binary releases: medusa (fuzzer), heimdall (decompiler), ityfuzz (hybrid fuzzer)
    [[ ${#BINARY_RELEASES_BLOCKCHAIN[@]} -gt 0 ]] && install_binary_releases "${BINARY_RELEASES_BLOCKCHAIN[@]}"

    # Foundry (forge, cast, anvil, chisel) — installed via foundryup
    if [[ "${SKIP_SOURCE:-false}" == "true" ]]; then
        log_warn "Skipping Foundry (--skip-source)"
    elif command_exists foundryup; then
        log_success "Foundry already installed"
    else
        log_warn "Installing Foundry via curl | bash (review: https://foundry.paradigm.xyz)"
        local _foundry_tmp _foundry_home
        _foundry_home="$(_builder_home)"
        _foundry_tmp=$(mktemp); _register_cleanup "$_foundry_tmp"
        # Mirror the privilege-drop + validation discipline used by every other
        # curl-pipe bootstrap (rustup/uv/nodesource): download to a temp file,
        # validate size + keywords, then run as $SUDO_USER (not root).
        if curl -L --proto '=https' --tlsv1.2 -fsSL https://foundry.paradigm.xyz -o "$_foundry_tmp" 2>>"$LOG_FILE" \
                && _validate_curl_pipe "$_foundry_tmp" 'foundry' 'foundryup' \
                && chmod +r "$_foundry_tmp" \
                && _as_builder "bash '$(_escape_single_quoted "$_foundry_tmp")'" >> "$LOG_FILE" 2>&1; then
            : # foundryup bootstrap placed in builder's ~/.foundry; run it below
        else
            log_error "Foundry install script failed (download or content verification) — skipping"
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        fi
        rm -f "$_foundry_tmp"
        if [[ -f "$_foundry_home/.foundry/bin/foundryup" ]]; then
            _start_spinner "Running foundryup..."
            if _as_builder "'$_foundry_home/.foundry/bin/foundryup'" >> "$LOG_FILE" 2>&1; then
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
    # foundryup installs under $SUDO_USER's home when privilege-dropping; resolve
    # the builder's home so the symlinks point at the real install location.
    local _foundry_dir; _foundry_dir="$(_builder_home)/.foundry/bin"
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
