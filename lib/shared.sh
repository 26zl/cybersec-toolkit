#!/bin/bash
# shared.sh — Shared base dependencies required by all modules.
# Compilers, runtimes, dev libraries — needed regardless of which modules
# are selected.  Source AFTER common.sh and installers.sh.

# shellcheck disable=SC2034  # Arrays consumed by install.sh, remove.sh, verify.sh

SHARED_BASE_PACKAGES=(
    # Core utilities
    git curl wget openssl unzip jq file

    # Compilers & build tools
    build-essential cmake autoconf automake libtool pkg-config

    # Runtimes
    python3 python3-pip python3-venv python3-dev
    ruby ruby-dev golang-go default-jdk

    # Dev libraries — needed by build-from-source tools and Python native extensions
    libpcap-dev libssl-dev libffi-dev
    zlib1g-dev libxml2-dev libxslt1-dev
    libglib2.0-dev libreadline-dev libsqlite3-dev libcurl4-openssl-dev
    libseccomp-dev binutils-dev libedit-dev liblzma-dev
    libkrb5-dev libsctp-dev libnfnetlink-dev
    libgmp-dev libecm-dev
    libldap2-dev libsasl2-dev

    # Misc utilities
    dos2unix rlwrap imagemagick
)

install_shared_deps() {
    install_apt_batch "Shared base dependencies" "${SHARED_BASE_PACKAGES[@]}"
}

# ensure_cargo — install Rust toolchain via rustup if cargo is not present.
ensure_cargo() {
    if command_exists cargo; then
        log_success "cargo already installed"
        return 0
    fi

    log_info "Installing Rust toolchain via rustup..."

    if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y >> "$LOG_FILE" 2>&1; then
        # Add cargo to PATH for the current session
        if [[ -f "$HOME/.cargo/env" ]]; then
            # shellcheck disable=SC1091  # File may not exist on all systems
            source "$HOME/.cargo/env"
        fi
        export PATH="$HOME/.cargo/bin:$PATH"
    fi

    if command_exists cargo; then
        log_success "Rust toolchain installed"
        return 0
    fi

    log_error "Failed to install Rust toolchain — Cargo tools will not be available"
    return 1
}
