#!/bin/bash
# shared.sh — Shared base dependencies required by all modules.
# Compilers, runtimes, dev libraries — needed regardless of which modules
# are selected.  Source AFTER common.sh and installers.sh.

# shellcheck disable=SC2034  # Arrays consumed by install.sh, remove.sh, verify.sh

SHARED_BASE_PACKAGES=(
    # Core utilities
    git curl wget openssl unzip jq file

    # Compilers & build tools
    build-essential cmake autoconf automake libtool pkg-config texinfo

    # Runtimes
    python3 python3-pip python3-venv python3-dev
    ruby ruby-dev golang-go default-jdk
    nodejs npm

    # Dev libraries — needed by build-from-source tools and Python native extensions
    libpcap-dev libssl-dev libffi-dev
    zlib1g-dev libxml2-dev libxslt1-dev
    libglib2.0-dev libreadline-dev libsqlite3-dev libcurl4-openssl-dev
    libseccomp-dev binutils-dev libedit-dev liblzma-dev
    libkrb5-dev libsctp-dev libnfnetlink-dev
    libgmp-dev libecm-dev
    libldap2-dev libsasl2-dev
    libpixman-1-dev libunwind-dev libini-config-dev

    # Compiler toolchains — needed by fuzzing, build-from-source, and native extensions
    llvm llvm-dev clang lld flex bison
    # Protobuf compiler — needed by Rust crates (yara-x) and Go tools that use protobufs
    protobuf-compiler

    # Misc utilities
    dos2unix rlwrap imagemagick
)

install_shared_deps() {
    log_info "Installing core utilities, compilers, runtimes (Python, Go, Ruby, Java), and dev libraries..."
    install_apt_batch "Shared base dependencies" "${SHARED_BASE_PACKAGES[@]}"

    # Report which key runtimes are now available
    local -a _runtimes=(python3 go ruby java cargo node npx)
    for _rt in "${_runtimes[@]}"; do
        if command_exists "$_rt"; then
            log_success "Runtime available: $_rt"
        fi
    done
}

# ensure_go — install modern Go from go.dev when the system package is too old.
# Many security tools (projectdiscovery, etc.) require Go >= 1.21.
# Ubuntu 22.04 ships Go 1.18, Debian 12 ships Go 1.19 — both too old.
GO_INSTALL_VERSION="${GO_INSTALL_VERSION:-1.23.6}"
GO_MIN_VERSION="${GO_MIN_VERSION:-1.21}"

ensure_go() {
    if command_exists go; then
        local current
        current=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
        if [[ -n "$current" ]]; then
            # Compare major.minor against minimum
            local cur_major cur_minor min_major min_minor
            cur_major=${current%%.*}
            cur_minor=${current#*.}; cur_minor=${cur_minor%%.*}
            min_major=${GO_MIN_VERSION%%.*}
            min_minor=${GO_MIN_VERSION#*.}; min_minor=${min_minor%%.*}
            if [[ "$cur_major" -gt "$min_major" ]] || \
               { [[ "$cur_major" -eq "$min_major" ]] && [[ "$cur_minor" -ge "$min_minor" ]]; }; then
                log_success "Go $current available (>= $GO_MIN_VERSION)"
                return 0
            fi
            log_warn "System Go $current is too old (need >= $GO_MIN_VERSION) — installing Go $GO_INSTALL_VERSION..."
        fi
    else
        log_warn "Go not found after shared deps — installing Go $GO_INSTALL_VERSION from go.dev..."
    fi

    # Determine install location
    local install_parent
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        install_parent="$PREFIX/lib"          # → $PREFIX/lib/go
    else
        install_parent="/usr/local"           # → /usr/local/go (standard)
    fi

    local tarball="go${GO_INSTALL_VERSION}.linux-${SYS_ARCH}.tar.gz"
    local url="https://go.dev/dl/${tarball}"

    log_info "Downloading Go $GO_INSTALL_VERSION from go.dev..."
    local tmp_tar
    tmp_tar=$(mktemp)
    if ! curl -fsSL "$url" -o "$tmp_tar" 2>>"$LOG_FILE"; then
        log_error "Failed to download Go $GO_INSTALL_VERSION"
        rm -f "$tmp_tar"
        return 1
    fi

    # Verify SHA256 against go.dev published hash
    log_info "Verifying Go tarball checksum..."
    local expected_hash
    expected_hash=$(curl -fsSL "https://go.dev/dl/?mode=json" 2>>"$LOG_FILE" \
        | python3 -c "
import json, sys
for rel in json.load(sys.stdin):
    if rel['version'] == 'go${GO_INSTALL_VERSION}':
        for f in rel['files']:
            if f['filename'] == '${tarball}':
                print(f['sha256'])
                break
        break
" 2>>"$LOG_FILE")

    if [[ -n "$expected_hash" ]]; then
        local actual_hash
        actual_hash=$(sha256sum "$tmp_tar" | awk '{print $1}')
        if [[ "$actual_hash" == "$expected_hash" ]]; then
            log_success "Go tarball checksum verified"
        else
            log_error "Go tarball checksum MISMATCH (expected: ${expected_hash:0:16}…, got: ${actual_hash:0:16}…)"
            rm -f "$tmp_tar"
            return 1
        fi
    else
        if [[ "${REQUIRE_CHECKSUMS:-false}" == "true" ]]; then
            log_error "Could not fetch Go checksum from go.dev (--require-checksums)"
            rm -f "$tmp_tar"
            return 1
        fi
        log_warn "Could not fetch Go checksum from go.dev — skipping verification"
    fi

    # Remove previous Go SDK at this location
    [[ -d "$install_parent/go" ]] && rm -rf "$install_parent/go"

    # Extract — creates $install_parent/go/{bin,src,pkg,...}
    mkdir -p "$install_parent" 2>/dev/null || true
    if ! tar -C "$install_parent" -xzf "$tmp_tar" 2>>"$LOG_FILE"; then
        log_error "Failed to extract Go tarball"
        rm -f "$tmp_tar"
        return 1
    fi
    rm -f "$tmp_tar"

    # Prepend to PATH so new Go shadows the old system Go
    export GOROOT="$install_parent/go"
    export PATH="$GOROOT/bin:$PATH"

    if command_exists go; then
        local new_ver
        new_ver=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
        log_success "Go $new_ver installed to $install_parent/go"
        return 0
    fi

    log_error "Failed to install Go $GO_INSTALL_VERSION"
    return 1
}

# ensure_cargo — install Rust toolchain via rustup if cargo is not present.
ensure_cargo() {
    if command_exists cargo; then
        log_success "cargo already installed"
        return 0
    fi

    # rustup is a curl-pipe install — respect --skip-source
    if [[ "${SKIP_SOURCE:-false}" == "true" ]]; then
        log_warn "Skipping Rust toolchain install (--skip-source) — Cargo tools will not be available"
        return 1
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

# ensure_cargo_binstall — install cargo-binstall for fast pre-compiled binary downloads.
# Downloads pre-compiled binaries instead of compiling from source (~3s vs ~20s per crate).
# Uses the official bootstrap script (same pattern as rustup above).
ensure_cargo_binstall() {
    if command_exists cargo-binstall; then
        log_debug "cargo-binstall already available"
        return 0
    fi

    if ! command_exists cargo; then
        log_debug "cargo not found — skipping cargo-binstall"
        return 1
    fi

    # curl-pipe install — respect --skip-source
    if [[ "${SKIP_SOURCE:-false}" == "true" ]]; then
        log_debug "Skipping cargo-binstall (--skip-source)"
        return 1
    fi

    log_info "Installing cargo-binstall for faster Rust tool downloads..."

    if curl -L --proto '=https' --tlsv1.2 -sSf \
            https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh \
            | bash >> "$LOG_FILE" 2>&1; then
        export PATH="$HOME/.cargo/bin:$PATH"
    fi

    if command_exists cargo-binstall; then
        log_success "cargo-binstall installed"
        return 0
    fi

    log_warn "Failed to install cargo-binstall — will compile from source instead"
    return 1
}

# ensure_node — install Node.js + npm via system package if not present.
# Required for npm-based tools (e.g., promptfoo).
ensure_node() {
    if command_exists node && command_exists npm; then
        log_success "Node.js + npm already installed"
        return 0
    fi

    log_info "Node.js/npm not found — installing via $PKG_MANAGER..."

    # Package names vary by distro
    local -a _node_pkgs
    case "$PKG_MANAGER" in
        apt)    _node_pkgs=(nodejs npm) ;;
        dnf)    _node_pkgs=(nodejs npm) ;;
        pacman) _node_pkgs=(nodejs npm) ;;
        zypper) _node_pkgs=(nodejs npm) ;;
        pkg)    _node_pkgs=(nodejs) ;;        # Termux: nodejs includes npm
        *)      _node_pkgs=(nodejs npm) ;;
    esac

    for _pkg in "${_node_pkgs[@]}"; do
        pkg_install "$_pkg" >> "$LOG_FILE" 2>&1 || true
    done

    if command_exists node && command_exists npm; then
        log_success "Node.js $(node --version 2>/dev/null) + npm installed"
        return 0
    fi

    log_error "Failed to install Node.js/npm — npm-based tools will not be available"
    return 1
}
