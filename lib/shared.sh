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
    libcapstone-dev libgmp-dev libecm-dev
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

    # openSUSE: install devel_basis pattern (equivalent of build-essential)
    # This is handled here instead of fixup_package_names() to avoid side effects
    # in the name-translation function (which is also called during removal).
    if [[ "$PKG_MANAGER" == "zypper" ]]; then
        maybe_sudo zypper --non-interactive install -t pattern devel_basis >> "$LOG_FILE" 2>&1 || true
    fi

    install_apt_batch "Shared base dependencies" "${SHARED_BASE_PACKAGES[@]}"

    # Report which key runtimes are now available
    local -a _runtimes=(python3 go ruby java cargo node npx)
    for _rt in "${_runtimes[@]}"; do
        if command_exists "$_rt"; then
            log_success "Runtime available: $_rt"
        fi
    done
}

# _version_ge — compare two major.minor version strings.
# Returns 0 (true) if $1 >= $2, 1 (false) otherwise.
# Usage: _version_ge "1.23" "1.21" && echo "ok"
_version_ge() {
    local cur="$1" min="$2"
    local cur_major cur_minor min_major min_minor
    cur_major=${cur%%.*}
    cur_minor=${cur#*.}; cur_minor=${cur_minor%%.*}
    min_major=${min%%.*}
    min_minor=${min#*.}; min_minor=${min_minor%%.*}
    [[ "$cur_major" -gt "$min_major" ]] && return 0
    [[ "$cur_major" -eq "$min_major" && "$cur_minor" -ge "$min_minor" ]]
}

# _validate_curl_pipe — validate a downloaded script before execution.
# Checks: non-empty file, minimum size, and multiple required keywords.
# Usage: _validate_curl_pipe "$file" "keyword1" "keyword2" ...
# Returns 0 if all checks pass, 1 otherwise.
_validate_curl_pipe() {
    local file="$1"; shift
    local -a keywords=("$@")
    # File must exist and be non-empty
    if [[ ! -s "$file" ]]; then
        log_warn "Downloaded script is empty or missing: $file"
        return 1
    fi
    # Minimum 512 bytes — a real install script is always larger
    local _size
    _size=$(wc -c < "$file")
    if [[ "$_size" -lt 512 ]]; then
        log_warn "Downloaded script is suspiciously small (${_size} bytes): $file"
        return 1
    fi
    # Must contain ALL required keywords (not just one)
    local kw
    for kw in "${keywords[@]}"; do
        if ! grep -q "$kw" "$file"; then
            log_warn "Downloaded script missing expected keyword '$kw': $file"
            return 1
        fi
    done
    return 0
}

# ensure_go — install modern Go from go.dev when the system package is too old.
# Many security tools (projectdiscovery, etc.) require Go >= 1.21.
# Ubuntu 22.04 ships Go 1.18, Debian 12 ships Go 1.19 — both too old.
GO_MIN_VERSION="${GO_MIN_VERSION:-1.21}"

ensure_go() {
    if command_exists go; then
        local current
        current=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
        if [[ -n "$current" ]]; then
            if _version_ge "$current" "$GO_MIN_VERSION"; then
                log_success "Go $current available (>= $GO_MIN_VERSION)"
                return 0
            fi
            log_warn "System Go $current is too old (need >= $GO_MIN_VERSION) — installing latest from go.dev..."
        fi
    else
        log_warn "Go not found after shared deps — installing latest from go.dev..."
    fi

    # Fetch latest stable Go version from go.dev API
    local GO_INSTALL_VERSION=""
    local _go_json
    _go_json=$(mktemp); _register_cleanup "$_go_json"
    if curl -fsSL "https://go.dev/dl/?mode=json" -o "$_go_json" 2>>"$LOG_FILE"; then
        GO_INSTALL_VERSION=$(python3 -c "
import json, sys
data = json.load(sys.stdin)
if data:
    print(data[0]['version'].lstrip('go'))
" < "$_go_json" 2>/dev/null)
    fi
    # Fallback to a known-good version if API fails
    GO_INSTALL_VERSION="${GO_INSTALL_VERSION:-1.24.0}"

    # Determine install location
    local install_parent
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        install_parent="$PREFIX/lib"          # → $PREFIX/lib/go
    else
        install_parent="/usr/local"           # → /usr/local/go (standard)
    fi

    local tarball="go${GO_INSTALL_VERSION}.linux-${SYS_ARCH}.tar.gz"
    local url="https://go.dev/dl/${tarball}"

    log_info "Downloading Go $GO_INSTALL_VERSION (latest stable) from go.dev..."
    local tmp_tar
    tmp_tar=$(mktemp); _register_cleanup "$tmp_tar"
    if ! curl -fsSL "$url" -o "$tmp_tar" 2>>"$LOG_FILE"; then
        log_error "Failed to download Go $GO_INSTALL_VERSION"
        rm -f "$tmp_tar"
        return 1
    fi

    # Verify SHA256 against go.dev published hash (reuse API JSON from version lookup)
    log_info "Verifying Go tarball checksum..."
    local expected_hash=""
    if [[ -f "$_go_json" ]] && [[ -s "$_go_json" ]]; then
        expected_hash=$(python3 -c "
import json, sys
for rel in json.load(sys.stdin):
    if rel['version'] == 'go${GO_INSTALL_VERSION}':
        for f in rel['files']:
            if f['filename'] == '${tarball}':
                print(f['sha256'])
                break
        break
" < "$_go_json" 2>>"$LOG_FILE")
    fi
    rm -f "$_go_json"

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
# Also handles the case where rustup is installed (via apt) but no default
# toolchain is configured — `cargo` shim exists but can't actually run.
ensure_cargo() {
    if command_exists cargo; then
        # Verify cargo actually works (rustup shim without default toolchain fails)
        if cargo --version >> "$LOG_FILE" 2>&1; then
            log_success "cargo already installed"
            return 0
        fi
        # rustup shim exists but no toolchain — install default
        log_warn "cargo shim found but no default toolchain — running rustup default stable..."
        if command_exists rustup && rustup default stable >> "$LOG_FILE" 2>&1; then
            if cargo --version >> "$LOG_FILE" 2>&1; then
                log_success "Rust stable toolchain configured"
                return 0
            fi
        fi
        log_warn "Failed to configure rustup default — reinstalling via rustup.rs"
    fi

    # rustup is a curl-pipe install — respect --skip-source
    if [[ "${SKIP_SOURCE:-false}" == "true" ]]; then
        log_warn "Skipping Rust toolchain install (--skip-source) — Cargo tools will not be available"
        return 1
    fi

    log_info "Installing Rust toolchain via rustup..."

    local _rustup_tmp
    _rustup_tmp=$(mktemp); _register_cleanup "$_rustup_tmp"
    if curl -L --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$_rustup_tmp" 2>>"$LOG_FILE" \
            && _validate_curl_pipe "$_rustup_tmp" 'rustup' 'RUSTUP' 'sh' \
            && chmod +r "$_rustup_tmp" \
            && _as_builder "sh '$_rustup_tmp' -y" >> "$LOG_FILE" 2>&1; then
        # Add cargo to PATH for the current session.
        # _as_builder installs rustup to $SUDO_USER's home, not root's $HOME.
        local _cargo_home
        _cargo_home="$(_builder_home)/.cargo"
        if [[ -f "$_cargo_home/env" ]]; then
            # shellcheck disable=SC1090  # Path is dynamic (builder's home)
            source "$_cargo_home/env"
        fi
        export PATH="$_cargo_home/bin:$PATH"
    fi
    rm -f "$_rustup_tmp"

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

    local _binstall_tmp
    _binstall_tmp=$(mktemp); _register_cleanup "$_binstall_tmp"
    if curl -L --proto '=https' --tlsv1.2 -sSf \
            https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh \
            -o "$_binstall_tmp" 2>>"$LOG_FILE" \
            && _validate_curl_pipe "$_binstall_tmp" 'cargo-binstall' 'install' 'github.com' \
            && chmod +r "$_binstall_tmp" \
            && _as_builder "bash '$_binstall_tmp'" >> "$LOG_FILE" 2>&1; then
        local _cbdir
        _cbdir="$(_builder_home)/.cargo/bin"
        export PATH="$_cbdir:$PATH"
    fi
    rm -f "$_binstall_tmp"

    if command_exists cargo-binstall; then
        log_success "cargo-binstall installed"
        return 0
    fi

    log_warn "Failed to install cargo-binstall — will compile from source instead"
    return 1
}

# ensure_python_modern — install a modern Python (>= PYTHON_MIN_VERSION) alongside
# the system Python when needed.  Some pipx tools have transitive dependencies
# requiring Python 3.11+ (e.g., sectools>=1.5.0).  Follows the ensure_go()/
# ensure_cargo() pattern: detect, install if needed, export PIPX_DEFAULT_PYTHON.
#
# Fully dynamic — version range derived from PYTHON_MIN_VERSION / PYTHON_TRY_MAX.
# Package names constructed per-distro from the version number (no hardcoded names).
PYTHON_MIN_VERSION="${PYTHON_MIN_VERSION:-3.11}"
PYTHON_TRY_MAX="${PYTHON_TRY_MAX:-3.13}"

ensure_python_modern() {
    # Parse current python3 version (major.minor)
    local cur_version=""
    if command_exists python3; then
        cur_version=$(python3 --version 2>/dev/null | awk '{print $2}' | cut -d. -f1,2)
    fi

    if [[ -n "$cur_version" ]]; then
        if _version_ge "$cur_version" "$PYTHON_MIN_VERSION"; then
            log_success "Python $cur_version available (>= $PYTHON_MIN_VERSION)"
            export PIPX_DEFAULT_PYTHON="python3"
            return 0
        fi
        log_warn "System Python $cur_version is too old (need >= $PYTHON_MIN_VERSION) — installing newer Python..."
    else
        log_warn "Python not found — skipping modern Python check"
        return 1
    fi

    # Build dynamic version list: from PYTHON_TRY_MAX down to PYTHON_MIN_VERSION
    local _max_minor=${PYTHON_TRY_MAX#*.}
    local _min_minor=${PYTHON_MIN_VERSION#*.}
    local -a _try_versions=()
    local _m
    for ((_m = _max_minor; _m >= _min_minor; _m--)); do
        _try_versions+=("3.${_m}")
    done

    # Install a newer Python per distro — try each version (newest first)
    case "$PKG_MANAGER" in
        apt)
            log_info "Adding deadsnakes PPA for newer Python..."
            if command_exists add-apt-repository; then
                add-apt-repository -y ppa:deadsnakes/ppa >> "$LOG_FILE" 2>&1 || true
                pkg_update >> "$LOG_FILE" 2>&1 || true
            fi
            for _v in "${_try_versions[@]}"; do
                if pkg_install "python${_v}" "python${_v}-venv" >> "$LOG_FILE" 2>&1; then
                    break
                fi
            done
            ;;
        dnf)
            for _v in "${_try_versions[@]}"; do
                if pkg_install "python${_v}" >> "$LOG_FILE" 2>&1; then
                    break
                fi
            done
            ;;
        pacman)
            # Arch always has latest Python — should not reach here
            ;;
        zypper)
            # zypper uses no dot: python312, python311, etc.
            for _v in "${_try_versions[@]}"; do
                local _zyp_name="python${_v//./}"
                if pkg_install "$_zyp_name" >> "$LOG_FILE" 2>&1; then
                    break
                fi
            done
            ;;
        pkg)
            # Termux always has latest Python — should not reach here
            ;;
    esac

    # Find the best available python3.X binary (prefer newest)
    local _py_bin=""
    for _v in "${_try_versions[@]}"; do
        if command -v "python${_v}" &>/dev/null; then
            _py_bin="$(command -v "python${_v}")"
            break
        fi
    done

    if [[ -n "$_py_bin" ]]; then
        local _found_ver
        _found_ver=$("$_py_bin" --version 2>/dev/null | awk '{print $2}' | cut -d. -f1,2)
        export PIPX_DEFAULT_PYTHON="$_py_bin"
        log_success "pipx will use Python $_found_ver ($_py_bin)"
        return 0
    fi

    log_warn "Could not install Python >= $PYTHON_MIN_VERSION — pipx will use system Python $cur_version"
    export PIPX_DEFAULT_PYTHON="python3"
    return 0
}

# ensure_node — install Node.js + npm, preferring Node.js 18+ LTS.
# Required for npm-based tools (e.g., promptfoo needs native modules that
# require Node.js 18+).  Ubuntu 22.04 ships Node.js 12 which is too old.
NODE_MIN_VERSION="${NODE_MIN_VERSION:-18}"

ensure_node() {
    if command_exists node && command_exists npm; then
        # Check if installed Node.js meets minimum version
        local cur_major
        cur_major=$(node --version 2>/dev/null | sed 's/^v//' | cut -d. -f1)
        if [[ -n "$cur_major" ]] && [[ "$cur_major" -ge "$NODE_MIN_VERSION" ]]; then
            log_success "Node.js $(node --version 2>/dev/null) + npm already installed"
            return 0
        fi
        log_warn "System Node.js v${cur_major} is too old (need >= $NODE_MIN_VERSION) — upgrading..."
    else
        log_info "Node.js/npm not found — installing..."
    fi

    # On apt-based systems, use NodeSource for modern Node.js
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        log_info "Installing Node.js ${NODE_MIN_VERSION}.x LTS from NodeSource..."
        local _ns_tmp
        _ns_tmp=$(mktemp); _register_cleanup "$_ns_tmp"
        if curl -fsSL "https://deb.nodesource.com/setup_${NODE_MIN_VERSION}.x" -o "$_ns_tmp" 2>>"$LOG_FILE" \
                && _validate_curl_pipe "$_ns_tmp" 'nodesource' 'nodejs' 'apt'; then
            if bash "$_ns_tmp" >> "$LOG_FILE" 2>&1; then
                pkg_install nodejs >> "$LOG_FILE" 2>&1 || true
            fi
        fi
        rm -f "$_ns_tmp"

        if command_exists node; then
            local _new_ver
            _new_ver=$(node --version 2>/dev/null | sed 's/^v//' | cut -d. -f1)
            if [[ -n "$_new_ver" ]] && [[ "$_new_ver" -ge "$NODE_MIN_VERSION" ]]; then
                log_success "Node.js $(node --version 2>/dev/null) + npm installed via NodeSource"
                return 0
            fi
        fi
        log_warn "NodeSource setup failed — falling back to system package"
    fi

    # Fallback: system package (may be too old for some tools)
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
