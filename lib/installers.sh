#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by modules and scripts that source this file
# installers.sh — Install method helpers for cybersec-tools-installer
# Provides batch install functions for: apt, pipx, go, cargo, gem, git, binary, docker
# Source AFTER common.sh

# Global tool failure counter — incremented by batch install functions.
# Used by install.sh to detect per-module failures without relying on
# the module function's return code (which only reflects the last command).
TOTAL_TOOL_FAILURES=0

# Distro-specific package name translation
fixup_package_names() {
    local -n arr=$1
    local new_arr=()
    for pkg in "${arr[@]}"; do
        case "$PKG_MANAGER" in
            apt)
                # Skip Kali/Parrot-only packages on standard Debian/Ubuntu
                if [[ "$DISTRO_ID" != "kali" && "$DISTRO_ID" != "parrot" ]]; then
                    case "$pkg" in
                        # Kali-only packages not available in standard Ubuntu/Debian repos
                        spike|enum4linux|bing-ip2hosts) continue ;;
                        sagemath) continue ;;
                        ghidra|rizin|radare2) continue ;;
                        bulk-extractor|forensics-extra) continue ;;
                        kismet|spooftooph|crackle|asleap|fern-wifi-cracker) continue ;;
                        smali) continue ;;
                        rsmangler) continue ;;
                        zeek|sentrypeer|chaosreader) continue ;;
                    esac
                fi
                ;;
            dnf)
                case "$pkg" in
                    netcat-openbsd)     pkg="nmap-ncat" ;;
                    dnsutils)           pkg="bind-utils" ;;
                    build-essential)    pkg="@development-tools" ;;
                    python3-venv)       pkg="python3" ;;
                    default-jdk)        pkg="java-17-openjdk-devel" ;;
                    zlib1g-dev)         pkg="zlib-devel" ;;
                    libxml2-dev)        pkg="libxml2-devel" ;;
                    libxslt1-dev)       pkg="libxslt-devel" ;;
                    libpcap-dev)        pkg="libpcap-devel" ;;
                    libssl-dev)         pkg="openssl-devel" ;;
                    libffi-dev)         pkg="libffi-devel" ;;
                    python3-dev)        pkg="python3-devel" ;;
                    wireshark-common)   pkg="wireshark-cli" ;;
                    proxychains4)       pkg="proxychains-ng" ;;
                    forensics-extra)    continue ;;
                    ettercap-graphical) pkg="ettercap" ;;
                    ruby-dev)           pkg="ruby-devel" ;;
                    golang-go)          pkg="golang" ;;
                    libimage-exiftool-perl) pkg="perl-Image-ExifTool" ;;
                    adb)                pkg="android-tools" ;;
                    bulk-extractor)     pkg="bulk_extractor" ;;
                    snmp)               pkg="net-snmp-utils" ;;
                    smbclient)          pkg="samba-client" ;;
                    imagemagick)        pkg="ImageMagick" ;;
                    upx-ucl)            pkg="upx" ;;
                    gqrx-sdr)           pkg="gqrx" ;;
                    spooftooph|cewl|hashid|wapiti|zmap|rizin) continue ;;
                    sentrypeer|chaosreader|apparmor-utils) continue ;;
                    smali|apksigner|zipalign) continue ;;
                    hcxdumptool|mfcuk|mfoc|rtl-433|libnfc-dev|avrdude) continue ;;
                    scrcpy)             continue ;;
                    auditd)             pkg="audit" ;;
                    checksec)           pkg="checksec" ;;
                    sonic-visualiser)   pkg="sonic-visualiser" ;;
                    qemu-user-static)   pkg="qemu-user-static" ;;
                    qemu-system-x86)    pkg="qemu-system-x86" ;;
                    libseccomp-dev)     pkg="libseccomp-devel" ;;
                    binutils-dev)       pkg="binutils-devel" ;;
                    libedit-dev)        pkg="libedit-devel" ;;
                    liblzma-dev)        pkg="xz-devel" ;;
                    libkrb5-dev)        pkg="krb5-devel" ;;
                    libsctp-dev)        pkg="lksctp-tools-devel" ;;
                    libnfnetlink-dev)   pkg="libnfnetlink-devel" ;;
                    libgmp-dev)         pkg="gmp-devel" ;;
                    libecm-dev)         pkg="gmp-ecm-devel" ;;
                    libglib2.0-dev)     pkg="glib2-devel" ;;
                    libreadline-dev)    pkg="readline-devel" ;;
                    libsqlite3-dev)     pkg="sqlite-devel" ;;
                    libcurl4-openssl-dev) pkg="libcurl-devel" ;;
                    libldap2-dev)       pkg="openldap-devel" ;;
                    libsasl2-dev)       pkg="cyrus-sasl-devel" ;;
                    llvm-dev)           pkg="llvm-devel" ;;
                    libpixman-1-dev)    pkg="pixman-devel" ;;
                    sslsplit)           pkg="sslsplit" ;;
                esac
                ;;
            pacman)
                case "$pkg" in
                    netcat-openbsd)     pkg="gnu-netcat" ;;
                    dnsutils)           pkg="bind" ;;
                    build-essential)    pkg="base-devel" ;;
                    python3-pip)        pkg="python-pip" ;;
                    python3-venv|python3-dev) continue ;;
                    python3)            pkg="python" ;;
                    default-jdk)        pkg="jdk-openjdk" ;;
                    zlib1g-dev)         pkg="zlib" ;;
                    libxml2-dev)        pkg="libxml2" ;;
                    libxslt1-dev)       pkg="libxslt" ;;
                    libpcap-dev)        pkg="libpcap" ;;
                    libssl-dev)         pkg="openssl" ;;
                    libffi-dev)         pkg="libffi" ;;
                    wireshark-common)   pkg="wireshark-cli" ;;
                    proxychains4)       pkg="proxychains-ng" ;;
                    forensics-extra)    continue ;;
                    ettercap-graphical) pkg="ettercap" ;;
                    ruby-dev)           continue ;;
                    golang-go)          pkg="go" ;;
                    libimage-exiftool-perl) pkg="perl-image-exiftool" ;;
                    adb)                pkg="android-tools" ;;
                    bulk-extractor)     pkg="bulk_extractor" ;;
                    snmp)               pkg="net-snmp" ;;
                    spooftooph|cewl|hashid|wapiti) continue ;;
                    sentrypeer|chaosreader|apparmor-utils) continue ;;
                    smali|apksigner|zipalign) continue ;;
                    mfcuk|mfoc|libnfc-dev) continue ;;
                    rtl-433)            pkg="rtl_433" ;;
                    auditd)             pkg="audit" ;;
                    upx-ucl)            pkg="upx" ;;
                    qemu-user-static)   pkg="qemu-user-static" ;;
                    qemu-system-x86)    pkg="qemu-system-x86" ;;
                    libseccomp-dev)     pkg="libseccomp" ;;
                    binutils-dev)       pkg="binutils-devel" ;;
                    libedit-dev)        pkg="libedit" ;;
                    liblzma-dev)        pkg="xz" ;;
                    libkrb5-dev)        pkg="krb5" ;;
                    libsctp-dev)        pkg="lksctp-tools" ;;
                    libnfnetlink-dev)   pkg="libnfnetlink" ;;
                    libgmp-dev)         pkg="gmp" ;;
                    libecm-dev)         continue ;;
                    libglib2.0-dev)     pkg="glib2" ;;
                    libreadline-dev)    pkg="readline" ;;
                    libsqlite3-dev)     pkg="sqlite" ;;
                    libcurl4-openssl-dev) pkg="curl" ;;
                    libldap2-dev)       pkg="libldap" ;;
                    libsasl2-dev)       pkg="libsasl" ;;
                    llvm-dev)           pkg="llvm" ;;
                    libpixman-1-dev)    pkg="pixman" ;;
                    sslsplit)           pkg="sslsplit" ;;
                esac
                ;;
            zypper)
                case "$pkg" in
                    netcat-openbsd)     pkg="netcat-openbsd" ;;
                    dnsutils)           pkg="bind-utils" ;;
                    build-essential)
                        zypper install -y -t pattern devel_basis >> "$LOG_FILE" 2>&1 || true
                        continue ;;
                    default-jdk)        pkg="java-17-openjdk-devel" ;;
                    zlib1g-dev)         pkg="zlib-devel" ;;
                    libxml2-dev)        pkg="libxml2-devel" ;;
                    libxslt1-dev)       pkg="libxslt-devel" ;;
                    libpcap-dev)        pkg="libpcap-devel" ;;
                    libssl-dev)         pkg="libopenssl-devel" ;;
                    libffi-dev)         pkg="libffi-devel" ;;
                    python3-dev)        pkg="python3-devel" ;;
                    forensics-extra)    continue ;;
                    ettercap-graphical) pkg="ettercap" ;;
                    ruby-dev)           pkg="ruby-devel" ;;
                    golang-go)          pkg="go" ;;
                    libimage-exiftool-perl) pkg="exiftool" ;;
                    adb)                pkg="android-tools" ;;
                    bulk-extractor)     pkg="bulk_extractor" ;;
                    snmp)               pkg="net-snmp" ;;
                    smbclient)          pkg="samba-client" ;;
                    imagemagick)        pkg="ImageMagick" ;;
                    upx-ucl)            pkg="upx" ;;
                    spooftooph|cewl|hashid|wapiti|zmap|checksec|rizin|sagemath|sonic-visualiser) continue ;;
                    sentrypeer|chaosreader|apparmor-utils) continue ;;
                    smali|apksigner|zipalign|scrcpy) continue ;;
                    hackrf|hcxdumptool|mfcuk|mfoc|rtl-433|libnfc-dev|avrdude) continue ;;
                    auditd)             pkg="audit" ;;
                    qemu-user-static)   pkg="qemu-linux-user" ;;
                    qemu-system-x86)    pkg="qemu-x86" ;;
                    libseccomp-dev)     pkg="libseccomp-devel" ;;
                    binutils-dev)       pkg="binutils-devel" ;;
                    libedit-dev)        pkg="libedit-devel" ;;
                    liblzma-dev)        pkg="xz-devel" ;;
                    libkrb5-dev)        pkg="krb5-devel" ;;
                    libsctp-dev)        pkg="lksctp-tools-devel" ;;
                    libnfnetlink-dev)   pkg="libnfnetlink-devel" ;;
                    libgmp-dev)         pkg="gmp-devel" ;;
                    libecm-dev)         pkg="gmp-ecm-devel" ;;
                    libglib2.0-dev)     pkg="glib2-devel" ;;
                    libreadline-dev)    pkg="readline-devel" ;;
                    libsqlite3-dev)     pkg="sqlite3-devel" ;;
                    libcurl4-openssl-dev) pkg="libcurl-devel" ;;
                    libldap2-dev)       pkg="openldap2-devel" ;;
                    libsasl2-dev)       pkg="cyrus-sasl-devel" ;;
                    llvm-dev)           pkg="llvm-devel" ;;
                    libpixman-1-dev)    pkg="libpixman-1-devel" ;;
                    sslsplit)           pkg="sslsplit" ;;
                esac
                ;;
            pkg)
                case "$pkg" in
                    # Build tools — Termux uses clang, no gcc (two packages)
                    build-essential)    new_arr+=("clang" "make"); continue ;;
                    # Python — Termux uses 'python' (pip/venv/dev included)
                    python3)            pkg="python" ;;
                    python3-pip|python3-venv|python3-dev) continue ;;
                    # Runtimes
                    golang-go)          pkg="golang" ;;
                    default-jdk)        pkg="openjdk-17" ;;
                    ruby-dev)           continue ;;  # included in ruby
                    # Dev libraries — Termux drops the -dev suffix
                    libpcap-dev)        pkg="libpcap" ;;
                    libssl-dev)         pkg="openssl" ;;
                    libffi-dev)         pkg="libffi" ;;
                    zlib1g-dev)         pkg="zlib" ;;
                    libxml2-dev)        pkg="libxml2" ;;
                    libxslt1-dev)       pkg="libxslt" ;;
                    libglib2.0-dev)     pkg="glib" ;;
                    libreadline-dev)    pkg="readline" ;;
                    libsqlite3-dev)     pkg="libsqlite" ;;
                    libcurl4-openssl-dev) pkg="libcurl" ;;
                    libedit-dev)        pkg="libedit" ;;
                    liblzma-dev)        pkg="xz-utils" ;;
                    libgmp-dev)         pkg="libgmp" ;;
                    # Unavailable dev libs on Termux — skip
                    libseccomp-dev|binutils-dev|libkrb5-dev|libsctp-dev) continue ;;
                    libnfnetlink-dev|libecm-dev|libldap2-dev|libsasl2-dev) continue ;;
                    llvm-dev|libpixman-1-dev) continue ;;
                    # Networking tools — Termux bundles ncat with nmap
                    netcat-openbsd)     pkg="nmap" ;;
                    dnsutils)           pkg="dnsutils" ;;
                    proxychains4)       pkg="proxychains-ng" ;;
                    # Unavailable tools on Termux
                    spooftooph|cewl|hashid|wapiti) continue ;;
                    wireshark-common|ettercap-graphical) continue ;;
                    kismet|crackle|asleap|fern-wifi-cracker) continue ;;
                    forensics-extra|bulk-extractor) continue ;;
                    auditd|apparmor-utils) continue ;;
                    adb|smali|scrcpy|apksigner|zipalign) continue ;;
                    qemu-user-static|qemu-system-x86) continue ;;
                    sagemath|ghidra|rizin) continue ;;
                    hackrf|hcxdumptool|mfcuk|mfoc|rtl-433|libnfc-dev|avrdude) continue ;;
                    sentrypeer|chaosreader) continue ;;
                    sonic-visualiser|gqrx-sdr|sslsplit) continue ;;
                    checksec|rsmangler|zmap) continue ;;
                    snmp)               pkg="net-snmp" ;;
                    imagemagick)        pkg="imagemagick" ;;
                    upx-ucl)            pkg="upx" ;;
                    libimage-exiftool-perl) pkg="exiftool" ;;
                    dos2unix)           pkg="dos2unix" ;;
                esac
                ;;
        esac
        new_arr+=("$pkg")
    done
    if [[ ${#new_arr[@]} -gt 0 ]]; then
        arr=("${new_arr[@]}")
    else
        arr=()
    fi
}

# Batch APT install with progress and distro fixup
install_apt_batch() {
    local label="$1"; shift
    local -a packages=("$@")

    fixup_package_names packages

    local total=${#packages[@]}
    [[ "$total" -eq 0 ]] && return 0
    local failed=0

    log_debug "install_apt_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    log_info "Installing ${label} ($total packages)..."

    # Fast path: try all packages in one transaction (~50-80% faster)
    if pkg_install "${packages[@]}" >> "$LOG_FILE" 2>&1; then
        # All succeeded — track versions in bulk
        for pkg in "${packages[@]}"; do
            track_version "$pkg" "apt" "system"
        done
        echo ""
        log_success "${label}: ${total}/${total} installed (0 failed) [batch]"
    else
        # Fallback: one-by-one to identify broken packages
        log_warn "${label}: batch install failed — falling back to per-package install"
        local current=0
        for pkg in "${packages[@]}"; do
            current=$((current + 1))
            show_progress "$current" "$total" "$pkg"
            if ! pkg_install "$pkg" >> "$LOG_FILE" 2>&1; then
                log_error "Failed: $pkg"
                failed=$((failed + 1))
            else
                track_version "$pkg" "apt" "system"
            fi
        done
        echo ""
        log_success "${label}: $((total - failed))/$total installed ($failed failed) [fallback]"
    fi

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_apt_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Batch pipx install
install_pipx_batch() {
    local label="$1"; shift
    local -a tools=("$@")
    local total=${#tools[@]}
    [[ "$total" -eq 0 ]] && return 0

    log_debug "install_pipx_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    ensure_pipx
    # Cache the installed list once to avoid calling pipx list per tool
    local installed_pipx=""
    if command_exists pipx; then
        installed_pipx=$(pipx list --short 2>/dev/null || true)
    fi

    log_info "Installing ${label} ($total pipx tools)..."

    # pipx uses shared venv state — always sequential to avoid lock conflicts
    local current=0 failed=0 skipped=0
    for tool in "${tools[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$tool"
        if echo "$installed_pipx" | grep -qi "^${tool} "; then
            skipped=$((skipped + 1))
            track_version "$tool" "pipx" "existing"
            continue
        fi
        if ! pipx_install "$tool" >> "$LOG_FILE" 2>&1; then
            log_error "Failed pipx: $tool"
            failed=$((failed + 1))
        else
            track_version "$tool" "pipx" "latest"
        fi
    done

    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_pipx_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Batch Go install
install_go_batch() {
    local label="$1"; shift
    local -a tools=("$@")
    local total=${#tools[@]}
    [[ "$total" -eq 0 ]] && return 0

    if ! command_exists go; then
        log_warn "Go not found — skipping ${label}"
        return 0
    fi
    # GOPATH and GOBIN are set in common.sh (GOPATH=$GOPATH, GOBIN=$GOBIN)

    log_debug "install_go_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    log_info "Installing ${label} ($total Go tools)..."

    if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
        # --- Parallel mode ---
        local _results_dir; _results_dir=$(mktemp -d)

        for tool in "${tools[@]}"; do
            local name
            name=$(_go_bin_name "$tool")

            # Skip-check in main process
            if command_exists "$name"; then
                printf 'skip\nexisting\n' > "$_results_dir/$name"
                continue
            fi

            _wait_for_job_slot

            (
                if go install "$tool" >> "$LOG_FILE" 2>&1; then
                    printf 'ok\nlatest\n' > "$_results_dir/$name"
                else
                    printf 'fail\n\n' > "$_results_dir/$name"
                fi
            ) &
        done
        wait

        _collect_parallel_results "$_results_dir" "go"
        # shellcheck disable=SC2154  # _par_failed/_par_skipped set by _collect_parallel_results
        local failed=$_par_failed skipped=$_par_skipped
    else
        # --- Sequential mode (original) ---
        local current=0 failed=0 skipped=0
        for tool in "${tools[@]}"; do
            current=$((current + 1))
            local name
            name=$(_go_bin_name "$tool")
            show_progress "$current" "$total" "$name"
            # Skip if binary already exists (GOBIN is in PATH, so command_exists suffices)
            if command_exists "$name"; then
                skipped=$((skipped + 1))
                track_version "$name" "go" "existing"
                continue
            fi
            if ! go install "$tool" >> "$LOG_FILE" 2>&1; then
                log_error "Failed go: $name"
                failed=$((failed + 1))
            else
                track_version "$name" "go" "latest"
            fi
        done
    fi

    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_go_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Batch cargo install
install_cargo_batch() {
    local label="$1"; shift
    local -a crates=("$@")
    local total=${#crates[@]}
    [[ "$total" -eq 0 ]] && return 0

    if ! command_exists cargo; then
        log_warn "Cargo not found — skipping ${label}"
        log_warn "Install Rust first: https://rustup.rs/"
        return 0
    fi
    export PATH="$HOME/.cargo/bin:$PATH"

    log_debug "install_cargo_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    log_info "Installing ${label} ($total Rust tools)..."

    # cargo uses a shared registry lock — always sequential to avoid conflicts
    local current=0 failed=0 skipped=0
    for crate in "${crates[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$crate"
        if command_exists "$crate"; then
            skipped=$((skipped + 1))
            track_version "$crate" "cargo" "existing"
            continue
        fi
        if ! cargo install "$crate" >> "$LOG_FILE" 2>&1; then
            log_error "Failed cargo: $crate"
            failed=$((failed + 1))
        else
            if [[ -f "$HOME/.cargo/bin/$crate" ]]; then
                ln -sf "$HOME/.cargo/bin/$crate" "$PIPX_BIN_DIR/$crate" 2>/dev/null || true
            fi
            track_version "$crate" "cargo" "latest"
        fi
    done

    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_cargo_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Batch gem install
install_gem_batch() {
    local label="$1"; shift
    local -a gems=("$@")
    local total=${#gems[@]}
    [[ "$total" -eq 0 ]] && return 0

    if ! command_exists gem; then
        log_warn "Ruby gem not found — skipping ${label}"
        return 0
    fi

    log_debug "install_gem_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    # Cache the installed list once
    local installed_gems=""
    installed_gems=$(gem list --no-details 2>/dev/null || true)

    log_info "Installing ${label} ($total Ruby gems)..."

    # gem uses a shared gem dir — always sequential to avoid conflicts
    local current=0 failed=0 skipped=0
    for gem_name in "${gems[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$gem_name"
        if echo "$installed_gems" | grep -q "^${gem_name} "; then
            skipped=$((skipped + 1))
            track_version "$gem_name" "gem" "existing"
            continue
        fi
        if gem install "$gem_name" --no-document >> "$LOG_FILE" 2>&1; then
            track_version "$gem_name" "gem" "latest"
        else
            log_error "Failed gem: $gem_name"
            failed=$((failed + 1))
        fi
    done

    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_gem_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Post-clone setup for git repos
# Creates isolated venvs for Python repos with requirements.txt.
# Does NOT execute setup.py/pyproject.toml (supply-chain risk: arbitrary code as root).
# Only installs pinned dependencies from requirements.txt into the venv.
setup_git_repo() {
    local dest="$1"
    local name
    name=$(basename "$dest")

    # Python project with requirements.txt: create isolated venv + install deps
    # NOTE: Only requirements.txt is installed — setup.py is NOT executed.
    # This avoids running arbitrary code from cloned repos as root.
    if [[ -f "$dest/requirements.txt" ]]; then
        if [[ ! -d "$dest/venv" ]]; then
            python3 -m venv "$dest/venv" 2>>"$LOG_FILE" || return 0
        fi
        "$dest/venv/bin/pip" install -q --upgrade pip >> "$LOG_FILE" 2>&1 || true
        "$dest/venv/bin/pip" install -q -r "$dest/requirements.txt" >> "$LOG_FILE" 2>&1 || true
    fi

    # Create wrapper scripts in $PIPX_BIN_DIR for discoverable entry points
    # Look for executable scripts the venv created, or standalone .py scripts
    if [[ -d "$dest/venv/bin" ]]; then
        for candidate in "$dest/venv/bin/$name" "$dest/venv/bin/${name,,}" "$dest/venv/bin/${name//-/_}"; do
            if [[ -f "$candidate" ]] && [[ -x "$candidate" ]]; then
                ln -sf "$candidate" "$PIPX_BIN_DIR/$(basename "$candidate")" 2>/dev/null || true
                break
            fi
        done
    fi

    # Standalone Python script: make executable
    if [[ -f "$dest/$name.py" ]] && [[ ! -d "$dest/venv" ]]; then
        chmod +x "$dest/$name.py" 2>/dev/null || true
        # Create a wrapper in PATH
        cat > "$PIPX_BIN_DIR/$name" 2>/dev/null << PYWRAP || true
#!/bin/bash
exec python3 "$dest/$name.py" "\$@"
PYWRAP
        chmod +x "$PIPX_BIN_DIR/$name" 2>/dev/null || true
    fi

    # Standalone shell script: symlink to PATH
    if [[ -f "$dest/$name.sh" ]] && [[ ! -L "$PIPX_BIN_DIR/$name" ]]; then
        chmod +x "$dest/$name.sh" 2>/dev/null || true
        ln -sf "$dest/$name.sh" "$PIPX_BIN_DIR/$name" 2>/dev/null || true
    fi
}

# Batch git clone with auto-setup
# Usage: install_git_batch "Label" name1=url1 name2=url2 ...
install_git_batch() {
    local label="$1"; shift
    local -a repos=("$@")
    local total=${#repos[@]}
    [[ "$total" -eq 0 ]] && return 0

    log_debug "install_git_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    local base_dir="$GITHUB_TOOL_DIR"
    log_info "Installing ${label} ($total repos)..."

    if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
        # --- Parallel mode ---
        local _results_dir; _results_dir=$(mktemp -d)

        for entry in "${repos[@]}"; do
            local name="${entry%%=*}"
            local url="${entry#*=}"
            local dest="$base_dir/$name"

            _wait_for_job_slot

            (
                local is_existing=false
                [[ -d "$dest/.git" ]] && is_existing=true
                if git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1; then
                    setup_git_repo "$dest" >> "$LOG_FILE" 2>&1 || true
                    if [[ "$is_existing" == "true" ]]; then
                        printf 'skip\nHEAD\n' > "$_results_dir/$name"
                    else
                        printf 'ok\nHEAD\n' > "$_results_dir/$name"
                    fi
                else
                    printf 'fail\n\n' > "$_results_dir/$name"
                fi
            ) &
        done
        wait

        _collect_parallel_results "$_results_dir" "git"
        # shellcheck disable=SC2154  # _par_failed/_par_skipped set by _collect_parallel_results
        local failed=$_par_failed skipped=$_par_skipped
    else
        # Sequential mode (original)
        local current=0 failed=0 skipped=0
        for entry in "${repos[@]}"; do
            current=$((current + 1))
            local name="${entry%%=*}"
            local url="${entry#*=}"
            local dest="$base_dir/$name"
            show_progress "$current" "$total" "$name"
            local is_existing=false
            [[ -d "$dest/.git" ]] && is_existing=true
            if ! git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1; then
                log_error "Failed git: $name"
                failed=$((failed + 1))
            else
                # Auto-setup: venv, requirements, symlinks
                setup_git_repo "$dest" >> "$LOG_FILE" 2>&1 || true
                [[ "$is_existing" == "true" ]] && skipped=$((skipped + 1))
                track_version "$name" "git" "HEAD"
            fi
        done
    fi

    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} updated, ${failed} failed"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_git_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# GitHub API curl options (with optional token auth)
_github_curl_opts() {
    local -a opts=(-sSL)
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        opts+=(-H "Authorization: token $GITHUB_TOKEN")
    fi
    echo "${opts[@]}"
}

# Verify download against release checksum file
# Looks for SHA256 checksum files in the same GitHub release and verifies
# the downloaded file.  Returns 0 on match, 1 on mismatch or missing checksums.
verify_github_checksum() {
    local release_json="$1"
    local file_path="$2"
    local file_name="$3"

    # Look for a checksum asset in the release
    local checksum_url
    checksum_url=$(echo "$release_json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for asset in data.get('assets', []):
    name = asset.get('name', '').lower()
    if any(k in name for k in ('checksums', 'sha256sums', 'sha256sum', 'sha256')):
        print(asset['browser_download_url'])
        break
" 2>>"$LOG_FILE")

    if [[ -z "$checksum_url" ]]; then
        log_warn "No checksum file in release for $file_name — skipping verification"
        return 1
    fi

    local checksums
    # shellcheck disable=SC2046  # Intentional word splitting of curl options
    checksums=$(curl $(_github_curl_opts) "$checksum_url" 2>>"$LOG_FILE")
    if [[ -z "$checksums" ]]; then
        log_warn "Failed to download checksums for $file_name"
        return 1
    fi

    local expected_hash
    expected_hash=$(echo "$checksums" | grep "$file_name" | awk '{print $1}' | head -1)
    if [[ -z "$expected_hash" ]]; then
        log_warn "No checksum entry for $file_name in checksums file"
        return 1
    fi

    local actual_hash
    actual_hash=$(sha256sum "$file_path" | awk '{print $1}')
    if [[ "$actual_hash" == "$expected_hash" ]]; then
        log_success "Checksum verified: $file_name"
        return 0
    else
        log_error "Checksum MISMATCH for $file_name (expected: ${expected_hash:0:16}…, got: ${actual_hash:0:16}…)"
        # Signal hard failure — caller checks this marker file
        touch "$(dirname "$file_path")/.checksum_mismatch"
        return 1
    fi
}

# Download GitHub release binary
# Usage: download_github_release "owner/repo" "binary_name" "filename_pattern" [dest_dir]
download_github_release() {
    local repo="$1"
    local binary="$2"
    local pattern="$3"
    local dest_dir="${4:-$PIPX_BIN_DIR}"

    # Check if already installed
    if command_exists "$binary"; then
        log_success "Already installed: $binary"
        track_version "$binary" "binary" "existing"
        return 0
    fi

    # Ensure unzip is available for .zip archives
    if ! command_exists unzip; then
        log_warn "unzip not found — installing..."
        pkg_install unzip >> "$LOG_FILE" 2>&1 || true
    fi

    # Adapt arch tokens in the pattern to match the current system architecture
    if [[ "$SYS_ARCH" != "amd64" ]]; then
        pattern="${pattern//amd64/$SYS_ARCH}"
        pattern="${pattern//x86_64/$SYS_ARCH_ALT}"
    fi

    log_debug "download_github_release: repo=$repo binary=$binary pattern=$pattern"
    log_info "Downloading $binary from $repo releases..."
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local release_json
    # shellcheck disable=SC2046  # Intentional word splitting of curl options
    release_json=$(curl $(_github_curl_opts) "$api_url" 2>>"$LOG_FILE")
    if [[ -z "$release_json" ]]; then
        log_error "Could not fetch release info for $binary"
        return 1
    fi

    # Extract actual release tag for version tracking
    local release_tag=""
    release_tag=$(echo "$release_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null || true)

    # Parse download URL using Python (portable — no grep -P dependency)
    local download_url
    download_url=$(echo "$release_json" | python3 -c "
import json, sys, re
data = json.load(sys.stdin)
for asset in data.get('assets', []):
    if re.search(r'''$pattern''', asset.get('name', '')):
        print(asset['browser_download_url'])
        break
" 2>>"$LOG_FILE")

    if [[ -z "$download_url" ]]; then
        log_error "Could not find release for $binary (pattern: $pattern)"
        return 1
    fi

    log_debug "download_github_release: URL=$download_url"

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local asset_name
    asset_name=$(basename "$download_url")
    if ! curl -sSL -o "$tmp_dir/$asset_name" "$download_url" >> "$LOG_FILE" 2>&1; then
        log_error "Download failed: $binary"
        rm -rf "$tmp_dir"
        return 1
    fi

    # Verify checksum — fail-closed on mismatch, warn-only if no checksums available
    if ! verify_github_checksum "$release_json" "$tmp_dir/$asset_name" "$asset_name"; then
        # Check if it was a real mismatch (exit code 2) vs missing checksums (exit code 1)
        if [[ -f "$tmp_dir/.checksum_mismatch" ]]; then
            log_error "Aborting install of $binary due to checksum mismatch"
            rm -rf "$tmp_dir"
            return 1
        fi
        # No checksum file available — warn but continue
    fi

    # Handle archive types
    case "$download_url" in
        *.tar.gz|*.tgz)
            tar xzf "$tmp_dir/$asset_name" -C "$tmp_dir" 2>>"$LOG_FILE" ;;
        *.zip)
            unzip -qo "$tmp_dir/$asset_name" -d "$tmp_dir" 2>>"$LOG_FILE" ;;
        *.deb)
            if [[ "$PKG_MANAGER" != "apt" && "$PKG_MANAGER" != "pkg" ]]; then
                log_error "$binary is a .deb package — not supported on $PKG_MANAGER"
                rm -rf "$tmp_dir"
                return 1
            fi
            # Script runs as root on Linux (check_root); Termux runs without root
            if ! dpkg -i "$tmp_dir/$asset_name" >> "$LOG_FILE" 2>&1; then
                if ! apt-get install -f -y >> "$LOG_FILE" 2>&1; then
                    log_error "Failed to install $binary (.deb) — dpkg and dependency fix both failed"
                    rm -rf "$tmp_dir"
                    return 1
                fi
            fi
            rm -rf "$tmp_dir"
            if command_exists "$binary"; then
                log_success "Installed: $binary (.deb)"
                track_version "$binary" "binary" "${release_tag:-latest}"
            else
                log_error "Install failed: $binary (.deb) — binary not found after dpkg"
                return 1
            fi
            return 0 ;;
        *.jar)
            mkdir -p "$dest_dir" 2>/dev/null || true
            cp "$tmp_dir/$asset_name" "$dest_dir/$binary.jar"
            # Create wrapper script
            cat > "$PIPX_BIN_DIR/$binary" << WRAPPER
#!/bin/bash
exec java -jar "$dest_dir/$binary.jar" "\$@"
WRAPPER
            chmod +x "$PIPX_BIN_DIR/$binary"
            rm -rf "$tmp_dir"
            log_success "Installed: $binary (.jar)"
            track_version "$binary" "binary" "${release_tag:-latest}"
            return 0 ;;
        *)
            chmod +x "$tmp_dir/$asset_name" ;;
    esac

    # Find the binary in extracted files
    local found
    found=$(find "$tmp_dir" -name "$binary" -type f 2>/dev/null | head -1)
    if [[ -z "$found" ]]; then
        # Try finding any executable
        found=$(find "$tmp_dir" -type f -executable 2>/dev/null | head -1)
    fi
    if [[ -z "$found" ]]; then
        # Last resort: the downloaded file itself
        found="$tmp_dir/$asset_name"
    fi

    if [[ "$dest_dir" != "$PIPX_BIN_DIR" ]]; then
        # Custom dest_dir (e.g. /opt/jadx): copy entire extracted tree there
        mkdir -p "$dest_dir" 2>/dev/null || true
        cp -a "$tmp_dir"/* "$dest_dir/" 2>/dev/null || true
        # Find the binary in dest_dir (NOT tmp_dir — it's about to be deleted)
        # Some tools ship with .sh extension (e.g. d2j-dex2jar.sh), so try both
        local dest_bin=""
        for candidate in \
            "$dest_dir/bin/$binary" \
            "$dest_dir/bin/${binary}.sh" \
            "$dest_dir/$binary" \
            "$dest_dir/${binary}.sh"; do
            if [[ -f "$candidate" ]]; then
                dest_bin="$candidate"
                break
            fi
        done
        if [[ -z "$dest_bin" ]]; then
            dest_bin=$(find "$dest_dir" \( -name "$binary" -o -name "${binary}.sh" \) -type f 2>/dev/null | head -1)
        fi
        if [[ -n "$dest_bin" ]]; then
            chmod +x "$dest_bin" 2>/dev/null || true
            ln -sf "$dest_bin" "$PIPX_BIN_DIR/$binary" 2>/dev/null || true
        fi
    else
        install -m 755 "$found" "$dest_dir/$binary" 2>>"$LOG_FILE"
    fi
    rm -rf "$tmp_dir"

    if command_exists "$binary"; then
        log_success "Installed: $binary"
        track_version "$binary" "binary" "${release_tag:-latest}"
    else
        # Binary may be in dest_dir but not in PATH — still a success if file exists
        if [[ -f "$dest_dir/$binary" ]] || [[ -f "$dest_dir/bin/$binary" ]]; then
            log_success "Installed: $binary (in $dest_dir)"
            track_version "$binary" "binary" "${release_tag:-latest}"
        else
            log_error "Install failed: $binary"
            return 1
        fi
    fi
}

# Download GitHub release binary (update mode — no skip)
# Same as download_github_release() but does NOT skip already-installed binaries.
# Used by scripts/update.sh to force re-download when a new version is detected.
# Returns the release tag via the global _RELEASE_TAG variable.
_RELEASE_TAG=""
download_github_release_update() {
    local repo="$1"
    local binary="$2"
    local pattern="$3"
    local dest_dir="${4:-$PIPX_BIN_DIR}"
    _RELEASE_TAG=""

    # Ensure unzip is available for .zip archives
    if ! command_exists unzip; then
        pkg_install unzip >> "$LOG_FILE" 2>&1 || true
    fi

    # Adapt arch tokens in the pattern to match the current system architecture
    if [[ "$SYS_ARCH" != "amd64" ]]; then
        pattern="${pattern//amd64/$SYS_ARCH}"
        pattern="${pattern//x86_64/$SYS_ARCH_ALT}"
    fi

    log_debug "download_github_release_update: repo=$repo binary=$binary pattern=$pattern"
    log_info "Downloading $binary from $repo releases..."
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local release_json
    # shellcheck disable=SC2046  # Intentional word splitting of curl options
    release_json=$(curl $(_github_curl_opts) "$api_url" 2>>"$LOG_FILE")
    if [[ -z "$release_json" ]]; then
        log_error "Could not fetch release info for $binary"
        return 1
    fi

    # Extract the release tag
    _RELEASE_TAG=$(echo "$release_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null)

    # Parse download URL using Python (portable — no grep -P dependency)
    local download_url
    download_url=$(echo "$release_json" | python3 -c "
import json, sys, re
data = json.load(sys.stdin)
for asset in data.get('assets', []):
    if re.search(r'''$pattern''', asset.get('name', '')):
        print(asset['browser_download_url'])
        break
" 2>>"$LOG_FILE")

    if [[ -z "$download_url" ]]; then
        log_error "Could not find release for $binary (pattern: $pattern)"
        return 1
    fi

    log_debug "download_github_release_update: URL=$download_url"

    local tmp_dir
    tmp_dir=$(mktemp -d)
    local asset_name
    asset_name=$(basename "$download_url")
    if ! curl -sSL -o "$tmp_dir/$asset_name" "$download_url" >> "$LOG_FILE" 2>&1; then
        log_error "Download failed: $binary"
        rm -rf "$tmp_dir"
        return 1
    fi

    # Verify checksum — fail-closed on mismatch, warn-only if no checksums available
    if ! verify_github_checksum "$release_json" "$tmp_dir/$asset_name" "$asset_name"; then
        if [[ -f "$tmp_dir/.checksum_mismatch" ]]; then
            log_error "Aborting update of $binary due to checksum mismatch"
            rm -rf "$tmp_dir"
            return 1
        fi
    fi

    # Handle archive types
    case "$download_url" in
        *.tar.gz|*.tgz)
            tar xzf "$tmp_dir/$asset_name" -C "$tmp_dir" 2>>"$LOG_FILE" ;;
        *.zip)
            unzip -qo "$tmp_dir/$asset_name" -d "$tmp_dir" 2>>"$LOG_FILE" ;;
        *.deb)
            if [[ "$PKG_MANAGER" != "apt" && "$PKG_MANAGER" != "pkg" ]]; then
                log_error "$binary is a .deb package — not supported on $PKG_MANAGER"
                rm -rf "$tmp_dir"
                return 1
            fi
            if ! dpkg -i "$tmp_dir/$asset_name" >> "$LOG_FILE" 2>&1; then
                if ! apt-get install -f -y >> "$LOG_FILE" 2>&1; then
                    rm -rf "$tmp_dir"
                    return 1
                fi
            fi
            rm -rf "$tmp_dir"
            return 0 ;;
        *.jar)
            mkdir -p "$dest_dir" 2>/dev/null || true
            cp "$tmp_dir/$asset_name" "$dest_dir/$binary.jar"
            cat > "$PIPX_BIN_DIR/$binary" << WRAPPER
#!/bin/bash
exec java -jar "$dest_dir/$binary.jar" "\$@"
WRAPPER
            chmod +x "$PIPX_BIN_DIR/$binary"
            rm -rf "$tmp_dir"
            return 0 ;;
        *)
            chmod +x "$tmp_dir/$asset_name" ;;
    esac

    # Find the binary in extracted files
    local found
    found=$(find "$tmp_dir" -name "$binary" -type f 2>/dev/null | head -1)
    if [[ -z "$found" ]]; then
        found=$(find "$tmp_dir" -type f -executable 2>/dev/null | head -1)
    fi
    if [[ -z "$found" ]]; then
        found="$tmp_dir/$asset_name"
    fi

    if [[ "$dest_dir" != "$PIPX_BIN_DIR" ]]; then
        mkdir -p "$dest_dir" 2>/dev/null || true
        cp -a "$tmp_dir"/* "$dest_dir/" 2>/dev/null || true
        local dest_bin=""
        for candidate in \
            "$dest_dir/bin/$binary" \
            "$dest_dir/bin/${binary}.sh" \
            "$dest_dir/$binary" \
            "$dest_dir/${binary}.sh"; do
            if [[ -f "$candidate" ]]; then
                dest_bin="$candidate"
                break
            fi
        done
        if [[ -z "$dest_bin" ]]; then
            dest_bin=$(find "$dest_dir" \( -name "$binary" -o -name "${binary}.sh" \) -type f 2>/dev/null | head -1)
        fi
        if [[ -n "$dest_bin" ]]; then
            chmod +x "$dest_bin" 2>/dev/null || true
            ln -sf "$dest_bin" "$PIPX_BIN_DIR/$binary" 2>/dev/null || true
        fi
    else
        install -m 755 "$found" "$dest_dir/$binary" 2>>"$LOG_FILE"
    fi
    rm -rf "$tmp_dir"
    return 0
}

# Docker image pull
docker_pull() {
    local image="$1"
    local name="$2"

    if ! command_exists docker; then
        log_warn "Docker not installed — skipping $name"
        return 1
    fi

    log_info "Pulling Docker image: $name..."
    if docker pull "$image" >> "$LOG_FILE" 2>&1; then
        log_success "Docker: $name ready"
        track_version "$name" "docker" "$image"
    else
        log_error "Docker pull failed: $name"
        TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        return 1
    fi
}

# Version tracking
track_version() {
    local tool="$1"
    local method="$2"
    local version="$3"
    local version_file="${VERSION_FILE:-$SCRIPT_DIR/.versions}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Create version file if it doesn't exist
    [[ -f "$version_file" ]] || echo "# tool|method|version|last_updated" > "$version_file"

    # Remove existing entry for this tool
    if grep -q "^${tool}|" "$version_file" 2>/dev/null; then
        sed -i "/^${tool}|/d" "$version_file"
    fi

    echo "${tool}|${method}|${version}|${timestamp}" >> "$version_file"
}

# Build from source helper
build_from_source() {
    local name="$1"
    local url="$2"
    local build_cmd="$3"
    local dest="$GITHUB_TOOL_DIR/$name"

    # Termux: build-from-source tools assume glibc/x86 — skip entirely
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        log_warn "Skipping build-from-source on Termux: $name"
        return 0
    fi

    if ! git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1; then
        log_error "Clone failed: $name"
        TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        return 1
    fi
    # Run build in a subshell to avoid changing the caller's working directory.
    # Uses bash -c to support multi-step commands (e.g. "cmake . && make").
    if (cd "$dest" && bash -c "$build_cmd") >> "$LOG_FILE" 2>&1; then
        log_success "Built: $name"
        track_version "$name" "source" "HEAD"
    else
        log_error "Build failed: $name"
        TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        return 1
    fi
}

# Binary release registry (single source of truth) 
# Format: "repo|binary|pattern|dest_dir" (dest_dir optional, defaults to $PIPX_BIN_DIR)
# Used by modules for install and scripts/update.sh for updates.
BINARY_RELEASES_MISC=(
    "DominicBreuker/pspy|pspy|pspy64$"
    "gophish/gophish|gophish|linux-64bit"
    "trufflesecurity/trufflehog|trufflehog|linux_amd64\\.tar\\.gz"
    "gitleaks/gitleaks|gitleaks|linux_x64\\.tar\\.gz"
)
BINARY_RELEASES_NETWORKING=(
    "nicocha30/ligolo-ng|ligolo-proxy|linux_amd64"
    "nicocha30/ligolo-ng|ligolo-agent|agent.*linux_amd64"
    "fatedier/frp|frp|linux_amd64\\.tar\\.gz"
)
BINARY_RELEASES_RECON=(
    "Findomain/Findomain|findomain|linux"
)
BINARY_RELEASES_WEB=(
    "frohoff/ysoserial|ysoserial|ysoserial-all.jar|${GITHUB_TOOL_DIR}/cybersec-jars"
)
BINARY_RELEASES_REVERSING=(
    "0vercl0k/rp|rp-lin|rp-lin"
    "java-decompiler/jd-gui|jd-gui|jd-gui.*\\.jar|${GITHUB_TOOL_DIR}/cybersec-jars"
)
BINARY_RELEASES_FORENSICS=(
    "WithSecureLabs/chainsaw|chainsaw|x86_64.*linux"
)
BINARY_RELEASES_ENTERPRISE=(
    "ropnop/kerbrute|kerbrute|linux_amd64"
)
BINARY_RELEASES_BLUETEAM=(
    "Velocidex/velociraptor|velociraptor|linux-amd64$"
    "threathunters-io/laurel|laurel|x86_64-glibc"
)
BINARY_RELEASES_CONTAINERS=(
    "aquasecurity/trivy|trivy|Linux-64bit\\.tar\\.gz"
    "anchore/grype|grype|linux_amd64\\.tar\\.gz"
    "anchore/syft|syft|linux_amd64\\.tar\\.gz"
    "Shopify/kubeaudit|kubeaudit|linux_amd64\\.tar\\.gz"
    "kubescape/kubescape|kubescape|linux_amd64\\.tar\\.gz"
    "cdk-team/CDK|cdk|cdk_linux_amd64"
)
BINARY_RELEASES_MALWARE=(
    "mandiant/flare-floss|floss|linux\\.zip"
    "mandiant/capa|capa|linux\\.zip"
)
BINARY_RELEASES_STEGO=(
    "RickdeJager/stegseek|stegseek|\\.deb"
)

# Docker image registry (single source of truth)
# Format: "image|label"
# Used by modules for install and scripts for update/remove/verify.
ALL_DOCKER_IMAGES=(
    "beefproject/beef|BeEF"
    "bcsecurity/empire|Empire"
    "opensecurity/mobile-security-framework-mobsf|MobSF"
    "spiderfoot/spiderfoot|SpiderFoot"
    "specterops/bloodhound|BloodHound CE"
    "strangebee/thehive:latest|TheHive"
    "thehiveproject/cortex:latest|Cortex"
    "trailofbits/echidna|Echidna"
)

# install_binary_releases — install all binary releases from a registry array.
# Usage: install_binary_releases "${BINARY_RELEASES_MISC[@]}"
# Supports parallel downloads when PARALLEL_JOBS > 1 (~3-4x faster, network I/O bound).
# Skipped on Termux/Android — most GitHub release assets are Linux/glibc and won't run.
install_binary_releases() {
    local -a entries=("$@")
    local total=${#entries[@]}
    [[ "$total" -eq 0 ]] && return 0

    # Termux: GitHub release binaries are almost always Linux/glibc — skip entirely
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        log_warn "Skipping $total binary release(s) on Termux (Linux/glibc binaries)"
        return 0
    fi

    log_debug "install_binary_releases: starting with $total items, PARALLEL_JOBS=$PARALLEL_JOBS"
    local _batch_start; _batch_start=$(date +%s)

    if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
        # --- Parallel mode ---
        local _results_dir; _results_dir=$(mktemp -d)

        for _entry in "${entries[@]}"; do
            IFS='|' read -r _repo _binary _pattern _dest <<< "$_entry"
            _dest="${_dest:-$PIPX_BIN_DIR}"

            # Skip-check in main process (avoid spawning a job for already-installed tools)
            if command_exists "$_binary"; then
                log_success "Already installed: $_binary"
                printf 'skip\nexisting\n' > "$_results_dir/$_binary"
                continue
            fi

            _wait_for_job_slot

            (
                if download_github_release "$_repo" "$_binary" "$_pattern" "$_dest" >> "$LOG_FILE" 2>&1; then
                    # Read the actual tag that download_github_release stored
                    local _stored_ver=""
                    _stored_ver=$(grep "^${_binary}|" "$VERSION_FILE" 2>/dev/null | cut -d'|' -f3)
                    printf 'ok\n%s\n' "${_stored_ver:-latest}" > "$_results_dir/$_binary"
                else
                    printf 'fail\n\n' > "$_results_dir/$_binary"
                fi
            ) &
        done
        wait

        _collect_parallel_results "$_results_dir" "binary"
        # shellcheck disable=SC2154  # _par_failed/_par_skipped set by _collect_parallel_results
        local failed=$_par_failed skipped=$_par_skipped
        [[ "$failed" -gt 0 ]] && TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed))
        log_success "Binary releases: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"
    else
        # --- Sequential mode (original) ---
        local failed=0
        for _entry in "${entries[@]}"; do
            IFS='|' read -r _repo _binary _pattern _dest <<< "$_entry"
            if ! download_github_release "$_repo" "$_binary" "$_pattern" "${_dest:-$PIPX_BIN_DIR}"; then
                failed=$((failed + 1))
            fi
        done
        [[ "$failed" -gt 0 ]] && TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed))
    fi

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_binary_releases: completed in ${_batch_elapsed}s"
}

# Install searchsploit symlink
install_searchsploit_symlink() {
    if [[ -f "$GITHUB_TOOL_DIR/exploitdb/searchsploit" ]]; then
        ln -sf "$GITHUB_TOOL_DIR/exploitdb/searchsploit" "$PIPX_BIN_DIR/searchsploit" 2>/dev/null
    fi
}

# Metasploit
install_metasploit() {
    if command_exists msfconsole; then
        log_success "Metasploit already installed"
        return 0
    fi

    # Prefer system package (available on Debian/Kali/Parrot with their repos)
    log_info "Installing Metasploit Framework..."
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        if pkg_install metasploit-framework >> "$LOG_FILE" 2>&1; then
            log_success "Metasploit installed via apt"
            track_version "metasploit" "apt" "system"
            return 0
        fi
        log_warn "metasploit-framework not in apt repos — trying official installer"
    fi

    # Fallback: official Rapid7 installer script (with basic verification)
    local tmp_installer
    tmp_installer=$(mktemp)
    local msf_url="https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb"
    if ! curl -fsSL "$msf_url" -o "$tmp_installer" 2>> "$LOG_FILE"; then
        log_error "Failed to download Metasploit installer"
        rm -f "$tmp_installer"
        return 1
    fi

    # Basic content verification — ensure the script is the Metasploit installer
    if ! grep -q "metasploit" "$tmp_installer" 2>/dev/null; then
        log_error "Metasploit installer content verification failed — aborting"
        rm -f "$tmp_installer"
        return 1
    fi

    chmod 755 "$tmp_installer"
    if "$tmp_installer" >> "$LOG_FILE" 2>&1; then
        log_success "Metasploit installed via Rapid7 script"
        track_version "metasploit" "special" "latest"
        rm -f "$tmp_installer"
        return 0
    fi
    rm -f "$tmp_installer"

    # Second fallback: manually add apt.metasploit.com repo (modern signed-by keyring)
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        log_warn "Rapid7 script failed — trying manual apt.metasploit.com repo setup"
        local _keyring="/usr/share/keyrings/metasploit-framework.gpg"
        curl -fsSL "https://apt.metasploit.com/metasploit-framework.gpg.key" 2>>"$LOG_FILE" \
            | gpg --dearmor 2>/dev/null | tee "$_keyring" >/dev/null 2>&1
        if [[ -f "$_keyring" ]]; then
            # "xenial" is Rapid7's universal release name — it works on all Debian/Ubuntu distros
            echo "deb [signed-by=$_keyring] https://apt.metasploit.com/ xenial main" \
                > /etc/apt/sources.list.d/metasploit-framework.list
            pkg_update >> "$LOG_FILE" 2>&1
            if pkg_install metasploit-framework >> "$LOG_FILE" 2>&1; then
                log_success "Metasploit installed via apt.metasploit.com"
                track_version "metasploit" "apt" "latest"
                return 0
            fi
        fi
    fi

    log_error "All Metasploit installation methods failed"
    rm -f "$tmp_installer"
    TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
    return 1
}

# Burp Suite
# NOTE: Burp Suite requires a GUI installer and cannot be fully automated.
# This downloads the installer and provides instructions for manual completion.
install_burpsuite() {
    if command_exists burpsuite; then
        log_success "Burp Suite already installed"
        return 0
    fi
    local version="$BURP_VERSION"
    local dest_dir="$GITHUB_TOOL_DIR/burpsuite-installer"
    local installer="$dest_dir/burpsuite_community_v${version}_install.sh"

    log_info "Downloading Burp Suite Community v${version}..."
    mkdir -p "$dest_dir"
    if ! wget -q -O "$installer" "https://portswigger.net/burp/releases/download?product=community&version=${version}&type=Linux" 2>> "$LOG_FILE"; then
        log_error "Failed to download Burp Suite"
        TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        return 1
    fi
    chmod +x "$installer"

    log_warn "============================================="
    log_warn "Burp Suite requires MANUAL GUI installation:"
    log_warn "  Run: $installer"
    log_warn "============================================="
    track_version "burpsuite" "special" "$version (downloaded, needs manual install)"
}

# OWASP ZAP
install_zap() {
    if command_exists zaproxy; then
        log_success "OWASP ZAP already installed"
        return 0
    fi
    if snap_available; then
        log_info "Installing OWASP ZAP via snap..."
        if snap_install zaproxy --classic >> "$LOG_FILE" 2>&1; then
            log_success "OWASP ZAP installed"
            track_version "zaproxy" "snap" "latest"
        else
            log_error "OWASP ZAP snap install failed"
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
            return 1
        fi
    else
        log_warn "snap not available — install OWASP ZAP manually"
    fi
}
