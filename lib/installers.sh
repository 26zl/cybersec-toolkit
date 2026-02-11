#!/bin/bash
# =============================================================================
# installers.sh — Install method helpers for cybersec-tools-installer
# Provides batch install functions for: apt, pipx, go, cargo, gem, git, binary, docker
# Source AFTER common.sh
# =============================================================================

# ----- Distro-specific package name translation ------------------------------
fixup_package_names() {
    local -n arr=$1
    local new_arr=()
    for pkg in "${arr[@]}"; do
        case "$PKG_MANAGER" in
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
                    sslsplit)           pkg="sslsplit" ;;
                esac
                ;;
            zypper)
                case "$pkg" in
                    netcat-openbsd)     pkg="netcat-openbsd" ;;
                    dnsutils)           pkg="bind-utils" ;;
                    build-essential)
                        # shellcheck disable=SC2024  # Script runs as root; redirect is fine
                        sudo zypper install -y -t pattern devel_basis >> "$LOG_FILE" 2>&1 || true
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
                    sslsplit)           pkg="sslsplit" ;;
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

# ----- Batch APT install with progress and distro fixup ---------------------
install_apt_batch() {
    local label="$1"; shift
    local -a packages=("$@")

    fixup_package_names packages

    local total=${#packages[@]}
    [[ "$total" -eq 0 ]] && return 0
    local current=0 failed=0 skipped=0

    log_info "Installing ${label} ($total packages)..."
    for pkg in "${packages[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$pkg"
        # apt/dnf/pacman handle already-installed packages gracefully (no-op),
        # but we still track the outcome consistently.
        if ! pkg_install "$pkg" >> "$LOG_FILE" 2>&1; then
            log_error "Failed: $pkg"
            failed=$((failed + 1))
        else
            track_version "$pkg" "apt" "system"
        fi
    done
    echo ""
    log_success "${label}: $((total - failed))/$total installed ($failed failed)"
}

# ----- Batch pipx install ---------------------------------------------------
install_pipx_batch() {
    local label="$1"; shift
    local -a tools=("$@")
    local total=${#tools[@]}
    [[ "$total" -eq 0 ]] && return 0
    local current=0 failed=0 skipped=0

    ensure_pipx
    # Cache the installed list once to avoid calling pipx list per tool
    local installed_pipx=""
    if command_exists pipx; then
        installed_pipx=$(pipx list --short 2>/dev/null || true)
    fi

    log_info "Installing ${label} ($total pipx tools)..."
    for tool in "${tools[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$tool"
        # Skip if already installed
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
}

# ----- Batch Go install -----------------------------------------------------
install_go_batch() {
    local label="$1"; shift
    local -a tools=("$@")
    local total=${#tools[@]}
    [[ "$total" -eq 0 ]] && return 0

    if ! command_exists go; then
        log_warn "Go not found — skipping ${label}"
        return 0
    fi
    # GOPATH and GOBIN are set in common.sh (system-wide: /opt/go, /usr/local/bin)

    local current=0 failed=0 skipped=0
    log_info "Installing ${label} ($total Go tools)..."
    for tool in "${tools[@]}"; do
        current=$((current + 1))
        local name
        name=$(echo "$tool" | rev | cut -d/ -f1 | rev | cut -d@ -f1)
        show_progress "$current" "$total" "$name"
        # Skip if binary already exists (GOBIN=/usr/local/bin, so command_exists suffices)
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
    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"
}

# ----- Batch cargo install --------------------------------------------------
install_cargo_batch() {
    local label="$1"; shift
    local -a crates=("$@")
    local total=${#crates[@]}
    [[ "$total" -eq 0 ]] && return 0

    if ! command_exists cargo; then
        log_warn "Cargo not found — installing Rust toolchain..."
        # shellcheck disable=SC2016  # Single quotes intentional — expanded by the subshell
        if bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y' >> "$LOG_FILE" 2>&1; then
            export PATH="$HOME/.cargo/bin:$PATH"
            log_success "Rust toolchain installed"
        else
            log_error "Failed to install Rust — skipping ${label}"
            return 1
        fi
    fi
    export PATH="$HOME/.cargo/bin:$PATH"

    local current=0 failed=0 skipped=0
    log_info "Installing ${label} ($total Rust tools)..."
    for crate in "${crates[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$crate"
        # Skip if binary already exists in /usr/local/bin or cargo bin
        if command_exists "$crate"; then
            skipped=$((skipped + 1))
            track_version "$crate" "cargo" "existing"
            continue
        fi
        if ! cargo install "$crate" >> "$LOG_FILE" 2>&1; then
            log_error "Failed cargo: $crate"
            failed=$((failed + 1))
        else
            # Symlink cargo binary to /usr/local/bin for system-wide access
            if [[ -f "$HOME/.cargo/bin/$crate" ]]; then
                ln -sf "$HOME/.cargo/bin/$crate" "/usr/local/bin/$crate" 2>/dev/null || true
            fi
            track_version "$crate" "cargo" "latest"
        fi
    done
    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"
}

# ----- Batch gem install ----------------------------------------------------
install_gem_batch() {
    local label="$1"; shift
    local -a gems=("$@")
    local total=${#gems[@]}
    [[ "$total" -eq 0 ]] && return 0

    if ! command_exists gem; then
        log_warn "Ruby gem not found — skipping ${label}"
        return 0
    fi

    local current=0 failed=0 skipped=0
    log_info "Installing ${label} ($total Ruby gems)..."
    local installed_gems=""
    installed_gems=$(gem list --no-details 2>/dev/null || true)
    for gem_name in "${gems[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$gem_name"
        # Skip if already installed
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
}

# ----- Post-clone setup for git repos ---------------------------------------
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
            python3 -m venv "$dest/venv" 2>/dev/null || return 0
        fi
        "$dest/venv/bin/pip" install -q --upgrade pip >> "$LOG_FILE" 2>&1 || true
        "$dest/venv/bin/pip" install -q -r "$dest/requirements.txt" >> "$LOG_FILE" 2>&1 || true
    fi

    # Create wrapper scripts in /usr/local/bin for discoverable entry points
    # Look for executable scripts the venv created, or standalone .py scripts
    if [[ -d "$dest/venv/bin" ]]; then
        for candidate in "$dest/venv/bin/$name" "$dest/venv/bin/${name,,}" "$dest/venv/bin/${name//-/_}"; do
            if [[ -f "$candidate" ]] && [[ -x "$candidate" ]]; then
                ln -sf "$candidate" "/usr/local/bin/$(basename "$candidate")" 2>/dev/null || true
                break
            fi
        done
    fi

    # Standalone Python script: make executable
    if [[ -f "$dest/$name.py" ]] && [[ ! -d "$dest/venv" ]]; then
        chmod +x "$dest/$name.py" 2>/dev/null || true
        # Create a wrapper in PATH
        cat > "/usr/local/bin/$name" 2>/dev/null << PYWRAP || true
#!/bin/bash
exec python3 "$dest/$name.py" "\$@"
PYWRAP
        chmod +x "/usr/local/bin/$name" 2>/dev/null || true
    fi

    # Standalone shell script: symlink to PATH
    if [[ -f "$dest/$name.sh" ]] && [[ ! -L "/usr/local/bin/$name" ]]; then
        chmod +x "$dest/$name.sh" 2>/dev/null || true
        ln -sf "$dest/$name.sh" "/usr/local/bin/$name" 2>/dev/null || true
    fi
}

# ----- Batch git clone with auto-setup -------------------------------------
# Usage: install_git_batch "Label" name1=url1 name2=url2 ...
install_git_batch() {
    local label="$1"; shift
    local -a repos=("$@")
    local total=${#repos[@]}
    [[ "$total" -eq 0 ]] && return 0
    local current=0 failed=0 skipped=0

    local base_dir="$GITHUB_TOOL_DIR"
    log_info "Installing ${label} ($total repos)..."
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
    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} updated, ${failed} failed"
}

# ----- Verify download against release checksum file ------------------------
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
" 2>/dev/null)

    if [[ -z "$checksum_url" ]]; then
        log_warn "No checksum file in release for $file_name — skipping verification"
        return 1
    fi

    local checksums
    checksums=$(curl -sSL "$checksum_url" 2>/dev/null)
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

# ----- Download GitHub release binary ---------------------------------------
# Usage: download_github_release "owner/repo" "binary_name" "filename_pattern" [dest_dir]
download_github_release() {
    local repo="$1"
    local binary="$2"
    local pattern="$3"
    local dest_dir="${4:-/usr/local/bin}"

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

    log_info "Downloading $binary from $repo releases..."
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local release_json
    release_json=$(curl -sSL "$api_url" 2>/dev/null)
    if [[ -z "$release_json" ]]; then
        log_error "Could not fetch release info for $binary"
        return 1
    fi

    # Parse download URL using Python (portable — no grep -P dependency)
    local download_url
    download_url=$(echo "$release_json" | python3 -c "
import json, sys, re
data = json.load(sys.stdin)
for asset in data.get('assets', []):
    if re.search(r'''$pattern''', asset.get('name', '')):
        print(asset['browser_download_url'])
        break
" 2>/dev/null)

    if [[ -z "$download_url" ]]; then
        log_error "Could not find release for $binary (pattern: $pattern)"
        return 1
    fi

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
            tar xzf "$tmp_dir/$asset_name" -C "$tmp_dir" 2>/dev/null ;;
        *.zip)
            unzip -qo "$tmp_dir/$asset_name" -d "$tmp_dir" 2>/dev/null ;;
        *.deb)
            # shellcheck disable=SC2024  # Script runs as root; redirect is fine
            sudo dpkg -i "$tmp_dir/$asset_name" >> "$LOG_FILE" 2>&1
            rm -rf "$tmp_dir"
            log_success "Installed: $binary (.deb)"
            track_version "$binary" "binary" "latest"
            return 0 ;;
        *.jar)
            sudo mkdir -p "$dest_dir"
            sudo cp "$tmp_dir/$asset_name" "$dest_dir/$binary.jar"
            # Create wrapper script
            sudo tee "/usr/local/bin/$binary" > /dev/null << WRAPPER
#!/bin/bash
exec java -jar "$dest_dir/$binary.jar" "\$@"
WRAPPER
            sudo chmod +x "/usr/local/bin/$binary"
            rm -rf "$tmp_dir"
            log_success "Installed: $binary (.jar)"
            track_version "$binary" "binary" "latest"
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

    if [[ "$dest_dir" != "/usr/local/bin" ]]; then
        # Custom dest_dir (e.g. /opt/jadx): copy entire extracted tree there
        sudo mkdir -p "$dest_dir"
        sudo cp -a "$tmp_dir"/* "$dest_dir/" 2>/dev/null || true
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
            sudo chmod +x "$dest_bin" 2>/dev/null || true
            sudo ln -sf "$dest_bin" "/usr/local/bin/$binary" 2>/dev/null || true
        fi
    else
        sudo install -m 755 "$found" "$dest_dir/$binary" 2>/dev/null
    fi
    rm -rf "$tmp_dir"

    if command_exists "$binary"; then
        log_success "Installed: $binary"
        track_version "$binary" "binary" "latest"
    else
        # Binary may be in dest_dir but not in PATH — still a success if file exists
        if [[ -f "$dest_dir/$binary" ]] || [[ -f "$dest_dir/bin/$binary" ]]; then
            log_success "Installed: $binary (in $dest_dir)"
            track_version "$binary" "binary" "latest"
        else
            log_error "Install failed: $binary"
            return 1
        fi
    fi
}

# ----- Docker image pull ----------------------------------------------------
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
        return 1
    fi
}

# ----- Version tracking -----------------------------------------------------
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

# ----- Build from source helper ---------------------------------------------
build_from_source() {
    local name="$1"
    local url="$2"
    local build_cmd="$3"
    local dest="$GITHUB_TOOL_DIR/$name"

    git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1 || return 1
    # Run build in a subshell to avoid changing the caller's working directory
    if (cd "$dest" && eval "$build_cmd") >> "$LOG_FILE" 2>&1; then
        log_success "Built: $name"
        track_version "$name" "source" "HEAD"
    else
        log_error "Build failed: $name"
        return 1
    fi
}

# ----- Install searchsploit symlink ----------------------------------------
install_searchsploit_symlink() {
    if [[ -f "$GITHUB_TOOL_DIR/exploitdb/searchsploit" ]]; then
        sudo ln -sf "$GITHUB_TOOL_DIR/exploitdb/searchsploit" /usr/local/bin/searchsploit 2>/dev/null
    fi
}

# ----- Metasploit -----------------------------------------------------------
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

    # Basic content verification — ensure the script is from Rapid7
    if ! grep -q "rapid7" "$tmp_installer" 2>/dev/null; then
        log_error "Metasploit installer content verification failed — aborting"
        rm -f "$tmp_installer"
        return 1
    fi

    chmod 755 "$tmp_installer"
    if "$tmp_installer" >> "$LOG_FILE" 2>&1; then
        log_success "Metasploit installed"
        track_version "metasploit" "special" "latest"
    else
        log_error "Metasploit installation failed"
        rm -f "$tmp_installer"
        return 1
    fi
    rm -f "$tmp_installer"
}

# ----- Burp Suite -----------------------------------------------------------
# NOTE: Burp Suite requires a GUI installer and cannot be fully automated.
# This downloads the installer and provides instructions for manual completion.
install_burpsuite() {
    if command_exists burpsuite; then
        log_success "Burp Suite already installed"
        return 0
    fi
    local version="${BURP_VERSION:-2024.10.1}"
    local dest_dir="/opt/burpsuite-installer"
    local installer="$dest_dir/burpsuite_community_v${version}_install.sh"

    log_info "Downloading Burp Suite Community v${version}..."
    mkdir -p "$dest_dir"
    if ! wget -q -O "$installer" "https://portswigger.net/burp/releases/download?product=community&version=${version}&type=Linux" 2>> "$LOG_FILE"; then
        log_error "Failed to download Burp Suite"
        return 1
    fi
    chmod +x "$installer"

    log_warn "============================================="
    log_warn "Burp Suite requires MANUAL GUI installation:"
    log_warn "  Run: $installer"
    log_warn "============================================="
    track_version "burpsuite" "special" "$version (downloaded, needs manual install)"
}

# ----- OWASP ZAP ------------------------------------------------------------
install_zap() {
    if command_exists zaproxy; then
        log_success "OWASP ZAP already installed"
        return 0
    fi
    if snap_available; then
        log_info "Installing OWASP ZAP via snap..."
        snap_install zaproxy --classic >> "$LOG_FILE" 2>&1
        log_success "OWASP ZAP installed"
        track_version "zaproxy" "snap" "latest"
    else
        log_warn "snap not available — install OWASP ZAP manually"
    fi
}
