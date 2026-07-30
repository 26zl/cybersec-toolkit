#!/usr/bin/env bats
# Tests for lib/installers.sh
# fixup_package_names, track_version, Go binary name extraction

setup() {
    load 'test_helper'
}

# release archive validation

@test "release archive validator accepts regular tar contents" {
    source_libs --installers debian apt
    make_test_tmpdir
    mkdir -p "$TEST_TMPDIR/src"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/src/tool"
    tar -czf "$TEST_TMPDIR/release.tar.gz" -C "$TEST_TMPDIR/src" tool

    run _validate_release_archive "$TEST_TMPDIR/release.tar.gz" tar
    assert_success
}

@test "release archive validator rejects tar symlinks" {
    source_libs --installers debian apt
    make_test_tmpdir
    mkdir -p "$TEST_TMPDIR/src"
    ln -s /etc/passwd "$TEST_TMPDIR/src/tool"
    tar -czf "$TEST_TMPDIR/release.tar.gz" -C "$TEST_TMPDIR/src" tool

    run _validate_release_archive "$TEST_TMPDIR/release.tar.gz" tar
    assert_failure
    assert_output --partial "unsupported archive member type"
}

@test "release archive validator rejects zip symlinks" {
    source_libs --installers debian apt
    make_test_tmpdir
    python3 - "$TEST_TMPDIR/release.zip" <<'PY'
import stat
import sys
import zipfile

entry = zipfile.ZipInfo("tool")
entry.create_system = 3
entry.external_attr = (stat.S_IFLNK | 0o777) << 16
with zipfile.ZipFile(sys.argv[1], "w") as archive:
    archive.writestr(entry, "/etc/passwd")
PY

    run _validate_release_archive "$TEST_TMPDIR/release.zip" zip
    assert_failure
    assert_output --partial "symlink archive member rejected"
}

@test "release archive validator rejects corrupt archives" {
    source_libs --installers debian apt
    make_test_tmpdir
    printf 'not an archive\n' > "$TEST_TMPDIR/release.zip"

    run _validate_release_archive "$TEST_TMPDIR/release.zip" zip
    assert_failure
    assert_output --partial "invalid zip archive"
}

@test "release archive validator rejects tar path traversal members" {
    source_libs --installers debian apt
    make_test_tmpdir
    python3 - "$TEST_TMPDIR/release.tar.gz" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w:gz") as tf:
    data = b"x"
    info = tarfile.TarInfo(name="../escape")
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))
PY

    run _validate_release_archive "$TEST_TMPDIR/release.tar.gz" tar
    assert_failure
    assert_output --partial "unsafe archive member path"
}

@test "release archive validator rejects zip path traversal members" {
    source_libs --installers debian apt
    make_test_tmpdir
    python3 - "$TEST_TMPDIR/release.zip" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as archive:
    archive.writestr("../escape", "x")
PY

    run _validate_release_archive "$TEST_TMPDIR/release.zip" zip
    assert_failure
    assert_output --partial "unsafe archive member path"
}

# GitHub release checksum enforcement (offline)

@test "verify_github_checksum accepts a matching checksum" {
    source_libs --installers debian apt
    make_test_tmpdir
    _gh_api_cache_init
    local url="https://example.com/checksums.txt"
    local key; key=$(echo "$url" | sed 's|[/:?&=]|_|g')
    local bin="$TEST_TMPDIR/tool"
    printf 'binary-contents\n' > "$bin"
    local hash; hash=$(sha256sum "$bin" | awk '{print $1}')
    printf '%s  tool\n' "$hash" > "$_GH_API_CACHE_DIR/checksum_${key}"
    local rel='{"assets":[{"name":"checksums.txt","browser_download_url":"'"$url"'"}]}'

    run verify_github_checksum "$rel" "$bin" "tool"
    assert_success
}

@test "verify_github_checksum rejects a mismatch and writes the .checksum_mismatch marker" {
    source_libs --installers debian apt
    make_test_tmpdir
    _gh_api_cache_init
    local url="https://example.com/checksums.txt"
    local key; key=$(echo "$url" | sed 's|[/:?&=]|_|g')
    local bin="$TEST_TMPDIR/tool"
    printf 'binary-contents\n' > "$bin"
    printf '%s  tool\n' "$(printf '0%.0s' {1..64})" > "$_GH_API_CACHE_DIR/checksum_${key}"
    local rel='{"assets":[{"name":"checksums.txt","browser_download_url":"'"$url"'"}]}'

    run verify_github_checksum "$rel" "$bin" "tool"
    assert_failure
    [ -f "$TEST_TMPDIR/.checksum_mismatch" ]
}

@test "verify_github_checksum fails (no marker) when the asset has no checksum entry" {
    source_libs --installers debian apt
    make_test_tmpdir
    _gh_api_cache_init
    local url="https://example.com/checksums.txt"
    local key; key=$(echo "$url" | sed 's|[/:?&=]|_|g')
    local bin="$TEST_TMPDIR/tool"
    printf 'binary-contents\n' > "$bin"
    local hash; hash=$(sha256sum "$bin" | awk '{print $1}')
    printf '%s  someotherfile\n' "$hash" > "$_GH_API_CACHE_DIR/checksum_${key}"
    local rel='{"assets":[{"name":"checksums.txt","browser_download_url":"'"$url"'"}]}'

    run verify_github_checksum "$rel" "$bin" "tool"
    assert_failure
    [ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]
}

# GitHub token handling (netrc, not a header)

@test "_setup_curl_opts stores the token in a chmod-600 netrc, never a header or the raw token" {
    source_libs --installers debian apt
    export GITHUB_TOKEN=faketoken123

    _setup_curl_opts

    [ -n "$_GH_NETRC_FILE" ]
    [ -f "$_GH_NETRC_FILE" ]
    local mode
    mode=$(stat -c '%a' "$_GH_NETRC_FILE" 2>/dev/null || stat -f '%Lp' "$_GH_NETRC_FILE")
    [ "$mode" = "600" ]
    grep -q "password faketoken123" "$_GH_NETRC_FILE"

    local opts="${_CURL_OPTS[*]}"
    [[ "$opts" == *"--netrc-file"* ]]
    [[ "$opts" != *"faketoken123"* ]]
    [[ "$opts" != *" -H "* ]]
}

# curl-pipe content validation gate

@test "curl-pipe validator rejects an empty download" {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/lib/shared.sh"
    make_test_tmpdir
    : > "$TEST_TMPDIR/script.sh"

    run _validate_curl_pipe "$TEST_TMPDIR/script.sh" install
    assert_failure
    assert_output --partial "empty or missing"
}

@test "curl-pipe validator rejects a suspiciously small download" {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/lib/shared.sh"
    make_test_tmpdir
    printf '#!/bin/sh\necho hi\n' > "$TEST_TMPDIR/script.sh"

    run _validate_curl_pipe "$TEST_TMPDIR/script.sh" install
    assert_failure
    assert_output --partial "suspiciously small"
}

@test "curl-pipe validator accepts a valid script containing all keywords" {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/lib/shared.sh"
    make_test_tmpdir
    { printf 'install github\n'; printf '%*s' 600 ''; printf '\n'; } > "$TEST_TMPDIR/script.sh"

    run _validate_curl_pipe "$TEST_TMPDIR/script.sh" install github
    assert_success
}

@test "curl-pipe validator rejects a script missing a required keyword" {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/lib/shared.sh"
    make_test_tmpdir
    { printf 'install only\n'; printf '%*s' 600 ''; printf '\n'; } > "$TEST_TMPDIR/script.sh"

    run _validate_curl_pipe "$TEST_TMPDIR/script.sh" install github
    assert_failure
    assert_output --partial "missing expected keyword"
}

# fixup_package_names — apt (no-op)

@test "fixup_package_names is a no-op for apt" {
    source_libs --installers debian apt
    local -a pkgs=(curl git nmap netcat-openbsd build-essential)
    local -a original=("${pkgs[@]}")
    fixup_package_names pkgs
    [[ "${pkgs[*]}" == "${original[*]}" ]]
}

# fixup_package_names — dnf translations

@test "fixup: dnf translates netcat-openbsd to nmap-ncat" {
    source_libs --installers fedora dnf
    local -a pkgs=(netcat-openbsd)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "nmap-ncat" ]]
}

@test "fixup: dnf translates build-essential to @development-tools" {
    source_libs --installers fedora dnf
    local -a pkgs=(build-essential)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "@development-tools" ]]
}

@test "fixup: dnf translates dnsutils to bind-utils" {
    source_libs --installers fedora dnf
    local -a pkgs=(dnsutils)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "bind-utils" ]]
}

@test "fixup: dnf translates proxychains4 to proxychains-ng" {
    source_libs --installers fedora dnf
    local -a pkgs=(proxychains4)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "proxychains-ng" ]]
}

@test "fixup: dnf translates python3-dev to python3-devel" {
    source_libs --installers fedora dnf
    local -a pkgs=(python3-dev)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "python3-devel" ]]
}

@test "fixup: dnf translates libssl-dev to openssl-devel" {
    source_libs --installers fedora dnf
    local -a pkgs=(libssl-dev)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "openssl-devel" ]]
}

# fixup_package_names — pacman translations

@test "fixup: pacman translates build-essential to base-devel" {
    source_libs --installers arch pacman
    local -a pkgs=(build-essential)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "base-devel" ]]
}

# openbsd-netcat is the Arch [extra] package; gnu-netcat (the old mapping) is
# AUR-only, so the container audit corrected it.
@test "fixup: pacman translates netcat-openbsd to openbsd-netcat" {
    source_libs --installers arch pacman
    local -a pkgs=(netcat-openbsd)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "openbsd-netcat" ]]
}

@test "fixup: pacman translates dnsutils to bind" {
    source_libs --installers arch pacman
    local -a pkgs=(dnsutils)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "bind" ]]
}

@test "fixup: pacman translates proxychains4 to proxychains-ng" {
    source_libs --installers arch pacman
    local -a pkgs=(proxychains4)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "proxychains-ng" ]]
}

@test "fixup: pacman translates python3 to python" {
    source_libs --installers arch pacman
    local -a pkgs=(python3)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "python" ]]
}

@test "fixup: pacman translates golang-go to go" {
    source_libs --installers arch pacman
    local -a pkgs=(golang-go)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "go" ]]
}

# fixup_package_names — skipped packages

# fixup_package_names — apt Kali-only filtering

@test "fixup: apt on Ubuntu removes Kali-only spike" {
    source_libs --installers ubuntu apt
    local -a pkgs=(curl spike git)
    fixup_package_names pkgs
    local joined="${pkgs[*]}"
    [[ "$joined" != *"spike"* ]]
    [[ ${#pkgs[@]} -eq 2 ]]
}

@test "fixup: apt on Kali keeps spike" {
    source_libs --installers kali apt
    local -a pkgs=(curl spike git)
    fixup_package_names pkgs
    local joined="${pkgs[*]}"
    [[ "$joined" == *"spike"* ]]
    [[ ${#pkgs[@]} -eq 3 ]]
}

# fixup_package_names — skipped packages

@test "fixup: dnf removes spooftooph" {
    source_libs --installers fedora dnf
    local -a pkgs=(curl spooftooph git)
    fixup_package_names pkgs
    local joined="${pkgs[*]}"
    [[ "$joined" != *"spooftooph"* ]]
}

@test "fixup: dnf removes cewl" {
    source_libs --installers fedora dnf
    local -a pkgs=(cewl)
    fixup_package_names pkgs
    [[ ${#pkgs[@]} -eq 0 ]]
}

@test "fixup: dnf removes hashid" {
    source_libs --installers fedora dnf
    local -a pkgs=(hashid)
    fixup_package_names pkgs
    [[ ${#pkgs[@]} -eq 0 ]]
}

@test "fixup: pacman removes spooftooph" {
    source_libs --installers arch pacman
    local -a pkgs=(nmap spooftooph curl)
    fixup_package_names pkgs
    local joined="${pkgs[*]}"
    [[ "$joined" != *"spooftooph"* ]]
}

@test "fixup: pacman removes python3-venv" {
    source_libs --installers arch pacman
    local -a pkgs=(python3-venv)
    fixup_package_names pkgs
    [[ ${#pkgs[@]} -eq 0 ]]
}

@test "fixup: pacman removes python3-dev" {
    source_libs --installers arch pacman
    local -a pkgs=(python3-dev)
    fixup_package_names pkgs
    [[ ${#pkgs[@]} -eq 0 ]]
}

# fixup_package_names — zypper translations

@test "fixup: zypper translates dnsutils to bind-utils" {
    source_libs --installers opensuse-tumbleweed zypper
    local -a pkgs=(dnsutils)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "bind-utils" ]]
}

@test "fixup: zypper translates libssl-dev to libopenssl-devel" {
    source_libs --installers opensuse-tumbleweed zypper
    local -a pkgs=(libssl-dev)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "libopenssl-devel" ]]
}

@test "fixup: zypper skips build-essential (handled by install_shared_deps)" {
    source_libs --installers opensuse-tumbleweed zypper
    local -a pkgs=(curl build-essential git)
    fixup_package_names pkgs
    local joined="${pkgs[*]}"
    [[ "$joined" != *"build-essential"* ]]
    [[ "$joined" != *"devel_basis"* ]]
    [[ ${#pkgs[@]} -eq 2 ]]
}

@test "fixup: zypper removes skipped packages" {
    source_libs --installers opensuse-tumbleweed zypper
    local -a pkgs=(spooftooph cewl hashid checksec rizin)
    fixup_package_names pkgs
    [[ ${#pkgs[@]} -eq 0 ]]
}

# fixup preserves non-translated packages

@test "fixup: unknown packages pass through unchanged on dnf" {
    source_libs --installers fedora dnf
    local -a pkgs=(curl git nmap)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "curl" ]]
    [[ "${pkgs[1]}" == "git" ]]
    [[ "${pkgs[2]}" == "nmap" ]]
}

# track_version

@test "track_version writes correct pipe-delimited format" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"

    track_version "sqlmap" "pipx" "1.8.2"

    [[ -f "$VERSION_FILE" ]]
    # Header line
    grep -q "^# tool|method|version|last_updated" "$VERSION_FILE"
    # Data line: tool|method|version|timestamp
    grep -q "^sqlmap|pipx|1.8.2|" "$VERSION_FILE"
}

@test "track_version replaces existing entry for same tool" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"

    track_version "nmap" "apt" "7.94"
    track_version "nmap" "apt" "7.95"

    local count
    count=$(grep -c "^nmap|" "$VERSION_FILE")
    [[ "$count" -eq 1 ]]
    grep -q "^nmap|apt|7.95|" "$VERSION_FILE"
}

@test "track_version creates file if missing" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/new_versions"

    [[ ! -f "$VERSION_FILE" ]]
    track_version "testool" "go" "latest"
    [[ -f "$VERSION_FILE" ]]
}

@test "install_go_batch counts missing Go as failures" {
    source_libs --installers debian apt
    TOTAL_TOOL_FAILURES=0
    command_exists() {
        [[ "$1" != "go" ]]
    }

    local status=0
    install_go_batch "Go test" \
        "github.com/example/one@latest" \
        "github.com/example/two@latest" || status=$?

    [[ "$status" -eq 1 ]]
    [[ "$TOTAL_TOOL_FAILURES" -eq 2 ]]
}

@test "install_cargo_batch counts missing Cargo as failures" {
    source_libs --installers debian apt
    TOTAL_TOOL_FAILURES=0
    _builder_cmd() { return 1; }

    local status=0
    install_cargo_batch "Cargo test" rustscan aderyn || status=$?

    [[ "$status" -eq 1 ]]
    [[ "$TOTAL_TOOL_FAILURES" -eq 2 ]]
}

# _load_distro_compat — TSV loader

@test "TSV loader populates _COMPAT_DNF array" {
    source_libs --installers fedora dnf
    _load_distro_compat
    [[ "${_COMPAT_DNF[netcat-openbsd]}" == "nmap-ncat" ]]
    [[ "${_COMPAT_DNF[libssl-dev]}" == "openssl-devel" ]]
    [[ "${_COMPAT_DNF[spooftooph]}" == "-" ]]
}

@test "TSV loader populates _COMPAT_PACMAN array" {
    source_libs --installers arch pacman
    _load_distro_compat
    [[ "${_COMPAT_PACMAN[build-essential]}" == "base-devel" ]]
    [[ "${_COMPAT_PACMAN[python3]}" == "python" ]]
}

@test "TSV loader populates _COMPAT_PKG array" {
    source_libs --installers debian apt
    _load_distro_compat
    [[ "${_COMPAT_PKG[build-essential]}" == "clang+make" ]]
    [[ "${_COMPAT_PKG[python3]}" == "python" ]]
}

@test "TSV loader handles missing file gracefully" {
    source_libs --installers fedora dnf
    make_test_tmpdir
    # Reset loaded flag and point to a directory with no TSV
    _COMPAT_LOADED=false
    _COMPAT_DNF=()
    _COMPAT_PACMAN=()
    _COMPAT_ZYPPER=()
    _COMPAT_PKG=()
    export SCRIPT_DIR="$TEST_TMPDIR"
    # Should not error, just warn and set loaded flag
    _load_distro_compat
    [[ "$_COMPAT_LOADED" == "true" ]]
    # Packages should pass through unchanged (no mappings loaded)
    local -a pkgs=(netcat-openbsd curl)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "netcat-openbsd" ]]
    [[ "${pkgs[1]}" == "curl" ]]
}

@test "fixup: pkg expands build-essential to clang and make" {
    source_libs --installers debian pkg
    export TERMUX_VERSION=1
    local -a pkgs=(build-essential curl)
    fixup_package_names pkgs
    local joined="${pkgs[*]}"
    [[ "$joined" == *"clang"* ]]
    [[ "$joined" == *"make"* ]]
    [[ "$joined" == *"curl"* ]]
    [[ "$joined" != *"build-essential"* ]]
}

# Go binary name extraction (_go_bin_name)

@test "Go binary name extracted from full import path" {
    source_libs debian apt
    [[ "$(_go_bin_name "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")" == "subfinder" ]]
}

@test "Go binary name extraction for simple path" {
    source_libs debian apt
    [[ "$(_go_bin_name "github.com/tomnomnom/assetfinder@latest")" == "assetfinder" ]]
}

@test "Go binary name extraction for versioned path" {
    source_libs debian apt
    # /v2 suffix is stripped, returns the actual tool name
    [[ "$(_go_bin_name "github.com/ffuf/ffuf/v2@latest")" == "ffuf" ]]
}

@test "Go binary name extraction for /... wildcard path" {
    source_libs debian apt
    [[ "$(_go_bin_name "github.com/owasp-amass/amass/v4/...@latest")" == "amass" ]]
}

@test "Go binary name extraction for v3 module" {
    source_libs debian apt
    [[ "$(_go_bin_name "github.com/OJ/gobuster/v3@latest")" == "gobuster" ]]
}

# architecture-aware release assets

@test "new forensic and blue-team releases select x64 assets on amd64" {
    source_libs debian apt
    export SYS_ARCH=amd64
    source "$PROJECT_ROOT/lib/installers.sh"

    [[ "${BINARY_RELEASES_FORENSICS[*]}" == *"MemProcFS|memprocfs|linux_x64-"* ]]
    [[ "${BINARY_RELEASES_BLUETEAM[*]}" == *"hayabusa|hayabusa|lin-x64-gnu"* ]]
}

@test "new forensic and blue-team releases select aarch64 assets on arm64" {
    source_libs debian apt
    export SYS_ARCH=arm64
    source "$PROJECT_ROOT/lib/installers.sh"

    [[ "${BINARY_RELEASES_FORENSICS[*]}" == *"MemProcFS|memprocfs|linux_aarch64-"* ]]
    [[ "${BINARY_RELEASES_BLUETEAM[*]}" == *"hayabusa|hayabusa|lin-aarch64-gnu"* ]]
}

# Stage-1 C2 aggregation (install.sh install_modules loop)
#
# Replicates the per-module aggregation loop from install_modules() in
# install.sh: it appends each module's <PREFIX>_GIT / BINARY_RELEASES_<MOD>
# arrays, and — only when INCLUDE_C2=true — the <PREFIX>_C2_GIT /
# BINARY_RELEASES_<MOD>_C2 arrays.

# Source common.sh + installers.sh (BINARY_RELEASES_MISC_C2) + misc module
# (MISC_C2_GIT), then run the aggregation loop for the given modules.
_aggregate_c2_test_setup() {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/modules/misc.sh"
}

# Mirror of the install_modules() Stage-1 loop. Populates _ALL_GIT/_ALL_BINARY.
_run_c2_aggregation() {
    local -a _modules=("$@")
    _ALL_GIT=()
    _ALL_BINARY=()
    local _mod _pfx _mod_upper
    for _mod in "${_modules[@]}"; do
        _pfx=$(_module_prefix "$_mod")
        _mod_upper="${_mod^^}"
        _append_module_array _ALL_GIT   "${_pfx}_GIT"
        _append_module_array _ALL_BINARY "BINARY_RELEASES_${_mod_upper}"
        if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
            _append_module_array _ALL_GIT    "${_pfx}_C2_GIT"
            _append_module_array _ALL_BINARY "BINARY_RELEASES_${_mod_upper}_C2"
        fi
    done
}

@test "C2 aggregation: INCLUDE_C2=true includes misc C2 git repos" {
    _aggregate_c2_test_setup
    export INCLUDE_C2=true
    declare -a _ALL_GIT _ALL_BINARY
    _run_c2_aggregation misc
    [[ "${_ALL_GIT[*]}" == *"SET=https://github.com/trustedsec/social-engineer-toolkit.git"* ]]
    [[ "${_ALL_GIT[*]}" == *"Loki-C2=https://github.com/boku7/Loki.git"* ]]
    [[ "${_ALL_GIT[*]}" == *"Caldera=https://github.com/mitre/caldera.git"* ]]
}

@test "C2 aggregation: INCLUDE_C2=true includes misc C2 binary releases" {
    _aggregate_c2_test_setup
    export INCLUDE_C2=true
    declare -a _ALL_GIT _ALL_BINARY
    _run_c2_aggregation misc
    [[ "${_ALL_BINARY[*]}" == *"gophish/gophish|gophish|linux-64bit"* ]]
    [[ "${_ALL_BINARY[*]}" == *"BishopFox/sliver|sliver-server|"* ]]
    [[ "${_ALL_BINARY[*]}" == *"BishopFox/sliver|sliver-client|"* ]]
    [[ "${_ALL_BINARY[*]}" == *"kgretzky/evilginx2|evilginx|"* ]]
}

@test "C2 aggregation: INCLUDE_C2=false excludes misc C2 git repos" {
    _aggregate_c2_test_setup
    export INCLUDE_C2=false
    declare -a _ALL_GIT _ALL_BINARY
    _run_c2_aggregation misc
    [[ "${_ALL_GIT[*]}" != *"SET=https://github.com/trustedsec/social-engineer-toolkit.git"* ]]
    [[ "${_ALL_GIT[*]}" != *"Loki-C2=https://github.com/boku7/Loki.git"* ]]
}

@test "C2 aggregation: INCLUDE_C2=false excludes misc C2 binary releases" {
    _aggregate_c2_test_setup
    export INCLUDE_C2=false
    declare -a _ALL_GIT _ALL_BINARY
    _run_c2_aggregation misc
    [[ "${_ALL_BINARY[*]}" != *"gophish/gophish|gophish|linux-64bit"* ]]
    [[ "${_ALL_BINARY[*]}" != *"sliver-server"* ]]
}

# install provenance ("existing" vs installed)
# The uninstall paths skip anything recorded as "existing". Covers all five
# package managers via pkg_is_installed.

@test "install_apt_batch marks already-installed packages as existing" {
    source_libs --installers fedora dnf
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"

    # curl/git are "already there"; nmap is not. Groups cannot be queried.
    pkg_is_installed() { [[ "$1" == "curl" || "$1" == "git" ]]; }
    pkg_install() { return 0; }
    fixup_package_names() { :; }
    show_progress() { :; }

    install_apt_batch "test" curl git nmap @development-tools

    grep -q "^curl|dnf|existing|" "$VERSION_FILE"
    grep -q "^git|dnf|existing|" "$VERSION_FILE"
    grep -q "^nmap|dnf|system|" "$VERSION_FILE"
    grep -q "^@development-tools|dnf|existing|" "$VERSION_FILE"
}

@test "track_version keeps pre-existing tools out of the rollback set" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    export _SESSION_FILE="$TEST_TMPDIR/manifest"
    : > "$_SESSION_FILE"

    track_version "wireshark" "apt" "existing"
    track_version "ffuf" "go" "latest"

    # --rollback only acts on action == "installed"
    grep -q "^wireshark|apt|existing|" "$_SESSION_FILE"
    grep -q "^ffuf|go|installed|" "$_SESSION_FILE"
}

@test "filter_preexisting drops tools recorded as existing" {
    source_libs --installers arch pacman
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"

    track_version "curl" "pacman" "existing"
    track_version "nmap" "pacman" "system"

    _PREEXISTING_LOADED=false
    _PREEXISTING_TOOLS=()
    local -a pkgs=(curl nmap sqlmap)
    filter_preexisting pkgs "system packages"

    [[ "${pkgs[*]}" == "nmap sqlmap" ]]
}

@test "filter_preexisting empties the array when everything pre-existed" {
    source_libs --installers opensuse zypper
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"

    track_version "curl" "zypper" "existing"

    _PREEXISTING_LOADED=false
    _PREEXISTING_TOOLS=()
    local -a pkgs=(curl)
    filter_preexisting pkgs "system packages"

    [[ "${#pkgs[@]}" -eq 0 ]]
}

@test "_tree_provenance flags a directory this installer never created" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    mkdir -p "$TEST_TMPDIR/opt/usertool" "$TEST_TMPDIR/opt/ourtool"

    track_version "ourtool" "git" "HEAD"

    [[ "$(_tree_provenance usertool "$TEST_TMPDIR/opt/usertool")" == "existing" ]]
    [[ "$(_tree_provenance ourtool "$TEST_TMPDIR/opt/ourtool")" == "HEAD" ]]
    [[ "$(_tree_provenance gone "$TEST_TMPDIR/opt/gone")" == "HEAD" ]]
}

# uninstall helpers

@test "remove_source_build drops the build tree and its symlink" {
    source_libs --installers debian apt
    make_test_tmpdir
    export GITHUB_TOOL_DIR="$TEST_TMPDIR/opt"
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$GITHUB_TOOL_DIR/AFLplusplus" "$PIPX_BIN_DIR"
    : > "$PIPX_BIN_DIR/AFLplusplus"

    run remove_source_build AFLplusplus
    assert_success
    [[ ! -d "$GITHUB_TOOL_DIR/AFLplusplus" ]]
    [[ ! -e "$PIPX_BIN_DIR/AFLplusplus" ]]
}

@test "uninstall helpers report unknown names instead of guessing" {
    source_libs --installers debian apt

    run remove_special_tool definitely-not-a-tool
    assert_failure
    run remove_snap_tool definitely-not-a-tool
    assert_failure
}

@test "remove_special_tool removes the patator venv and its symlink" {
    source_libs --installers debian apt
    make_test_tmpdir
    export GITHUB_TOOL_DIR="$TEST_TMPDIR/opt"
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$GITHUB_TOOL_DIR/patator/venv/bin" "$PIPX_BIN_DIR"
    : > "$PIPX_BIN_DIR/patator"

    run remove_special_tool patator
    assert_success
    [[ ! -d "$GITHUB_TOOL_DIR/patator" ]]
    [[ ! -e "$PIPX_BIN_DIR/patator" ]]
}

@test "a second install run does not relabel its own packages as pre-existing" {
    # Toolkit-owned packages remain removable without belonging to later sessions.
    source_libs --installers fedora dnf
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"

    declare -gA FAKE_INSTALLED=([curl]=1)     # only curl predates the toolkit
    pkg_is_installed() { [[ -n "${FAKE_INSTALLED[$1]:-}" ]]; }
    pkg_install() { local p; for p in "$@"; do FAKE_INSTALLED["$p"]=1; done; }
    fixup_package_names() { :; }
    show_progress() { :; }

    _SESSION_FILE=""
    install_apt_batch "run1" curl nmap sqlmap
    export _SESSION_FILE="$TEST_TMPDIR/run2.manifest"
    : > "$_SESSION_FILE"
    install_apt_batch "run2" curl nmap sqlmap
    install_apt_batch "run3" curl nmap sqlmap

    grep -q "^curl|dnf|existing|" "$VERSION_FILE"
    grep -q "^nmap|dnf|system|" "$VERSION_FILE"
    grep -q "^sqlmap|dnf|system|" "$VERSION_FILE"
    grep -q "^nmap|dnf|existing|" "$_SESSION_FILE"
    grep -q "^sqlmap|dnf|existing|" "$_SESSION_FILE"
    ! grep -q "^nmap|dnf|installed|" "$_SESSION_FILE"
    ! grep -q "^sqlmap|dnf|installed|" "$_SESSION_FILE"
}

@test "_tree_provenance keeps its verdict across repeated runs" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    mkdir -p "$TEST_TMPDIR/opt/usertool"       # the user's own clone

    local r n v
    for r in 1 2 3; do
        for n in usertool ourtool; do
            v=$(_tree_provenance "$n" "$TEST_TMPDIR/opt/$n")
            mkdir -p "$TEST_TMPDIR/opt/$n"     # the clone happens after the check
            track_version "$n" git "$v"
        done
    done

    grep -q "^usertool|git|existing|" "$VERSION_FILE"
    grep -q "^ourtool|git|HEAD|" "$VERSION_FILE"
}

@test "sequential Git rerun stays out of the new rollback session" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    export GITHUB_TOOL_DIR="$TEST_TMPDIR/opt"
    export PARALLEL_JOBS=1
    mkdir -p "$GITHUB_TOOL_DIR/ourtool/.git"

    _SESSION_FILE=""
    track_version "ourtool" "git" "HEAD"
    export _SESSION_FILE="$TEST_TMPDIR/manifest"
    : > "$_SESSION_FILE"
    git_clone_or_pull() { return 0; }
    setup_git_repo() { return 0; }
    show_progress() { :; }

    install_git_batch "test" "ourtool=https://internal.example/ourtool.git"

    grep -q "^ourtool|git|existing|" "$_SESSION_FILE"
    ! grep -q "^ourtool|git|installed|" "$_SESSION_FILE"
    grep -q "^ourtool|git|HEAD|" "$VERSION_FILE"
}

@test "source rerun stays out of the new rollback session" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    export GITHUB_TOOL_DIR="$TEST_TMPDIR/opt"
    mkdir -p "$GITHUB_TOOL_DIR/ourtool"

    _SESSION_FILE=""
    track_version "ourtool" "source" "HEAD"
    export _SESSION_FILE="$TEST_TMPDIR/manifest"
    : > "$_SESSION_FILE"
    git_clone_or_pull() { return 0; }
    _as_builder() { return 0; }

    build_from_source "ourtool" \
        "https://internal.example/ourtool.git" "make"

    grep -q "^ourtool|source|existing|" "$_SESSION_FILE"
    ! grep -q "^ourtool|source|installed|" "$_SESSION_FILE"
    grep -q "^ourtool|source|HEAD|" "$VERSION_FILE"
}

@test "install summary counts exclude pre-existing tools" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    printf '# tool|method|version|last_updated\n' > "$VERSION_FILE"
    printf 'curl|apt|existing|x\nnmap|apt|system|x\nffuf|go|existing|x\nsqlmap|pipx|latest|x\n' >> "$VERSION_FILE"

    local installed existing
    installed=$(awk -F'|' '!/^#/ && $3 != "existing"' "$VERSION_FILE" | wc -l)
    existing=$(awk -F'|' '!/^#/ && $3 == "existing"' "$VERSION_FILE" | wc -l)
    [[ "$installed" -eq 2 ]]
    [[ "$existing" -eq 2 ]]
}

@test "a tool we installed is not relabelled pre-existing on the next run" {
    # The "existing" label is only for tools the user already had. Deriving it from
    # presence alone would protect our own installs from ever being removed.
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"

    _SESSION_FILE=""
    track_version "ours" "cargo" "latest"          # an earlier run installed it
    export _SESSION_FILE="$TEST_TMPDIR/manifest"
    : > "$_SESSION_FILE"

    _track_already_present "theirs" "cargo"        # never installed by us
    _track_already_present "theirs" "cargo"        # run 2 sees both present
    _track_already_present "ours" "cargo"

    grep -q "^theirs|cargo|existing|" "$VERSION_FILE"
    grep -q "^ours|cargo|latest|" "$VERSION_FILE"
    ! grep -q "^ours|cargo|installed|" "$_SESSION_FILE"
    grep -q "^ours|cargo|existing|" "$_SESSION_FILE"
}

# ---------- rollback must not report success on a failed removal --------------

@test "remove_source_build fails when the tree survives" {
    source_libs --installers debian apt
    make_test_tmpdir
    export GITHUB_TOOL_DIR="$TEST_TMPDIR/opt"
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$GITHUB_TOOL_DIR/stubborn" "$PIPX_BIN_DIR"

    # rm -rf is a no-op here, so the tree is still there afterwards.
    rm() { :; }
    run remove_source_build stubborn
    assert_failure
    [[ -d "$GITHUB_TOOL_DIR/stubborn" ]]
}

@test "remove_source_build succeeds once the tree is gone" {
    source_libs --installers debian apt
    make_test_tmpdir
    export GITHUB_TOOL_DIR="$TEST_TMPDIR/opt"
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$GITHUB_TOOL_DIR/gone" "$PIPX_BIN_DIR"

    run remove_source_build gone
    assert_success
    [[ ! -e "$GITHUB_TOOL_DIR/gone" ]]
}

@test "remove_special_tool separates unknown name from failed removal" {
    source_libs --installers debian apt
    make_test_tmpdir
    export GITHUB_TOOL_DIR="$TEST_TMPDIR/opt"
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$GITHUB_TOOL_DIR/patator" "$PIPX_BIN_DIR"

    run remove_special_tool definitely-not-a-tool
    [[ "$status" -eq 1 ]]            # unknown name

    rm() { :; }
    run remove_special_tool patator
    [[ "$status" -eq 2 ]]            # tried, but the venv survived
}
