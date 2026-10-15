#!/usr/bin/env bats
# Tests for lib/installers.sh

setup() {
    load 'test_helper'
}

@test "_install_staged_bin installs a fresh 0755 file and refuses a symlink" {
    source_libs --installers debian apt
    make_test_tmpdir
    mkdir -p "$TEST_TMPDIR/stage" "$TEST_TMPDIR/bin"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/stage/tool"
    chmod 0600 "$TEST_TMPDIR/stage/tool"
    _install_staged_bin "$TEST_TMPDIR/stage/tool" "$TEST_TMPDIR/bin/tool"
    [[ "$(stat -c %a "$TEST_TMPDIR/bin/tool")" == "755" ]]
    [[ ! -e "$TEST_TMPDIR/stage/tool" ]]

    printf 'secret\n' > "$TEST_TMPDIR/private"
    ln -s "$TEST_TMPDIR/private" "$TEST_TMPDIR/stage/link"
    run _install_staged_bin "$TEST_TMPDIR/stage/link" "$TEST_TMPDIR/bin/link"
    assert_failure
    [[ ! -e "$TEST_TMPDIR/bin/link" ]]
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

@test "tar release assets install without archive group/world-write bits" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions" FAST_MODE=true SYS_ARCH=amd64
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$TEST_TMPDIR/src" "$PIPX_BIN_DIR"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/src/zz-fake-tool"
    chmod 0777 "$TEST_TMPDIR/src" "$TEST_TMPDIR/src/zz-fake-tool"
    tar -czf "$TEST_TMPDIR/fixture.tar.gz" -C "$TEST_TMPDIR/src" .
    _gh_api_get() {
        printf '{"tag_name":"v1","assets":[{"name":"zz-fake-tool_linux_amd64.tar.gz","browser_download_url":"https://example.invalid/zz-fake-tool_linux_amd64.tar.gz"}]}'
    }
    curl() {
        local out=""
        while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && out="$2"; shift; done
        cp "$TEST_TMPDIR/fixture.tar.gz" "$out"
    }

    # run: the GNU-only `find -perm /6000` step errors on BSD find hosts.
    run download_github_release "example/zz-fake-tool" "zz-fake-tool" "linux_amd64\\.tar\\.gz$" \
        "$TEST_TMPDIR/opt/zz-fake-tool"
    assert_success

    local f="$TEST_TMPDIR/opt/zz-fake-tool/zz-fake-tool"
    [[ -x "$f" ]]
    [[ -L "$PIPX_BIN_DIR/zz-fake-tool" ]]
    [[ -z "$(find "$TEST_TMPDIR/opt/zz-fake-tool" -perm -o+w)" ]]
    grep -q "^zz-fake-tool|binary|v1|" "$VERSION_FILE"
}

@test "strict checksum mode wins over an inherited FAST_MODE (SI-8)" {
    source_libs --installers debian apt
    make_test_tmpdir
    # update.sh has no --fast/--production exclusivity check, so both can be set.
    export VERSION_FILE="$TEST_TMPDIR/.versions" FAST_MODE=true REQUIRE_CHECKSUMS=true SYS_ARCH=amd64
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$TEST_TMPDIR/src" "$PIPX_BIN_DIR"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/src/zz-fake-tool"
    tar -czf "$TEST_TMPDIR/fixture.tar.gz" -C "$TEST_TMPDIR/src" .
    # The release publishes no checksum file.
    _gh_api_get() {
        printf '{"tag_name":"v1","assets":[{"name":"zz-fake-tool_linux_amd64.tar.gz","browser_download_url":"https://example.invalid/zz-fake-tool_linux_amd64.tar.gz"}]}'
    }
    curl() {
        local out=""
        while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && out="$2"; shift; done
        cp "$TEST_TMPDIR/fixture.tar.gz" "$out"
    }

    run download_github_release "example/zz-fake-tool" "zz-fake-tool" "linux_amd64\\.tar\\.gz$" \
        "$TEST_TMPDIR/opt/zz-fake-tool"
    assert_failure
    assert_output --partial "no checksum file"
    [[ ! -e "$TEST_TMPDIR/opt/zz-fake-tool/zz-fake-tool" ]]
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

@test "verify_github_checksum accepts a per-file .sha256 holding a bare hash" {
    source_libs --installers debian apt
    make_test_tmpdir
    _gh_api_cache_init
    local url="https://example.com/tool.sha256"
    local key; key=$(echo "$url" | sed 's|[/:?&=]|_|g')
    local bin="$TEST_TMPDIR/tool"
    printf 'binary-contents\n' > "$bin"
    local hash; hash=$(sha256sum "$bin" | awk '{print $1}')
    printf '%s\n' "$hash" > "$_GH_API_CACHE_DIR/checksum_${key}"
    # Selection must prefer the per-file .sha256 and skip the signature asset.
    local rel='{"assets":[{"name":"tool.sha256","browser_download_url":"'"$url"'"},{"name":"tool.sig","browser_download_url":"https://example.com/tool.sig"}]}'

    run verify_github_checksum "$rel" "$bin" "tool"
    assert_success
}

@test "verify_github_checksum ignores a signature-only release (no false verify)" {
    source_libs --installers debian apt
    make_test_tmpdir
    _gh_api_cache_init
    local bin="$TEST_TMPDIR/tool"
    printf 'binary-contents\n' > "$bin"
    # Only a .sig asset — no hash anywhere, so verification must report "no checksum".
    local rel='{"assets":[{"name":"tool.sig","browser_download_url":"https://example.com/tool.sig"}]}'

    run verify_github_checksum "$rel" "$bin" "tool"
    assert_failure
    [ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]
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

@test "_setup_curl_opts falls back to the invoking user's gh login under sudo" {
    source_libs --installers debian apt
    unset GITHUB_TOKEN
    export SUDO_USER=builder
    gh() { return 1; }
    _as_builder() { [[ "$1" == "gh auth token" ]] && printf 'usertoken456\n'; }

    _setup_curl_opts

    [ "$GITHUB_TOKEN" = "usertoken456" ]
    grep -q "password usertoken456" "$_GH_NETRC_FILE"
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

# openbsd-netcat is the Arch [extra] package; gnu-netcat is AUR-only.
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

# remove_npm_packages — the destructive npm path. It must never uninstall a
# package the host already had (remove.sh filters those out first) and must not
# treat an absent package as a failure.

@test "remove_npm_packages uninstalls only globally installed packages" {
    run bash -lc '
        source_libs() { :; }
        source "'"$PROJECT_ROOT"'/lib/common.sh" >/dev/null 2>&1
        source "'"$PROJECT_ROOT"'/lib/installers.sh" >/dev/null 2>&1
        _log=$(mktemp); export LOG_FILE="$_log"
        REMOVAL_FAILURES=0
        npm() {
            case "$1 $2" in
                "ls -g")  [[ "$4" == "surya" ]] ;;
                "uninstall -g") echo "UNINSTALL:$3" ;;
                *) return 1 ;;
            esac
        }
        remove_npm_packages surya solgraph
        cat "$_log"; rm -f "$_log"
        echo "failures=$REMOVAL_FAILURES"
    '
    assert_success
    assert_output --partial "UNINSTALL:surya"
    refute_output --partial "UNINSTALL:solgraph"
    assert_output --partial "npm packages: 1 removed, 1 already removed"
    assert_output --partial "failures=0"
}

@test "remove_npm_packages counts a failed uninstall and keeps going" {
    run bash -lc '
        source "'"$PROJECT_ROOT"'/lib/common.sh" >/dev/null 2>&1
        source "'"$PROJECT_ROOT"'/lib/installers.sh" >/dev/null 2>&1
        export LOG_FILE=/dev/null
        REMOVAL_FAILURES=0
        npm() { [[ "$1 $2" == "ls -g" ]] && return 0; return 1; }
        remove_npm_packages apk-mitm surya
        echo "failures=$REMOVAL_FAILURES"
    '
    assert_success
    assert_output --partial "failures=2"
    assert_output --partial "npm packages: 0 removed, 0 already removed"
}

@test "remove_npm_packages is a no-op without npm or without packages" {
    run bash -lc '
        source "'"$PROJECT_ROOT"'/lib/common.sh" >/dev/null 2>&1
        source "'"$PROJECT_ROOT"'/lib/installers.sh" >/dev/null 2>&1
        export LOG_FILE=/dev/null
        command_exists() { [[ "$1" != "npm" ]]; }
        remove_npm_packages surya || exit 1
        remove_npm_packages || exit 1
    '
    assert_success
    assert_output --partial "npm not found"
}

@test "install_npm_batch records a globally pre-installed package as existing" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    ensure_node() { return 0; }
    show_progress() { :; }
    npm() {
        case "$1 $2" in
            "ls -g")      [[ "$4" == "surya" ]] ;;
            "install -g") echo "$3" >> "$TEST_TMPDIR/npm_installs" ;;
            *)            return 1 ;;
        esac
    }

    install_npm_batch "npm test" surya solgraph

    grep -q "^surya|npm|existing|" "$VERSION_FILE"
    grep -q "^solgraph|npm|latest|" "$VERSION_FILE"
    [[ "$(cat "$TEST_TMPDIR/npm_installs")" == "solgraph" ]]
}

# ligolo-ng publishes separate agent/proxy tarballs whose binaries are named
# agent and proxy; assets are listed alphabetically, agent first.
@test "ligolo-ng entries select their own tarball and in-archive binary" {
    source_libs debian apt
    export SYS_ARCH=amd64
    source "$PROJECT_ROOT/lib/installers.sh"
    local assets='{"assets":[
        {"name":"ligolo-ng_0.9.1_checksums.txt"},
        {"name":"ligolo-ng_agent_0.9.1_linux_amd64.tar.gz"},
        {"name":"ligolo-ng_agent_0.9.1_windows_amd64.zip"},
        {"name":"ligolo-ng_proxy_0.9.1_linux_amd64.tar.gz"}]}'
    local entry repo binary pattern dest archive picked checked=0
    for entry in "${BINARY_RELEASES_NETWORKING[@]}"; do
        IFS='|' read -r repo binary pattern dest archive <<< "$entry"
        [[ "$repo" == "nicocha30/ligolo-ng" ]] || continue
        checked=$((checked + 1))
        picked=$(printf '%s' "$assets" | python3 -c '
import json, re, sys
for a in json.load(sys.stdin)["assets"]:
    if re.search(sys.argv[1], a["name"]):
        print(a["name"]); break' "$pattern")
        case "$binary" in
            ligolo-proxy) [[ "$picked" == "ligolo-ng_proxy_0.9.1_linux_amd64.tar.gz" && "$archive" == "proxy" ]] ;;
            ligolo-agent) [[ "$picked" == "ligolo-ng_agent_0.9.1_linux_amd64.tar.gz" && "$archive" == "agent" ]] ;;
            *) false ;;
        esac
    done
    [[ "$checked" -eq 2 ]]
}

# npm aggregation — install.sh, update.sh and remove.sh all reach module _NPM
# arrays through the shared collectors, so one broken prefix silently drops the
# tools from install, update and rollback at once.

@test "npm aggregation: _collect_module_arrays picks up every module _NPM array" {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/modules/mobile.sh"
    source "$PROJECT_ROOT/modules/blockchain.sh"

    declare -a _ALL_NPM=()
    _collect_module_arrays "NPM" _ALL_NPM

    [[ "${_ALL_NPM[*]}" == *"apk-mitm"* ]]
    [[ "${_ALL_NPM[*]}" == *"rms-runtime-mobile-security"* ]]
    [[ "${_ALL_NPM[*]}" == *"surya"* ]]
    [[ "${_ALL_NPM[*]}" == *"solgraph"* ]]
}

@test "npm aggregation: _append_module_array and _module_array_names cover _NPM" {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/modules/mobile.sh"

    declare -a _appended=()
    _append_module_array _appended "MOBILE_NPM"
    [[ "${_appended[*]}" == *"apk-mitm"* ]]

    declare -a _names=()
    _module_array_names NPM _names
    [[ "${_names[*]}" == *"MOBILE_NPM"* ]]
    [[ "${_names[*]}" == *"BLOCKCHAIN_NPM"* ]]
}

# Stage-1 C2 aggregation (install.sh install_modules loop)

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

@test "uninstall helpers report a survivor with status 2" {
    source_libs --installers debian apt
    snap_available() { return 0; }
    snap() { [[ "$1" == list ]]; }
    docker() { [[ "$1" != rmi ]]; }
    command_exists() { [[ "$1" == docker ]]; }

    run remove_snap_tool zaproxy
    assert_failure 2
    run remove_docker_tool SpiderFoot
    assert_failure 2
}

@test "remove_binary_release removes a dedicated release dir but keeps a shared one" {
    source_libs --installers debian apt
    make_test_tmpdir
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin" VERSION_FILE="$TEST_TMPDIR/.versions"
    mkdir -p "$PIPX_BIN_DIR" "$TEST_TMPDIR/own" "$TEST_TMPDIR/shared"
    BINARY_RELEASES_FIXTURE=(
        "o/own|owntool|x|$TEST_TMPDIR/own"
        "o/a|jar-a|x|$TEST_TMPDIR/shared"
        "o/b|jar-b|x|$TEST_TMPDIR/shared"
    )
    touch "$PIPX_BIN_DIR/owntool" "$PIPX_BIN_DIR/jar-a"
    printf 'jar-b|binary|v1|2026-01-01 00:00:00\n' > "$VERSION_FILE"

    run remove_binary_release owntool
    assert_success
    [[ ! -e "$TEST_TMPDIR/own" && ! -e "$PIPX_BIN_DIR/owntool" ]]
    run remove_binary_release jar-a
    assert_success
    [[ -d "$TEST_TMPDIR/shared" && ! -e "$PIPX_BIN_DIR/jar-a" ]]
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
    ! grep -q "^nmap|dnf|installed|" "$_SESSION_FILE" || false
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
    ! grep -q "^ourtool|git|installed|" "$_SESSION_FILE" || false
    grep -q "^ourtool|git|HEAD|" "$VERSION_FILE"
}

@test "docker_pull records an image the host already had as existing" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    export _SESSION_FILE="$TEST_TMPDIR/manifest"
    : > "$_SESSION_FILE"
    docker() { return 0; }
    command_exists() { [[ "$1" == docker ]]; }

    docker_pull "example/present:latest" "PresentTool"

    grep -q "^PresentTool|docker|existing|" "$VERSION_FILE"
    ! grep -q "^PresentTool|docker|installed|" "$_SESSION_FILE" || false
}

@test "docker_pull records a newly pulled image as installed" {
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    export _SESSION_FILE="$TEST_TMPDIR/manifest"
    : > "$_SESSION_FILE"
    docker() { [[ "$1" != image ]]; }
    command_exists() { [[ "$1" == docker ]]; }

    docker_pull "example/new:latest" "NewTool"

    grep -q "^NewTool|docker|example/new:latest|" "$VERSION_FILE"
    grep -q "^NewTool|docker|installed|" "$_SESSION_FILE"
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
    ! grep -q "^ourtool|source|installed|" "$_SESSION_FILE" || false
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
    ! grep -q "^ours|cargo|installed|" "$_SESSION_FILE" || false
    grep -q "^ours|cargo|existing|" "$_SESSION_FILE"
}

# Rollback must not report success on a failed removal.

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

@test "install_ctf_venv installs one package per pip call under the venvs dir" {
    source_libs --installers debian apt
    make_test_tmpdir
    export CYBERSEC_MCP_VENVS_DIR="$TEST_TMPDIR/venvs"
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    _as_builder() { echo "$1" >> "$TEST_TMPDIR/cmds"; }

    run install_ctf_venv crypto sympy fpylll
    assert_success

    run cat "$TEST_TMPDIR/cmds"
    assert_output --partial "python3 -m venv '$TEST_TMPDIR/venvs/crypto'"
    assert_output --partial "venvs/crypto/bin/pip' install -q 'sympy'"
    assert_output --partial "venvs/crypto/bin/pip' install -q 'fpylll'"
    # A venv we created is ours, so remove.sh may uninstall it.
    grep -q "^ctf-crypto-venv|special|latest|" "$VERSION_FILE"
}

@test "install_ctf_venv records a hand-built venv as pre-existing" {
    source_libs --installers debian apt
    make_test_tmpdir
    export CYBERSEC_MCP_VENVS_DIR="$TEST_TMPDIR/venvs"
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    # ~/.ctf-venvs/<name> is a documented manual pattern — adding libraries to a
    # venv the user built must not make remove.sh delete it.
    mkdir -p "$CYBERSEC_MCP_VENVS_DIR/crypto/bin"
    : > "$CYBERSEC_MCP_VENVS_DIR/crypto/bin/python"
    chmod +x "$CYBERSEC_MCP_VENVS_DIR/crypto/bin/python"
    _as_builder() { echo "$1" >> "$TEST_TMPDIR/cmds"; }

    run install_ctf_venv crypto sympy
    assert_success

    grep -q "^ctf-crypto-venv|special|existing|" "$VERSION_FILE"
    run cat "$TEST_TMPDIR/cmds"
    refute_output --partial "python3 -m venv"
    _is_preexisting ctf-crypto-venv
}

@test "install_ctf_venv keeps its own venv ours across a re-run" {
    source_libs --installers debian apt
    make_test_tmpdir
    export CYBERSEC_MCP_VENVS_DIR="$TEST_TMPDIR/venvs"
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    _as_builder() { return 0; }

    run install_ctf_venv crypto sympy
    assert_success
    # First run created it; simulate the interpreter it would have left behind.
    mkdir -p "$CYBERSEC_MCP_VENVS_DIR/crypto/bin"
    : > "$CYBERSEC_MCP_VENVS_DIR/crypto/bin/python"
    chmod +x "$CYBERSEC_MCP_VENVS_DIR/crypto/bin/python"

    run install_ctf_venv crypto sympy
    assert_success
    grep -q "^ctf-crypto-venv|special|latest|" "$VERSION_FILE"
    [[ "$(grep -c '^ctf-crypto-venv|' "$VERSION_FILE")" -eq 1 ]]
}

@test "install_ctf_venv reports the package that failed without tracking the venv" {
    source_libs --installers debian apt
    make_test_tmpdir
    export CYBERSEC_MCP_VENVS_DIR="$TEST_TMPDIR/venvs"
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    mkdir -p "$CYBERSEC_MCP_VENVS_DIR/crypto/bin"
    : > "$CYBERSEC_MCP_VENVS_DIR/crypto/bin/python"
    chmod +x "$CYBERSEC_MCP_VENVS_DIR/crypto/bin/python"
    # cypari2 has no wheel for every Python/arch — the rest must still install.
    _as_builder() { [[ "$1" == *"'cypari2'"* ]] && return 1; return 0; }

    run install_ctf_venv crypto sympy cypari2
    assert_failure
    assert_output --partial "cypari2 failed"
    assert_output --partial "1/2 libraries installed"
    [[ ! -f "$VERSION_FILE" ]]
}

@test "install_ctf_venv honours --skip-pipx" {
    source_libs --installers debian apt
    make_test_tmpdir
    export CYBERSEC_MCP_VENVS_DIR="$TEST_TMPDIR/venvs"
    export SKIP_PIPX=true

    run install_ctf_venv crypto sympy
    assert_success
    assert_output --partial "Skipping crypto venv"
    [[ ! -d "$CYBERSEC_MCP_VENVS_DIR" ]]
}

@test "remove_special_tool removes a ctf venv from the venvs dir" {
    source_libs --installers debian apt
    make_test_tmpdir
    export CYBERSEC_MCP_VENVS_DIR="$TEST_TMPDIR/venvs"
    mkdir -p "$CYBERSEC_MCP_VENVS_DIR/crypto/bin"

    run remove_special_tool ctf-crypto-venv
    assert_success
    [[ ! -e "$CYBERSEC_MCP_VENVS_DIR/crypto" ]]
}

@test "remove_special_tool refuses a ctf venv with an empty name" {
    source_libs --installers debian apt
    make_test_tmpdir
    export CYBERSEC_MCP_VENVS_DIR="$TEST_TMPDIR/venvs"
    mkdir -p "$CYBERSEC_MCP_VENVS_DIR/crypto/bin"

    # "ctf--venv" would otherwise resolve to the venvs root itself.
    run remove_special_tool ctf--venv
    assert_failure
    [[ -d "$CYBERSEC_MCP_VENVS_DIR/crypto" ]]
}

@test "batch provenance arrays are associative" {
    source_libs --installers debian apt

    # Without -A the subscript is evaluated arithmetically, so _track_pkg aborts
    # on the first package name under `set -u` ("unzip: unbound variable").
    run declare -p _APT_PREEXISTING
    assert_success
    assert_output --partial "declare -A"

    run declare -p _APT_PRIOR_TOOLKIT
    assert_success
    assert_output --partial "declare -A"
}

@test "remove_special_tool foundry removes binaries but keeps keystores" {
    source_libs --installers debian apt
    make_test_tmpdir
    _builder_home() { echo "$TEST_TMPDIR/home"; }
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$TEST_TMPDIR/home/.foundry/bin" "$TEST_TMPDIR/home/.foundry/keystores" "$PIPX_BIN_DIR"
    printf 'bin\n' > "$TEST_TMPDIR/home/.foundry/bin/forge"
    printf 'KEY\n' > "$TEST_TMPDIR/home/.foundry/keystores/wallet.json"
    ln -s "$TEST_TMPDIR/home/.foundry/bin/forge" "$PIPX_BIN_DIR/forge"

    remove_special_tool foundry

    [[ ! -e "$TEST_TMPDIR/home/.foundry/bin" ]]          # toolkit binaries removed
    [[ ! -e "$PIPX_BIN_DIR/forge" ]]                      # symlink removed
    [[ -f "$TEST_TMPDIR/home/.foundry/keystores/wallet.json" ]]  # wallet kept
}

@test "remove_special_tool steampipe keeps the .steampipe config dir" {
    source_libs --installers debian apt
    make_test_tmpdir
    _builder_home() { echo "$TEST_TMPDIR/home"; }
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$TEST_TMPDIR/home/.steampipe/config" "$PIPX_BIN_DIR"
    printf 'conn\n' > "$TEST_TMPDIR/home/.steampipe/config/aws.spc"

    remove_special_tool steampipe

    [[ -f "$TEST_TMPDIR/home/.steampipe/config/aws.spc" ]]  # connection config kept
}

@test "zip release assets install without archive group/world-write bits (SI-5)" {
    command -v unzip >/dev/null || skip "needs unzip"
    source_libs --installers debian apt
    make_test_tmpdir
    export VERSION_FILE="$TEST_TMPDIR/.versions" FAST_MODE=true SYS_ARCH=amd64
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$PIPX_BIN_DIR"
    # An upstream zip that stores its files world-writable (0777).
    python3 - "$TEST_TMPDIR/fixture.zip" <<'PY'
import sys, zipfile
info = zipfile.ZipInfo("zz-fake-tool")
info.external_attr = 0o100777 << 16
with zipfile.ZipFile(sys.argv[1], "w") as archive:
    archive.writestr(info, "#!/bin/sh\n")
PY
    _gh_api_get() {
        printf '{"tag_name":"v1","assets":[{"name":"zz-fake-tool_linux_amd64.zip","browser_download_url":"https://example.invalid/zz-fake-tool_linux_amd64.zip"}]}'
    }
    curl() {
        local out=""
        while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && out="$2"; shift; done
        cp "$TEST_TMPDIR/fixture.zip" "$out"
    }

    run download_github_release "example/zz-fake-tool" "zz-fake-tool" "linux_amd64\\.zip$" \
        "$TEST_TMPDIR/opt/zz-fake-tool"
    assert_success
    [[ -z "$(find "$TEST_TMPDIR/opt/zz-fake-tool" -perm /022)" ]]
}

_distro_package_fixture() {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/modules/blueteam.sh"
    source "$PROJECT_ROOT/modules/forensics.sh"
    IS_WSL=false
    IS_ARM=false
}

@test "OpenSCAP and mat2 compatibility rows match their module package names" {
    _distro_package_fixture
    [[ " ${BLUETEAM_PACKAGES[*]} " == *" openscap-scanner "* ]]
    [[ " ${FORENSICS_PACKAGES[*]} " == *" mat2 "* ]]
    _load_distro_compat
    [[ "${_COMPAT_PACMAN[openscap-scanner]}" == openscap ]]
    [[ "${_COMPAT_ZYPPER[openscap-scanner]}" == openscap-utils ]]
    [[ "${_COMPAT_ZYPPER[mat2]}" == - ]]
    [[ "${_COMPAT_PKG[openscap-scanner]}" == - && "${_COMPAT_PKG[mat2]}" == - ]]

    run python3 "$PROJECT_ROOT/scripts/validate_distro_compat.py"
    assert_success
    [[ "$output" == *"Errors: 0"* ]]
}

@test "OpenSCAP and mat2 translate to available package names across package managers" {
    _distro_package_fixture
    local distro manager expected
    while IFS='|' read -r distro manager expected; do
        DISTRO_ID="$distro"
        PKG_MANAGER="$manager"
        local -a packages=(openscap-scanner mat2 curl)
        fixup_package_names packages
        [[ "${packages[*]}" == "$expected" ]] || {
            printf '%s: expected %s, got %s\n' "$distro" "$expected" "${packages[*]}"
            return 1
        }
    done <<'MAPPINGS'
debian|apt|openscap-scanner mat2 curl
ubuntu|apt|openscap-scanner mat2 curl
fedora|dnf|openscap-scanner mat2 curl
arch|pacman|openscap mat2 curl
opensuse-tumbleweed|zypper|openscap-utils curl
termux|pkg|curl
MAPPINGS
}

@test "RHEL retains the supported OpenSCAP scanner package name" {
    _distro_package_fixture
    DISTRO_ID=rhel
    PKG_MANAGER=dnf
    local -a packages=(openscap-scanner curl)
    fixup_package_names packages
    [[ "${packages[*]}" == "openscap-scanner curl" ]]
}

@test "mat2 skip follows RHEL ancestry while Fedora derivatives retain their package" {
    _distro_package_fixture
    PKG_MANAGER=dnf
    DISTRO_ID=synthetic-fedora-derivative
    DISTRO_ID_LIKE=fedora
    local -a packages=(mat2)
    fixup_package_names packages
    [[ "${packages[*]}" == mat2 ]]
    DISTRO_ID=synthetic-rhel-derivative
    DISTRO_ID_LIKE='rhel fedora'
    packages=(mat2)
    fixup_package_names packages
    [[ ${#packages[@]} -eq 0 ]]
}

@test "mat2 remains available on Fedora and is skipped on RHEL derivatives" {
    _distro_package_fixture
    local distro expected
    PKG_MANAGER=dnf
    for distro in fedora rhel centos rocky almalinux; do
        DISTRO_ID="$distro"
        DISTRO_ID_LIKE=rhel
        local -a packages=(mat2 openscap-scanner curl)
        expected="openscap-scanner curl"
        [[ "$distro" == fedora ]] && expected="mat2 $expected"
        fixup_package_names packages
        [[ "${packages[*]}" == "$expected" ]] || {
            printf '%s: expected %s, got %s\n' "$distro" "$expected" "${packages[*]}"
            return 1
        }
    done
}

_binary_release_fixture() {
    source_libs --installers debian apt
    make_test_tmpdir
    GITHUB_TOOL_DIR="$TEST_TMPDIR/tools"
    PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    SYS_ARCH=amd64
    SYS_ARCH_ALT=x86_64
    IS_ARM=false
    VERSION_FILE="$TEST_TMPDIR/.versions"
    declare -gA MISC_BINARY_ARCHITECTURES=(
        [fixture-x64]='amd64'
        [fixture-arm64]='amd64 arm64'
        [fixture-portable]='amd64 arm64 armv7'
    )
    declare -gA MISC_BINARY_EXCLUSIVE_DIRS=(
        [fixture-release]=true
        [fixture-bundle]=true
    )
    declare -gA MISC_BINARY_RUNTIME_CONFIGS=([fixture-runtime]='{}')
    declare -gA MISC_BINARY_RUNTIME_RELEASES=([fixture-runtime]='v1.2.3')
}

@test "binary release patterns select upstream ARM asset names" {
    _binary_release_fixture
    SYS_ARCH=arm64
    SYS_ARCH_ALT=aarch64
    source "$PROJECT_ROOT/lib/installers.sh"
    local entry pattern
    for entry in "${BINARY_RELEASES_ENTERPRISE[@]}"; do
        [[ "$entry" == *'|TeamFiltration|'* ]] || continue
        IFS='|' read -r _ _ pattern _ <<< "$entry"
        [[ TeamFiltration-v3.5.5-linux-arm64.zip =~ $pattern ]]
        [[ ! TeamFiltration-v3.5.5-linux-x86_64.zip =~ $pattern ]]
    done
    SYS_ARCH=armv7
    SYS_ARCH_ALT=armv7l
    source "$PROJECT_ROOT/lib/installers.sh"
    for entry in "${BINARY_RELEASES_FORENSICS[@]}"; do
        [[ "$entry" == *'|vmkatz|'* ]] || continue
        IFS='|' read -r _ _ pattern _ <<< "$entry"
        [[ vmkatz-1.5.1-linux-armv7.tar.gz =~ $pattern ]]
        [[ ! vmkatz-1.5.1-linux-aarch64.tar.gz =~ $pattern ]]
    done
}

@test "single tool install and update skip unsupported binary platforms before network" {
    _binary_release_fixture
    _gh_api_get() { touch "$TEST_TMPDIR/network"; return 1; }
    SYS_ARCH=armv7
    download_github_release synthetic/project fixture-arm64 pattern
    download_github_release_update synthetic/project fixture-x64 pattern
    PKG_MANAGER=pkg
    SYS_ARCH=amd64
    download_github_release synthetic/project fixture-portable pattern
    [[ ! -e "$TEST_TMPDIR/network" ]]
    [[ ! -e "$PIPX_BIN_DIR" && -z "$_RELEASE_TAG" ]]
}

@test "pinned dependency cannot use metadata from another release tag" {
    _binary_release_fixture
    command_exists() { return 0; }
    _gh_api_get() { printf '{"tag_name":"v9.9.9","assets":[]}\n'; }
    curl() { touch "$TEST_TMPDIR/download"; return 1; }
    run _download_github_release_impl synthetic/dependency libfixture.so pattern \
        "$PIPX_BIN_DIR" dependency libfixture.so v1.2.3
    assert_failure
    assert_output --partial 'does not match requested tag v1.2.3'
    [[ ! -e "$TEST_TMPDIR/download" ]]
}

@test "unreviewed release fails before installing a configured runtime" {
    _binary_release_fixture
    run _prepare_binary_runtime fixture-runtime "$TEST_TMPDIR" fixture-executable v9.9.9
    assert_failure
    assert_output --partial 'needs a reviewed runtime configuration'
    [[ ! -e "$TEST_TMPDIR/.runtime" ]]
}

@test "binary runtime preparation keeps pinned dependencies private and preserves install settings" {
    _binary_release_fixture
    local content_root="$TEST_TMPDIR/bundle"
    mkdir -p "$content_root/bin"
    printf '#!/bin/sh\nexit 0\n' > "$content_root/bin/fixture-runtime"
    chmod +x "$content_root/bin/fixture-runtime"
    MISC_BINARY_RUNTIME_CONFIGS[fixture-runtime]='{"working_directory":".","library_directories":[".runtime"],"required_files":[".runtime/libfixture.so"],"commands":{"inspect":"input:i:p"}}'
    declare -gA MISC_BINARY_DEPENDENCIES=(
        [fixture-runtime]='synthetic/dependency|libfixture.so|^fixture.zip$|.runtime|v1.2.3'
    )
    REQUIRE_CHECKSUMS=false
    FAST_MODE=true
    _download_github_release_impl() {
        [[ "$1" == synthetic/dependency && "$2" == libfixture.so && "$5" == dependency && "$7" == v1.2.3 ]]
        [[ "$4" == "$TEST_TMPDIR/bundle/.runtime" && "$PIPX_BIN_DIR" == "$4" ]]
        [[ "$REQUIRE_CHECKSUMS" == true && "$FAST_MODE" == false ]]
        mkdir -p "$4"
        printf 'synthetic library\n' > "$4/libfixture.so"
    }

    _prepare_binary_runtime fixture-runtime "$content_root" "$content_root/bin/fixture-runtime" v1.2.3

    [[ -x "$content_root/runtime_launcher.py" && -f "$content_root/.runtime/libfixture.so" ]]
    [[ "$PIPX_BIN_DIR" == "$TEST_TMPDIR/bin" && "$REQUIRE_CHECKSUMS" == false && "$FAST_MODE" == true ]]
    [[ ! -e "$PIPX_BIN_DIR/libfixture.so" ]]
    run python3 - "$content_root/.runtime-launcher.json" <<'PYTHON'
import json
import sys
from pathlib import Path

configuration = json.loads(Path(sys.argv[1]).read_text())
assert configuration["executable"] == "bin/fixture-runtime"
assert configuration["library_directories"] == [".runtime"]
assert configuration["commands"] == {"inspect": "input:i:p"}
PYTHON
    assert_success
}

@test "binary runtime rejects unpinned or escaping dependencies before downloading" {
    _binary_release_fixture
    declare -gA MISC_BINARY_DEPENDENCIES=()
    _download_github_release_impl() { touch "$TEST_TMPDIR/download"; return 1; }
    local specification
    for specification in \
        'synthetic/dependency|libfixture.so|pattern|.runtime|' \
        'synthetic/dependency|libfixture.so|pattern|/outside|v1.2.3' \
        'synthetic/dependency|libfixture.so|pattern|../outside|v1.2.3' \
        'synthetic/dependency|libfixture.so|pattern|nested/../../outside|v1.2.3'; do
        MISC_BINARY_DEPENDENCIES[fixture-runtime]="$specification"
        run _prepare_binary_runtime fixture-runtime "$TEST_TMPDIR" "$TEST_TMPDIR/fixture-runtime" v1.2.3
        assert_failure
        assert_output --partial 'Invalid runtime dependency configuration'
        [[ ! -e "$TEST_TMPDIR/download" && ! -e "$TEST_TMPDIR/.runtime-launcher.json" ]]
    done
}

@test "unsupported binary batch does not record a successful phantom installation" {
    _binary_release_fixture
    SYS_ARCH=ppc64le
    _gh_api_get() { touch "$TEST_TMPDIR/network"; return 1; }
    track_version() { touch "$TEST_TMPDIR/tracked"; }
    install_binary_releases 'synthetic/project|fixture-x64|pattern' \
        'synthetic/project|fixture-arm64|pattern' 'synthetic/project|fixture-portable|pattern'
    [[ ! -e "$TEST_TMPDIR/network" && ! -e "$TEST_TMPDIR/tracked" ]]
}

@test "unsupported binary update leaves the existing version record untouched" {
    _binary_release_fixture
    eval "$(sed -n '/^    update_binary()/,/^    }/p' "$PROJECT_ROOT/scripts/update.sh")"
    SYS_ARCH=armv7
    _version_known() { touch "$TEST_TMPDIR/version-check"; return 0; }
    _track_update() { touch "$TEST_TMPDIR/tracked"; }
    _gh_api_get() { touch "$TEST_TMPDIR/network"; return 1; }
    update_binary synthetic/project fixture-arm64 pattern
    [[ ! -e "$TEST_TMPDIR/version-check" && ! -e "$TEST_TMPDIR/network" && ! -e "$TEST_TMPDIR/tracked" ]]
}

@test "exclusive release directories preserve untracked and pre-existing user files" {
    _binary_release_fixture
    _gh_api_get() { touch "$TEST_TMPDIR/network"; return 1; }
    local tool mode
    for tool in fixture-release fixture-bundle; do
        mkdir -p "$GITHUB_TOOL_DIR/$tool"
        printf 'synthetic user research\n' > "$GITHUB_TOOL_DIR/$tool/notes.txt"
        for mode in install update; do
            run _download_github_release_impl owner/repo "$tool" pattern "$GITHUB_TOOL_DIR/$tool" "$mode"
            assert_failure
            assert_output --partial 'Preserving destination not owned by the toolkit'
            [[ "$(cat "$GITHUB_TOOL_DIR/$tool/notes.txt")" == 'synthetic user research' ]]
        done
        printf '%s|binary|existing|2026-10-13\n' "$tool" > "$VERSION_FILE"
        run _download_github_release_impl owner/repo "$tool" pattern "$GITHUB_TOOL_DIR/$tool" install
        assert_failure
        assert_output --partial 'Preserving destination not owned by the toolkit'
    done
    [[ ! -e "$TEST_TMPDIR/network" ]]
}

@test "exclusive release directories refuse a symlink even with a toolkit version record" {
    _binary_release_fixture
    mkdir -p "$GITHUB_TOOL_DIR" "$TEST_TMPDIR/user-files"
    ln -s "$TEST_TMPDIR/user-files" "$GITHUB_TOOL_DIR/fixture-release"
    printf 'fixture-release|binary|v1.2.3|2026-10-13\n' > "$VERSION_FILE"
    _gh_api_get() { touch "$TEST_TMPDIR/network"; return 1; }
    run _download_github_release_impl synthetic/project fixture-release pattern "$GITHUB_TOOL_DIR/fixture-release" update
    assert_failure
    assert_output --partial 'Preserving existing destination'
    [[ -L "$GITHUB_TOOL_DIR/fixture-release" && ! -e "$TEST_TMPDIR/network" ]]
}

@test "owned exclusive release directories permit a refresh without relabeling ownership" {
    _binary_release_fixture
    mkdir -p "$GITHUB_TOOL_DIR/fixture-release" "$PIPX_BIN_DIR"
    printf '#!/bin/sh\nexit 0\n' > "$GITHUB_TOOL_DIR/fixture-release/fixture-release"
    chmod +x "$GITHUB_TOOL_DIR/fixture-release/fixture-release"
    ln -s "$GITHUB_TOOL_DIR/fixture-release/fixture-release" "$PIPX_BIN_DIR/fixture-release"
    printf 'fixture-release|binary|v1.2.3|2026-10-13\n' > "$VERSION_FILE"
    command_exists() { [[ "$1" == unzip ]]; }
    _gh_api_get() { touch "$TEST_TMPDIR/network"; return 1; }
    run _download_github_release_impl synthetic/project fixture-release pattern "$GITHUB_TOOL_DIR/fixture-release" update
    assert_failure
    [[ -e "$TEST_TMPDIR/network" ]]
    grep -q '^fixture-release|binary|v1.2.3|' "$VERSION_FILE"
}

@test "exclusive release updates preserve a foreign PATH replacement" {
    _binary_release_fixture
    mkdir -p "$PIPX_BIN_DIR" "$GITHUB_TOOL_DIR/fixture-release"
    printf 'fixture-release|binary|v1.2.3|2026-10-13\n' > "$VERSION_FILE"
    printf 'synthetic user file\n' > "$PIPX_BIN_DIR/fixture-release"
    _gh_api_get() { touch "$TEST_TMPDIR/network"; return 1; }
    run _download_github_release_impl synthetic/project fixture-release pattern "$GITHUB_TOOL_DIR/fixture-release" update
    assert_failure
    assert_output --partial 'Preserving existing executable'
    [[ "$(cat "$PIPX_BIN_DIR/fixture-release")" == 'synthetic user file' ]]
    rm "$PIPX_BIN_DIR/fixture-release"
    ln -s "$TEST_TMPDIR/foreign-program" "$PIPX_BIN_DIR/fixture-release"
    run _download_github_release_impl synthetic/project fixture-release pattern "$GITHUB_TOOL_DIR/fixture-release" update
    assert_failure
    [[ "$(readlink "$PIPX_BIN_DIR/fixture-release")" == "$TEST_TMPDIR/foreign-program" && ! -e "$TEST_TMPDIR/network" ]]
}

_release_checksum_fixture() {
    source_libs --installers debian apt
    make_test_tmpdir
    export SCRIPT_DIR="$TEST_TMPDIR"
    mkdir -p "$SCRIPT_DIR/lib" "$TEST_TMPDIR/cache"
    FIXTURE_ASSET="synthetic-tool_linux_amd64.tar.gz"
    FIXTURE_FILE="$TEST_TMPDIR/$FIXTURE_ASSET"
    printf 'synthetic release artifact\n' > "$FIXTURE_FILE"
    FIXTURE_HASH=$(sha256sum "$FIXTURE_FILE" | awk '{print $1}')
    WRONG_HASH=$(printf '%064d' 0)
    MOCK_CHECKSUM_BODY=""
    MOCK_CURL_STATUS=22
    : > "$TEST_TMPDIR/curl-calls"

    _gh_api_cache_init() {
        _GH_API_CACHE_DIR="$TEST_TMPDIR/cache"
    }
    _setup_curl_opts() {
        _CURL_OPTS=(-sSL)
    }
    curl() {
        printf '%s\n' "$*" >> "$TEST_TMPDIR/curl-calls"
        printf '%s' "$MOCK_CHECKSUM_BODY"
        return "$MOCK_CURL_STATUS"
    }
}

_release_fixture() {
    local digest="${1:-null}" tag="${2:-v1.2.3}" name="${3:-$FIXTURE_ASSET}"
    local duplicate="${4:-false}" manifest="${5:-false}"
    python3 - "$digest" "$tag" "$name" "$duplicate" "$manifest" <<'PY'
import json
import sys

digest, tag, name, duplicate, manifest = sys.argv[1:]
asset = {"name": name, "browser_download_url": "https://example.invalid/" + name}
if digest != "missing":
    asset["digest"] = json.loads(digest)
assets = [asset]
if duplicate == "true":
    assets.append({**asset, "browser_download_url": "https://example.invalid/duplicate/" + name})
if manifest == "true":
    assets.append({"name": "checksums.txt", "browser_download_url": "https://example.invalid/checksums.txt"})
print(json.dumps({"tag_name": tag, "assets": assets}))
PY
}

_reviewed_checksum() {
    printf 'synthetic/project\tv1.2.3\t%s\t%s\n' "$FIXTURE_ASSET" "${1:-$FIXTURE_HASH}" \
        > "$SCRIPT_DIR/lib/release_checksums.tsv"
}

@test "release metadata accepts only the exact asset SHA256 digest" {
    _release_checksum_fixture
    local release
    release=$(_release_fixture '"sha256:'"${FIXTURE_HASH^^}"'"')

    run _verify_release_metadata_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_success
    assert_output --partial "Checksum verified"
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
    [[ ! -s "$TEST_TMPDIR/curl-calls" ]]
}

@test "release digest mismatch is a hard failure even with a matching reviewed checksum" {
    _release_checksum_fixture
    _reviewed_checksum
    local release
    release=$(_release_fixture '"sha256:'"$WRONG_HASH"'"')

    run verify_github_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_failure
    assert_output --partial "Checksum MISMATCH"
    refute_output --partial "Checksum verified"
    [[ -f "$TEST_TMPDIR/.checksum_mismatch" ]]
    [[ ! -s "$TEST_TMPDIR/curl-calls" ]]
}

@test "invalid missing and non-string release digests do not verify" {
    _release_checksum_fixture
    local digest release
    for digest in missing null 42 '"sha256:invalid"' '"md5:'"$FIXTURE_HASH"'"'; do
        release=$(_release_fixture "$digest")
        run _verify_release_metadata_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
        assert_failure
        refute_output --partial "Checksum verified"
        [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
    done
}

@test "a digest belonging to another asset does not verify the requested artifact" {
    _release_checksum_fixture
    local release
    release=$(_release_fixture '"sha256:'"$FIXTURE_HASH"'"' v1.2.3 other-asset.tar.gz)

    run _verify_release_metadata_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_failure
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
}

@test "reviewed checksum verifies an exact repository tag and asset tuple" {
    _release_checksum_fixture
    _reviewed_checksum
    local release
    release=$(_release_fixture null)

    run verify_github_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_success
    assert_output --partial "reviewed checksum"
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
    [[ ! -s "$TEST_TMPDIR/curl-calls" ]]
}

@test "reviewed checksum cannot cross repository tag or asset boundaries" {
    _release_checksum_fixture
    _reviewed_checksum
    local release
    release=$(_release_fixture null)
    run _verify_release_metadata_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "different/project"
    assert_failure

    release=$(_release_fixture null v1.2.4)
    run _verify_release_metadata_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_failure

    release=$(_release_fixture null v1.2.3 other-asset.tar.gz)
    run _verify_release_metadata_checksum "$release" "$FIXTURE_FILE" other-asset.tar.gz "synthetic/project"
    assert_failure
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
}

@test "reviewed checksum cannot verify an asset absent from release metadata" {
    _release_checksum_fixture
    _reviewed_checksum
    local release
    release=$(_release_fixture null v1.2.3 other-asset.tar.gz)

    run _verify_release_metadata_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_failure
    refute_output --partial "Checksum verified"
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
}

@test "duplicate release asset names cannot verify through a digest" {
    _release_checksum_fixture
    local release
    release=$(_release_fixture '"sha256:'"$FIXTURE_HASH"'"' v1.2.3 "$FIXTURE_ASSET" true)

    run _verify_release_metadata_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_failure
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
}

@test "duplicate release asset names cannot verify through a reviewed checksum" {
    _release_checksum_fixture
    _reviewed_checksum
    local release
    release=$(_release_fixture null v1.2.3 "$FIXTURE_ASSET" true)

    run _verify_release_metadata_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_failure
    refute_output --partial "Checksum verified"
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
}

@test "a downloaded manifest mismatch cannot fall back to a matching digest or reviewed checksum" {
    _release_checksum_fixture
    _reviewed_checksum
    MOCK_CHECKSUM_BODY="$WRONG_HASH  $FIXTURE_ASSET"
    MOCK_CURL_STATUS=0
    local release
    release=$(_release_fixture '"sha256:'"$FIXTURE_HASH"'"' v1.2.3 "$FIXTURE_ASSET" false true)

    run verify_github_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_failure
    assert_output --partial "Checksum MISMATCH"
    refute_output --partial "Checksum verified"
    [[ -f "$TEST_TMPDIR/.checksum_mismatch" ]]
    [[ $(wc -l < "$TEST_TMPDIR/curl-calls") -eq 1 ]]
}

@test "an unavailable manifest may use the exact asset digest" {
    _release_checksum_fixture
    local release
    release=$(_release_fixture '"sha256:'"$FIXTURE_HASH"'"' v1.2.3 "$FIXTURE_ASSET" false true)

    run verify_github_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_success
    assert_output --partial "release digest"
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
    [[ $(wc -l < "$TEST_TMPDIR/curl-calls") -eq 1 ]]
}

@test "an unavailable manifest and absent metadata do not claim verification" {
    _release_checksum_fixture
    local release
    release=$(_release_fixture null v1.2.3 "$FIXTURE_ASSET" false true)

    run verify_github_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_failure
    assert_output --partial "Failed to download checksums"
    refute_output --partial "Checksum verified"
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
    [[ $(wc -l < "$TEST_TMPDIR/curl-calls") -eq 1 ]]
}

@test "a matching downloaded manifest is verified without metadata fallback" {
    _release_checksum_fixture
    MOCK_CHECKSUM_BODY="$FIXTURE_HASH  $FIXTURE_ASSET"
    MOCK_CURL_STATUS=0
    local release
    release=$(_release_fixture '"sha256:'"$WRONG_HASH"'"' v1.2.3 "$FIXTURE_ASSET" false true)

    run verify_github_checksum "$release" "$FIXTURE_FILE" "$FIXTURE_ASSET" "synthetic/project"
    assert_success
    refute_output --partial "release digest or reviewed checksum"
    [[ ! -f "$TEST_TMPDIR/.checksum_mismatch" ]]
    [[ $(wc -l < "$TEST_TMPDIR/curl-calls") -eq 1 ]]
}

_source_outputs_fixture() {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/modules/reversing.sh"
    RE_BUILD_NAMES=(fixture-tool)
    RE_BUILD_URLS[fixture-tool]='https://example.invalid/fixture-tool.git'
    RE_BUILD_CMDS[fixture-tool]='cmake -S . -B build && cmake --build build --parallel'
    declare -gA RE_BUILD_BINS=(
        [fixture-tool]=$'build/fixture-tool|fixture-tool\nbuild/fixture-companion|fixture-companion'
    )
    make_test_tmpdir
    export GITHUB_TOOL_DIR="$TEST_TMPDIR/tools with spaces"
    export PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    export VERSION_FILE="$TEST_TMPDIR/.versions"
    export SKIP_SOURCE=false
    export TOTAL_TOOL_FAILURES=0
    mkdir -p "$GITHUB_TOOL_DIR" "$PIPX_BIN_DIR"
    _SESSION_FILE=""
}

_source_artifacts() {
    mkdir -p "$GITHUB_TOOL_DIR/fixture-tool/build"
    local binary
    for binary in fixture-tool fixture-companion; do
        printf '#!/bin/sh\nprintf "synthetic %s\\n"\n' "$binary" \
            > "$GITHUB_TOOL_DIR/fixture-tool/build/$binary"
        chmod +x "$GITHUB_TOOL_DIR/fixture-tool/build/$binary"
    done
}

_source_build_fixture() {
    git_clone_or_pull() { mkdir -p "$2"; }
    _as_builder() { bash -c "$1"; }
    mkdir -p "$TEST_TMPDIR/stubs"
    cat > "$TEST_TMPDIR/stubs/cmake" <<'EOF'
#!/bin/bash
case "$1" in
    -S)
        [[ "${SOURCE_FIXTURE_FAIL_STAGE:-}" != configure ]] || exit 1
        mkdir -p build
        ;;
    --build)
        [[ "${SOURCE_FIXTURE_FAIL_STAGE:-}" != build ]] || exit 1
        for binary in fixture-tool fixture-companion; do
            [[ "$binary" != "${SOURCE_FIXTURE_OMIT_BINARY:-}" ]] || continue
            printf '#!/bin/sh\nprintf "synthetic %s\\n"\n' "$binary" > "build/$binary"
            chmod +x "build/$binary"
        done
        ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$TEST_TMPDIR/stubs/cmake"
    export PATH="$TEST_TMPDIR/stubs:$PATH"
}

@test "source install exposes both executables and records one package" {
    _source_outputs_fixture
    _source_build_fixture

    build_from_source fixture-tool "${RE_BUILD_URLS[fixture-tool]}" "${RE_BUILD_CMDS[fixture-tool]}"

    [[ "$(readlink "$PIPX_BIN_DIR/fixture-tool")" == "$GITHUB_TOOL_DIR/fixture-tool/build/fixture-tool" ]]
    [[ "$(readlink "$PIPX_BIN_DIR/fixture-companion")" == "$GITHUB_TOOL_DIR/fixture-tool/build/fixture-companion" ]]
    run "$PIPX_BIN_DIR/fixture-companion"
    assert_success
    assert_output 'synthetic fixture-companion'
    [[ "$(awk -F'|' '$1=="fixture-tool" && $2=="source" {n++} END {print n+0}' "$VERSION_FILE")" -eq 1 ]]
    ! grep -q '^fixture-companion|' "$VERSION_FILE"
}

@test "source missing secondary executable fails before recording an install" {
    _source_outputs_fixture
    _source_build_fixture
    export SOURCE_FIXTURE_OMIT_BINARY=fixture-companion

    if build_from_source fixture-tool "${RE_BUILD_URLS[fixture-tool]}" "${RE_BUILD_CMDS[fixture-tool]}"; then
        return 1
    fi

    [[ "$TOTAL_TOOL_FAILURES" -eq 1 ]]
    [[ ! -f "$VERSION_FILE" ]]
}

@test "source configure or compile failure never records success" {
    _source_outputs_fixture
    _source_build_fixture
    local stage
    for stage in configure build; do
        export SOURCE_FIXTURE_FAIL_STAGE="$stage"
        if build_from_source fixture-tool "${RE_BUILD_URLS[fixture-tool]}" "${RE_BUILD_CMDS[fixture-tool]}"; then
            return 1
        fi
    done

    [[ "$TOTAL_TOOL_FAILURES" -eq 2 ]]
    [[ ! -f "$VERSION_FILE" ]]
    [[ ! -e "$PIPX_BIN_DIR/fixture-tool" && ! -e "$PIPX_BIN_DIR/fixture-companion" ]]
}

@test "source successful retry remains owned after a failed first configure" {
    _source_outputs_fixture
    _source_build_fixture
    export SOURCE_FIXTURE_FAIL_STAGE=configure
    if build_from_source fixture-tool "${RE_BUILD_URLS[fixture-tool]}" "${RE_BUILD_CMDS[fixture-tool]}"; then
        return 1
    fi
    [[ ! -d "$GITHUB_TOOL_DIR/fixture-tool" ]]
    unset SOURCE_FIXTURE_FAIL_STAGE

    build_from_source fixture-tool "${RE_BUILD_URLS[fixture-tool]}" "${RE_BUILD_CMDS[fixture-tool]}"

    [[ "$TOTAL_TOOL_FAILURES" -eq 1 ]]
    grep -q '^fixture-tool|source|HEAD|' "$VERSION_FILE"
    ! grep -q '^fixture-tool|source|existing|' "$VERSION_FILE"
}

@test "source failed rebuild preserves a pre-existing source tree" {
    _source_outputs_fixture
    _source_build_fixture
    mkdir -p "$GITHUB_TOOL_DIR/fixture-tool"
    printf 'synthetic user changes\n' > "$GITHUB_TOOL_DIR/fixture-tool/user.txt"
    export SOURCE_FIXTURE_FAIL_STAGE=configure

    if build_from_source fixture-tool "${RE_BUILD_URLS[fixture-tool]}" "${RE_BUILD_CMDS[fixture-tool]}"; then
        return 1
    fi

    [[ "$(cat "$GITHUB_TOOL_DIR/fixture-tool/user.txt")" == 'synthetic user changes' ]]
    [[ ! -f "$VERSION_FILE" ]]
}

@test "source setup preserves a foreign executable and foreign symlink" {
    _source_outputs_fixture
    _source_artifacts
    printf '#!/bin/sh\n' > "$PIPX_BIN_DIR/fixture-tool"
    chmod +x "$PIPX_BIN_DIR/fixture-tool"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/foreign-fixture-companion"
    chmod +x "$TEST_TMPDIR/foreign-fixture-companion"
    ln -s "$TEST_TMPDIR/foreign-fixture-companion" "$PIPX_BIN_DIR/fixture-companion"

    run setup_source_build_bins fixture-tool

    assert_failure
    [[ ! -L "$PIPX_BIN_DIR/fixture-tool" && -x "$PIPX_BIN_DIR/fixture-tool" ]]
    [[ "$(readlink "$PIPX_BIN_DIR/fixture-companion")" == "$TEST_TMPDIR/foreign-fixture-companion" ]]
}

@test "source removal drops both owned links and preserves a replaced executable" {
    _source_outputs_fixture
    _source_artifacts
    setup_source_build_bins fixture-tool

    run remove_source_build fixture-tool

    assert_success
    [[ ! -e "$GITHUB_TOOL_DIR/fixture-tool" ]]
    [[ ! -L "$PIPX_BIN_DIR/fixture-tool" && ! -L "$PIPX_BIN_DIR/fixture-companion" ]]

    _source_artifacts
    setup_source_build_bins fixture-tool
    rm "$PIPX_BIN_DIR/fixture-companion"
    printf '#!/bin/sh\nprintf "foreign fixture\\n"\n' > "$PIPX_BIN_DIR/fixture-companion"
    chmod +x "$PIPX_BIN_DIR/fixture-companion"

    run remove_source_build fixture-tool

    assert_success
    [[ ! -L "$PIPX_BIN_DIR/fixture-tool" ]]
    run "$PIPX_BIN_DIR/fixture-companion"
    assert_success
    assert_output 'foreign fixture'
}

@test "requested source dependencies use module metadata and distro overrides" {
    _source_outputs_fixture
    declare -gA RE_BUILD_PACKAGES=([fixture-tool]='git cmake build-essential')
    declare -gA RE_BUILD_PACKAGES_ZYPPER=([fixture-tool]='git cmake gcc-c++ make')
    install_apt_batch() {
        shift
        printf '%s\n' "$@" > "$TEST_TMPDIR/dependencies"
    }

    _ensure_requested_source_deps fixture-tool
    [[ "$(tr '\n' ' ' < "$TEST_TMPDIR/dependencies")" == 'git cmake build-essential ' ]]
    PKG_MANAGER=zypper
    _ensure_requested_source_deps fixture-tool
    [[ "$(tr '\n' ' ' < "$TEST_TMPDIR/dependencies")" == 'git cmake gcc-c++ make ' ]]
    rm "$TEST_TMPDIR/dependencies"
    PKG_MANAGER=pkg
    _ensure_requested_source_deps fixture-tool
    [[ ! -e "$TEST_TMPDIR/dependencies" ]]
    PKG_MANAGER=apt
    install_apt_batch() { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1)); }
    run _ensure_requested_source_deps fixture-tool
    assert_failure
}

@test "package exclusions and explicit inclusions apply across package managers" {
    _distro_package_fixture
    declare -gA MISC_PACKAGE_EXCLUSIONS=([fixture-package]='fixture-blocked')
    declare -gA MISC_PACKAGE_INCLUSIONS=([fixture-package]='fixture-approved')
    local manager
    for manager in apt dnf pacman zypper pkg; do
        PKG_MANAGER="$manager"
        DISTRO_ID=fixture-blocked
        DISTRO_ID_LIKE=''
        local -a packages=(fixture-package curl)
        fixup_package_names packages
        [[ "${packages[*]}" == curl ]]
        DISTRO_ID=fixture-approved
        DISTRO_ID_LIKE=fixture-blocked
        packages=(fixture-package curl)
        fixup_package_names packages
        [[ "${packages[*]}" == 'fixture-package curl' ]]
    done
}

@test "source install preserves occupied files and symlinks before cloning" {
    _source_outputs_fixture
    git_clone_or_pull() { touch "$TEST_TMPDIR/cloned"; return 1; }
    _start_spinner() { :; }
    _stop_spinner() { :; }
    local destination="$GITHUB_TOOL_DIR/fixture-tool" kind status previous_failures
    mkdir -p "$TEST_TMPDIR/user-directory"
    printf 'synthetic user research\n' > "$TEST_TMPDIR/user-directory/notes.txt"
    for kind in file broken-symlink directory-symlink; do
        case "$kind" in
            file) printf 'synthetic user file\n' > "$destination" ;;
            broken-symlink) ln -s "$TEST_TMPDIR/missing-target" "$destination" ;;
            directory-symlink) ln -s "$TEST_TMPDIR/user-directory" "$destination" ;;
        esac
        status=0
        previous_failures="$TOTAL_TOOL_FAILURES"

        build_from_source fixture-tool "${RE_BUILD_URLS[fixture-tool]}" "${RE_BUILD_CMDS[fixture-tool]}" || status=$?

        [[ "$status" -eq 1 && "$TOTAL_TOOL_FAILURES" -eq $((previous_failures + 1)) ]]
        [[ ! -e "$TEST_TMPDIR/cloned" && ! -e "$VERSION_FILE" ]]
        case "$kind" in
            file) [[ -f "$destination" && "$(cat "$destination")" == 'synthetic user file' ]] ;;
            broken-symlink) [[ -L "$destination" && "$(readlink "$destination")" == "$TEST_TMPDIR/missing-target" ]] ;;
            directory-symlink)
                [[ -L "$destination" && "$(readlink "$destination")" == "$TEST_TMPDIR/user-directory" ]]
                [[ "$(cat "$TEST_TMPDIR/user-directory/notes.txt")" == 'synthetic user research' ]]
                ;;
        esac
        rm "$destination"
    done
}
