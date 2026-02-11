#!/usr/bin/env bats
# =============================================================================
# Tests for lib/installers.sh
# fixup_package_names, track_version, Go binary name extraction
# =============================================================================

setup() {
    load 'test_helper'
}

# ---------- fixup_package_names — apt (no-op) --------------------------------

@test "fixup_package_names is a no-op for apt" {
    source_libs --installers debian apt
    local -a pkgs=(curl git nmap netcat-openbsd build-essential)
    local -a original=("${pkgs[@]}")
    fixup_package_names pkgs
    [[ "${pkgs[*]}" == "${original[*]}" ]]
}

# ---------- fixup_package_names — dnf translations ---------------------------

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

# ---------- fixup_package_names — pacman translations ------------------------

@test "fixup: pacman translates build-essential to base-devel" {
    source_libs --installers arch pacman
    local -a pkgs=(build-essential)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "base-devel" ]]
}

@test "fixup: pacman translates netcat-openbsd to gnu-netcat" {
    source_libs --installers arch pacman
    local -a pkgs=(netcat-openbsd)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "gnu-netcat" ]]
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

# ---------- fixup_package_names — skipped packages ---------------------------

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

# ---------- fixup_package_names — zypper translations ------------------------

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

@test "fixup: zypper removes skipped packages" {
    source_libs --installers opensuse-tumbleweed zypper
    local -a pkgs=(spooftooph cewl hashid checksec rizin)
    fixup_package_names pkgs
    [[ ${#pkgs[@]} -eq 0 ]]
}

# ---------- fixup preserves non-translated packages --------------------------

@test "fixup: unknown packages pass through unchanged on dnf" {
    source_libs --installers fedora dnf
    local -a pkgs=(curl git nmap)
    fixup_package_names pkgs
    [[ "${pkgs[0]}" == "curl" ]]
    [[ "${pkgs[1]}" == "git" ]]
    [[ "${pkgs[2]}" == "nmap" ]]
}

# ---------- track_version ----------------------------------------------------

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

# ---------- Go binary name extraction ----------------------------------------

@test "Go binary name extracted from full import path" {
    # This tests the pattern used in install.sh for single-tool matching
    # Uses bash string manipulation (portable) instead of rev+cut
    local gopkg="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    local last_segment="${gopkg##*/}"   # subfinder@latest
    local goname="${last_segment%%@*}"  # subfinder
    [[ "$goname" == "subfinder" ]]
}

@test "Go binary name extraction for simple path" {
    local gopkg="github.com/tomnomnom/assetfinder@latest"
    local last_segment="${gopkg##*/}"
    local goname="${last_segment%%@*}"
    [[ "$goname" == "assetfinder" ]]
}

@test "Go binary name extraction for versioned path" {
    local gopkg="github.com/ffuf/ffuf/v2@latest"
    local last_segment="${gopkg##*/}"
    local goname="${last_segment%%@*}"
    # The last path component is v2 for versioned modules — this is expected.
    # install.sh matches on the last segment, so tools ending in
    # cmd/<toolname>@latest (like subfinder) work correctly.
    [[ "$goname" == "v2" ]]
}
