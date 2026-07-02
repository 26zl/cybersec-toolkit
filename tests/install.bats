#!/usr/bin/env bats
# =============================================================================
# Tests for install.sh CLI argument parsing
# These tests run install.sh in a subprocess and check exit codes / output.
# No root required — we test --help, --list-*, --dry-run, and error cases.
# =============================================================================

setup() {
    load 'test_helper'
    INSTALL_SH="$PROJECT_ROOT/install.sh"
}

# ---------- --help -----------------------------------------------------------

@test "install.sh --help exits 0" {
    run bash "$INSTALL_SH" --help
    assert_success
}

@test "install.sh -h exits 0" {
    run bash "$INSTALL_SH" -h
    assert_success
}

@test "install.sh --help shows usage text" {
    run bash "$INSTALL_SH" --help
    assert_success
    assert_output --partial "Usage:"
    assert_output --partial "--profile"
    assert_output --partial "--module"
    assert_output --partial "--dry-run"
}

# ---------- --list-profiles --------------------------------------------------

@test "install.sh --list-profiles exits 0" {
    run bash "$INSTALL_SH" --list-profiles
    assert_success
}

@test "install.sh --list-profiles shows all profiles" {
    run bash "$INSTALL_SH" --list-profiles
    assert_success
    assert_output --partial "full"
    assert_output --partial "ctf"
    assert_output --partial "redteam"
    assert_output --partial "web"
    assert_output --partial "osint"
    assert_output --partial "crackstation"
    assert_output --partial "lightweight"
    assert_output --partial "blueteam"
}

# ---------- --list-modules ---------------------------------------------------

@test "install.sh --list-modules exits 0" {
    run bash "$INSTALL_SH" --list-modules
    assert_success
}

@test "install.sh --list-modules shows all 18 modules" {
    run bash "$INSTALL_SH" --list-modules
    assert_success
    local modules=(misc networking recon web crypto pwn reversing forensics enterprise wireless cracking stego cloud containers blueteam mobile blockchain llm)
    for mod in "${modules[@]}"; do
        assert_output --partial "$mod"
    done
}

# ---------- --profile unknown ------------------------------------------------

@test "install.sh --profile unknown exits 1" {
    run bash "$INSTALL_SH" --profile nonexistent_profile_xyz --dry-run
    assert_failure
    assert_output --partial "Profile not found"
}

# ---------- --dry-run --------------------------------------------------------

@test "install.sh --dry-run with profile shows module list" {
    run bash "$INSTALL_SH" --profile ctf --dry-run
    assert_success
    assert_output --partial "DRY RUN"
    assert_output --partial "Modules:"
    assert_output --partial "misc"
    assert_output --partial "crypto"
}

@test "install.sh --dry-run shows install functions" {
    run bash "$INSTALL_SH" --profile web --dry-run
    assert_success
    assert_output --partial "install_module_"
}

@test "install.sh --dry-run shows flags" {
    run bash "$INSTALL_SH" --profile ctf --skip-heavy --dry-run
    assert_success
    assert_output --partial "Skip heavy:"
    assert_output --partial "true"
}

@test "install.sh --production enables strict checksum mode" {
    run bash "$INSTALL_SH" --profile ctf --production --dry-run
    assert_success
    assert_output --partial "Production:     true"
    assert_output --partial "Checksums req.: true"
}

@test "install.sh rejects --production with --fast" {
    run bash "$INSTALL_SH" --production --fast --dry-run
    assert_failure
    assert_output --partial "mutually exclusive"
}

@test "install.sh --dry-run with --module shows selected modules" {
    run bash "$INSTALL_SH" --module web --module recon --dry-run
    assert_success
    assert_output --partial "DRY RUN"
    assert_output --partial "web"
    assert_output --partial "recon"
}

# ---------- --verbose / -v ---------------------------------------------------

@test "install.sh --dry-run --verbose shows Verbose: true" {
    run bash "$INSTALL_SH" --dry-run --verbose
    assert_success
    assert_output --partial "Verbose:"
    assert_output --partial "true"
}

@test "install.sh --dry-run -v shows Verbose: true" {
    run bash "$INSTALL_SH" --dry-run -v
    assert_success
    assert_output --partial "Verbose:"
    assert_output --partial "true"
}

@test "install.sh --dry-run without verbose shows Verbose: false" {
    run bash "$INSTALL_SH" --dry-run
    assert_success
    assert_output --partial "Verbose:"
    assert_output --partial "false"
}

# ---------- CLI flags override profile values --------------------------------

@test "install.sh --enable-docker overrides profile default" {
    run bash "$INSTALL_SH" --profile osint --enable-docker --dry-run
    assert_success
    assert_output --partial "Docker:"
    assert_output --partial "true"
}

@test "install.sh --skip-heavy overrides profile default" {
    run bash "$INSTALL_SH" --profile full --skip-heavy --dry-run
    assert_success
    assert_output --partial "Skip heavy:"
    assert_output --partial "true"
}

# ---------- -j / --parallel --------------------------------------------------

@test "install.sh --dry-run shows default Parallel jobs: 4" {
    run bash "$INSTALL_SH" --dry-run
    assert_success
    assert_output --partial "Parallel jobs:  4"
}

@test "install.sh --dry-run -j 8 shows Parallel jobs: 8" {
    run bash "$INSTALL_SH" --dry-run -j 8
    assert_success
    assert_output --partial "Parallel jobs:  8"
}

@test "install.sh --dry-run --parallel 1 shows Parallel jobs: 1" {
    run bash "$INSTALL_SH" --dry-run --parallel 1
    assert_success
    assert_output --partial "Parallel jobs:  1"
}

@test "install.sh --help shows -j/--parallel flag" {
    run bash "$INSTALL_SH" --help
    assert_success
    assert_output --partial "--parallel"
    assert_output --partial "PARALLEL_JOBS"
}

@test "_installation_failed returns true when tool failures exist" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        tmpdir=$(mktemp -d)
        trap "rm -rf \"$tmpdir\"" EXIT
        export LOG_FILE=/dev/null VERSION_FILE="$tmpdir/.versions"
        TOTAL_TOOL_FAILURES=1
        TOTAL_MODULE_FAILURES=0
        _installation_failed
    '
    assert_success
}

@test "install_single_tool returns failure when package install fails" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        tmpdir=$(mktemp -d)
        trap "rm -rf \"$tmpdir\"" EXIT
        export LOG_FILE=/dev/null VERSION_FILE="$tmpdir/.versions"
        pkg_install() { return 1; }
        install_single_tool nmap
    '
    assert_failure
    assert_output --partial "Failed:"
}

@test "install_single_tool finds blockchain cargo tools" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        tmpdir=$(mktemp -d)
        trap "rm -rf \"$tmpdir\"" EXIT
        export LOG_FILE=/dev/null VERSION_FILE="$tmpdir/.versions"
        cargo() { :; }
        ensure_cargo() { return 0; }
        _as_builder() { return 0; }
        _builder_home() { echo /tmp; }
        install_single_tool aderyn
    '
    assert_success
    assert_output --partial "Installing aderyn via cargo"
}

@test "install_single_tool finds binary release tools" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        export LOG_FILE=/dev/null
        download_github_release() {
            echo "BINARY=$1|$2|$3"
            return 0
        }
        install_single_tool gitleaks
    '
    assert_success
    assert_output --partial "BINARY=gitleaks/gitleaks|gitleaks"
}

@test "install_single_tool preserves explicit archive binary aliases" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        export LOG_FILE=/dev/null
        download_github_release() {
            echo "ARCHIVE_BINARY=$5"
            return 0
        }
        install_single_tool crytic-medusa
    '
    assert_success
    assert_output --partial "ARCHIVE_BINARY=medusa"
}

@test "install_single_tool finds build-from-source tools" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        export LOG_FILE=/dev/null
        build_from_source() {
            echo "SOURCE=$1|$2|$3"
            return 0
        }
        install_single_tool massdns
    '
    assert_success
    assert_output --partial "SOURCE=massdns|https://github.com/blechschmidt/massdns.git|make"
}

# ---------- platform module filtering shared with dry-run --------------------

@test "_apply_platform_module_filters drops wireless module under WSL" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        export LOG_FILE=/dev/null
        IS_WSL=true
        MODULES_TO_INSTALL=(web wireless recon)
        _apply_platform_module_filters
        echo "RESULT=${MODULES_TO_INSTALL[*]}"
    '
    assert_success
    assert_line "RESULT=web recon"
}

@test "_apply_platform_module_filters keeps wireless module when not WSL" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        export LOG_FILE=/dev/null
        IS_WSL=false
        MODULES_TO_INSTALL=(web wireless recon)
        _apply_platform_module_filters
        echo "RESULT=${MODULES_TO_INSTALL[*]}"
    '
    assert_success
    assert_line "RESULT=web wireless recon"
}

@test "_apply_platform_module_filters disables Docker on Termux" {
    run bash -lc '
        set --
        export PKG_MANAGER=pkg DISTRO_ID=android DISTRO_NAME=android
        export PREFIX="/data/data/com.termux/files/usr"
        source "'"$INSTALL_SH"'"
        export LOG_FILE=/dev/null
        IS_WSL=false
        ENABLE_DOCKER=true
        MODULES_TO_INSTALL=(misc)
        _apply_platform_module_filters
        echo "DOCKER=${ENABLE_DOCKER}"
    '
    assert_success
    assert_line "DOCKER=false"
}
