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

@test "install.sh --list-profiles shows all 9 profiles" {
    run bash "$INSTALL_SH" --list-profiles
    assert_success
    assert_output --partial "full"
    assert_output --partial "ctf"
    assert_output --partial "redteam"
    assert_output --partial "web"
    assert_output --partial "malware"
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
    local modules=(misc networking recon web crypto pwn reversing forensics malware enterprise wireless password stego cloud containers blueteam mobile blockchain)
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

@test "install.sh --dry-run with --module shows selected modules" {
    run bash "$INSTALL_SH" --module web --module recon --dry-run
    assert_success
    assert_output --partial "DRY RUN"
    assert_output --partial "web"
    assert_output --partial "recon"
    # misc is always prepended
    assert_output --partial "misc"
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
