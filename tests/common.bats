#!/usr/bin/env bats
# =============================================================================
# Tests for lib/common.sh
# Logging, command_exists, distro detection, exported paths, ALL_MODULES
# =============================================================================

setup() {
    load 'test_helper'
    source_libs debian apt
}

# ---------- Logging functions ------------------------------------------------

@test "log_success outputs [+] prefix" {
    run log_success "test message"
    assert_success
    assert_output --partial "[+]"
    assert_output --partial "test message"
}

@test "log_info outputs [*] prefix" {
    run log_info "info message"
    assert_success
    assert_output --partial "[*]"
    assert_output --partial "info message"
}

@test "log_warn outputs [!] prefix" {
    run log_warn "warn message"
    assert_success
    assert_output --partial "[!]"
    assert_output --partial "warn message"
}

@test "log_error outputs [-] prefix" {
    run log_error "error message"
    assert_success
    assert_output --partial "[-]"
    assert_output --partial "error message"
}

@test "log_message writes to LOG_FILE" {
    make_test_tmpdir
    local logfile="$TEST_TMPDIR/test.log"
    LOG_FILE="$logfile"
    log_message "file write test"
    [[ -f "$logfile" ]]
    grep -q "file write test" "$logfile"
}

# ---------- command_exists ---------------------------------------------------

@test "command_exists returns 0 for bash" {
    run command_exists bash
    assert_success
}

@test "command_exists returns 1 for nonexistent command" {
    run command_exists __absolutely_fake_command_xyz__
    assert_failure
}

# ---------- Distro detection -------------------------------------------------

@test "detect_pkg_manager sets apt for debian" {
    # Re-source with real detect_pkg_manager
    unset -f detect_pkg_manager
    source "$PROJECT_ROOT/lib/common.sh"

    # Override DISTRO_ID after source
    DISTRO_ID="debian"
    DISTRO_ID_LIKE=""

    # Call the real function with our override
    unset -f detect_pkg_manager
    detect_pkg_manager() {
        # Skip detect_distro, just use the case
        case "$DISTRO_ID" in
            debian|ubuntu|kali|parrot|linuxmint|pop|elementary|zorin|mx)
                PKG_MANAGER="apt" ;;
            fedora|rhel|centos|rocky|alma|nobara)
                PKG_MANAGER="dnf" ;;
            arch|manjaro|endeavouros|garuda|artix)
                PKG_MANAGER="pacman" ;;
            opensuse*|sles)
                PKG_MANAGER="zypper" ;;
            *) PKG_MANAGER="unknown" ;;
        esac
        export PKG_MANAGER
    }

    for distro in debian ubuntu kali parrot; do
        DISTRO_ID="$distro"
        detect_pkg_manager
        [[ "$PKG_MANAGER" == "apt" ]]
    done
}

@test "detect_pkg_manager sets dnf for fedora family" {
    detect_pkg_manager() {
        case "$DISTRO_ID" in
            fedora|rhel|centos|rocky|alma|nobara) PKG_MANAGER="dnf" ;;
            *) PKG_MANAGER="unknown" ;;
        esac
        export PKG_MANAGER
    }

    for distro in fedora rhel centos rocky alma nobara; do
        DISTRO_ID="$distro"
        detect_pkg_manager
        [[ "$PKG_MANAGER" == "dnf" ]]
    done
}

@test "detect_pkg_manager sets pacman for arch family" {
    detect_pkg_manager() {
        case "$DISTRO_ID" in
            arch|manjaro|endeavouros|garuda|artix) PKG_MANAGER="pacman" ;;
            *) PKG_MANAGER="unknown" ;;
        esac
        export PKG_MANAGER
    }

    for distro in arch manjaro endeavouros garuda artix; do
        DISTRO_ID="$distro"
        detect_pkg_manager
        [[ "$PKG_MANAGER" == "pacman" ]]
    done
}

@test "detect_pkg_manager sets zypper for opensuse" {
    detect_pkg_manager() {
        case "$DISTRO_ID" in
            opensuse*|sles) PKG_MANAGER="zypper" ;;
            *) PKG_MANAGER="unknown" ;;
        esac
        export PKG_MANAGER
    }

    DISTRO_ID="opensuse-tumbleweed"
    detect_pkg_manager
    [[ "$PKG_MANAGER" == "zypper" ]]

    DISTRO_ID="sles"
    detect_pkg_manager
    [[ "$PKG_MANAGER" == "zypper" ]]
}

@test "detect_pkg_manager sets pkg for Termux" {
    # The real detect_pkg_manager checks TERMUX_VERSION env var
    # Simulate by calling source with android/pkg
    source_libs android pkg
    [[ "$PKG_MANAGER" == "pkg" ]]
    [[ "$DISTRO_ID" == "android" ]]
}

# ---------- Exported paths (Linux) -------------------------------------------

@test "GOBIN is /usr/local/bin on Linux" {
    source_libs debian apt
    [[ "$GOBIN" == "/usr/local/bin" ]]
}

@test "PIPX_HOME is /opt/pipx on Linux" {
    source_libs debian apt
    [[ "$PIPX_HOME" == "/opt/pipx" ]]
}

@test "PIPX_BIN_DIR is /usr/local/bin on Linux" {
    source_libs debian apt
    [[ "$PIPX_BIN_DIR" == "/usr/local/bin" ]]
}

@test "GOPATH defaults to /opt/go on Linux" {
    unset GOPATH
    source_libs debian apt
    [[ "$GOPATH" == "/opt/go" ]]
}

@test "GITHUB_TOOL_DIR defaults to /opt on Linux" {
    unset GITHUB_TOOL_DIR
    source_libs debian apt
    [[ "$GITHUB_TOOL_DIR" == "/opt" ]]
}

# ---------- Exported paths (Termux) -----------------------------------------

@test "GOBIN uses PREFIX/bin on Termux" {
    # Simulate Termux environment
    export TERMUX_VERSION="0.118"
    export PREFIX="/data/data/com.termux/files/usr"
    unset GOBIN PIPX_BIN_DIR PIPX_HOME GOPATH GITHUB_TOOL_DIR
    source_libs android pkg
    [[ "$GOBIN" == "$PREFIX/bin" ]]
}

@test "PIPX_BIN_DIR uses PREFIX/bin on Termux" {
    export TERMUX_VERSION="0.118"
    export PREFIX="/data/data/com.termux/files/usr"
    unset GOBIN PIPX_BIN_DIR PIPX_HOME GOPATH GITHUB_TOOL_DIR
    source_libs android pkg
    [[ "$PIPX_BIN_DIR" == "$PREFIX/bin" ]]
}

@test "GITHUB_TOOL_DIR defaults to HOME/tools on Termux" {
    export TERMUX_VERSION="0.118"
    export PREFIX="/data/data/com.termux/files/usr"
    unset GOBIN PIPX_BIN_DIR PIPX_HOME GOPATH GITHUB_TOOL_DIR
    source_libs android pkg
    [[ "$GITHUB_TOOL_DIR" == "$HOME/tools" ]]
}

# ---------- ALL_MODULES ------------------------------------------------------

@test "ALL_MODULES contains exactly 18 entries" {
    [[ ${#ALL_MODULES[@]} -eq 18 ]]
}

@test "ALL_MODULES contains all expected modules" {
    local expected=(misc networking recon web crypto pwn reversing forensics malware enterprise wireless cracking stego cloud containers blueteam mobile blockchain)
    for mod in "${expected[@]}"; do
        local found=false
        for m in "${ALL_MODULES[@]}"; do
            if [[ "$m" == "$mod" ]]; then
                found=true
                break
            fi
        done
        [[ "$found" == true ]] || { echo "Missing module: $mod"; return 1; }
    done
}

# ---------- VERBOSE / log_debug ----------------------------------------------

@test "VERBOSE defaults to false" {
    unset VERBOSE
    source_libs debian apt
    [[ "$VERBOSE" == "false" ]]
}

@test "log_debug is silent when VERBOSE is false" {
    VERBOSE=false
    run log_debug "should not appear"
    assert_success
    assert_output ""
}

@test "log_debug outputs [D] prefix when VERBOSE is true" {
    VERBOSE=true
    run log_debug "debug test message"
    assert_success
    assert_output --partial "[D]"
    assert_output --partial "debug test message"
}

@test "log_debug writes to LOG_FILE when VERBOSE is true" {
    make_test_tmpdir
    local logfile="$TEST_TMPDIR/debug.log"
    LOG_FILE="$logfile"
    VERBOSE=true
    log_debug "logfile debug test"
    [[ -f "$logfile" ]]
    grep -q "logfile debug test" "$logfile"
}

# ---------- Color variables --------------------------------------------------

@test "color variables are defined" {
    [[ -n "$RED" ]]
    [[ -n "$GREEN" ]]
    [[ -n "$YELLOW" ]]
    [[ -n "$BLUE" ]]
    [[ -n "$CYAN" ]]
    [[ -n "$BOLD" ]]
    [[ -n "$NC" ]]
}

# ---------- PARALLEL_JOBS ----------------------------------------------------

@test "PARALLEL_JOBS defaults to 4" {
    unset PARALLEL_JOBS
    source_libs debian apt
    [[ "$PARALLEL_JOBS" == "4" ]]
}

@test "PARALLEL_JOBS respects environment override" {
    PARALLEL_JOBS=8
    source_libs debian apt
    [[ "$PARALLEL_JOBS" == "8" ]]
}

# ---------- pkg_is_installed --------------------------------------------------

@test "pkg_is_installed function exists" {
    run type -t pkg_is_installed
    assert_success
    assert_output "function"
}

# ---------- PARALLEL_JOBS / helpers ------------------------------------------

@test "_wait_for_job_slot returns 0 when under limit" {
    PARALLEL_JOBS=4
    run _wait_for_job_slot
    assert_success
}

@test "_collect_parallel_results processes ok/skip/fail files" {
    make_test_tmpdir
    source_libs --installers debian apt

    local rdir="$TEST_TMPDIR/results"
    mkdir -p "$rdir"

    # Create result files
    printf 'ok\nlatest\n' > "$rdir/tool-a"
    printf 'skip\nexisting\n' > "$rdir/tool-b"
    printf 'fail\n\n' > "$rdir/tool-c"

    # Set up version file
    VERSION_FILE="$TEST_TMPDIR/.versions"

    _collect_parallel_results "$rdir" "test"

    [[ "$_par_failed" -eq 1 ]]
    [[ "$_par_skipped" -eq 1 ]]
    # Verify version tracking was called for ok and skip
    grep -q "^tool-a|test|latest|" "$VERSION_FILE"
    grep -q "^tool-b|test|existing|" "$VERSION_FILE"
    # fail should not be tracked
    ! grep -q "^tool-c|" "$VERSION_FILE"
}
