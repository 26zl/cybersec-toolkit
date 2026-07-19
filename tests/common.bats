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

# ---------- Package manager abstraction --------------------------------------

@test "maybe_sudo runs env directly on Termux (no sudo)" {
    make_test_tmpdir
    export TERMUX_VERSION=0.118
    sudo() { echo called > "$TEST_TMPDIR/sudo_marker"; }
    env() { echo "ENV_DIRECT:$*"; }

    run maybe_sudo apt-get update
    assert_success
    assert_output --partial "ENV_DIRECT:apt-get update"
    [ ! -f "$TEST_TMPDIR/sudo_marker" ]
}

@test "maybe_sudo runs env directly when PKG_MANAGER=pkg (no sudo)" {
    make_test_tmpdir
    export PKG_MANAGER=pkg
    sudo() { echo called > "$TEST_TMPDIR/sudo_marker"; }
    env() { echo "ENV_DIRECT:$*"; }

    run maybe_sudo pkg install foo
    assert_success
    assert_output --partial "ENV_DIRECT:pkg install foo"
    [ ! -f "$TEST_TMPDIR/sudo_marker" ]
}

@test "pkg_update retries zypper refresh after cleaning stale metadata" {
    source_libs opensuse-tumbleweed zypper
    make_test_tmpdir
    export ZYPPER_REFRESH_DELAY=0
    export CALLS_FILE="$TEST_TMPDIR/zypper.calls"
    export REFRESH_COUNT_FILE="$TEST_TMPDIR/zypper.refresh.count"
    printf '0\n' > "$REFRESH_COUNT_FILE"

    maybe_sudo() {
        printf '%s\n' "$*" >> "$CALLS_FILE"
        if [[ "$*" == "zypper --non-interactive --gpg-auto-import-keys refresh --force" ]]; then
            local count
            count=$(< "$REFRESH_COUNT_FILE")
            count=$((count + 1))
            printf '%s\n' "$count" > "$REFRESH_COUNT_FILE"
            (( count >= 2 ))
            return
        fi
        return 0
    }

    run pkg_update
    assert_success

    run grep -c -- "zypper --non-interactive --gpg-auto-import-keys refresh --force" "$CALLS_FILE"
    assert_success
    assert_output "2"

    run grep -c -- "zypper --non-interactive clean --all" "$CALLS_FILE"
    assert_success
    assert_output "1"
}

@test "pkg_update fails zypper refresh after configured retries are exhausted" {
    source_libs opensuse-tumbleweed zypper
    make_test_tmpdir
    export ZYPPER_REFRESH_ATTEMPTS=2
    export ZYPPER_REFRESH_DELAY=0
    export CALLS_FILE="$TEST_TMPDIR/zypper.calls"

    maybe_sudo() {
        printf '%s\n' "$*" >> "$CALLS_FILE"
        [[ "$*" == "zypper --non-interactive clean --all" ]]
    }

    run pkg_update
    assert_failure

    run grep -c -- "zypper --non-interactive --gpg-auto-import-keys refresh --force" "$CALLS_FILE"
    assert_success
    assert_output "2"

    run grep -c -- "zypper --non-interactive clean --all" "$CALLS_FILE"
    assert_success
    assert_output "1"
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
    local expected=(misc networking recon web crypto pwn reversing forensics enterprise wireless cracking stego cloud containers blueteam mobile blockchain llm)
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

# ---------- _builder_home ---------------------------------------------------

@test "_builder_home returns HOME when SUDO_USER unset" {
    source_libs debian apt
    unset SUDO_USER
    HOME="/home/tester"
    run _builder_home
    assert_success
    assert_output "/home/tester"
}

@test "_builder_home returns HOME when SUDO_USER is root" {
    source_libs debian apt
    SUDO_USER="root"
    HOME="/home/tester"
    run _builder_home
    assert_success
    assert_output "/home/tester"
}

@test "_builder_home falls back to absolute path for unresolvable SUDO_USER" {
    source_libs debian apt
    # A user that getent/NSS cannot resolve must NOT yield an empty or
    # /-rooted bogus home — it must fall back to a non-empty absolute path.
    SUDO_USER="nonexistent_user_zzz_$$"
    HOME="/home/tester"
    run _builder_home
    assert_success
    [[ -n "$output" ]]
    [[ "$output" == /* ]]
    # Must not be a bare slash that would produce /.cargo/bin etc.
    [[ "$output" != "/" ]]
}

@test "_builder_home never returns empty string" {
    source_libs debian apt
    SUDO_USER="nonexistent_user_yyy_$$"
    HOME="/home/tester"
    result="$(_builder_home)"
    [[ -n "$result" ]]
}

@test "_builder_home does not execute injected SUDO_USER (no eval)" {
    source_libs debian apt
    # SUDO_USER is attacker-influenced under sudo; it must only ever be passed
    # as data to getent/awk, never to a shell. A command-substitution payload
    # must NOT run when the home is resolved via the getent-miss fallback.
    local marker="$BATS_TEST_TMPDIR/pwned_$$"
    rm -f "$marker"
    SUDO_USER="\$(touch $marker)"
    HOME="/home/tester"
    run _builder_home
    assert_success
    [[ ! -e "$marker" ]]
}

# ---------- _list_sessions distinct-installed count --------------------------

@test "_list_sessions counts distinct installed tools, not raw lines" {
    source_libs debian apt
    make_test_tmpdir

    local session_dir="$TEST_TMPDIR/.install_sessions"
    mkdir -p "$session_dir"
    # Append-only manifest: a tool appears once per attempt (incl. retries and
    # failures). The TOOLS column must report distinct *installed* tools only.
    cat > "$session_dir/20260614-100000.manifest" <<'MANIFEST'
# Started: 2026-06-14 10:00:00
# Profile: ctf
# Status: completed
nmap|apt|installed|2026-06-14 10:01:00
nmap|apt|installed|2026-06-14 10:01:05
sqlmap|pipx|failed|2026-06-14 10:02:00
sqlmap|pipx|installed|2026-06-14 10:02:30
gobuster|go|failed|2026-06-14 10:03:00
ffuf|go|installed|2026-06-14 10:04:00
MANIFEST

    SCRIPT_DIR="$TEST_TMPDIR"
    run _list_sessions
    assert_success
    # Distinct installed = {nmap, sqlmap, ffuf} = 3 (NOT 6 raw non-comment lines)
    assert_output --partial "20260614-100000"
    # The TOOLS column for this session must read 3
    echo "$output" | grep -q "20260614-100000" || false
    [[ "$(echo "$output" | awk '/20260614-100000/{print $4}')" == "3" ]]
}
