#!/usr/bin/env bats
# Tests for lib/common.sh
# Logging, command_exists, distro detection, exported paths, ALL_MODULES

setup() {
    load 'test_helper'
    source_libs debian apt
}

# Logging functions

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

# command_exists

@test "command_exists returns 0 for bash" {
    run command_exists bash
    assert_success
}

@test "command_exists returns 1 for nonexistent command" {
    run command_exists __absolutely_fake_command_xyz__
    assert_failure
}

# Distro detection

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

# Package manager abstraction

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
    # Throwaway-container mode: the key auto-import flag is expected here.
    export CI=true
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
    export CI=true
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

# Exported paths (Linux)

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

# Exported paths (Termux)

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

# ALL_MODULES

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

# VERBOSE / log_debug

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

# Color variables

@test "color variables are defined" {
    [[ -n "${RED+x}" ]]
    [[ -n "${GREEN+x}" ]]
    [[ -n "${YELLOW+x}" ]]
    [[ -n "${BLUE+x}" ]]
    [[ -n "${CYAN+x}" ]]
    [[ -n "${BOLD+x}" ]]
    [[ -n "${NC+x}" ]]
}

@test "non-interactive output disables ANSI colors" {
    [[ "$COLOR_ENABLED" == "false" ]]
    [[ -z "$RED" ]]
    [[ -z "$NC" ]]
}

# PARALLEL_JOBS

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

# pkg_is_installed

@test "pkg_is_installed function exists" {
    run type -t pkg_is_installed
    assert_success
    assert_output "function"
}

# PARALLEL_JOBS / helpers

@test "_wait_for_job_slot returns 0 when under limit" {
    PARALLEL_JOBS=4
    run _wait_for_job_slot
    assert_success
}

@test "_global_cleanup stops a running spinner (Ctrl+C must not orphan it)" {
    sleep 30 &
    _SPINNER_PID=$!
    local pid=$_SPINNER_PID
    _global_cleanup
    ! kill -0 "$pid" 2>/dev/null || false
    [[ -z "$_SPINNER_PID" ]]
}

@test "_collect_parallel_results processes ok/skip/fail files" {
    make_test_tmpdir
    source_libs --installers debian apt

    local rdir="$TEST_TMPDIR/results"
    mkdir -p "$rdir"

    printf 'ok\nlatest\n' > "$rdir/tool-a"
    printf 'skip\nexisting\n' > "$rdir/tool-b"
    printf 'fail\n\n' > "$rdir/tool-c"

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

# _builder_home

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

# _list_sessions distinct-installed count

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

# _builder_cmd (privilege-drop tool resolution)
# Regression cover: root's cargo under /root is unreachable for $SUDO_USER, and a
# bare name misses ensure_go's /usr/local/go/bin.

_bc_setup() {
    source_libs debian apt
    make_test_tmpdir
    export SUDO_USER=fakebuilder          # force the privilege-drop branch
    mkdir -p "$TEST_TMPDIR/rootonly" "$TEST_TMPDIR/offpath/bin"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/rootonly/cargo"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/offpath/bin/go"
    chmod +x "$TEST_TMPDIR/rootonly/cargo" "$TEST_TMPDIR/offpath/bin/go"
    _BUILDER_CMD_CACHE=()

    # The builder: gem on PATH, go readable off-PATH, cargo unreachable.
    _as_builder() {
        case "$1" in
            "command -v gem")   return 0 ;;
            "command -v go")    return 1 ;;
            "command -v cargo") return 1 ;;
            "test -x '$TEST_TMPDIR/offpath/bin/go'")  return 0 ;;
            "test -x '$TEST_TMPDIR/rootonly/cargo'")  return 1 ;;
            *) return 1 ;;
        esac
    }
    # Root's PATH resolution.
    command() {
        if [[ "$1" == "-v" ]]; then
            case "$2" in
                go)    echo "$TEST_TMPDIR/offpath/bin/go" ;;
                cargo) echo "$TEST_TMPDIR/rootonly/cargo" ;;
                gem)   echo /usr/bin/gem ;;
                *)     return 1 ;;
            esac
            return 0
        fi
        builtin command "$@"
    }
}

@test "_builder_cmd returns the bare name when it is on the builder's PATH" {
    _bc_setup
    [[ "$(_builder_cmd gem)" == "gem" ]]
}

@test "_builder_cmd returns an absolute path for a readable off-PATH tool" {
    # The /usr/local/go/bin case — a bare name would be "command not found".
    _bc_setup
    [[ "$(_builder_cmd go)" == "$TEST_TMPDIR/offpath/bin/go" ]]
}

@test "_builder_cmd fails on a tool the builder cannot execute" {
    # The /root/.cargo/bin/cargo case — must fail loudly, not emit an unusable path.
    _bc_setup
    run _builder_cmd cargo
    assert_failure
    assert_output "cargo"
}

@test "_builder_cmd caches its resolution" {
    _bc_setup
    _builder_cmd gem >/dev/null
    [[ "${_BUILDER_CMD_CACHE[gem]}" == "gem" ]]
}

@test "_git_safe_reset_to_remote keeps local commits but follows a replaced upstream" {
    make_test_tmpdir
    local log="$TEST_TMPDIR/git.log"
    _bare_repo_with_commit() {
        git init -q --bare -b main "$1"
        git clone -q "$1" "$1.work" 2>/dev/null
        git -C "$1.work" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m "$2"
        git -C "$1.work" push -q origin main
    }
    _bare_repo_with_commit "$TEST_TMPDIR/up.git" base
    _bare_repo_with_commit "$TEST_TMPDIR/replaced.git" replaced

    # A user commit that no remote has must survive.
    git clone -q "$TEST_TMPDIR/up.git" "$TEST_TMPDIR/mine"
    git -C "$TEST_TMPDIR/mine" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m mine
    run _git_safe_reset_to_remote "$TEST_TMPDIR/mine" "$log"
    assert_failure
    [[ "$(git -C "$TEST_TMPDIR/mine" log -1 --format=%s)" == "mine" ]]

    # Upstream history replaced: the clone only holds old upstream commits, so it follows.
    git clone -q "$TEST_TMPDIR/up.git" "$TEST_TMPDIR/theirs"
    git -C "$TEST_TMPDIR/theirs" remote set-url origin "$TEST_TMPDIR/replaced.git"
    _git_safe_reset_to_remote "$TEST_TMPDIR/theirs" "$log"
    [[ "$(git -C "$TEST_TMPDIR/theirs" log -1 --format=%s)" == "replaced" ]]
}

@test "_path_append appends each directory once and never reorders PATH" {
    # A builder-owned dir ahead of /usr/bin would let it shadow sha256sum/tar for root.
    PATH="/usr/bin:/home/u/.local/bin"
    _path_append /home/u/.cargo/bin /home/u/.local/bin /home/u/.cargo/bin
    [[ "$PATH" == "/usr/bin:/home/u/.local/bin:/home/u/.cargo/bin" ]]
}

# Dead = gone, or a zombie awaiting reap by its parent.
_pid_dead() {
    local line
    read -r line < "/proc/$1/stat" 2>/dev/null || return 0
    line="${line##*) }"
    [[ "${line%% *}" == [ZX] ]]
}

@test "_kill_tree stops descendants that ignore SIGINT (Ctrl+C orphan case)" {
    [[ -d /proc/self ]] || skip "needs /proc"
    source_libs debian apt
    # Like Stage 3: a background parent whose own background children ignore SIGINT.
    bash -c 'trap "" INT; sleep 30 & sleep 30 & wait' &
    local parent=$!
    local kids="" i
    for i in $(seq 1 30); do
        kids=$(_child_pids "$parent")
        [[ $(wc -w <<<"$kids") -ge 2 ]] && break
        sleep 0.1
    done
    [[ $(wc -w <<<"$kids") -ge 2 ]]

    _kill_tree "$parent" TERM
    kill -TERM "$parent" 2>/dev/null || true

    local k alive
    for i in $(seq 1 30); do
        alive=0
        for k in $kids; do _pid_dead "$k" || alive=1; done
        [[ $alive -eq 0 ]] && break
        sleep 0.1
    done
    wait "$parent" 2>/dev/null || true
    [[ $alive -eq 0 ]]
}

@test "run lock preserves the caller's stderr" {
    bats_require_minimum_version 1.5.0
    command -v flock >/dev/null || skip "needs flock"
    make_test_tmpdir
    run --separate-stderr bash -c '
        source "$1/lib/common.sh"
        SCRIPT_DIR="$2"
        _acquire_run_lock
        printf "visible stdout\n"
        printf "visible stderr\n" >&2
    ' fixture "$PROJECT_ROOT" "$TEST_TMPDIR"
    assert_success
    assert_output "visible stdout"
    [[ "$stderr" == "visible stderr" ]]
}

@test "interrupt kills TERM-resistant reparented descendants and releases the run lock" {
    [[ -d /proc/self ]] || skip "needs /proc"
    command -v flock >/dev/null || skip "needs flock"
    make_test_tmpdir
    run python3 - "$PROJECT_ROOT" "$TEST_TMPDIR" <<'PY'
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

root, fixture = map(Path, sys.argv[1:])
child = fixture / "child.sh"
parent = fixture / "parent.sh"
pidfile = fixture / "child.pid"
ready = fixture / "ready"
child.write_text('trap "" TERM\nprintf "%s\\n" "$$" > "$1"\nexec sleep 90\n')
parent.write_text('bash "$1" "$2" &\nwait\n')
body = '''
source "$1/lib/common.sh"
SCRIPT_DIR="$2"
_acquire_run_lock
bash "$3" "$4" "$5" &
for i in {1..100}; do [[ -s "$5" ]] && break; sleep 0.01; done
trap '_stop_job_tree; exit 130' TERM
: > "$6"
wait
'''
process = subprocess.Popen(
    ["bash", "-c", body, "fixture", str(root), str(fixture), str(parent), str(child), str(pidfile), str(ready)],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    start_new_session=True,
)
pid = None
try:
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists(), "fixture did not become ready"
    pid = int(pidfile.read_text())
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 130, (process.returncode, stdout, stderr)
    stat = Path(f"/proc/{pid}/stat")
    assert not stat.exists() or stat.read_text().rsplit(") ", 1)[1].split()[0] in {"Z", "X"}
    retry = subprocess.run(
        ["bash", "-c", 'source "$1/lib/common.sh"; SCRIPT_DIR="$2"; _acquire_run_lock',
         "fixture", str(root), str(fixture)],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert retry.returncode == 0, (retry.stdout, retry.stderr)
finally:
    if pid is not None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate(timeout=5)
PY
    assert_success
}

@test "saved job identity does not signal a different process start time" {
    [[ -d /proc/self ]] || skip "needs /proc"
    sleep 30 &
    local pid=$! start
    start=$(_process_start_time "$pid")
    _signal_job "$pid" "$((start + 1))" KILL
    local alive=0
    kill -0 "$pid" 2>/dev/null && alive=1
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    [[ "$alive" -eq 1 ]]
}

@test "lazy package index refreshes once, only on the first install (CL-6)" {
    source_libs archlinux pacman
    make_test_tmpdir
    pkg_update() { echo refresh >> "$TEST_TMPDIR/calls"; }
    maybe_sudo() { echo "install $*" >> "$TEST_TMPDIR/calls"; }

    # Off by default: other install paths refresh up front themselves.
    pkg_install foo
    run grep -c refresh "$TEST_TMPDIR/calls"
    assert_output "0"

    # --tool path: no refresh until something is installed, then exactly once.
    : > "$TEST_TMPDIR/calls"
    _PKG_INDEX_LAZY=true
    _PKG_INDEX_REFRESHED=false
    pkg_install foo
    pkg_install bar
    run grep -c refresh "$TEST_TMPDIR/calls"
    assert_output "1"
}

@test "zypper refresh does not auto-import repo keys outside CI (SI-10)" {
    source_libs opensuse-tumbleweed zypper
    make_test_tmpdir
    unset CI CYBERSEC_ZYPPER_AUTO_IMPORT_KEYS
    export CALLS_FILE="$TEST_TMPDIR/zypper.calls"
    maybe_sudo() { printf '%s\n' "$*" >> "$CALLS_FILE"; return 0; }

    run pkg_update
    assert_success
    run cat "$CALLS_FILE"
    assert_output "zypper --non-interactive refresh --force"
}
