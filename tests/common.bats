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

# Distro detection (real detect_distro / detect_pkg_manager against fixture os-release files)

# _detect <os-release file> [VAR=value ...] — prints "<DISTRO_ID> <PKG_MANAGER>" from a fresh
# shell that sees a Linux uname regardless of the host.
_detect() {
    local osr="$1"; shift
    local fakebin="$TEST_TMPDIR/fakebin"
    mkdir -p "$fakebin"
    printf '#!/bin/sh\necho Linux\n' > "$fakebin/uname"
    chmod +x "$fakebin/uname"
    run env -u PKG_MANAGER -u DISTRO_ID -u TERMUX_VERSION PATH="$fakebin:$PATH" \
        CYBERSEC_OS_RELEASE="$osr" SCRIPT_DIR="$PROJECT_ROOT" LOG_FILE=/dev/null "$@" \
        bash -c 'source "$SCRIPT_DIR/lib/common.sh"; echo "$DISTRO_ID $PKG_MANAGER"'
}

@test "detect_pkg_manager maps each distro family to its package manager" {
    make_test_tmpdir
    local row id mgr
    for row in debian:apt ubuntu:apt kali:apt parrot:apt linuxmint:apt \
               fedora:dnf rhel:dnf centos:dnf rocky:dnf almalinux:dnf nobara:dnf \
               arch:pacman manjaro:pacman endeavouros:pacman \
               opensuse-tumbleweed:zypper sles:zypper alpine:unknown; do
        id="${row%%:*}"; mgr="${row##*:}"
        mock_os_release "$id"
        _detect "$MOCK_OS_RELEASE"
        assert_success
        assert_output "$id $mgr"
    done
}

@test "detect_distro reads the os-release override as data and never executes it" {
    make_test_tmpdir
    local osr="$TEST_TMPDIR/os-release"
    {
        printf 'touch "%s/pwned"\n' "$TEST_TMPDIR"
        printf 'ID="fedora"\n'
        printf 'ID_LIKE='"'"'rhel centos'"'"'\n'
        printf 'PRETTY_NAME="Fedora $(touch %s/pwned2)"\n' "$TEST_TMPDIR"
    } > "$osr"
    _detect "$osr"
    assert_success
    assert_output "fedora dnf"
    [[ ! -e "$TEST_TMPDIR/pwned" && ! -e "$TEST_TMPDIR/pwned2" ]]
}

@test "detect_pkg_manager follows ID_LIKE for derivatives" {
    make_test_tmpdir
    mock_os_release neon "KDE neon" 24 "ubuntu debian"
    _detect "$MOCK_OS_RELEASE"
    assert_output "neon apt"
    mock_os_release amzn "Amazon Linux" 2023 "fedora"
    _detect "$MOCK_OS_RELEASE"
    assert_output "amzn dnf"
    mock_os_release cachyos "CachyOS" "" "arch"
    _detect "$MOCK_OS_RELEASE"
    assert_output "cachyos pacman"
}

@test "detect_distro survives an os-release without ID" {
    make_test_tmpdir
    printf 'NAME=Foo\nVERSION=1\n' > "$TEST_TMPDIR/osr"
    _detect "$TEST_TMPDIR/osr"
    assert_success
    assert_output "linux unknown"
    refute_output --partial "unbound variable"
}

@test "detect_distro does not leak os-release variables into the shell" {
    make_test_tmpdir
    mock_os_release debian "Debian GNU/Linux 12" 12
    local fakebin="$TEST_TMPDIR/fakebin"; mkdir -p "$fakebin"
    printf '#!/bin/sh\necho Linux\n' > "$fakebin/uname"; chmod +x "$fakebin/uname"
    run env -u PKG_MANAGER PATH="$fakebin:$PATH" CYBERSEC_OS_RELEASE="$MOCK_OS_RELEASE" \
        SCRIPT_DIR="$PROJECT_ROOT" LOG_FILE=/dev/null \
        bash -c 'source "$SCRIPT_DIR/lib/common.sh"; echo "[${VERSION_ID:-unset}]"'
    assert_output "[unset]"
}

@test "detect_pkg_manager sets pkg for Termux" {
    make_test_tmpdir
    mock_os_release debian
    _detect "$MOCK_OS_RELEASE" TERMUX_VERSION=0.118 PREFIX="$TEST_TMPDIR/prefix"
    assert_output "android pkg"
}

@test "_normalize_bool canonicalises truthy and falsy spellings" {
    source_libs debian apt
    local v
    for v in true 1 yes on TRUE Yes; do
        FLAG="$v"; _normalize_bool FLAG; [[ "$FLAG" == "true" ]]
    done
    for v in false 0 no off FALSE ""; do
        FLAG="$v"; _normalize_bool FLAG; [[ "$FLAG" == "false" ]]
    done
}

@test "_normalize_bool rejects anything else with exit 2" {
    source_libs debian apt
    FLAG=banana
    run _normalize_bool FLAG
    assert_failure 2
    assert_output --partial "Invalid value for FLAG"
}

@test "PARALLEL_JOBS with leading zeros is read as decimal" {
    run env PARALLEL_JOBS=0016 SCRIPT_DIR="$PROJECT_ROOT" LOG_FILE=/dev/null PKG_MANAGER=apt DISTRO_ID=debian \
        bash -c 'source "$SCRIPT_DIR/lib/common.sh"; echo "$PARALLEL_JOBS"'
    assert_output "16"
    run env PARALLEL_JOBS=08 SCRIPT_DIR="$PROJECT_ROOT" LOG_FILE=/dev/null PKG_MANAGER=apt DISTRO_ID=debian \
        bash -c 'source "$SCRIPT_DIR/lib/common.sh"; echo "$PARALLEL_JOBS"'
    assert_output "8"
}

@test "log_message prints backslash sequences verbatim on one line" {
    source_libs debian apt
    make_test_tmpdir
    LOG_FILE="$TEST_TMPDIR/out.log"
    : > "$LOG_FILE"
    run log_info 'path C:\new\table and \c cut'
    assert_success
    assert_output --partial 'path C:\new\table and \c cut'
    [[ "${#lines[@]}" -eq 1 ]]
    log_info 'path C:\new\table and \c cut'
    log_info 'next'
    [[ "$(wc -l < "$LOG_FILE" | tr -d ' ')" == "3" ]]
    grep -qF 'path C:\new\table and \c cut' "$LOG_FILE"
    ! grep -q $'\033' "$LOG_FILE"
}

@test "log_message strips ANSI colour codes from the log file" {
    source_libs debian apt
    make_test_tmpdir
    LOG_FILE="$TEST_TMPDIR/out.log"
    : > "$LOG_FILE"
    log_message $'\033[31mred\033[0m text'
    grep -q ' - red text$' "$LOG_FILE"
}

@test "_acquire_run_lock warns when flock is unavailable" {
    source_libs debian apt
    local saved_path="$PATH"
    PATH=/nonexistent
    run _acquire_run_lock
    PATH="$saved_path"
    assert_success
    assert_output --partial "No run lock"
}

@test "root PATH keeps \$HOME/.cargo/bin after the system directories" {
    run env -u PKG_MANAGER HOME="$BATS_TEST_TMPDIR/h" SCRIPT_DIR="$PROJECT_ROOT" LOG_FILE=/dev/null \
        PKG_MANAGER=apt DISTRO_ID=debian \
        bash -c 'source "$SCRIPT_DIR/lib/common.sh"
                 case ":$PATH:" in *":/usr/bin:"*"$HOME/.cargo/bin:"*) echo ordered ;; *) echo "bad: $PATH" ;; esac'
    assert_output "ordered"
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
# Root's cargo under /root is unreachable for $SUDO_USER, and a
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

@test "_git_safe_reset_to_remote stops before resetting when local edits cannot be stashed" {
    make_test_tmpdir
    local repository="$TEST_TMPDIR/repo"
    git init -q -b main "$repository"
    printf 'original\n' > "$repository/notes"
    git -C "$repository" add notes
    git -C "$repository" -c user.name=fixture -c user.email=fixture@example.invalid commit -qm original
    git -C "$repository" update-ref refs/remotes/origin/main HEAD
    git -C "$repository" symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main
    printf 'local changes\n' > "$repository/notes"
    _as_builder() {
        printf '%s\n' "$1" >> "$TEST_TMPDIR/git-commands"
        [[ "$1" != *' stash push '* ]] || return 1
        [[ "$1" != *' fetch origin'* ]] || return 0
        bash -c "$1"
    }

    run _git_safe_reset_to_remote "$repository" "$TEST_TMPDIR/git.log"

    assert_failure
    [[ "$(cat "$repository/notes")" == 'local changes' ]]
    ! grep -q 'reset --hard' "$TEST_TMPDIR/git-commands"
}

@test "_git_safe_reset_to_remote leaves an older automatic stash untouched" {
    make_test_tmpdir
    local upstream="$TEST_TMPDIR/upstream" repository="$TEST_TMPDIR/repo"
    git init -q -b main "$upstream"
    printf 'original\n' > "$upstream/notes"
    git -C "$upstream" add notes
    git -C "$upstream" -c user.name=fixture -c user.email=fixture@example.invalid commit -qm original
    git clone -q "$upstream" "$repository"
    printf 'older changes\n' > "$repository/notes"
    git -C "$repository" stash push -qm 'cybersec-toolkit: auto-stash before update'
    local previous_stash
    previous_stash=$(git -C "$repository" rev-parse refs/stash)

    run _git_safe_reset_to_remote "$repository" "$TEST_TMPDIR/git.log"

    assert_success
    [[ "$(cat "$repository/notes")" == original ]]
    [[ "$(git -C "$repository" rev-parse refs/stash)" == "$previous_stash" ]]
}

@test "_path_append appends each directory once and never reorders PATH" {
    # A builder-owned dir ahead of /usr/bin would let it shadow sha256sum/tar for root.
    # PATH is restored before asserting: bats' own cleanup needs rm, which is /bin/rm on macOS.
    local saved_path="$PATH" result
    PATH="/usr/bin:/home/u/.local/bin"
    _path_append /home/u/.cargo/bin /home/u/.local/bin /home/u/.cargo/bin
    result="$PATH"
    PATH="$saved_path"
    [[ "$result" == "/usr/bin:/home/u/.local/bin:/home/u/.cargo/bin" ]]
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

@test "lazy package index refreshes once, only on the first install" {
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

@test "zypper refresh does not auto-import repo keys outside CI" {
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

@test "git_clone_or_pull leaves an existing non-git directory alone" {
    make_test_tmpdir
    local dest="$TEST_TMPDIR/opt/tool"
    mkdir -p "$dest"
    printf 'mine\n' > "$dest/notes.txt"
    export SUDO_USER=builder
    chown() { echo "chown $*" >> "$TEST_TMPDIR/calls.log"; }
    _as_builder() { echo "as_builder $*" >> "$TEST_TMPDIR/calls.log"; return 1; }

    run git_clone_or_pull "https://internal.example/tool.git" "$dest"

    assert_failure
    [[ ! -e "$TEST_TMPDIR/calls.log" ]]
    [[ -f "$dest/notes.txt" ]]
}

@test "strict mode refuses an unsigned bootstrap only when it would run as root" {
    REQUIRE_CHECKSUMS=true PKG_MANAGER=apt SUDO_USER="" run _strict_refuses_root_bootstrap rustup
    assert_success
    assert_output --partial "Skipping rustup in strict mode"
    REQUIRE_CHECKSUMS=true PKG_MANAGER=apt SUDO_USER=builder run _strict_refuses_root_bootstrap rustup
    assert_failure
    REQUIRE_CHECKSUMS=false PKG_MANAGER=apt SUDO_USER="" run _strict_refuses_root_bootstrap rustup
    assert_failure
}

@test "pkg_remove refuses a removal that would take dependent packages along" {
    make_test_tmpdir
    apt-get() {
        if [[ "$1" == -s ]]; then
            printf 'Remv nodejs [20.1]\nRemv user-app [1.0]\n'
        else
            echo "apt-get $*" >> "$TEST_TMPDIR/calls"
        fi
    }
    maybe_sudo() { env "$@" 2>/dev/null || "$@"; }
    PKG_MANAGER=apt

    run pkg_remove nodejs
    assert_failure
    assert_output --partial "user-app"
    [[ ! -e "$TEST_TMPDIR/calls" ]]
}

@test "pkg_cleanup leaves orphaned packages alone unless autoremove is requested" {
    make_test_tmpdir
    maybe_sudo() { echo "$*" >> "$TEST_TMPDIR/calls"; }

    for manager in apt dnf; do
        : > "$TEST_TMPDIR/calls"
        PKG_MANAGER="$manager" PKG_AUTOREMOVE=0 run pkg_cleanup
        assert_success
        run grep -c autoremove "$TEST_TMPDIR/calls"
        assert_output "0"
        run grep -c clean "$TEST_TMPDIR/calls"
        refute_output "0"

        : > "$TEST_TMPDIR/calls"
        PKG_MANAGER="$manager" PKG_AUTOREMOVE=1 run pkg_cleanup
        assert_success
        run grep -c autoremove "$TEST_TMPDIR/calls"
        assert_output "1"
    done
}

@test "the install log never writes through a planted symlink" {
    make_test_tmpdir
    printf 'keep\n' > "$TEST_TMPDIR/victim"
    ln -s "$TEST_TMPDIR/victim" "$TEST_TMPDIR/cybersec_install.log"

    _init_log_file "$TEST_TMPDIR/cybersec_install.log"

    [[ "$(cat "$TEST_TMPDIR/victim")" == "keep" ]]
    [[ ! -L "$TEST_TMPDIR/cybersec_install.log" ]]
}

@test "_show_log_tail prints the end of the run log to stderr" {
    bats_require_minimum_version 1.5.0
    make_test_tmpdir
    printf 'line %s\n' 1 2 3 4 5 > "$TEST_TMPDIR/run.log"
    LOG_FILE="$TEST_TMPDIR/run.log"

    run --separate-stderr _show_log_tail 2
    assert_success
    assert_output ""
    [[ "$stderr" == *"line 4"* && "$stderr" == *"line 5"* && "$stderr" != *"line 3"* ]]
}

@test "_show_log_tail is silent without a readable log" {
    LOG_FILE=/dev/null run _show_log_tail
    assert_success
    assert_output ""
}

# apt-get stub for the removal tests: user-app needs lib-b, and lib-b needs lib-c.
_apt_removal_stub() {
    apt-get() {
        if [[ "$1" != -s ]]; then
            echo "apt-get $*" >> "$TEST_TMPDIR/calls"
            return 0
        fi
        shift 2
        local pkg
        for pkg in "$@"; do
            printf 'Remv %s [1.0]\n' "$pkg"
            case "$pkg" in
                lib-b) printf 'Remv user-app [1.0]\n' ;;
                lib-c) printf 'Remv lib-b [1.0]\n' ;;
            esac
        done
    }
    maybe_sudo() { "$@"; }
    PKG_MANAGER=apt
}

@test "pkg_remove removes what nothing else needs and keeps the rest" {
    make_test_tmpdir
    _apt_removal_stub

    run pkg_remove tool-a lib-b
    assert_failure
    assert_output --partial "Keeping lib-b: needed by user-app"
    run cat "$TEST_TMPDIR/calls"
    assert_output "apt-get remove -y tool-a"
}

@test "pkg_remove also keeps a package that a kept package needs" {
    make_test_tmpdir
    _apt_removal_stub

    run pkg_remove tool-a lib-b lib-c
    assert_failure
    assert_output --partial "Keeping lib-c: needed by lib-b"
    run cat "$TEST_TMPDIR/calls"
    assert_output "apt-get remove -y tool-a"
}

@test "pkg_remove removes a whole list that depends only on itself" {
    make_test_tmpdir
    _apt_removal_stub

    run pkg_remove tool-a tool-d
    assert_success
    run cat "$TEST_TMPDIR/calls"
    assert_output "apt-get remove -y tool-a tool-d"
}

@test "pkg_remove treats an unreadable package manager answer as a blocker" {
    make_test_tmpdir
    apt-get() {
        [[ "$1" == -s ]] || { echo "apt-get $*" >> "$TEST_TMPDIR/calls"; return 0; }
        # The list as a whole reports a dependent; the per-package question then fails.
        [[ $# -gt 3 ]] && { printf 'Remv a [1]\nRemv other [1]\n'; return 0; }
        return 100
    }
    maybe_sudo() { "$@"; }
    PKG_MANAGER=apt

    run pkg_remove a b
    assert_failure
    [[ ! -e "$TEST_TMPDIR/calls" ]]
}

# lib/shared.sh hardening

@test "_version_ge handles pre-release, non-numeric and zero-padded versions" {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/lib/shared.sh"
    run _version_ge 1.26rc1 1.21
    assert_success
    refute_output --partial "too great"
    run _version_ge devel 1.21
    assert_failure 1
    refute_output --partial "unbound"
    run _version_ge 1.9 1.21
    assert_failure 1
    run _version_ge 1.21 1.21
    assert_success
    run _version_ge 1.08 1.8
    assert_success

    run _version_ge 1.26rc1 1.27
    assert_failure
    run _version_ge 3.11rc2 3.12
    assert_failure
}

@test "version-bound env vars with command substitutions fall back to defaults" {
    make_test_tmpdir
    run env NODE_MIN_VERSION='a[$(touch '"$TEST_TMPDIR"'/pwned)]' GO_MIN_VERSION='1.x' \
        PYTHON_MIN_VERSION='3.$(id)' PYTHON_TRY_MAX='x' \
        SCRIPT_DIR="$PROJECT_ROOT" LOG_FILE=/dev/null PKG_MANAGER=apt DISTRO_ID=debian \
        bash -c 'source "$SCRIPT_DIR/lib/common.sh"; source "$SCRIPT_DIR/lib/installers.sh"
                 source "$SCRIPT_DIR/lib/shared.sh"
                 echo "$NODE_MIN_VERSION $GO_MIN_VERSION $PYTHON_MIN_VERSION $PYTHON_TRY_MAX"'
    assert_output "22 1.21 3.11 3.13"
    [ ! -e "$TEST_TMPDIR/pwned" ]
}

# _ppa_probe DISTRO [VAR=value ...] — run ensure_python_modern on a stubbed apt host
# with Python 3.10; add-apt-repository leaves a marker file instead of touching apt.
_ppa_probe() {
    local _distro="$1"; shift
    make_test_tmpdir
    rm -f "$TEST_TMPDIR/ppa_added"
    run env "$@" SCRIPT_DIR="$PROJECT_ROOT" LOG_FILE=/dev/null PKG_MANAGER=apt \
        PPA_MARKER="$TEST_TMPDIR/ppa_added" PROBE_DISTRO="$_distro" \
        bash -c 'source "$SCRIPT_DIR/lib/common.sh"; source "$SCRIPT_DIR/lib/installers.sh"
                 source "$SCRIPT_DIR/lib/shared.sh"
                 DISTRO_ID="$PROBE_DISTRO"; DISTRO_ID_LIKE=debian
                 python3() { echo "Python 3.10.12"; }
                 command_exists() { [[ "$1" == python3 || "$1" == add-apt-repository ]]; }
                 add-apt-repository() { : > "$PPA_MARKER"; }
                 pkg_update() { :; }
                 pkg_install() { return 1; }
                 ensure_python_modern'
}

@test "ensure_python_modern never adds the deadsnakes PPA in strict mode" {
    _ppa_probe ubuntu REQUIRE_CHECKSUMS=true
    [ ! -e "$TEST_TMPDIR/ppa_added" ]
    assert_output --partial "Strict mode"
}

@test "ensure_python_modern adds the deadsnakes PPA on Ubuntu unless CYBERSEC_ALLOW_PPA=0" {
    _ppa_probe ubuntu REQUIRE_CHECKSUMS=false
    [ -e "$TEST_TMPDIR/ppa_added" ]
    assert_output --partial "CYBERSEC_ALLOW_PPA=0 skips it"
    _ppa_probe ubuntu REQUIRE_CHECKSUMS=false CYBERSEC_ALLOW_PPA=0
    [ ! -e "$TEST_TMPDIR/ppa_added" ]
}

@test "ensure_python_modern never adds the Ubuntu-only deadsnakes PPA on Debian or Kali" {
    _ppa_probe debian REQUIRE_CHECKSUMS=false
    [ ! -e "$TEST_TMPDIR/ppa_added" ]
    assert_output --partial "Ubuntu-only"
    _ppa_probe kali REQUIRE_CHECKSUMS=false
    [ ! -e "$TEST_TMPDIR/ppa_added" ]
}
