#!/usr/bin/env bats

setup() {
    load 'test_helper'
    make_test_tmpdir
}

_guard_fixture() {
    export XDG_STATE_HOME="$TEST_TMPDIR/state"
    export CYBERSEC_MCP_AUDIT_LOG="$TEST_TMPDIR/audit.log"
    mkdir -p "$XDG_STATE_HOME/cybersec-tools-mcp"
    printf '2026-07-28T10:00:00.000Z\n' \
        > "$XDG_STATE_HOME/cybersec-tools-mcp/guard-session"
}

_run_guarded_nmap() {
    run env \
        XDG_STATE_HOME="$XDG_STATE_HOME" \
        CYBERSEC_MCP_AUDIT_LOG="$CYBERSEC_MCP_AUDIT_LOG" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" pre-bash \
        <<< '{"tool_input":{"command":"nmap 192.0.2.10"}}'
}

@test "agent guard is not unlocked by an unrelated MCP call" {
    _guard_fixture
    printf '%s\n' \
        '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"list_tools"}' \
        > "$CYBERSEC_MCP_AUDIT_LOG"

    _run_guarded_nmap

    assert_success
    assert_output --partial '"permissionDecision":"deny"'
}

@test "agent guard accepts the documented advisor calls" {
    local advisor
    for advisor in guided_assessment suggest_for_ctf suggest_for_bounty; do
        _guard_fixture
        printf '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"%s"}\n' \
            "$advisor" > "$CYBERSEC_MCP_AUDIT_LOG"

        _run_guarded_nmap

        assert_success
        assert_output ""
    done
}

@test "a recent unrelated call does not mask a stale advisor call" {
    _guard_fixture
    {
        printf '%s\n' \
            '{"ts":"2026-07-28T09:59:59.000Z","event":"tool_call","tool":"guided_assessment"}'
        printf '%s\n' \
            '{"ts":"2026-07-28T10:00:02.000Z","event":"tool_call","tool":"check_installed"}'
    } > "$CYBERSEC_MCP_AUDIT_LOG"

    _run_guarded_nmap

    assert_success
    assert_output --partial '"permissionDecision":"deny"'
}

@test "backup help is side-effect free" {
    local test_home="$TEST_TMPDIR/home"
    mkdir -p "$test_home"

    run env -u SUDO_USER \
        HOME="$test_home" \
        PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 \
        bash "$PROJECT_ROOT/scripts/backup.sh" --help

    assert_success
    assert_output --partial "Usage:"
    [[ ! -e "$test_home/cybersec_tools_backup" ]]
}

@test "backup artifacts and directory are owner-only" {
    local test_home="$TEST_TMPDIR/home"
    local backup_dir="$test_home/cybersec_tools_backup"
    mkdir -p "$test_home"

    run env -u SUDO_USER \
        HOME="$test_home" \
        PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" backup

    assert_success
    [[ "$(stat -c '%a' "$backup_dir")" == "700" ]]
    local -a encrypted=("$backup_dir"/backup_*.tar.gz.enc)
    [[ -f "${encrypted[0]}" ]]
    [[ -f "${encrypted[0]}.hmac" ]]
    [[ "$(stat -c '%a' "${encrypted[0]}")" == "600" ]]
    [[ "$(stat -c '%a' "${encrypted[0]}.hmac")" == "600" ]]
    [[ -z "$(find "$backup_dir" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)" ]]
    [[ -z "$(find "$backup_dir" -mindepth 1 -maxdepth 1 -type d -print -quit)" ]]
}

@test "restore rejects multiple archive roots without overwriting stored backups" {
    local test_home="$TEST_TMPDIR/home"
    local backup_dir="$test_home/cybersec_tools_backup"
    local archive_src="$TEST_TMPDIR/archive-src"
    local archive="$TEST_TMPDIR/restore.tar.gz"
    mkdir -p "$backup_dir" "$archive_src/backup_fixture"
    printf 'original\n' > "$backup_dir/preserved.tar.gz.enc"
    printf 'archive-controlled\n' > "$archive_src/preserved.tar.gz.enc"
    tar -czf "$archive" -C "$archive_src" backup_fixture preserved.tar.gz.enc

    run env -u SUDO_USER \
        HOME="$test_home" \
        PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "$archive"

    assert_failure
    assert_output --partial "exactly one top-level directory"
    [[ "$(< "$backup_dir/preserved.tar.gz.enc")" == "original" ]]
}

@test "backup rejects a symlinked storage directory" {
    local test_home="$TEST_TMPDIR/home"
    local redirected="$TEST_TMPDIR/redirected"
    mkdir -p "$test_home" "$redirected"
    ln -s "$redirected" "$test_home/cybersec_tools_backup"

    run env -u SUDO_USER \
        HOME="$test_home" \
        PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" backup

    assert_failure
    assert_output --partial "Refusing unsafe backup path"
    [[ -z "$(find "$redirected" -mindepth 1 -print -quit)" ]]
}

@test "sudo restore returns ownership only for restored subtrees" {
    local test_home="$TEST_TMPDIR/home"
    local archive_src="$TEST_TMPDIR/archive-src"
    local archive="$TEST_TMPDIR/restore.tar.gz"
    local mock_bin="$TEST_TMPDIR/bin"
    local chown_log="$TEST_TMPDIR/chown.log"
    mkdir -p "$test_home" "$archive_src/backup_fixture/network/.nmap" "$mock_bin"
    printf 'setting\n' > "$archive_src/backup_fixture/network/.nmap/settings"
    tar -czf "$archive" -C "$archive_src" backup_fixture

    printf '%s\n' \
        '#!/bin/sh' \
        'printf "fixture-user:x:1001:1001::%s:/bin/bash\n" "$FAKE_HOME"' \
        > "$mock_bin/getent"
    printf '%s\n' \
        '#!/bin/sh' \
        'printf "%s\n" "$*" >> "$CHOWN_LOG"' \
        > "$mock_bin/chown"
    chmod +x "$mock_bin/getent" "$mock_bin/chown"

    run env \
        SUDO_USER=fixture-user \
        FAKE_HOME="$test_home" \
        CHOWN_LOG="$chown_log" \
        HOME="$TEST_TMPDIR/root-home" \
        PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 \
        PATH="$mock_bin:$PATH" \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "$archive"

    assert_success
    [[ -f "$test_home/.nmap/settings" ]]
    grep -Fx -- "-R -- fixture-user $test_home/.nmap" "$chown_log"
    ! grep -Fx -- "-R -- fixture-user $test_home" "$chown_log"
}

@test "restore rejects a symlinked config parent" {
    local test_home="$TEST_TMPDIR/home"
    local redirected="$TEST_TMPDIR/redirected"
    local archive_src="$TEST_TMPDIR/archive-src"
    local archive="$TEST_TMPDIR/restore.tar.gz"
    mkdir -p "$test_home" "$redirected" \
        "$archive_src/backup_fixture/web/nuclei"
    ln -s "$redirected" "$test_home/.config"
    printf 'setting\n' \
        > "$archive_src/backup_fixture/web/nuclei/settings"
    tar -czf "$archive" -C "$archive_src" backup_fixture

    run env -u SUDO_USER \
        HOME="$test_home" \
        PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "$archive"

    assert_failure
    assert_output --partial "symlinked destination"
    [[ ! -e "$redirected/nuclei" ]]
}

@test "backup integrity commands keep secret material out of argv" {
    run grep -En -- 'hexpass:|hexkey:' "$PROJECT_ROOT/scripts/backup.sh"

    assert_failure
}

@test "distro package validator help is explicit" {
    run bash "$PROJECT_ROOT/scripts/validate_distro_packages.sh" --help

    assert_success
    assert_output --partial "Usage:"
    refute_output --partial "set -uo pipefail"
}

@test "distro package validator rejects an unknown module" {
    run bash "$PROJECT_ROOT/scripts/validate_distro_packages.sh" \
        --module definitely-not-a-module

    assert_failure
    assert_output --partial "Unknown module"
}

@test "distro package validator rejects a missing module argument" {
    run bash "$PROJECT_ROOT/scripts/validate_distro_packages.sh" --module

    assert_failure
    assert_output --partial "Missing value for --module"
}

# ---------- backup restore: transactional per-target (points 8/9/10) ----------
# Load just _restore_tree with stub loggers so we can exercise it in isolation.
_load_restore_tree() {
    log_warn() { :; }
    log_error() { :; }
    ensure_dir() { mkdir -p "$1" 2>/dev/null; }
    eval "$(sed -n '/^_restore_tree()/,/^}/p' "$PROJECT_ROOT/scripts/backup.sh")"
}

@test "restore replaces the target and leaves no staging files" {
    _load_restore_tree
    mkdir -p "$TEST_TMPDIR/src/.nmap" "$TEST_TMPDIR/home/.nmap"
    echo NEW > "$TEST_TMPDIR/src/.nmap/c"
    echo OLD > "$TEST_TMPDIR/home/.nmap/c"

    run _restore_tree "$TEST_TMPDIR/src/.nmap" "$TEST_TMPDIR/home" ".nmap"
    assert_success
    [[ "$(cat "$TEST_TMPDIR/home/.nmap/c")" == "NEW" ]]
    ! find "$TEST_TMPDIR/home" -name '.cybersec-restore.*' | grep -q .
}

@test "restore rolls back to the old target when the copy fails" {
    _load_restore_tree
    mkdir -p "$TEST_TMPDIR/src/.nmap" "$TEST_TMPDIR/home/.nmap"
    echo NEW > "$TEST_TMPDIR/src/.nmap/c"
    echo OLD > "$TEST_TMPDIR/home/.nmap/c"
    cp() { return 1; }   # force the staging copy to fail

    run _restore_tree "$TEST_TMPDIR/src/.nmap" "$TEST_TMPDIR/home" ".nmap"
    assert_failure
    [[ "$(cat "$TEST_TMPDIR/home/.nmap/c")" == "OLD" ]]
    ! find "$TEST_TMPDIR/home" -name '.cybersec-restore.*' | grep -q .
}

@test "restore refuses a symlinked destination without writing through it" {
    _load_restore_tree
    mkdir -p "$TEST_TMPDIR/src/.nmap" "$TEST_TMPDIR/elsewhere" "$TEST_TMPDIR/home"
    echo X > "$TEST_TMPDIR/src/.nmap/c"
    ln -s "$TEST_TMPDIR/elsewhere" "$TEST_TMPDIR/home/.nmap"

    run _restore_tree "$TEST_TMPDIR/src/.nmap" "$TEST_TMPDIR/home" ".nmap"
    assert_failure
    [[ ! -e "$TEST_TMPDIR/elsewhere/c" ]]
}
