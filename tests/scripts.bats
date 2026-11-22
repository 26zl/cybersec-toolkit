#!/usr/bin/env bats

setup() {
    load 'test_helper'
    make_test_tmpdir
}

# Octal mode of a path; `stat -c` is GNU, `stat -f` is BSD/macOS.
_file_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

_guard_fixture() {
    export XDG_STATE_HOME="$TEST_TMPDIR/state"
    export CYBERSEC_MCP_AUDIT_LOG="$TEST_TMPDIR/audit.log"
    mkdir -p "$XDG_STATE_HOME/cybersec-tools-mcp"
    printf '2026-07-28T10:00:00.000Z\n' \
        > "$XDG_STATE_HOME/cybersec-tools-mcp/guard-session"
    # The fixtures are dated 2026-07-28 10:00 UTC; the guard's clock reads ten minutes later.
    export CYBERSEC_AGENT_GUARD_NOW=1785233400
}

_run_guarded_nmap() {
    # -u: a developer with the documented escape hatch exported must not see false failures.
    run env -u CYBERSEC_AGENT_GUARD \
        XDG_STATE_HOME="$XDG_STATE_HOME" \
        CYBERSEC_MCP_AUDIT_LOG="$CYBERSEC_MCP_AUDIT_LOG" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" pre-bash \
        <<< '{"tool_input":{"command":"nmap 192.0.2.10"}}'
}

@test "an advisor call earlier in the same second does not clear a session that starts after it" {
    export XDG_STATE_HOME="$TEST_TMPDIR/state" CYBERSEC_MCP_AUDIT_LOG="$TEST_TMPDIR/audit.log"
    mkdir -p "$XDG_STATE_HOME/cybersec-tools-mcp"
    : > "$CYBERSEC_MCP_AUDIT_LOG"
    run env -u CYBERSEC_AGENT_GUARD bash "$PROJECT_ROOT/scripts/agent-guard.sh" session-start \
        <<< '{"session_id":"same-second"}'
    assert_success
    local marker
    marker=$(cat "$XDG_STATE_HOME/cybersec-tools-mcp/guard-session.same-second")
    printf '{"ts":"%s.500Z","event":"tool_call","tool":"suggest_for_ctf"}\n' "${marker%.*}" \
        > "$CYBERSEC_MCP_AUDIT_LOG"
    run env -u CYBERSEC_AGENT_GUARD bash "$PROJECT_ROOT/scripts/agent-guard.sh" pre-bash \
        <<< '{"session_id":"same-second","tool_input":{"command":"nmap 192.0.2.10"}}'
    assert_success
    assert_output --partial '"permissionDecision":"deny"'
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

_run_guard_on() {
    local json
    json=$(python3 -c 'import json, sys; print(json.dumps({"tool_input": {"command": sys.argv[1]}}))' "$1")
    run env -u CYBERSEC_AGENT_GUARD \
        XDG_STATE_HOME="$XDG_STATE_HOME" \
        CYBERSEC_MCP_AUDIT_LOG="$CYBERSEC_MCP_AUDIT_LOG" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" pre-bash <<< "$json"
}

@test "agent guard derives git CLI names and native aliases from the registry" {
    _guard_fixture
    printf '%s\n' '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"list_tools"}' \
        > "$CYBERSEC_MCP_AUDIT_LOG"
    local cmd audit_before
    audit_before=$(cat "$CYBERSEC_MCP_AUDIT_LOG")
    for cmd in \
        'commix --help' \
        '/usr/local/bin/ghauri --help' \
        'tplmap --help' \
        'python3 /opt/SSRFmap/ssrfmap.py --help' \
        'jwt_tool --help' \
        'ASRepCatcher --help' \
        'RsaCtfTool --help' \
        'rsacrack --help' \
        'qltool --help' \
        'krak2 --help' \
        'setoolkit --help' \
        'afl-fuzz --help' \
        'sstrip --help'; do
        _run_guard_on "$cmd"
        assert_success
        assert_output --partial '"permissionDecision":"deny"'
    done
    [[ "$(cat "$CYBERSEC_MCP_AUDIT_LOG")" == "$audit_before" ]]
    [[ ! -e "$XDG_STATE_HOME/cybersec-tools-mcp/remote_hosts.json" ]]
}

@test "agent guard accepts new registry CLI aliases after the advisor call" {
    _guard_fixture
    printf '%s\n' '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"guided_assessment"}' \
        > "$CYBERSEC_MCP_AUDIT_LOG"
    local cmd
    for cmd in 'commix --help' 'python3 /opt/SSRFmap/ssrfmap.py --help' 'rsacrack --help' 'afl-fuzz --help'; do
        _run_guard_on "$cmd"
        assert_success
        assert_output ""
    done
}

@test "agent guard registry expansion preserves development commands and shell builtins" {
    _guard_fixture
    printf '%s\n' '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"list_tools"}' \
        > "$CYBERSEC_MCP_AUDIT_LOG"
    local cmd
    for cmd in \
        'set -uo pipefail' \
        'git diff --stat' \
        'python3 -m pytest tests/' \
        'gdb --version' \
        'readelf --headers synthetic.o' \
        'objdump -d synthetic.o' \
        'openssl version' \
        'node --version' \
        'make --version'; do
        _run_guard_on "$cmd"
        assert_success
        assert_output ""
    done
}

@test "agent guard asks for a fresh advisor call once the last one is hours old" {
    _guard_fixture
    printf '%s\n' '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"guided_assessment"}' \
        > "$CYBERSEC_MCP_AUDIT_LOG"

    # Three hours and 59 minutes after the call it still clears; a minute past four hours it does not.
    CYBERSEC_AGENT_GUARD_NOW=$((1785233400 - 600 + 14340)) _run_guarded_nmap
    assert_success
    assert_output ""

    CYBERSEC_AGENT_GUARD_NOW=$((1785233400 - 600 + 14460)) _run_guarded_nmap
    assert_success
    assert_output --partial '"permissionDecision":"deny"'
    refute_output --partial "CYBERSEC_AGENT_GUARD"
}

@test "agent guard treats quoted text and heredoc bodies as data" {
    _guard_fixture
    printf '%s\n' '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"list_tools"}' \
        > "$CYBERSEC_MCP_AUDIT_LOG"
    local cmd
    for cmd in \
        'git commit -m "update tools; nmap now pinned"' \
        'grep -nE "nmap|nuclei|ffuf" tools_config.json' \
        'FOO="a nmap b" make test' \
        'command -v nmap' \
        $'cat > notes.md <<\'EOF\'\nnmap -sV 192.0.2.10\nEOF' \
        $'git commit -F - <<\'EOF\'\nnuclei: bump templates\nEOF'; do
        _run_guard_on "$cmd"
        assert_success
        assert_output ""
    done
}

@test "agent guard still gates governed tools after separators, wrappers, and heredocs" {
    _guard_fixture
    printf '%s\n' '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"list_tools"}' \
        > "$CYBERSEC_MCP_AUDIT_LOG"
    local cmd
    for cmd in \
        'cd /tmp && nmap 192.0.2.10' \
        'sudo -u root nmap 192.0.2.10' \
        'echo "$(sqlmap -u http://192.0.2.10)"' \
        '/usr/bin/nmap 192.0.2.10' \
        $'cat > f <<\'EOF\'\nhello\nEOF\nnmap 192.0.2.10' \
        $'echo "<<EOF"\nnmap 192.0.2.10' \
        $'x=$((a << b))\nnmap 192.0.2.10' \
        'timeout 300 nmap 192.0.2.10' \
        'nice -n 10 nmap 192.0.2.10' \
        'echo 192.0.2.10 | xargs nmap' \
        'bash -c "nmap 192.0.2.10"'; do
        _run_guard_on "$cmd"
        assert_success
        assert_output --partial '"permissionDecision":"deny"'
    done
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
    [[ "$(_file_mode "$backup_dir")" == "700" ]]
    local -a encrypted=("$backup_dir"/backup_*.tar.gz.enc)
    [[ -f "${encrypted[0]}" ]]
    [[ -f "${encrypted[0]}.hmac" ]]
    [[ "$(_file_mode "${encrypted[0]}")" == "600" ]]
    [[ "$(_file_mode "${encrypted[0]}.hmac")" == "600" ]]
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
        BACKUP_ALLOW_UNVERIFIED=1 \
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
        BACKUP_ALLOW_UNVERIFIED=1 \
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
        BACKUP_ALLOW_UNVERIFIED=1 \
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

# Backup restore is transactional per target.
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

@test "backup leaves out symlinks so the archive stays restorable" {
    local test_home="$TEST_TMPDIR/home"
    mkdir -p "$test_home/.nmap"
    printf 'setting\n' > "$test_home/.nmap/settings"
    ln -s settings "$test_home/.nmap/alias"

    run env -u SUDO_USER \
        HOME="$test_home" \
        PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" backup
    assert_success

    local -a encrypted=("$test_home"/cybersec_tools_backup/backup_*.tar.gz.enc)
    printf 'test-only-passphrase' > "$TEST_TMPDIR/pass"
    openssl enc -chacha20 -d -pbkdf2 -iter 600000 -in "${encrypted[0]}" \
        -out "$TEST_TMPDIR/backup.tar.gz" -pass file:"$TEST_TMPDIR/pass"
    run tar -tvzf "$TEST_TMPDIR/backup.tar.gz"
    assert_success
    assert_output --partial ".nmap/settings"
    refute_line --regexp '^l'
}

@test "backup skips a symlinked config directory instead of archiving its target" {
    local test_home="$TEST_TMPDIR/home" secret="$TEST_TMPDIR/secret-target"
    mkdir -p "$test_home" "$secret"
    printf 'marker-content\n' > "$secret/marker-file"
    ln -s "$secret" "$test_home/.john"

    run env -u SUDO_USER \
        HOME="$test_home" \
        PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" backup
    assert_success
    assert_output --partial "Skipping symlinked config path: $test_home/.john"

    local -a encrypted=("$test_home"/cybersec_tools_backup/backup_*.tar.gz.enc)
    printf 'test-only-passphrase' > "$TEST_TMPDIR/pass"
    openssl enc -chacha20 -d -pbkdf2 -iter 600000 -in "${encrypted[0]}" \
        -out "$TEST_TMPDIR/backup.tar.gz" -pass file:"$TEST_TMPDIR/pass"
    run tar -tzf "$TEST_TMPDIR/backup.tar.gz"
    assert_success
    refute_output --partial "marker-file"
}

@test "sudo restore creates a missing config parent owned by the invoking user" {
    local test_home="$TEST_TMPDIR/home"
    local archive_src="$TEST_TMPDIR/archive-src"
    local archive="$TEST_TMPDIR/restore.tar.gz"
    local mock_bin="$TEST_TMPDIR/bin"
    local chown_log="$TEST_TMPDIR/chown.log"
    mkdir -p "$test_home" "$archive_src/backup_fixture/web/nuclei" "$mock_bin"
    printf 'setting\n' > "$archive_src/backup_fixture/web/nuclei/settings"
    tar -czf "$archive" -C "$archive_src" backup_fixture
    printf '%s\n' '#!/bin/sh' \
        'printf "fixture-user:x:1001:1001::%s:/bin/bash\n" "$FAKE_HOME"' > "$mock_bin/getent"
    printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$*" >> "$CHOWN_LOG"' > "$mock_bin/chown"
    chmod +x "$mock_bin/getent" "$mock_bin/chown"

    run env \
        SUDO_USER=fixture-user FAKE_HOME="$test_home" CHOWN_LOG="$chown_log" \
        HOME="$TEST_TMPDIR/root-home" PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 BACKUP_ALLOW_UNVERIFIED=1 PATH="$mock_bin:$PATH" \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "$archive"

    assert_success
    [[ -f "$test_home/.config/nuclei/settings" ]]
    grep -Fx -- "-- fixture-user $test_home/.config" "$chown_log"
    [[ "$(_file_mode "$test_home/.config")" == "755" ]]
}

# Back up a one-file home, then print the archive path.
_restore_gate_backup() {
    local test_home="$1"
    mkdir -p "$test_home/.nmap"
    printf 'setting\n' > "$test_home/.nmap/settings"
    env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" backup >/dev/null 2>&1
    local -a encrypted=("$test_home"/cybersec_tools_backup/backup_*.tar.gz.enc)
    printf '%s' "${encrypted[0]}"
}

_restore_gate_run() {
    local test_home="$1" archive="$2"
    run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "$archive"
}

@test "restore refuses a tampered archive and leaves the home untouched" {
    local test_home="$TEST_TMPDIR/home" archive
    archive="$(_restore_gate_backup "$test_home")"
    rm -rf "$test_home/.nmap"
    python3 - "$archive" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
b[-1] ^= 0x01
open(p, 'wb').write(bytes(b))
PY
    _restore_gate_run "$test_home" "$archive"
    assert_failure
    assert_output --partial "Integrity check FAILED"
    [[ ! -e "$test_home/.nmap" ]]
}

@test "restore refuses an encrypted archive without its integrity tag" {
    local test_home="$TEST_TMPDIR/home" archive
    archive="$(_restore_gate_backup "$test_home")"
    rm -rf "$test_home/.nmap"
    rm -f "$archive.hmac"
    _restore_gate_run "$test_home" "$archive"
    assert_failure
    assert_output --partial "refusing an unauthenticated restore"
    [[ ! -e "$test_home/.nmap" ]]
}

# Build a legacy .tar.gz holding one hostile member of the given kind.
_craft_legacy_archive() {
    python3 - "$1" "$2" <<'PY'
import io, sys, tarfile
out, kind = sys.argv[1], sys.argv[2]
with tarfile.open(out, 'w:gz') as t:
    def add(name, data=b'x', **kw):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        for k, v in kw.items():
            setattr(ti, k, v)
        t.addfile(ti, io.BytesIO(data))
    if kind == 'dotdot':
        add('backup_x/../escape')
    elif kind == 'absolute':
        add('/tmp/escape')
    elif kind == 'symlink':
        ti = tarfile.TarInfo('backup_x/link')
        ti.type = tarfile.SYMTYPE
        ti.linkname = '/etc/passwd'
        t.addfile(ti)
    elif kind == 'hardlink':
        add('backup_x/a')
        ti = tarfile.TarInfo('backup_x/b')
        ti.type = tarfile.LNKTYPE
        ti.linkname = 'backup_x/a'
        t.addfile(ti)
PY
}

@test "restore refuses unsafe member paths in a legacy archive" {
    local test_home="$TEST_TMPDIR/home" kind
    mkdir -p "$test_home"
    for kind in dotdot absolute; do
        _craft_legacy_archive "$TEST_TMPDIR/$kind.tar.gz" "$kind"
        run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
            BACKUP_ALLOW_UNVERIFIED=1 \
            bash "$PROJECT_ROOT/scripts/backup.sh" restore "$TEST_TMPDIR/$kind.tar.gz"
        assert_failure
        assert_output --partial "unsafe path"
    done
}

@test "restore refuses symlink and hardlink members in a legacy archive" {
    local test_home="$TEST_TMPDIR/home" kind
    mkdir -p "$test_home"
    for kind in symlink hardlink; do
        _craft_legacy_archive "$TEST_TMPDIR/$kind.tar.gz" "$kind"
        run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
            BACKUP_ALLOW_UNVERIFIED=1 \
            bash "$PROJECT_ROOT/scripts/backup.sh" restore "$TEST_TMPDIR/$kind.tar.gz"
        assert_failure
        assert_output --partial "links or special members"
    done
}

@test "restore strips setuid bits from a legacy archive" {
    local test_home="$TEST_TMPDIR/home" src="$TEST_TMPDIR/archive-src"
    mkdir -p "$test_home" "$src/backup_fixture/network/.nmap"
    printf 'x\n' > "$src/backup_fixture/network/.nmap/suid"
    chmod 4755 "$src/backup_fixture/network/.nmap/suid"
    tar -czf "$TEST_TMPDIR/suid.tar.gz" -C "$src" backup_fixture

    run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_ALLOW_UNVERIFIED=1 \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "$TEST_TMPDIR/suid.tar.gz"
    assert_success
    [[ -f "$test_home/.nmap/suid" ]]
    [[ ! -u "$test_home/.nmap/suid" ]]
}

@test "restore leaves no group or world write bits on restored files" {
    local test_home="$TEST_TMPDIR/home" src="$TEST_TMPDIR/archive-src" f mode
    mkdir -p "$test_home" "$src/backup_fixture/network/.nmap"
    printf 'x\n' > "$src/backup_fixture/network/.nmap/plain"
    printf 'x\n' > "$src/backup_fixture/network/.nmap/loose"
    chmod 0644 "$src/backup_fixture/network/.nmap/plain"
    chmod 0666 "$src/backup_fixture/network/.nmap/loose"
    tar -czf "$TEST_TMPDIR/modes.tar.gz" -C "$src" backup_fixture

    run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_ALLOW_UNVERIFIED=1 bash "$PROJECT_ROOT/scripts/backup.sh" restore "$TEST_TMPDIR/modes.tar.gz"
    assert_success
    for f in plain loose; do
        mode=$(python3 -c 'import os, sys; print(os.stat(sys.argv[1]).st_mode & 0o7777)' "$test_home/.nmap/$f")
        (( (mode & 8#022) == 0 && (mode & 8#600) == 8#600 )) || { printf '%s has mode %o\n' "$f" "$mode"; return 1; }
    done
}

# Lifecycle scripts run as fake Termux against a copy of the repo with every
# package manager stubbed, so nothing on the host is touched.
_lifecycle_fixture() {
    LC_REPO="$TEST_TMPDIR/repo"
    LC_STUBS="$TEST_TMPDIR/stubs"
    mkdir -p "$LC_REPO/scripts" "$LC_STUBS" "$TEST_TMPDIR/home" \
        "$TEST_TMPDIR/prefix/bin" "$TEST_TMPDIR/tools"
    cp -R "$PROJECT_ROOT/lib" "$PROJECT_ROOT/modules" "$LC_REPO/"
    cp "$PROJECT_ROOT"/scripts/*.sh "$LC_REPO/scripts/"
    local cmd
    for cmd in pkg dpkg apt-get npm gem cargo pipx docker snap go sudo rustup uv; do
        printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\nexit 1\n' \
            "$cmd" "$TEST_TMPDIR" > "$LC_STUBS/$cmd"
        chmod +x "$LC_STUBS/$cmd"
    done
    printf '# schema: 2\n# tool|method|version|last_updated\n' > "$LC_REPO/.versions"
}

_run_lifecycle() {
    local script="$1"; shift
    run env -i HOME="$TEST_TMPDIR/home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        PKG_MANAGER=pkg DISTRO_ID=android DISTRO_ID_LIKE= DISTRO_NAME=Termux \
        GITHUB_TOOL_DIR="$TEST_TMPDIR/tools" TMPDIR="$TEST_TMPDIR" TERM=dumb \
        PATH="$LC_STUBS:$TEST_TMPDIR/prefix/bin:$PATH" \
        bash "$LC_REPO/scripts/$script" "$@"
}

_run_verify_linux() {
    run env -i HOME="$TEST_TMPDIR/home" PKG_MANAGER=apt DISTRO_ID=debian \
        DISTRO_ID_LIKE= DISTRO_NAME=Debian GITHUB_TOOL_DIR="$TEST_TMPDIR/tools" \
        CYBERSEC_FIXTURE_BIN="$LC_STUBS" TMPDIR="$TEST_TMPDIR" TERM=dumb PATH="$LC_STUBS:$PATH" \
        bash "$LC_REPO/scripts/verify.sh" "$@"
}

@test "tool array parser ignores associative metadata while retaining indexed tools" {
    run python3 - "$PROJECT_ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + '/scripts')
from validate_tools_config import parse_arrays
source = '''declare -gA SAMPLE_BINARY_RUNTIME_CONFIGS=(
    [fixture]='{
        "working_directory": ".",
        "commands": {"analyze": "input:i:p output:o:p"}
    }'
)
SAMPLE_PACKAGES=("fixture-package" "other-package")
'''
assert parse_arrays(source) == {'SAMPLE_PACKAGES': ['fixture-package', 'other-package']}
print('Indexed tool arrays retained; associative metadata excluded')
PY
    assert_success
    assert_output 'Indexed tool arrays retained; associative metadata excluded'
}

@test "skill frontmatter reader keeps multi-line and quoted values whole" {
    run python3 - "$PROJECT_ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + '/scripts')
from _skill_frontmatter import frontmatter
text = """---
name: sample
description: First line
  continues here: with a colon
quoted: 'It''s
  two lines

  '
---
body
"""
fm = frontmatter(text)
assert fm["description"] == "First line continues here: with a colon", fm
assert fm["quoted"] == "It's two lines", fm
assert set(fm) == {"name", "description", "quoted"}, fm
print("ok")
PY
    assert_success
    assert_output "ok"
}

@test "source module removal clears all mapped executables" {
    _lifecycle_fixture
    _source_fixture_module "$LC_REPO"
    mkdir -p "$TEST_TMPDIR/tools/fixture-tool/build"
    local binary
    for binary in fixture-tool fixture-companion; do
        printf '#!/bin/sh\nexit 0\n' > "$TEST_TMPDIR/tools/fixture-tool/build/$binary"
        chmod +x "$TEST_TMPDIR/tools/fixture-tool/build/$binary"
        ln -s "$TEST_TMPDIR/tools/fixture-tool/build/$binary" "$TEST_TMPDIR/prefix/bin/$binary"
    done
    printf 'fixture-tool|source|synthetic|2026-10-13\n' >> "$LC_REPO/.versions"
    _run_lifecycle remove.sh --module reversing --yes
    assert_success
    [[ ! -L "$TEST_TMPDIR/prefix/bin/fixture-tool" && ! -L "$TEST_TMPDIR/prefix/bin/fixture-companion" ]]
    [[ ! -d "$TEST_TMPDIR/tools/fixture-tool" ]]
}

@test "installed-only verification recognizes OpenSCAP distro package records" {
    _lifecycle_fixture
    printf '#!/bin/sh\nexit 0\n' > "$LC_STUBS/oscap"
    chmod +x "$LC_STUBS/oscap"
    local package
    for package in openscap-scanner openscap openscap-utils; do
        printf '%s|apt|synthetic|2026-10-13\n' "$package" > "$LC_REPO/.versions"
        _run_verify_linux --module blueteam --installed-only --summary
        assert_success
        assert_output --partial 'Total checked: 1'
        assert_output --partial 'Found:   1'
    done
}

@test "forensics verification detects a missing tracked mat2 command" {
    _lifecycle_fixture
    cat >> "$LC_REPO/lib/common.sh" <<'EOF'
command_exists() {
    if [[ "$1" == mat2 ]]; then
        [[ -x "$CYBERSEC_FIXTURE_BIN/mat2" ]]
    else
        command -v "$1" &>/dev/null
    fi
}
EOF
    printf 'mat2|apt|synthetic|2026-10-13\n' > "$LC_REPO/.versions"
    _run_verify_linux --module forensics --installed-only --summary
    assert_failure
    assert_output --partial 'Total checked: 1'
    assert_output --partial 'Missing: 1'

    printf '#!/bin/sh\nexit 0\n' > "$LC_STUBS/mat2"
    chmod +x "$LC_STUBS/mat2"
    _run_verify_linux --module forensics --installed-only --summary
    assert_success
    assert_output --partial 'Found:   1'
}

@test "verification skips new tools unavailable on native Termux" {
    _lifecycle_fixture
    printf '%s\n' 'mat2|apt|synthetic|2026-10-13' \
        'openscap-scanner|apt|synthetic|2026-10-13' 'pycdc|source|synthetic|2026-10-13' \
        'kernel-hardening-checker|source|synthetic|2026-10-13' 'takajo|binary|synthetic|2026-10-13' \
        'vmkatz|binary|synthetic|2026-10-13' 'TeamFiltration|binary|synthetic|2026-10-13' \
        > "$LC_REPO/.versions"
    _run_lifecycle verify.sh --module blueteam --module forensics --module reversing \
        --module enterprise --installed-only --summary
    assert_success
    assert_output --partial 'Total checked: 0'
    assert_output --partial 'Missing: 0'
}

_metasploit_removal_fixture() {
    _lifecycle_fixture
    MSF_SOURCE="$TEST_TMPDIR/metasploit-framework.list"
    MSF_KEY="$TEST_TMPDIR/metasploit-framework.gpg"
    printf 'deb [signed-by=%s] https://apt.metasploit.com/ xenial main\n' "$MSF_KEY" > "$MSF_SOURCE"
    printf 'synthetic-key\n' > "$MSF_KEY"
    printf 'metasploit|pkg|latest|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"
    python3 - "$LC_REPO/scripts/remove.sh" "$MSF_SOURCE" "$MSF_KEY" <<'PY'
from pathlib import Path
import shlex
import sys

script, source, key = sys.argv[1:]
path = Path(script)
text = path.read_text()
text = text.replace('_msf_list=/etc/apt/sources.list.d/metasploit-framework.list', '_msf_list=' + shlex.quote(source))
text = text.replace('_msf_key=/usr/share/keyrings/metasploit-framework.gpg', '_msf_key=' + shlex.quote(key))
path.write_text(text)
PY
    printf '#!/bin/sh\nif [ "$2" = metasploit-framework ] && [ ! -e "%s/metasploit-removed" ]; then\n echo "ii  metasploit-framework 1.0 all fixture"\n exit 0\nfi\nexit 1\n' \
        "$TEST_TMPDIR" > "$LC_STUBS/dpkg"
    printf '#!/bin/sh\nexit 0\n' > "$LC_STUBS/msfconsole"
    chmod +x "$LC_STUBS/msfconsole"
}

@test "failed Metasploit removal keeps its apt source, key and install record" {
    _metasploit_removal_fixture

    _run_lifecycle remove.sh --yes

    assert_failure
    assert_output --partial "Failed to remove Metasploit"
    refute_output --partial "Metasploit removed"
    [[ -f "$MSF_SOURCE" && -f "$MSF_KEY" ]]
    run grep -F 'metasploit|pkg|latest|' "$LC_REPO/.versions"
    assert_success
}

@test "successful Metasploit removal cleans up its matching apt source and key" {
    _metasploit_removal_fixture
    printf '#!/bin/sh\nif [ "$1" = uninstall ]; then : > "%s/metasploit-removed"; fi\nexit 0\n' \
        "$TEST_TMPDIR" > "$LC_STUBS/pkg"

    _run_lifecycle remove.sh --yes

    assert_success
    assert_output --partial "Removed the apt.metasploit.com source and key"
    [[ ! -e "$MSF_SOURCE" && ! -e "$MSF_KEY" && ! -e "$LC_REPO/.versions" ]]
}

@test "Metasploit cleanup preserves source files holding other repositories" {
    _metasploit_removal_fixture
    printf 'deb https://packages.example.invalid/ stable main\n' >> "$MSF_SOURCE"
    printf '#!/bin/sh\nif [ "$1" = uninstall ]; then : > "%s/metasploit-removed"; fi\nexit 0\n' \
        "$TEST_TMPDIR" > "$LC_STUBS/pkg"

    _run_lifecycle remove.sh --yes

    assert_success
    [[ -f "$MSF_SOURCE" && -f "$MSF_KEY" ]]
    run grep -F 'packages.example.invalid' "$MSF_SOURCE"
    assert_success
}

@test "Metasploit repository cleanup failures preserve the record for a retry" {
    _metasploit_removal_fixture
    printf '#!/bin/sh\nif [ "$1" = uninstall ]; then : > "%s/metasploit-removed"; fi\nexit 0\n' \
        "$TEST_TMPDIR" > "$LC_STUBS/pkg"
    printf '#!/bin/sh\nfor arg do\n [ "$arg" = "%s" ] && exit 1\ndone\nexec "%s" "$@"\n' \
        "$MSF_SOURCE" "$(command -v rm)" > "$LC_STUBS/rm"
    chmod +x "$LC_STUBS/rm"

    _run_lifecycle remove.sh --yes

    assert_failure
    assert_output --partial "Failed to remove the apt.metasploit.com source and key"
    [[ -f "$MSF_SOURCE" && -f "$MSF_KEY" && -f "$LC_REPO/.versions" ]]
    rm -f "$LC_STUBS/rm" "$LC_STUBS/msfconsole"

    _run_lifecycle remove.sh --yes

    assert_success
    [[ ! -e "$MSF_SOURCE" && ! -e "$MSF_KEY" && ! -e "$LC_REPO/.versions" ]]
}

_backup_schedule_fixture() {
    _lifecycle_fixture
    SC_ENV="$TEST_TMPDIR/cybersec-backup.env"
    SC_CRON="$TEST_TMPDIR/crontab"
    # Root ownership and the credential destination are simulated; crontab writes stay in the fixture.
    python3 - "$LC_REPO/scripts/backup.sh" "$SC_ENV" <<'PY'
from pathlib import Path
import shlex
import sys

script, env_file = sys.argv[1:]
path = Path(script)
text = path.read_text()
text = text.replace('if [[ $EUID -ne 0 ]]; then', 'if false; then')
text = text.replace('local env_file="/etc/cybersec-backup.env"', 'local env_file=' + shlex.quote(env_file))
path.write_text(text)
PY
    printf '#!/bin/sh\nif [ "$1" = -c ] && [ "$2" = "%%u" ]; then echo 0; else exec "%s" "$@"; fi\n' \
        "$(command -v stat)" > "$LC_STUBS/stat"
    printf '#!/bin/sh\nif [ "$#" -eq 5 ] && [ "$2" = -maxdepth ] && [ "$3" = 0 ] && [ "$4" = -perm ]; then exit 0; fi\nexec "%s" "$@"\n' \
        "$(command -v find)" > "$LC_STUBS/find"
    printf '#!/bin/sh\ncase "$1" in\n -l) cat "%s" ;;\n -) cat > "%s" ;;\n *) exit 1 ;;\nesac\n' \
        "$SC_CRON" "$SC_CRON" > "$LC_STUBS/crontab"
    chmod +x "$LC_STUBS/stat" "$LC_STUBS/find" "$LC_STUBS/crontab"
}

_run_backup_schedule() {
    local checkout="$1"; shift
    run env -i HOME="$TEST_TMPDIR/home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        GITHUB_TOOL_DIR="$TEST_TMPDIR/tools" TMPDIR="$TEST_TMPDIR" TERM=dumb \
        BACKUP_PASSPHRASE="synthetic-backup-passphrase" \
        PATH="$LC_STUBS:$TEST_TMPDIR/prefix/bin:$PATH" \
        bash "$checkout/scripts/backup.sh" "$@"
}

@test "backup schedule persists its physical checkout and replaces schedules through aliases" {
    _backup_schedule_fixture
    ln -s "$LC_REPO" "$TEST_TMPDIR/first-alias"
    ln -s "$LC_REPO" "$TEST_TMPDIR/second-alias"

    _run_backup_schedule "$TEST_TMPDIR/first-alias" schedule daily 09:08

    assert_success
    [[ -f "$SC_ENV" && "$(_file_mode "$SC_ENV")" == 600 ]]
    run grep -F "$LC_REPO/scripts/backup.sh" "$SC_CRON"
    assert_success
    refute_output --partial "first-alias"

    _run_backup_schedule "$TEST_TMPDIR/second-alias" schedule daily 10:09

    assert_success
    [[ "$(grep -cF "$LC_REPO/scripts/backup.sh" "$SC_CRON")" == 1 ]]
    run cat "$SC_CRON"
    assert_output --partial "9 10 * * *"
    refute_output --partial "second-alias"

    _run_backup_schedule "$TEST_TMPDIR/first-alias" unschedule

    assert_success
    [[ -z "$(cat "$SC_CRON")" && ! -e "$SC_ENV" ]]
}

@test "backup schedule rejects linked dependencies before storing a passphrase or cron entry" {
    _backup_schedule_fixture
    mv "$LC_REPO/lib/common.sh" "$TEST_TMPDIR/common-target.sh"
    ln -s "$TEST_TMPDIR/common-target.sh" "$LC_REPO/lib/common.sh"

    _run_backup_schedule "$LC_REPO" schedule daily 09:08

    assert_failure
    assert_output --partial "Refusing to schedule"
    [[ ! -e "$SC_ENV" && ! -e "$SC_CRON" ]]
}

@test "backup schedule replaces a legacy alias entry and preserves unrelated cron jobs" {
    _backup_schedule_fixture
    printf '15 3 * * * /usr/bin/true\n' > "$SC_CRON"
    printf "0 1 * * * . '%s' && export BACKUP_PASSPHRASE && '%s/scripts/backup.sh' backup\n" \
        "$SC_ENV" "$TEST_TMPDIR/legacy-alias" >> "$SC_CRON"

    _run_backup_schedule "$LC_REPO" schedule daily 09:08

    assert_success
    [[ "$(wc -l < "$SC_CRON")" -eq 2 ]]
    run cat "$SC_CRON"
    assert_output --partial "/usr/bin/true"
    assert_output --partial "$LC_REPO/scripts/backup.sh"
    refute_output --partial "legacy-alias"
}

@test "backup unschedule removes legacy alias entries and preserves unrelated cron jobs" {
    _backup_schedule_fixture
    printf 'synthetic-env-fixture\n' > "$SC_ENV"
    printf '15 3 * * * /usr/bin/true\n' > "$SC_CRON"
    printf "0 1 * * * . '%s' && export BACKUP_PASSPHRASE && '%s/scripts/backup.sh' backup\n" \
        "$SC_ENV" "$TEST_TMPDIR/legacy-alias" >> "$SC_CRON"

    _run_backup_schedule "$LC_REPO" unschedule

    assert_success
    [[ ! -e "$SC_ENV" ]]
    run cat "$SC_CRON"
    assert_output "15 3 * * * /usr/bin/true"
}

@test "remove leaves tools this toolkit did not install" {
    _lifecycle_fixture
    printf '#!/bin/sh\ncase "$2" in dnsenum|tor) echo "ii  $2 1.0 all fixture"; exit 0 ;; esac\nexit 1\n' \
        > "$LC_STUBS/dpkg"
    printf '#!/bin/sh\necho "pkg $*" >> "%s/calls.log"\n' "$TEST_TMPDIR" > "$LC_STUBS/pkg"
    printf 'dnsenum|pkg|system|2026-01-01 00:00:00\njadx|binary|existing|2026-01-01 00:00:00\n' \
        >> "$LC_REPO/.versions"
    mkdir -p "$TEST_TMPDIR/tools/Mythic" "$TEST_TMPDIR/tools/jadx/bin"
    printf 'fixture\n' > "$TEST_TMPDIR/tools/Mythic/operation.db"

    _run_lifecycle remove.sh --yes

    assert_success
    [[ -f "$TEST_TMPDIR/tools/Mythic/operation.db" ]]
    [[ -d "$TEST_TMPDIR/tools/jadx/bin" ]]
    run grep -F "uninstall" "$TEST_TMPDIR/calls.log"
    assert_output "pkg uninstall -y dnsenum"
}

@test "remove keeps system packages when the install record predates provenance tracking" {
    _lifecycle_fixture
    printf '#!/bin/sh\ncase "$2" in dnsenum) echo "ii  $2 1.0 all fixture"; exit 0 ;; esac\nexit 1\n' \
        > "$LC_STUBS/dpkg"
    printf '#!/bin/sh\necho "pkg $*" >> "%s/calls.log"\n' "$TEST_TMPDIR" > "$LC_STUBS/pkg"
    printf '# tool|method|version|last_updated\ndnsenum|pkg|system|2026-01-01 00:00:00\n' > "$LC_REPO/.versions"

    _run_lifecycle remove.sh --yes

    assert_success
    assert_output --partial "Keeping all system packages"
    run grep -F "uninstall" "$TEST_TMPDIR/calls.log"
    assert_failure

    # The same record is trusted when every install session on file was written under schema 2.
    printf '# tool|method|version|last_updated\ndnsenum|pkg|system|2026-01-01 00:00:00\n' > "$LC_REPO/.versions"
    mkdir -p "$LC_REPO/.install_sessions"
    printf '# Session: fixture\n# Schema: 2\n' > "$LC_REPO/.install_sessions/20260101_000000_1.manifest"
    _run_lifecycle remove.sh --yes

    assert_success
    refute_output --partial "Keeping all system packages"
    run grep -F "uninstall" "$TEST_TMPDIR/calls.log"
    assert_output "pkg uninstall -y dnsenum"
}

@test "remove --module drops the rows of what it removed" {
    _lifecycle_fixture
    printf 'jwt_tool|git|HEAD|2026-01-01 00:00:00\nnmap|pkg|system|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"
    mkdir -p "$TEST_TMPDIR/tools/jwt_tool"

    _run_lifecycle remove.sh --module web --yes

    assert_success
    [[ ! -e "$TEST_TMPDIR/tools/jwt_tool" ]]
    ! grep -q '^jwt_tool|' "$LC_REPO/.versions" || false
    grep -q '^nmap|' "$LC_REPO/.versions"
}

@test "partial removal preserves version records and reports a failed row rewrite" {
    _lifecycle_fixture
    printf 'jwt_tool|git|HEAD|2026-01-01 00:00:00\nnmap|pkg|system|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"
    cp "$LC_REPO/.versions" "$TEST_TMPDIR/original-versions"
    mkdir -p "$TEST_TMPDIR/tools/jwt_tool"
    local real_awk
    real_awk=$(command -v awk)
    cat > "$LC_STUBS/awk" <<EOF
#!/bin/bash
if [[ "\$*" == *'gone['* ]]; then
    printf 'incomplete rewrite\n'
    exit 1
fi
exec '$real_awk' "\$@"
EOF
    chmod +x "$LC_STUBS/awk"

    _run_lifecycle remove.sh --module web --yes

    assert_failure
    assert_output --partial 'Failed to update install records'
    cmp "$LC_REPO/.versions" "$TEST_TMPDIR/original-versions"
    [[ ! -e "$TEST_TMPDIR/tools/jwt_tool" ]]
}

@test "Git removal cleans escaped launchers and preserves independent commands" {
    _lifecycle_fixture
    local tool_path="$TEST_TMPDIR/tools with spaces/enum4linux-ng"
    mkdir -p "$tool_path"
    printf 'enum4linux-ng|git|HEAD|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"
    source_libs --installers debian apt
    PIPX_BIN_DIR="$TEST_TMPDIR/prefix/bin"
    _write_git_launcher "$tool_path" enum4linux-ng python3 "$tool_path/enum4linux-ng.py"
    printf '#!/bin/sh\nprintf independent\\n\n' > "$PIPX_BIN_DIR/enum4linux_ng"

    run env -i HOME="$TEST_TMPDIR/home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        PKG_MANAGER=pkg DISTRO_ID=android DISTRO_ID_LIKE= DISTRO_NAME=Termux \
        GITHUB_TOOL_DIR="$TEST_TMPDIR/tools with spaces" TMPDIR="$TEST_TMPDIR" TERM=dumb \
        PATH="$LC_STUBS:$TEST_TMPDIR/prefix/bin:$PATH" \
        bash "$LC_REPO/scripts/remove.sh" --module enterprise --yes

    assert_success
    [[ ! -e "$tool_path" ]]
    [[ ! -e "$PIPX_BIN_DIR/enum4linux-ng" ]]
    [[ -f "$PIPX_BIN_DIR/enum4linux_ng" ]]
}

@test "remove keeps the install record when a special tool survives" {
    [[ "$(id -u)" -ne 0 ]] || skip "root ignores the read-only directory"
    _lifecycle_fixture
    mkdir -p "$TEST_TMPDIR/home/.foundry/bin"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/home/.foundry/bin/forge"
    chmod 555 "$TEST_TMPDIR/home/.foundry"
    printf 'foundry|special|latest|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"

    _run_lifecycle remove.sh --yes

    chmod 755 "$TEST_TMPDIR/home/.foundry"
    assert_failure
    assert_output --partial "Failed to remove Foundry"
    [[ -f "$LC_REPO/.versions" ]]
}

@test "remove drops a cloned repo's PATH wrapper and multi-field release dirs" {
    _lifecycle_fixture
    printf 'nikto|git|HEAD|2026-01-01 00:00:00\nmemprocfs|binary|v1|2026-01-01 00:00:00\n' \
        >> "$LC_REPO/.versions"
    mkdir -p "$TEST_TMPDIR/tools/nikto" "$TEST_TMPDIR/tools/MemProcFS"
    printf '#!/bin/bash\nexec perl "%s/tools/nikto/nikto.pl" "$@"\n' "$TEST_TMPDIR" \
        > "$TEST_TMPDIR/prefix/bin/nikto"
    printf '#!/bin/bash\nexec perl "/elsewhere/nikto.pl" "$@"\n' > "$TEST_TMPDIR/prefix/bin/unrelated"
    chmod +x "$TEST_TMPDIR/prefix/bin/nikto" "$TEST_TMPDIR/prefix/bin/unrelated"

    _run_lifecycle remove.sh --module web --module forensics --yes

    assert_success
    [[ ! -e "$TEST_TMPDIR/tools/nikto" && ! -e "$TEST_TMPDIR/prefix/bin/nikto" ]]
    [[ -e "$TEST_TMPDIR/prefix/bin/unrelated" ]]
    [[ ! -e "$TEST_TMPDIR/tools/MemProcFS" ]]
}

@test "verify --installed-only skips Foundry chisel when Foundry is untracked" {
    _lifecycle_fixture
    printf 'gf|go|latest|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/prefix/bin/gf"
    chmod +x "$TEST_TMPDIR/prefix/bin/gf"

    _run_lifecycle verify.sh --installed-only

    assert_success
    refute_output --partial "chisel (foundry)"
}

@test "verify --installed-only checks tracked packages whose command differs" {
    _lifecycle_fixture
    printf 'snmp|apt|system|2026-01-01 00:00:00\nnetcat-openbsd|apt|system|2026-01-01 00:00:00\n' \
        >> "$LC_REPO/.versions"

    _run_verify_linux --installed-only --module networking

    assert_output --partial "snmp —"
    assert_output --partial "netcat-openbsd —"
}

@test "update rebuilds pulled build trees and skips same-named user repos" {
    _lifecycle_fixture
    local up="$TEST_TMPDIR/upstream"
    local -a gitid=(-c user.email=fixture@example.invalid -c user.name=fixture)
    git init -q "$up"
    # AFLplusplus is rebuilt with its registry command (make source-only), never the default target.
    printf 'all:\n\tmkdir -p bin && cp version.txt bin/massdns && chmod +x bin/massdns\nsource-only:\n\tcp version.txt built.txt && cp version.txt afl-fuzz && chmod +x afl-fuzz\n' \
        > "$up/Makefile"
    printf 'v1\n' > "$up/version.txt"
    git -C "$up" add -A
    git -C "$up" "${gitid[@]}" commit -qm v1
    git clone -q "$up" "$TEST_TMPDIR/tools/massdns"
    make -s -C "$TEST_TMPDIR/tools/massdns" >/dev/null
    git clone -q "$up" "$TEST_TMPDIR/tools/AFLplusplus"
    git clone -q "$up" "$TEST_TMPDIR/tools/codext"
    printf 'mine\n' > "$TEST_TMPDIR/tools/codext/mine.txt"
    git -C "$TEST_TMPDIR/tools/codext" add mine.txt
    git -C "$TEST_TMPDIR/tools/codext" "${gitid[@]}" commit -qm local
    printf 'v2\n' > "$up/version.txt"
    git -C "$up" "${gitid[@]}" commit -qam v2
    printf '%s\n' 'massdns|source|HEAD|2026-01-01 00:00:00' \
        'AFLplusplus|source|HEAD|2026-01-01 00:00:00' \
        'codext|pipx|latest|2026-01-01 00:00:00' >> "$LC_REPO/.versions"

    _run_lifecycle update.sh --skip-system --skip-pipx --skip-go --skip-gems \
        --skip-cargo --skip-binary --skip-special --skip-docker

    assert_success
    [[ "$(cat "$TEST_TMPDIR/tools/massdns/bin/massdns")" == "v2" ]]
    [[ "$(cat "$TEST_TMPDIR/tools/AFLplusplus/built.txt")" == "v2" ]]
    [[ "$(git -C "$TEST_TMPDIR/tools/codext" log -1 --format=%s)" == "local" ]]
}

@test "Git update rebuilds a registered CLI and repairs its missing launcher" {
    _lifecycle_fixture
    local upstream="$TEST_TMPDIR/upstream"
    local -a identity=(-c user.email=fixture@example.invalid -c user.name=fixture)
    git init -q "$upstream"
    printf 'all:\n\tcp version.sh kwp && chmod +x kwp\n' > "$upstream/Makefile"
    printf '#!/bin/sh\nprintf "v1\\n"\n' > "$upstream/version.sh"
    git -C "$upstream" add -A
    git -C "$upstream" "${identity[@]}" commit -qm v1
    git clone -q "$upstream" "$TEST_TMPDIR/tools/kwprocessor"
    printf 'kwprocessor|git|HEAD|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"
    printf '#!/bin/sh\nprintf "v2\\n"\n' > "$upstream/version.sh"
    git -C "$upstream" "${identity[@]}" commit -qam v2

    _run_lifecycle update.sh --skip-system --skip-pipx --skip-go --skip-gems \
        --skip-cargo --skip-binary --skip-special --skip-docker
    assert_success
    run "$TEST_TMPDIR/prefix/bin/kwprocessor"
    assert_success
    assert_output v2
    rm "$TEST_TMPDIR/prefix/bin/kwprocessor"
    _run_lifecycle update.sh --skip-system --skip-pipx --skip-go --skip-gems \
        --skip-cargo --skip-binary --skip-special --skip-docker
    assert_success
    [[ -x "$TEST_TMPDIR/prefix/bin/kwprocessor" ]]
}

# _registry_clone NAME FILE — a clone of a synthetic upstream under a registry Git name,
# with one upstream commit the clone has not pulled yet.
_registry_clone() {
    local upstream="$TEST_TMPDIR/upstream-$1"
    local -a gitid=(-c user.email=fixture@example.invalid -c user.name=fixture)
    git init -q "$upstream"
    printf 'print("synthetic %s")\n' "$1" > "$upstream/$2"
    git -C "$upstream" add "$2"
    git -C "$upstream" "${gitid[@]}" commit -qm v1
    git clone -q "$upstream" "$TEST_TMPDIR/tools/$1"
    printf '# v2\n' >> "$upstream/$2"
    git -C "$upstream" "${gitid[@]}" commit -qam v2
}

@test "update keeps another method's row on a registry-named clone, so remove leaves the clone" {
    _lifecycle_fixture
    _registry_clone commix commix.py
    printf 'commix|pipx|latest|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"

    _run_lifecycle update.sh --skip-system --skip-pipx --skip-go --skip-gems \
        --skip-cargo --skip-binary --skip-special --skip-docker
    assert_success
    grep -q '^commix|pipx|latest|' "$LC_REPO/.versions"

    _run_lifecycle remove.sh --module web --yes
    assert_success
    [[ -d "$TEST_TMPDIR/tools/commix/.git" ]]
}

@test "update does not add a launcher for a registry-named clone the toolkit never recorded" {
    _lifecycle_fixture
    _registry_clone XSStrike XSStrike.py

    _run_lifecycle update.sh --skip-system --skip-pipx --skip-go --skip-gems \
        --skip-cargo --skip-binary --skip-special --skip-docker

    assert_success
    [[ "$(git -C "$TEST_TMPDIR/tools/XSStrike" log -1 --format=%s)" == "v2" ]]
    [[ ! -e "$TEST_TMPDIR/prefix/bin/xsstrike" ]]
}

@test "update rebuilds only Go tools the toolkit installed" {
    _lifecycle_fixture
    printf '#!/bin/sh\necho "go $*" >> "%s/calls.log"\n[ "$1" = version ] && echo "go version go1.23.0 linux/amd64"\nexit 0\n' \
        "$TEST_TMPDIR" > "$LC_STUBS/go"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/prefix/bin/ffuf"
    printf '#!/bin/sh\n' > "$TEST_TMPDIR/prefix/bin/gf"
    chmod +x "$TEST_TMPDIR/prefix/bin/ffuf" "$TEST_TMPDIR/prefix/bin/gf"
    printf 'gf|go|latest|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"

    _run_lifecycle update.sh --skip-system --skip-pipx --skip-git --skip-gems \
        --skip-cargo --skip-binary --skip-special --skip-docker

    run grep -F "go install" "$TEST_TMPDIR/calls.log"
    assert_output --partial "github.com/tomnomnom/gf@latest"
    refute_output --partial "ffuf"
}

@test "verify --installed-only matches tracked names literally, not as patterns" {
    _lifecycle_fixture
    printf 'dissectXtarget|pipx|latest|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"

    _run_lifecycle verify.sh --installed-only --module forensics

    refute_output --partial "dissect.target"
}

@test "verify reads the version record named by VERSION_FILE" {
    _lifecycle_fixture
    printf 'gf|go|latest|2026-01-01 00:00:00\n' > "$TEST_TMPDIR/relocated.versions"

    run env -i HOME="$TEST_TMPDIR/home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        PKG_MANAGER=pkg DISTRO_ID=android DISTRO_ID_LIKE= DISTRO_NAME=Termux \
        GITHUB_TOOL_DIR="$TEST_TMPDIR/tools" TMPDIR="$TEST_TMPDIR" TERM=dumb \
        VERSION_FILE="$TEST_TMPDIR/relocated.versions" \
        PATH="$LC_STUBS:$TEST_TMPDIR/prefix/bin:$PATH" \
        bash "$LC_REPO/scripts/verify.sh" --installed-only

    assert_output --partial "Filtering by $TEST_TMPDIR/relocated.versions (1 tracked tools)"
}

@test "deep clean reports a cache it could not remove and exits non-zero" {
    [[ $EUID -ne 0 ]] || skip "root removes read-only trees"
    _lifecycle_fixture
    local cache="$TEST_TMPDIR/home/.cache"
    mkdir -p "$cache/pip"
    chmod 555 "$cache"

    _run_lifecycle remove.sh --deep-clean --yes
    chmod 755 "$cache"

    assert_failure
    assert_output --partial "Failed to remove $cache/pip"
    refute_output --partial "Removed pip cache"
}

@test "update --skip-git leaves build-from-source trees alone" {
    _source_outputs_fixture
    _source_update_fixture
    _source_tracked_clone
    local upstream="$TEST_TMPDIR/upstream"
    local -a git_identity=(-c user.email=fixture@example.invalid -c user.name=fixture)
    printf 'v2\n' > "$upstream/version.txt"
    git -C "$upstream" "${git_identity[@]}" commit -qam v2

    _source_run_lifecycle update.sh --skip-git --skip-system --skip-pipx --skip-go \
        --skip-gems --skip-cargo --skip-binary --skip-special --skip-docker

    assert_success
    assert_output --partial "Skipping build-from-source update"
    [[ "$(< "$GITHUB_TOOL_DIR/fixture-tool/version.txt")" == "v1" ]]
}

# A pipx that lists the given "name version" lines and logs every other call.
_lifecycle_pipx_stub() {
    {
        printf '#!/bin/sh\n'
        printf 'if [ "$1" = list ]; then\n'
        printf '    printf "%%s\\n" %s\n' "$(printf "'%s' " "$@")"
        printf '    exit 0\nfi\n'
        printf 'echo "pipx $*" >> "%s/calls.log"\n' "$TEST_TMPDIR"
        printf 'echo "upgraded package $2 from 1.0 to 2.0"\n'
    } > "$LC_STUBS/pipx"
}

@test "update upgrades only the pipx tools this toolkit installed" {
    _lifecycle_fixture
    _lifecycle_pipx_stub "codext 1.0" "dissect-target 3.0" "sqlmap 1.8" "users-own-tool 2.0"
    printf '%s\n' 'codext|pipx|latest|2026-01-01 00:00:00' \
        'dissect.target|pipx|latest|2026-01-01 00:00:00' \
        'sqlmap|pipx|existing|2026-01-01 00:00:00' >> "$LC_REPO/.versions"

    _run_lifecycle update.sh --skip-system --skip-go --skip-git --skip-gems \
        --skip-cargo --skip-binary --skip-special --skip-docker

    assert_output --partial "pipx packages: 2 updated"
    run grep -F "pipx " "$TEST_TMPDIR/calls.log"
    assert_line "pipx upgrade codext"
    assert_line "pipx upgrade dissect.target"
    refute_output --partial "upgrade-all"
    refute_output --partial "sqlmap"
    refute_output --partial "users-own-tool"
}

@test "deep clean keeps pipx venvs and dangling links that are not the toolkit's" {
    _lifecycle_fixture
    local phys; phys="$(cd "$TEST_TMPDIR" && pwd -P)"
    local pipx_home="$phys/home/.local/pipx" bin="$phys/prefix/bin"
    # codext's uninstall left its venv behind; the other venv was never the toolkit's.
    _lifecycle_pipx_stub
    printf 'codext|pipx|latest|2026-01-01 00:00:00\n' >> "$LC_REPO/.versions"
    mkdir -p "$pipx_home/venvs/codext" "$pipx_home/venvs/users-own-tool" "$pipx_home/shared"
    ln -s "$pipx_home/venvs/codext/bin/codext" "$bin/codext"
    ln -s "$TEST_TMPDIR/unmounted-volume/tool" "$bin/users-own-link"

    _run_lifecycle remove.sh --deep-clean --yes

    assert_success
    assert_output --partial "Keeping 1 pipx venvs this toolkit did not install"
    [[ ! -e "$pipx_home/venvs/codext" ]]
    [[ -d "$pipx_home/venvs/users-own-tool" && -d "$pipx_home/shared" ]]
    [[ ! -L "$bin/codext" ]]
    [[ -L "$bin/users-own-link" ]]
}

@test "mcp-launch.sh --local runs uv on the host, not the sandbox" {
    run env CYBERSEC_SANDBOX_MODE= bash -c '
        PATH="'"$TEST_TMPDIR"'/bin:$PATH"
        mkdir -p "'"$TEST_TMPDIR"'/bin"
        cat > "'"$TEST_TMPDIR"'/bin/uv" <<EOF
#!/usr/bin/env bash
echo "UV_RAN: \$*"
EOF
        chmod +x "'"$TEST_TMPDIR"'/bin/uv"
        exec bash "'"$PROJECT_ROOT"'/scripts/mcp-launch.sh" --local
    '
    assert_success
    assert_output --partial "UV_RAN:"
    assert_output --partial "server.py"
}

@test "mcp-launch.sh forwards separate host-control opt-ins and defaults both off" {
    mkdir -p "$TEST_TMPDIR/bin"
    cat > "$TEST_TMPDIR/bin/uv" <<'EOF'
#!/usr/bin/env bash
printf 'HOST_CONTROL:%s:%s\n' "$CYBERSEC_MCP_ALLOW_USBKILL" "$CYBERSEC_MCP_ALLOW_NIPE"
EOF
    chmod +x "$TEST_TMPDIR/bin/uv"
    run env -u CYBERSEC_MCP_ALLOW_USBKILL -u CYBERSEC_MCP_ALLOW_NIPE \
        PATH="$TEST_TMPDIR/bin:$PATH" bash "$PROJECT_ROOT/scripts/mcp-launch.sh" --local
    assert_success
    assert_output --partial 'HOST_CONTROL:0:0'
    run env CYBERSEC_MCP_ALLOW_USBKILL=1 CYBERSEC_MCP_ALLOW_NIPE=1 \
        PATH="$TEST_TMPDIR/bin:$PATH" bash "$PROJECT_ROOT/scripts/mcp-launch.sh" --local
    assert_success
    assert_output --partial 'HOST_CONTROL:1:1'
}

@test "mcp-launch.sh rejects an unknown mode" {
    run bash "$PROJECT_ROOT/scripts/mcp-launch.sh" --bogus
    assert_failure
    assert_output --partial "Usage"
}

@test "mcp-launch.sh kata mode fails closed without node" {
    mkdir -p "$TEST_TMPDIR/nonode"
    for _c in bash sed grep cat dirname; do
        _p="$(command -v "$_c")" && ln -sf "$_p" "$TEST_TMPDIR/nonode/$_c"
    done
    # Report Linux so the missing-Node check is reached on any host OS.
    printf '#!/usr/bin/env bash\necho Linux\n' > "$TEST_TMPDIR/nonode/uname"
    # A uv shim that would prove a wrong fall-through to host execution.
    printf '#!/usr/bin/env bash\necho UV_RAN: "$*"\n' > "$TEST_TMPDIR/nonode/uv"
    chmod +x "$TEST_TMPDIR/nonode/uname" "$TEST_TMPDIR/nonode/uv"

    run env -i CYBERSEC_SANDBOX_MODE=kata PATH="$TEST_TMPDIR/nonode" \
        bash "$PROJECT_ROOT/scripts/mcp-launch.sh"
    assert_failure
    assert_output --partial "Node.js"
    # Never falls through to host execution when the sandbox cannot start.
    refute_output --partial "UV_RAN:"
}

@test "mcp-launch.sh kata mode refuses a non-Linux host and points at --local" {
    mkdir -p "$TEST_TMPDIR/darwin"
    for _c in bash sed grep cat dirname; do
        _p="$(command -v "$_c")" && ln -sf "$_p" "$TEST_TMPDIR/darwin/$_c"
    done
    printf '#!/usr/bin/env bash\necho Darwin\n' > "$TEST_TMPDIR/darwin/uname"
    # node present and a uv shim: the OS check must fail closed before either runs.
    printf '#!/usr/bin/env bash\necho v22.0.0\n' > "$TEST_TMPDIR/darwin/node"
    printf '#!/usr/bin/env bash\necho UV_RAN: "$*"\n' > "$TEST_TMPDIR/darwin/uv"
    chmod +x "$TEST_TMPDIR/darwin/uname" "$TEST_TMPDIR/darwin/node" "$TEST_TMPDIR/darwin/uv"

    run env -i CYBERSEC_SANDBOX_MODE=kata PATH="$TEST_TMPDIR/darwin" \
        bash "$PROJECT_ROOT/scripts/mcp-launch.sh"
    assert_failure
    assert_output --partial "Linux host with KVM"
    assert_output --partial "--local"
    refute_output --partial "UV_RAN:"
}

@test "remove refuses to run non-interactively without --yes" {
    _lifecycle_fixture
    # Without a terminal, cancelling must exit non-zero so CI and cron cannot read it as success.
    run env -i HOME="$TEST_TMPDIR/home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        PKG_MANAGER=pkg DISTRO_ID=android DISTRO_ID_LIKE= DISTRO_NAME=Termux \
        GITHUB_TOOL_DIR="$TEST_TMPDIR/tools" TMPDIR="$TEST_TMPDIR" TERM=dumb \
        PATH="$LC_STUBS:$TEST_TMPDIR/prefix/bin:$PATH" \
        bash "$LC_REPO/scripts/remove.sh" < /dev/null
    assert_failure
    assert_output --partial "Re-run with --yes"
}

@test "remove accepts -y as --yes" {
    _lifecycle_fixture
    _run_lifecycle remove.sh -y
    assert_success
}

@test "remove refuses --deep-clean combined with --module" {
    _lifecycle_fixture
    _run_lifecycle remove.sh --module web --deep-clean --yes
    assert_failure
    assert_output --partial "cannot be combined with --module"
}

@test "verify does not report untracked opt-in Docker images missing" {
    _lifecycle_fixture
    # A docker stub with no images: the opt-in images were never pulled.
    printf '#!/bin/sh\nexit 0\n' > "$LC_STUBS/docker"
    chmod +x "$LC_STUBS/docker"

    _run_lifecycle verify.sh --module blueteam

    refute_output --partial "Docker image NOT found"
}

@test "verify fails loudly on an unreadable .versions" {
    [[ $EUID -ne 0 ]] || skip "root reads any file"
    _lifecycle_fixture
    chmod 000 "$LC_REPO/.versions"

    _run_lifecycle verify.sh --installed-only

    assert_failure
    assert_output --partial "Cannot read"
    chmod 644 "$LC_REPO/.versions"
}

@test "restore runs unattended with BACKUP_PASSPHRASE" {
    local test_home="$TEST_TMPDIR/home"
    mkdir -p "$test_home/.nmap"
    printf 'setting\n' > "$test_home/.nmap/settings"
    run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" backup
    assert_success

    local -a encrypted=("$test_home"/cybersec_tools_backup/backup_*.tar.gz.enc)
    rm -rf "$test_home/.nmap"
    # No terminal: the passphrase must come from the environment.
    run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "${encrypted[0]}" < /dev/null
    assert_success
    [[ -f "$test_home/.nmap/settings" ]]
}

@test "backup with BACKUP_KEEP prunes the oldest archives" {
    local test_home="$TEST_TMPDIR/home" store="$TEST_TMPDIR/home/cybersec_tools_backup"
    mkdir -p "$test_home/.nmap" "$store"
    chmod 700 "$store"
    printf 'setting\n' > "$test_home/.nmap/settings"
    touch "$store/backup_20200101_000000.tar.gz.enc" "$store/backup_20200101_000000.tar.gz.enc.hmac" \
        "$store/backup_20200102_000000.tar.gz.enc"

    run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" BACKUP_KEEP=2 \
        bash "$PROJECT_ROOT/scripts/backup.sh" backup

    assert_success
    [[ ! -e "$store/backup_20200101_000000.tar.gz.enc" && ! -e "$store/backup_20200101_000000.tar.gz.enc.hmac" ]]
    [[ -e "$store/backup_20200102_000000.tar.gz.enc" ]]
    [[ "$(find "$store" -name 'backup_*.tar.gz.enc' | wc -l)" -eq 2 ]]
}

@test "restore keeps user files named *.enc in a current-format backup" {
    local test_home="$TEST_TMPDIR/home"
    mkdir -p "$test_home/.msf4/loot"
    printf 'loot\n' > "$test_home/.msf4/loot/capture.enc"
    run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" backup
    assert_success

    local -a encrypted=("$test_home"/cybersec_tools_backup/backup_*.tar.gz.enc)
    rm -rf "$test_home/.msf4"
    run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "${encrypted[0]}" < /dev/null
    assert_success
    [[ "$(cat "$test_home/.msf4/loot/capture.enc")" == "loot" ]]
}

@test "a second install/update/remove run refuses while one holds the lock" {
    command -v flock >/dev/null || skip "needs flock"
    _lifecycle_fixture
    # Hold the run lock as a concurrent run would.
    flock "$LC_REPO/.versions.run.lock" sleep 30 &
    local holder=$!
    local i
    for i in $(seq 1 30); do
        flock -n "$LC_REPO/.versions.run.lock" true 2>/dev/null || break
        sleep 0.1
    done

    _run_lifecycle remove.sh --yes

    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
    assert_failure
    assert_output --partial "Another install, update or remove run is active"
}

@test "an install refused by the run lock keeps the active run's log" {
    command -v flock >/dev/null || skip "needs flock"
    _lifecycle_fixture
    cp "$PROJECT_ROOT/install.sh" "$PROJECT_ROOT/VERSION" "$LC_REPO/"
    cp -R "$PROJECT_ROOT/profiles" "$LC_REPO/"
    printf 'line1\nline2\nline3\n' > "$LC_REPO/cybersec_install.log"
    flock "$LC_REPO/.versions.run.lock" sleep 30 &
    local holder=$!
    local i
    for i in $(seq 1 30); do
        flock -n "$LC_REPO/.versions.run.lock" true 2>/dev/null || break
        sleep 0.1
    done

    run env -i HOME="$TEST_TMPDIR/home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        PKG_MANAGER=pkg DISTRO_ID=android DISTRO_ID_LIKE= DISTRO_NAME=Termux TERM=dumb \
        TMPDIR="$TEST_TMPDIR" PATH="$LC_STUBS:$PATH" bash "$LC_REPO/install.sh" --tool nmap

    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
    assert_failure
    assert_output --partial "Another install, update or remove run is active"
    [[ "$(wc -l < "$LC_REPO/cybersec_install.log")" -eq 3 ]]
}

@test "restore decrypts a legacy per-file archive into place" {
    local test_home="$TEST_TMPDIR/home"
    local src="$TEST_TMPDIR/archive-src/backup_fixture"
    local archive="$TEST_TMPDIR/legacy.tar.gz"
    mkdir -p "$test_home" "$src/encrypted/network/.nmap"
    printf 'test-only-passphrase' > "$TEST_TMPDIR/pass"
    printf 'setting\n' | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 \
        -out "$src/encrypted/network/.nmap/nmap.conf.enc" -pass file:"$TEST_TMPDIR/pass"
    tar -czf "$archive" -C "$TEST_TMPDIR/archive-src" backup_fixture

    run env -u SUDO_USER HOME="$test_home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        BACKUP_ALLOW_UNVERIFIED=1 BACKUP_PASSPHRASE="test-only-passphrase" \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "$archive" < /dev/null

    assert_success
    [[ "$(cat "$test_home/.nmap/nmap.conf")" == "setting" ]]
}

@test "restore refuses an unauthenticated legacy archive by default" {
    local test_home="$TEST_TMPDIR/home"
    local archive_src="$TEST_TMPDIR/archive-src"
    local archive="$TEST_TMPDIR/restore.tar.gz"
    mkdir -p "$test_home" "$archive_src/backup_fixture/network/.nmap"
    printf 'setting\n' > "$archive_src/backup_fixture/network/.nmap/settings"
    tar -czf "$archive" -C "$archive_src" backup_fixture

    run env -u SUDO_USER -u BACKUP_ALLOW_UNVERIFIED \
        HOME="$test_home" \
        PREFIX="$TEST_TMPDIR/prefix" \
        TERMUX_VERSION=1 \
        bash "$PROJECT_ROOT/scripts/backup.sh" restore "$archive"

    assert_failure
    assert_output --partial "BACKUP_ALLOW_UNVERIFIED=1"
    [[ ! -e "$test_home/.nmap/settings" ]]
}

@test "remove --remove-deps keeps a uv the user installed and uv's data" {
    _lifecycle_fixture
    local home="$TEST_TMPDIR/home"
    mkdir -p "$home/.local/bin" "$home/.local/share/uv/python"
    printf '#!/bin/sh\n' > "$home/.local/bin/uv"
    chmod +x "$home/.local/bin/uv"

    # No provenance marker: this uv is the user's own.
    _run_lifecycle remove.sh --module recon --remove-deps --yes
    [[ -x "$home/.local/bin/uv" ]]

    # A uv this toolkit installed: binaries go, the user's uv data stays.
    mkdir -p "$home/.local/state/cybersec-toolkit"
    : > "$home/.local/state/cybersec-toolkit/uv-installed"
    _run_lifecycle remove.sh --module recon --remove-deps --yes
    [[ ! -e "$home/.local/bin/uv" ]]
    [[ -d "$home/.local/share/uv/python" ]]
}

@test "agent guard keeps a separate clearance window per session" {
    _guard_fixture
    local dir="$XDG_STATE_HOME/cybersec-tools-mcp"
    # Session A started, then an advisor call, then session B started.
    printf '2026-07-28T10:00:00.000Z\n' > "$dir/guard-session.sessA"
    printf '%s\n' '{"ts":"2026-07-28T10:00:05.000Z","event":"tool_call","tool":"guided_assessment"}' \
        > "$CYBERSEC_MCP_AUDIT_LOG"
    printf '2026-07-28T10:00:09.000Z\n' > "$dir/guard-session.sessB"
    # The shared marker was reset by B's start; A must still be cleared.
    printf '2026-07-28T10:00:09.000Z\n' > "$dir/guard-session"

    run env -u CYBERSEC_AGENT_GUARD XDG_STATE_HOME="$XDG_STATE_HOME" CYBERSEC_MCP_AUDIT_LOG="$CYBERSEC_MCP_AUDIT_LOG" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" pre-bash \
        <<< '{"session_id":"sessA","tool_input":{"command":"nmap 192.0.2.10"}}'
    assert_success
    refute_output --partial '"permissionDecision":"deny"'

    run env -u CYBERSEC_AGENT_GUARD XDG_STATE_HOME="$XDG_STATE_HOME" CYBERSEC_MCP_AUDIT_LOG="$CYBERSEC_MCP_AUDIT_LOG" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" pre-bash \
        <<< '{"session_id":"sessB","tool_input":{"command":"nmap 192.0.2.10"}}'
    assert_output --partial '"permissionDecision":"deny"'
}

@test "agent guard session-start writes a per-session marker" {
    _guard_fixture
    run env -u CYBERSEC_AGENT_GUARD XDG_STATE_HOME="$XDG_STATE_HOME" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" session-start <<< '{"session_id":"abc-123"}'
    assert_success
    [[ -s "$XDG_STATE_HOME/cybersec-tools-mcp/guard-session.abc-123" ]]
    [[ -s "$XDG_STATE_HOME/cybersec-tools-mcp/guard-session" ]]

    # An id that is not a safe filename component is ignored.
    run env -u CYBERSEC_AGENT_GUARD XDG_STATE_HOME="$XDG_STATE_HOME" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" session-start <<< '{"session_id":"../escape"}'
    assert_success
    [[ ! -e "$XDG_STATE_HOME/cybersec-tools-mcp/guard-session.../escape" ]]
    [[ ! -e "$XDG_STATE_HOME/escape" ]]
}

@test "agent guard keeps a session's clearance across compaction" {
    _guard_fixture
    local dir="$XDG_STATE_HOME/cybersec-tools-mcp"
    printf '2026-07-28T10:00:00.000Z\n' > "$dir/guard-session.sessA"
    printf '%s\n' '{"ts":"2026-07-28T10:00:05.000Z","event":"tool_call","tool":"guided_assessment"}' \
        > "$CYBERSEC_MCP_AUDIT_LOG"

    run env -u CYBERSEC_AGENT_GUARD XDG_STATE_HOME="$XDG_STATE_HOME" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" session-start <<< '{"session_id":"sessA","source":"compact"}'
    assert_success
    run env -u CYBERSEC_AGENT_GUARD XDG_STATE_HOME="$XDG_STATE_HOME" CYBERSEC_MCP_AUDIT_LOG="$CYBERSEC_MCP_AUDIT_LOG" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" pre-bash \
        <<< '{"session_id":"sessA","tool_input":{"command":"nmap 192.0.2.10"}}'
    refute_output --partial '"permissionDecision":"deny"'
}

_source_fixture_module() {
    cat >> "$1/modules/reversing.sh" <<'EOF'
RE_BUILD_NAMES=(fixture-tool)
RE_BUILD_URLS[fixture-tool]='https://example.invalid/fixture-tool.git'
RE_BUILD_CMDS[fixture-tool]='cmake -S . -B build && cmake --build build --parallel'
declare -gA RE_BUILD_BINS=(
    [fixture-tool]=$'build/fixture-tool|fixture-tool\nbuild/fixture-companion|fixture-companion'
)
EOF
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

_source_update_fixture() {
    SOURCE_FIXTURE_REPO="$TEST_TMPDIR/repo"
    SOURCE_FIXTURE_STUBS="$TEST_TMPDIR/stubs"
    mkdir -p "$SOURCE_FIXTURE_REPO/scripts" "$SOURCE_FIXTURE_STUBS" "$TEST_TMPDIR/home" \
        "$TEST_TMPDIR/prefix/bin"
    cp -R "$PROJECT_ROOT/lib" "$PROJECT_ROOT/modules" "$SOURCE_FIXTURE_REPO/"
    cp "$PROJECT_ROOT/scripts/update.sh" "$PROJECT_ROOT/scripts/verify.sh" "$PROJECT_ROOT/scripts/stale_artefacts.sh" "$SOURCE_FIXTURE_REPO/scripts/"
    _source_fixture_module "$SOURCE_FIXTURE_REPO"
    local command
    for command in pkg dpkg apt-get npm gem cargo pipx docker snap go sudo rustup uv; do
        printf '#!/bin/sh\nexit 1\n' > "$SOURCE_FIXTURE_STUBS/$command"
        chmod +x "$SOURCE_FIXTURE_STUBS/$command"
    done
    cat > "$SOURCE_FIXTURE_STUBS/cmake" <<'EOF'
#!/bin/bash
case "$1" in
    -S) mkdir -p build ;;
    --build)
        for binary in fixture-tool fixture-companion; do
            printf '#!/bin/sh\nprintf "%s %s\\n"\n' "$binary" "$(cat version.txt)" > "build/$binary"
            chmod +x "build/$binary"
        done
        ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$SOURCE_FIXTURE_STUBS/cmake"
    printf '# tool|method|version|last_updated\nfixture-tool|source|HEAD|2026-01-01 00:00:00\n' \
        > "$SOURCE_FIXTURE_REPO/.versions"
}

_source_run_lifecycle() {
    local script="$1"
    shift
    run env -i HOME="$TEST_TMPDIR/home" PREFIX="$TEST_TMPDIR/prefix" TERMUX_VERSION=1 \
        PKG_MANAGER=pkg DISTRO_ID=android DISTRO_ID_LIKE= DISTRO_NAME=Termux \
        GITHUB_TOOL_DIR="$GITHUB_TOOL_DIR" TMPDIR="$TEST_TMPDIR" TERM=dumb \
        PATH="$SOURCE_FIXTURE_STUBS:$TEST_TMPDIR/prefix/bin:$PATH" \
        bash "$SOURCE_FIXTURE_REPO/scripts/$script" "$@"
}

_source_run_update() {
    _source_run_lifecycle update.sh --skip-system --skip-pipx --skip-go \
        --skip-gems --skip-cargo --skip-binary --skip-special --skip-docker
}

_source_tracked_clone() {
    local upstream="$TEST_TMPDIR/upstream"
    local -a git_identity=(-c user.email=fixture@example.invalid -c user.name=fixture)
    git init -q "$upstream"
    printf 'v1\n' > "$upstream/version.txt"
    git -C "$upstream" add version.txt
    git -C "$upstream" "${git_identity[@]}" commit -qm v1
    git clone -q "$upstream" "$GITHUB_TOOL_DIR/fixture-tool"
}

@test "source update rebuilds both executables and restores their PATH links" {
    _source_outputs_fixture
    _source_update_fixture
    _source_tracked_clone
    local upstream="$TEST_TMPDIR/upstream"
    local -a git_identity=(-c user.email=fixture@example.invalid -c user.name=fixture)
    printf 'v2\n' > "$upstream/version.txt"
    git -C "$upstream" "${git_identity[@]}" commit -qam v2

    _source_run_update

    assert_success
    run "$TEST_TMPDIR/prefix/bin/fixture-tool"
    assert_success
    assert_output 'fixture-tool v2'
    run "$TEST_TMPDIR/prefix/bin/fixture-companion"
    assert_success
    assert_output 'fixture-companion v2'
}

@test "source update keeps conflicting local edits in the stash and rebuilds from upstream" {
    _source_outputs_fixture
    _source_update_fixture
    _source_tracked_clone
    local upstream="$TEST_TMPDIR/upstream" clone="$GITHUB_TOOL_DIR/fixture-tool"
    local -a git_identity=(-c user.email=fixture@example.invalid -c user.name=fixture)
    printf 'local edits\n' > "$clone/version.txt"
    printf 'upstream v2\n' > "$upstream/version.txt"
    git -C "$upstream" "${git_identity[@]}" commit -qam v2

    _source_run_update

    assert_failure
    assert_output --partial "kept in the stash"
    [[ "$(git -C "$clone" stash show -p)" == *'local edits'* ]]
    [[ -z "$(git -C "$clone" diff --name-only --diff-filter=U)" ]]
    [[ "$(cat "$clone/version.txt")" == 'upstream v2' ]]
    run "$TEST_TMPDIR/prefix/bin/fixture-tool"
    assert_output 'fixture-tool upstream v2'

    _source_run_update
    assert_success
}

@test "unchanged source update repairs links and rejects missing build artifacts" {
    _source_outputs_fixture
    _source_update_fixture
    _source_tracked_clone
    _source_artifacts

    _source_run_update

    assert_success
    [[ -L "$TEST_TMPDIR/prefix/bin/fixture-tool" && -L "$TEST_TMPDIR/prefix/bin/fixture-companion" ]]

    rm "$GITHUB_TOOL_DIR/fixture-tool/build/fixture-companion"

    _source_run_update

    assert_failure
    assert_output --partial 'Failed to expose built executable: fixture-tool'
}

@test "source verify requires the companion even when the primary executable is in PATH" {
    _source_outputs_fixture
    _source_update_fixture
    _source_artifacts
    ln -s "$GITHUB_TOOL_DIR/fixture-tool/build/fixture-tool" "$TEST_TMPDIR/prefix/bin/fixture-tool"
    rm "$GITHUB_TOOL_DIR/fixture-tool/build/fixture-companion"

    _source_run_lifecycle verify.sh --module reversing --installed-only

    assert_failure
    assert_output --partial 'required executable fixture-companion NOT found'
    _source_artifacts

    _source_run_lifecycle verify.sh --module reversing --installed-only

    assert_success
}

# Vendored skill updates (scripts/revendor_skills.py)

# Build an upstream repository with one skill at two commits, and a local copy of the first.
# Sets UPSTREAM, PIN, TARGET and SKILLS. The second commit is whatever the caller wrote before.
_skill_fixture() {
    UPSTREAM="$TEST_TMPDIR/upstream"
    SKILLS="$TEST_TMPDIR/skills"
    mkdir -p "$UPSTREAM/skills/demo/helpers" "$SKILLS"
    git -C "$UPSTREAM" init -q
    git -C "$UPSTREAM" config user.email fixture@example.invalid
    git -C "$UPSTREAM" config user.name fixture
    git -C "$UPSTREAM" config commit.gpgsign false
    printf -- '---\nname: demo\ndescription: First description.\n---\n\n# Demo\n\nstep one\n\nstep two\n\nstep three\n' \
        > "$UPSTREAM/skills/demo/SKILL.md"
    printf 'helper v1\n' > "$UPSTREAM/skills/demo/helpers/run.txt"
    git -C "$UPSTREAM" add -A
    git -C "$UPSTREAM" commit -q -m first
    PIN="$(git -C "$UPSTREAM" rev-parse HEAD)"
    cp -R "$UPSTREAM/skills/demo" "$SKILLS/demo"
}

# Replace one exact line of a file; avoids `sed -i`, which differs between GNU and BSD.
_replace_line() {
    python3 - "$1" "$2" "$3" <<'EOF'
import sys

path, old, new = sys.argv[1:]
lines = open(path, encoding="utf-8").read().split("\n")
assert old in lines, old
open(path, "w", encoding="utf-8").write("\n".join(new if line == old else line for line in lines))
EOF
}

_skill_commit() {
    git -C "$UPSTREAM" add -A
    git -C "$UPSTREAM" commit -q -m "$1"
    TARGET="$(git -C "$UPSTREAM" rev-parse HEAD)"
}

_revendor() {
    python3 "$PROJECT_ROOT/scripts/revendor_skills.py" --clone "$UPSTREAM" --pin "$PIN" --target "$TARGET" \
        --skills-dir "$SKILLS" --name fixture "$@"
}

@test "revendor keeps a local edit while taking an upstream change elsewhere in the file" {
    _skill_fixture
    _replace_line "$SKILLS/demo/SKILL.md" "step three" "step three, locally hardened"
    _replace_line "$UPSTREAM/skills/demo/SKILL.md" "step one" "step one, upstream rewrite"
    _skill_commit second

    run _revendor --list-local-edits
    assert_success
    assert_output --partial "UPDATED: demo"
    assert_output --partial "LOCAL-EDIT: demo/SKILL.md"
    assert_output --partial "PIN: advance"
    run cat "$SKILLS/demo/SKILL.md"
    assert_output --partial "step one, upstream rewrite"
    assert_output --partial "step three, locally hardened"
}

@test "revendor merges frontmatter by key, so a local provenance key does not block an upstream edit beside it" {
    _skill_fixture
    _replace_line "$SKILLS/demo/SKILL.md" "name: demo" "name: demo"$'\n'"source: example/upstream"$'\n'"upstream_commit: $PIN"
    _replace_line "$UPSTREAM/skills/demo/SKILL.md" "description: First description." "description: Second description."
    _skill_commit second

    run _revendor
    assert_success
    run cat "$SKILLS/demo/SKILL.md"
    assert_output --partial "description: Second description."
    assert_output --partial "source: example/upstream"
    assert_output --partial "upstream_commit: $TARGET"
}

@test "revendor writes nothing when a skill conflicts, then finishes after a hand merge" {
    bats_require_minimum_version 1.5.0
    _skill_fixture
    _replace_line "$SKILLS/demo/SKILL.md" "step two" "step two, local wording"
    _replace_line "$UPSTREAM/skills/demo/SKILL.md" "step two" "step two, upstream wording"
    printf 'helper v2\n' > "$UPSTREAM/skills/demo/helpers/run.txt"
    _skill_commit second

    run -3 _revendor
    assert_output --partial "BLOCKED: demo: conflict in SKILL.md"
    assert_output --partial "PIN: hold"
    run cat "$SKILLS/demo/helpers/run.txt"
    assert_output "helper v1"

    run -3 _revendor --mark-conflicts
    run grep -c '^<<<<<<< ' "$SKILLS/demo/SKILL.md"
    assert_output "1"
    run cat "$SKILLS/demo/helpers/run.txt"
    assert_output "helper v2"

    run -3 _revendor --finalize
    assert_output --partial "conflict markers left in SKILL.md"

    printf -- '---\nname: demo\ndescription: First description.\n---\n\n# Demo\n\nstep one\n\nstep two, merged\n\nstep three\n' \
        > "$SKILLS/demo/SKILL.md"
    run _revendor --finalize
    assert_success
    assert_output --partial "PIN: advance"
}

@test "revendor treats a copy older than the pin as unmodified" {
    _skill_fixture
    _replace_line "$UPSTREAM/skills/demo/SKILL.md" "step one" "step one, second version"
    _skill_commit second
    PIN="$TARGET"
    _replace_line "$UPSTREAM/skills/demo/SKILL.md" "step one, second version" "step one, third version"
    _skill_commit third

    run _revendor --list-local-edits
    assert_success
    assert_output --partial "1 local copies predated the recorded pin"
    refute_output --partial "LOCAL-EDIT"
    run grep -c 'third version' "$SKILLS/demo/SKILL.md"
    assert_output "1"
}

@test "revendor keeps a locally removed helper directory removed" {
    _skill_fixture
    rm -r "$SKILLS/demo/helpers"
    printf 'helper v2\n' > "$UPSTREAM/skills/demo/helpers/run.txt"
    printf 'new helper\n' > "$UPSTREAM/skills/demo/helpers/extra.txt"
    _replace_line "$UPSTREAM/skills/demo/SKILL.md" "step one" "step one, upstream rewrite"
    _skill_commit second

    run _revendor
    assert_success
    [[ ! -e "$SKILLS/demo/helpers" ]]
    run grep -c 'upstream rewrite' "$SKILLS/demo/SKILL.md"
    assert_output "1"
}

@test "revendor reports a skill upstream removed and deletes it only with --prune" {
    _skill_fixture
    git -C "$UPSTREAM" rm -q -r skills/demo
    mkdir -p "$UPSTREAM/skills/other"
    printf -- '---\nname: other\ndescription: Another skill.\n---\n' > "$UPSTREAM/skills/other/SKILL.md"
    _skill_commit second

    run _revendor
    assert_success
    assert_output --partial "REMOVED-UPSTREAM: demo"
    assert_output --partial "NEW-UPSTREAM: other"
    [[ -f "$SKILLS/demo/SKILL.md" ]]

    run _revendor --prune
    assert_success
    assert_output --partial "PRUNED: demo"
    [[ ! -e "$SKILLS/demo" ]]
}

@test "revendor writes invisible characters from upstream as visible escapes" {
    _skill_fixture
    printf 'summarize this \xf3\xa0\x81\xb3\xf3\xa0\x81\xa5 now\n' >> "$UPSTREAM/skills/demo/SKILL.md"
    _skill_commit second

    run _revendor
    assert_success
    assert_output --partial "INVISIBLE-TEXT: demo/SKILL.md"
    run grep -c 'summarize this <U+E0073 U+E0065> now' "$SKILLS/demo/SKILL.md"
    assert_output "1"
}

@test "revendor refuses a skill that gains a symlink upstream" {
    bats_require_minimum_version 1.5.0
    _skill_fixture
    ln -s /etc/hostname "$UPSTREAM/skills/demo/link"
    _skill_commit second

    run -3 _revendor
    assert_output --partial "BLOCKED: demo: refused: upstream link has mode 120000"
    [[ ! -e "$SKILLS/demo/link" ]]
}

@test "revendor drops a tool grant that upstream adds to a skill" {
    _skill_fixture
    _replace_line "$UPSTREAM/skills/demo/SKILL.md" "name: demo" "name: demo"$'\n'"allowed-tools: Bash Write WebFetch"
    _replace_line "$UPSTREAM/skills/demo/SKILL.md" "step one" "step one, upstream rewrite"
    _skill_commit second

    run _revendor
    assert_success
    assert_output --partial "UPDATED: demo"
    run cat "$SKILLS/demo/SKILL.md"
    assert_output --partial "step one, upstream rewrite"
    refute_output --partial "allowed-tools"
}

@test "the skills validator separates workspace lookups from tools that execute, write or fetch" {
    run python3 - "$PROJECT_ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from _skill_text import PROMPT_FREE_TOOLS, drop_tool_grant, granted_tools

inline = "---\nname: x\nallowed-tools: Read Grep Bash(git diff:*) WebFetch\neffort: low\n---\nbody\n"
listed = "---\nallowed-tools:\n- Write\n- mcp__server__tool\nname: x\n---\nallowed-tools: in the body\n"
assert granted_tools(inline) == ["Read", "Grep", "Bash(git diff:*)", "WebFetch"]
assert set(granted_tools(inline)) - PROMPT_FREE_TOOLS == {"Bash(git diff:*)", "WebFetch"}
assert granted_tools(listed) == ["Write", "mcp__server__tool"]
assert granted_tools("---\nname: x\nallowed-tools: Read Glob\n---\n") == ["Read", "Glob"]
assert granted_tools("---\nname: x\n---\nallowed-tools: Bash\n") is None
assert drop_tool_grant(inline) == "---\nname: x\neffort: low\n---\nbody\n"
assert drop_tool_grant(listed) == "---\nname: x\n---\nallowed-tools: in the body\n"
PY
    assert_success
}

@test "the skills validator rejects invisible characters and accepts an emoji joiner" {
    run python3 - "$PROJECT_ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/scripts")
from _skill_text import find_invisible, show_invisible

hidden = "".join(chr(0xE0000 + ord(c)) for c in "hi")
assert find_invisible("a" + hidden + "b") is not None
assert find_invisible("a​b") is not None
assert find_invisible("‮abc") is not None
assert find_invisible("\U0001F468‍\U0001F469") is None
assert find_invisible("﻿plain text with a byte-order mark") is None
assert show_invisible("a" + hidden + "b") == "a<U+E0068 U+E0069>b"
assert find_invisible(show_invisible("a" + hidden + "​b")) is None
PY
    assert_success
}

# One evidence item from a tool run, as a JSON fragment.
_finding_evidence() {
    printf '{"source":"run_tool","command":"curl -s http://10.0.0.5/","captured_at":"2026-11-14T18:00:00Z","locator":"body, line 3","excerpt":"x"%s}' "${1:-}"
}

@test "validate_findings accepts observed, claimed and confirmed findings that carry their evidence" {
    local sha
    sha=$(printf 'a%.0s' $(seq 64))
    printf '%s\n' \
        "{\"id\":\"F-1\",\"title\":\"Banner\",\"kind\":\"observation\",\"status\":\"observed\",\"target\":\"10.0.0.5\",\"uncertainty\":\"banner only\",\"evidence\":[$(_finding_evidence)]}" \
        '{"id":"F-2","title":"Hint in README","kind":"observation","status":"claimed","target":"archive","uncertainty":"untested","evidence":[{"source":"target_claim","captured_at":"2026-11-14T18:01:00Z","locator":"README.md line 3","excerpt":"the key is in notes.txt"}]}' \
        "{\"id\":\"F-3\",\"title\":\"Flag\",\"kind\":\"flag_candidate\",\"status\":\"confirmed\",\"target\":\"capture\",\"derivation\":\"stream 4 decodes to it\",\"confirmed_by\":\"decoded again from the original\",\"evidence\":[$(_finding_evidence ",\"sha256\":\"$sha\"")]}" \
        > "$TEST_TMPDIR/findings.jsonl"

    run python3 "$PROJECT_ROOT/scripts/validate_findings.py" "$TEST_TMPDIR/findings.jsonl"
    assert_success
    assert_output --partial "3 finding(s): 1 claimed, 1 confirmed, 1 observed"
    run python3 "$PROJECT_ROOT/scripts/validate_findings.py" --markdown "$TEST_TMPDIR/findings.jsonl"
    assert_success
    assert_line "| F-3 | confirmed | flag_candidate |  | Flag | capture | 1 item(s) |"
}

@test "validate_findings refuses a flag without a derivation and a claim promoted to a fact" {
    printf '[%s,%s]' \
        "{\"id\":\"B-1\",\"title\":\"flag{looks_right}\",\"kind\":\"flag_candidate\",\"status\":\"observed\",\"target\":\"page\",\"uncertainty\":\"all of it\",\"evidence\":[$(_finding_evidence)]}" \
        '{"id":"B-2","title":"Password in a comment","kind":"vulnerability","status":"confirmed","target":"page","derivation":"the comment says so","confirmed_by":"the comment","evidence":[{"source":"target_claim","captured_at":"2026-11-14T18:00:00Z","locator":"HTML comment","excerpt":"x"}]}' \
        > "$TEST_TMPDIR/findings.json"

    run python3 "$PROJECT_ROOT/scripts/validate_findings.py" "$TEST_TMPDIR/findings.json"
    assert_failure
    assert_output --partial "B-1: a flag candidate needs a 'derivation'"
    assert_output --partial "B-2: every evidence item is a target claim, so the status can only be 'claimed'"
    assert_output --partial "B-2: a confirmed finding needs one evidence item with the 'sha256' of its raw data"
}

@test "scan_skills --compare lists only the findings the newer result adds" {
    printf '%s' '{"scanner":"s","skills":1,"incomplete":[],"findings":[{"skill":"a","rule":"P1","severity":"HIGH","category":"c","file":"SKILL.md","line":1,"digest":"d1","excerpt":"old"}]}' > "$TEST_TMPDIR/old.json"
    printf '%s' '{"scanner":"s","skills":1,"incomplete":[],"findings":[{"skill":"a","rule":"P1","severity":"HIGH","category":"c","file":"SKILL.md","line":1,"digest":"d1","excerpt":"old"},{"skill":"a","rule":"P2","severity":"CRITICAL","category":"c","file":"SKILL.md","line":9,"digest":"d2","excerpt":"added"}]}' > "$TEST_TMPDIR/new.json"

    run python3 "$PROJECT_ROOT/scripts/scan_skills.py" --compare "$TEST_TMPDIR/old.json" "$TEST_TMPDIR/new.json"
    assert_success
    assert_output --partial "New since the earlier scan: 1 CRITICAL"
    assert_output --partial "CRITICAL P2 (c) a/SKILL.md:9: added"
    refute_output --partial ": old"
}

@test "update-skills rejects flag combinations that would move a pin by mistake" {
    run bash "$PROJECT_ROOT/scripts/update-skills.sh" --finalize
    assert_failure 2
    run bash "$PROJECT_ROOT/scripts/update-skills.sh" --apply --finalize bughunter
    assert_failure 2
    assert_output --partial "--finalize needs --target"
    run bash "$PROJECT_ROOT/scripts/update-skills.sh" --apply --target abc bughunter
    assert_failure 2
    run bash "$PROJECT_ROOT/scripts/update-skills.sh" --apply no-such-source
    assert_failure 2
}

@test "deep clean finds toolkit links when the tool tree sits behind a symlink" {
    _lifecycle_fixture
    local bin="$TEST_TMPDIR/prefix/bin"
    rmdir "$TEST_TMPDIR/tools"
    mkdir -p "$TEST_TMPDIR/real-tools"
    ln -s "$TEST_TMPDIR/real-tools" "$TEST_TMPDIR/tools"
    ln -s "$TEST_TMPDIR/real-tools/gone/gone.py" "$bin/gone"
    ln -s "$TEST_TMPDIR/elsewhere/tool" "$bin/users-own-link"

    _run_lifecycle remove.sh --deep-clean --yes

    assert_success
    [[ ! -L "$bin/gone" ]]
    [[ -L "$bin/users-own-link" ]]
}

@test "deep clean removes the Go module cache, the tool log and keeps a failing removal visible" {
    _lifecycle_fixture
    local module="$TEST_TMPDIR/home/.go/pkg/mod/example.invalid/m@v1.0.0"
    mkdir -p "$module"
    printf 'package m\n' > "$module/m.go"
    # Go leaves its module cache read-only.
    chmod -R a-w "$TEST_TMPDIR/home/.go/pkg/mod/example.invalid"
    : > "$LC_REPO/cybersec_tool.log"
    : > "$LC_REPO/cybersec_install.log"

    _run_lifecycle remove.sh --deep-clean --yes
    chmod -R u+w "$TEST_TMPDIR/home/.go" 2>/dev/null || true

    assert_success
    [[ ! -e "$TEST_TMPDIR/home/.go/pkg" ]]
    [[ ! -e "$LC_REPO/cybersec_tool.log" && ! -e "$LC_REPO/cybersec_install.log" ]]
}

# A pipx stub that lists "commix 0.1" and removes the venv on uninstall.
_stale_pipx_stub() {
    {
        printf '#!/bin/sh\n'
        printf 'echo "pipx $*" >> "%s/calls.log"\n' "$TEST_TMPDIR"
        printf 'if [ "$1" = list ]; then printf "%%s\\n" "commix 0.1" "man-spider 1.0"; exit 0; fi\n'
        printf 'if [ "$1" = uninstall ]; then rm -rf "%s/home/.local/pipx/venvs/$2"; exit 0; fi\n' "$TEST_TMPDIR"
        printf 'exit 1\n'
    } > "$LC_STUBS/pipx"
}

@test "update keeps old-method artefacts and rows: only install.sh removes them, with a successor" {
    _lifecycle_fixture
    local pipx_home="$TEST_TMPDIR/home/.local/pipx" bin="$TEST_TMPDIR/prefix/bin"
    _stale_pipx_stub
    mkdir -p "$pipx_home/venvs/commix/bin" "$TEST_TMPDIR/tools/apktool"
    : > "$pipx_home/venvs/commix/bin/commix"
    ln -s "$pipx_home/venvs/commix/bin/commix" "$bin/commix"
    printf '%s\n' 'commix|pipx|latest|2026-01-01 00:00:00' \
        'apktool|git|HEAD|2026-01-01 00:00:00' >> "$LC_REPO/.versions"

    _run_lifecycle update.sh --skip-system --skip-pipx --skip-go --skip-git --skip-gems \
        --skip-cargo --skip-binary --skip-special --skip-docker

    refute_output --partial "stale"
    [[ -d "$pipx_home/venvs/commix" && -L "$bin/commix" && -d "$TEST_TMPDIR/tools/apktool" ]]
    grep -q '^commix|pipx|' "$LC_REPO/.versions"
    grep -q '^apktool|git|' "$LC_REPO/.versions"
}

@test "remove clears stale method-change artefacts and does not treat their rows as the current install" {
    _lifecycle_fixture
    local pipx_home="$TEST_TMPDIR/home/.local/pipx"
    _stale_pipx_stub
    mkdir -p "$pipx_home/venvs/commix"
    printf '#!/bin/sh\necho "pkg $*" >> "%s/calls.log"\n' "$TEST_TMPDIR" > "$LC_STUBS/pkg"
    printf '#!/bin/sh\ncase "$2" in apktool) echo "ii  $2 1.0 all fixture"; exit 0 ;; esac\nexit 1\n' > "$LC_STUBS/dpkg"
    printf '%s\n' 'commix|pipx|latest|2026-01-01 00:00:00' \
        'apktool|git|HEAD|2026-01-01 00:00:00' >> "$LC_REPO/.versions"

    _run_lifecycle remove.sh --yes

    assert_success
    [[ ! -e "$pipx_home/venvs/commix" ]]
    run grep -F "uninstall -y apktool" "$TEST_TMPDIR/calls.log"
    assert_failure
}

_tree_state() {
    (cd "$TEST_TMPDIR" && find . -mindepth 1 -path ./calls.log -prune -o -print | LC_ALL=C sort \
        | while read -r p; do printf '%s %s\n' "$p" "$(stat -c '%Y' "$p" 2>/dev/null || stat -f '%m' "$p")"; done)
}

@test "remove --dry-run lists the planned removals and changes nothing" {
    _lifecycle_fixture
    local pipx_home="$TEST_TMPDIR/home/.local/pipx" bin="$TEST_TMPDIR/prefix/bin"
    printf '#!/bin/sh\necho "pipx $*" >> "%s/calls.log"\n[ "$1" = list ] && echo "codext 1.0"\nexit 0\n' \
        "$TEST_TMPDIR" > "$LC_STUBS/pipx"
    printf '#!/bin/sh\necho "docker $*" >> "%s/calls.log"\n[ "$1" = images ] && echo abc123\nexit 0\n' \
        "$TEST_TMPDIR" > "$LC_STUBS/docker"
    printf '#!/bin/sh\necho "dpkg $*" >> "%s/calls.log"\ncase "$2" in dnsenum) echo "ii  $2 1.0 all fixture"; exit 0 ;; esac\nexit 1\n' \
        "$TEST_TMPDIR" > "$LC_STUBS/dpkg"
    mkdir -p "$pipx_home/venvs/codext" "$TEST_TMPDIR/tools/nikto" "$TEST_TMPDIR/tools/MemProcFS" \
        "$TEST_TMPDIR/home/.go/pkg/mod"
    printf '#!/bin/sh\n' > "$bin/gf"
    printf '#!/bin/sh\n' > "$bin/chainsaw"
    chmod +x "$bin/gf" "$bin/chainsaw"
    printf '%s\n' 'codext|pipx|latest|2026-01-01 00:00:00' 'gf|go|latest|2026-01-01 00:00:00' \
        'nikto|git|HEAD|2026-01-01 00:00:00' 'chainsaw|binary|v1|2026-01-01 00:00:00' \
        'dnsenum|pkg|system|2026-01-01 00:00:00' 'BeEF|docker|beef|2026-01-01 00:00:00' \
        'commix|pipx|latest|2026-01-01 00:00:00' >> "$LC_REPO/.versions"
    : > "$LC_REPO/cybersec_tool.log"
    local before after
    cp "$LC_REPO/.versions" "$TEST_TMPDIR/versions.before"
    before=$(_tree_state)
    : > "$TEST_TMPDIR/calls.log"

    _run_lifecycle remove.sh --dry-run --yes --deep-clean

    assert_success
    assert_output --partial "Would remove pipx package: codext"
    assert_output --partial "Would remove Go binary: $bin/gf"
    assert_output --partial "Would remove git/source tree: $TEST_TMPDIR/tools/nikto"
    assert_output --partial "Would remove binary release: $bin/chainsaw"
    assert_output --partial "Would remove system package: dnsenum"
    assert_output --partial "Would remove Docker image: beefproject/beef"
    assert_output --partial "Would remove stale pipx artefact: commix"
    assert_output --partial "Would remove deep-clean path: $TEST_TMPDIR/home/.go/pkg"
    assert_output --partial "nothing was changed"
    after=$(_tree_state)
    [[ "$before" == "$after" ]]
    [[ "$(cksum < "$LC_REPO/.versions")" == "$(cksum < "$TEST_TMPDIR/versions.before")" ]]
    run grep -E "uninstall|remove|rmi|clean|-rf" "$TEST_TMPDIR/calls.log"
    assert_failure
    [[ -e "$LC_REPO/cybersec_tool.log" && ! -e "$LC_REPO/tool_removal.log" ]]
}

@test "agent guard sees a governed tool behind shell keywords, interpreters and wrappers" {
    _guard_fixture
    printf '%s\n' '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"list_tools"}' > "$CYBERSEC_MCP_AUDIT_LOG"
    local c
    for c in 'for h in a b; do nmap $h; done' 'if nmap x; then echo ok; fi' '{ nmap x; }' '! nmap x' 'while true; do nmap x; done' 'python3 /opt/sqlmap/sqlmap.py -u http://x' 'python3 -m sqlmap' 'python3 vol.py -f mem' 'bash -lc "nmap x"' 'bash --login -c "nmap x"' '/usr/bin/env nmap x' 'doas nmap x' 'eval "nmap x"' 'nm""ap 192.0.2.10'; do
        _run_guard_on "$c"
        assert_success
        assert_output --partial '"permissionDecision":"deny"'
    done
    for c in 'python3 build.py' 'bash -lc ls' 'echo "do nmap"' 'git commit -m "if nmap"'; do
        _run_guard_on "$c"
        assert_success
        refute_output --partial 'deny'
    done
}

@test "agent guard honours an advisor call that rotated into audit.log.1" {
    _guard_fixture
    printf '%s\n' '{"ts":"2026-07-28T10:00:01.000Z","event":"tool_call","tool":"list_tools"}' > "$CYBERSEC_MCP_AUDIT_LOG"
    printf '%s\n' '{"ts":"2026-07-28T10:00:02.000Z","event":"tool_call","tool":"guided_assessment"}' > "$CYBERSEC_MCP_AUDIT_LOG.1"
    _run_guard_on 'nmap x'
    assert_success
    refute_output --partial 'deny'
}

@test "update-skills validates MIN_AGE_DAYS and documents its options" {
    run env MIN_AGE_DAYS=abc bash "$PROJECT_ROOT/scripts/update-skills.sh" --check-pins
    assert_failure 2
    assert_output --partial "must be non-negative integers"

    run bash "$PROJECT_ROOT/scripts/update-skills.sh" --help
    assert_success
    assert_output --partial "--check-pins"
    assert_output --partial "MAX_STALE_DAYS"
}

@test "mcp-launch.sh --local reports a missing uv" {
    mkdir -p "$TEST_TMPDIR/nouv"
    for _c in bash sed grep cat dirname; do
        _p="$(command -v "$_c")" && ln -sf "$_p" "$TEST_TMPDIR/nouv/$_c"
    done
    run env -i PATH="$TEST_TMPDIR/nouv" bash "$PROJECT_ROOT/scripts/mcp-launch.sh" --local
    assert_failure 1
    assert_output --partial "requires uv"
}

@test "validate_profiles.sh rejects an empty MODULES and a missing SKIP_HEAVY" {
    local tree="$TEST_TMPDIR/profiles-tree"
    mkdir -p "$tree/scripts" "$tree/lib" "$tree/profiles"
    cp "$PROJECT_ROOT/scripts/validate_profiles.sh" "$tree/scripts/"
    cp "$PROJECT_ROOT/lib/common.sh" "$tree/lib/"
    cp "$PROJECT_ROOT"/profiles/*.conf "$tree/profiles/"
    local -a confs=("$tree"/profiles/*.conf)
    sed -i.bak 's/^MODULES=.*/MODULES=""/' "${confs[0]}"
    sed -i.bak '/^SKIP_HEAVY=/d' "${confs[1]}"
    rm -f "$tree"/profiles/*.bak

    run bash "$tree/scripts/validate_profiles.sh"

    assert_failure 1
    assert_output --partial "MODULES is empty"
    assert_output --partial "SKIP_HEAVY must be set"
}

@test "sandbox-source-hash changes when lib/common.sh changes" {
    command -v sha256sum >/dev/null || skip "sha256sum not available"
    local tree="$TEST_TMPDIR/hash-tree"
    mkdir -p "$tree/scripts" "$tree/mcp_server" "$tree/lib" "$tree/modules" "$tree/profiles" "$tree/sandbox"
    cp "$PROJECT_ROOT/scripts/sandbox-source-hash.sh" "$tree/scripts/"
    printf 'x\n' > "$tree/mcp_server/server.py"
    : > "$tree/mcp_server/pyproject.toml"; : > "$tree/mcp_server/uv.lock"; : > "$tree/mcp_server/README.md"
    : > "$tree/tools_config.json"; : > "$tree/install.sh"
    : > "$tree/sandbox/Dockerfile"; : > "$tree/sandbox/guest-mcp.json"
    printf 'a\n' > "$tree/lib/common.sh"; : > "$tree/modules/m.sh"; : > "$tree/profiles/p.conf"

    local before after
    before=$(bash "$tree/scripts/sandbox-source-hash.sh")
    printf 'b\n' >> "$tree/lib/common.sh"
    after=$(bash "$tree/scripts/sandbox-source-hash.sh")

    [[ -n "$before" && "$before" != "$after" ]]
}

# sync-skills.sh, sync-wsl.sh, pip-audit-lock.sh and test-distros.sh run from a copy of the
# repository layout so the real .agents/ mirror is never touched.

_skills_fixture() {
    SK_REPO="$TEST_TMPDIR/skills-repo"
    mkdir -p "$SK_REPO/scripts" "$SK_REPO/.claude/skills/alpha" "$SK_REPO/.claude/skills/beta"
    cp "$PROJECT_ROOT/scripts/sync-skills.sh" "$SK_REPO/scripts/"
    printf -- '---\nname: alpha\n---\n' > "$SK_REPO/.claude/skills/alpha/SKILL.md"
    printf -- '---\nname: beta\n---\n' > "$SK_REPO/.claude/skills/beta/SKILL.md"
}

@test "sync-skills mirrors .claude/skills into .agents/skills" {
    make_test_tmpdir
    _skills_fixture
    run bash "$SK_REPO/scripts/sync-skills.sh"
    assert_success
    assert_output --partial "synced 2 skill directories"
    [[ -f "$SK_REPO/.agents/skills/alpha/SKILL.md" && -f "$SK_REPO/.agents/skills/beta/SKILL.md" ]]
}

@test "sync-skills --check reports drift and writes nothing" {
    command -v diff >/dev/null || skip "needs diff"
    make_test_tmpdir
    _skills_fixture
    run bash "$SK_REPO/scripts/sync-skills.sh" --check
    assert_failure 1
    [[ ! -e "$SK_REPO/.agents" ]]

    bash "$SK_REPO/scripts/sync-skills.sh" >/dev/null
    run bash "$SK_REPO/scripts/sync-skills.sh" --check
    assert_success
    assert_output --partial "up to date"

    printf 'changed\n' >> "$SK_REPO/.claude/skills/alpha/SKILL.md"
    run bash "$SK_REPO/scripts/sync-skills.sh" --check
    assert_failure 1
    assert_output --partial "out of date"
    run grep -q changed "$SK_REPO/.agents/skills/alpha/SKILL.md"
    assert_failure
}

@test "sync-skills --check without diff fails with a clear error, not a drift report" {
    make_test_tmpdir
    _skills_fixture
    bash "$SK_REPO/scripts/sync-skills.sh" >/dev/null
    local nodiff="$TEST_TMPDIR/nodiff" tool
    mkdir -p "$nodiff"
    for tool in bash dirname basename; do
        ln -s "$(command -v "$tool")" "$nodiff/$tool"
    done
    run env PATH="$nodiff" bash "$SK_REPO/scripts/sync-skills.sh" --check
    assert_failure 2
    assert_output --partial "needs diff"
    refute_output --partial "out of date"
}

@test "sync-skills drops mirrored skills that were removed from the source" {
    make_test_tmpdir
    _skills_fixture
    bash "$SK_REPO/scripts/sync-skills.sh" >/dev/null
    rm -rf "$SK_REPO/.claude/skills/beta"
    run bash "$SK_REPO/scripts/sync-skills.sh"
    assert_success
    [[ ! -e "$SK_REPO/.agents/skills/beta" && -d "$SK_REPO/.agents/skills/alpha" ]]
}

@test "sync-skills rejects unknown arguments and fails without a source directory" {
    make_test_tmpdir
    _skills_fixture
    run bash "$SK_REPO/scripts/sync-skills.sh" --bogus
    assert_failure 2
    run bash "$SK_REPO/scripts/sync-skills.sh" --help
    assert_success
    rm -rf "$SK_REPO/.claude"
    run bash "$SK_REPO/scripts/sync-skills.sh"
    assert_failure 1
    assert_output --partial "source skills directory not found"
    [[ ! -e "$SK_REPO/.agents" ]]
}

@test "sync-wsl rejects a distro name with shell metacharacters before calling wsl.exe" {
    make_test_tmpdir
    mkdir -p "$TEST_TMPDIR/stubs"
    printf '#!/bin/sh\necho called >> "%s/wsl.log"\n' "$TEST_TMPDIR" > "$TEST_TMPDIR/stubs/wsl.exe"
    chmod +x "$TEST_TMPDIR/stubs/wsl.exe"
    run env PATH="$TEST_TMPDIR/stubs:$PATH" bash "$PROJECT_ROOT/scripts/sync-wsl.sh" 'kali;touch x'
    assert_failure 1
    assert_output --partial "Invalid distro name"
    [[ ! -e "$TEST_TMPDIR/wsl.log" ]]
}

@test "pip-audit-lock fails clearly when uv is missing and touches nothing" {
    make_test_tmpdir
    local repo="$TEST_TMPDIR/audit-repo" bin="$TEST_TMPDIR/nobin"
    mkdir -p "$repo/scripts" "$repo/mcp_server" "$bin"
    cp "$PROJECT_ROOT/scripts/pip-audit-lock.sh" "$repo/scripts/"
    ln -s "$(command -v dirname)" "$bin/dirname"
    run env PATH="$bin" "$BASH" "$repo/scripts/pip-audit-lock.sh"
    assert_failure 1
    assert_output --partial "uv not found"
    [[ -z "$(ls -A "$repo/mcp_server")" ]]
}

@test "test-distros prints usage for --help and rejects unknown arguments before any container work" {
    run bash "$PROJECT_ROOT/scripts/test-distros.sh" --help
    assert_success
    assert_output --partial "Multi-distro smoke test"
    run bash "$PROJECT_ROOT/scripts/test-distros.sh" --bogus
    assert_failure 2
    assert_output --partial "Unknown argument"
}
