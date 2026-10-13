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
}

_run_guarded_nmap() {
    # -u: a developer with the documented escape hatch exported must not see false failures.
    run env -u CYBERSEC_AGENT_GUARD \
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

_run_guard_on() {
    local json
    json=$(python3 -c 'import json, sys; print(json.dumps({"tool_input": {"command": sys.argv[1]}}))' "$1")
    run env -u CYBERSEC_AGENT_GUARD \
        XDG_STATE_HOME="$XDG_STATE_HOME" \
        CYBERSEC_MCP_AUDIT_LOG="$CYBERSEC_MCP_AUDIT_LOG" \
        bash "$PROJECT_ROOT/scripts/agent-guard.sh" pre-bash <<< "$json"
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
        $'x=$((a << b))\nnmap 192.0.2.10'; do
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
    printf '# tool|method|version|last_updated\n' > "$LC_REPO/.versions"
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

@test "update rebuilds pulled build trees and skips same-named user repos" {
    _lifecycle_fixture
    local up="$TEST_TMPDIR/upstream"
    local -a gitid=(-c user.email=fixture@example.invalid -c user.name=fixture)
    git init -q "$up"
    # AFLplusplus is rebuilt with its registry command (make source-only), never the default target.
    printf 'all:\n\tmkdir -p bin && cp version.txt bin/massdns\nsource-only:\n\tcp version.txt built.txt\n' \
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
    # Without a terminal a "cancel" used to exit 0 (silent success in CI/cron).
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

@test "remove refuses --deep-clean combined with --module (CL-3)" {
    _lifecycle_fixture
    _run_lifecycle remove.sh --module web --deep-clean --yes
    assert_failure
    assert_output --partial "cannot be combined with --module"
}

@test "verify does not report untracked opt-in Docker images missing (CL-7)" {
    _lifecycle_fixture
    # A docker stub with no images: the opt-in images were never pulled.
    printf '#!/bin/sh\nexit 0\n' > "$LC_STUBS/docker"
    chmod +x "$LC_STUBS/docker"

    _run_lifecycle verify.sh --module blueteam

    refute_output --partial "Docker image NOT found"
}

@test "verify fails loudly on an unreadable .versions (CL-7)" {
    [[ $EUID -ne 0 ]] || skip "root reads any file"
    _lifecycle_fixture
    chmod 000 "$LC_REPO/.versions"

    _run_lifecycle verify.sh --installed-only

    assert_failure
    assert_output --partial "Cannot read"
    chmod 644 "$LC_REPO/.versions"
}

@test "restore runs unattended with BACKUP_PASSPHRASE (CL-15)" {
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

@test "a second install/update/remove run refuses while one holds the lock (OP-4)" {
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

@test "restore refuses an unauthenticated legacy archive by default (SI-12)" {
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

@test "remove --remove-deps keeps a uv the user installed and uv's data (SI-11)" {
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

@test "agent guard keeps a separate clearance window per session (CL-17)" {
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

@test "agent guard session-start writes a per-session marker (CL-17)" {
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
    cp "$PROJECT_ROOT/scripts/update.sh" "$PROJECT_ROOT/scripts/verify.sh" "$SOURCE_FIXTURE_REPO/scripts/"
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
