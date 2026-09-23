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

_run_guard_on() {
    local json
    json=$(python3 -c 'import json, sys; print(json.dumps({"tool_input": {"command": sys.argv[1]}}))' "$1")
    run env \
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
