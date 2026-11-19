#!/usr/bin/env bats
# Tests for install.sh CLI argument parsing
# These tests run install.sh in a subprocess and check exit codes / output.
# No root required — we test --help, --list-*, --dry-run, and error cases.

setup() {
    load 'test_helper'
    INSTALL_SH="$PROJECT_ROOT/install.sh"
}

# --help

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

@test "install.sh --help works with HOME unset (cron/systemd/qm guest exec)" {
    run env -u HOME bash "$INSTALL_SH" --help
    assert_success
    refute_output --partial "unbound variable"
}

# --list-profiles

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

# --list-modules

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

# --doctor

@test "install.sh --doctor prints a readiness report" {
    run bash "$INSTALL_SH" --doctor
    assert_output --partial "cybersec-toolkit doctor"
    # A readiness verdict is always the last line (ready / not ready / note).
    assert_output --regexp "ready|not ready|note"
    # Verdict exit code, never a crash (2 = bad args, 127 = command not found).
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

# --profile unknown

@test "install.sh --profile unknown exits 2" {
    run bash "$INSTALL_SH" --profile nonexistent_profile_xyz --dry-run
    assert_failure 2
    assert_output --partial "Profile not found"
}

# --dry-run

@test "install.sh --dry-run with profile shows module list" {
    run bash "$INSTALL_SH" --profile ctf --dry-run
    assert_success
    assert_output --partial "DRY RUN"
    assert_output --partial "Modules:"
    assert_output --partial "misc"
    assert_output --partial "crypto"
}

@test "install.sh ignores FAST_MODE and FORCE_YES from the environment" {
    # An inherited FAST_MODE would silently disable checksum verification.
    run env FAST_MODE=true FORCE_YES=true bash "$INSTALL_SH" --profile ctf --dry-run
    assert_success
    assert_output --partial "Fast mode:      false"
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

@test "install.sh exits non-zero on an unknown option" {
    run bash "$INSTALL_SH" --require-checksum --dry-run
    assert_failure
    assert_output --partial "Unknown option: --require-checksum"
}

@test "install.sh refuses --dry-run with --tool instead of installing" {
    run bash "$INSTALL_SH" --tool nmap --dry-run
    assert_failure
    assert_output --partial "cannot be combined"
    refute_output --partial "must be run as root"
}

@test "install.sh refuses --dry-run with --rollback instead of removing" {
    run bash "$INSTALL_SH" --rollback last --yes --dry-run
    assert_failure
    assert_output --partial "cannot be combined"
}

@test "install.sh rejects --profile combined with --module" {
    run bash "$INSTALL_SH" --profile ctf --module web --dry-run
    assert_failure
    assert_output --partial "Mutually exclusive options"
}

@test "install.sh rejects --tool combined with --profile" {
    run bash "$INSTALL_SH" --tool nmap --profile ctf
    assert_failure
    assert_output --partial "Mutually exclusive options"
}

@test "sourcing install.sh does not create or truncate the install log" {
    local copy="$BATS_TEST_TMPDIR/toolkit"
    mkdir -p "$copy"
    cp -R "$PROJECT_ROOT/install.sh" "$PROJECT_ROOT/lib" "$PROJECT_ROOT/modules" \
        "$PROJECT_ROOT/profiles" "$PROJECT_ROOT/VERSION" "$copy/"
    run bash -c '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$copy"'/install.sh"
    '
    assert_success
    [ ! -e "$copy/cybersec_install.log" ]
}

@test "rollback keeps rows and manifest when a system package survives removal" {
    local copy="$BATS_TEST_TMPDIR/toolkit" fake="$BATS_TEST_TMPDIR/fakebin"
    mkdir -p "$copy/.install_sessions" "$fake" "$BATS_TEST_TMPDIR/prefix/bin"
    cp -R "$PROJECT_ROOT/install.sh" "$PROJECT_ROOT/lib" "$PROJECT_ROOT/modules" \
        "$PROJECT_ROOT/profiles" "$PROJECT_ROOT/VERSION" "$copy/"
    printf 'alpha\nstuck\n' > "$BATS_TEST_TMPDIR/installed"
    # dpkg -l reports the state file; `pkg uninstall` drops everything except
    # "stuck" and still exits 0, like pacman's masked pkg_remove.
    cat > "$fake/dpkg" <<EOF
#!/bin/sh
grep -qx "\$2" "$BATS_TEST_TMPDIR/installed" && echo "ii  \$2"
exit 0
EOF
    cat > "$fake/pkg" <<EOF
#!/bin/sh
grep -x stuck "$BATS_TEST_TMPDIR/installed" > "$BATS_TEST_TMPDIR/installed.new"
mv "$BATS_TEST_TMPDIR/installed.new" "$BATS_TEST_TMPDIR/installed"
exit 0
EOF
    chmod +x "$fake/dpkg" "$fake/pkg"
    {
        echo "# Session: 20260101_000000_1"
        echo "# Schema: 2"
        echo "alpha|pkg|installed|2026-01-01 00:00:00"
        echo "stuck|pkg|installed|2026-01-01 00:00:00"
    } > "$copy/.install_sessions/20260101_000000_1.manifest"
    printf '# tool|method|version|last_updated\nalpha|pkg|system|x\nstuck|pkg|system|x\n' > "$copy/.versions"

    run env PATH="$fake:$PATH" PKG_MANAGER=pkg DISTRO_ID=android DISTRO_NAME=Termux \
        PREFIX="$BATS_TEST_TMPDIR/prefix" \
        bash "$copy/install.sh" --rollback 20260101_000000_1 --yes < /dev/null
    assert_failure
    assert_output --partial "Still installed after removal attempt: stuck"
    ! grep -q '^alpha|' "$copy/.versions" || false
    grep -q '^stuck|' "$copy/.versions"
    [ -f "$copy/.install_sessions/20260101_000000_1.manifest" ]
}

@test "install.sh --dry-run with --module shows selected modules" {
    run bash "$INSTALL_SH" --module web --module recon --dry-run
    assert_success
    assert_output --partial "DRY RUN"
    assert_output --partial "web"
    assert_output --partial "recon"
}

# --verbose / -v

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

# CLI flags override profile values

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

# -j / --parallel

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

@test "install.sh rejects a non-numeric -j instead of silently using 4" {
    run bash "$INSTALL_SH" --dry-run -j abc
    assert_failure
    assert_output --partial "requires a positive number"
}

@test "install.sh clamps -j above 16 with a warning" {
    run bash "$INSTALL_SH" --dry-run -j 99
    assert_success
    assert_output --partial "using 16"
    assert_output --partial "Parallel jobs:  16"
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
        install_single_tool ropr
    '
    assert_success
    assert_output --partial "Installing ropr via cargo"
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

@test "explicit pycdc and kernel checker installs provision their build dependencies" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        LOG_FILE=/dev/null
        install_apt_batch() { shift; echo "DEPENDENCIES=$*"; }
        build_from_source() { echo "SOURCE=$1"; }
        install_single_tool pycdc
        install_single_tool kernel-hardening-checker
    '
    assert_success
    assert_output --partial 'DEPENDENCIES=git cmake build-essential'
    assert_output --partial 'DEPENDENCIES=git python3 python3-pip python3-venv'
    assert_output --partial 'SOURCE=pycdc'
    assert_output --partial 'SOURCE=kernel-hardening-checker'
}

@test "explicit source install stops when a required build package fails" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        LOG_FILE=/dev/null
        install_apt_batch() { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1)); }
        build_from_source() { echo SHOULD_NOT_BUILD; }
        install_single_tool pycdc
    '
    assert_failure
    refute_output --partial SHOULD_NOT_BUILD
}

@test "install_single_tool resolves INCLUDE_C2-gated git tools (Hoaxshell)" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        export LOG_FILE=/dev/null
        git_clone_or_pull() { return 0; }
        setup_git_repo() { return 0; }
        _tree_provenance() { echo latest; }
        track_version() { :; }
        install_single_tool Hoaxshell
    '
    assert_success
    assert_output --partial "Installed: Hoaxshell"
}

@test "install_single_tool finds module npm packages and promptfoo" {
    run bash -lc '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$INSTALL_SH"'"
        export LOG_FILE=/dev/null
        ensure_node() { return 0; }
        track_version() { :; }
        npm() { [[ "$*" == "install -g ${expected}@latest" ]]; }
        for expected in apk-mitm surya promptfoo; do
            install_single_tool "$expected" || exit 1
        done
        expected=rea-agents
        install_single_tool rea || exit 1
        npm() { return 1; }
        ! install_single_tool surya
    '
    assert_success
    assert_output --partial "Installed: apk-mitm"
    assert_output --partial "Installed: surya"
    assert_output --partial "Installed: promptfoo"
    assert_output --partial "Installed: rea ("
    assert_output --partial "Failed: surya"
}

# platform module filtering shared with dry-run

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

# Environment flags, exit codes and --tool preflight

@test "REQUIRE_CHECKSUMS=1 in the environment enables strict checksums" {
    run env REQUIRE_CHECKSUMS=1 bash "$INSTALL_SH" --dry-run
    assert_success
    assert_output --partial "Checksums req.: true"
}

@test "a malformed environment boolean does not block --help or --version" {
    run env PRODUCTION_MODE=banana bash "$INSTALL_SH" --help
    assert_success
    assert_output --partial "Usage"
    run env PRODUCTION_MODE=banana bash "$INSTALL_SH" --version
    assert_success
    run env PRODUCTION_MODE=banana bash "$INSTALL_SH" --dry-run
    [[ "$status" -eq 2 ]]
}

@test "PRODUCTION_MODE=yes in the environment implies required checksums" {
    run env PRODUCTION_MODE=yes bash "$INSTALL_SH" --dry-run
    assert_success
    assert_output --partial "Checksums req.: true"
}

@test "an unrecognised boolean environment value exits 2" {
    run env PRODUCTION_MODE=banana bash "$INSTALL_SH" --dry-run
    assert_failure 2
    assert_output --partial "Invalid value for PRODUCTION_MODE"
}

@test "install.sh -j 08 reads the number as decimal" {
    run bash "$INSTALL_SH" -j 08 --dry-run
    assert_success
    assert_output --partial "Parallel jobs:  8"
    refute_output --partial "too great"
}

@test "install.sh --version prints the VERSION file" {
    run bash "$INSTALL_SH" --version
    assert_success
    assert_output "cybersec-toolkit $(tr -d '[:space:]' < "$PROJECT_ROOT/VERSION")"
}

@test "install.sh --rollback rejects path components with exit 2" {
    run bash "$INSTALL_SH" --rollback ../x --yes
    assert_failure 2
    assert_output --partial "Invalid rollback target"
    run bash "$INSTALL_SH" --rollback a/b --yes
    assert_failure 2
}

@test "install.sh --tool stops on an unsupported OS before touching anything" {
    local copy="$BATS_TEST_TMPDIR/toolkit" fake="$BATS_TEST_TMPDIR/fakebin"
    mkdir -p "$copy" "$fake"
    cp -R "$PROJECT_ROOT/install.sh" "$PROJECT_ROOT/lib" "$PROJECT_ROOT/modules" \
        "$PROJECT_ROOT/profiles" "$PROJECT_ROOT/VERSION" "$copy/"
    printf '#!/bin/sh\necho Darwin\n' > "$fake/uname"
    chmod +x "$fake/uname"
    run env -u PKG_MANAGER PATH="$fake:$PATH" bash "$copy/install.sh" --tool nmap
    assert_failure 1
    assert_output --partial "macOS is not supported"
    [ ! -e "$copy/cybersec_install.log" ]
    [ ! -e "$copy/cybersec_tool.log" ]
}

@test "install.sh --tool leaves the full-install log intact" {
    local copy="$BATS_TEST_TMPDIR/toolkit"
    mkdir -p "$copy" "$BATS_TEST_TMPDIR/prefix/bin"
    cp -R "$PROJECT_ROOT/install.sh" "$PROJECT_ROOT/lib" "$PROJECT_ROOT/modules" \
        "$PROJECT_ROOT/profiles" "$PROJECT_ROOT/VERSION" "$copy/"
    printf 'previous run record\n' > "$copy/cybersec_install.log"
    run env PKG_MANAGER=pkg DISTRO_ID=android DISTRO_NAME=Termux \
        PREFIX="$BATS_TEST_TMPDIR/prefix" \
        bash "$copy/install.sh" --tool __no_such_tool_xyz__ < /dev/null
    assert_failure 1
    [ "$(cat "$copy/cybersec_install.log")" = "previous run record" ]
    [ -f "$copy/cybersec_tool.log" ]
}

@test "non-interactive rollback without --yes refuses and keeps the manifest" {
    local copy="$BATS_TEST_TMPDIR/toolkit"
    mkdir -p "$copy/.install_sessions" "$BATS_TEST_TMPDIR/prefix/bin"
    cp -R "$PROJECT_ROOT/install.sh" "$PROJECT_ROOT/lib" "$PROJECT_ROOT/modules" \
        "$PROJECT_ROOT/profiles" "$PROJECT_ROOT/VERSION" "$copy/"
    printf '# Session: s1\n# Schema: 2\nalpha|pkg|installed|2026-01-01 00:00:00\n' \
        > "$copy/.install_sessions/s1.manifest"
    run env PKG_MANAGER=pkg DISTRO_ID=android DISTRO_NAME=Termux \
        PREFIX="$BATS_TEST_TMPDIR/prefix" \
        bash "$copy/install.sh" --rollback s1 < /dev/null
    assert_failure 1
    assert_output --partial "Refusing to run destructive rollback"
    [ -f "$copy/.install_sessions/s1.manifest" ]
}

@test "--skip-heavy help names the SDR packages it actually skips" {
    run bash "$INSTALL_SH" --help
    assert_success
    assert_output --partial "WIRELESS_HEAVY_PACKAGES: gnuradio, gqrx-sdr"
    source "$PROJECT_ROOT/modules/wireless.sh"
    [[ "${WIRELESS_HEAVY_PACKAGES[*]}" == "gnuradio gqrx-sdr" ]]
}

_stale_install_fixture() {
    STALE_COPY="$BATS_TEST_TMPDIR/toolkit"
    mkdir -p "$STALE_COPY/scripts" "$BATS_TEST_TMPDIR/bin" "$BATS_TEST_TMPDIR/pipx/venvs/commix/bin" \
        "$BATS_TEST_TMPDIR/tools"
    cp -R "$PROJECT_ROOT/install.sh" "$PROJECT_ROOT/lib" "$PROJECT_ROOT/modules" \
        "$PROJECT_ROOT/profiles" "$PROJECT_ROOT/VERSION" "$STALE_COPY/"
    cp "$PROJECT_ROOT/scripts/stale_artefacts.sh" "$STALE_COPY/scripts/"
    : > "$BATS_TEST_TMPDIR/pipx/venvs/commix/bin/commix"
    ln -s "$BATS_TEST_TMPDIR/pipx/venvs/commix/bin/commix" "$BATS_TEST_TMPDIR/bin/commix"
}

_run_stale_cleanup() {
    run bash -c '
        set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "'"$STALE_COPY"'/install.sh"
        PIPX_HOME="'"$BATS_TEST_TMPDIR"'/pipx"; PIPX_BIN_DIR="'"$BATS_TEST_TMPDIR"'/bin"
        GITHUB_TOOL_DIR="'"$BATS_TEST_TMPDIR"'/tools"; LOG_FILE=/dev/null
        VERSION_FILE="'"$STALE_COPY"'/.versions"
        _cleanup_stale_method_artefacts
    '
}

@test "install removes the old pipx commix venv and link while its row still exists" {
    _stale_install_fixture
    printf '%s\n' 'commix|pipx|latest|2026-01-01 00:00:00' 'nikto|git|HEAD|2026-01-01 00:00:00' \
        > "$STALE_COPY/.versions"
    _run_stale_cleanup
    assert_success
    [ ! -e "$BATS_TEST_TMPDIR/pipx/venvs/commix" ]
    [ ! -L "$BATS_TEST_TMPDIR/bin/commix" ]
    ! grep -q '^commix|' "$STALE_COPY/.versions"
    grep -q '^nikto|git|' "$STALE_COPY/.versions"
}

@test "individual commix install migrates its old pipx launcher before recording Git ownership" {
    _stale_install_fixture
    printf '%s\n' 'commix|pipx|latest|2026-01-01 00:00:00' 'apktool|git|HEAD|2026-01-01 00:00:00' \
        > "$STALE_COPY/.versions"
    mkdir -p "$BATS_TEST_TMPDIR/tools/apktool" "$BATS_TEST_TMPDIR/home" "$BATS_TEST_TMPDIR/stubs"
    mkdir -p "$BATS_TEST_TMPDIR/home/.local"
    mv "$BATS_TEST_TMPDIR/pipx" "$BATS_TEST_TMPDIR/home/.local/pipx"
    ln -sf "$BATS_TEST_TMPDIR/home/.local/pipx/venvs/commix/bin/commix" "$BATS_TEST_TMPDIR/bin/commix"
    cat >> "$STALE_COPY/lib/installers.sh" <<'EOF'
git_clone_or_pull() {
    mkdir -p "$2/.git"
    printf 'print("synthetic commix")\n' > "$2/commix.py"
}
EOF
    printf '#!/bin/sh\nexit 1\n' > "$BATS_TEST_TMPDIR/stubs/pipx"
    chmod +x "$BATS_TEST_TMPDIR/stubs/pipx"

    run env -i HOME="$BATS_TEST_TMPDIR/home" PREFIX="$BATS_TEST_TMPDIR" TERMUX_VERSION=1 \
        PKG_MANAGER=pkg DISTRO_ID=android DISTRO_NAME=Termux TERM=dumb \
        GITHUB_TOOL_DIR="$BATS_TEST_TMPDIR/tools" \
        PATH="$BATS_TEST_TMPDIR/stubs:$PATH" \
        bash "$STALE_COPY/install.sh" --tool commix

    assert_success
    [[ ! -e "$BATS_TEST_TMPDIR/home/.local/pipx/venvs/commix" ]]
    [[ -f "$BATS_TEST_TMPDIR/bin/commix" && ! -L "$BATS_TEST_TMPDIR/bin/commix" ]]
    grep -q '^commix|git|HEAD|' "$STALE_COPY/.versions"
    [[ -d "$BATS_TEST_TMPDIR/tools/apktool" ]]
    grep -q '^apktool|git|HEAD|' "$STALE_COPY/.versions"
}

@test "individual Git install reports CLI setup failure and retains clone provenance" {
    _stale_install_fixture
    mkdir -p "$BATS_TEST_TMPDIR/home"
    cat >> "$STALE_COPY/lib/installers.sh" <<'EOF'
git_clone_or_pull() { mkdir -p "$2/.git"; }
setup_git_repo() { return 1; }
EOF

    run env -i HOME="$BATS_TEST_TMPDIR/home" PREFIX="$BATS_TEST_TMPDIR" TERMUX_VERSION=1 \
        PKG_MANAGER=pkg DISTRO_ID=android DISTRO_NAME=Termux TERM=dumb \
        GITHUB_TOOL_DIR="$BATS_TEST_TMPDIR/tools" PATH="$PATH" \
        bash "$STALE_COPY/install.sh" --tool commix

    assert_failure
    assert_output --partial 'CLI setup failed for commix'
    [[ -d "$BATS_TEST_TMPDIR/tools/commix/.git" ]]
    grep -q '^commix|git|HEAD|' "$STALE_COPY/.versions"
}

@test "selected man-spider migration recognizes its legacy package name and leaves commix alone" {
    _stale_install_fixture
    source_libs --installers debian apt
    source "$PROJECT_ROOT/scripts/stale_artefacts.sh"
    PIPX_HOME="$BATS_TEST_TMPDIR/pipx"
    PIPX_BIN_DIR="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$PIPX_HOME/venvs/manspider"
    printf '%s\n' 'commix|pipx|latest|2026-01-01 00:00:00' 'manspider|pipx|latest|2026-01-01 00:00:00' \
        > "$STALE_COPY/.versions"
    pipx() { return 1; }

    run _cleanup_stale_artefacts "$STALE_COPY/.versions" man-spider

    assert_success
    [[ ! -e "$PIPX_HOME/venvs/manspider" && -d "$PIPX_HOME/venvs/commix" ]]
    ! grep -q '^manspider|' "$STALE_COPY/.versions"
    grep -q '^commix|pipx|' "$STALE_COPY/.versions"
}

@test "install leaves a venv alone when its tool is not recorded as pipx-installed" {
    _stale_install_fixture
    printf 'commix|git|HEAD|2026-01-01 00:00:00\n' > "$STALE_COPY/.versions"
    _run_stale_cleanup
    assert_success
    [ -d "$BATS_TEST_TMPDIR/pipx/venvs/commix" ]
    grep -q '^commix|git|' "$STALE_COPY/.versions"
}

@test "main runs the stale-artefact cleanup before the install stages" {
    run awk '/^main\(\) \{/,/^}/' "$PROJECT_ROOT/install.sh"
    assert_output --partial "_cleanup_stale_method_artefacts"
}

@test "install keeps a stale clone with local changes and its row" {
    _stale_install_fixture
    git init -q "$BATS_TEST_TMPDIR/tools/apktool"
    printf 'mine\n' > "$BATS_TEST_TMPDIR/tools/apktool/notes.txt"
    printf 'apktool|git|HEAD|2026-01-01 00:00:00\n' > "$STALE_COPY/.versions"
    _run_stale_cleanup
    assert_success
    assert_output --partial "uncommitted changes"
    [ -f "$BATS_TEST_TMPDIR/tools/apktool/notes.txt" ]
    grep -q '^apktool|git|' "$STALE_COPY/.versions"
}

@test "stale cleanup keeps a clone and its record when Git status fails" {
    _stale_install_fixture
    git init -q "$BATS_TEST_TMPDIR/tools/apktool"
    printf 'synthetic local data\n' > "$BATS_TEST_TMPDIR/tools/apktool/notes.txt"
    printf 'apktool|git|HEAD|2026-01-01 00:00:00\n' > "$STALE_COPY/.versions"

    run bash -c '
        stale_copy_path="$1"; stale_test_path="$2"; set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "$stale_copy_path/install.sh"
        source "$stale_copy_path/scripts/stale_artefacts.sh"
        PIPX_HOME="$stale_test_path/pipx"; PIPX_BIN_DIR="$stale_test_path/bin"
        GITHUB_TOOL_DIR="$stale_test_path/tools"; LOG_FILE=/dev/null
        git() { return 128; }
        _cleanup_stale_artefacts "$stale_copy_path/.versions"
    ' _ "$STALE_COPY" "$BATS_TEST_TMPDIR"

    assert_failure
    assert_output --partial 'cannot inspect its Git working tree'
    [ -f "$BATS_TEST_TMPDIR/tools/apktool/notes.txt" ]
    grep -q '^apktool|git|' "$STALE_COPY/.versions"
}

@test "stale cleanup keeps a linked worktree with local changes and its record" {
    _stale_install_fixture
    local source_repo="$BATS_TEST_TMPDIR/worktree-source"
    local worktree="$BATS_TEST_TMPDIR/tools/apktool"
    local -a git_fixture=(git -c core.hooksPath=/dev/null -c commit.gpgsign=false)
    "${git_fixture[@]}" init -q "$source_repo"
    printf 'synthetic tracked file\n' > "$source_repo/tracked.txt"
    "${git_fixture[@]}" -C "$source_repo" add tracked.txt
    "${git_fixture[@]}" -C "$source_repo" -c user.email=fixture@example.invalid \
        -c user.name=fixture commit -qm fixture
    "${git_fixture[@]}" -C "$source_repo" worktree add -q -b fixture-linked "$worktree"
    [ -f "$worktree/.git" ]
    printf 'synthetic local edit\n' >> "$worktree/tracked.txt"
    printf 'apktool|git|HEAD|2026-01-01 00:00:00\n' > "$STALE_COPY/.versions"

    _run_stale_cleanup

    assert_success
    assert_output --partial 'uncommitted changes'
    grep -q 'synthetic local edit' "$worktree/tracked.txt"
    grep -q '^apktool|git|' "$STALE_COPY/.versions"
}

@test "stale cleanup reports an install-record write failure without claiming success" {
    _stale_install_fixture
    printf 'commix|pipx|latest|2026-01-01 00:00:00\n' > "$STALE_COPY/.versions"

    run bash -c '
        stale_copy_path="$1"; stale_test_path="$2"; set --
        export PKG_MANAGER=apt DISTRO_ID=debian DISTRO_NAME=debian
        source "$stale_copy_path/install.sh"
        source "$stale_copy_path/scripts/stale_artefacts.sh"
        PIPX_HOME="$stale_test_path/pipx"; PIPX_BIN_DIR="$stale_test_path/bin"
        GITHUB_TOOL_DIR="$stale_test_path/tools"; LOG_FILE=/dev/null
        command_exists() { [[ "$1" != pipx ]]; }
        mktemp() { return 1; }
        _cleanup_stale_artefacts "$stale_copy_path/.versions"
    ' _ "$STALE_COPY" "$BATS_TEST_TMPDIR"

    assert_failure
    assert_output --partial 'could not update its install record'
    refute_output --partial 'and dropped its install record'
    [ ! -e "$BATS_TEST_TMPDIR/pipx/venvs/commix" ]
    grep -q '^commix|pipx|' "$STALE_COPY/.versions"
}
