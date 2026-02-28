#!/bin/bash
# =============================================================================
# test_helper.bash — Shared setup for bats tests
# Loaded by each .bats file via: load 'test_helper'
# =============================================================================

# Locate project root (one level up from tests/)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load bats helpers
load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'

# ---------- Mock /etc/os-release for distro detection -----------------------

# Create a temporary os-release that simulates a given distro.
# Usage: mock_os_release debian "Debian GNU/Linux 12" 12
mock_os_release() {
    local id="$1"
    local pretty="${2:-$1}"
    local version="${3:-}"
    local id_like="${4:-}"

    export MOCK_OS_RELEASE
    MOCK_OS_RELEASE="$(mktemp)"
    cat > "$MOCK_OS_RELEASE" <<EOF
ID=$id
PRETTY_NAME="$pretty"
VERSION_ID="$version"
ID_LIKE="$id_like"
EOF
}

# ---------- Source project libraries with mocked distro ---------------------

# Source common.sh (and optionally installers.sh) with distro overrides.
# Patches /etc/os-release by temporarily redefining detect_distro.
# Usage: source_libs [--installers] <distro_id> [pkg_manager]
source_libs() {
    local with_installers=false
    if [[ "${1:-}" == "--installers" ]]; then
        with_installers=true
        shift
    fi

    local distro_id="${1:-debian}"
    local pkg_mgr="${2:-apt}"

    # Prevent common.sh from calling detect_pkg_manager on source by
    # pre-setting the variables it would set.
    export DISTRO_ID="$distro_id"
    export DISTRO_ID_LIKE=""
    export DISTRO_NAME="$distro_id"
    export PKG_MANAGER="$pkg_mgr"

    # Stub out detect_pkg_manager so the auto-init at bottom of common.sh
    # doesn't overwrite our values (it reads /etc/os-release which may not
    # match on the CI runner).
    detect_pkg_manager() { :; }
    export -f detect_pkg_manager

    # Set SCRIPT_DIR so common.sh resolves paths correctly
    export SCRIPT_DIR="$PROJECT_ROOT"

    # Suppress log file writes during tests
    export LOG_FILE="/dev/null"

    # Source the library
    source "$PROJECT_ROOT/lib/common.sh"

    # Now restore our overrides (common.sh auto-init may have run)
    export DISTRO_ID="$distro_id"
    export PKG_MANAGER="$pkg_mgr"

    if [[ "$with_installers" == true ]]; then
        source "$PROJECT_ROOT/lib/installers.sh"
    fi
}

# ---------- Cleanup ---------------------------------------------------------

# Automatically clean up temp files after each test
teardown() {
    if [[ -n "${MOCK_OS_RELEASE:-}" && -f "${MOCK_OS_RELEASE:-}" ]]; then
        rm -f "$MOCK_OS_RELEASE"
    fi
    if [[ -n "${TEST_TMPDIR:-}" && -d "${TEST_TMPDIR:-}" ]]; then
        rm -rf "$TEST_TMPDIR"
    fi
}

# Create a temporary directory for test artifacts
make_test_tmpdir() {
    TEST_TMPDIR="$(mktemp -d)"
    export TEST_TMPDIR
}
