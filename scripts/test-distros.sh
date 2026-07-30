#!/usr/bin/env bash
# Multi-distro smoke test via rootless podman (or docker). Runs the CI-equivalent
# checks plus the package-name audit and the full bats suite inside real
# ubuntu/fedora/arch/opensuse containers, so apt/dnf/pacman/zypper differences are
# caught before release — the things that are invisible from a single host.
#
# The repo is streamed in over a stdin tar (no bind mounts, so SELinux never blocks
# it and the host tree is never mutated). The script re-invokes itself inside each
# container via --in-container, so it is a single self-contained file.
#
# Usage:
#   scripts/test-distros.sh                  # all four distros, full checks
#   scripts/test-distros.sh --quick          # skip the real install/remove steps
#   scripts/test-distros.sh --strict         # make the package-name audit fatal
#   scripts/test-distros.sh ubuntu arch      # a subset of distros
#
# Exit status is non-zero if any hard check failed. The package-name audit is
# reported but non-fatal unless --strict (the pacman/zypper columns are still
# being brought up to parity; this mirrors the non-blocking CI gate).
set -uo pipefail

# in-container mode: run the actual checks against the copied repo.
if [[ "${1:-}" == "--in-container" ]]; then
    DISTRO="$2"; MODE="${3:-full}"
    cd "$(dirname "$0")/.." || exit 2      # repo root (mounted at /work)

    fails=0
    pass() { printf '[%s] PASS %s\n' "$DISTRO" "$1"; }
    fail() { printf '[%s] FAIL %s\n' "$DISTRO" "$1"; fails=$((fails + 1)); }
    run()  { local l="$1"; shift; if "$@" >/tmp/o 2>&1; then pass "$l"; else fail "$l"; sed 's/^/      /' /tmp/o | tail -15; fi; }

    echo "[$DISTRO] bash $BASH_VERSION"

    run "bash -n all shell" bash -n install.sh lib/*.sh modules/*.sh scripts/*.sh
    run "source chain loads" bash -c '
        set -uo pipefail; SCRIPT_DIR="'"$PWD"'"; LOG_FILE=/dev/null
        source lib/common.sh && source lib/installers.sh && source lib/shared.sh'
    run "dry-run --profile full" bash install.sh --dry-run --profile full

    # Package-name audit — reported; fatal only with --strict.
    if bash scripts/validate_distro_packages.sh >/tmp/vp 2>&1; then
        pass "package names resolve"
    else
        if [[ "$MODE" == "strict" ]]; then fail "package names resolve"; else
            printf '[%s] WARN package names resolve (non-fatal)\n' "$DISTRO"; fi
        grep -A100 'MISSING from' /tmp/vp | head -40
    fi

    if [[ -x ./tests/bats/bin/bats ]]; then
        if ./tests/bats/bin/bats tests/*.bats >/tmp/bats 2>&1; then
            pass "bats suite ($(grep -c '^ok ' /tmp/bats) tests)"
        else
            fail "bats suite"; grep -E '^not ok|^#   ' /tmp/bats | head -30
        fi
    else
        printf '[%s] SKIP bats (submodules absent)\n' "$DISTRO"
    fi

    if [[ "$MODE" != "quick" ]]; then
        if bash install.sh --tool nmap --tool curl --tool tcpdump --tool socat --tool whois >/tmp/inst 2>&1; then
            miss=""; for t in nmap curl tcpdump socat whois; do command -v "$t" >/dev/null 2>&1 || miss="$miss $t"; done
            [[ -z "$miss" ]] && pass "install subset (5 tools)" || { fail "install subset —$miss"; tail -15 /tmp/inst; }
        else
            fail "install subset (installer errored)"; tail -20 /tmp/inst
        fi
        # curl ships in the prereqs, so provenance must record it "existing".
        if [[ -f .versions ]] && [[ "$(awk -F'|' '$1=="curl"{print $3}' .versions)" == "existing" ]]; then
            pass "provenance protects pre-existing curl"
        else
            fail "provenance: curl not marked existing"
        fi
        run "remove --module networking" bash scripts/remove.sh --module networking --yes
    fi

    echo "[$DISTRO] === $fails hard failure(s) ==="
    exit "$fails"
fi

# driver mode: run the checks across the distro containers.
ENGINE=""
for e in podman docker; do command -v "$e" >/dev/null 2>&1 && { "$e" info >/dev/null 2>&1 && ENGINE="$e" && break; }; done
[[ -n "$ENGINE" ]] || { echo "No usable podman or docker found." >&2; exit 2; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/cybersec-distros.XXXXXX")"

MODE=full
declare -a WANT=()
for arg in "$@"; do
    case "$arg" in
        --quick)  MODE=quick ;;
        --strict) MODE=strict ;;
        ubuntu|fedora|arch|opensuse) WANT+=("$arg") ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done
[[ ${#WANT[@]} -eq 0 ]] && WANT=(ubuntu fedora arch opensuse)

declare -A IMAGE=(
    [ubuntu]="docker.io/library/ubuntu:26.04"
    [fedora]="registry.fedoraproject.org/fedora:44"
    [arch]="docker.io/library/archlinux:latest"
    [opensuse]="registry.opensuse.org/opensuse/tumbleweed:latest"
)
# Prereqs cover everything the checks need — notably openssl (backup encryption)
# and the bats/tar/awk tooling — so a missing tool never masquerades as a failure.
declare -A PREREQ=(
    [ubuntu]='apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq --no-install-recommends \
        git curl wget sudo ca-certificates python3 openssl tar gzip >/dev/null 2>&1'
    [fedora]='dnf install -y -q git curl wget sudo which python3 openssl tar gzip findutils gawk >/dev/null 2>&1'
    [arch]='pacman -Sy --noconfirm --needed git curl wget sudo which python openssl tar gzip >/dev/null 2>&1'
    [opensuse]='zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null 2>&1
        zypper --non-interactive install -y git curl wget sudo which python3 openssl tar gzip gawk findutils >/dev/null 2>&1'
)

# Build the staging tree once: repo working tree (minus .git and the host's
# root-owned runtime artifacts) plus this script, streamed to every container.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$OUT"' EXIT
tar --exclude=.git --exclude='*.log' --exclude='.versions*' \
    --exclude='.install_sessions' --exclude='cybersec_tools_backup' \
    -C "$REPO" -cf - . 2>/dev/null | tar -C "$STAGE" -xf -

echo "Engine: $ENGINE   Mode: $MODE   Distros: ${WANT[*]}"
run_one() {
    local d="$1"
    {
        echo "===== $d (${IMAGE[$d]}) ====="
        tar -C "$STAGE" -cf - . | "$ENGINE" run -i --rm "${IMAGE[$d]}" bash -c "
            set -uo pipefail
            mkdir -p /work && tar -C /work -xf -
            ${PREREQ[$d]}
            bash /work/scripts/test-distros.sh --in-container $d $MODE
        "
        echo "EXIT=\$?"
    } >"$OUT/$d.log" 2>&1
    echo "  $d finished"
}
for d in "${WANT[@]}"; do run_one "$d" & done
wait

echo
echo "===================== SUMMARY ====================="
overall=0
# grep -c prints "0" and exits 1 on no match, so `|| echo 0` would double it.
_count() { local n; n=$(grep -c "$1" "$2" 2>/dev/null); [[ "$n" =~ ^[0-9]+$ ]] && printf '%s' "$n" || printf 0; }
for d in "${WANT[@]}"; do
    hard=$(_count '\] FAIL ' "$OUT/$d.log")
    pc=$(_count '\] PASS ' "$OUT/$d.log")
    warn=$(_count '\] WARN ' "$OUT/$d.log")
    status="ok"; [[ "$hard" -gt 0 ]] && { status="FAIL"; overall=1; }
    printf '  %-9s %2s pass  %s hard-fail  %s warn   [%s]\n' "$d" "$pc" "$hard" "$warn" "$status"
    [[ "$hard" -gt 0 ]] && grep '\] FAIL ' "$OUT/$d.log" | sed 's/^/       /'
done
echo
echo "Full logs copied to: ./test-distros-logs/"
rm -rf "$REPO/test-distros-logs"; cp -r "$OUT" "$REPO/test-distros-logs"
exit "$overall"
