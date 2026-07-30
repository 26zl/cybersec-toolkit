#!/bin/bash
# shellcheck disable=SC1090  # Dynamic source paths are intentional (modular architecture)
# Validate installer package names against the current distro repositories.
set -uo pipefail

show_usage() {
    cat <<'EOF'
Usage: bash scripts/validate_distro_packages.sh [--module <name>]...

Checks package availability without installing anything. Repeat --module to
limit the check; omitting it checks every module.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${LOG_FILE:-/dev/null}"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/installers.sh"
source "$SCRIPT_DIR/lib/shared.sh"
_source_all_modules "$SCRIPT_DIR"

CHECK_MODULES=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --module)
            [[ $# -ge 2 && -n "$2" ]] || {
                echo "Missing value for --module" >&2
                show_usage >&2
                exit 1
            }
            CHECK_MODULES+=("$2")
            shift 2
            ;;
        -h|--help) show_usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done
[[ ${#CHECK_MODULES[@]} -eq 0 ]] && CHECK_MODULES=("${ALL_MODULES[@]}")
_validate_module_names "use --help to see available modules" "${CHECK_MODULES[@]}"

case "$PKG_MANAGER" in
    apt|dnf|pacman|zypper|pkg) ;;
    *)
        log_error "Unsupported package manager for repository validation: ${PKG_MANAGER:-none}"
        exit 1
        ;;
esac

# resolve_bulk — one query for all plain names, printing those that resolved.
# Only has to be *safe*, not complete: anything it misses falls through to the
# per-package check below, so a parsing quirk costs time, never correctness.
resolve_bulk() {
    case "$PKG_MANAGER" in
        apt|pkg) apt-cache show "$@" 2>/dev/null | awk '/^Package: /{print $2}' ;;
        dnf)     dnf -q repoquery --qf '%{name}\n' "$@" 2>/dev/null ;;
        pacman)  pacman -Si "$@" 2>/dev/null | awk -F': *' '/^Name +:/{print $2}' ;;
        *)       : ;;   # zypper has no cheap bulk form — per-package is fast enough
    esac
}

# pkg_exists — does the package manager know this name? Accepts virtual provides
# and groups, which are legitimate entries in the arrays (java-devel,
# @development-tools, base-devel).
pkg_exists() {
    local p="$1"
    case "$PKG_MANAGER" in
        apt)
            [[ -n "$(apt-cache policy "$p" 2>/dev/null)" ]] ;;
        dnf)
            if [[ "$p" == @* ]]; then
                dnf -q group info "${p#@}" &>/dev/null
            else
                [[ -n "$(dnf -q repoquery --whatprovides "$p" 2>/dev/null)" ]]
            fi ;;
        pacman)
            # -Sp resolves provides (what `pacman -S` accepts), so a package
            # installable only via a provide — pkg-config→pkgconf, rfkill→util-linux
            # — is not falsely reported missing.
            pacman -Si "$p" &>/dev/null || pacman -Sg "$p" &>/dev/null \
                || pacman -Sp "$p" &>/dev/null ;;
        zypper)
            # --provides matches capabilities too (what `zypper install` accepts),
            # e.g. python3 / nodejs / npm resolving through their versioned packages.
            zypper --non-interactive --quiet search --match-exact "$p" &>/dev/null \
                || zypper --non-interactive --quiet search --provides --match-exact "$p" &>/dev/null ;;
        pkg)
            pkg show "$p" &>/dev/null || apt-cache policy "$p" &>/dev/null ;;
        *)
            return 0 ;;   # unknown manager: nothing to assert
    esac
}

collect() {
    local -n __out=$1; shift
    local arr
    for arr in "$@"; do
        # Not every module declares every array (e.g. no *_HEAVY_PACKAGES).
        declare -p "$arr" &>/dev/null || continue
        local -n __src="$arr"
        [[ ${#__src[@]} -gt 0 ]] && __out+=("${__src[@]}")
        unset -n __src
    done
}

PKGS=()
collect PKGS SHARED_BASE_PACKAGES
for _mod in "${CHECK_MODULES[@]}"; do
    _pfx=$(_module_prefix "$_mod")
    collect PKGS "${_pfx}_PACKAGES" "${_pfx}_HEAVY_PACKAGES"
done

fixup_package_names PKGS
# Deduplicate — several modules share packages.
mapfile -t PKGS < <(printf '%s\n' "${PKGS[@]}" | sort -u)

echo "Distro: ${DISTRO_NAME:-?} (${PKG_MANAGER})"
echo "Checking ${#PKGS[@]} package names from ${#CHECK_MODULES[@]} modules + shared base..."
echo ""

declare -A resolved=()
_plain=()
for pkg in "${PKGS[@]}"; do
    [[ "$pkg" == @* ]] || _plain+=("$pkg")
done
if [[ ${#_plain[@]} -gt 0 ]]; then
    while read -r _name; do
        [[ -n "$_name" ]] && resolved["$_name"]=1
    done < <(resolve_bulk "${_plain[@]}")
fi

# Names carried only by a third-party repo the installer does not add (Terra,
# RPM Fusion, AUR). Not mapping rot — the install just no-ops without that repo.
THIRD_PARTY_OK=(ghidra)

missing=()
optional=()
for pkg in "${PKGS[@]}"; do
    [[ -n "${resolved[$pkg]:-}" ]] && continue
    pkg_exists "$pkg" && continue
    if [[ " ${THIRD_PARTY_OK[*]} " == *" $pkg "* ]]; then
        optional+=("$pkg")
    else
        missing+=("$pkg")
    fi
done

if [[ ${#optional[@]} -gt 0 ]]; then
    echo "Not in the base repos, third-party only (not an error): ${optional[*]}"
    echo ""
fi

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "MISSING from ${PKG_MANAGER} repositories (${#missing[@]}):"
    printf '  %s\n' "${missing[@]}"
    echo ""
    echo "Fix the ${PKG_MANAGER} column in lib/distro_compat.tsv — map to the current"
    echo "name, or to '-' when the package is genuinely unavailable on this distro."
fi

echo "Errors: ${#missing[@]}"
[[ ${#missing[@]} -eq 0 ]] || exit 1
echo "OK: every mapped package name resolves on ${PKG_MANAGER}"
