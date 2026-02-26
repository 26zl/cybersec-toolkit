#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by modules and scripts that source this file
# installers.sh — Install method helpers for cybersec-tools-installer
# Provides batch install functions for: apt, pipx, go, cargo, gem, git, binary, docker
# Source AFTER common.sh

# Global tool failure counter — incremented by batch install functions.
# Used by install.sh to detect per-module failures without relying on
# the module function's return code (which only reflects the last command).
TOTAL_TOOL_FAILURES=0

# ---------------------------------------------------------------------------
# Distro compatibility layer — data-driven package name translation
# Maps Debian package names to equivalents for dnf/pacman/zypper/pkg.
# Mappings are loaded from lib/distro_compat.tsv (lazy, once).
# ---------------------------------------------------------------------------

# Associative arrays populated by _load_distro_compat()
declare -gA _COMPAT_DNF=()
declare -gA _COMPAT_PACMAN=()
declare -gA _COMPAT_ZYPPER=()
declare -gA _COMPAT_PKG=()
_COMPAT_LOADED=false

# Load distro_compat.tsv into the four associative arrays.
# Called once on first use; subsequent calls are no-ops.
_load_distro_compat() {
    [[ "$_COMPAT_LOADED" == "true" ]] && return 0

    local tsv_path="${SCRIPT_DIR:-.}/lib/distro_compat.tsv"
    if [[ ! -f "$tsv_path" ]]; then
        log_warn "distro_compat.tsv not found at $tsv_path — package names will pass through unchanged"
        _COMPAT_LOADED=true
        return 0
    fi

    # NOTE: We cannot use IFS=$'\t' read -r ... because tab is IFS-whitespace
    # in POSIX, so consecutive tabs (empty fields) get collapsed. Instead we
    # read each line raw and split manually on the first 4 tabs.
    local _line _rest debian dnf pacman zypper pkg
    while IFS='' read -r _line; do
        # Skip comments and blank lines
        [[ -z "$_line" || "$_line" == \#* ]] && continue
        # Strip trailing \r in case of CRLF line endings
        _line="${_line%$'\r'}"
        # Split on tabs positionally (preserves empty fields)
        _rest="$_line"
        debian="${_rest%%	*}"; _rest="${_rest#*	}"
        dnf="${_rest%%	*}";    _rest="${_rest#*	}"
        pacman="${_rest%%	*}"; _rest="${_rest#*	}"
        zypper="${_rest%%	*}"; _rest="${_rest#*	}"
        pkg="$_rest"
        [[ -n "$dnf" ]]    && _COMPAT_DNF["$debian"]="$dnf"
        [[ -n "$pacman" ]] && _COMPAT_PACMAN["$debian"]="$pacman"
        [[ -n "$zypper" ]] && _COMPAT_ZYPPER["$debian"]="$zypper"
        [[ -n "$pkg" ]]    && _COMPAT_PKG["$debian"]="$pkg"
    done < "$tsv_path"

    _COMPAT_LOADED=true
    log_debug "_load_distro_compat: loaded from $tsv_path"
}

# Translate Debian package names in-place for the current PKG_MANAGER.
# Usage: fixup_package_names <array_nameref>
fixup_package_names() {
    local -n __arr=$1
    local new_arr=()
    local -a _parts

    _load_distro_compat

    for pkg in "${__arr[@]}"; do
        # WSL: skip kernel/hardware-dependent tools (no kernel module access)
        if [[ "$IS_WSL" == "true" ]]; then
            case "$pkg" in
                auditd|apparmor-utils|rr) continue ;;
            esac
        fi

        # ARM: skip x86-only packages
        if [[ "$IS_ARM" == "true" ]]; then
            case "$pkg" in
                qemu-system-x86) continue ;;
            esac
        fi

        case "$PKG_MANAGER" in
            apt)
                # Skip Kali/Parrot-only packages on standard Debian/Ubuntu
                if [[ "$DISTRO_ID" != "kali" && "$DISTRO_ID" != "parrot" ]]; then
                    case "$pkg" in
                        spike|enum4linux|bing-ip2hosts) continue ;;
                        ghidra|rizin|radare2) continue ;;
                        bulk-extractor|forensics-extra) continue ;;
                        kismet|spooftooph|crackle|asleap|fern-wifi-cracker) continue ;;
                        smali) continue ;;
                        sentrypeer|chaosreader) continue ;;
                    esac
                fi
                ;;
            dnf|pacman|zypper|pkg)
                # Select the right lookup table for this package manager
                local -n _map="_COMPAT_${PKG_MANAGER^^}"
                local mapped="${_map[$pkg]:-}"

                if [[ "$mapped" == "-" ]]; then
                    # Skip — package unavailable on this distro
                    continue
                elif [[ -n "$mapped" ]]; then
                    if [[ "$mapped" == *"+"* ]]; then
                        # Multi-expand: a+b → two packages (e.g. clang+make)
                        IFS='+' read -ra _parts <<< "$mapped"
                        new_arr+=("${_parts[@]}")
                        continue
                    fi
                    pkg="$mapped"
                fi
                # else: no mapping → passthrough (keep Debian name)
                ;;
        esac
        new_arr+=("$pkg")
    done
    if [[ ${#new_arr[@]} -gt 0 ]]; then
        __arr=("${new_arr[@]}")
    else
        __arr=()
    fi
}

# Batch APT install with progress and distro fixup
install_apt_batch() {
    [[ "${_SKIP_BATCH_REINSTALL:-false}" == "true" ]] && return 0
    local label="$1"; shift
    local -a packages=("$@")

    fixup_package_names packages

    local total=${#packages[@]}
    [[ "$total" -eq 0 ]] && return 0
    local failed=0

    log_debug "install_apt_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    log_info "Installing ${label} ($total packages)..."

    # Fast path: try all packages in one transaction (~50-80% faster)
    if pkg_install "${packages[@]}" >> "$LOG_FILE" 2>&1; then
        # All succeeded — track versions in bulk
        for pkg in "${packages[@]}"; do
            track_version "$pkg" "$PKG_MANAGER" "system"
        done
        echo ""
        log_success "${label}: ${total}/${total} installed (0 failed) [batch]"
    else
        # Fallback: install in small groups of 10 to isolate broken packages faster
        # than one-by-one, while still finding which specific packages fail.
        log_warn "${label}: batch install failed — falling back to grouped install$(_disk_hint)"
        local current=0 group_size=10
        local -a group=()
        for pkg in "${packages[@]}"; do
            group+=("$pkg")
            if [[ ${#group[@]} -ge $group_size ]]; then
                if pkg_install "${group[@]}" >> "$LOG_FILE" 2>&1; then
                    for _g in "${group[@]}"; do
                        current=$((current + 1))
                        show_progress "$current" "$total" "$_g"
                        track_version "$_g" "$PKG_MANAGER" "system"
                    done
                else
                    # Group failed — fall back to per-package within this group
                    for _g in "${group[@]}"; do
                        current=$((current + 1))
                        show_progress "$current" "$total" "$_g"
                        if ! pkg_install "$_g" >> "$LOG_FILE" 2>&1; then
                            log_error "Failed: $_g$(_disk_hint)"
                            failed=$((failed + 1))
                            track_session "$_g" "$PKG_MANAGER" "failed" 2>/dev/null || true
                        else
                            track_version "$_g" "$PKG_MANAGER" "system"
                        fi
                    done
                fi
                group=()
            fi
        done
        # Handle remaining packages
        if [[ ${#group[@]} -gt 0 ]]; then
            if pkg_install "${group[@]}" >> "$LOG_FILE" 2>&1; then
                for _g in "${group[@]}"; do
                    current=$((current + 1))
                    show_progress "$current" "$total" "$_g"
                    track_version "$_g" "$PKG_MANAGER" "system"
                done
            else
                for _g in "${group[@]}"; do
                    current=$((current + 1))
                    show_progress "$current" "$total" "$_g"
                    if ! pkg_install "$_g" >> "$LOG_FILE" 2>&1; then
                        log_error "Failed: $_g$(_disk_hint)"
                        failed=$((failed + 1))
                    else
                        track_version "$_g" "$PKG_MANAGER" "system"
                    fi
                done
            fi
        fi
        echo ""
        log_success "${label}: $((total - failed))/$total installed ($failed failed) [fallback]"
    fi

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_apt_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Batch pipx install
install_pipx_batch() {
    [[ "${_SKIP_BATCH_REINSTALL:-false}" == "true" ]] && return 0
    local label="$1"; shift
    local -a tools=("$@")
    local total=${#tools[@]}
    [[ "$total" -eq 0 ]] && return 0

    if [[ "${SKIP_PIPX:-false}" == "true" ]]; then
        log_warn "Skipping ${label} (--skip-pipx)"
        _report_method_total "pipx" 0
        return 0
    fi

    log_debug "install_pipx_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    ensure_pipx
    # Cache the installed list once to avoid calling pipx list per tool
    local installed_pipx=""
    if command_exists pipx; then
        installed_pipx=$(pipx list --short 2>/dev/null || true)
    fi

    log_info "Installing ${label} ($total pipx tools)..."
    _report_method_total "pipx" "$total"

    if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
        # --- Parallel mode ---
        # pipx venvs are isolated per-package, so parallel installs are safe.
        # pip's download cache has built-in locking for concurrent access.
        local _results_dir; _results_dir=$(mktemp -d); _register_cleanup "$_results_dir"

        for tool in "${tools[@]}"; do
            # Skip-check in main process
            if echo "$installed_pipx" | grep -qi "^${tool} "; then
                printf 'skip\nexisting\n' > "$_results_dir/$tool"
                _report_tool_done "pipx" "$tool" "skip"
                continue
            fi

            _wait_for_job_slot

            (
                trap '_release_job_slot' EXIT
                _report_tool_start "pipx" "$tool"
                if pipx_install "$tool" >> "$LOG_FILE" 2>&1; then
                    printf 'ok\nlatest\n' > "$_results_dir/$tool"
                    _report_tool_done "pipx" "$tool" "ok"
                else
                    log_error "Failed pipx: $tool"
                    printf 'fail\n\n' > "$_results_dir/$tool"
                    _report_tool_done "pipx" "$tool" "fail"
                fi
            ) &
        done
        wait

        _collect_parallel_results "$_results_dir" "pipx"
        # shellcheck disable=SC2154  # _par_failed/_par_skipped set by _collect_parallel_results
        local failed=$_par_failed skipped=$_par_skipped
    else
        # --- Sequential mode ---
        local current=0 failed=0 skipped=0
        for tool in "${tools[@]}"; do
            current=$((current + 1))
            show_progress "$current" "$total" "$tool"
            _report_tool_start "pipx" "$tool"
            if echo "$installed_pipx" | grep -qi "^${tool} "; then
                skipped=$((skipped + 1))
                track_version "$tool" "pipx" "existing"
                _report_tool_done "pipx" "$tool" "skip"
                continue
            fi
            if ! pipx_install "$tool" >> "$LOG_FILE" 2>&1; then
                log_error "Failed pipx: $tool$(_disk_hint)"
                failed=$((failed + 1))
                track_session "$tool" "pipx" "failed" 2>/dev/null || true
                _report_tool_done "pipx" "$tool" "fail"
            else
                track_version "$tool" "pipx" "latest"
                _report_tool_done "pipx" "$tool" "ok"
            fi
        done
    fi

    # Safety net: older pipx versions (e.g. 1.0.0 on Ubuntu 22.04) may ignore
    # PIPX_BIN_DIR and place binaries in ~/.local/bin instead of /usr/local/bin.
    # Symlink any that are missing from PIPX_BIN_DIR.
    local _fallback_dir="$HOME/.local/bin"
    if [[ -d "$_fallback_dir" ]] && [[ "$_fallback_dir" != "$PIPX_BIN_DIR" ]]; then
        local _symlinked=0
        for _f in "$_fallback_dir"/*; do
            [[ -f "$_f" ]] && [[ -x "$_f" ]] || continue
            local _bname
            _bname=$(basename "$_f")
            if [[ ! -f "$PIPX_BIN_DIR/$_bname" ]] && [[ ! -L "$PIPX_BIN_DIR/$_bname" ]]; then
                ln -sf "$_f" "$PIPX_BIN_DIR/$_bname" 2>/dev/null && _symlinked=$((_symlinked + 1))
            fi
        done
        [[ "$_symlinked" -gt 0 ]] && log_info "Symlinked $_symlinked pipx binaries from $_fallback_dir → $PIPX_BIN_DIR"
    fi

    # Python 3.12+ removed setuptools from venvs by default, but many tools
    # still use 'import pkg_resources' at runtime.  Inject setuptools into all
    # pipx venvs so they don't crash with ModuleNotFoundError.
    local _py_major _py_minor
    _py_major=$(python3 -c 'import sys; print(sys.version_info.major)' 2>/dev/null || echo 3)
    _py_minor=$(python3 -c 'import sys; print(sys.version_info.minor)' 2>/dev/null || echo 0)
    if [[ "$_py_major" -ge 3 ]] && [[ "$_py_minor" -ge 12 ]] && [[ -d "$PIPX_HOME/venvs" ]]; then
        local _injected=0
        for _venv_dir in "$PIPX_HOME/venvs"/*/; do
            [[ -x "$_venv_dir/bin/python" ]] || continue
            # Skip if setuptools is already installed in this venv
            "$_venv_dir/bin/python" -c 'import setuptools' 2>/dev/null && continue
            # Some pipx venvs lack the pip binary — use python -m pip instead.
            # Bootstrap pip via ensurepip if neither is available.
            if ! "$_venv_dir/bin/python" -m pip --version &>/dev/null; then
                "$_venv_dir/bin/python" -m ensurepip --default-pip >> "$LOG_FILE" 2>&1 || continue
            fi
            # Pin setuptools<75: version 75+ removed pkg_resources
            "$_venv_dir/bin/python" -m pip install -q 'setuptools<75' >> "$LOG_FILE" 2>&1 && _injected=$((_injected + 1))
        done
        [[ "$_injected" -gt 0 ]] && log_info "Injected setuptools into $_injected pipx venvs (Python $_py_major.$_py_minor compat)"
    fi

    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_pipx_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Batch Go install
install_go_batch() {
    [[ "${_SKIP_BATCH_REINSTALL:-false}" == "true" ]] && return 0
    local label="$1"; shift
    local -a tools=("$@")
    local total=${#tools[@]}
    [[ "$total" -eq 0 ]] && return 0

    if [[ "${SKIP_GO:-false}" == "true" ]]; then
        log_warn "Skipping ${label} (--skip-go)"
        _report_method_total "Go" 0
        return 0
    fi

    if ! command_exists go; then
        log_warn "Go not found — skipping ${label}"
        _report_method_total "Go" 0
        return 0
    fi
    # GOPATH and GOBIN are set in common.sh (GOPATH=$GOPATH, GOBIN=$GOBIN)
    # When privilege-dropping via _as_builder, $SUDO_USER cannot write to root-owned
    # GOBIN (/usr/local/bin) or GOPATH (/opt/go).  Use a staging GOBIN that $SUDO_USER
    # owns, then move completed binaries to the real GOBIN as root.
    local _gobin_stage=""
    if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER:-}" != "root" ]] && [[ "$PKG_MANAGER" != "pkg" ]]; then
        _gobin_stage=$(mktemp -d "/tmp/cybersec-gobin.XXXXXX")
        _register_cleanup "$_gobin_stage"
        _chown_for_builder "$_gobin_stage"
        mkdir -p "$GOPATH" 2>/dev/null || true
        # Recursive: previous runs may have left root-owned subdirs in the module cache
        chown -R "$SUDO_USER" "$GOPATH" 2>/dev/null || true
    fi
    local _effective_gobin="${_gobin_stage:-$GOBIN}"

    log_debug "install_go_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    log_info "Installing ${label} ($total Go tools)..."
    _report_method_total "Go" "$total"

    if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
        # --- Parallel mode ---
        local _results_dir; _results_dir=$(mktemp -d); _register_cleanup "$_results_dir"

        for tool in "${tools[@]}"; do
            local name
            name=$(_go_bin_name "$tool")

            # Skip-check in main process
            if command_exists "$name"; then
                printf 'skip\nexisting\n' > "$_results_dir/$name"
                _report_tool_done "Go" "$name" "skip"
                continue
            fi

            _wait_for_job_slot

            (
                trap '_release_job_slot' EXIT
                _report_tool_start "Go" "$name"
                if _as_builder "GOPATH='$GOPATH' GOBIN='$_effective_gobin' $(command -v go) install $tool" >> "$LOG_FILE" 2>&1; then
                    # Move binary from staging dir to system GOBIN (runs as root)
                    [[ -n "$_gobin_stage" ]] && [[ -f "$_gobin_stage/$name" ]] \
                        && mv "$_gobin_stage/$name" "$GOBIN/$name" && chmod +x "$GOBIN/$name"
                    printf 'ok\nlatest\n' > "$_results_dir/$name"
                    _report_tool_done "Go" "$name" "ok"
                else
                    log_error "Failed go: $name"
                    printf 'fail\n\n' > "$_results_dir/$name"
                    _report_tool_done "Go" "$name" "fail"
                fi
            ) &
        done
        wait

        _collect_parallel_results "$_results_dir" "go"
        # shellcheck disable=SC2154  # _par_failed/_par_skipped set by _collect_parallel_results
        local failed=$_par_failed skipped=$_par_skipped
    else
        # --- Sequential mode (original) ---
        local current=0 failed=0 skipped=0
        for tool in "${tools[@]}"; do
            current=$((current + 1))
            local name
            name=$(_go_bin_name "$tool")
            show_progress "$current" "$total" "$name"
            _report_tool_start "Go" "$name"
            # Skip if binary already exists (GOBIN is in PATH, so command_exists suffices)
            if command_exists "$name"; then
                skipped=$((skipped + 1))
                track_version "$name" "go" "existing"
                _report_tool_done "Go" "$name" "skip"
                continue
            fi
            if ! _as_builder "GOPATH='$GOPATH' GOBIN='$_effective_gobin' $(command -v go) install $tool" >> "$LOG_FILE" 2>&1; then
                log_error "Failed go: $name$(_disk_hint)"
                failed=$((failed + 1))
                track_session "$name" "go" "failed" 2>/dev/null || true
                _report_tool_done "Go" "$name" "fail"
            else
                # Move binary from staging dir to system GOBIN (runs as root)
                [[ -n "$_gobin_stage" ]] && [[ -f "$_gobin_stage/$name" ]] \
                    && mv "$_gobin_stage/$name" "$GOBIN/$name" && chmod +x "$GOBIN/$name"
                track_version "$name" "go" "latest"
                _report_tool_done "Go" "$name" "ok"
            fi
        done
    fi

    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_go_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Batch cargo install
install_cargo_batch() {
    [[ "${_SKIP_BATCH_REINSTALL:-false}" == "true" ]] && return 0
    local label="$1"; shift
    local -a crates=("$@")
    local total=${#crates[@]}
    [[ "$total" -eq 0 ]] && return 0

    if [[ "${SKIP_CARGO:-false}" == "true" ]]; then
        log_warn "Skipping ${label} (--skip-cargo)"
        _report_method_total "Cargo" 0
        return 0
    fi

    if ! command_exists cargo; then
        log_warn "Cargo not found — skipping ${label}"
        log_warn "Install Rust first: https://rustup.rs/"
        _report_method_total "Cargo" 0
        return 0
    fi
    local _cbdir
    _cbdir="$(_builder_home)/.cargo/bin"
    export PATH="$_cbdir:$PATH"

    # Try to set up cargo-binstall for faster pre-compiled downloads
    local _use_binstall=false
    if type ensure_cargo_binstall &>/dev/null; then
        ensure_cargo_binstall && _use_binstall=true
    elif command_exists cargo-binstall; then
        _use_binstall=true
    fi

    log_debug "install_cargo_batch: starting '$label' with $total items (binstall=$_use_binstall)"
    local _batch_start; _batch_start=$(date +%s)

    if [[ "$_use_binstall" == "true" ]]; then
        log_info "Installing ${label} ($total Rust tools via cargo-binstall)..."
    else
        log_info "Installing ${label} ($total Rust tools)..."
    fi
    _report_method_total "Cargo" "$total"

    # cargo uses a shared registry lock — always sequential to avoid conflicts
    local current=0 failed=0 skipped=0
    for crate in "${crates[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$crate"
        _report_tool_start "Cargo" "$crate"
        if command_exists "$crate"; then
            skipped=$((skipped + 1))
            track_version "$crate" "cargo" "existing"
            _report_tool_done "Cargo" "$crate" "skip"
            continue
        fi
        local _installed=false
        # Try cargo-binstall first (downloads pre-compiled binary, ~3s vs ~20s)
        if [[ "$_use_binstall" == "true" ]]; then
            if _as_builder "$(command -v cargo) binstall $crate --no-confirm" >> "$LOG_FILE" 2>&1; then
                _installed=true
                log_debug "Installed $crate via cargo-binstall"
            else
                log_debug "cargo-binstall failed for $crate — falling back to cargo install"
            fi
        fi
        # Fall back to cargo install (compiles from source)
        if [[ "$_installed" == "false" ]]; then
            if ! _as_builder "$(command -v cargo) install $crate" >> "$LOG_FILE" 2>&1; then
                log_error "Failed cargo: $crate$(_disk_hint)"
                failed=$((failed + 1))
                track_session "$crate" "cargo" "failed" 2>/dev/null || true
                _report_tool_done "Cargo" "$crate" "fail"
                continue
            fi
        fi
        local _cargo_bin_dir; _cargo_bin_dir="$(_builder_home)/.cargo/bin"
        if [[ -f "$_cargo_bin_dir/$crate" ]]; then
            ln -sf "$_cargo_bin_dir/$crate" "$PIPX_BIN_DIR/$crate" 2>/dev/null || true
        fi
        track_version "$crate" "cargo" "latest"
        _report_tool_done "Cargo" "$crate" "ok"
    done

    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_cargo_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Batch gem install
install_gem_batch() {
    [[ "${_SKIP_BATCH_REINSTALL:-false}" == "true" ]] && return 0
    local label="$1"; shift
    local -a gems=("$@")
    local total=${#gems[@]}
    [[ "$total" -eq 0 ]] && return 0

    if [[ "${SKIP_GEMS:-false}" == "true" ]]; then
        log_warn "Skipping ${label} (--skip-gems)"
        _report_method_total "Gems" 0
        return 0
    fi

    if ! command_exists gem; then
        log_warn "Ruby gem not found — skipping ${label}"
        _report_method_total "Gems" 0
        return 0
    fi

    log_debug "install_gem_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    # Cache the installed list once
    local installed_gems=""
    installed_gems=$(gem list --no-details 2>/dev/null || true)

    log_info "Installing ${label} ($total Ruby gems)..."
    _report_method_total "Gems" "$total"

    # gem uses a shared gem dir — always sequential to avoid conflicts
    local current=0 failed=0 skipped=0
    for gem_name in "${gems[@]}"; do
        current=$((current + 1))
        show_progress "$current" "$total" "$gem_name"
        _report_tool_start "Gems" "$gem_name"
        if echo "$installed_gems" | grep -q "^${gem_name} "; then
            skipped=$((skipped + 1))
            track_version "$gem_name" "gem" "existing"
            _report_tool_done "Gems" "$gem_name" "skip"
            continue
        fi
        if _as_builder "$(command -v gem) install $gem_name --no-document" >> "$LOG_FILE" 2>&1; then
            # Symlink gem executables to PIPX_BIN_DIR (gems install to user-local
            # dir under _as_builder, which isn't in system PATH)
            local _gem_bin_dir
            _gem_bin_dir="$(_builder_home)/.local/share/gem/ruby/*/bin" 2>/dev/null
            # shellcheck disable=SC2086  # glob expansion intentional
            for _gbin in $_gem_bin_dir/$gem_name; do
                [[ -f "$_gbin" ]] && ln -sf "$_gbin" "$PIPX_BIN_DIR/$(basename "$_gbin")" 2>/dev/null || true
            done
            track_version "$gem_name" "gem" "latest"
            _report_tool_done "Gems" "$gem_name" "ok"
        else
            log_error "Failed gem: $gem_name$(_disk_hint)"
            failed=$((failed + 1))
            track_session "$gem_name" "gem" "failed" 2>/dev/null || true
            _report_tool_done "Gems" "$gem_name" "fail"
        fi
    done

    echo ""
    log_success "${label}: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_gem_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# Post-clone setup for git repos
# Creates isolated venvs for Python repos with requirements.txt.
# Does NOT execute setup.py/pyproject.toml (supply-chain risk: arbitrary code as root).
# Only installs pinned dependencies from requirements.txt into the venv.
#
# Wrapper creation cascade (first match wins):
#   1. Python + requirements.txt → venv + symlink entry points
#   2. Java JAR → java -jar wrapper
#   3. Python script → python3 wrapper (case-insensitive, underscore/hyphen variants)
#   4. Shell script → symlink (case-insensitive)
#   5. Perl script → perl wrapper
#   6. Ruby script → ruby wrapper
#   7. Executable matching name → symlink (fallback for compiled tools)
setup_git_repo() {
    local dest="$1"
    local name
    name=$(basename "$dest")
    local name_lower="${name,,}"
    local name_under="${name_lower//-/_}"
    _SETUP_GIT_DEP_WARN=false

    # Early exit: don't clobber existing wrappers
    [[ -f "$PIPX_BIN_DIR/$name_lower" ]] && return 0

    # --- 1. Python project with requirements.txt ---
    # NOTE: Only requirements.txt is installed — setup.py is NOT executed.
    # This avoids running arbitrary code from cloned repos as root.
    if [[ -f "$dest/requirements.txt" ]]; then
        if [[ ! -d "$dest/venv" ]]; then
            python3 -m venv "$dest/venv" 2>>"$LOG_FILE" || return 0
        fi
        "$dest/venv/bin/pip" install -q --upgrade pip >> "$LOG_FILE" 2>&1 || true
        # Replace abandoned pycrypto with drop-in pycryptodome (Python 3.12+ compat)
        if grep -qi 'pycrypto' "$dest/requirements.txt" 2>/dev/null; then
            sed 's/^pycrypto.*/pycryptodome/i' "$dest/requirements.txt" > "$dest/requirements.txt.tmp" \
                && mv "$dest/requirements.txt.tmp" "$dest/requirements.txt"
        fi
        if ! "$dest/venv/bin/pip" install -q -r "$dest/requirements.txt" >> "$LOG_FILE" 2>&1; then
            # Some packages fail to build against the latest Python (e.g. lxml on 3.13).
            # Try an older Python if available on the system.
            local _fallback_ok=false
            for _pyver in python3.12 python3.11 python3.10; do
                command -v "$_pyver" &>/dev/null || continue
                log_info "Retrying $name with $_pyver (build failed on $(python3 --version 2>&1))..."
                rm -rf "$dest/venv"
                if "$_pyver" -m venv "$dest/venv" 2>>"$LOG_FILE"; then
                    "$dest/venv/bin/pip" install -q --upgrade pip >> "$LOG_FILE" 2>&1 || true
                    if "$dest/venv/bin/pip" install -q -r "$dest/requirements.txt" >> "$LOG_FILE" 2>&1; then
                        _fallback_ok=true
                    fi
                fi
                [[ "$_fallback_ok" == "true" ]] && break
            done
            if [[ "$_fallback_ok" != "true" ]]; then
                log_warn "pip install failed for $name (some dependencies may be missing)"
                _SETUP_GIT_DEP_WARN=true
            fi
        fi

        # Symlink venv entry points to PATH
        if [[ -d "$dest/venv/bin" ]]; then
            for candidate in "$dest/venv/bin/$name" "$dest/venv/bin/$name_lower" "$dest/venv/bin/$name_under"; do
                if [[ -f "$candidate" ]] && [[ -x "$candidate" ]]; then
                    ln -sf "$candidate" "$PIPX_BIN_DIR/$(basename "$candidate")" 2>/dev/null || true
                    return 0
                fi
            done
        fi
    fi

    # --- 2. Java JAR → java -jar wrapper ---
    local jar_file=""
    for jar_candidate in "$dest/$name.jar" "$dest/$name_lower.jar" \
                         "$dest/${name_under}.jar" "$dest/target/$name.jar" \
                         "$dest/target/${name_lower}.jar" "$dest/build/$name.jar" \
                         "$dest/build/${name_lower}.jar"; do
        if [[ -f "$jar_candidate" ]]; then
            jar_file="$jar_candidate"
            break
        fi
    done
    # Broader search (maxdepth 2) if exact matches miss
    if [[ -z "$jar_file" ]]; then
        jar_file=$(find "$dest" -maxdepth 2 -iname "*.jar" -type f 2>/dev/null | head -1)
    fi
    if [[ -n "$jar_file" ]]; then
        cat > "$PIPX_BIN_DIR/$name_lower" 2>/dev/null << JARWRAP || true
#!/bin/bash
exec java -jar "$jar_file" "\$@"
JARWRAP
        chmod +x "$PIPX_BIN_DIR/$name_lower" 2>/dev/null || true
        return 0
    fi

    # --- 3. Python script → python3 wrapper (case-insensitive, variants) ---
    if [[ ! -d "$dest/venv" ]]; then
        local py_file=""
        for py_candidate in "$dest/$name.py" "$dest/$name_lower.py" \
                            "$dest/${name_under}.py" "$dest/__main__.py"; do
            if [[ -f "$py_candidate" ]]; then
                py_file="$py_candidate"
                break
            fi
        done
        # Case-insensitive fallback: find <name>.py anywhere in top-level
        if [[ -z "$py_file" ]]; then
            py_file=$(find "$dest" -maxdepth 1 -iname "${name}.py" -type f 2>/dev/null | head -1)
        fi
        if [[ -n "$py_file" ]]; then
            chmod +x "$py_file" 2>/dev/null || true
            cat > "$PIPX_BIN_DIR/$name_lower" 2>/dev/null << PYWRAP || true
#!/bin/bash
exec python3 "$py_file" "\$@"
PYWRAP
            chmod +x "$PIPX_BIN_DIR/$name_lower" 2>/dev/null || true
            return 0
        fi
    fi

    # --- 4. Shell script → symlink (case-insensitive, variants) ---
    local sh_file=""
    for sh_candidate in "$dest/$name.sh" "$dest/$name_lower.sh" \
                        "$dest/${name_under}.sh"; do
        if [[ -f "$sh_candidate" ]]; then
            sh_file="$sh_candidate"
            break
        fi
    done
    if [[ -z "$sh_file" ]]; then
        sh_file=$(find "$dest" -maxdepth 1 -iname "${name}.sh" -type f 2>/dev/null | head -1)
    fi
    if [[ -n "$sh_file" ]]; then
        chmod +x "$sh_file" 2>/dev/null || true
        ln -sf "$sh_file" "$PIPX_BIN_DIR/$name_lower" 2>/dev/null || true
        return 0
    fi

    # --- 5. Perl script → perl wrapper ---
    local pl_file=""
    for pl_candidate in "$dest/$name.pl" "$dest/$name_lower.pl" \
                        "$dest/${name_under}.pl"; do
        if [[ -f "$pl_candidate" ]]; then
            pl_file="$pl_candidate"
            break
        fi
    done
    if [[ -z "$pl_file" ]]; then
        pl_file=$(find "$dest" -maxdepth 1 -iname "${name}.pl" -type f 2>/dev/null | head -1)
    fi
    if [[ -n "$pl_file" ]]; then
        chmod +x "$pl_file" 2>/dev/null || true
        cat > "$PIPX_BIN_DIR/$name_lower" 2>/dev/null << PLWRAP || true
#!/bin/bash
exec perl "$pl_file" "\$@"
PLWRAP
        chmod +x "$PIPX_BIN_DIR/$name_lower" 2>/dev/null || true
        return 0
    fi

    # --- 6. Ruby script → ruby wrapper ---
    local rb_file=""
    for rb_candidate in "$dest/$name.rb" "$dest/$name_lower.rb" \
                        "$dest/${name_under}.rb"; do
        if [[ -f "$rb_candidate" ]]; then
            rb_file="$rb_candidate"
            break
        fi
    done
    if [[ -z "$rb_file" ]]; then
        rb_file=$(find "$dest" -maxdepth 1 -iname "${name}.rb" -type f 2>/dev/null | head -1)
    fi
    if [[ -n "$rb_file" ]]; then
        chmod +x "$rb_file" 2>/dev/null || true
        cat > "$PIPX_BIN_DIR/$name_lower" 2>/dev/null << RBWRAP || true
#!/bin/bash
exec ruby "$rb_file" "\$@"
RBWRAP
        chmod +x "$PIPX_BIN_DIR/$name_lower" 2>/dev/null || true
        return 0
    fi

    # --- 7. Executable matching name → symlink (fallback for compiled tools) ---
    local exec_file=""
    for exec_candidate in "$dest/$name" "$dest/$name_lower" "$dest/$name_under" \
                          "$dest/bin/$name" "$dest/bin/$name_lower" "$dest/bin/$name_under"; do
        if [[ -f "$exec_candidate" ]] && [[ -x "$exec_candidate" ]]; then
            exec_file="$exec_candidate"
            break
        fi
    done
    if [[ -n "$exec_file" ]]; then
        ln -sf "$exec_file" "$PIPX_BIN_DIR/$name_lower" 2>/dev/null || true
        return 0
    fi
}

# Batch git clone with auto-setup
# Usage: install_git_batch "Label" name1=url1 name2=url2 ...
install_git_batch() {
    [[ "${_SKIP_BATCH_REINSTALL:-false}" == "true" ]] && return 0
    local label="$1"; shift
    local -a repos=("$@")
    local total=${#repos[@]}
    [[ "$total" -eq 0 ]] && return 0

    if [[ "${SKIP_GIT:-false}" == "true" ]]; then
        log_warn "Skipping ${label} (--skip-git)"
        _report_method_total "Git" 0
        return 0
    fi

    log_debug "install_git_batch: starting '$label' with $total items"
    local _batch_start; _batch_start=$(date +%s)

    local base_dir="$GITHUB_TOOL_DIR"
    log_info "Installing ${label} ($total repos)..."
    _report_method_total "Git" "$total"

    if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
        # --- Parallel mode ---
        local _results_dir; _results_dir=$(mktemp -d); _register_cleanup "$_results_dir"

        for entry in "${repos[@]}"; do
            local name="${entry%%=*}"
            local url="${entry#*=}"
            local dest="$base_dir/$name"

            _wait_for_job_slot

            (
                trap '_release_job_slot' EXIT
                _report_tool_start "Git" "$name"
                local is_existing=false
                [[ -d "$dest/.git" ]] && is_existing=true
                if git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1; then
                    _SETUP_GIT_DEP_WARN=false
                    setup_git_repo "$dest" >> "$LOG_FILE" 2>&1 || log_warn "setup_git_repo failed for $(basename "$dest")"
                    local _status="ok"
                    [[ "$is_existing" == "true" ]] && _status="skip"
                    [[ "$_SETUP_GIT_DEP_WARN" == "true" ]] && _status="${_status}:depwarn"
                    printf '%s\nHEAD\n' "$_status" > "$_results_dir/$name"
                    _report_tool_done "Git" "$name" "ok"
                else
                    log_error "Failed git: $name"
                    printf 'fail\n\n' > "$_results_dir/$name"
                    _report_tool_done "Git" "$name" "fail"
                fi
            ) &
        done
        wait

        _collect_parallel_results "$_results_dir" "git"
        # shellcheck disable=SC2154  # _par_failed/_par_skipped/_par_dep_warns set by _collect_parallel_results
        local failed=$_par_failed skipped=$_par_skipped dep_warns=$_par_dep_warns
    else
        # Sequential mode (original)
        local current=0 failed=0 skipped=0 dep_warns=0
        for entry in "${repos[@]}"; do
            current=$((current + 1))
            local name="${entry%%=*}"
            local url="${entry#*=}"
            local dest="$base_dir/$name"
            show_progress "$current" "$total" "$name"
            _report_tool_start "Git" "$name"
            local is_existing=false
            [[ -d "$dest/.git" ]] && is_existing=true
            if ! git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1; then
                log_error "Failed git: $name$(_disk_hint)"
                failed=$((failed + 1))
                track_session "$name" "git" "failed" 2>/dev/null || true
                _report_tool_done "Git" "$name" "fail"
            else
                # Auto-setup: venv, requirements, symlinks
                _SETUP_GIT_DEP_WARN=false
                setup_git_repo "$dest" >> "$LOG_FILE" 2>&1 || true
                [[ "$_SETUP_GIT_DEP_WARN" == "true" ]] && dep_warns=$((dep_warns + 1))
                [[ "$is_existing" == "true" ]] && skipped=$((skipped + 1))
                track_version "$name" "git" "HEAD"
                _report_tool_done "Git" "$name" "ok"
            fi
        done
    fi

    echo ""
    local _git_summary="${label}: $((total - failed - skipped))/$total new, ${skipped} updated, ${failed} failed"
    [[ "${dep_warns:-0}" -gt 0 ]] && _git_summary+=", ${dep_warns} with dependency warnings"
    log_success "$_git_summary"

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_git_batch: '$label' completed in ${_batch_elapsed}s"
    [[ "$failed" -gt 0 ]] && { TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed)); return 1; }
    return 0
}

# GitHub API curl options (with optional token auth)
# Sets the global _CURL_OPTS array — callers expand it as "${_CURL_OPTS[@]}".
# This avoids the word-splitting problem with echoing options as a string
# (the Authorization header contains spaces that must not be split).
_CURL_OPTS=()
# Security: GITHUB_TOKEN is passed via a temporary netrc file instead of a
# command-line -H header to prevent the token from appearing in process listings
# and bash debug trace (set -x) output written to the log file.
_GH_NETRC_FILE=""
_setup_curl_opts() {
    _CURL_OPTS=(-sSL)
    # Auto-detect token from gh CLI if not explicitly set
    if [[ -z "${GITHUB_TOKEN:-}" ]] && command -v gh &>/dev/null; then
        GITHUB_TOKEN=$(gh auth token 2>/dev/null) || true
        [[ -n "${GITHUB_TOKEN:-}" ]] && log_info "Using GitHub token from gh CLI (5000 req/hr API limit)"
    fi
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        _GH_NETRC_FILE=$(mktemp "${TMPDIR:-/tmp}/gh-netrc.XXXXXX")
        chmod 600 "$_GH_NETRC_FILE"
        printf 'machine github.com\nlogin x-access-token\npassword %s\n' "$GITHUB_TOKEN" > "$_GH_NETRC_FILE"
        printf 'machine api.github.com\nlogin x-access-token\npassword %s\n' "$GITHUB_TOKEN" >> "$_GH_NETRC_FILE"
        _register_cleanup "$_GH_NETRC_FILE"
        _CURL_OPTS+=(--netrc-file "$_GH_NETRC_FILE")
    fi
}
_setup_curl_opts

# GitHub API response cache — avoids redundant API calls and rate limit exhaustion.
# GitHub allows 60 requests/hour unauthenticated, 5000 with a token.
# Cache dir is per-run. Must be initialized BEFORE forking parallel subshells
# so all children share the same cache and rate-limit coordination files.
_GH_API_CACHE_DIR=""
_gh_api_cache_init() {
    if [[ -z "$_GH_API_CACHE_DIR" ]]; then
        _GH_API_CACHE_DIR=$(mktemp -d)
        _register_cleanup "$_GH_API_CACHE_DIR"
    fi
}
_gh_api_cache_cleanup() {
    [[ -n "${_GH_API_CACHE_DIR:-}" && -d "${_GH_API_CACHE_DIR:-}" ]] && rm -rf "$_GH_API_CACHE_DIR"
    _GH_API_CACHE_DIR=""
}

# _gh_api_get — cached GitHub API GET with coordinated rate-limit backoff.
# Uses a shared lock file so parallel subshells don't all retry simultaneously
# when the 60 req/hr unauthenticated limit is hit.
# Usage: _gh_api_get "https://api.github.com/repos/owner/repo/releases/latest"
# Outputs the response body. Returns 1 on failure.
_gh_api_get() {
    local url="$1"
    _gh_api_cache_init

    # Cache key: sanitize URL to filename
    local cache_key
    cache_key=$(echo "$url" | sed 's|[/:?&=]|_|g')
    local cache_file="$_GH_API_CACHE_DIR/$cache_key"

    # Return cached response if available
    if [[ -f "$cache_file" ]]; then
        cat "$cache_file"
        return 0
    fi

    # Shared rate-limit state file — parallel jobs coordinate through this.
    # Contains the epoch timestamp when the rate limit resets.
    local _rl_file="$_GH_API_CACHE_DIR/.rate_limit_reset"

    # If another job already detected a rate limit, wait for the reset time
    # before even attempting the request (avoids wasting the retry).
    if [[ -f "$_rl_file" ]]; then
        local _reset_ts _now _wait_secs
        read -r _reset_ts < "$_rl_file" 2>/dev/null || _reset_ts=0
        _now=$(date +%s)
        if [[ "$_reset_ts" -gt "$_now" ]]; then
            _wait_secs=$((_reset_ts - _now + 2))  # +2s safety margin
            [[ "$_wait_secs" -gt 120 ]] && _wait_secs=120
            log_debug "_gh_api_get: rate-limited, waiting ${_wait_secs}s (reset at $_reset_ts)"
            sleep "$_wait_secs"
        fi
    fi

    local http_code _attempt
    local tmp_body; tmp_body=$(mktemp); _register_cleanup "$tmp_body"
    local tmp_headers; tmp_headers=$(mktemp); _register_cleanup "$tmp_headers"

    for _attempt in 1 2 3; do
        http_code=$(curl "${_CURL_OPTS[@]}" -D "$tmp_headers" -w "%{http_code}" \
            -o "$tmp_body" "$url" 2>>"$LOG_FILE") || http_code="000"

        if [[ "$http_code" == "200" ]]; then
            break
        fi

        if [[ "$http_code" == "403" || "$http_code" == "429" ]]; then
            # Parse X-RateLimit-Reset header (epoch timestamp) from GitHub response
            local _reset_epoch
            _reset_epoch=$(sed -n 's/^[Xx]-[Rr]ate[Ll]imit-[Rr]eset: *\([0-9]*\).*/\1/p' "$tmp_headers" | head -1)

            if [[ -n "$_reset_epoch" && "$_reset_epoch" =~ ^[0-9]+$ ]]; then
                # Write reset timestamp for other parallel jobs to see
                echo "$_reset_epoch" > "$_rl_file" 2>/dev/null || true
                local _now _wait
                _now=$(date +%s)
                _wait=$((_reset_epoch - _now + 2))
                [[ "$_wait" -lt 10 ]] && _wait=10
                [[ "$_wait" -gt 120 ]] && _wait=120
            else
                # No reset header — use progressive backoff
                local _wait=$((30 * _attempt))
            fi

            if [[ "$_attempt" -eq 1 ]]; then
                log_warn "GitHub API rate limit hit — waiting ${_wait}s before retry (attempt $_attempt/3)..."
                [[ -z "${GITHUB_TOKEN:-}" ]] && \
                    log_warn "Tip: export GITHUB_TOKEN=ghp_... to raise the limit from 60 to 5000 requests/hour"
            else
                log_debug "_gh_api_get: rate limit retry attempt $_attempt/3 — waiting ${_wait}s"
            fi

            sleep "$_wait"
        else
            # Non-rate-limit error (404, 500, network failure) — no retry
            break
        fi
    done

    rm -f "$tmp_headers"

    if [[ "$http_code" != "200" ]]; then
        log_debug "_gh_api_get: HTTP $http_code for $url$(_disk_hint)"
        rm -f "$tmp_body"
        return 1
    fi

    # Clear rate-limit state on success (limit may have reset)
    rm -f "$_rl_file" 2>/dev/null || true

    # Validate JSON before caching (guards against empty/HTML responses on 200)
    if ! python3 -c "import json,sys; json.load(sys.stdin)" < "$tmp_body" 2>/dev/null; then
        log_debug "_gh_api_get: invalid JSON response for $url"
        rm -f "$tmp_body"
        return 1
    fi

    # Cache and output (cache write is best-effort — disk may be full)
    cp "$tmp_body" "$cache_file" 2>/dev/null || true
    cat "$tmp_body"
    rm -f "$tmp_body"
}

# Verify download against release checksum file
# Looks for SHA256 checksum files in the same GitHub release and verifies
# the downloaded file.  Returns 0 on match, 1 on mismatch or missing checksums.
verify_github_checksum() {
    local release_json="$1"
    local file_path="$2"
    local file_name="$3"

    # Look for a checksum asset in the release
    local checksum_url
    checksum_url=$(echo "$release_json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for asset in data.get('assets', []):
    name = asset.get('name', '').lower()
    if any(k in name for k in ('checksums', 'sha256sums', 'sha256sum', 'sha256')):
        print(asset['browser_download_url'])
        break
" 2>>"$LOG_FILE")

    if [[ -z "$checksum_url" ]]; then
        log_warn "No checksum file in release for $file_name — skipping verification"
        return 1
    fi

    # Cache checksum files — multiple binaries from the same release share one file
    _gh_api_cache_init
    local _cksum_cache_key
    _cksum_cache_key=$(echo "$checksum_url" | sed 's|[/:?&=]|_|g')
    local _cksum_cache_file="$_GH_API_CACHE_DIR/checksum_${_cksum_cache_key}"

    local checksums=""
    if [[ -f "$_cksum_cache_file" ]]; then
        checksums=$(< "$_cksum_cache_file")
    else
        checksums=$(curl "${_CURL_OPTS[@]}" "$checksum_url" 2>>"$LOG_FILE")
        if [[ -n "$checksums" ]]; then
            echo "$checksums" > "$_cksum_cache_file"
        fi
    fi
    if [[ -z "$checksums" ]]; then
        log_warn "Failed to download checksums for $file_name"
        return 1
    fi

    local expected_hash
    expected_hash=$(echo "$checksums" | awk -v f="$file_name" '$2 == f || $2 == ("*" f) {print $1; exit}')
    if [[ -z "$expected_hash" ]]; then
        log_warn "No checksum entry for $file_name in checksums file"
        return 1
    fi

    local actual_hash
    actual_hash=$(sha256sum "$file_path" | awk '{print $1}')
    if [[ "$actual_hash" == "$expected_hash" ]]; then
        log_success "Checksum verified: $file_name"
        return 0
    else
        log_error "Checksum MISMATCH for $file_name (expected: ${expected_hash:0:16}…, got: ${actual_hash:0:16}…)"
        # Signal hard failure — caller checks this marker file
        touch "$(dirname "$file_path")/.checksum_mismatch"
        return 1
    fi
}

# Internal implementation for downloading GitHub release binaries.
# Used by both download_github_release() and download_github_release_update().
# Args: repo binary pattern dest_dir mode
#   mode=install: skip if already installed, track version, log success/failure
#   mode=update:  force re-download, set _RELEASE_TAG, no version tracking (caller does it)
_download_github_release_impl() {
    local repo="$1"
    local binary="$2"
    local pattern="$3"
    local dest_dir="${4:-$PIPX_BIN_DIR}"
    local mode="${5:-install}"  # "install" or "update"

    # Ensure unzip is available for .zip archives
    if ! command_exists unzip; then
        [[ "$mode" == "install" ]] && log_warn "unzip not found — installing..."
        pkg_install unzip >> "$LOG_FILE" 2>&1 || true
    fi

    # Adapt arch tokens in the pattern to match the current system architecture
    if [[ "$SYS_ARCH" != "amd64" ]]; then
        pattern="${pattern//amd64/$SYS_ARCH}"
        pattern="${pattern//x86_64/$SYS_ARCH_ALT}"
        pattern="${pattern//x64/$SYS_ARCH}"
        # Replace standalone 64bit (used by gophish, evilginx, trivy)
        pattern="${pattern//64bit/${SYS_ARCH}}"
    fi

    log_debug "_download_github_release_impl[$mode]: repo=$repo binary=$binary pattern=$pattern"
    log_info "Downloading $binary from $repo releases..."
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local release_json
    release_json=$(_gh_api_get "$api_url")
    if [[ -z "$release_json" ]]; then
        log_error "Could not fetch release info for $binary (API rate limit or network error)$(_disk_hint)"
        return 1
    fi

    # Extract actual release tag for version tracking
    local release_tag=""
    release_tag=$(echo "$release_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('tag_name',''))" 2>/dev/null || true)

    # Set _RELEASE_TAG for update callers
    [[ "$mode" == "update" ]] && _RELEASE_TAG="$release_tag"

    # Parse download URL using Python (portable — no grep -P dependency)
    local download_url
    download_url=$(echo "$release_json" | python3 -c "
import json, sys, re
pattern = sys.argv[1]
data = json.load(sys.stdin)
for asset in data.get('assets', []):
    if re.search(pattern, asset.get('name', '')):
        print(asset['browser_download_url'])
        break
" "$pattern" 2>>"$LOG_FILE")

    if [[ -z "$download_url" ]]; then
        log_error "Could not find release for $binary (pattern: $pattern)"
        return 1
    fi

    log_debug "_download_github_release_impl[$mode]: URL=$download_url"

    local tmp_dir
    tmp_dir=$(mktemp -d); _register_cleanup "$tmp_dir"
    local asset_name
    asset_name=$(basename "$download_url")
    if ! curl -sSL -o "$tmp_dir/$asset_name" "$download_url" >> "$LOG_FILE" 2>&1; then
        log_error "Download failed: $binary$(_disk_hint)"
        rm -rf "$tmp_dir"
        return 1
    fi

    # Verify checksum — fail-closed on mismatch, warn-only if no checksums available
    # --fast skips verification entirely (mutually exclusive with --require-checksums)
    local _action_label="install"
    [[ "$mode" == "update" ]] && _action_label="update"
    if [[ "${FAST_MODE:-false}" != "true" ]] && ! verify_github_checksum "$release_json" "$tmp_dir/$asset_name" "$asset_name"; then
        if [[ -f "$tmp_dir/.checksum_mismatch" ]]; then
            log_error "Aborting $_action_label of $binary due to checksum mismatch"
            rm -rf "$tmp_dir"
            return 1
        fi
        if [[ "${REQUIRE_CHECKSUMS:-false}" == "true" ]]; then
            log_error "Aborting $_action_label of $binary — no checksum file (--require-checksums)"
            rm -rf "$tmp_dir"
            return 1
        fi
    fi

    # Handle archive types — with path traversal protection
    case "$download_url" in
        *.tar.gz|*.tgz)
            # List tar contents first and reject any paths that escape the directory
            if tar tzf "$tmp_dir/$asset_name" 2>/dev/null | grep -qE '(^|/)\.\.(/|$)'; then
                log_error "Tar path traversal detected in $asset_name — aborting"
                rm -rf "$tmp_dir"
                return 1
            fi
            tar xzf "$tmp_dir/$asset_name" -C "$tmp_dir" 2>>"$LOG_FILE" ;;
        *.zip)
            # List zip contents first and reject any paths that escape the directory
            if unzip -l "$tmp_dir/$asset_name" 2>/dev/null | awk 'NR>3{print $4}' | grep -qE '(^|/)\.\.(/|$)'; then
                log_error "Zip path traversal detected in $asset_name — aborting"
                rm -rf "$tmp_dir"
                return 1
            fi
            unzip -qo "$tmp_dir/$asset_name" -d "$tmp_dir" 2>>"$LOG_FILE"
            ;;
        *.deb)
            if [[ "$PKG_MANAGER" != "apt" && "$PKG_MANAGER" != "pkg" ]]; then
                log_error "$binary is a .deb package — not supported on $PKG_MANAGER"
                rm -rf "$tmp_dir"
                return 1
            fi
            if ! maybe_sudo dpkg -i "$tmp_dir/$asset_name" >> "$LOG_FILE" 2>&1; then
                if ! maybe_sudo apt-get install -f -y >> "$LOG_FILE" 2>&1; then
                    [[ "$mode" == "install" ]] && log_error "Failed to install $binary (.deb) — dpkg and dependency fix both failed"
                    rm -rf "$tmp_dir"
                    return 1
                fi
            fi
            rm -rf "$tmp_dir"
            if [[ "$mode" == "install" ]]; then
                if command_exists "$binary"; then
                    log_success "Installed: $binary (.deb)"
                    track_version "$binary" "binary" "${release_tag:-latest}"
                else
                    log_error "Install failed: $binary (.deb) — binary not found after dpkg"
                    return 1
                fi
            fi
            return 0 ;;
        *.jar)
            mkdir -p "$dest_dir" 2>/dev/null || true
            cp "$tmp_dir/$asset_name" "$dest_dir/$binary.jar"
            cat > "$PIPX_BIN_DIR/$binary" << WRAPPER
#!/bin/bash
exec java -jar "$dest_dir/$binary.jar" "\$@"
WRAPPER
            chmod +x "$PIPX_BIN_DIR/$binary"
            rm -rf "$tmp_dir"
            if [[ "$mode" == "install" ]]; then
                log_success "Installed: $binary (.jar)"
                track_version "$binary" "binary" "${release_tag:-latest}"
            fi
            return 0 ;;
        *)
            chmod +x "$tmp_dir/$asset_name" ;;
    esac

    # Find the binary in extracted files
    local found
    found=$(find "$tmp_dir" -name "$binary" -type f 2>/dev/null | head -1)
    if [[ -z "$found" ]]; then
        found=$(find "$tmp_dir" -type f -executable 2>/dev/null | head -1)
    fi
    if [[ -z "$found" ]]; then
        found="$tmp_dir/$asset_name"
    fi

    if [[ "$dest_dir" != "$PIPX_BIN_DIR" ]]; then
        mkdir -p "$dest_dir" 2>/dev/null || true
        cp -a "$tmp_dir"/* "$dest_dir/" 2>/dev/null || true
        local dest_bin=""
        for candidate in \
            "$dest_dir/bin/$binary" \
            "$dest_dir/bin/${binary}.sh" \
            "$dest_dir/$binary" \
            "$dest_dir/${binary}.sh"; do
            if [[ -f "$candidate" ]]; then
                dest_bin="$candidate"
                break
            fi
        done
        if [[ -z "$dest_bin" ]]; then
            dest_bin=$(find "$dest_dir" \( -name "$binary" -o -name "${binary}.sh" \) -type f 2>/dev/null | head -1)
        fi
        if [[ -n "$dest_bin" ]]; then
            chmod +x "$dest_bin" 2>/dev/null || true
            ln -sf "$dest_bin" "$PIPX_BIN_DIR/$binary" 2>/dev/null || true
        fi
    else
        install -m 755 "$found" "$dest_dir/$binary" 2>>"$LOG_FILE"
    fi
    rm -rf "$tmp_dir"

    if [[ "$mode" == "install" ]]; then
        if command_exists "$binary"; then
            log_success "Installed: $binary"
            echo "${release_tag:-latest}" > "${dest_dir}/.${binary}.vtag"
        elif [[ -f "$dest_dir/$binary" ]] || [[ -f "$dest_dir/bin/$binary" ]]; then
            log_success "Installed: $binary (in $dest_dir)"
            echo "${release_tag:-latest}" > "${dest_dir}/.${binary}.vtag"
        else
            log_error "Install failed: $binary"
            return 1
        fi
    fi
}

# Download GitHub release binary (install mode — skips if already installed)
# Usage: download_github_release "owner/repo" "binary_name" "filename_pattern" [dest_dir]
download_github_release() {
    local repo="$1"
    local binary="$2"
    local pattern="$3"
    local dest_dir="${4:-$PIPX_BIN_DIR}"

    if [[ "${SKIP_BINARY:-false}" == "true" ]]; then
        log_warn "Skipping binary release: $binary (--skip-binary)"
        return 0
    fi
    if command_exists "$binary"; then
        log_success "Already installed: $binary"
        track_version "$binary" "binary" "existing"
        return 0
    fi
    _download_github_release_impl "$repo" "$binary" "$pattern" "$dest_dir" "install"
    local _rc=$?
    # Consume vtag sidecar for version tracking (written by _download_github_release_impl).
    # The file is intentionally NOT deleted here — parallel callers read it separately.
    local _vtag_file="${dest_dir}/.${binary}.vtag"
    if [[ -f "$_vtag_file" ]]; then
        track_version "$binary" "binary" "$(< "$_vtag_file")"
    fi
    return $_rc
}

# Download GitHub release binary (update mode — no skip)
# Used by scripts/update.sh to force re-download when a new version is detected.
# Returns the release tag via the global _RELEASE_TAG variable.
_RELEASE_TAG=""
download_github_release_update() {
    local repo="$1"
    local binary="$2"
    local pattern="$3"
    local dest_dir="${4:-$PIPX_BIN_DIR}"
    _RELEASE_TAG=""
    _download_github_release_impl "$repo" "$binary" "$pattern" "$dest_dir" "update"
}

# Docker image pull
docker_pull() {
    local image="$1"
    local name="$2"

    if ! command_exists docker; then
        log_warn "Docker not installed — skipping $name"
        return 1
    fi

    _start_spinner "Pulling Docker image: $name..."
    if docker pull "$image" >> "$LOG_FILE" 2>&1; then
        _stop_spinner
        log_success "Docker: $name ready"
        track_version "$name" "docker" "$image"
    else
        _stop_spinner
        log_error "Docker pull failed: $name"
        TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        return 1
    fi
}

# Version tracking — atomic write via temp file + rename (safe under parallel load)
track_version() {
    local tool="$1"
    local method="$2"
    local version="$3"
    local version_file="${VERSION_FILE:-$SCRIPT_DIR/.versions}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Record in session manifest (if a session is active)
    track_session "$tool" "$method" "installed" 2>/dev/null || true

    # Inner logic shared between locked and unlocked paths
    _tv_write() {
        if [[ ! -f "$version_file" ]]; then
            echo "# tool|method|version|last_updated" > "$version_file"
            chmod 644 "$version_file" 2>/dev/null || true
        fi
        local tmp_file
        tmp_file=$(mktemp "${version_file}.XXXXXX")
        grep -v "^${tool}|" "$version_file" > "$tmp_file" 2>/dev/null || true
        echo "${tool}|${method}|${version}|${timestamp}" >> "$tmp_file"
        mv -f "$tmp_file" "$version_file"
    }

    # Use flock when available (parallel safety), fall back to mkdir-based lock
    if command -v flock &>/dev/null; then
        (
            flock -x 200
            _tv_write
        ) 200>"${version_file}.lock"
    else
        # mkdir is atomic on all POSIX systems — use as spinlock fallback
        local _lockdir="${version_file}.lockdir" _tries=0
        while ! mkdir "$_lockdir" 2>/dev/null; do
            _tries=$((_tries + 1))
            [[ "$_tries" -ge 50 ]] && break  # give up after ~5s
            sleep 0.1
        done
        _tv_write
        rmdir "$_lockdir" 2>/dev/null || true
    fi
}

# Build from source helper
build_from_source() {
    local name="$1"
    local url="$2"
    local build_cmd="$3"
    local dest="$GITHUB_TOOL_DIR/$name"

    if [[ "${SKIP_SOURCE:-false}" == "true" ]]; then
        log_warn "Skipping build-from-source: $name (--skip-source)"
        return 0
    fi

    # Termux: build-from-source tools assume glibc/x86 — skip entirely
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        log_warn "Skipping build-from-source on Termux: $name"
        return 0
    fi

    _start_spinner "Building $name..."
    if ! git_clone_or_pull "$url" "$dest" >> "$LOG_FILE" 2>&1; then
        _stop_spinner
        log_error "Clone failed: $name"
        TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        return 1
    fi
    # Run build in a subshell to avoid changing the caller's working directory.
    # Uses _as_builder for privilege dropping (build as user, not root).
    if (cd "$dest" && _as_builder "$build_cmd") >> "$LOG_FILE" 2>&1; then
        _stop_spinner
        log_success "Built: $name"
        track_version "$name" "source" "HEAD"
    else
        _stop_spinner
        log_error "Build failed: $name"
        log_error "  Check the log for details: $LOG_FILE"
        log_error "  Use --skip-source to skip all build-from-source tools"
        TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        return 1
    fi
}

# Binary release registry (single source of truth) 
# Format: "repo|binary|pattern|dest_dir" (dest_dir optional, defaults to $PIPX_BIN_DIR)
# Used by modules for install and scripts/update.sh for updates.
BINARY_RELEASES_MISC=(
    "DominicBreuker/pspy|pspy|pspy64$"
    "gophish/gophish|gophish|linux-64bit"
    "trufflesecurity/trufflehog|trufflehog|linux_amd64\\.tar\\.gz"
    "gitleaks/gitleaks|gitleaks|linux_x64\\.tar\\.gz"
    "BishopFox/sliver|sliver-server|sliver-server_linux-amd64$"
    "BishopFox/sliver|sliver-client|sliver-client_linux-amd64$"
    "kgretzky/evilginx2|evilginx|linux-64bit\\.zip"
)
BINARY_RELEASES_NETWORKING=(
    "nicocha30/ligolo-ng|ligolo-proxy|linux_amd64"
    "nicocha30/ligolo-ng|ligolo-agent|agent.*linux_amd64"
    "fatedier/frp|frpc|linux_amd64\\.tar\\.gz"
    "fatedier/frp|frps|linux_amd64\\.tar\\.gz"
)
BINARY_RELEASES_RECON=(
    "Findomain/Findomain|findomain|findomain-linux\\.zip$"
    "sundowndev/phoneinfoga|phoneinfoga|Linux_x86_64\\.tar\\.gz"
)
BINARY_RELEASES_WEB=(
    "frohoff/ysoserial|ysoserial|ysoserial-all.jar|${GITHUB_TOOL_DIR}/cybersec-jars"
    "assetnote/kiterunner|kr|linux_amd64"
)
BINARY_RELEASES_REVERSING=(
    "0vercl0k/rp|rp-lin|rp-lin"
    "java-decompiler/jd-gui|jd-gui|jd-gui.*\\.jar|${GITHUB_TOOL_DIR}/cybersec-jars"
)
BINARY_RELEASES_FORENSICS=(
    "WithSecureLabs/chainsaw|chainsaw|x86_64.*linux"
)
BINARY_RELEASES_ENTERPRISE=(
    "ropnop/kerbrute|kerbrute|linux_amd64"
)
BINARY_RELEASES_BLUETEAM=(
    "Velocidex/velociraptor|velociraptor|linux-amd64$"
    "threathunters-io/laurel|laurel|x86_64-glibc"
    "mandiant/flare-floss|floss|linux\\.zip"
    "mandiant/capa|capa|linux\\.zip"
    "Neo23x0/Loki-RS|loki|loki-linux-x86_64.*\\.tar\\.gz"
)
BINARY_RELEASES_CONTAINERS=(
    "aquasecurity/trivy|trivy|Linux-64bit\\.tar\\.gz"
    "anchore/grype|grype|linux_amd64\\.tar\\.gz"
    "anchore/syft|syft|linux_amd64\\.tar\\.gz"
    "Shopify/kubeaudit|kubeaudit|linux_amd64\\.tar\\.gz"
    "kubescape/kubescape|kubescape|linux_amd64\\.tar\\.gz"
    "cdk-team/CDK|cdk|cdk_linux_amd64"
)
BINARY_RELEASES_MOBILE=(
    "skylot/jadx|jadx|jadx.*\\.zip|${GITHUB_TOOL_DIR}/jadx"
    "pxb1988/dex2jar|d2j-dex2jar|dex-tools.*\\.zip|${GITHUB_TOOL_DIR}/dex2jar"
)
BINARY_RELEASES_STEGO=(
    "RickdeJager/stegseek|stegseek|\\.deb"
)

# Docker image registry (single source of truth)
# Format: "image|label"
# Used by modules for install and scripts for update/remove/verify.
ALL_DOCKER_IMAGES=(
    "beefproject/beef|BeEF"
    "bcsecurity/empire|Empire"
    "opensecurity/mobile-security-framework-mobsf|MobSF"
    "spiderfoot/spiderfoot|SpiderFoot"
    "specterops/bloodhound|BloodHound CE"
    "strangebee/thehive:latest|TheHive"
    "thehiveproject/cortex:latest|Cortex"
    "trailofbits/echidna|Echidna"
    "vxcontrol/pentagi:latest|PentAGI"
)

# install_binary_releases — install all binary releases from a registry array.
# Usage: install_binary_releases "${BINARY_RELEASES_MISC[@]}"
# Supports parallel downloads when PARALLEL_JOBS > 1 (~3-4x faster, network I/O bound).
# Skipped on Termux/Android — most GitHub release assets are Linux/glibc and won't run.
install_binary_releases() {
    [[ "${_SKIP_BATCH_REINSTALL:-false}" == "true" ]] && return 0
    local -a entries=("$@")
    local total=${#entries[@]}
    [[ "$total" -eq 0 ]] && return 0

    if [[ "${SKIP_BINARY:-false}" == "true" ]]; then
        log_warn "Skipping binary releases (--skip-binary)"
        _report_method_total "Binary" 0
        return 0
    fi

    # Termux: GitHub release binaries are almost always Linux/glibc — skip entirely
    if [[ "$PKG_MANAGER" == "pkg" ]]; then
        log_warn "Skipping $total binary release(s) on Termux (Linux/glibc binaries)"
        _report_method_total "Binary" 0
        return 0
    fi

    # ARM: filter out x86-only binary releases that have no ARM builds
    if [[ "$IS_ARM" == "true" ]]; then
        local -a _arm_filtered=()
        local -a _arm_skip_bins=(pspy rp-lin chainsaw velociraptor laurel)
        for _entry in "${entries[@]}"; do
            IFS='|' read -r _repo _binary _pattern _dest <<< "$_entry"
            local _skip=false
            for _sb in "${_arm_skip_bins[@]}"; do
                if [[ "$_binary" == "$_sb" ]]; then
                    _skip=true
                    break
                fi
            done
            if [[ "$_skip" == "true" ]]; then
                log_warn "Skipping x86-only binary on ARM: $_binary"
            else
                _arm_filtered+=("$_entry")
            fi
        done
        if [[ ${#_arm_filtered[@]} -gt 0 ]]; then
            entries=("${_arm_filtered[@]}")
        else
            entries=()
        fi
        total=${#entries[@]}
        [[ "$total" -eq 0 ]] && return 0
    fi

    log_debug "install_binary_releases: starting with $total items, PARALLEL_JOBS=$PARALLEL_JOBS"
    local _batch_start; _batch_start=$(date +%s)
    _report_method_total "Binary" "$total"

    # Initialize shared API cache before forking — all subshells inherit the same dir
    _gh_api_cache_init

    if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
        # --- Parallel mode ---
        local _results_dir; _results_dir=$(mktemp -d); _register_cleanup "$_results_dir"

        for _entry in "${entries[@]}"; do
            IFS='|' read -r _repo _binary _pattern _dest <<< "$_entry"
            _dest="${_dest:-$PIPX_BIN_DIR}"

            # Skip-check in main process (avoid spawning a job for already-installed tools)
            if command_exists "$_binary"; then
                log_success "Already installed: $_binary"
                printf 'skip\nexisting\n' > "$_results_dir/$_binary"
                _report_tool_done "Binary" "$_binary" "skip"
                continue
            fi

            _wait_for_job_slot

            (
                trap '_release_job_slot' EXIT
                _report_tool_start "Binary" "$_binary"
                if download_github_release "$_repo" "$_binary" "$_pattern" "$_dest" >> "$LOG_FILE" 2>&1; then
                    # Read version from vtag sidecar (written by _download_github_release_impl)
                    local _stored_ver=""
                    local _vtag_file="${_dest}/.${_binary}.vtag"
                    [[ -f "$_vtag_file" ]] && { _stored_ver=$(< "$_vtag_file"); rm -f "$_vtag_file"; }
                    printf 'ok\n%s\n' "${_stored_ver:-latest}" > "$_results_dir/$_binary"
                    _report_tool_done "Binary" "$_binary" "ok"
                else
                    log_error "Failed binary: $_binary ($_repo)"
                    printf 'fail\n\n' > "$_results_dir/$_binary"
                    _report_tool_done "Binary" "$_binary" "fail"
                fi
            ) &
        done
        wait

        _collect_parallel_results "$_results_dir" "binary"
        # shellcheck disable=SC2154  # _par_failed/_par_skipped set by _collect_parallel_results
        local failed=$_par_failed skipped=$_par_skipped
        [[ "$failed" -gt 0 ]] && TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed))
        log_success "Binary releases: $((total - failed - skipped))/$total new, ${skipped} existing, ${failed} failed"
    else
        # --- Sequential mode (original) ---
        local failed=0
        for _entry in "${entries[@]}"; do
            IFS='|' read -r _repo _binary _pattern _dest <<< "$_entry"
            _report_tool_start "Binary" "$_binary"
            if ! download_github_release "$_repo" "$_binary" "$_pattern" "${_dest:-$PIPX_BIN_DIR}"; then
                failed=$((failed + 1))
                _report_tool_done "Binary" "$_binary" "fail"
            else
                _report_tool_done "Binary" "$_binary" "ok"
            fi
        done
        [[ "$failed" -gt 0 ]] && TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + failed))
    fi

    local _batch_elapsed=$(( $(date +%s) - _batch_start ))
    log_debug "install_binary_releases: completed in ${_batch_elapsed}s"
}

# Install searchsploit symlink
install_searchsploit_symlink() {
    if [[ -f "$GITHUB_TOOL_DIR/exploitdb/searchsploit" ]]; then
        ln -sf "$GITHUB_TOOL_DIR/exploitdb/searchsploit" "$PIPX_BIN_DIR/searchsploit" 2>/dev/null
    fi
}

# Metasploit
# Install order: apt (Kali/Parrot repos) → snap → Rapid7 script → apt.metasploit.com repo
install_metasploit() {
    if command_exists msfconsole; then
        log_success "Metasploit already installed"
        return 0
    fi

    log_info "Installing Metasploit Framework..."

    # 1) Prefer system package (available on Debian/Kali/Parrot with their repos)
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        _start_spinner "Installing Metasploit via apt..."
        if pkg_install metasploit-framework >> "$LOG_FILE" 2>&1; then
            _stop_spinner
            log_success "Metasploit installed via apt"
            track_version "metasploit" "$PKG_MANAGER" "system"
            return 0
        fi
        _stop_spinner
        log_warn "metasploit-framework not in apt repos — trying snap"
    fi

    # 2) Snap — primary method for standard Ubuntu/Debian (not available in Docker)
    if [[ "${SKIP_SOURCE:-false}" != "true" ]] && [[ "$IS_DOCKER" != "true" ]]; then
        if ensure_snap; then
            _start_spinner "Installing Metasploit via snap..."
            if snap_install metasploit-framework >> "$LOG_FILE" 2>&1; then
                _stop_spinner
                log_success "Metasploit installed via snap"
                track_version "metasploit" "snap" "latest"
                return 0
            fi
            _stop_spinner
            log_warn "Metasploit snap install failed — trying Rapid7 installer"
        else
            log_warn "snap not available — trying Rapid7 installer"
        fi
    fi

    # 3) Fallback: official Rapid7 installer script (with basic verification)
    local tmp_installer
    tmp_installer=$(mktemp); _register_cleanup "$tmp_installer"
    local msf_url="https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb"
    if ! curl -fsSL "$msf_url" -o "$tmp_installer" 2>> "$LOG_FILE"; then
        log_error "Failed to download Metasploit installer"
        rm -f "$tmp_installer"
        # Don't return yet — try apt.metasploit.com repo below
    else
        # Content verification — check multiple Rapid7/Metasploit-specific markers
        # to reduce risk of running a spoofed script. A legitimate msfupdate.erb
        # contains all of these strings.
        local _msf_checks=0
        grep -q "metasploit" "$tmp_installer" 2>/dev/null && _msf_checks=$((_msf_checks + 1))
        grep -q "rapid7" "$tmp_installer" 2>/dev/null && _msf_checks=$((_msf_checks + 1))
        grep -q "msfupdate\|msfconsole\|metasploit-framework" "$tmp_installer" 2>/dev/null && _msf_checks=$((_msf_checks + 1))
        grep -q "apt\|dpkg\|yum\|rpm" "$tmp_installer" 2>/dev/null && _msf_checks=$((_msf_checks + 1))
        if [[ "$_msf_checks" -lt 3 ]]; then
            log_error "Metasploit installer content verification failed (only $_msf_checks/4 markers matched) — skipping"
        else
            chmod 755 "$tmp_installer"
            _start_spinner "Installing Metasploit via Rapid7 installer..."
            if "$tmp_installer" >> "$LOG_FILE" 2>&1; then
                _stop_spinner
                log_success "Metasploit installed via Rapid7 script"
                track_version "metasploit" "special" "latest"
                rm -f "$tmp_installer"
                return 0
            fi
            _stop_spinner
        fi
    fi
    rm -f "$tmp_installer"

    # 4) Last resort: manually add apt.metasploit.com repo (modern signed-by keyring)
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        log_warn "Rapid7 script failed — trying manual apt.metasploit.com repo setup"
        local _keyring="/usr/share/keyrings/metasploit-framework.gpg"
        local _tmp_key
        _tmp_key=$(mktemp); _register_cleanup "$_tmp_key"
        if curl -fsSL "https://apt.metasploit.com/metasploit-framework.gpg.key" -o "$_tmp_key" 2>>"$LOG_FILE"; then
            # Verify downloaded key is non-empty before processing
            if [[ ! -s "$_tmp_key" ]]; then
                log_error "Metasploit GPG key download produced empty file"
                rm -f "$_tmp_key"
                return 1
            fi
            # Verify GPG key fingerprint before trusting
            # Try --show-keys (GnuPG >= 2.2.8), fall back to --with-fingerprint
            local _fp=""
            local _gpg_tmp; _gpg_tmp=$(mktemp -d); _register_cleanup "$_gpg_tmp"
            _fp=$(gpg --homedir "$_gpg_tmp" --with-colons --show-keys "$_tmp_key" 2>/dev/null \
                | awk -F: '/^fpr:/{print $10; exit}') || true
            if [[ -z "$_fp" ]]; then
                _fp=$(gpg --homedir "$_gpg_tmp" --with-colons --import-options show-only --import "$_tmp_key" 2>/dev/null \
                    | awk -F: '/^fpr:/{print $10; exit}') || true
            fi
            if [[ -z "$_fp" ]]; then
                _fp=$(gpg --homedir "$_gpg_tmp" --with-fingerprint "$_tmp_key" 2>/dev/null \
                    | grep -oE '[A-F0-9 ]{40,}' | tr -d ' ' | head -1) || true
            fi
            rm -rf "$_gpg_tmp"
            if [[ -z "$_fp" ]]; then
                log_error "Could not extract Metasploit GPG key fingerprint — skipping repo setup"
                rm -f "$_tmp_key"
                return 1
            fi
            if [[ "$_fp" != "CEC43851245B2886296060A827FF0E3B4BAE526D" ]]; then
                log_error "Metasploit GPG key fingerprint mismatch (got: $_fp) — refusing to trust"
                rm -f "$_tmp_key"
                return 1
            fi
            gpg --dearmor < "$_tmp_key" 2>/dev/null > "$_keyring"
        fi
        rm -f "$_tmp_key"
        if [[ -f "$_keyring" ]]; then
            # "xenial" is Rapid7's universal release name — it works on all Debian/Ubuntu distros
            echo "deb [signed-by=$_keyring] https://apt.metasploit.com/ xenial main" \
                > /etc/apt/sources.list.d/metasploit-framework.list
            pkg_update >> "$LOG_FILE" 2>&1
            _start_spinner "Installing Metasploit via apt.metasploit.com..."
            if pkg_install metasploit-framework >> "$LOG_FILE" 2>&1; then
                _stop_spinner
                log_success "Metasploit installed via apt.metasploit.com"
                track_version "metasploit" "$PKG_MANAGER" "latest"
                return 0
            fi
            _stop_spinner
        fi
    fi

    log_error "All Metasploit installation methods failed"
    TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
    return 1
}


# OWASP ZAP
install_zap() {
    if command_exists zaproxy; then
        log_success "OWASP ZAP already installed"
        return 0
    fi
    if [[ "$IS_DOCKER" == "true" ]]; then
        log_warn "OWASP ZAP requires snap (unavailable in Docker) — skipping"
        return 0
    fi
    if snap_available; then
        _start_spinner "Installing OWASP ZAP via snap..."
        if snap_install zaproxy --classic >> "$LOG_FILE" 2>&1; then
            _stop_spinner
            log_success "OWASP ZAP installed"
            track_version "zaproxy" "snap" "latest"
        else
            _stop_spinner
            log_error "OWASP ZAP snap install failed"
            TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
            return 1
        fi
    else
        log_warn "snap not available — install OWASP ZAP manually"
    fi
}
