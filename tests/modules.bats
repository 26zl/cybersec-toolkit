#!/usr/bin/env bats
# Tests for module files in modules/*.sh
# Validates install functions, array naming, git format, Go @latest suffix

setup() {
    load 'test_helper'
    source_libs --installers debian apt

    for mod in "${ALL_MODULES[@]}"; do
        source "$PROJECT_ROOT/modules/${mod}.sh"
    done
}

@test "all 18 module files exist" {
    for mod in "${ALL_MODULES[@]}"; do
        [[ -f "$PROJECT_ROOT/modules/${mod}.sh" ]] || { echo "Missing: modules/${mod}.sh"; return 1; }
    done
}

@test "each module defines install_module_<name> function" {
    for mod in "${ALL_MODULES[@]}"; do
        local func="install_module_${mod}"
        declare -f "$func" > /dev/null 2>&1 || { echo "Missing function: $func"; return 1; }
    done
}

# Array naming convention

@test "modules define arrays with correct prefixes" {
    # Check that at least the primary array types exist for each module
    # Not all modules have all array types, but each should have at least one
    for mod in "${ALL_MODULES[@]}"; do
        local prefix
        prefix=$(_module_prefix "$mod")
        [[ -n "$prefix" ]] || { echo "No prefix mapping for: $mod"; return 1; }

        # At least one of these arrays should be declared
        local found=false
        for suffix in PACKAGES HEAVY_PACKAGES PIPX GO GIT CARGO GEMS; do
            local arr_name="${prefix}_${suffix}"
            if declare -p "$arr_name" &>/dev/null; then
                found=true
                break
            fi
        done
        [[ "$found" == true ]] || { echo "No arrays found for module $mod (prefix: $prefix)"; return 1; }
    done
}

@test "all git arrays use name=url format" {
    local git_arrays=(
        MISC_GIT NET_GIT RECON_GIT WEB_GIT CRYPTO_GIT PWN_GIT RE_GIT
        FORENSICS_GIT ENTERPRISE_GIT WIRELESS_GIT CRACKING_GIT STEGO_GIT
        CLOUD_GIT CONTAINER_GIT BLUETEAM_GIT MOBILE_GIT BLOCKCHAIN_GIT LLM_GIT
    )

    for arr_name in "${git_arrays[@]}"; do
        declare -p "$arr_name" &>/dev/null || continue
        local -n arr="$arr_name"
        [[ ${#arr[@]} -eq 0 ]] && continue

        for entry in "${arr[@]}"; do
            [[ "$entry" == *"="* ]] || { echo "$arr_name: entry missing '=' separator: $entry"; return 1; }
            # URL part should start with https://
            local url="${entry#*=}"
            [[ "$url" == https://* ]] || { echo "$arr_name: URL doesn't start with https://: $url"; return 1; }
        done
    done
}

@test "all Go tool paths end with @latest" {
    local go_arrays=() mod
    for mod in "${ALL_MODULES[@]}"; do go_arrays+=("$(_module_prefix "$mod")_GO"); done

    for arr_name in "${go_arrays[@]}"; do
        declare -p "$arr_name" &>/dev/null || continue
        local -n arr="$arr_name"
        [[ ${#arr[@]} -eq 0 ]] && continue

        for gopkg in "${arr[@]}"; do
            [[ "$gopkg" == *"@latest" ]] || { echo "$arr_name: missing @latest suffix: $gopkg"; return 1; }
        done
    done
}

@test "no duplicate entries in pipx arrays" {
    local pipx_arrays=() mod
    for mod in "${ALL_MODULES[@]}"; do pipx_arrays+=("$(_module_prefix "$mod")_PIPX"); done

    for arr_name in "${pipx_arrays[@]}"; do
        declare -p "$arr_name" &>/dev/null || continue
        local -n arr="$arr_name"
        [[ ${#arr[@]} -eq 0 ]] && continue

        # Check for duplicates using sort -u
        local sorted
        sorted=$(printf '%s\n' "${arr[@]}" | sort)
        local unique
        unique=$(printf '%s\n' "${arr[@]}" | sort -u)
        [[ "$sorted" == "$unique" ]] || { echo "$arr_name has duplicate entries"; return 1; }
    done
}

# verify.sh and remove.sh work from the name arrays, so they must list exactly
# what the install arrays install, in the same order.
@test "name arrays match the git and Go install arrays of every module" {
    local mod prefix pair entry
    for mod in "${ALL_MODULES[@]}"; do
        prefix=$(_module_prefix "$mod")
        for pair in GIT:GIT_NAMES C2_GIT:C2_GIT_NAMES GO:GO_BINS; do
            local src="${prefix}_${pair%%:*}" names="${prefix}_${pair##*:}"
            declare -p "$src" &>/dev/null || continue
            local -n src_ref="$src"
            local -a derived=()
            for entry in "${src_ref[@]}"; do
                if [[ "$pair" == GO:* ]]; then
                    derived+=("$(_go_bin_name "$entry")")
                else
                    derived+=("${entry%%=*}")
                fi
            done
            [[ ${#derived[@]} -eq 0 ]] && continue
            declare -p "$names" &>/dev/null || { echo "Missing $names for $src"; return 1; }
            local -n names_ref="$names"
            [[ "$(printf '%s\n' "${derived[@]}")" == "$(printf '%s\n' "${names_ref[@]}")" ]] \
                || { echo "$names does not match $src"; return 1; }
        done
    done
}

@test "pipx arrays hold no names that resolve to unrelated PyPI projects" {
    local mod arr_name entry
    for mod in "${ALL_MODULES[@]}"; do
        arr_name="$(_module_prefix "$mod")_PIPX"
        declare -p "$arr_name" &>/dev/null || continue
        local -n arr="$arr_name"
        for entry in ${arr[@]+"${arr[@]}"}; do
            [[ "$entry" != manspider && "$entry" != commix ]] || { echo "$arr_name: $entry is not the upstream tool"; return 1; }
        done
    done
    [[ " ${ENTERPRISE_PIPX[*]} " == *" man-spider "* ]]
}

@test "commix installs from upstream git and apktool from apt" {
    [[ " ${WEB_GIT_NAMES[*]} " == *" commix "* ]]
    [[ "$(printf '%s\n' "${WEB_GIT[@]}" | grep '^commix=')" == "commix=https://github.com/commixproject/commix.git" ]]
    [[ " ${MOBILE_PACKAGES[*]} " == *" apktool "* ]]
    [[ " ${MOBILE_GIT_NAMES[*]} " != *" apktool "* ]]
}

@test "SpiderFoot is a git tool and no module pulls the nonexistent Docker image" {
    [[ " ${RECON_GIT_NAMES[*]} " == *" spiderfoot "* ]]
    [[ " ${MISC_GIT_NAMES[*]} " != *" spiderfoot "* ]]
    run grep -n 'spiderfoot/spiderfoot' "$PROJECT_ROOT"/modules/*.sh
    assert_failure
}

@test "every docker_pull image in modules is listed in ALL_DOCKER_IMAGES" {
    local image
    while read -r image; do
        printf '%s\n' "${ALL_DOCKER_IMAGES[@]}" | grep -q "^${image}|" || { echo "not in ALL_DOCKER_IMAGES: $image"; return 1; }
    done < <(grep -h -o 'docker_pull "[^"$]*"' "$PROJECT_ROOT"/modules/*.sh | sed 's/docker_pull "//; s/"$//')
}

@test "registry URLs do not use renamed GitHub owners" {
    run grep -n -E 'BloodHoundAD/AzureHound|FortyNorthSecurity/EyeWitness|p1ngul1n0/blackbird|soxrok2212/PSKracker|spipm/Depix[.". ]|mitre/caldera|SecuraBV/CVE-2020-1472|WithSecureLabs/chainsaw' \
        "$PROJECT_ROOT"/modules/*.sh "$PROJECT_ROOT/lib/installers.sh" "$PROJECT_ROOT/tools_config.json"
    assert_failure
}

@test "every *_HEAVY_PACKAGES array is non-empty" {
    local mod arr_name
    for mod in "${ALL_MODULES[@]}"; do
        arr_name="$(_module_prefix "$mod")_HEAVY_PACKAGES"
        declare -p "$arr_name" &>/dev/null || continue
        local -n arr="$arr_name"
        [[ ${#arr[@]} -gt 0 ]] || { echo "$arr_name is empty"; return 1; }
    done
}

# Module-level gating of C2 frameworks and heavy packages

_gating_fixture() {
    make_test_tmpdir
    ENABLE_DOCKER=false
    INCLUDE_C2=false
    SKIP_HEAVY=false
    SKIP_SOURCE=true
    PKG_MANAGER=apt
    CALLS="$TEST_TMPDIR/calls"
    : > "$CALLS"
    local fn
    for fn in install_apt_batch install_pipx_batch install_go_batch install_cargo_batch \
        install_gem_batch install_git_batch install_npm_batch; do
        eval "$fn() { { printf '%s' '$fn'; printf ' %s' \"\$@\"; printf '\\n'; } >> \"\$CALLS\"; }"
    done
    install_binary_releases() { { printf 'install_binary_releases'; printf ' %s' "$@"; printf '\n'; } >> "$CALLS"; }
    docker_pull() { printf 'docker_pull %s\n' "$1" >> "$CALLS"; }
    build_module_from_source() { :; }
    install_metasploit() { :; }
    install_searchsploit_symlink() { :; }
    install_zap() { :; }
}

_never_called() {
    ! grep -q "$1" "$CALLS" || { echo "unexpected call matching: $1"; return 1; }
}

@test "misc module passes C2 git and binary entries only with INCLUDE_C2" {
    _gating_fixture
    install_module_misc
    _never_called 'Zphisher\|Mythic' || return 1
    _never_called '^docker_pull bcsecurity/empire' || return 1
    _never_called '^docker_pull' || return 1
    INCLUDE_C2=true
    ENABLE_DOCKER=true
    : > "$CALLS"
    install_module_misc
    grep -q 'Zphisher' "$CALLS"
    grep -q 'Mythic' "$CALLS"
    grep -qx 'docker_pull bcsecurity/empire' "$CALLS"
}

@test "extract_seclists_rockyou unpacks the tarball once and leaves existing files alone" {
    source "$PROJECT_ROOT/modules/misc.sh"
    GITHUB_TOOL_DIR="$BATS_TEST_TMPDIR/tools"
    local dir="$GITHUB_TOOL_DIR/SecLists/Passwords/Leaked-Databases"
    mkdir -p "$dir" "$BATS_TEST_TMPDIR/src"
    printf 'password\n' > "$BATS_TEST_TMPDIR/src/rockyou.txt"
    tar -czf "$dir/rockyou.txt.tar.gz" -C "$BATS_TEST_TMPDIR/src" rockyou.txt
    extract_seclists_rockyou
    [[ "$(cat "$dir/rockyou.txt")" == "password" ]]
    printf 'edited\n' > "$dir/rockyou.txt"
    extract_seclists_rockyou
    [[ "$(cat "$dir/rockyou.txt")" == "edited" ]]
}

@test "extract_seclists_rockyou is a no-op without the archive" {
    source "$PROJECT_ROOT/modules/misc.sh"
    GITHUB_TOOL_DIR="$BATS_TEST_TMPDIR/none"
    run extract_seclists_rockyou
    assert_success
}

@test "extract_seclists_rockyou rejects linked archive members" {
    GITHUB_TOOL_DIR="$BATS_TEST_TMPDIR/tools"
    local dir="$GITHUB_TOOL_DIR/SecLists/Passwords/Leaked-Databases"
    mkdir -p "$dir" "$BATS_TEST_TMPDIR/src"
    printf 'outside\n' > "$BATS_TEST_TMPDIR/outside"
    ln -s "$BATS_TEST_TMPDIR/outside" "$BATS_TEST_TMPDIR/src/rockyou.txt"
    tar -czf "$dir/rockyou.txt.tar.gz" -C "$BATS_TEST_TMPDIR/src" rockyou.txt

    run extract_seclists_rockyou

    assert_failure
    [[ ! -e "$dir/rockyou.txt" && ! -L "$dir/rockyou.txt" ]]
    [[ "$(cat "$BATS_TEST_TMPDIR/outside")" == outside ]]
}

@test "extract_seclists_rockyou ignores other members and never follows existing clone links" {
    GITHUB_TOOL_DIR="$BATS_TEST_TMPDIR/tools"
    local dir="$GITHUB_TOOL_DIR/SecLists/Passwords/Leaked-Databases"
    mkdir -p "$dir" "$BATS_TEST_TMPDIR/src/linked" "$BATS_TEST_TMPDIR/outside"
    printf 'outside\n' > "$BATS_TEST_TMPDIR/outside/notes"
    printf 'replacement\n' > "$BATS_TEST_TMPDIR/src/linked/notes"
    printf 'wordlist\n' > "$BATS_TEST_TMPDIR/src/rockyou.txt"
    ln -s "$BATS_TEST_TMPDIR/outside" "$dir/linked"
    tar -czf "$dir/rockyou.txt.tar.gz" -C "$BATS_TEST_TMPDIR/src" rockyou.txt linked/notes

    run extract_seclists_rockyou

    assert_success
    [[ "$(cat "$dir/rockyou.txt")" == wordlist ]]
    [[ "$(cat "$BATS_TEST_TMPDIR/outside/notes")" == outside ]]
}

@test "extract_seclists_rockyou preserves an existing dangling output link" {
    GITHUB_TOOL_DIR="$BATS_TEST_TMPDIR/tools"
    local dir="$GITHUB_TOOL_DIR/SecLists/Passwords/Leaked-Databases"
    mkdir -p "$dir" "$BATS_TEST_TMPDIR/src"
    printf 'wordlist\n' > "$BATS_TEST_TMPDIR/src/rockyou.txt"
    tar -czf "$dir/rockyou.txt.tar.gz" -C "$BATS_TEST_TMPDIR/src" rockyou.txt
    ln -s "$BATS_TEST_TMPDIR/missing" "$dir/rockyou.txt"

    run extract_seclists_rockyou

    assert_success
    [[ -L "$dir/rockyou.txt" && ! -e "$BATS_TEST_TMPDIR/missing" ]]
}

@test "misc module with Docker but without INCLUDE_C2 skips Empire" {
    _gating_fixture
    ENABLE_DOCKER=true
    install_module_misc
    _never_called 'bcsecurity/empire' || return 1
}

@test "pwn module passes C2 git entries only with INCLUDE_C2" {
    _gating_fixture
    source "$PROJECT_ROOT/modules/pwn.sh"
    local first="${PWN_C2_GIT[0]%%=*}"
    install_module_pwn
    _never_called "$first=" || return 1
    INCLUDE_C2=true
    : > "$CALLS"
    install_module_pwn
    grep -q "$first=" "$CALLS"
}

@test "wireless module gates phishing frameworks on INCLUDE_C2 and heavy packages on SKIP_HEAVY" {
    _gating_fixture
    source "$PROJECT_ROOT/modules/wireless.sh"
    local c2="${WIRELESS_C2_GIT[0]%%=*}"
    SKIP_HEAVY=true
    install_module_wireless
    _never_called "$c2=" || return 1
    _never_called 'gnuradio' || return 1
    SKIP_HEAVY=false
    INCLUDE_C2=true
    : > "$CALLS"
    install_module_wireless
    grep -q "$c2=" "$CALLS"
    grep -q 'gnuradio' "$CALLS"
}

@test "web module exposes commix through a python3 wrapper, not a link to the python-shebang script" {
    _gating_fixture
    GITHUB_TOOL_DIR="$TEST_TMPDIR/tools"
    PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    LOG_FILE="$TEST_TMPDIR/log"
    mkdir -p "$GITHUB_TOOL_DIR/commix" "$PIPX_BIN_DIR" "$TEST_TMPDIR/stubs"
    printf '#!/usr/bin/env python\nprint("commix")\n' > "$GITHUB_TOOL_DIR/commix/commix.py"
    printf '#!/bin/bash\necho "python3 ran: $*"\n' > "$TEST_TMPDIR/stubs/python3"
    chmod +x "$TEST_TMPDIR/stubs/python3"
    setup_git_repo "$GITHUB_TOOL_DIR/commix"
    install_module_web
    [[ ! -L "$PIPX_BIN_DIR/commix" && -x "$PIPX_BIN_DIR/commix" ]]
    run env PATH="$TEST_TMPDIR/stubs:/usr/bin:/bin" "$PIPX_BIN_DIR/commix" --version
    [[ "$status" -eq 0 ]]
    [[ "$output" == "python3 ran: "*"commix.py --version" ]]
}

@test "recon module exposes spiderfoot through a wrapper around sf.py" {
    _gating_fixture
    GITHUB_TOOL_DIR="$TEST_TMPDIR/tools"
    PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$GITHUB_TOOL_DIR/spiderfoot" "$PIPX_BIN_DIR" "$TEST_TMPDIR/stubs"
    printf 'print("sf")\n' > "$GITHUB_TOOL_DIR/spiderfoot/sf.py"
    printf '#!/bin/bash\necho "python3 ran: $*"\n' > "$TEST_TMPDIR/stubs/python3"
    chmod +x "$TEST_TMPDIR/stubs/python3"
    install_module_recon
    [[ -x "$PIPX_BIN_DIR/spiderfoot" ]]
    run env PATH="$TEST_TMPDIR/stubs:/usr/bin:/bin" "$PIPX_BIN_DIR/spiderfoot" -l 127.0.0.1:5001
    [[ "$status" -eq 0 ]]
    [[ "$output" == "python3 ran: "*"sf.py -l 127.0.0.1:5001" ]]
}

@test "spiderfoot wrapper prefers the clone venv python and keeps an existing command" {
    _gating_fixture
    GITHUB_TOOL_DIR="$TEST_TMPDIR/tools"
    PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$GITHUB_TOOL_DIR/spiderfoot/venv/bin" "$PIPX_BIN_DIR"
    : > "$GITHUB_TOOL_DIR/spiderfoot/sf.py"
    printf '#!/bin/bash\necho "venv ran: $*"\n' > "$GITHUB_TOOL_DIR/spiderfoot/venv/bin/python"
    chmod +x "$GITHUB_TOOL_DIR/spiderfoot/venv/bin/python"
    install_module_recon
    run "$PIPX_BIN_DIR/spiderfoot" -x
    [[ "$output" == "venv ran: "*"sf.py -x" ]]
    printf '#!/bin/bash\necho mine\n' > "$PIPX_BIN_DIR/spiderfoot"
    install_module_recon
    run "$PIPX_BIN_DIR/spiderfoot"
    [[ "$output" == "mine" ]]
}

@test "every build-from-source name has a URL and a build command" {
    local mod prefix name
    for mod in "${ALL_MODULES[@]}"; do
        prefix=$(_module_prefix "$mod")
        declare -p "${prefix}_BUILD_NAMES" &>/dev/null || continue
        local -n build_names="${prefix}_BUILD_NAMES"
        local -n build_urls="${prefix}_BUILD_URLS"
        local -n build_cmds="${prefix}_BUILD_CMDS"
        for name in "${build_names[@]}"; do
            [[ -n "${build_urls[$name]:-}" && -n "${build_cmds[$name]:-}" ]] \
                || { echo "${prefix}_BUILD_NAMES: $name lacks a URL or command"; return 1; }
        done
    done
}

@test "verify.sh checks every module's Go, Cargo and binary release arrays" {
    local verify="$PROJECT_ROOT/scripts/verify.sh" mod prefix
    for mod in "${ALL_MODULES[@]}"; do
        prefix=$(_module_prefix "$mod")
        if declare -p "${prefix}_GO_BINS" &>/dev/null; then
            grep -qF "\"\${${prefix}_GO_BINS[@]}\"" "$verify" \
                || { echo "verify.sh never checks ${prefix}_GO_BINS"; return 1; }
        fi
        if declare -p "${prefix}_CARGO" &>/dev/null; then
            grep -qF "check_module_cargo \"$mod\"" "$verify" \
                || { echo "verify.sh never checks ${prefix}_CARGO"; return 1; }
        fi
        if declare -p "BINARY_RELEASES_${mod^^}" &>/dev/null; then
            grep -qw "check_binary_array BINARY_RELEASES_${mod^^}" "$verify" \
                || { echo "verify.sh never checks BINARY_RELEASES_${mod^^}"; return 1; }
        fi
    done
}


_module_install_fixture() {
    source_libs --installers debian apt
    source "$PROJECT_ROOT/modules/blueteam.sh"
    make_test_tmpdir
    GITHUB_TOOL_DIR="$TEST_TMPDIR/tools with spaces"
    PIPX_BIN_DIR="$TEST_TMPDIR/bin"
    mkdir -p "$PIPX_BIN_DIR"
    TOTAL_TOOL_FAILURES=0
    ENABLE_DOCKER=false
    install_pipx_batch() { :; }
    install_cargo_batch() { :; }
    install_git_batch() { :; }
    install_binary_releases() { :; }
    _builder_home() { printf '%s\n' "$TEST_TMPDIR"; }
    _start_spinner() { :; }
    _stop_spinner() { :; }
}

@test "Blue Team installs OpenSCAP through packages and VirusTotal through Go" {
    _module_install_fixture
    install_apt_batch() { shift; printf '%s\n' "$@" > "$TEST_TMPDIR/packages"; }
    install_go_batch() { shift; printf '%s\n' "$@" > "$TEST_TMPDIR/go-packages"; }
    build_module_from_source() { :; }

    install_module_blueteam

    grep -qxF openscap-scanner "$TEST_TMPDIR/packages"
    local go_package
    go_package="$(cat "$TEST_TMPDIR/go-packages")"
    [[ "$go_package" == github.com/VirusTotal/* ]]
    [[ "$(_go_bin_name "$go_package")" == vt ]]
}

@test "Blue Team source skip avoids cloning and Python bootstrapping" {
    _module_install_fixture
    install_apt_batch() { :; }
    install_go_batch() { :; }
    git_clone_or_pull() { touch "$TEST_TMPDIR/cloned"; return 1; }
    _as_builder() { touch "$TEST_TMPDIR/built"; return 1; }
    SKIP_SOURCE=true

    run install_module_blueteam

    assert_success
    [[ ! -e "$TEST_TMPDIR/cloned" && ! -e "$TEST_TMPDIR/built" ]]
    [[ "$output" == *"kernel-hardening-checker (--skip-source)"* ]]
}

@test "Blue Team source installation skips Termux before cloning" {
    _module_install_fixture
    install_apt_batch() { :; }
    install_go_batch() { :; }
    git_clone_or_pull() { touch "$TEST_TMPDIR/cloned"; return 1; }
    SKIP_SOURCE=false
    PKG_MANAGER=pkg

    run install_module_blueteam

    assert_success
    [[ ! -e "$TEST_TMPDIR/cloned" ]]
    [[ "$output" == *"Skipping build-from-source on Termux: kernel-hardening-checker"* ]]
}

@test "Kernel Hardening Checker build fails if packaging omits the console entrypoint" {
    _module_install_fixture
    git_clone_or_pull() { mkdir -p "$2"; }
    _tree_provenance() { printf 'latest\n'; }
    track_version() { touch "$TEST_TMPDIR/tracked"; }
    _as_builder() { bash -c "$1"; }
    python3() {
        [[ "$1" == -m && "$2" == venv && "$3" == .venv ]] || return 1
        mkdir -p "$3/bin"
        printf '#!/usr/bin/env bash\nexit 0\n' > "$3/bin/python"
        chmod +x "$3/bin/python"
    }
    export -f python3
    SKIP_SOURCE=false

    local build_status=0
    build_from_source kernel-hardening-checker \
        "${BLUETEAM_BUILD_URLS[kernel-hardening-checker]}" \
        "${BLUETEAM_BUILD_CMDS[kernel-hardening-checker]}" || build_status=$?

    [[ "$build_status" -eq 1 && "$TOTAL_TOOL_FAILURES" -eq 1 ]]
    [[ ! -e "$TEST_TMPDIR/tracked" ]]
    [[ ! -e "$GITHUB_TOOL_DIR/kernel-hardening-checker" ]]
}

@test "source output metadata names registered builds and safe executable paths" {
    local module prefix tool relative binary extra
    for module in "${ALL_MODULES[@]}"; do
        prefix=$(_module_prefix "$module")
        declare -p "${prefix}_BUILD_BINS" &>/dev/null || continue
        local -n outputs="${prefix}_BUILD_BINS"
        local -n names="${prefix}_BUILD_NAMES"
        for tool in "${!outputs[@]}"; do
            [[ " ${names[*]} " == *" $tool "* ]] || {
                printf '%s: output metadata for an unknown source build\n' "$tool"
                return 1
            }
            while IFS='|' read -r relative binary extra; do
                [[ -n "$relative" && -n "$binary" && -z "$extra" ]]
                [[ "$relative" != /* && "/$relative/" != */../* ]]
                [[ "$binary" =~ ^[[:alnum:]][[:alnum:]._+-]*$ ]]
            done <<< "${outputs[$tool]}"
        done
    done
}

@test "every source build publishes its declared executables to PATH" {
    _module_install_fixture
    local module prefix tool relative binary outputs count=0
    for module in "${ALL_MODULES[@]}"; do
        prefix=$(_module_prefix "$module")
        declare -p "${prefix}_BUILD_NAMES" &>/dev/null || continue
        local -n names="${prefix}_BUILD_NAMES"
        for tool in "${names[@]}"; do
            outputs=$(_source_build_bins "$tool")
            [[ -n "$outputs" ]] || { printf '%s: no executable outputs\n' "$tool"; return 1; }
            while IFS='|' read -r relative binary; do
                mkdir -p "$(dirname "$GITHUB_TOOL_DIR/$tool/$relative")"
                printf '#!/bin/sh\nprintf "source fixture\\n"\n' > "$GITHUB_TOOL_DIR/$tool/$relative"
                chmod +x "$GITHUB_TOOL_DIR/$tool/$relative"
            done <<< "$outputs"

            setup_source_build_bins "$tool"

            while IFS='|' read -r relative binary; do
                [[ "$(readlink "$PIPX_BIN_DIR/$binary")" == "$GITHUB_TOOL_DIR/$tool/$relative" ]]
                run "$PIPX_BIN_DIR/$binary"
                assert_success
                assert_output 'source fixture'
            done <<< "$outputs"
            count=$((count + 1))
        done
    done
    [[ "$count" -eq 25 ]]
}

@test "source setup rejects a massdns clone without its built executable" {
    _module_install_fixture
    mkdir -p "$GITHUB_TOOL_DIR/massdns"

    run setup_source_build_bins massdns

    assert_failure
    [[ ! -e "$PIPX_BIN_DIR/massdns" ]]
}

@test "binary metadata keys match the module release entries" {
    local module prefix suffix entry tool release_array
    for module in "${ALL_MODULES[@]}"; do
        prefix=$(_module_prefix "$module")
        local -a binaries=()
        for release_array in "BINARY_RELEASES_${module^^}" "BINARY_RELEASES_${module^^}_C2"; do
            declare -p "$release_array" &>/dev/null || continue
            local -n releases="$release_array"
            for entry in "${releases[@]}"; do
                IFS='|' read -r _ tool _ <<< "$entry"
                binaries+=("$tool")
            done
        done
        for suffix in BINARY_ARCHITECTURES BINARY_EXCLUSIVE_DIRS BINARY_RUNTIME_CONFIGS \
            BINARY_RUNTIME_RELEASES BINARY_DEPENDENCIES; do
            declare -p "${prefix}_$suffix" &>/dev/null || continue
            local -n metadata="${prefix}_$suffix"
            for tool in "${!metadata[@]}"; do
                [[ " ${binaries[*]} " == *" $tool "* ]] || {
                    printf '%s: %s has metadata for an unknown binary release\n' "$module" "$suffix"
                    return 1
                }
            done
        done
    done
}

@test "package command metadata targets declared packages and executable names" {
    local module prefix package command
    for module in "${ALL_MODULES[@]}"; do
        prefix=$(_module_prefix "$module")
        declare -p "${prefix}_PACKAGE_BIN_NAMES" &>/dev/null || continue
        local -n binaries="${prefix}_PACKAGE_BIN_NAMES"
        local -n packages="${prefix}_PACKAGES"
        for package in "${!binaries[@]}"; do
            [[ " ${packages[*]} " == *" $package "* ]]
            [[ -n "${binaries[$package]}" ]]
            for command in ${binaries[$package]}; do
                [[ "$command" =~ ^[[:alnum:]][[:alnum:]._+-]*$ ]]
            done
        done
    done
}

@test "every BINARY_RELEASES asset pattern is anchored with a trailing \$" {
    local arr entry pattern
    for arr in $(compgen -v BINARY_RELEASES_); do
        local -n entries="$arr"
        for entry in "${entries[@]}"; do
            IFS='|' read -r _ _ pattern _ <<< "$entry"
            [[ "$pattern" == *'$' ]] || { echo "$arr: unanchored pattern in '$entry'"; return 1; }
        done
    done
}

@test "retired Aderyn is not installed from crates.io" {
    [[ " ${BLOCKCHAIN_CARGO[*]:-} " != *" aderyn "* ]]
    run grep -c '"name": "aderyn"' "$PROJECT_ROOT/tools_config.json"
    assert_output "0"
}
