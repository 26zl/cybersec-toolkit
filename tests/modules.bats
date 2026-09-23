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

# Map module names to their array prefixes
_get_prefix() {
    case "$1" in
        misc)       echo "MISC" ;;
        networking) echo "NET" ;;
        recon)      echo "RECON" ;;
        web)        echo "WEB" ;;
        crypto)     echo "CRYPTO" ;;
        pwn)        echo "PWN" ;;
        reversing)  echo "RE" ;;
        forensics)  echo "FORENSICS" ;;
        enterprise) echo "ENTERPRISE" ;;
        wireless)   echo "WIRELESS" ;;
        cracking)   echo "CRACKING" ;;
        stego)      echo "STEGO" ;;
        cloud)      echo "CLOUD" ;;
        containers) echo "CONTAINER" ;;
        blueteam)   echo "BLUETEAM" ;;
        mobile)     echo "MOBILE" ;;
        blockchain) echo "BLOCKCHAIN" ;;
        llm)        echo "LLM" ;;
    esac
}

@test "modules define arrays with correct prefixes" {
    # Check that at least the primary array types exist for each module
    # Not all modules have all array types, but each should have at least one
    for mod in "${ALL_MODULES[@]}"; do
        local prefix
        prefix=$(_get_prefix "$mod")
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

@test "Go binary arrays have entries for modules with Go tools" {
    local -A go_to_bins=(
        [RECON_GO]=RECON_GO_BINS
        [WEB_GO]=WEB_GO_BINS
        [NET_GO]=NET_GO_BINS
        [ENTERPRISE_GO]=ENTERPRISE_GO_BINS
    )

    for go_arr in "${!go_to_bins[@]}"; do
        declare -p "$go_arr" &>/dev/null || continue
        local -n goref="$go_arr"
        [[ ${#goref[@]} -eq 0 ]] && continue

        local bins_arr="${go_to_bins[$go_arr]}"
        declare -p "$bins_arr" &>/dev/null || { echo "Missing $bins_arr for $go_arr"; return 1; }
        local -n binsref="$bins_arr"
        [[ ${#binsref[@]} -gt 0 ]] || { echo "$bins_arr is empty but $go_arr has entries"; return 1; }
    done
}

@test "Git name arrays have entries for modules with git repos" {
    local -A git_to_names=(
        [RECON_GIT]=RECON_GIT_NAMES
        [WEB_GIT]=WEB_GIT_NAMES
        [NET_GIT]=NET_GIT_NAMES
        [ENTERPRISE_GIT]=ENTERPRISE_GIT_NAMES
    )

    for git_arr in "${!git_to_names[@]}"; do
        declare -p "$git_arr" &>/dev/null || continue
        local -n gitref="$git_arr"
        [[ ${#gitref[@]} -eq 0 ]] && continue

        local names_arr="${git_to_names[$git_arr]}"
        declare -p "$names_arr" &>/dev/null || { echo "Missing $names_arr for $git_arr"; return 1; }
        local -n namesref="$names_arr"
        [[ ${#namesref[@]} -gt 0 ]] || { echo "$names_arr is empty but $git_arr has entries"; return 1; }
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
