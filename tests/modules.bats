#!/usr/bin/env bats
# =============================================================================
# Tests for module files in modules/*.sh
# Validates install functions, array naming, git format, Go @latest suffix
# =============================================================================

setup() {
    load 'test_helper'
    source_libs --installers debian apt

    # Source all module files
    for mod in "${ALL_MODULES[@]}"; do
        source "$PROJECT_ROOT/modules/${mod}.sh"
    done
}

# ---------- Module files exist -----------------------------------------------

@test "all 18 module files exist" {
    for mod in "${ALL_MODULES[@]}"; do
        [[ -f "$PROJECT_ROOT/modules/${mod}.sh" ]] || { echo "Missing: modules/${mod}.sh"; return 1; }
    done
}

# ---------- install_module_* functions defined -------------------------------

@test "each module defines install_module_<name> function" {
    for mod in "${ALL_MODULES[@]}"; do
        local func="install_module_${mod}"
        declare -f "$func" > /dev/null 2>&1 || { echo "Missing function: $func"; return 1; }
    done
}

# ---------- Array naming convention ------------------------------------------

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
        malware)    echo "MALWARE" ;;
        enterprise) echo "ENTERPRISE" ;;
        wireless)   echo "WIRELESS" ;;
        password)   echo "PASSWORD" ;;
        stego)      echo "STEGO" ;;
        cloud)      echo "CLOUD" ;;
        containers) echo "CONTAINER" ;;
        blueteam)   echo "BLUETEAM" ;;
        mobile)     echo "MOBILE" ;;
        blockchain) echo "BLOCKCHAIN" ;;
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
        for suffix in PACKAGES BASE_PACKAGES SECURITY_PACKAGES PIPX GO GIT CARGO GEMS; do
            local arr_name="${prefix}_${suffix}"
            if declare -p "$arr_name" &>/dev/null; then
                found=true
                break
            fi
        done
        [[ "$found" == true ]] || { echo "No arrays found for module $mod (prefix: $prefix)"; return 1; }
    done
}

# ---------- Git arrays use name=url format -----------------------------------

@test "all git arrays use name=url format" {
    local git_arrays=(
        MISC_RESOURCES MISC_POSTEXPLOIT MISC_SOCIAL MISC_CTF
        NET_GIT RECON_GIT WEB_GIT CRYPTO_GIT PWN_GIT RE_GIT
        FORENSICS_GIT ENTERPRISE_GIT WIRELESS_GIT PASSWORD_GIT STEGO_GIT
        CLOUD_GIT CONTAINER_GIT BLUETEAM_GIT MOBILE_GIT
    )

    for arr_name in "${git_arrays[@]}"; do
        declare -p "$arr_name" &>/dev/null || continue
        local -n arr="$arr_name"
        [[ ${#arr[@]} -eq 0 ]] && continue

        for entry in "${arr[@]}"; do
            # Must contain = separator
            [[ "$entry" == *"="* ]] || { echo "$arr_name: entry missing '=' separator: $entry"; return 1; }
            # URL part should start with https://
            local url="${entry#*=}"
            [[ "$url" == https://* ]] || { echo "$arr_name: URL doesn't start with https://: $url"; return 1; }
        done
    done
}

# ---------- Go arrays end with @latest ---------------------------------------

@test "all Go tool paths end with @latest" {
    local go_arrays=(
        MISC_GO NET_GO RECON_GO WEB_GO CRYPTO_GO PWN_GO RE_GO
        FORENSICS_GO ENTERPRISE_GO CLOUD_GO CONTAINER_GO BLUETEAM_GO MOBILE_GO
        MALWARE_GO WIRELESS_GO PASSWORD_GO STEGO_GO
    )

    for arr_name in "${go_arrays[@]}"; do
        declare -p "$arr_name" &>/dev/null || continue
        local -n arr="$arr_name"
        [[ ${#arr[@]} -eq 0 ]] && continue

        for gopkg in "${arr[@]}"; do
            [[ "$gopkg" == *"@latest" ]] || { echo "$arr_name: missing @latest suffix: $gopkg"; return 1; }
        done
    done
}

# ---------- Go binary arrays match Go arrays ---------------------------------

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

# ---------- Git name arrays have entries for modules with Git repos ----------

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

# ---------- No duplicate entries in arrays -----------------------------------

@test "no duplicate entries in pipx arrays" {
    local pipx_arrays=(
        MISC_PIPX NET_PIPX RECON_PIPX WEB_PIPX CRYPTO_PIPX PWN_PIPX RE_PIPX
        FORENSICS_PIPX MALWARE_PIPX ENTERPRISE_PIPX WIRELESS_PIPX PASSWORD_PIPX
        STEGO_PIPX CLOUD_PIPX BLUETEAM_PIPX MOBILE_PIPX
    )

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
