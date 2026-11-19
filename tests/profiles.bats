#!/usr/bin/env bats
# Tests for profile configs in profiles/*.conf
# Validates structure, required variables, and module name validity

setup() {
    load 'test_helper'
    PROFILES_DIR="$PROJECT_ROOT/profiles"
    source_libs debian apt
    VALID_MODULES=("${ALL_MODULES[@]}")
}

# Profile file existence

@test "all expected profile files exist" {
    local expected=(full ctf redteam web osint crackstation lightweight blueteam forensics pwn mobile cloud blockchain wireless)
    for prof in "${expected[@]}"; do
        [[ -f "$PROFILES_DIR/${prof}.conf" ]] || { echo "Missing: ${prof}.conf"; return 1; }
    done
}

@test "no extra unexpected profile files" {
    local count
    count=$(find "$PROFILES_DIR" -maxdepth 1 -name '*.conf' | wc -l)
    # 14 profiles: full, ctf, redteam, web, osint, crackstation, lightweight,
    # blueteam, forensics, pwn, mobile, cloud, blockchain, wireless
    [[ "$count" -eq 14 ]]
}

# MODULES variable

@test "each profile defines MODULES variable" {
    for conf in "$PROFILES_DIR"/*.conf; do
        grep -q '^MODULES=' "$conf" || { echo "Missing MODULES in $(basename "$conf")"; return 1; }
    done
}

@test "each profile defines SKIP_HEAVY variable" {
    for conf in "$PROFILES_DIR"/*.conf; do
        grep -q '^SKIP_HEAVY=' "$conf" || { echo "Missing SKIP_HEAVY in $(basename "$conf")"; return 1; }
    done
}

@test "each profile defines ENABLE_DOCKER variable" {
    for conf in "$PROFILES_DIR"/*.conf; do
        grep -q '^ENABLE_DOCKER=' "$conf" || { echo "Missing ENABLE_DOCKER in $(basename "$conf")"; return 1; }
    done
}

@test "each profile defines INCLUDE_C2 variable" {
    for conf in "$PROFILES_DIR"/*.conf; do
        grep -q '^INCLUDE_C2=' "$conf" || { echo "Missing INCLUDE_C2 in $(basename "$conf")"; return 1; }
    done
}

@test "all module names in profiles are valid" {
    for conf in "$PROFILES_DIR"/*.conf; do
        local modules_line
        modules_line=$(grep '^MODULES=' "$conf" | head -1)
        local modules_value
        modules_value=$(echo "$modules_line" | sed 's/^MODULES="//' | sed 's/"$//')

        for mod in $modules_value; do
            local found=false
            for valid in "${VALID_MODULES[@]}"; do
                if [[ "$mod" == "$valid" ]]; then
                    found=true
                    break
                fi
            done
            [[ "$found" == true ]] || { echo "$(basename "$conf"): invalid module '$mod'"; return 1; }
        done
    done
}

@test "full.conf includes all 18 modules" {
    local modules_line
    modules_line=$(grep '^MODULES=' "$PROFILES_DIR/full.conf" | head -1)
    local modules_value
    modules_value=$(echo "$modules_line" | sed 's/^MODULES="//' | sed 's/"$//')

    for valid in "${VALID_MODULES[@]}"; do
        [[ " $modules_value " == *" $valid "* ]] || { echo "full.conf missing module: $valid"; return 1; }
    done
}

# Profile-specific checks

@test "ctf.conf sets SKIP_HEAVY=true" {
    grep -q '^SKIP_HEAVY=true' "$PROFILES_DIR/ctf.conf"
}

@test "ctf.conf sets ENABLE_DOCKER=false" {
    grep -q '^ENABLE_DOCKER=false' "$PROFILES_DIR/ctf.conf"
}

@test "redteam.conf enables docker and c2" {
    grep -q '^ENABLE_DOCKER=true' "$PROFILES_DIR/redteam.conf"
    grep -q '^INCLUDE_C2=true' "$PROFILES_DIR/redteam.conf"
}

@test "lightweight.conf has minimal modules" {
    local modules_line
    modules_line=$(grep '^MODULES=' "$PROFILES_DIR/lightweight.conf" | head -1)
    local modules_value
    modules_value=$(echo "$modules_line" | sed 's/^MODULES="//' | sed 's/"$//')

    local count=0
    for _ in $modules_value; do
        count=$((count + 1))
    done
    [[ "$count" -le 6 ]]
}

@test "SKIP_HEAVY and ENABLE_DOCKER are boolean values" {
    for conf in "$PROFILES_DIR"/*.conf; do
        local skip_heavy enable_docker
        skip_heavy=$(grep '^SKIP_HEAVY=' "$conf" | sed 's/^SKIP_HEAVY=//')
        enable_docker=$(grep '^ENABLE_DOCKER=' "$conf" | sed 's/^ENABLE_DOCKER=//')
        [[ "$skip_heavy" == "true" || "$skip_heavy" == "false" ]] || { echo "$(basename "$conf"): SKIP_HEAVY not boolean"; return 1; }
        [[ "$enable_docker" == "true" || "$enable_docker" == "false" ]] || { echo "$(basename "$conf"): ENABLE_DOCKER not boolean"; return 1; }
    done
}

# Sourced semantics (install.sh sources each profile)

_source_profile() {
    local conf="$1"
    # shellcheck disable=SC1090
    (source "$conf" && printf '%s|%s|%s|%s\n' "$MODULES" "$SKIP_HEAVY" "$ENABLE_DOCKER" "$INCLUDE_C2")
}

@test "every profile sources cleanly with boolean flags and a duplicate-free MODULES list starting with misc" {
    for conf in "$PROFILES_DIR"/*.conf; do
        local out modules skip docker c2
        out=$(_source_profile "$conf") || { echo "$(basename "$conf"): does not source"; return 1; }
        IFS='|' read -r modules skip docker c2 <<< "$out"
        [[ -n "$modules" ]] || { echo "$(basename "$conf"): MODULES empty"; return 1; }
        [[ "${modules%% *}" == misc ]] || { echo "$(basename "$conf"): MODULES must begin with misc"; return 1; }
        [[ "$(tr ' ' '\n' <<< "$modules" | sort | uniq -d)" == "" ]] || { echo "$(basename "$conf"): duplicate modules"; return 1; }
        for flag in "$skip" "$docker" "$c2"; do
            [[ "$flag" == true || "$flag" == false ]] || { echo "$(basename "$conf"): non-boolean flag '$flag'"; return 1; }
        done
    done
}

@test "INCLUDE_C2=true only for the full and redteam profiles" {
    for conf in "$PROFILES_DIR"/*.conf; do
        local name out c2
        name=$(basename "$conf" .conf)
        out=$(_source_profile "$conf")
        c2="${out##*|}"
        if [[ "$name" == full || "$name" == redteam ]]; then
            [[ "$c2" == true ]] || { echo "$name must set INCLUDE_C2=true"; return 1; }
        else
            [[ "$c2" == false ]] || { echo "$name must not enable C2"; return 1; }
        fi
    done
}

# Prints one line per README profile row: name|modules|docker|c2
_readme_profile_rows() {
    awk -F'|' '/^### Profiles/ {on = 1; next} /^#/ {on = 0} on && /^[|] \140[a-z]+\140 [|]/ {
        for (i = 2; i <= 4; i++) gsub(/^ +| +$|[^A-Za-z0-9, ]/, "", $i)
        gsub(/^ +| +$|[^A-Za-z0-9, ]/, "", $5)
        print $2 "|" $3 "|" $4 "|" $5
    }' "$PROJECT_ROOT/README.md"
}

@test "README profiles agree with the configs" {
    local name modules docker c2 out cmods cdocker cc2 m checked=0
    while IFS='|' read -r name modules docker c2; do
        out=$(_source_profile "$PROFILES_DIR/$name.conf") || { echo "README lists unknown profile $name"; return 1; }
        IFS='|' read -r cmods _ cdocker cc2 <<< "$out"
        if [[ "$modules" == "All 18" ]]; then
            modules="${ALL_MODULES[*]}"
        else
            modules="${modules//,/}"
        fi
        [[ "$modules" == "$cmods" ]] || { echo "$name: README modules '$modules' != conf '$cmods'"; return 1; }
        [[ -z "$docker" && "$cdocker" == false || "$docker" == yes && "$cdocker" == true ]] || { echo "$name: Docker column differs"; return 1; }
        [[ -z "$c2" && "$cc2" == false || "$c2" == yes && "$cc2" == true ]] || { echo "$name: C2 column differs"; return 1; }
        checked=$((checked + 1))
    done < <(_readme_profile_rows)
    [[ "$checked" -eq 14 ]] || { echo "expected 14 README profile rows, found $checked"; return 1; }
}
