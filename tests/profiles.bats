#!/usr/bin/env bats
# =============================================================================
# Tests for profile configs in profiles/*.conf
# Validates structure, required variables, and module name validity
# =============================================================================

setup() {
    load 'test_helper'
    PROFILES_DIR="$PROJECT_ROOT/profiles"
    VALID_MODULES=(misc networking recon web crypto pwn reversing forensics malware ad wireless password stego cloud containers blueteam mobile)
}

# ---------- Profile file existence -------------------------------------------

@test "all 9 profile files exist" {
    local expected=(full ctf redteam web malware osint crackstation lightweight blueteam)
    for prof in "${expected[@]}"; do
        [[ -f "$PROFILES_DIR/${prof}.conf" ]] || { echo "Missing: ${prof}.conf"; return 1; }
    done
}

@test "no extra unexpected profile files" {
    local count
    count=$(find "$PROFILES_DIR" -maxdepth 1 -name '*.conf' | wc -l)
    [[ "$count" -eq 9 ]]
}

# ---------- MODULES variable -------------------------------------------------

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

# ---------- Module name validation -------------------------------------------

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

# ---------- full.conf includes all 17 modules --------------------------------

@test "full.conf includes all 17 modules" {
    local modules_line
    modules_line=$(grep '^MODULES=' "$PROFILES_DIR/full.conf" | head -1)
    local modules_value
    modules_value=$(echo "$modules_line" | sed 's/^MODULES="//' | sed 's/"$//')

    for valid in "${VALID_MODULES[@]}"; do
        [[ " $modules_value " == *" $valid "* ]] || { echo "full.conf missing module: $valid"; return 1; }
    done
}

# ---------- Profile-specific checks ------------------------------------------

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

    # Count modules
    local count=0
    for _ in $modules_value; do
        count=$((count + 1))
    done
    # lightweight should have fewer modules than full (17)
    [[ "$count" -lt 17 ]]
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
