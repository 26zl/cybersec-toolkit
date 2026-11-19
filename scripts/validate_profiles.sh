#!/usr/bin/env bash
# Validate profiles/*.conf: each must set a non-empty MODULES of known modules and
# SKIP_HEAVY, ENABLE_DOCKER and INCLUDE_C2 as true/false.
# ALL_MODULES in lib/common.sh is the single source of truth. Emits ::error
# annotations so the same script works in CI and locally (make validate == CI).
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

VALID_MODULES=$(grep '^ALL_MODULES=' lib/common.sh | sed 's/ALL_MODULES=(//' | sed 's/)//')
exit_code=0

for conf in profiles/*.conf; do
    profile_name="$(basename "$conf")"

    if ! grep -q '^MODULES=' "$conf"; then
        echo "::error file=$conf::$profile_name: missing MODULES variable"
        exit_code=1
        continue
    fi

    modules_line=$(grep '^MODULES=' "$conf" | head -1)
    modules_value=$(echo "$modules_line" | sed 's/^MODULES="//' | sed 's/"$//')

    if [[ -z "${modules_value//[[:space:]]/}" ]]; then
        echo "::error file=$conf::$profile_name: MODULES is empty"
        exit_code=1
    fi

    for flag in SKIP_HEAVY ENABLE_DOCKER INCLUDE_C2; do
        if ! grep -qE "^${flag}=(true|false)\$" "$conf"; then
            echo "::error file=$conf::$profile_name: $flag must be set to true or false"
            exit_code=1
        fi
    done

    seen=" "
    for mod in $modules_value; do
        if [[ "$seen" == *" $mod "* ]]; then
            echo "::warning file=$conf::$profile_name: duplicate module '$mod'"
        fi
        seen+="$mod "
        found=0
        for valid in $VALID_MODULES; do
            if [[ "$mod" == "$valid" ]]; then
                found=1
                break
            fi
        done
        if [[ $found -eq 0 ]]; then
            echo "::error file=$conf::$profile_name: unknown module '$mod'"
            exit_code=1
        fi
    done

    echo "$profile_name: OK (modules: $modules_value)"
done

exit $exit_code
