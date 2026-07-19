#!/usr/bin/env bash
# Validate profiles/*.conf: each must set MODULES and reference only known modules.
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

    for mod in $modules_value; do
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
