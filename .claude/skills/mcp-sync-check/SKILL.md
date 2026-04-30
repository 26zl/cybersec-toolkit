---
name: mcp-sync-check
description: Use when the MCP server may be out of sync with bash sources after editing tools_db.py, profiles.py, lib/common.sh MODULE_DESCRIPTIONS, lib/installers.sh ALL_DOCKER_IMAGES, or scripts/verify.sh _PIPX_BIN_NAMES. Triggers on "check mcp sync", "validate mcp", "is the python in sync".
---

# Check MCP server ↔ bash source sync

The MCP server hardcodes data that's also defined in bash. Drift breaks AI tool suggestions silently.

## What's mirrored

| Python (mcp_server/) | Bash (lib/, scripts/, profiles/) |
| --- | --- |
| `tools_db.py` → `PIPX_BIN_NAMES` | `scripts/verify.sh` → `_PIPX_BIN_NAMES` |
| `tools_db.py` → `MODULE_DESCRIPTIONS` | `lib/common.sh` → `MODULE_DESCRIPTIONS` |
| `tools_db.py` → `DOCKER_IMAGES` | `lib/installers.sh` → `ALL_DOCKER_IMAGES` |
| `profiles.py` → `PROFILES` | `profiles/*.conf` files |

## Run the validator

```bash
python3 scripts/validate_mcp_sync.py
```

Output:

- ✅ `0 errors` → both sides match. Done.
- ❌ Mismatches → fix the Python side to match bash (bash is the source of truth).

## When you've edited bash → mirror to Python

### Added a new Docker image

`lib/installers.sh` → `ALL_DOCKER_IMAGES+=("img|label")` →
`mcp_server/tools_db.py` → add to `DOCKER_IMAGES` dict.

### Added a new pipx tool with mismatched binary name

`scripts/verify.sh` → `_PIPX_BIN_NAMES["pypi-name"]="bin-name"` →
`mcp_server/tools_db.py` → add to `PIPX_BIN_NAMES` dict.

### Added a new module

`lib/common.sh` → `MODULE_DESCRIPTIONS["mod"]="desc"` →
`mcp_server/tools_db.py` → add to `MODULE_DESCRIPTIONS` dict.

### Added a new profile

`profiles/myprof.conf` → set `PROFILE_DESC` and `MODULES` →
`mcp_server/profiles.py` → add to `PROFILES` dict with same modules list.

## When you've edited Python → mirror to bash

This is rare and usually wrong. Bash is the source of truth. If a tool is only known to MCP, the install side won't be able to install it. Fix bash first, then mirror.

## After fixing

Re-run:

```bash
python3 scripts/validate_mcp_sync.py
cd mcp_server && uv run --group dev pytest tests/ -q
```

Both must pass.
