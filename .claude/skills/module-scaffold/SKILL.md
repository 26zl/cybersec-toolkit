---
name: module-scaffold
description: Use when creating a brand new module file in modules/ for a new tool category. Generates the boilerplate with correct array prefix, install_module_<name>() function, and ensures it integrates with install.sh, profiles, and MCP server. Triggers on "new module", "add a module for X", "scaffold module".
---

# Scaffold a new module

Adding a module is more invasive than adding a tool — it requires edits in several places.

## 1. Choose name + prefix

Pick a short module name and a SCREAMING_SNAKE prefix. Examples already used:
`misc/MISC`, `networking/NET`, `recon/RECON`, `web/WEB`, `crypto/CRYPTO`, `pwn/PWN`, `reversing/RE`, `forensics/FORENSICS`, `enterprise/ENTERPRISE`, `wireless/WIRELESS`, `cracking/CRACKING`, `stego/STEGO`, `cloud/CLOUD`, `containers/CONTAINER`, `blueteam/BLUETEAM`, `mobile/MOBILE`, `blockchain/BLOCKCHAIN`, `llm/LLM`.

## 2. Create `modules/<name>.sh`

Template:

```bash
#!/usr/bin/env bash
# Module: <name>
# Description: <one-line description>

# shellcheck disable=SC2034
<PREFIX>_PACKAGES=()

# shellcheck disable=SC2034
<PREFIX>_PIPX=()

# shellcheck disable=SC2034
<PREFIX>_GO=()
# shellcheck disable=SC2034
<PREFIX>_GO_BINS=()

# shellcheck disable=SC2034
<PREFIX>_CARGO=()

# shellcheck disable=SC2034
<PREFIX>_GEMS=()

# shellcheck disable=SC2034
<PREFIX>_GIT=()
# shellcheck disable=SC2034
<PREFIX>_GIT_NAMES=()

install_module_<name>() {
    log_info "Installing <name> module..."

    install_apt_packages "${<PREFIX>_PACKAGES[@]}"
    install_pipx_packages "${<PREFIX>_PIPX[@]}"
    install_go_packages "${<PREFIX>_GO[@]}"
    install_cargo_packages "${<PREFIX>_CARGO[@]}"
    install_gem_packages "${<PREFIX>_GEMS[@]}"
    install_git_repos "${<PREFIX>_GIT[@]}"

    log_success "<name> module install complete"
}
```

Mark executable: `chmod +x modules/<name>.sh`.

## 3. Register the module

### `lib/common.sh` → `ALL_MODULES`

Append the new module name to the `ALL_MODULES` array.

### `lib/common.sh` → `MODULE_DESCRIPTIONS`

Add a one-line description (mirrored to MCP).

### `install.sh`

`install.sh` sources modules conditionally — verify the dispatcher case statement covers `<name>`. Most installers iterate `ALL_MODULES` so no change needed.

## 4. Mirror to MCP server

In `mcp_server/tools_db.py`:

```python
MODULE_DESCRIPTIONS = {
    ...
    "<name>": "<same description as common.sh>",
}
```

Run `python3 scripts/validate_mcp_sync.py` after.

## 5. Add at least one tool

A module with empty arrays is dead code. Use the `add-tool` skill to add ≥1 tool before merging.

## 6. Add a profile (optional)

If the module deserves its own profile (e.g., `myprofile.conf`):

```ini
# profiles/<name>.conf
PROFILE_DESC="..."
MODULES="misc <name>"
SKIP_HEAVY=0
ENABLE_DOCKER=1
INCLUDE_C2=0
```

Profile validator (`scripts/validate_profiles.sh` / CI job) checks every name in `MODULES=` against `ALL_MODULES`.

## 7. Validate

Use the `validate-all` skill — must show zero errors before merging.
