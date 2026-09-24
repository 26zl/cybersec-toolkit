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

Mirror an existing module such as `modules/stego.sh`:

```bash
#!/bin/bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: <Title>
# <one-line description>

<PREFIX>_PACKAGES=()
<PREFIX>_PIPX=()
<PREFIX>_GO=()                # "module/path@latest" entries
<PREFIX>_GO_BINS=()           # binary name per <PREFIX>_GO entry
<PREFIX>_CARGO=()
<PREFIX>_GEMS=()
<PREFIX>_GIT=()               # "name=https://github.com/owner/repo.git" entries
<PREFIX>_GIT_NAMES=()         # the names from <PREFIX>_GIT

install_module_<name>() {
    install_apt_batch "<Title> - Packages" "${<PREFIX>_PACKAGES[@]}"
    install_pipx_batch "<Title> - Python" "${<PREFIX>_PIPX[@]}"
    install_go_batch "<Title> - Go" "${<PREFIX>_GO[@]}"
    install_cargo_batch "<Title> - Rust" "${<PREFIX>_CARGO[@]}"
    install_gem_batch "<Title> - Ruby" "${<PREFIX>_GEMS[@]}"
    install_git_batch "<Title> - Git" "${<PREFIX>_GIT[@]}"
}
```

Binary releases go in `BINARY_RELEASES_<MODULE>` in `lib/installers.sh`, installed with
`install_binary_releases "${BINARY_RELEASES_<MODULE>[@]}"`.

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
# Profile: <one-line description>
MODULES="misc <name>"
SKIP_HEAVY=true
ENABLE_DOCKER=false
INCLUDE_C2=false
```

The first-line `# Profile:` header is the description, and the flags must be `true`/`false`.
Mirror the profile in `mcp_server/profiles.py` (`PROFILES`), then run
`bash scripts/validate_profiles.sh` and `python3 scripts/validate_mcp_sync.py`.

## 7. Validate

Use the `validate-all` skill — must show zero errors before merging.
