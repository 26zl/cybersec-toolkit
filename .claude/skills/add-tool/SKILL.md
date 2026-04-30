---
name: add-tool
description: Use when adding a new cybersecurity tool to this installer. Walks through editing the right module file, adding to tools_config.json, running validators, and syncing MCP server data if needed. Triggers on phrases like "add tool", "add <toolname>", "register a new tool", "include X in the installer".
---

# Add a new tool to the installer

Use this when the user wants to add a new tool. Follow these steps in order. **Do not skip validation.**

## 1. Decide which module the tool belongs to

Match the tool to one of the 18 modules:

| Module | Prefix | Tools |
| --- | --- | --- |
| `misc.sh` | `MISC_` | General CLI helpers, utilities |
| `networking.sh` | `NET_` | Scanners, sniffers, proxies |
| `recon.sh` | `RECON_` | OSINT, subdomain enum, fingerprinting |
| `web.sh` | `WEB_` | Web app testing, fuzzing, scanners |
| `crypto.sh` | `CRYPTO_` | Crypto attack tools, analysis |
| `pwn.sh` | `PWN_` | Binary exploitation, debuggers, fuzzers |
| `reversing.sh` | `RE_` | Disassemblers, decompilers |
| `forensics.sh` | `FORENSICS_` | Disk/memory/file forensics |
| `enterprise.sh` | `ENTERPRISE_` | AD, Kerberos, post-exploit |
| `wireless.sh` | `WIRELESS_` | Wi-Fi, Bluetooth |
| `cracking.sh` | `CRACKING_` | Password cracking, hash tools |
| `stego.sh` | `STEGO_` | Steganography |
| `cloud.sh` | `CLOUD_` | AWS/GCP/Azure tooling |
| `containers.sh` | `CONTAINER_` | Docker, k8s |
| `blueteam.sh` | `BLUETEAM_` | Detection, IR, hardening |
| `mobile.sh` | `MOBILE_` | APK, iOS analysis |
| `blockchain.sh` | `BLOCKCHAIN_` | Smart contracts, EVM |
| `llm.sh` | `LLM_` | AI/LLM testing |

## 2. Pick the install method

Preferred order: **apt > pipx > go > cargo > binary release > gem > Docker > git clone > build from source**

Add to the matching array in `modules/<module>.sh`:

| Method | Array | Format |
| --- | --- | --- |
| apt | `<PREFIX>_PACKAGES` | `"package-name"` |
| pipx | `<PREFIX>_PIPX` | `"pypi-name"` |
| Go | `<PREFIX>_GO` + `<PREFIX>_GO_BINS` | `"github.com/owner/repo/cmd@latest"` + `"binary-name"` |
| Cargo | `<PREFIX>_CARGO` | `"crate-name"` |
| Gem | `<PREFIX>_GEMS` | `"gem-name"` |
| Git | `<PREFIX>_GIT` + `<PREFIX>_GIT_NAMES` | `"name=https://github.com/owner/repo"` + `"name"` |
| Binary release | `BINARY_RELEASES_<MODULE>` in `lib/installers.sh` | `"owner/repo\|binary\|pattern\|dest_dir"` |
| Docker | `ALL_DOCKER_IMAGES` in `lib/installers.sh` | `"image\|label"` + add `docker_pull` call in module install function |
| Build from source | `build_from_source` call in `install_module_*()` + `<PREFIX>_BUILD_NAMES` | inline |

If apt package name differs across distros, add a row to `lib/distro_compat.tsv` (columns: `debian | dnf | pacman | zypper | pkg`). Use `-` to skip a distro, empty for passthrough, `a+b` for multi-package expand.

## 3. Add metadata to `tools_config.json`

Append an entry:

```json
{
  "name": "tool-name",
  "method": "apt|pipx|go|cargo|gem|binary|docker|git|build",
  "module": "module-name",
  "url": "https://upstream/url"
}
```

## 4. Run validators (REQUIRED — must show 0 errors)

```bash
python3 scripts/validate_tools_config.py
```

If URLs are missing, populate them automatically:

```bash
python3 scripts/validate_tools_config.py --sync
```

## 5. Update MCP sync if applicable

If the tool was added to a data source mirrored in the MCP server:

- New Docker image → also update `mcp_server/tools_db.py` `DOCKER_IMAGES`
- New pipx tool whose binary name differs from PyPI name → also update `mcp_server/tools_db.py` `PIPX_BIN_NAMES` (mirror of `scripts/verify.sh` `_PIPX_BIN_NAMES`)
- New module → also update `lib/common.sh` `MODULE_DESCRIPTIONS` AND `mcp_server/tools_db.py` `MODULE_DESCRIPTIONS`

Then validate sync:

```bash
python3 scripts/validate_mcp_sync.py
```

## 6. Lint and final checks

```bash
shellcheck --severity=warning install.sh lib/*.sh modules/*.sh scripts/*.sh
bash -n install.sh lib/*.sh modules/*.sh scripts/*.sh
```

`scripts/verify.sh`, `scripts/update.sh`, `scripts/remove.sh` all source modules and pick up array changes automatically — no edits needed there.

## 7. Optional: smoke test

```bash
./install.sh --module <module-name> --dry-run
```
