# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Modular bash installer for 580+ cybersecurity tools on Linux and Termux (Android). Multi-distro (Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE, Termux). 12 install methods, 18 modules, 14 profiles. Includes an MCP server for AI-assisted hacking.

## Commands

### Validation (run before pushing)

```bash
# Lint all shell scripts
shellcheck --severity=warning install.sh lib/*.sh modules/*.sh scripts/*.sh

# Bash syntax check
bash -n install.sh lib/*.sh modules/*.sh scripts/*.sh

# Cross-validate tools_config.json against module arrays (0 errors, 0 warnings = pass)
python3 scripts/validate_tools_config.py

# Validate MCP hardcoded data matches bash sources
python3 scripts/validate_mcp_sync.py

# Validate distro compatibility TSV (0 errors = pass)
python3 scripts/validate_distro_compat.py

# Populate missing URLs in tools_config.json from module source
python3 scripts/validate_tools_config.py --sync

# Lint challenge writeups (workflows/ is gitignored, so CI won't check these)
npx markdownlint-cli2 "workflows/**/*.md"
```

### Testing

```bash
# Initialize bats submodules (first time only)
git submodule update --init --recursive

# Run all bats tests
./tests/bats/bin/bats tests/*.bats

# Run a single test file
./tests/bats/bin/bats tests/common.bats

# Windows: requires core.autocrlf=input (set per-repo, not global)
git config core.autocrlf input
git -C tests/bats config core.autocrlf input
```

Test files: `tests/common.bats`, `tests/install.bats`, `tests/installers.bats`, `tests/modules.bats`, `tests/profiles.bats`. Helper at `tests/test_helper.bash` provides `mock_os_release()`, `source_libs()`, `make_test_tmpdir()`.

**Windows note:** `install.bats` tests run `install.sh` as a subprocess which calls `exit 1` on Windows. All other test files use `source_libs()` which pre-sets `PKG_MANAGER` to skip the OS check — these pass on Windows/Git Bash.

### MCP Server

```bash
# Install uv (one-time)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Interactive MCP Inspector (web UI)
cd mcp_server && uv run fastmcp dev server.py

# CLI entrypoint
cd mcp_server && uv run cybersec-mcp

# Import check
python3 -c "import sys; sys.path.insert(0,'.'); from mcp_server.server import mcp; print('OK')"

# Python tests (must use uv to get pytest-asyncio)
cd mcp_server && uv run --group dev pytest tests/ -q

# Run a single test class/method
cd mcp_server && uv run --group dev pytest tests/test_security.py::TestCheckPolicy -q

# Lint + format check
cd mcp_server && uv run --group dev ruff check . && uv run --group dev ruff format --check .

# Auto-format
cd mcp_server && uv run --group dev ruff format .
```

### WSL Setup (Windows)

```bash
# Sync MCP server files to WSL-local copy (needed because uv can't create .venv on NTFS)
./scripts/sync-wsl.sh                  # sync to default WSL distro
./scripts/sync-wsl.sh kali-linux       # sync to specific distro

# Set up pwntools venv (one-time, directly in WSL — not through MCP)
wsl.exe bash -lc "mkdir -p ~/.ctf-venvs && python3 -m venv ~/.ctf-venvs/pwntools && ~/.ctf-venvs/pwntools/bin/pip install pwntools z3-solver"

# Backup/restore tool configurations (ChaCha20-encrypted)
scripts/backup.sh backup               # interactive backup
scripts/backup.sh restore <file>       # restore from backup
scripts/backup.sh schedule             # set up cron schedule
```

MCP server config for Claude Code (`.mcp.json`) and Claude Desktop (`claude_desktop_config.json`) both use `wsl.exe` to run the server from the WSL-local copy at `~/cybersec-toolkit/mcp_server/`. Run `sync-wsl.sh` after code changes.

**WSL env variable forwarding:** Windows env vars set in MCP config `"env"` blocks do NOT propagate into WSL automatically. Two mechanisms are used together:

1. `export VAR=val &&` inside the `bash -lc` command string
2. `WSLENV` env var listing variables to forward (e.g. `"WSLENV": "CYBERSEC_MCP_ALLOW_SCRIPTS/u:CYBERSEC_MCP_ALLOW_EXTERNAL/u"`)

**Pwntools venv:** Must be created directly in WSL (has full network access), NOT through `run_script` (which is subject to MCP network policy). The venv lives at `~/.ctf-venvs/pwntools/` and is used via `run_script(code, venv="pwntools")`.

### Docker

```bash
docker build -t cybersec-toolkit .
docker run cybersec-toolkit --profile ctf              # Run installer
docker run -i --rm --entrypoint bash cybersec-toolkit \  # Run MCP server
  -c 'export PATH="$HOME/.local/bin:$PATH" && cd /opt/cybersec-toolkit/mcp_server && uv run fastmcp run server.py'
```

## CI Pipeline

Ten parallel jobs on push to main and PRs (`.github/workflows/ci.yml`):

1. **shellcheck** — `shellcheck --severity=warning` on all `.sh` files
2. **bash-syntax** — `bash -n` on all `.sh` files
3. **markdown-lint** — markdownlint-cli2 on all `.md` files
4. **bats-tests** — `bats tests/*.bats` (unit tests)
5. **validate-tools-config** — `python3 scripts/validate_tools_config.py` (0 errors, 0 warnings)
6. **distro-compat-validate** — `python3 scripts/validate_distro_compat.py` (distro package mappings)
7. **python-lint** — `ruff check` + `ruff format --check` on MCP server
8. **python-tests** — `pytest` on MCP server tests
9. **mcp-server-check** — `uv sync`, import test, `validate_mcp_sync.py`
10. **validate-profiles** — checks every `profiles/*.conf` module name against `ALL_MODULES`

Security workflow (`.github/workflows/security.yml`, separate from CI):

- **gitleaks** — secret detection via Gitleaks
- **custom-security-scan** — hardcoded IPs, secrets, non-HTTPS URLs, unsafe eval, curl|bash, chmod 777
- **pip-audit** — audits MCP server Python dependencies for known CVEs (via `uvx pip-audit`)
- **pin-check** — enforces all GitHub Actions use full SHA commit pins (blocks tag-only references)
- **scorecard** — OSSF Scorecard (public repos only, push to main)

Supply chain hardening: all workflow jobs use `step-security/harden-runner` (egress audit mode) as the first step, and all actions are SHA-pinned with version comments.

Integration tests (`.github/workflows/integration.yml`, push to main + weekly): Ubuntu 24.04, Fedora 41, Arch, openSUSE.

Automated dependency updates (`.github/workflows/uv-update.yml`): weekly `uv lock --upgrade` with auto-PR.

## Architecture

### Source Chain

`lib/common.sh` → `lib/installers.sh` → `lib/shared.sh` → `modules/<name>.sh`

All scripts source the chain in this order. `common.sh` auto-detects distro/pkg manager on source. Module files are sourced conditionally by `install.sh` based on profile/module selection. `scripts/verify.sh`, `scripts/update.sh`, `scripts/remove.sh` source ALL modules to access arrays.

### Module System

18 modules, each in `modules/<name>.sh`. Each defines arrays with a consistent prefix and an `install_module_<name>()` function:

- Arrays: `<PREFIX>_PACKAGES` (apt), `<PREFIX>_PIPX`, `<PREFIX>_GO`, `<PREFIX>_CARGO`, `<PREFIX>_GEMS`, `<PREFIX>_GIT` (name=url pairs), `<PREFIX>_GO_BINS`, `<PREFIX>_GIT_NAMES`
- Prefixes: `MISC`, `NET`, `RECON`, `WEB`, `CRYPTO`, `PWN`, `RE`, `FORENSICS`, `ENTERPRISE`, `WIRELESS`, `CRACKING`, `STEGO`, `CLOUD`, `CONTAINER`, `BLUETEAM`, `MOBILE`, `BLOCKCHAIN`, `LLM`
- All arrays optional — only define what's needed. Consumed by batch install functions via `_collect_module_arrays()`

### Profile System

14 profiles in `profiles/*.conf`. Each sets `MODULES="..."`, `SKIP_HEAVY`, `ENABLE_DOCKER`, `INCLUDE_C2`. Used via `install.sh --profile <name>`.

### MCP Server (`mcp_server/`)

**CRITICAL: MCP tools must ALWAYS be used first.** Priority order: `run_tool` → `run_pipeline` → `run_script`. Use `run_tool("curl", ...)` for HTTP, `run_tool("nmap", ...)` for scanning, etc. Only fall back to `run_script` when you need actual programming logic (loops, exploit code, complex parsing). If `run_tool` is blocked by policy (e.g. `CYBERSEC_MCP_ALLOW_EXTERNAL=0`), tell the user to fix config and restart — do NOT silently bypass with `run_script`.

Separate Python package (FastMCP). 13 AI-accessible tools: `list_tools`, `check_installed`, `get_tool_info`, `get_module_info`, `get_profile_tools`, `suggest_for_ctf`, `suggest_for_bounty`, `recommend_install`, `list_profiles`, `run_tool`, `run_pipeline`, `run_script`, `manage_remote_hosts`.

**Module layout:**

- `server.py` — FastMCP tool registrations (13 tools)
- `security.py` — Execution engine: `execute_tool()`, `execute_pipeline()`, `execute_script()`, `execute_tool_remote()`, policy enforcement, argument sanitization
- `tools_db.py` — Tool registry loader, install checks, version tracking
- `profiles.py` — Profile data (synced from `profiles/*.conf`)
- `ctf_advisor.py` — CTF category suggestions, `TOOL_ALIASES` mapping, methodology steps
- `bounty_advisor.py` — Bug bounty target-type suggestions, methodology, common vulns
- `remote.py` — `RemoteHostConfig` for SSH-based remote tool execution
- `audit.py` — JSON-line audit logging (5MB rotating) for blocked/executed tools and scripts
- `sanitize.py` — Output processing: ANSI stripping, control char removal, 200KB truncation

**Key design decisions:**

- Uses `uv` for dependency management (`pyproject.toml`), not pip/venv
- All imports use absolute paths with `sys.path` fixup (no relative imports) — required for compatibility with both `python -m mcp_server.server` and `fastmcp dev inspector server.py`
- `TOOL_ALIASES` in `ctf_advisor.py` maps user-friendly names to registry names (e.g., `wireshark` → `wireshark-common`)
- Termux-aware: command suggestions omit `sudo` when `TERMUX_VERSION` is set
- TTL-cached `.versions` reads (2s) to avoid per-tool file reads during batch operations

**Environment variables** (set in `.mcp.json` / `claude_desktop_config.json`):

- `CYBERSEC_MCP_ALLOW_SCRIPTS=1` — enables `run_script()` (Python/Bash execution)
- `CYBERSEC_MCP_ALLOW_EXTERNAL=1` — allows network tools to target external IPs (default: private/loopback only)
- `CYBERSEC_MCP_VENVS_DIR` — custom location for script venvs (default: `~/.ctf-venvs/`)
- `CYBERSEC_INSTALLER_ROOT` — override project root path for tools_config.json lookup

**Hardcoded data that must stay in sync with bash sources** (validated by `scripts/validate_mcp_sync.py`):

| Python location | Bash source |
| --- | --- |
| `tools_db.py` → `PIPX_BIN_NAMES` | `scripts/verify.sh` `_PIPX_BIN_NAMES` |
| `tools_db.py` → `MODULE_DESCRIPTIONS` | `lib/common.sh` `MODULE_DESCRIPTIONS` |
| `tools_db.py` → `DOCKER_IMAGES` | `lib/installers.sh` `ALL_DOCKER_IMAGES` |
| `profiles.py` → `PROFILES` | `profiles/*.conf` files |

**Execution security** (`security.py`):

- Registry allowlist + install check + argument sanitization (blocks `; & | \`` `$( ${`)
- Universal blocked flags: `--delete`, `-rf`, `--force-delete`, `--remove-all`, `--exploit`
- Tool-specific blocked flags: sqlmap (`--os-shell`, `--os-cmd`, `--os-pwn`, `--priv-esc`, `--file-read`, `--file-write`, `--file-dest`), nmap (`-iL`, `-iR`), masscan (`--includefile`), sed (`-i`), awk (`system()`, `pipe|getline`), tar (`--checkpoint-action`, `--to-command`)
- `socat` excluded from SYSTEM_UTILITIES (EXEC:/SYSTEM: allow arbitrary command execution)
- Network policy: network tools restricted to private/loopback IPs by default. `_allow_external()` checks `CYBERSEC_MCP_ALLOW_EXTERNAL=1` env var at call time (not import time)
- `_allow_scripts()` checks `CYBERSEC_MCP_ALLOW_SCRIPTS=1` similarly — both are functions, not constants
- Network target parsing: `_looks_like_target()` heuristic + `_has_file_extension()` to avoid false positives from filenames (`.txt`, `.pcap`, `.json`, etc.)
- Rate limiter checked BEFORE semaphore in all three execution paths (`execute_tool`, `execute_pipeline`, `execute_tool_remote`)
- Pipeline intermediate steps with non-zero exit (e.g., grep returning 1) pass output forward; only the last step's exit code matters
- Thread-safe DNS resolution via daemon thread (no process-global `socket.setdefaulttimeout`)
- `$`, `>`, `<` are NOT blocked — no shell is used (`create_subprocess_exec`), and tools need them for regex/awk/XML
- Tool-specific blocked flags use `pattern.search()` not `pattern.match()` (must match anywhere in arg, not just position 0)
- IPv6-aware target parsing. No `shell=True`. Timeout 1-300s. Output capped at 200KB

### Install Method Hierarchy

Preferred order: `apt > pipx > go > cargo > binary > gem > Docker > git clone > source`

### Distro Support

- `fixup_package_names()` in `lib/installers.sh` translates Debian package names for dnf/pacman/zypper/pkg using data from `lib/distro_compat.tsv` (TSV with columns: debian, dnf, pacman, zypper, pkg). Values: name=rename, `-`=skip, empty=passthrough, `a+b`=multi-expand
- Some packages skipped on non-Debian distros (e.g., `spooftooph`, `cewl`). Kali-only packages skipped on standard Ubuntu (inline in function, not in TSV)
- `build-essential` maps to `@development-tools` (dnf), `base-devel` (pacman), `clang make` (Termux)
- **Termux**: Detected via `TERMUX_VERSION`. Uses `pkg` (no sudo). Paths: `$PREFIX/bin` + `$HOME/tools`. Docker/snap/binary releases/build-from-source skipped

## Important Patterns

- All scripts use `set -uo pipefail` (not `-e` — individual tool failures don't abort)
- Empty arrays guarded with `[[ ${#arr[@]} -gt 0 ]]` before expansion (bash `set -u` safety)
- Version tracking: `.versions` file with `tool|method|version|timestamp` format
- All non-system binaries end up in `/usr/local/bin` (Linux) or `$PREFIX/bin` (Termux)
- `TOTAL_TOOL_FAILURES` global counter in `installers.sh` tracks failures across all batch install functions
- Binary releases SHA256-verified when checksums available; `--require-checksums` makes missing checksums a hard failure
- Go SDK version fetched dynamically from `go.dev/dl/?mode=json` API (fallback: hardcoded). SHA256-verified against the same API. `ensure_go()` downloads Go when system Go < 1.21
- GitHub API auth: auto-detects `gh auth token` if `GITHUB_TOKEN` is not set. Raises rate limit from 60 to 5000 req/hr
- setuptools<75 injected into all pipx venvs on Python 3.12+ (setuptools 75+ removed `pkg_resources`)
- Gem binaries symlinked from user-local gem dir to `$PIPX_BIN_DIR` (gems install via `_as_builder` to `~/.local/share/gem/`)
- Git repos with pip install failures automatically retry with Python 3.12→3.11→3.10 fallback, then a relaxed-pins fallback (`==` → `>=`) as last resort
- `_builder_home()` in `lib/installers.sh` returns the real user's home when running under sudo (`$SUDO_USER`). Used by cargo/gem installs, `scripts/remove.sh`, and `scripts/update.sh` to find user-local directories
- `scripts/remove.sh` removes in dependency order: pipx/gems/cargo FIRST, system packages LAST. Includes build-from-source binary cleanup (`/usr/local/bin`)
- `scripts/update.sh` handles build-from-source tools via git pull + rebuild
- `_as_builder()` prepends `$HOME/.cargo/bin:/usr/local/bin` to PATH in the sudo branch so Rust and locally-installed tools are found
- `git_clone_or_pull()` retries with `fetch + reset --hard origin/<branch>` when `git pull` fails (e.g., CRLF-dirty working tree)
- `install_shared_deps()` dynamically installs `gcc-N-plugin-dev` on apt systems (needed by AFLplusplus gcc_plugin)
- Curl-pipe installs use `_validate_curl_pipe` which checks minimum file size + multiple keywords before piping to `sh`/`bash`
- `track_session` uses `flock` FD-redirect pattern (not `flock -c`) for parallel safety without injection risk
- `.gitattributes` enforces `* text=auto eol=lf` — prevents CRLF breakage on Windows checkouts

## DANGER: Never Read Unvalidated Images

**NEVER use the `Read` tool on image files (PNG, JPG, PPM, BMP, etc.) without first verifying they are valid.** Reading a corrupt or malformed image poisons the entire conversation context — the broken image gets stuck in the message history, and every subsequent API call fails with "Could not process image". The only fix is to abandon the conversation and start a new one.

**Before viewing any image with `Read`:**

1. Validate with MCP tools first: `run_tool("file", "/path/to/image")` — confirm it reports a valid image type
2. Check integrity: `run_tool("identify", "/path/to/image")` (ImageMagick) or `run_script("from PIL import Image; img = Image.open('/path/to/image'); print(img.size, img.mode)")`
3. Only if both checks pass, copy to a Windows path and use `Read` to view it

**If the image is reconstructed, converted, or extracted from a challenge:** assume it may be corrupt until proven otherwise. Always validate first.

## Challenge Writeups (MANDATORY)

After solving ANY challenge (CTF, bug bounty, lab, practice box), **always** write a detailed workflow writeup in `workflows/`. This is non-negotiable.

**Format:** `workflows/<competition>/` folder per competition, one file per challenge (e.g., `workflows/ehax2026/chusembly.md`, `workflows/htb/pilgrimage.md`). Writeups MUST pass markdownlint (run `npx markdownlint-cli2 "workflows/**/*.md"` to check).

**Writing style:**

- Write like a human pentester documenting their work — direct, technical, no filler
- NO AI-style language: no "Let's", "I'll", "Great question", "Here's what we found", "It's worth noting"
- Use first person plural ("we") or passive voice: "Ran nmap", "The binary was stripped", "Found SQLi in the login endpoint"
- Be detailed: include exact commands run, exact output (trimmed), exact payloads, exact flags
- Document dead ends too — what didn't work and why, so we don't repeat mistakes
- Include timestamps or a rough timeline if the challenge took multiple sessions

**Structure:**

```markdown
# <Challenge Name>
**Platform:** HTB / TryHackMe / CTF Name / Bug Bounty Program
**Category:** Web / Pwn / Crypto / Forensics / etc.
**Difficulty:** Easy / Medium / Hard
**Date:** YYYY-MM-DD

## Recon
[What we discovered during initial enumeration]

## Exploitation
[Step-by-step attack path with commands and output]

## Dead Ends
[Approaches that didn't work and why]

## Flag / Finding
[The flag or vulnerability confirmed]

## Tools Used
[List of tools that were key to the solve]

## Lessons Learned
[What to remember for next time]
```

## Tool-First Approach (MANDATORY)

**ALWAYS use existing tools before attempting anything manually.** This applies to ALL categories: web, crypto, pwn, reversing, forensics, stego, networking, cloud, mobile, blockchain — everything.

**Before starting any challenge or task:**

1. Check `workflows/` for previous writeups with similar techniques — reuse patterns, avoid repeated dead ends
2. Run `suggest_for_ctf` or `suggest_for_bounty` to get the recommended tool stack
3. Check which recommended tools are installed with `check_installed`
4. Use `list_tools` with the relevant module to see what's available
5. **Use every applicable tool** from our 580+ tool registry before resorting to manual scripting

**Do NOT:**

- Skip tool usage and jump straight to writing custom scripts
- Use `run_script` with requests/urllib when `run_tool("curl", ...)` works
- Manually parse binaries when `binwalk`, `foremost`, `strings`, `readelf`, `objdump` exist
- Write custom port scanners when `nmap`, `masscan` are available
- Write custom fuzzers when `ffuf`, `gobuster`, `wfuzz` are installed
- Manually decode things when `CyberChef`, `base64`, `xxd` handle it

**The rule is simple: if a tool exists for it, use the tool.**

## Discovering and Installing New Tools (MANDATORY)

When working on a challenge, if you discover — through web searches, GitHub exploration, reading writeups, or any other means — a tool that would help solve the problem and is NOT already in our registry:

1. **Install it immediately.** Do not mention it and move on. Do not say "there's a tool called X that could help" without installing it.
2. **Preferred install methods** (in order): `apt`/`pipx`/`go install`/`cargo install` → `git clone` to `/opt/` or `~/tools/` → `pip install` in a venv
3. **For one-off tools:** Clone to `/tmp/` or use `run_script` to install and run in one step
4. **For reusable tools:** Clone to `~/tools/<name>` or install system-wide so it's available for future challenges
5. After installing, use it immediately on the current problem

**Examples of when this applies:**

- Found a GitHub repo with a specific CVE exploit — clone and run it
- Discovered a specialized decoder/parser for an obscure format — install it
- Read a writeup that used a tool we don't have — install it before trying manually
- Web search reveals a purpose-built tool for exactly this challenge type — get it

**Do NOT:**

- Mention a useful tool exists but then try to solve it manually instead
- Say "if we had tool X installed, we could..." — just install it
- Reimplement functionality that an existing open-source tool already provides
- Skip installing a tool because "it might not work" — try it first, then fall back

## CTF/Bounty Tactical Methodology

These rules apply when solving CTF challenges or doing bug bounty through the MCP server. They supplement the per-category workflows available via `suggest_for_ctf` and `suggest_for_bounty`.

### Decision tree for unknown files

1. `run_tool("file", "/path")` to identify type
2. `run_pipeline` with `strings | grep -i flag` (CTF) or `strings | grep -i password\|secret\|key` (bounty)
3. `run_tool("xxd", "/path")` piped to `head` for hex inspection
4. Route by type: ELF→pwn/reversing, PCAP→networking, PNG/JPG→stego, ZIP→forensics, APK→mobile, Solidity→blockchain, text→crypto/misc

### Avoid hallucination

- **NEVER assume — verify.** Do not guess tool output. Run it, read the actual result, then reason about it.
- **Do not fabricate output.** If you haven't run a tool, do not claim results.
- **Test one variable at a time.** When exploring unknown behavior, change ONE thing per test.
- **Verify before chaining.** Before building a multi-step exploit, verify each step independently.

### Avoid dead ends

- **Follow anomalies immediately.** Unexpected output is likely the intended attack vector.
- **Pivot after 2-3 failures.** If the same approach fails 2-3 times with variations, switch to a completely different technique.
- **Test at every layer.** For web: test both the web layer (SSTI, injection) AND the application layer (instruction set, object model).
- **Keep a mental scoreboard.** Track promising leads vs dead ends. Prioritize promising leads.

### Sensitive data handling

- Flag discovered credentials/keys clearly but do NOT spread them across multiple outputs
- Do NOT exfiltrate data beyond what's needed for a minimal PoC
- Clean up temporary files containing secrets after use
- Bug bounty: report existence and access method, not the credentials themselves

## Adding a New Tool

1. Add to the appropriate array in `modules/<module>.sh`:
   - **apt**: `<PREFIX>_PACKAGES`. If the package name differs across distros, add a row to `lib/distro_compat.tsv`
   - **pipx**: `<PREFIX>_PIPX`
   - **Go**: `<PREFIX>_GO` (full path with `@latest`) + binary name in `<PREFIX>_GO_BINS`
   - **Cargo**: `<PREFIX>_CARGO`
   - **Gem**: `<PREFIX>_GEMS`
   - **Git**: `<PREFIX>_GIT` as `name=url` + directory name in `<PREFIX>_GIT_NAMES`
   - **Binary release**: `BINARY_RELEASES_<MODULE>` in `lib/installers.sh` (format: `"owner/repo|binary|pattern|dest_dir"`)
   - **Docker**: `ALL_DOCKER_IMAGES` in `lib/installers.sh` (format: `"image|label"`) + `docker_pull` call in module's install function
   - **Build from source**: `build_from_source` call in `install_module_*()` + name in `<PREFIX>_BUILD_NAMES`
2. Add entry to `tools_config.json` with `name`, `method`, `module`, `url`
3. Run `python3 scripts/validate_tools_config.py` — must show 0 errors, 0 warnings
4. If tool was added to a data source mirrored in MCP (Docker images, pipx binary names), update the Python constant and run `python3 scripts/validate_mcp_sync.py`
5. verify/update/remove scripts pick up array changes automatically
