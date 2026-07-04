# AGENTS.md

Vendor-neutral guidance for AI coding agents and MCP-capable assistants working in
this repository (Codex, Cursor, Continue, Cline/Roo, Goose, Aider, local LLMs behind
an MCP-capable client, and others).

> Claude Code reads [`CLAUDE.md`](CLAUDE.md), which carries the same project guidance
> plus Claude-specific extras. This file is the vendor-neutral companion — keep the two
> in sync when you change shared guidance (project layout, commands, MCP rules,
> methodology). Sections marked **(Claude-specific)** below do not apply to other agents.

## Project Overview

Modular bash installer for 580+ cybersecurity tools on Linux and Termux (Android).
Multi-distro (Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE, Termux).
12 install methods, 18 modules, 14 profiles. Includes an MCP server for AI-assisted
security work that any MCP-capable client can drive.

## How AI Integration Works Here

The integration surface is split into two layers:

1. **MCP server (`mcp_server/`) — vendor-neutral.** This is the core integration. Any
   MCP-capable client can launch it over stdio and use its 15 tools. This works with
   Claude Code/Desktop, Codex, Cursor, Continue, Cline/Roo, Goose, and local LLMs that
   run behind an MCP-capable client. A bare local model does **not** speak MCP on its
   own — it needs an agent/client wrapper that can call MCP tools.
2. **Agent instructions and skills — partly portable.** `AGENTS.md` (this file) is read
   natively by Codex and many agentic tools. `CLAUDE.md` is Claude's equivalent.
   `.claude/skills/` is a Claude Code feature; other agents can consume a mirrored copy
   via `scripts/sync-skills.sh` (see [Skills](#skills-portable-via-sync)).

### Connecting a client to the MCP server

The server is launched the same way everywhere — over stdio with `uv`:

```bash
uv run --directory mcp_server fastmcp run server.py --transport stdio --no-banner
```

| Client | Config file | Notes |
| --- | --- | --- |
| Claude Code | `.mcp.json` (tracked, repo root) | Picked up automatically; tools appear in `/mcp`. |
| Claude Desktop | `claude_desktop_config.json` | See `mcp_server/README.md`. |
| Codex | `.codex/config.toml` (repo) or `~/.codex/config.toml` | `[mcp_servers.*]` block. Codex's primary config is `~/.codex/config.toml`; if project-level config is not picked up, merge the block into the home config. |
| Cursor / Continue / Cline / Roo / Goose | client-specific MCP settings | Same command/args; consult the client's MCP docs. |
| LM Studio (≥0.3.17) | `mcp.json` (Cursor notation) | Native MCP host, no bridge needed. Add the server under `mcpServers` with an absolute path (or the git-root wrapper), since LM Studio's working directory isn't the repo. Using MCP via LM Studio's API requires ≥0.4.0 and an MCP-capable endpoint such as `/api/v1/chat` or `/v1/responses`. |
| Ollama | the MCP host/agent in front of it | Ollama is a model runtime, not an MCP host. Put an MCP-capable agent in front of it (e.g. Kit). |
| Local LLM (other) | the MCP-capable host/client wrapping it | A bare model doesn't speak MCP; configure the host (LM Studio, Cline, Continue, Goose, Kit, or Open WebUI via an MCP→OpenAPI bridge such as `mcpo`), not the model. |

Default-safe environment for every client: `CYBERSEC_MCP_ALLOW_EXTERNAL=0` and
`CYBERSEC_MCP_ALLOW_SCRIPTS=0`. Opt into scripts/external scopes only with explicit
authorization (see [MCP environment variables](#mcp-environment-variables)).

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

# Validate skill metadata and SKILLS.md counts (Claude-specific data, but the
# validator runs anywhere)
python3 scripts/validate_claude_skills.py

# Validate optional Python deps used by skill helper scripts are declared
python3 scripts/audit_skill_dependencies.py --check-declared

# Check CLAUDE.md and AGENTS.md agree (headline counts + shared MANDATORY sections)
python3 scripts/validate_agent_docs.py

# Regenerate skill curation index after adding/removing/renaming a skill dir
# (validate_claude_skills.py checks curation freshness)
python3 scripts/curate_claude_skills.py --write

# Populate missing URLs in tools_config.json from module source
python3 scripts/validate_tools_config.py --sync
```

### Testing

```bash
# Initialize bats submodules (first time only)
git submodule update --init --recursive

# Run all bats tests
./tests/bats/bin/bats tests/*.bats

# Run a single test file
./tests/bats/bin/bats tests/common.bats
```

Test files: `tests/common.bats`, `tests/install.bats`, `tests/installers.bats`,
`tests/modules.bats`, `tests/profiles.bats`. Helper at `tests/test_helper.bash`.

### MCP Server

```bash
# Install uv (one-time)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Interactive MCP Inspector (web UI)
cd mcp_server && uv run fastmcp dev server.py

# CLI entrypoint
cd mcp_server && uv run cybersec-mcp

# Python tests (must use uv to get pytest-asyncio)
cd mcp_server && uv run --group dev pytest tests/ -q

# Lint + format check
cd mcp_server && uv run --group dev ruff check . && uv run --group dev ruff format --check .
```

## MCP Server Usage (MANDATORY tool order)

**MCP tools must ALWAYS be used first.** For an unclear or high-level security task,
start with `guided_assessment` (or `suggest_for_ctf` / `suggest_for_bounty`) so MCP can
infer the workflow/problem type and choose the right tools. Execution priority after
that is `run_tool` → `run_pipeline` → `run_script`. Use `run_tool("curl", ...)` for HTTP,
`run_tool("nmap", ...)` for scanning, etc. Only fall back to `run_script` when you need
actual programming logic (loops, exploit code, complex parsing). If `run_tool` is
blocked by policy (e.g. `CYBERSEC_MCP_ALLOW_EXTERNAL=0`), tell the user to fix config
and restart — do **not** silently bypass with `run_script`.
In opt-in `guided_assessment(mode="autonomous")`, if appropriate tools/pipelines do not
make progress after real output is reviewed and programming logic is the smallest reliable
path, the AI/client agent should create, save, and run scoped helper scripts via
`run_script`; persist reusable scripts under `manual_scripts/`. Simple recon/HTTP commands
such as `curl` remain normal `run_tool` calls.

15 AI-accessible tools: `list_tools`, `check_installed`, `get_tool_info`,
`get_module_info`, `get_profile_tools`, `suggest_for_ctf`, `suggest_for_bounty`,
`guided_assessment`, `get_cve_info`, `recommend_install`, `list_profiles`, `run_tool`, `run_pipeline`,
`run_script`, `manage_remote_hosts`.

### MCP environment variables

- `CYBERSEC_MCP_ALLOW_SCRIPTS=1` — enables unsandboxed Python/Bash execution with
  the MCP process user's filesystem and network permissions
- `CYBERSEC_MCP_ALLOW_EXTERNAL=0` — safest default; governed network tools and
  SSH remotes target private/loopback only (it does not sandbox `run_script`)
- `CYBERSEC_MCP_ALLOW_EXTERNAL=1` — opt in only for explicitly authorized external scopes
- `CYBERSEC_MCP_VENVS_DIR` — custom location for script venvs (default: `~/.ctf-venvs/`)
- `CYBERSEC_MCP_AUDIT_LOG` — custom audit path (default:
  `~/.local/state/cybersec-tools-mcp/audit.log`)
- `CYBERSEC_MCP_AUDIT_REQUIRED=1` — fail startup instead of falling back to stderr
  when file audit logging is unavailable
- `CYBERSEC_INSTALLER_ROOT` — override project root for `tools_config.json` lookup

## Architecture

### Source Chain

`lib/common.sh` → `lib/installers.sh` → `lib/shared.sh` → `modules/<name>.sh`

All scripts source the chain in this order. `common.sh` auto-detects distro/pkg manager
on source. `scripts/verify.sh`, `scripts/update.sh`, `scripts/remove.sh` source ALL
modules to access arrays.

### Module System

18 modules, each in `modules/<name>.sh`, each defining arrays with a consistent prefix
and an `install_module_<name>()` function. Arrays: `<PREFIX>_PACKAGES` (apt),
`<PREFIX>_PIPX`, `<PREFIX>_GO`, `<PREFIX>_CARGO`, `<PREFIX>_GEMS`, `<PREFIX>_GIT`
(name=url pairs), `<PREFIX>_GO_BINS`, `<PREFIX>_GIT_NAMES`. Prefixes: `MISC`, `NET`,
`RECON`, `WEB`, `CRYPTO`, `PWN`, `RE`, `FORENSICS`, `ENTERPRISE`, `WIRELESS`,
`CRACKING`, `STEGO`, `CLOUD`, `CONTAINER`, `BLUETEAM`, `MOBILE`, `BLOCKCHAIN`, `LLM`.

### Profile System

14 profiles in `profiles/*.conf`. Each sets `MODULES="..."`, `SKIP_HEAVY`,
`ENABLE_DOCKER`, `INCLUDE_C2`. Used via `install.sh --profile <name>`.

### MCP Server Module Layout (`mcp_server/`)

Separate Python package (FastMCP), managed with `uv` (`pyproject.toml`), not pip/venv.

- `server.py` — FastMCP tool registrations (15 tools)
- `cve_advisor.py` — CVE → curated skills/tools/modules mapping + live NVD/KEV/EPSS lookup commands (local-first)
- `guided_assessment.py` — companion-first target/finding classification, triage/report
  routing, tool selection, and opt-in autonomous solving. Autonomous mode uses governed
  `run_tool`/`run_pipeline` calls and may use the separately enabled, unsandboxed
  `run_script` capability for scoped helpers; scripts must not bypass authorization,
  scope, or policy decisions
- `security.py` — execution engine + policy enforcement + argument sanitization
- `tools_db.py` — tool registry loader, install checks, version tracking
- `advisor_utils.py` — shared alias map + install-status helpers used by the advisor modules
- `profiles.py` — profile data (synced from `profiles/*.conf`)
- `ctf_advisor.py` / `bounty_advisor.py` — category suggestions and methodology
- `remote.py` — SSH-based remote tool execution
- `audit.py` — JSON-line audit logging (5MB rotating)
- `sanitize.py` — output processing (ANSI stripping, injection-marker stripping)

Key design decisions: absolute imports with `sys.path` fixup (no relative imports);
`TOOL_ALIASES` in `advisor_utils.py` maps friendly names to registry names; Termux-aware
(omits `sudo` when `TERMUX_VERSION` is set); all subprocess code uses
`create_subprocess_exec` (no `shell=True`) and `_bounded_communicate()` (not
`communicate()`).

**Hardcoded data that must stay in sync with bash sources** (validated by
`scripts/validate_mcp_sync.py`): `tools_db.py` `PIPX_BIN_NAMES` ↔ `scripts/verify.sh`;
`tools_db.py` `MODULE_DESCRIPTIONS` ↔ `lib/common.sh`; `tools_db.py` `DOCKER_IMAGES` ↔
`lib/installers.sh` `ALL_DOCKER_IMAGES`; `profiles.py` `PROFILES` ↔ `profiles/*.conf`;
`advisor_utils.py` `TOOL_ALIASES` targets ↔ `tools_config.json` tool names.

### Install Method Hierarchy

Preferred order: `apt > pipx > go > cargo > binary > gem > Docker > git clone > source`

## Skills (portable via sync)

`.claude/skills/` ships 872 on-demand skills (CTF/bounty methodology, offensive/defensive
how-tos, code-audit skills, project developer skills, and cross-skill coordinators). They
are a **Claude Code feature**, but the content is plain Markdown + helper scripts and is
useful to any agent.

To make them available to Codex and other agents that read `.agents/skills/`, mirror them:

```bash
scripts/sync-skills.sh            # mirror .claude/skills/ -> .agents/skills/
scripts/sync-skills.sh --check    # report drift without writing
```

`.claude/skills/` is the **single source of truth**; `.agents/skills/` is a generated
mirror and is git-ignored. Re-run the sync after editing skills. Source/category index:
[`.claude/skills/SKILLS.md`](.claude/skills/SKILLS.md).

Vendored skills are copies (not submodules) of six upstream repos, each pinned to a
commit in `SKILLS.md`. `scripts/update-skills.sh` clones every pinned source and reports
drift per skill (in sync / locally modified / upstream-only / local-only) plus whether a
source's HEAD moved past the pin. It only reports — re-vendoring is manual. "locally
modified" is an upper bound: it also counts the `source:`/`license:` frontmatter we add
and the upstream helper dirs we trim, so review the listed skills, not the raw count.
When you re-vendor a source, bump its pin in `SKILLS.md`, `THIRD_PARTY_NOTICES.md`, and
the `SOURCES` array in that script; `update-skills.sh --check-pins` (offline, no cloning)
asserts all four places — including per-skill `upstream_commit` frontmatter — agree, and
runs as a CI gate. A weekly workflow (`.github/workflows/skills-update.yml`) opens a
`skills-update` tracking issue when a source advances past its pin (past a 3-day cooldown)
or ships new skills — the notify-only analog of Dependabot, which does not cover copies.

Each skill is `<name>/SKILL.md` with frontmatter where `name` must equal the directory
name. `SKILLS.md` counts, generated `curation.json` + `CURATION.md` (written by
`scripts/curate_claude_skills.py --write`), and `.claude/skills/requirements.txt`
(written by `scripts/audit_skill_dependencies.py --write-requirements`) must stay
consistent; validate with `validate_claude_skills.py` and
`audit_skill_dependencies.py --check-declared`. **Cross-skill coordinators** other
skills route through: `finding-triage` (finding → disposition), `security-comms`
(audience translation), `authorization-gate` (pre-flight auth check), and
`evidence-hygiene` (sanitize report/writeup evidence before sharing). The repo is also a
**Claude Code plugin marketplace** (`.claude-plugin/`); the skills install via
`/plugin marketplace add 26zl/cybersec-toolkit`.

## Important Patterns

- All scripts use `set -uo pipefail` (not `-e` — individual tool failures don't abort)
- Empty arrays guarded with `[[ ${#arr[@]} -gt 0 ]]` before expansion (bash `set -u`)
- Version tracking: `.versions` file with `tool|method|version|timestamp` format
- Non-system binaries end up in `/usr/local/bin` (Linux) or `$PREFIX/bin` (Termux)
- Binary releases SHA256-verified when checksums available; `--production` or
  `--require-checksums` makes missing checksums a hard failure
- GitHub API auth: auto-detects `gh auth token` if `GITHUB_TOKEN` is unset (60 → 5000 req/hr)
- `fixup_package_names()` in `lib/installers.sh` translates package names per distro from
  `lib/distro_compat.tsv`
- `.gitattributes` enforces `* text=auto eol=lf` — prevents CRLF breakage on Windows

## DANGER: Never Read Unvalidated Images

**NEVER open image files (PNG, JPG, PPM, BMP, etc.) with a vision/Read tool without
first verifying they are valid.** A corrupt image can poison the conversation context.
Validate first: `run_tool("file", "/path")` → `run_tool("identify", "/path")` (or PIL),
and only view if both checks pass. Treat any reconstructed/extracted image as suspect
until proven valid.

## Writeups (MANDATORY)

After completing any substantive security workflow with this project, **always** write a
clear technical writeup in `writeups/`. This applies to everything the project helps
solve: CTF challenges, bug bounty findings, CVE reproduction or validation,
vulnerability research, guided MCP assessments, pentest/recon workflows,
malware/forensics/DFIR cases, cloud/API/mobile/network/web security reviews, and
tool-assisted investigations or troubleshooting.

Use a descriptive filename that makes the subject obvious. Recommended format:
`writeups/<category>/<descriptive-case-name>.md` (for example,
`writeups/ctf/htb-pilgrimage.md`, `writeups/bug-bounty/example-idor.md`,
`writeups/cve/CVE-2024-xxxx-reproduction.md`, or
`writeups/guided-assessment/example-web-recon.md`). Writeups must pass
`npx markdownlint-cli2 "writeups/**/*.md"`.

Writing style: write like a human pentester — direct, technical, no filler. No AI-style
language ("Let's", "I'll", "Great question"). Use "we"/passive voice. Include exact
commands, output (trimmed), payloads, flags. Document dead ends too.

Structure: Context/Scope → Recon/Analysis → Exploitation/Validation → Dead Ends →
Finding/Result → Tools Used → Lessons Learned → Cleanup/Safety Notes, with a header
block appropriate to the case (Platform/Program, Category, Difficulty/Severity, Date).

## Tool-First Approach (MANDATORY)

**ALWAYS use existing tools before attempting anything manually**, across all categories.
Before starting: check `writeups/` for prior writeups, run `suggest_for_ctf` /
`suggest_for_bounty`, check installs with `check_installed`, browse with `list_tools`.

Do NOT: skip tools and jump to custom scripts; use `run_script` with requests/urllib when
`run_tool("curl", ...)` works; hand-parse binaries when `binwalk`/`strings`/`readelf`
exist; write custom scanners/fuzzers when `nmap`/`ffuf`/`gobuster` are installed.
When existing tools and pipelines genuinely stop making progress, use `run_script` for the
missing logic. The AI/client agent should create these scripts for the user and put
reusable multi-step helpers in `manual_scripts/`.

## Discovering and Adding New Tools (Approval-Gated)

If you discover a tool that would help and is NOT in the registry: recommend it with
evidence (use case, source URL, trust signal) first; install only with explicit user
approval and authorized scope; prefer `apt`/`pipx`/`go install`/`cargo install` →
`git clone` → `pip install` in a venv. For reusable tools, add them to
`tools_config.json` and the matching module installer. Do not reimplement what an
existing open-source tool already provides.

## CTF/Bounty Tactical Methodology

- **Decision tree for unknown files:** `run_tool("file", ...)` → `run_pipeline` with
  `strings | grep -i flag` (CTF) or `... password|secret|key` (bounty) → `xxd | head` →
  route by type (ELF→pwn/rev, PCAP→net, PNG/JPG→stego, ZIP→forensics, APK→mobile,
  Solidity→blockchain, text→crypto/misc).
- **Avoid hallucination:** never assume — run the tool, read the real output. Do not
  fabricate output. Test one variable at a time. Verify each step before chaining.
- **Avoid dead ends:** follow anomalies immediately; pivot after 2-3 failures; test at
  every layer; keep a mental scoreboard of leads vs dead ends.
- **Sensitive data:** flag discovered credentials/keys clearly but don't spread them
  across outputs; don't exfiltrate beyond a minimal PoC; clean up temp secret files;
  for bug bounty, report existence and access method, not the credentials themselves.

## Adding a New Tool

1. Add to the appropriate array in `modules/<module>.sh` (apt → `<PREFIX>_PACKAGES`
   with a `lib/distro_compat.tsv` row if names differ; pipx → `<PREFIX>_PIPX`; Go →
   `<PREFIX>_GO` + `<PREFIX>_GO_BINS`; Cargo → `<PREFIX>_CARGO`; Gem → `<PREFIX>_GEMS`;
   Git → `<PREFIX>_GIT` + `<PREFIX>_GIT_NAMES`; binary → `BINARY_RELEASES_<MODULE>` in
   `lib/installers.sh`; Docker → `ALL_DOCKER_IMAGES` + `docker_pull` call; source →
   `build_from_source` + `<PREFIX>_BUILD_NAMES`).
2. Add an entry to `tools_config.json` (`name`, `method`, `module`, `url`).
3. Run `python3 scripts/validate_tools_config.py` — must show 0 errors, 0 warnings.
4. If the tool touches a data source mirrored in the MCP server, update the Python
   constant and run `python3 scripts/validate_mcp_sync.py`.
5. verify/update/remove scripts pick up array changes automatically.
