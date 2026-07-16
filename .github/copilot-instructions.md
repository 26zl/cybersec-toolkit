# GitHub Copilot instructions for the Cybersec Toolkit

This file provides concise guidance to GitHub Copilot when working in this
repository. For full project guidance, see [`AGENTS.md`](../AGENTS.md).

## Repository architecture

- `tools_config.json` — tool-registry source of truth
- `.claude/skills/` — maintained skill source
- `.agents/skills/` — generated mirror (run `scripts/sync-skills.sh`)
- `mcp_server/` — vendor-neutral FastMCP server
- `install.sh` + `lib/` + `modules/` — bash installer
- `profiles/*.conf` — install profiles
- `scripts/` — validators, sync, update, remove, verify

## Validation commands

```bash
make check          # everything CI runs
make lint           # shellcheck + ruff + markdownlint
make test           # bats + pytest
make validate       # all data-consistency validators
```

## MCP source-of-truth rules

- `tools_config.json` is the single tool-registry source of truth.
- `.claude/skills/` is the single skill source of truth.
- `.agents/skills/` is a generated mirror — never edit it directly.
- `AGENTS.md` and `CLAUDE.md` must stay synchronized.
- MCP hardcoded data must match bash sources (validated by `validate_mcp_sync.py`).

## Safe editing practices

- All shell scripts use `set -uo pipefail`.
- Guard empty arrays with `[[ ${#arr[@]} -gt 0 ]]` before expansion.
- Never use `shell=True` in Python subprocess code.
- Use `_bounded_communicate()` instead of `communicate()`.
- Binary releases are SHA256-verified when checksums are available.

## Python conventions (mcp_server/)

- Absolute imports with `sys.path` fixup (no relative imports).
- Managed with `uv` (`pyproject.toml`), not pip/venv.
- 3-day `exclude-newer` window for dependency resolution.
- Ruff for linting and formatting (line length 120).

## Shell conventions

- `lib/common.sh` → `lib/installers.sh` → `lib/shared.sh` → `modules/<name>.sh`
- Module arrays: `<PREFIX>_PACKAGES`, `<PREFIX>_PIPX`, `<PREFIX>_GO`, etc.
- `fixup_package_names()` translates package names per distro from `lib/distro_compat.tsv`.
- GitHub API auth auto-detects `gh auth token` if `GITHUB_TOKEN` is unset.

## Execution policy

- MCP execution must go through the governed path (`security.py`).
- Never bypass a denied `run_tool` with `run_script`, shell execution, or
  another MCP client.
- `CYBERSEC_MCP_ALLOW_EXTERNAL=0` and `CYBERSEC_MCP_ALLOW_SCRIPTS=0` are
  the safe defaults.
