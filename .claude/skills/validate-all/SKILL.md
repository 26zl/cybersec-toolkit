---
name: validate-all
description: Run the full local validation suite for this installer before pushing or opening a PR. Runs shellcheck, bash syntax checks, tools_config validators, MCP sync validator, distro-compat validator, bats tests, ruff lint, and pytest. Triggers on phrases like "validate", "check before push", "run all checks", "make sure everything passes", "pre-commit check".
---

# Run the full validation suite

Run these in parallel where possible. Goal: zero errors, zero warnings before pushing.

## Bash side

```bash
# 1. Shellcheck (warning level)
shellcheck --severity=warning install.sh lib/*.sh modules/*.sh scripts/*.sh

# 2. Bash syntax
bash -n install.sh lib/*.sh modules/*.sh scripts/*.sh

# 3. Bats unit tests
./tests/bats/bin/bats tests/*.bats
```

If `tests/bats/bin/bats` is missing, init submodules first:

```bash
git submodule update --init --recursive
```

## Cross-validation

```bash
# 4. tools_config.json ↔ module arrays
python3 scripts/validate_tools_config.py

# 5. MCP hardcoded data ↔ bash sources
python3 scripts/validate_mcp_sync.py

# 6. Distro compatibility TSV
python3 scripts/validate_distro_compat.py
```

All three must report **0 errors** (validate_tools_config.py also requires 0 warnings).

## Python (MCP server) side

```bash
cd mcp_server
uv run --group dev ruff check .
uv run --group dev ruff format --check .
uv run --group dev pytest tests/ -q
```

## Markdown (writeups + project docs)

```bash
npx markdownlint-cli2 "**/*.md" "#node_modules" "#tests/bats"
```

If only working on writeups:

```bash
npx markdownlint-cli2 "workflows/**/*.md"
```

## Profiles

```bash
# Implicit in CI: validate-profiles checks profiles/*.conf module names against ALL_MODULES
grep -h '^MODULES=' profiles/*.conf | sort -u
```

## Reporting

After running, summarize results:

- ✅ which checks passed
- ❌ which failed (with file:line if available)
- Recommend the smallest fix for each failure

If a single check fails, run it again with verbose output before suggesting a fix.

## Common failure patterns

- **shellcheck SC2086**: unquoted variable expansion → wrap in `"..."`
- **validate_tools_config: missing URL** → run `python3 scripts/validate_tools_config.py --sync`
- **validate_mcp_sync: drift** → update the Python constant in `mcp_server/tools_db.py` to match the bash source
- **bats fails on Windows** → set `git config core.autocrlf input` per repo and re-checkout
- **ruff format --check fails** → `uv run --group dev ruff format .` (fixes in place)
