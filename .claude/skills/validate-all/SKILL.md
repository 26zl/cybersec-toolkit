---
name: validate-all
description: Run the full local validation suite for this installer before pushing or opening a PR. Covers `make check` (lint, every validator, bats, pytest, sandbox node tests) and the individual commands behind it. Triggers on phrases like "validate", "check before push", "run all checks", "make sure everything passes", "pre-commit check".
---

# Run the full validation suite

Goal: zero errors, zero warnings before pushing.

## Shortcut

```bash
make check          # lint + validate + test
# or in pieces:
make lint validate test
make lint-sh lint-py lint-md validate test-bats test-py test-sandbox
```

`make lint-py` also lints `scripts/` and `lib/`; `make validate` runs the validators listed below plus `audit_skill_dependencies.py --check-declared`, `update-skills.sh --check-pins`, `validate_agent_docs.py`, `validate_client_configs.py`, `check_doc_links.py`, `verify_audit_chain.py --selftest`, `validate_profiles.sh` and `validate_version.sh`. The individual commands follow.

## Bash side

```bash
# 1. Shellcheck (warning level)
shellcheck --severity=warning install.sh lib/*.sh modules/*.sh scripts/*.sh

# 2. Bash syntax
for f in install.sh lib/*.sh modules/*.sh scripts/*.sh; do bash -n "$f"; done

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
python3 scripts/validate_tools_config.py --strict

# 5. MCP hardcoded data ↔ bash sources
python3 scripts/validate_mcp_sync.py

# 6. Distro compatibility TSV
python3 scripts/validate_distro_compat.py

# 7. Claude Code skill metadata + index consistency (SKILLS.md counts, curation freshness)
python3 scripts/validate_claude_skills.py
```

Every validator must report **0 errors** (validate_tools_config.py also requires 0 warnings).

> If you added, removed, or renamed a skill dir under `.claude/skills/`, first update
> the `SKILLS.md` counts and regenerate the curation index and requirements, otherwise step 7 fails:
>
> ```bash
> make curate
> ```

## Python (MCP server) side

```bash
cd mcp_server
uv run --group dev ruff check .
uv run --group dev ruff format --check .
uv run --group dev pytest tests/ -q
```

## Markdown (writeups + project docs)

```bash
make lint-md    # pinned markdownlint over tracked docs, vendored skills excluded
```

If only working on writeups:

```bash
npx markdownlint-cli2 "writeups/**/*.md"
```

## Profiles

```bash
bash scripts/validate_profiles.sh
```

## Reporting

After running, summarize results:

- ✅ which checks passed
- ❌ which failed (with file:line if available)
- Recommend the smallest fix for each failure

If a single check fails, run it again with verbose output before suggesting a fix.

## Verification discipline

"It looks fine" is not evidence. A check is passed only when you have run it and read its actual output — not when you predict it would pass.

| Rationalization | Reality |
| --- | --- |
| "This change is tiny, it can't break the validators" | Tiny changes break `validate_tools_config` (one missing array entry) and `validate_mcp_sync` (one drifted constant) constantly. Run them. |
| "I only touched Python, skip shellcheck/bats" | Fine — but say so explicitly in the report; don't claim a clean run you didn't do. |
| "Tests are slow, I'll assume they pass" | Then the suite is unverified. Run it, or report it as not run. |
| "ruff format will probably be clean" | `--check` is one command. Run it instead of guessing. |

If you skip a check for a real reason (e.g. no Docker locally), **state which check was skipped and why** in the report — a skipped check is a known gap; a silently-skipped check is a false "all green".

## Common failure patterns

- **shellcheck SC2086**: unquoted variable expansion → wrap in `"..."`
- **validate_tools_config: missing URL** → run `python3 scripts/validate_tools_config.py --sync`
- **validate_mcp_sync: drift** → update the Python constant in `mcp_server/tools_db.py` to match the bash source
- **bats fails on Windows** → set `git config core.autocrlf input` per repo and re-checkout
- **ruff format --check fails** → `uv run --group dev ruff format .` (fixes in place)
