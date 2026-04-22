# Contributing

Thanks for helping make this toolkit better. Most contributions fall into one of three buckets: **adding a tool**, **improving the installer or MCP server**, or **fixing a bug**.

Before starting anything non-trivial, open an issue first so we can agree on the approach. For small fixes (typos, broken URLs, a single tool addition), a PR is fine without prior discussion.

## Quick start

```bash
git clone https://github.com/26zl/cybersec-toolkit.git
cd cybersec-toolkit
git submodule update --init --recursive
```

Dev dependencies:

```bash
# Shell linting
sudo apt install shellcheck

# MCP server (requires uv)
curl -LsSf https://astral.sh/uv/install.sh | sh
cd mcp_server && uv sync --group dev
```

## Adding a tool

1. Find the right module in `modules/<name>.sh` and add the tool to the correct array:

   | Array suffix | Use for | Format |
   | --- | --- | --- |
   | `_PACKAGES` | apt / dnf / pacman packages | `toolname` |
   | `_PIPX` | Python tools via pipx | `toolname` |
   | `_GO` + `_GO_BINS` | Go tools | full module path with `@latest` + binary name |
   | `_CARGO` | Rust tools | `crate-name` |
   | `_GEMS` | Ruby gems | `gem-name` |
   | `_GIT` + `_GIT_NAMES` | Git repos | `name=url` + directory name |

   If the package name differs across distros, add a row to `lib/distro_compat.tsv` (columns: `debian dnf pacman zypper pkg`; use `-` to skip, empty for passthrough, `a+b` to expand).

2. Add a matching entry to `tools_config.json`:

   ```json
   {"name": "toolname", "method": "apt|pipx|go|cargo|gem|git|binary|docker", "module": "web", "url": "https://github.com/owner/repo"}
   ```

3. Validate locally (all three must be clean):

   ```bash
   python3 scripts/validate_tools_config.py        # 0 errors, 0 warnings
   python3 scripts/validate_mcp_sync.py            # if you touched Docker/pipx data shared with MCP
   python3 scripts/validate_distro_compat.py       # if you touched distro_compat.tsv
   ```

4. `verify.sh`, `update.sh`, and `remove.sh` pick up array changes automatically — no extra wiring needed.

Full details on the module system, install method hierarchy, and distro handling live in [CLAUDE.md](CLAUDE.md).

## Install method priority

Prefer installation methods in this order: `apt > pipx > go > cargo > binary > gem > Docker > git clone > build from source`. Use the highest-priority method that works. Don't add a git-clone entry for something that's packaged in apt.

## Running tests

```bash
# Shell (must pass before push)
shellcheck --severity=warning install.sh lib/*.sh modules/*.sh scripts/*.sh
bash -n install.sh lib/*.sh modules/*.sh scripts/*.sh

# Bats unit tests
./tests/bats/bin/bats tests/*.bats

# MCP server
cd mcp_server
uv run --group dev ruff check .
uv run --group dev ruff format --check .
uv run --group dev pytest tests/ -q
```

CI runs all of these on every PR. Red in draft is fine; green before merge is required.

## MCP server changes

Absolute imports only (no relative imports) — required for compatibility with both `python -m mcp_server.server` and `fastmcp dev server.py`. See `mcp_server/README.md` for the full rationale.

Hardcoded data in the MCP server must stay in sync with the bash source:

| Python | Bash source |
| --- | --- |
| `tools_db.py` → `PIPX_BIN_NAMES` | `scripts/verify.sh` `_PIPX_BIN_NAMES` |
| `tools_db.py` → `MODULE_DESCRIPTIONS` | `lib/common.sh` `MODULE_DESCRIPTIONS` |
| `tools_db.py` → `DOCKER_IMAGES` | `lib/installers.sh` `ALL_DOCKER_IMAGES` |
| `profiles.py` → `PROFILES` | `profiles/*.conf` |

`scripts/validate_mcp_sync.py` enforces this.

## Pull requests

- Keep PRs focused. Adding one tool: one PR. Refactoring: separate PR.
- Include a brief description. For a tool addition, mention the module and install method.
- Don't commit `.mcp.json`, `.versions`, or anything under `workflows/` (all gitignored).
- Use clear commit subjects ("add subfinder to recon module", not "update"). Reference issue numbers when relevant.

## Code style

- **Bash:** `shellcheck --severity=warning` clean. Use `set -uo pipefail` at the top of new scripts. Guard empty arrays with `[[ ${#arr[@]} -gt 0 ]]` before expansion (bash `set -u` safety).
- **Python (MCP server):** `ruff check` and `ruff format` clean. Absolute imports only.
- **Markdown:** `markdownlint-cli2` clean for any `.md` you add outside `workflows/`.

## Reporting security issues

Don't open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
