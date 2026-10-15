# Contributing

Thanks for helping make this toolkit better. Most contributions fall into one of three buckets: **adding a tool**, **improving the installer or MCP server**, or **fixing a bug**.

Before starting anything non-trivial, open an issue first so we can agree on the approach. For small fixes (typos, broken URLs, a single tool addition), a PR is fine without prior discussion.

By participating, follow the [Code of Conduct](CODE_OF_CONDUCT.md). Do not open public issues for vulnerabilities; use [SECURITY.md](SECURITY.md).

## Issues and pull requests

Use the GitHub issue form for bugs, install failures, tool requests, feature ideas, documentation issues, and MCP/Claude integration problems. It keeps the important context in one place without requiring separate templates for every case.

Pull requests use the short PR template in `.github/PULL_REQUEST_TEMPLATE.md`. Fill in the summary, contribution type, and any validation you ran. It is fine to leave irrelevant validation boxes unchecked.

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
make setup    # submodules, locked MCP deps, sandbox deps, skill mirror
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
   {"name": "toolname", "method": "apt|pipx|go|cargo|gem|git|binary|source|docker|npm|snap|special", "module": "web", "url": "https://github.com/owner/repo"}
   ```

3. Validate locally (the first must be clean; run the others when their data changed):

   ```bash
   python3 scripts/validate_tools_config.py --strict   # 0 errors, 0 warnings
   python3 scripts/validate_mcp_sync.py            # if you touched Docker/pipx data shared with MCP
   python3 scripts/validate_distro_compat.py       # if you touched distro_compat.tsv
   ```

4. `verify.sh`, `update.sh`, and `remove.sh` pick up array changes automatically — no extra wiring needed.

Full details on the module system, install method hierarchy, and distro handling live in [AGENTS.md](AGENTS.md).

Optional installation metadata belongs in the existing module, using associative arrays keyed by the registered tool name. Shared installer and lifecycle helpers consume these arrays; avoid adding tool-named helper files or branches in common code.

| Module array suffix | Value |
| --- | --- |
| `_BUILD_BINS` | Newline-separated `relative/path\|command` outputs, all required for verification |
| `_BUILD_PACKAGES` | Space-separated build dependency packages for individual installation |
| `_BUILD_PACKAGES_<MANAGER>` | Optional package-manager override for build dependencies |
| `_PACKAGE_EXCLUSIONS` / `_PACKAGE_INCLUSIONS` | Space-separated distro IDs; inclusions override inherited exclusions |
| `_PACKAGE_BIN_NAMES` | Space-separated alternative commands to verify for a package; consumed automatically for selected modules |
| `_BINARY_ARCHITECTURES` | Space-separated toolkit architecture names for Linux release bundles |
| `_BINARY_EXCLUSIVE_DIRS` | `true` when a release owns its entire custom destination directory |
| `_BINARY_DEPENDENCIES` | Newline-separated `repo\|binary\|asset-regex\|relative-directory\|release-tag` |
| `_BINARY_RUNTIME_CONFIGS` | JSON configuration for the shared `lib/runtime_launcher.py` |
| `_BINARY_RUNTIME_RELEASES` | Optional space-separated release tags supported by the runtime configuration |

Runtime dependencies use pinned release tags, mandatory checksum verification and private bundle directories. A runtime configuration identifies the relative executable, optional working directory, library directories and required files. It preserves arguments and the caller's working directory by default. `argument_style: "cligen"` enables configured `commands` schemas with `name:short:kind` fields (`p` path, `b` boolean, `v` scalar), `default_outputs`, `conditional_defaults` and `informational_options`; caller-relative paths retain their meaning when the program needs another working directory.

Argument safety checks belong in the MCP server's shared policy registry. Their parsing must match each executable's actual CLI semantics; a common launcher does not replace authorization or scope checks. Keep tests in the existing installer, module and lifecycle suites, using synthetic fixtures for shared behavior.

## Install method priority

Prefer installation methods in this order: `apt > pipx > go > cargo > binary > gem > Docker > git clone > build from source`. Use the highest-priority method that works. Don't add a git-clone entry for something that's packaged in apt.

## Running tests

```bash
make check    # lint (shellcheck, bash -n, ruff, markdownlint), every validator, bats, pytest, sandbox tests
```

`make check` is the validation checklist; `make help` lists the narrower targets. The
sandbox tests need `npm --prefix sandbox ci --ignore-scripts` once (`make setup` does it).
CI runs the same checks on every PR, plus security scanning, CodeQL and integration. Red in draft is fine; green before merge is required.

## MCP server changes

Absolute imports only (no relative imports): `server.py` puts the repo root on `sys.path`, so `mcp_server.*` imports resolve both under `python -m mcp_server.server` and when FastMCP loads the file by path (`fastmcp dev inspector server.py`).

Hardcoded data in the MCP server must stay in sync with the bash source:

| Python | Bash source |
| --- | --- |
| `tools_db.py` → `PIPX_BIN_NAMES` | `scripts/verify.sh` `_PIPX_BIN_NAMES` |
| `tools_db.py` → `MODULE_DESCRIPTIONS` | `lib/common.sh` `MODULE_DESCRIPTIONS` |
| `tools_db.py` → `DOCKER_IMAGES` | `lib/installers.sh` `ALL_DOCKER_IMAGES` |
| `profiles.py` → `PROFILES` | `profiles/*.conf` |
| `advisor_utils.py` → `TOOL_ALIASES` targets | `tools_config.json` tool names |

`scripts/validate_mcp_sync.py` enforces these and the other mirrored constants (C2, CVE, binary-name, toolchain and audit-stream data).

## Pull requests

- Keep PRs focused. Adding one tool: one PR. Refactoring: separate PR.
- Include a brief description. For a tool addition, mention the module and install method.
- The project `.mcp.json` is tracked intentionally. Do not add personal tokens, hostnames, or local-only MCP settings to it.
- Don't commit `.versions`, generated install logs, local caches, local editor/Claude settings, or anything under `writeups/` (all gitignored).
- Use clear commit subjects ("add subfinder to recon module", not "update"). Reference issue numbers when relevant.

## Code style

- **Bash:** `shellcheck --severity=warning` clean. Use `set -uo pipefail` at the top of new scripts. Guard empty arrays with `[[ ${#arr[@]} -gt 0 ]]` before expansion (bash `set -u` safety).
- **Python (MCP server):** `ruff check` and `ruff format` clean. Absolute imports only.
- **Markdown:** `markdownlint-cli2` clean for any `.md` you add outside `writeups/`.

## Reporting security issues

Don't open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
