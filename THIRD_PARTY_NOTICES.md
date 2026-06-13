# Third-Party Notices

This project (MIT-licensed — see [`LICENSE`](LICENSE)) bundles skills and content
from third-party open-source projects. Each retains its original license. This
file is the centralized index; full license texts are vendored under
[`.claude/skills/`](.claude/skills/), and per-skill provenance is recorded in each
skill's `SKILL.md` frontmatter (`source` / `license` / `upstream_commit`).

## Vendored Claude Code skills (`.claude/skills/`)

| Source | Skills | License | License text | Upstream |
| --- | ---: | --- | --- | --- |
| [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 754 | Apache-2.0 | [`LICENSE-Apache-2.0`](.claude/skills/LICENSE-Apache-2.0) | operational how-tos |
| [SnailSploit Claude-Red](https://github.com/SnailSploit/Claude-Red) | 58 | MIT | [`LICENSE-Claude-Red-MIT`](.claude/skills/LICENSE-Claude-Red-MIT) | commit `aeb41eca7088a703c3a35fbcba3086d4a6c1aa4e` |
| [Trail of Bits skills](https://github.com/trailofbits/skills) | 14 | CC-BY-SA-4.0 | [`LICENSE-CC-BY-SA-4.0`](.claude/skills/LICENSE-CC-BY-SA-4.0) | code audit & vuln research; `constant-time-analysis` ships the upstream `ct_analyzer/` (commit `c070b9b`) and `zeroize-audit` its `tools/` |
| [BugHunter (claude-bug-bounty)](https://github.com/shuvonsec/claude-bug-bounty) | 10 | MIT | [`LICENSE-BugHunter-MIT`](.claude/skills/LICENSE-BugHunter-MIT) | commit `22ea70b763618984a08d6f601bb2e3e079e86a15` |
| [Transilience community tools](https://github.com/transilienceai/communitytools) | 4 | MIT | [`LICENSE-Transilience-MIT`](.claude/skills/LICENSE-Transilience-MIT) | high-level workflows |
| [multica-ai/andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills) | 1 | MIT | (frontmatter attribution) | coding-agent workflow |

The remaining 29 skills (project developer skills, cross-skill coordinators,
coverage-gap anchors, CTF methodology, and the `bounty-*` methodology set) are
authored in this repository under its MIT license.

## Vendored companion files

Some skills bundle upstream companion files skill-locally so their documented
commands and references resolve (the established pattern set by `zeroize-audit`):

| Skill | Vendored from upstream | Location |
| --- | --- | --- |
| `constant-time-analysis` | Trail of Bits `ct_analyzer/` package (`analyzer.py`, `script_analyzers.py`, `__init__.py`) | `.claude/skills/constant-time-analysis/ct_analyzer/` |
| `meme-coin-audit` | BugHunter `web3/{10,11,12}-*.md` deep-dive references | `.claude/skills/meme-coin-audit/references/` |
| `web2-vuln-classes` | BugHunter `wordlists/sensitive-files.txt` | `.claude/skills/web2-vuln-classes/references/` |

> **Note on BugHunter skills.** They are adapted for this repository. Static deep-dive
> references this project needs are vendored skill-locally (table above). The upstream
> **executable scaffolding** (`tools/*.py` / `tools/*.sh` helper scripts, the standalone
> `wordlists/` pipeline, slash-commands, and direct `pip3`/`brew`/shell-rc install steps)
> describes the standalone claude-bug-bounty layout and is **not bundled here** — it imports
> a sibling-module package plus its own installer and duplicates this repo's MCP server. A
> note at the top of each such `SKILL.md` directs users to this repo's MCP server, installer,
> and `add-tool` skill instead.

## Runtime dependencies

The MCP server's Python dependencies are not vendored; they are declared in
[`mcp_server/pyproject.toml`](mcp_server/pyproject.toml) and pinned in
[`mcp_server/uv.lock`](mcp_server/uv.lock), each under its own upstream license.

## Installed security tools

The installer downloads 580+ third-party security tools from their official
upstream sources at install time. Those tools are **not** redistributed by this
repository and remain under their respective upstream licenses; consult each
tool's own project for terms.
