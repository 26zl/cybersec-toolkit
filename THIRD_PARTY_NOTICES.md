# Third-Party Notices

This project (MIT-licensed — see [`LICENSE`](LICENSE)) bundles skills and content
from third-party open-source projects. Each retains its original license. This
file is the centralized index; full license texts are vendored under
[`.claude/skills/`](.claude/skills/). The table below is the authoritative
per-source attribution. Per-skill provenance is also recorded in each vendored
skill's `SKILL.md` frontmatter: the SnailSploit, BugHunter, and Karpathy skills
carry `source` + `upstream_commit` + `license`; the Trail of Bits and Transilience
skills carry `source` + `license` (their upstream commits are recorded in the table
below, not pinned per-skill); and the Anthropic-Cybersecurity skills carry a
`license` field (and a vendored upstream `LICENSE` file). The curation manifest
[`scripts/curate_claude_skills.py`](scripts/curate_claude_skills.py) maps each
skill name to its source, and `scripts/validate_claude_skills.py` reconciles the
table's counts against the live inventory.

## Vendored Claude Code skills (`.claude/skills/`)

| Source | Skills | License | License text | Upstream |
| --- | ---: | --- | --- | --- |
| [mukul975/Anthropic-Cybersecurity-Skills (community project)](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 754 | Apache-2.0 | [`LICENSE-Apache-2.0`](.claude/skills/LICENSE-Apache-2.0) | operational how-tos; commit `673da1f3b0b7be34ffc9624ef3858fe45f1c3bed` |
| [SnailSploit Claude-Red](https://github.com/SnailSploit/Claude-Red) | 58 | MIT | [`LICENSE-Claude-Red-MIT`](.claude/skills/LICENSE-Claude-Red-MIT) | commit `aeb41eca7088a703c3a35fbcba3086d4a6c1aa4e` |
| [Trail of Bits skills](https://github.com/trailofbits/skills) | 14 | CC-BY-SA-4.0 | [`LICENSE-CC-BY-SA-4.0`](.claude/skills/LICENSE-CC-BY-SA-4.0) | commit `cfe5d7b1619e47fb5b38b7e2561dad7e5f1e89af`; code audit & vuln research; `constant-time-analysis` ships the upstream `ct_analyzer/` (commit `c070b9b`) and `zeroize-audit` its `tools/` |
| [BugHunter (claude-bug-bounty)](https://github.com/shuvonsec/claude-bug-bounty) | 10 | MIT | [`LICENSE-BugHunter-MIT`](.claude/skills/LICENSE-BugHunter-MIT) | commit `22ea70b763618984a08d6f601bb2e3e079e86a15` |
| [Transilience community tools](https://github.com/transilienceai/communitytools) | 4 | MIT | [`LICENSE-Transilience-MIT`](.claude/skills/LICENSE-Transilience-MIT) | high-level workflows; commit `58b552ef35029814b95fa53924790e3546a4a146` |
| [multica-ai/andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills) | 1 | MIT | (frontmatter attribution) | coding-agent workflow; commit `2c606141936f1eeef17fa3043a72095b4765b9c2` |

The remaining 31 skills (project developer skills, cross-skill coordinators,
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

## ShareAlike obligation (Trail of Bits skills)

The 14 Trail of Bits skills (and the vendored `ct_analyzer/` and `tools/` companion
files) are licensed under **CC-BY-SA-4.0**, a copyleft ShareAlike license. The
project's MIT grant in [`LICENSE`](LICENSE) does **not** apply to this material.
Anyone who redistributes or adapts these skills must comply with CC-BY-SA-4.0:
keep attribution to Trail of Bits, indicate any changes, and license the
redistributed material (and any adaptations) under CC-BY-SA-4.0 or a compatible
license. CC-BY-SA-4.0 material cannot be relicensed under MIT. The full license
text is vendored at
[`LICENSE-CC-BY-SA-4.0`](.claude/skills/LICENSE-CC-BY-SA-4.0).

## Runtime dependencies

The MCP server's Python dependencies are not vendored; they are declared in
[`mcp_server/pyproject.toml`](mcp_server/pyproject.toml) and pinned in
[`mcp_server/uv.lock`](mcp_server/uv.lock), each under its own upstream license.

## Installed security tools

The installer downloads 580+ third-party security tools from their official
upstream sources at install time. Those tools are **not** redistributed by this
repository and remain under their respective upstream licenses; consult each
tool's own project for terms.
