# Third-Party Notices

This project (MIT-licensed — see [`LICENSE`](LICENSE)) bundles skills and content
from third-party open-source projects. Each retains its original license. This
file is the centralized index; full license texts are vendored under
[`.claude/skills/`](.claude/skills/). The table below is the authoritative
per-source attribution. Per-skill provenance is also recorded in each vendored
skill's `SKILL.md` frontmatter: the SnailSploit, BugHunter, Karpathy and ctf-skills
skills carry `source` + `upstream_commit` + `license`; the Trail of Bits and Transilience
skills carry `source` + `license` (their upstream commits are recorded in the table
below, not pinned per-skill); and the Anthropic-Cybersecurity skills carry a
`license` field (and a vendored upstream `LICENSE` file). The curation manifest
[`scripts/curate_claude_skills.py`](scripts/curate_claude_skills.py) maps each
skill name to its source, and `scripts/validate_claude_skills.py` reconciles the
table's counts against the live inventory.

## Vendored Claude Code skills (`.claude/skills/`)

| Source | Skills | License | License text | Upstream |
| --- | ---: | --- | --- | --- |
| [mukul975/Anthropic-Cybersecurity-Skills (community project)](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 754 | Apache-2.0 | [`LICENSE-Apache-2.0`](.claude/skills/LICENSE-Apache-2.0) | operational how-tos; commit `54a798831d2266a3ca61ce68a7acb80b81160d57` |
| [SnailSploit Claude-Red](https://github.com/SnailSploit/Claude-Red) | 58 | MIT | [`LICENSE-Claude-Red-MIT`](.claude/skills/LICENSE-Claude-Red-MIT) | commit `fd81441b613c7d4fab39256720a31c96859d138b` |
| [Trail of Bits skills](https://github.com/trailofbits/skills) | 14 | CC-BY-SA-4.0 | [`LICENSE-CC-BY-SA-4.0`](.claude/skills/LICENSE-CC-BY-SA-4.0) | commit `149d7b21f4067765b82e67029730b42d228ef4b4`; code audit & vuln research; `insecure-defaults` is kept at commit `cfe5d7b1619e47fb5b38b7e2561dad7e5f1e89af`, the last upstream version that shipped it as a skill; `constant-time-analysis` ships the upstream `ct_analyzer/` (commit `c070b9b`) and `zeroize-audit` its `tools/` |
| [BugHunter (awarexone/Agentic-Bug-Hunter, formerly shuvonsec/claude-bug-bounty)](https://github.com/awarexone/Agentic-Bug-Hunter) | 10 | MIT | [`LICENSE-BugHunter-MIT`](.claude/skills/LICENSE-BugHunter-MIT) | commit `82f4512ec432765297c36e6b3ef7dc3fe5a58be2` |
| [Transilience community tools](https://github.com/transilienceai/communitytools) | 4 | MIT | [`LICENSE-Transilience-MIT`](.claude/skills/LICENSE-Transilience-MIT) | high-level workflows; commit `95fdc128af4ca1ae16b3226f9430f1bad97b0656` |
| [multica-ai/andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills) | 1 | MIT | [`LICENSE-Karpathy-MIT`](.claude/skills/LICENSE-Karpathy-MIT) (upstream declares MIT in README/frontmatter but ships no LICENSE file) | coding-agent workflow; commit `2c606141936f1eeef17fa3043a72095b4765b9c2` |
| [ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills) | 8 | MIT | [`LICENSE-ctf-skills-MIT`](.claude/skills/LICENSE-ctf-skills-MIT) | CTF solving workflow; commit `20d182d9377f0467830f314bb0f843cae4dbf55e`; the `allowed-tools` grants and the `ctf-similar-search` helper scripts are not vendored, each `SKILL.md` carries a vendored note, and upstream `ctf-crypto`, `ctf-forensics`, `ctf-pwn` and `ctf-web` are not vendored because the project-authored skills of those names stay |

Changes to the Apache-2.0 skills (§4(b)): repository copies may add `source`/`license` frontmatter and a full per-skill `LICENSE`; content changes are listed here. `scripts/update-skills.sh --local-edits` lists every vendored file that differs from all upstream versions, so this list can be checked against the tree.

- `implementing-scim-provisioning-with-okta/scripts/process.py` runs its Flask server with `debug=False` (upstream enables the Werkzeug debugger on all interfaces) and reads its bearer token from `SCIM_BEARER_TOKEN` instead of a literal, comparing in constant time and rejecting every request when it is unset.
- `performing-threat-emulation-with-atomic-red-team/scripts/agent.py` runs and cleans up Atomic tests only when `CYBERSEC_SKILL_ALLOW_ATOMIC_EXECUTION=1` is set.
- `analyzing-email-headers-for-phishing-investigation/SKILL.md` and its `references/api-reference.md` read API keys from `ABUSEIPDB_API_KEY` and `VT_API_KEY` instead of inline placeholders.
- Syntax fixes without a behavior change: escape sequences in `analyzing-windows-amcache-artifacts/scripts/agent.py`, `hunting-for-living-off-the-land-binaries/scripts/process.py`, `implementing-api-threat-protection-with-apigee/scripts/agent.py` and `performing-ransomware-tabletop-exercise/scripts/agent.py`; the `global` statement order in `building-vulnerability-dashboard-with-defectdojo/scripts/process.py`; an `if`/`elseif` chain for an invalid `switch` in `detecting-ntlm-relay-with-event-correlation/scripts/audit_smb_signing.ps1`.
- Unused code removed: an import in `analyzing-android-malware-with-apktool/scripts/agent.py` and `exploiting-active-directory-with-bloodhound/scripts/process.py`; an import and an unused parameter in `exploiting-nosql-injection-vulnerabilities/scripts/process.py`.
- Explanatory comments added in `building-c2-infrastructure-with-sliver-framework/scripts/process.py`, `exploiting-http-request-smuggling/scripts/agent.py` and `exploiting-active-directory-with-bloodhound/scripts/process.py`.
- Table separators normalized in `exploiting-kerberoasting-with-impacket/SKILL.md` and `exploiting-zerologon-vulnerability-cve-2020-1472/SKILL.md`.
- The full Apache-2.0 text replaces a truncated upstream `LICENSE` in `implementing-attack-surface-management` and `performing-cloud-log-forensics-with-athena`.
- Not vendored: the six upstream `SKILL.es.md` translations and `hunting-for-anomalous-powershell-execution/references/api-reference.md`.

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
> **executable scaffolding** (`bughunter/tools/*.py` / `bughunter/tools/*.sh` helper scripts, the standalone
> `wordlists/` pipeline, slash-commands, and direct `pip3`/`brew`/shell-rc install steps)
> describes the standalone upstream layout and is **not bundled here** — it imports
> a sibling-module package plus its own installer and duplicates this repo's MCP server. A
> note at the top of each such `SKILL.md` directs users to this repo's MCP server, installer,
> and `add-tool` skill instead, and maps the upstream helper scripts the text names to the
> registry tool or skill that takes their place. Invisible characters in upstream examples (Unicode tag
> characters, zero-width spaces) are written as visible `<U+XXXX>` escapes.

## ShareAlike obligation (Trail of Bits skills)

The 14 Trail of Bits skills (and the vendored `ct_analyzer/` and `tools/` companion
files) are licensed under **CC-BY-SA-4.0**, a copyleft ShareAlike license. The
project's MIT grant in [`LICENSE`](LICENSE) does **not** apply to this material.
The repository copies add provenance/license frontmatter, drop the `allowed-tools`
frontmatter key (Claude Code reads it as permission to run the named tools without
asking), and omit upstream helper directories, and the `uv.lock` files of helper
scripts, except for the companion files listed above; these are the material
changes made for repository packaging.
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

The sandbox launcher's Node dependencies are likewise not vendored; they are
declared in [`sandbox/package.json`](sandbox/package.json) and pinned in
[`sandbox/package-lock.json`](sandbox/package-lock.json). Its direct dependency
is [`@ai-hero/sandcastle`](https://github.com/mattpocock/sandcastle) (MIT).

## Installed security tools

The installer downloads 670+ third-party security tools from their official
upstream sources at install time. Those tools are **not** redistributed by this
repository and remain under their respective upstream licenses; consult each
tool's own project for terms.
