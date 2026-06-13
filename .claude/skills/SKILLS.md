# Claude Code Skills

This directory contains 870 skills that activate on demand based on what you're working on. Skills extend Claude Code without permanently consuming context.

## Project-specific developer skills (9)

Maintained in this repo. Cover the install-side workflow.

| Skill | When it activates |
| --- | --- |
| `add-tool` | Adding a new tool to a module + tools_config.json |
| `module-scaffold` | Creating a brand-new `modules/<name>.sh` |
| `validate-all` | Running the full validation suite before push |
| `mcp-sync-check` | Verifying Python ↔ Bash data parity |
| `writeup-template` | Generating workflows/<comp>/<chal>.md after a solve |
| `security-wordlists` | Pointing to SecLists / PayloadsAllTheThings paths |
| `security-payloads` | Quick-reference exploit payloads |
| `skill-dependency-audit` | Auditing optional Python imports used by vendored skill helper scripts |
| `skill-curation-router` | Choosing/ranking skills for broad tasks and reducing duplicate skill noise |

## Coverage gap anchor skills (7)

Maintained in this repo to cover domains that are intentionally thinner in the vendored operational skill set.

| Skill | Domain |
| --- | --- |
| `grc-compliance-privacy-program` | GRC, compliance, privacy, audit readiness, evidence mapping |
| `ai-llm-security-review` | AI/LLM app security, RAG, agent tools, evals, model supply chain |
| `iot-embedded-hardware-security-assessment` | IoT, embedded, firmware, hardware interfaces, OTA, device cloud |
| `mainframe-security-assessment` | z/OS, RACF/ACF2/Top Secret, CICS, DB2, JCL, APF, USS |
| `telecom-5g-security-assessment` | 5G/mobile core, RAN, roaming, SS7/Diameter/GTP, SBA APIs |
| `sap-erp-security-assessment` | SAP, S/4HANA, NetWeaver, ABAP, HANA, RFC, Gateway, SoD |
| `supply-chain-prodsec-hardening` | SBOM, SLSA, provenance, signing, pinning, CI/CD release security |

## Coding-agent workflow skills (1)

| Skill | What it does |
| --- | --- |
| `karpathy-guidelines` | Keeps coding agents simple, surgical, assumption-aware, and verification-driven |

## Cross-skill coordinators (3)

Maintained in this repo. Other skills route their output through these for normalization, communication, and pre-flight authorization.

| Skill | What it does |
| --- | --- |
| `finding-triage` | Normalizes a single finding (scanner/audit/pentest/CVE) into a defensible disposition: Fixed, Deferred, Accepted Risk, or False Positive |
| `security-comms` | Translates a finding/incident/update for a specific audience — board, exec, engineering, customer, legal, procurement |
| `authorization-gate` | Shared pre-flight authorization check for offensive/simulation work; defines scope confirmation and hard refusals |

## CTF methodology (6)

Per-category decision trees + tool ordering.

| Skill | Category |
| --- | --- |
| `ctf-crypto` | RSA, AES, classical, ECC, lattice |
| `ctf-pwn` | BOF, ROP, fmtstr, heap, pwntools venv |
| `ctf-web` | SQLi/XSS/SSTI/SSRF/upload/JWT |
| `ctf-rev` | ELF/PE/Java/.NET/WASM/anti-debug/custom VMs |
| `ctf-forensics` | PCAP, memory, disk, MFT, log |
| `ctf-stego` | LSB, audio spectrogram, polyglots |

## Bug bounty methodology (4)

| Skill | Phase |
| --- | --- |
| `bounty-recon` | Scope-aware passive + active enum |
| `bounty-web` | OWASP web app testing |
| `bounty-api` | OWASP API Top 10 + GraphQL |
| `bounty-mobile` | APK/IPA static + dynamic + Frida |

## BugHunter — bug bounty workflow (10)

MIT — see `LICENSE-BugHunter-MIT`. Source: <https://github.com/shuvonsec/claude-bug-bounty>, commit `22ea70b763618984a08d6f601bb2e3e079e86a15`.

Use these only for authorized security research, training, CTF/lab work, or testing within an approved bug bounty program scope.

| Skill | Role |
| --- | --- |
| `bb-methodology` | Session orchestrator — 5-phase non-linear workflow + critical-thinking framework |
| `bug-bounty` | Master end-to-end workflow (recon → hunt → LLM/AI testing → chaining → report) |
| `web2-recon` | Subdomain enum, live host discovery, URL crawl, JS analysis, monitoring |
| `web2-vuln-classes` | 22 web2 bug classes with root causes, bypass tables, paid examples |
| `security-arsenal` | Payloads, bypass tables, gf patterns, always-rejected + chain-only lists |
| `triage-validation` | 7-Question Gate + 4 pre-submission gates before writing a report |
| `report-writing` | H1/Bugcrowd/Intigriti/Immunefi templates, impact-first, CVSS 3.1 |
| `credential-attack` | Password-spray methodology + BBP legal guardrails (hard-stop before spray) |
| `web3-audit` | Smart contract audit — 10 DeFi bug classes + Foundry PoC template |
| `meme-coin-audit` | Token/meme-coin rug pull + honeypot + LP attack detection |

## SnailSploit Claude-Red — offensive methodology (58)

MIT — see `LICENSE-Claude-Red-MIT`. Source: <https://github.com/SnailSploit/Claude-Red>, commit `aeb41eca7088a703c3a35fbcba3086d4a6c1aa4e`.

Use these only for authorized security research, training, CTF/lab work, or scoped assessments.

| Category | Skills |
| --- | ---: |
| `web` | 16 |
| `wireless` | 14 |
| `infrastructure` | 7 |
| `exploit-dev` | 6 |
| `fuzzing` | 4 |
| `auth` | 2 |
| `recon` | 2 |
| `utility` | 2 |
| `active-directory` | 1 |
| `ai` | 1 |
| `cloud` | 1 |
| `iot` | 1 |
| `mobile` | 1 |

## Trail of Bits — code audit & vulnerability research (14)

CC-BY-SA 4.0 — see `LICENSE-CC-BY-SA-4.0`. Source: <https://github.com/trailofbits/skills>.

| Skill | What it does |
| --- | --- |
| `yara-rule-authoring` | Author + lint YARA detection rules with examples |
| `semgrep` | Use Semgrep for SAST scanning |
| `semgrep-rule-creator` | Author custom Semgrep rules |
| `codeql` | CodeQL queries + DB build + threat models |
| `sarif-parsing` | Parse SARIF output from scanners |
| `insecure-defaults` | Find insecure defaults / hardcoded creds / fail-open |
| `constant-time-analysis` | Crypto timing side-channel review |
| `zeroize-audit` | Find missing/incomplete secret zeroization |
| `fp-check` | Systematically verify findings (kill false positives) |
| `differential-review` | Security review of git diffs / PRs |
| `supply-chain-risk-auditor` | Dependency / supply-chain threat assessment |
| `sharp-edges` | Find error-prone APIs and footguns |
| `dimensional-analysis` | Detect unit/formula bugs |
| `variant-analysis` | Find similar bugs across codebases |

## Anthropic Cybersecurity Skills — operational how-tos (754)

Apache 2.0 — see `LICENSE-Apache-2.0`. Source: <https://github.com/mukul975/Anthropic-Cybersecurity-Skills>. The full upstream skill set is mirrored here as local Claude Code skills. Each skill maps to MITRE ATT&CK / D3FEND / NIST CSF.

Subdomain coverage:

| Subdomain | Skills |
| --- | ---: |
| `cloud-security` | 63 |
| `threat-hunting` | 56 |
| `threat-intelligence` | 50 |
| `network-security` | 43 |
| `web-application-security` | 42 |
| `malware-analysis` | 39 |
| `digital-forensics` | 37 |
| `identity-access-management` | 33 |
| `soc-operations` | 33 |
| `container-security` | 29 |
| `api-security` | 28 |
| `ot-ics-security` | 28 |
| `security-operations` | 28 |
| `incident-response` | 26 |
| `vulnerability-management` | 25 |
| `red-teaming` | 24 |
| `penetration-testing` | 20 |
| `endpoint-security` | 17 |
| `devsecops` | 17 |
| `zero-trust-architecture` | 17 |
| `cryptography` | 15 |
| `phishing-defense` | 15 |
| `ransomware-defense` | 13 |
| `mobile-security` | 13 |
| `threat-detection` | 7 |
| `application-security` | 4 |
| `compliance-governance` | 4 |
| `deception-technology` | 3 |
| `supply-chain-security` | 3 |
| `ai-security` | 2 |
| `identity-and-access-management` | 2 |
| `offensive-security` | 2 |
| `privacy-compliance` | 2 |
| `red-team` | 2 |
| `wireless-security` | 2 |
| `blockchain-security` | 1 |
| `data-protection` | 1 |
| `firmware-analysis` | 1 |
| `firmware-security` | 1 |
| `governance-risk-compliance` | 1 |
| `identity-security` | 1 |
| `ot-security` | 1 |
| `purple-team` | 1 |
| `social-engineering-defense` | 1 |
| `zero-trust` | 1 |

## Transilience — high-level workflows (4)

MIT — see `LICENSE-Transilience-MIT`. Source: <https://github.com/transilienceai/communitytools>.

- `cve-poc-generator` — Research CVEs, query NVD, generate Python PoCs
- `dfir` — Windows event logs, PCAP, AD attack pattern analysis
- `ai-threat-testing` — OWASP LLM Top 10 risks
- `blockchain-security` — Smart contract logic, EVM storage, DeFi vectors

## Adding more skills

Curated ranking lives in `CURATION.md` and `curation.json`. Regenerate after inventory changes:

```bash
python3 scripts/curate_claude_skills.py --write
```

```bash
# Format
.claude/skills/<skill-name>/
├── SKILL.md              # required, with name + description frontmatter
├── references/           # optional, .md files referenced from SKILL.md
├── scripts/              # optional, helper scripts
└── workflows/            # optional, longer process docs
```

Frontmatter format:

```yaml
---
name: skill-name
description: When to use this skill. Include trigger phrases.
---
```

The description is what Claude matches against — be specific about when to activate.

## License attribution

This project is MIT-licensed. The vendored skills retain their original licenses
(centralized index: [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md)):

- Trail of Bits skills: CC-BY-SA 4.0 (`LICENSE-CC-BY-SA-4.0`)
- Anthropic Cybersecurity Skills: Apache 2.0 (`LICENSE-Apache-2.0`)
- Transilience skills: MIT (`LICENSE-Transilience-MIT`)
- Karpathy guidelines skill: MIT, source <https://github.com/multica-ai/andrej-karpathy-skills>
- SnailSploit Claude-Red skills: MIT (`LICENSE-Claude-Red-MIT`)
- BugHunter (claude-bug-bounty) skills: MIT (`LICENSE-BugHunter-MIT`)

When modifying vendored skills, retain the source attribution in their SKILL.md frontmatter.
