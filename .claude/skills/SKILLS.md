# Claude Code Skills

This directory contains 71 skills that activate on demand based on what you're working on. Skills extend Claude Code without permanently consuming context.

## Project-specific developer skills (6)

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

## Anthropic Cybersecurity Skills — operational how-tos (30)

Apache 2.0 — see `LICENSE-Apache-2.0`. Source: <https://github.com/mukul975/Anthropic-Cybersecurity-Skills> (754 skills total, this is a curated subset). Each skill maps to MITRE ATT&CK / D3FEND / NIST CSF.

### Malware & forensics (12)

- `analyzing-memory-dumps-with-volatility`
- `analyzing-network-traffic-with-wireshark`
- `analyzing-network-packets-with-scapy`
- `analyzing-malicious-pdf-with-peepdf`
- `analyzing-macro-malware-in-office-documents`
- `analyzing-android-malware-with-apktool`
- `analyzing-ios-app-security-with-objection`
- `analyzing-cobalt-strike-beacon-configuration`
- `analyzing-disk-image-with-autopsy`
- `analyzing-mft-for-deleted-file-recovery`
- `analyzing-email-headers-for-phishing-investigation`
- `analyzing-ethereum-smart-contract-vulnerabilities`

### Extraction (2)

- `extracting-credentials-from-memory-dump`
- `extracting-iocs-from-malware-samples`

### Exploitation (11)

- `exploiting-active-directory-with-bloodhound`
- `exploiting-kerberoasting-with-impacket`
- `exploiting-zerologon-vulnerability-cve-2020-1472`
- `exploiting-ms17-010-eternalblue-vulnerability`
- `exploiting-jwt-algorithm-confusion-attack`
- `exploiting-http-request-smuggling`
- `exploiting-server-side-request-forgery`
- `exploiting-insecure-deserialization`
- `exploiting-nosql-injection-vulnerabilities`
- `exploiting-prototype-pollution-in-javascript`
- `exploiting-race-condition-vulnerabilities`

### Threat hunting & detection (5)

- `hunting-for-cobalt-strike-beacons`
- `hunting-for-anomalous-powershell-execution`
- `hunting-for-data-exfiltration-indicators`
- `building-detection-rules-with-sigma`
- `building-c2-infrastructure-with-sliver-framework`

## Orizon — automated pentest lifecycle (6)

MIT — see `LICENSE-Orizon-MIT`. Source: <https://github.com/Orizon-eu/claude-code-pentest>. Each skill bundles executable Python scripts (43 total).

- `recon-dominator` — Full-scope recon: subdomain enum, port scan, tech fingerprint, OSINT, dorking, Wayback (8 scripts)
- `attack-path-architect` — MITRE ATT&CK-aligned asset classification + attack tree generation (3 scripts)
- `webapp-exploit-hunter` — SQLi/XSS/SSRF/SSTI/IDOR/upload/race testing with PoC generation (11 scripts)
- `api-breaker` — API discovery, schema reconstruction, BOLA/BFLA/JWT/GraphQL testing (8 scripts)
- `cloud-pivot-finder` — S3/GCS/Azure bucket detection, subdomain takeover, serverless/CI-CD exposure (7 scripts)
- `vuln-chain-composer` — Cross-domain finding correlation, exploit chain building, CVSS, bug bounty reports (6 scripts)

## Transilience — high-level workflows (4)

MIT — see `LICENSE-Transilience-MIT`. Source: <https://github.com/transilienceai/communitytools>.

- `cve-poc-generator` — Research CVEs, query NVD, generate Python PoCs
- `dfir` — Windows event logs, PCAP, AD attack pattern analysis
- `ai-threat-testing` — OWASP LLM Top 10 risks
- `blockchain-security` — Smart contract logic, EVM storage, DeFi vectors

## Adding more skills

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

This project is MIT-licensed. The vendored skills retain their original licenses:

- Trail of Bits skills: CC-BY-SA 4.0 (`LICENSE-CC-BY-SA-4.0`)
- Anthropic Cybersecurity Skills: Apache 2.0 (`LICENSE-Apache-2.0`)
- Transilience skills: MIT (`LICENSE-Transilience-MIT`)

- Orizon pentest skills: MIT (`LICENSE-Orizon-MIT`)

When modifying vendored skills, retain the source attribution in their SKILL.md frontmatter.
