---
name: writeup-template
description: Use after completing any substantive security workflow with this project, including CTF, bug bounty, CVE validation, guided MCP assessment, DFIR, pentest/recon, or troubleshooting. Generates a writeup at writeups/<category>/<descriptive-case-name>.md following the project's mandatory structure. Triggers on "write writeup", "document this challenge", "write up the solve", "document this finding", or right after a flag/finding/result is confirmed.
---

# Generate a security workflow writeup

This is **MANDATORY** after every substantive security workflow per `CLAUDE.md`.
Writeups MUST pass markdownlint.

## File location

```text
writeups/<category>/<descriptive-case-name>.md
```

Examples:

- `writeups/ctf/htb-pilgrimage.md`
- `writeups/bug-bounty/example-idor.md`
- `writeups/cve/CVE-2024-xxxx-reproduction.md`
- `writeups/dfir/suspicious-powershell-investigation.md`
- `writeups/guided-assessment/example-web-recon.md`

If the directory doesn't exist, create it.

## Required structure

```markdown
# <Challenge Name>

**Platform/Program:** HTB / TryHackMe / CTF Name / Bug Bounty Program / Lab / Internal Scope
**Category:** Web / Pwn / Crypto / Forensics / CVE / DFIR / Cloud / Mobile / Network / Guided Assessment
**Difficulty/Severity:** Easy / Medium / Hard / Insane / Low / Medium / High / Critical
**Date:** YYYY-MM-DD

## Context / Scope

[What was being investigated and what was authorized.]

## Recon / Analysis

[What we discovered during initial enumeration or analysis. Include exact commands and trimmed output.]

## Exploitation / Validation

[Step-by-step attack path, validation path, exact commands, exact payloads, and exact flags.]

## Dead Ends

[Approaches that didn't work and why. So we don't repeat the mistake.]

## Finding / Result

[The flag, vulnerability, conclusion, or operational result. Do NOT paste credentials.]

## Tools Used

[Bullet list of tools that were key to the solve.]

## Lessons Learned

[1-3 bullets on what to remember next time.]

## Cleanup / Safety Notes

[Cleanup performed, sensitive data handling, or safety notes where relevant.]
```

## Writing style (HARD RULES)

- **No AI-isms.** Banned phrases: "Let's", "I'll", "Great question", "Here's what we found", "It's worth noting", "In conclusion".
- Use `we` or passive voice. Examples: "Ran nmap", "The binary was stripped", "Found SQLi in the login endpoint".
- Be detailed: exact commands, trimmed real output, exact payloads.
- Document failures too — they prevent repeat dead ends.
- If multi-session: add a rough timeline.

## Markdownlint compliance

Default project config at `.markdownlint.jsonc`. Common issues to avoid:

- Surround headings with blank lines
- Surround fenced code blocks with blank lines
- No trailing whitespace
- Specify language on every fenced block
- ATX-style headings (`#`, not `===`)
- One blank line between sections (no double-blank)

Run before considering done:

```bash
npx markdownlint-cli2 "writeups/**/*.md"
```

## Sensitive data

- Flag credentials/keys clearly but do NOT spread across multiple sections
- Bug bounty: report existence + access method, NOT the actual credentials
- Strip session tokens, real IPs of unrelated systems, PII
- Trim output blocks aggressively — full nmap output is noise, the open ports are the signal
