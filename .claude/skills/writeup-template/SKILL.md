---
name: writeup-template
description: Use after solving any CTF, bug bounty, lab, or practice box. Generates a writeup at workflows/<competition>/<challenge>.md following the project's mandatory structure. Triggers on "write writeup", "document this challenge", "write up the solve", or right after a flag is captured.
---

# Generate a challenge writeup

This is **MANDATORY** after every solve per `CLAUDE.md`. Writeups MUST pass markdownlint.

## File location

```text
workflows/<competition>/<challenge>.md
```

Examples:

- `workflows/htb/pilgrimage.md`
- `workflows/ehax2026/chusembly.md`
- `workflows/picoCTF/2024/web-cookies.md`

If the directory doesn't exist, create it.

## Required structure

```markdown
# <Challenge Name>

**Platform:** HTB / TryHackMe / CTF Name / Bug Bounty Program
**Category:** Web / Pwn / Crypto / Forensics / Reversing / Stego / Misc / Mobile / Blockchain
**Difficulty:** Easy / Medium / Hard / Insane
**Date:** YYYY-MM-DD

## Recon

[What we discovered during initial enumeration. Include exact commands and trimmed output.]

## Exploitation

[Step-by-step attack path. Exact commands, exact payloads, exact flags.]

## Dead Ends

[Approaches that didn't work and why. So we don't repeat the mistake.]

## Flag / Finding

[The flag string OR — for bug bounty — the vulnerability and minimal PoC. Do NOT paste credentials.]

## Tools Used

[Bullet list of tools that were key to the solve.]

## Lessons Learned

[1-3 bullets on what to remember next time.]
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
npx markdownlint-cli2 "workflows/**/*.md"
```

## Sensitive data

- Flag credentials/keys clearly but do NOT spread across multiple sections
- Bug bounty: report existence + access method, NOT the actual credentials
- Strip session tokens, real IPs of unrelated systems, PII
- Trim output blocks aggressively — full nmap output is noise, the open ports are the signal
