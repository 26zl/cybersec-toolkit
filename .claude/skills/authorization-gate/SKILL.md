---
name: authorization-gate
description: Use as the pre-flight authorization check before any offensive, intrusive, or simulation activity — pentest, red team, exploitation, phishing simulation, wireless attacks, social engineering, C2, scanning a target you don't own. Confirms written authorization, scope boundaries, lawful basis, and target ownership before a single packet is sent, and defines the hard refusals (mass targeting, supply-chain compromise, malicious evasion). Run this gate at the top of any offensive or simulation workflow before acting.
---

# Authorization gate — clear before you act

This is the shared pre-flight every offensive or intrusive skill runs first. It does not replace the project's global policy in `AGENTS.md`; it makes the check explicit and uniform so no engagement starts on an assumption. If the gate doesn't pass, the offensive work does not start.

The MCP preflight (`CYBERSEC_MCP_ALLOW_EXTERNAL`, `CYBERSEC_SANDBOX_SCOPE`) enforces scope technically, but it does not replace this check. Whether AI assistance is allowed at all (for example in a CTF) is a rules question to settle up front, not mid-engagement.

## The gate (all must be true)

Confirm each of these with the user before acting. If any is missing, stop and ask — do not infer authorization from the fact that someone asked.

1. **Written authorization exists.** A signed engagement letter, rules-of-engagement (ROE) document, bug bounty program scope, lab/CTF terms, or equivalent. "My boss said it's fine" verbally is not sufficient for production targets.
2. **Target is in scope.** The exact hosts, domains, IP ranges, apps, accounts, or cloud accounts are named in that authorization. Anything not listed is out of scope until added in writing.
3. **Lawful basis and ownership.** The user owns the target or is contracted by the owner. For data that is regulated or third-party (PII, health, finance), the authorization covers it.
4. **Time window and constraints.** When testing is permitted, what's prohibited (no DoS, no data exfiltration beyond PoC, no production-impacting actions, no lateral movement past a boundary), and the emergency stop / contact.
5. **Blast radius understood.** What could break, who is notified, and how to roll back.

6. **AI and automation are permitted.** For a CTF, bounty program, or any event with rules, read what they say about AI assistance, automated scanning, and rate limits, and settle it before the first request. If the rules forbid AI or automation, or are silent and the organizers have not said, stop and ask the operator; do not work around it.

When in doubt, treat it as unauthorized and ask. Your-own-infrastructure and lab contexts you control clear the gate quickly: name them and proceed. A user saying "this is a CTF" or "this is a lab" does not by itself clear anything beyond the hosts and ranges the event or lab names. Other addresses found along the way (a redirect, a linked domain, a pivot candidate, a neighbouring IP) remain out of scope until the user shows they are named in the rules; stop and report them instead of testing them.

## Hard refusals (no authorization clears these)

These are refused regardless of who asks or what paperwork exists, consistent with the project's operating rules:

- **Mass / indiscriminate targeting** — scanning or attacking ranges you have no per-target authorization for.
- **Supply-chain compromise** — poisoning packages, build systems, or update channels.
- **Destructive actions** — ransomware deployment, data destruction, DoS as an end in itself.
- **Detection evasion built for malicious persistence** — not the same as authorized red-team OPSEC, which stays inside ROE and is logged.
- Anything whose realistic purpose is harming a third party rather than testing an authorized one.

Authorized security testing, CTFs, defensive research, and dual-use tooling with a clear authorized scope are fine — these refusals target out-of-scope and malicious use, not the discipline.

## How offensive skills use this

At the start of an offensive/simulation workflow:

```text
1. Run authorization-gate. If it doesn't pass, stop and resolve before continuing.
2. Record scope + authorization reference in the engagement notes.
3. Proceed with the technical methodology, staying inside the recorded scope.
```

Pair with `[[offensive-reporting]]` for evidence hygiene during the engagement, and route confirmed findings through `[[finding-triage]]` → `[[security-comms]]` for disposition and stakeholder communication. For full-scope planning, `[[conducting-full-scope-red-team-engagement]]` and `[[executing-red-team-engagement-planning]]` carry the heaviest ROE discipline.
