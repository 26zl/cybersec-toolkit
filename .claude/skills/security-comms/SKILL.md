---
name: security-comms
description: Use to translate a security finding, incident, or program update for a specific audience — board, executives, engineering, customer success, end customers, legal, or procurement. Produces audience-tuned writeups: incident notification, breach disclosure, post-mortem, status update, remediation ask, and customer-facing advisory. Use when the same technical fact needs different framing per stakeholder, when drafting external disclosure, or when an exec/board/customer needs the "so what" without the packet captures. Coordinator skill — findings and incidents route here for the human-readable layer.
---

# Security communications — one fact, many audiences

This is a coordinator skill. The technical work is done elsewhere; this one decides what each audience needs to hear, in their language, at the right altitude. The same finding becomes seven different paragraphs without changing a single fact.

## Audiences and what they actually need

| Audience | They care about | Lead with | Cut |
| --- | --- | --- | --- |
| **Board** | Business risk, liability, are we exposed vs peers | One-line risk statement + decision needed | Every technical detail |
| **Executives** | Impact, cost, timeline, who owns it | Impact + decision + ask | CVE numbers, tool names |
| **Engineering** | What to change and where, how to verify | Exact location, repro, fix, verification | Business framing |
| **Customer success** | What to tell customers, is anyone affected | Affected-or-not + the approved customer line | Internal blame, raw severity debates |
| **End customers** | Am I affected, what do I do, are you handling it | Plain impact + the one action they take | Internal process, root-cause speculation |
| **Legal** | Disclosure obligations, regulated data, timelines, evidence | What data, what jurisdictions, what timeline | Remediation engineering detail |
| **Procurement/vendor** | Is the vendor at fault, contractual exposure | The contract/SLA-relevant fact | Internal architecture |

Rule: every audience gets the truth, but each gets the slice they can act on. Never send engineering's writeup to the board, and never send the board's to engineering.

## Templates

Pick the one that fits and fill it. Keep facts identical across versions — only framing and depth change.

1. **Incident notification (internal)** — what happened, current status, impact so far, what we're doing, next update time.
2. **Breach disclosure (external/regulatory)** — only after `[[grc-compliance-privacy-program]]` and legal confirm the obligation and timeline. What data, who is affected, what they should do, how to contact you. Do not speculate on root cause in writing before it's confirmed.
3. **Post-mortem** — timeline, root cause, contributing factors, what worked, action items with owners and dates. Blameless. Route to `[[conducting-post-incident-lessons-learned]]` for the full process.
4. **Status update** — for a long-running incident or remediation: what changed since last update, current risk, ETA, next checkpoint.
5. **Remediation ask** — to get engineering or a vendor to fix something: the finding (one line), why it matters to *them*, the specific change, the deadline and what happens if it slips.
6. **Customer-facing advisory** — affected/not affected, the single action to take, your contact path. Approved by legal before it leaves.

## Workflow

1. **Get the verified fact.** Pull the disposition from `[[finding-triage]]` or the incident state — do not write comms off an unverified finding.
2. **Pick the audience(s).** Often you need two or three versions of the same event.
3. **Set the altitude.** Board/exec/customer = impact and action, no jargon. Engineering = precise and reproducible. Legal = data, jurisdiction, timeline.
4. **Lead with the answer.** The reader's question ("am I affected?", "what do I decide?") gets answered in the first sentence, not the conclusion.
5. **State the ask or the next update.** Every message ends with either an action the reader takes or a time they'll hear from you again.
6. **Defang and scrub.** Strip live credentials, internal hostnames, and customer PII from anything leaving the team. For IOCs in external sharing, route to `[[building-ioc-defanging-and-sharing-pipeline]]`.

## Guardrails

- Do not send external disclosure without legal/GRC sign-off on the obligation and timeline — getting the timing wrong has regulatory consequences.
- Do not speculate on root cause or attribution in writing before it's confirmed; "under investigation" is a complete answer.
- Do not leak credentials, PII, or internal infrastructure detail into broad-audience comms.
- Keep the facts identical across audience versions. Different framing is fine; different facts is how trust dies.
