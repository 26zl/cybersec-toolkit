---
name: finding-triage
description: Use to triage a single security finding — from a scanner (SAST/DAST/SCA), an audit, a pentest report, a bug bounty submission, a CVE advisory, or a threat hunt — into a defensible disposition with the required evidence. Produces a ticket-ready writeup: Fixed, Deferred, Accepted Risk, or False Positive. Use when normalizing findings across different sources, deciding whether something is real and reachable, assigning contextual severity, or building an audit trail that survives review six months later. Coordinator skill — route findings from audit, offensive, and detection work here for disposition.
---

# Finding triage — single finding to defensible disposition

This is a coordinator skill. Other skills surface raw findings; this one normalizes one finding at a time into a disposition with the evidence a reviewer, auditor, or regulator will accept later. Run it once per finding, not per scan.

Inputs come from anywhere: SAST/DAST/SCA scanner output, dependency advisories, `[[offensive-reporting]]` deliverables, bug bounty reports, `[[performing-web-application-vulnerability-triage]]`, threat hunts, vendor disclosures. Wherever the finding came from, the output shape is the same.

## The four dispositions

Every finding ends in exactly one of these, with its required fields filled in. A disposition without its fields is not done.

| Disposition | Required fields |
| --- | --- |
| **Fixed** | Fix description, deploy plan (where/when), verification method (how you proved it's closed) |
| **Deferred** | Deferral reason, new deadline, owner, escalation condition if the deadline slips |
| **Accepted Risk** | (1) Why the fix doesn't apply or isn't worth it, (2) compensating controls in place, (3) re-evaluation trigger (date or event) |
| **False Positive** | Evidence supporting the determination, scanner rule ID for suppression so it doesn't recur |

"Accepted Risk" and "False Positive" are the two that get challenged in audits — over-document them, not under.

## Workflow

1. **Restate the finding in your own words.** CWE/CVE if any, exact location (`file:line`, endpoint, ARN, package@version), the preconditions for exploitation, and the concrete impact if exploited. If you can't state the impact, you can't triage it — go back to the source skill.
2. **Verify reachability.** Is the vulnerable code path actually reachable from attacker-controlled input in this deployment? A SQLi in dead code, a CVE in a dependency whose vulnerable function is never called, an IDOR behind an auth wall the tester didn't pass — these change the disposition. Verify with the tool, don't assume. For CVE depth use `[[cve-poc-generator]]` or `[[performing-cve-prioritization-with-kev-catalog]]`; check KEV and EPSS before trusting raw CVSS.
3. **Apply contextual severity.** The scanner's rating is a starting point, not the answer. Adjust for: internet-facing vs internal, regulated/sensitive data in scope, existing compensating controls, exploit maturity (KEV-listed? public PoC?). Document the adjustment and why. Use `[[prioritizing-vulnerabilities-with-cvss-scoring]]` or `[[triaging-vulnerabilities-with-ssvc-framework]]` for a defensible method.
4. **Assign the disposition** and fill its required fields from the table above.
5. **Document defensibly.** Write it so someone with no context can read the ticket in six months and agree with the call. Evidence, not adjectives.
6. **Escalate High/Critical.** Anything you rate High or Critical gets a named secondary reviewer before it closes. Note who and when.

## Output format

```text
FINDING: <one-line title>  [<source skill / scanner>]
CWE/CVE: <id or n/a>   LOCATION: <file:line | endpoint | ARN | pkg@ver>
REACHABLE: <yes/no — evidence>
SEVERITY: <scanner rating> → <adjusted rating>  (reason: <...>)
DISPOSITION: <Fixed | Deferred | Accepted Risk | False Positive>
  <required fields for that disposition>
ESCALATION: <reviewer + date, or n/a for Low/Medium>
```

## Hand-off

- Translating this for a non-technical audience (exec, customer, legal, board)? Route to `[[security-comms]]`.
- Rolling many triaged findings into program-level evidence, SLA tracking, or compliance mapping? Route to `[[grc-compliance-privacy-program]]`.
- Writing it into an engagement deliverable? Route to `[[offensive-reporting]]`.

## Guardrails

- Do not fabricate reachability or impact. If you haven't verified the path, say "unverified" and mark it for follow-up — an honest gap beats a confident guess.
- Do not downgrade a finding to make a number look better. Contextual severity adjusts up as readily as down.
- A False Positive needs evidence, not just disagreement with the scanner.
