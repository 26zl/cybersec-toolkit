---
name: evidence-hygiene
description: Sanitize security evidence before sharing, reporting, or writing up findings. Use for bug bounty reports, guided MCP assessments, pentest/DFIR notes, screenshots, HAR files, curl commands, request/response logs, PoC output, terminal transcripts, writeups, and any evidence that may contain cookies, bearer tokens, API keys, session IDs, PII, customer data, credentials, internal hostnames, or excessive exploit output.
---

# Evidence hygiene

Use this before `report-writing`, `writeup-template`, external submission, or sharing
PoC artifacts. Keep evidence useful enough for reproduction while removing secrets,
PII, and unrelated data.

## Workflow

1. Inventory artifacts: screenshots, HAR, curl commands, HTTP requests/responses,
   terminal output, logs, payloads, files, cloud/API responses, and writeup snippets.
2. Identify sensitive values:
   - Cookies: `Cookie`, `Set-Cookie`, session IDs, CSRF tokens.
   - Auth: `Authorization`, bearer tokens, JWTs, API keys, OAuth codes, refresh tokens.
   - PII/customer data: names, emails, phone numbers, addresses, IDs, invoices.
   - Secrets: passwords, private keys, seed phrases, database URLs, webhooks.
   - Internal data: private hostnames, non-public IPs, employee names, tenant IDs.
3. Replace values with stable placeholders that preserve meaning:
   - `[REDACTED_COOKIE]`, `[REDACTED_TOKEN]`, `[REDACTED_EMAIL]`,
     `[REDACTED_CUSTOMER_ID]`, `[REDACTED_INTERNAL_HOST]`.
   - Keep the first and last 2-4 characters only when comparison matters:
     `tok_abcd...[REDACTED]...7890`.
4. Minimize proof:
   - Show the smallest request/response pair that proves impact.
   - Trim long output; include only relevant lines.
   - Do not paste credentials or full data dumps. Prove existence and access path.
5. Preserve reproducibility:
   - Keep HTTP method, endpoint, relevant parameters, status code, role/account type,
     timestamps, and exact command flags.
   - Mark every redaction clearly; do not silently alter semantics.
6. Separate raw from shareable:
   - Do not commit raw evidence with secrets.
   - Keep raw evidence local/private only when needed for responsible disclosure.
   - Use sanitized evidence in `writeups/` and external reports.

## Artifact-specific checks

- **Screenshots:** crop unrelated tabs, bookmarks, email, user avatars, tenant names,
  notification popups, and account identifiers. Blur or redact before sharing.
- **HAR/curl:** remove `Cookie`, `Authorization`, `X-API-Key`, CSRF, JWT, and tracking
  headers unless a redacted placeholder is needed to explain auth context.
- **Logs/terminal:** remove shell history noise, tokens in environment variables,
  usernames/hostnames that are not necessary, and unrelated command output.
- **API/cloud output:** reduce arrays to one or two representative records and redact
  account IDs, tenant IDs, ARNs/project IDs, object keys, and customer fields.
- **Exploit output:** include enough to prove control or access; avoid destructive
  output, mass enumeration, or copied secrets.

## Report-ready checklist

- Authorization and exact scope are stated.
- Evidence shows affected asset, actor/role, request, response, and impact.
- All secrets/PII are redacted with explicit placeholders.
- Redactions do not hide the root cause or make reproduction impossible.
- The report says what was accessed, not the sensitive value itself.
- Cleanup and data-handling notes are included when relevant.
