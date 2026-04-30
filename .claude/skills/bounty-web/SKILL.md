---
name: bounty-web
description: Use during the testing phase of a web application bug bounty. Provides OWASP-aligned attack catalog, payload sources, and tool ordering for SQLi, XSS, SSRF, SSTI, IDOR, auth, race conditions, file upload, deserialization. Triggers on "bounty web", "test this app", "web app testing", "h1 web target".
---

# Bug bounty web testing methodology

Build on top of `bounty-recon` results. Tool-first: use SecLists wordlists (already cloned in this installer) before writing custom payloads.

## 1. Authentication & session

| Test | How |
| --- | --- |
| Default creds | `hydra`, manual common pairs (admin:admin, root:root) |
| User enum (different errors) | manual login form probing |
| Account takeover via password reset | inspect token entropy, host header injection on reset email |
| Session fixation | check if session ID is set before login |
| Session predictability | gather 50+ tokens, run statistical analysis |
| MFA bypass | response manipulation (401→200), brute the OTP, race the verify endpoint |
| Login CSRF | missing CSRF token on /login |
| Logout / impersonation flaws | swap session cookies, replay |

## 2. Authorization (highest-paying class)

- **IDOR:** swap numeric IDs, UUIDs, encoded IDs. Try both directions: A→B and B→A.
- **BFLA:** swap roles. Test admin endpoints as a regular user.
- **BOLA (API):** access another user's resource by ID.
- **Path traversal in route params:** `/users/../admin/users`.
- **JWT scope claims:** modify `role: user` → `role: admin`, re-sign or use alg=none.
- **Race conditions on permission grants:** use `turbo-intruder` or parallel curl.

Methodology: enumerate all endpoints with low-privilege user, then re-request each with no auth, expired token, and other-user token. Diff responses.

## 3. Input handling

### XSS

```bash
# DOM/reflected discovery
dalfox url https://target.com/?q=test
xsstrike -u "https://target.com/?q=FUZZ"

# Stored — manual; create accounts and probe every input field
```

CSP analysis: parse `Content-Security-Policy` header — look for `unsafe-inline`, `unsafe-eval`, wildcards, exploitable allowlisted CDNs (`*.googleapis.com` allows JSONP).

### SQLi

```bash
sqlmap -u "https://target.com/page?id=1" --batch --level=5 --risk=2 --random-agent

# When WAF blocks
sqlmap ... --tamper=between,space2comment,charencode
```

### SSRF

- Always test cloud metadata: AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure `169.254.169.254/metadata/instance`
- Bypass filters with: `localhost` → `127.0.0.1` → `0.0.0.0` → `127.1` → `2130706433` (decimal IP) → DNS rebinding
- Gopher for raw protocols: `gopherus --exploit mysql/redis/...`
- Burp Collaborator for blind SSRF

### SSTI

`{{7*7}}` → if `49`, identify engine, then RCE payload.

### XXE

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

Try blind XXE with out-of-band exfil (Burp Collaborator, your own server).

## 4. Business logic

These pay the highest because scanners can't find them. Always think:

- What if I do step N before step M?
- What if I send 100 of these requests in parallel?
- What if I supply a negative number / zero / extreme value?
- What if I cancel-and-retry mid-transaction?
- What if I substitute someone else's coupon / referral / credit?

Examples that have paid 5-figure bounties: race conditions on coupon redemption, integer over/underflow in price/quantity, refund-without-return, IDOR on transaction history.

## 5. File upload

Always try (in order):

1. Plain `.php`/`.asp`/`.jsp` upload
2. Double extension: `file.php.jpg`, `file.jpg.php`
3. Less-common PHP: `.phtml`, `.php5`, `.phar`, `.phps`
4. Null byte: `file.php%00.jpg`
5. MIME spoof: `Content-Type: image/jpeg` on PHP body
6. Magic byte prefix: `GIF89a<?php ?>`
7. SVG with embedded JS (XSS / SSRF on render)
8. ZIP slip / tar slip (path traversal in archive)
9. ImageMagick CVE chain — try identify on uploaded image
10. `.htaccess` upload to remap extensions

## 6. Deserialization

Detect: serialized blobs in cookies/parameters (`O:8:"User":...` PHP, `rO0AB...` Java, `gASV` Python pickle, `ac` ruby).

| Language | Tool |
| --- | --- |
| Java | `ysoserial`, `marshalsec` |
| .NET | `ysoserial.net` |
| PHP | `phpggc` |
| Python | manual pickle (`__reduce__`) |
| Ruby | manual + `marshal` |
| Node | `node-serialize` IIFE payload |

## 7. Tool stack from this installer

Recon: `subfinder`, `httpx`, `katana`, `gau`, `waybackurls`
Discovery: `ffuf`, `gobuster`, `feroxbuster`, `dirsearch`
Scanners: `nuclei`, `nikto`, `arjun` (param mining)
Specific: `sqlmap`, `dalfox`, `xsstrike`, `commix`, `tplmap`, `jwt_tool`
Wordlists: `SecLists` (cloned), `PayloadsAllTheThings` (cloned)

## 8. Reporting (do NOT skip)

Per finding:

- Asset / endpoint
- Severity (CVSS 3.1)
- Reproduction: numbered steps with curl commands or Burp request
- Impact (concrete — "exfil any user's PII", not "potential data exposure")
- Suggested remediation
- Screenshots/PoC video for visual confirmation

Strip credentials from the report. Show *that* access works, not the credentials themselves.

## After triage

Use the `writeup-template` skill for your own records.
