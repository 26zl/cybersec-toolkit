---
name: bounty-api
description: Use when bug-bountying an API target — REST, GraphQL, gRPC, WebSocket. Covers OWASP API Top 10 (BOLA, BFLA, mass assignment, rate limiting bypass, JWT issues, GraphQL abuse). Triggers on "bounty api", "graphql security", "rest api testing", "api top 10".
---

# Bug bounty API testing

## 1. Discover the API

```bash
# Mobile app reverse → APK / IPA → look for endpoints
# JS bundle inspection
katana -u https://target.com -jc -silent | grep -E "/api/|/v1/|/graphql"
LinkFinder -i https://target.com/app.js -o cli

# Common paths
ffuf -w api-paths.txt -u https://target.com/FUZZ -mc 200,401,403
# /api, /api/v1, /v1, /graphql, /rest, /rpc, /swagger.json, /openapi.json,
# /api-docs, /redoc, /docs, /.well-known/

# Schema endpoints (huge if found)
curl https://target.com/swagger.json
curl https://target.com/openapi.json
curl -X POST https://target.com/graphql -d '{"query":"{__schema{types{name}}}"}'
```

If you find a swagger/openapi/graphql introspection — that IS the attack surface map. Use `kiterunner` to brute API routes if not.

## 2. OWASP API Top 10 — checklist per endpoint

### API1: Broken Object Level Authorization (BOLA)

For every endpoint with an ID:

```bash
# Login as user A. Get user B's resource.
curl -H "Authorization: Bearer $A_TOKEN" https://api/users/$B_ID
```

Try: numeric→numeric swap, UUID enumeration via Wayback/JS, encoded ID decoding.

### API2: Broken Authentication

- Missing / weak JWT verification
- Token reuse after logout
- Refresh-token abuse
- Hardcoded API keys in mobile bundles

### API3: Broken Object Property Level (Mass Assignment + Excessive Data Exposure)

Mass assignment:

```bash
# Sign-up sends: {"email": "...", "password": "..."}
# Try: {"email": "...", "password": "...", "is_admin": true, "role": "admin"}
```

Excessive exposure: GET /users/me returns entire user object including hashed password / secret_question_answer / internal_notes — report it.

### API4: Unrestricted Resource Consumption

Endpoints that allow `?limit=99999`, deeply nested GraphQL queries, expensive operations without rate limit.

### API5: Broken Function Level Authorization (BFLA)

Admin endpoints (`POST /admin/users`, `DELETE /admin/posts/N`) accessed as regular user.

### API6: Unrestricted Access to Sensitive Business Flows

Anti-automation gaps: bulk-creating accounts, scraping product data, mass-redeeming gift cards.

### API7: Server-Side Request Forgery (SSRF)

Any endpoint that takes a URL parameter (avatar URL, webhook URL, OAuth callback, image proxy) → SSRF target. See `bounty-web` SSRF section.

### API8: Security Misconfiguration

- CORS: `Access-Control-Allow-Origin: *` with `Allow-Credentials: true` is a vuln
- Verbose error stack traces
- Default keys / debug endpoints
- HTTP methods like `TRACE`, `OPTIONS` revealing info

### API9: Improper Inventory Management

Old API versions with weaker auth (`/api/v1/`) alongside new (`/api/v2/`). Test the old version.

### API10: Unsafe Consumption of APIs

When the target API consumes a third-party API and trusts its response — SSRF chains, prototype pollution from upstream.

## 3. GraphQL specifics

```bash
# Introspection (if not disabled)
graphql-cop -t https://target/graphql
graphw00f https://target/graphql
clairvoyance https://target/graphql -w wordlist.txt    # if introspection is off

# Common issues
# 1. Introspection enabled in prod
# 2. No query depth limit → DoS
# 3. Batched queries bypassing rate limit
# 4. Fields exposed without auth
# 5. Mutations callable from queries (some impls)
# 6. Field-level authz missing — anonymous user fetches private fields
```

Useful tools: `inql` (Burp ext), `gqlmap`, `BatchQL`.

## 4. JWT

```bash
jwt_tool $TOKEN                      # decode + checks
jwt_tool $TOKEN -X a                 # alg=none
jwt_tool $TOKEN -X i                 # weak HMAC, brute
jwt_tool $TOKEN -X k -pk pubkey.pem  # key confusion (RS256→HS256)
jwt_tool $TOKEN -X kid               # kid injection
```

Also test: kid path traversal (`kid: "../../../../dev/null"` → empty key), JKU/X5U server-controlled injection.

## 5. Rate limit bypass

- Add header: `X-Forwarded-For: 1.2.3.4`, `X-Real-IP`, `X-Originating-IP`, `X-Client-IP`, `X-Remote-IP`
- Change `User-Agent` (some rate limiters key on UA+IP)
- Add trailing slash, change case, add path params (`/login` vs `/login/`)
- HTTP/2 — concurrent stream race
- Delay-based: many requesters bucket per second, sub-second burst slips through

## 6. Tool stack

`kiterunner`, `arjun`, `nuclei`, `mitmproxy`, `BurpSuite` (commercial), `inql`, `graphql-cop`, `clairvoyance`, `jwt_tool`, `Postman`/`Hoppscotch` for repro.

## 7. Reporting

Always include the exact request (method, path, headers, body). Mask tokens but show the structure. Demonstrate impact with two accounts (attacker + victim) where applicable.
