---
name: bounty-api
description: Use when bug-bountying an API target — REST, GraphQL, gRPC, WebSocket. Covers OWASP API Top 10 (BOLA, BFLA, mass assignment, rate limiting bypass, JWT issues, GraphQL abuse). Triggers on "bounty api", "graphql security", "rest api testing", "api top 10".
---

# Bug bounty API testing

> **Pre-flight.** Run `authorization-gate` and read the program policy first: confirm that automated scanning, brute force and rate-limit testing are allowed, and stay inside scope. Start with `suggest_for_bounty` or `guided_assessment`. Commands below are CLI notation: run them with `run_tool`/`run_pipeline` using registry names (`list_tools`), and `run_script` only for real logic. If policy blocks a command (for example `CYBERSEC_MCP_ALLOW_EXTERNAL=0`), ask the operator to fix the configuration and restart; do not fall back to the client shell. A tool that is not in the registry is a recommendation to the user (approval-gated install), not a bare command.

## 1. Discover the API

```text
# Mobile app reverse → APK / IPA → look for endpoints
# JS bundle inspection
run_pipeline([{"tool": "katana", "args": "-u https://target.com -jc -silent"}, {"tool": "grep", "args": "-E -e /api/ -e /v1/ -e /graphql"}])
run_tool("LinkFinder", "-i https://target.com/app.js -o cli")

# Common paths
run_tool("ffuf", "-w /opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt -u https://target.com/FUZZ -mc 200,401,403")
# /api, /api/v1, /v1, /graphql, /rest, /rpc, /swagger.json, /openapi.json,
# /api-docs, /redoc, /docs, /.well-known/

# Schema endpoints (huge if found)
run_tool("curl", "https://target.com/swagger.json")
run_tool("curl", "https://target.com/openapi.json")
run_tool("curl", "-X POST https://target.com/graphql -d '{\"query\":\"{__schema{types{name}}}\"}'")
```

If you find a swagger/openapi/graphql introspection — that IS the attack surface map. Use `kiterunner` to brute API routes if not.

## 2. OWASP API Top 10 — checklist per endpoint

### API1: Broken Object Level Authorization (BOLA)

For every endpoint with an ID:

```text
# Login as user A. Get user B's resource (substitute the real token and ID; run_tool does not expand $VARS).
run_tool("curl", "-H 'Authorization: Bearer <A_TOKEN>' https://api/users/<B_ID>")
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

```text
# Introspection (if not disabled); graphw00f has a registered CLI route, while graphql-cop requires approval to add.
run_tool("curl", "-X POST https://target/graphql -d '{\"query\":\"{__schema{types{name}}}\"}'")
run_tool("clairvoyance", "https://target/graphql -w wordlist.txt")    # if introspection is off

# Common issues
# 1. Introspection enabled in prod
# 2. No query depth limit → DoS (report from introspection only; do not send depth bombs)
# 3. Batched queries bypassing rate limit (only if the program allows rate-limit testing)
# 4. Fields exposed without auth
# 5. Mutations callable from queries (some impls)
# 6. Field-level authz missing — anonymous user fetches private fields
```

Useful tools: `inql` (Burp ext), `gqlmap`, `BatchQL`.

## 4. JWT

```text
# Substitute the actual token; run_tool does not expand environment variables.
run_tool("jwt_tool", "<TOKEN>")                       # decode + checks
run_tool("jwt_tool", "<TOKEN> -X a")                  # alg=none
run_tool("jwt_tool", "<TOKEN> -X i")                  # weak HMAC, only if credential testing is allowed
run_tool("jwt_tool", "<TOKEN> -X k -pk pubkey.pem")   # key confusion (RS256→HS256)
run_tool("jwt_tool", "<TOKEN> -X kid")                # kid injection
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
