---
name: api-breaker
description: Automated API security testing starting from domains. Discovers REST, GraphQL, and SOAP APIs, reconstructs schemas, and tests for BOLA/IDOR, BFLA, mass assignment, JWT attacks, rate limiting bypass, and business logic flaws. Use when user asks to "test API security", "break API", "find API vulnerabilities", "test GraphQL", "test JWT", "API pentest", or provides domains with API endpoints. For authorized testing only.
metadata:
  author: orizon.one
  version: 1.0.0
---

# API Breaker

Intelligent API security testing. Discovers, maps, and exploits API vulnerabilities.

## Important

CRITICAL: Only test APIs you have explicit authorization to test.

## Instructions

### Step 1: API Discovery

```bash
python scripts/api_discovery.py --domain {target_domain}
```

Discovery methods:
1. **Path fuzzing**: /api/, /v1/, /v2/, /graphql, /rest/, /swagger.json, /openapi.json, /api-docs
2. **JavaScript analysis**: Parse JS files for hardcoded API endpoints, base URLs, fetch/axios calls
3. **Wayback Machine**: Historical API endpoints that may still be active
4. **Common patterns**: /{resource}s, /{resource}/{id}, /{resource}/{id}/{subresource}
5. **GraphQL detection**: /graphql, /graphiql, /playground, /api/graphql
6. **Documentation endpoints**: Swagger, OpenAPI, WADL, WSDL

For each discovered API:
- Record base URL, authentication method, content type
- Detect API standard (REST, GraphQL, gRPC-web, SOAP)

### Step 2: Schema Reconstruction

```bash
python scripts/schema_builder.py --api-base {api_url}
```

Even without documentation:
1. Send requests with varying parameters and observe responses
2. Analyze error messages for expected field names/types
3. Use OPTIONS/HEAD to discover allowed methods
4. Test content negotiation (JSON, XML, form-encoded)
5. GraphQL: Send introspection query to get full schema

Output: Reconstructed API schema in OpenAPI format.

### Step 3: Authentication Analysis

```bash
python scripts/auth_analyzer.py --api-base {api_url}
```

Detect and test:
- **JWT tokens**: Decode, test none algorithm, key confusion (RS256->HS256), weak secrets, claim tampering
- **API keys**: Test in different positions (header, query, body), check for key leakage
- **OAuth flows**: Test for open redirect in callback, token leakage, PKCE bypass
- **Session tokens**: Predictability, fixation, rotation on privilege change
- **No auth**: Endpoints accessible without any authentication

### Step 4: Authorization Testing (BOLA/BFLA)

```bash
python scripts/authz_tester.py --schema {schema_file} --token {user_token}
```

**BOLA (Broken Object-Level Authorization):**
For every endpoint with an object ID:
1. Create resource as User A, note the ID
2. Access that ID as User B (different token)
3. If User B can read/modify/delete User A's resource = BOLA

**BFLA (Broken Function-Level Authorization):**
1. Map endpoints by intended role (user vs admin)
2. Test admin endpoints with regular user token
3. Test all HTTP methods (GET, POST, PUT, DELETE, PATCH) on each endpoint

### Step 5: Mass Assignment Testing

```bash
python scripts/mass_assignment.py --schema {schema_file} --token {token}
```

For each creation/update endpoint:
1. Send normal request, note accepted fields
2. Add extra fields: `role`, `isAdmin`, `price`, `discount`, `verified`, `approved`, `permissions`
3. Check if extra fields are processed
4. Test with nested objects: `{"user": {"role": "admin"}}`

### Step 6: Rate Limiting and Resource Testing

```bash
python scripts/rate_limiter.py --api-base {api_url}
```

Test:
- Send 100+ rapid requests to each endpoint
- Check for 429 responses or rate limit headers
- If rate limited: test bypass via IP rotation headers (X-Forwarded-For, X-Real-IP)
- Test resource-intensive endpoints for DoS potential (large pagination, deep queries)
- GraphQL: Test query batching, nested query depth, alias-based multiplication

### Step 7: Business Logic Testing

```bash
python scripts/logic_tester.py --schema {schema_file} --token {token}
```

Context-aware tests:
- **E-commerce**: Price manipulation, quantity overflow, currency confusion, coupon stacking
- **Financial**: Double spending via race conditions, negative amount transfer
- **User management**: Self-privilege escalation, email verification bypass, 2FA bypass
- **File handling**: Path traversal in file names, SSRF in URL fields, XXE in XML endpoints

### Step 8: Report Generation

```bash
python scripts/api_report.py --findings {findings_dir}
```

Per-finding output:
- Vulnerability type and OWASP API Security Top 10 mapping
- Affected endpoint and method
- Request/response showing the issue
- curl command for reproduction
- Impact assessment
- Remediation recommendation

## Error Handling

### No API Documentation Found
If no Swagger/OpenAPI exists:
1. Schema reconstruction from observed behavior (Step 2)
2. Use error messages as hints for field discovery
3. Inform user of reduced coverage without docs

### Authentication Required
1. Ask user for API token/credentials
2. Support: Bearer token, API key, Basic auth, OAuth token
3. Usage: `--token "Bearer abc123"` or `--api-key "key123"`

### GraphQL Introspection Disabled
If introspection is blocked:
1. Use field suggestion: send partial queries, use error messages to discover fields
2. Use clairvoyance-style wordlist-based field discovery
3. Check for GraphQL Voyager/Playground on alternative paths

## Examples

### Example 1: Full API Assessment
User says: "Test the API at api.example.com"

Actions:
1. Discover all endpoints
2. Reconstruct schema
3. Test auth, BOLA, BFLA, mass assignment
4. Test rate limiting
5. Generate comprehensive report

### Example 2: GraphQL Security Audit
User says: "Audit the GraphQL API at example.com/graphql"

Actions:
1. Send introspection query
2. Map all queries and mutations
3. Test authorization on each mutation
4. Test query depth/complexity limits
5. Test batching attacks
6. Report findings

### Example 3: JWT Penetration Test
User says: "Test JWT security on the API"

Actions:
1. Capture JWT from auth flow
2. Decode and analyze claims
3. Test none algorithm
4. Test RS256->HS256 confusion
5. Brute-force weak secrets
6. Test claim manipulation (user ID, role, expiry)
