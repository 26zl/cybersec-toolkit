---
name: bounty-recon
description: Use at the start of a bug bounty engagement. Provides scope-aware recon methodology — passive enumeration, subdomain discovery, asset attribution, tech stack fingerprinting, content discovery. Respects scope and program rules. Triggers on "bounty recon", "subdomain enum", "attack surface map", "h1 recon", "bug bounty start".
---

# Bug bounty recon methodology

> **Pre-flight.** Run `authorization-gate` and read the program policy first: confirm that automated scanning, brute force and rate-limit testing are allowed, and stay inside scope. Start with `suggest_for_bounty` or `guided_assessment`. Commands below are CLI notation: run them with `run_tool`/`run_pipeline` using registry names (`list_tools`), and `run_script` only for real logic. If policy blocks a command (for example `CYBERSEC_MCP_ALLOW_EXTERNAL=0`), ask the operator to fix the configuration and restart; do not fall back to the client shell. A tool that is not in the registry is a recommendation to the user (approval-gated install), not a bare command.

## 0. Read the scope, twice

Before running any tool:

- In-scope domains, IPs, mobile apps?
- Out-of-scope (often: blogs, marketing sites, third-party SaaS, login portals with rate limits)?
- Allowed test types (active scanning? brute force? social engineering?)?
- Reporting requirements (PoC format, CVSS, screenshots)?

If on HackerOne / Bugcrowd, parse the scope CSV. Out-of-scope hits cost reputation.

## 1. Passive (no traffic to target)

```text
# Subdomain via cert transparency
run_pipeline([{"tool": "curl", "args": "-s https://crt.sh/?q=%25.target.com&output=json"}, {"tool": "jq", "args": "-r .[].name_value"}, {"tool": "sort", "args": "-u"}])

# Subdomain via passive sources
run_tool("amass", "enum -passive -d target.com")
run_tool("subfinder", "-d target.com -all -silent")
run_tool("assetfinder", "--subs-only target.com")
run_tool("findomain", "-t target.com")

# Certificate names and SANs
run_tool("tlsx", "-u target.com -san -cn -silent")
```

GitHub / GitLab / Postman dorking:

```text
# tools in registry
run_tool("gitleaks", "detect --source=. --no-git")
run_tool("trufflehog", "github --org=target-org")

# Manual:
# site:github.com "target.com" password
# site:postman.com "target.com"
```

OSINT layer:

- `run_tool("whois", "target.com")`
- ASN: `run_tool("whois", "-h whois.cymru.com -v target.com")`
- Reverse DNS / reverse whois — `domainmonster`, `viewdns.info`
- Wayback: `run_pipeline([{"tool": "waybackurls", "args": "target.com"}, {"tool": "sort", "args": "-u"}])`
- Common Crawl: `run_tool("gau", "target.com")`

## 2. Active (only after passive sweep)

Subdomain bruteforcing — only if scope allows:

```text
# DNS bruteforce
run_tool("shuffledns", "-d target.com -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -r resolvers.txt")

# Permutation: gotator is not in the registry; generate permutations with run_script if the operator allows it
```

Live host probing:

```text
# httpx -l is blocked by policy; feed hosts on stdin. Pipelines are not scope-checked on piped data, so keep to in-scope hosts
run_pipeline([{"tool": "cat", "args": "all_subs.txt"}, {"tool": "httpx", "args": "-silent -title -tech-detect -status-code -ip"}])
```

Port scan (only if scope allows full port range):

```text
# List files (-list, -iL) are blocked by policy: pass hosts directly or use run_pipeline.
run_tool("naabu", "-host 203.0.113.10 -top-ports 1000 -silent")

# Full range, only if the program allows it
run_tool("masscan", "203.0.113.10 -p 1-65535 --rate=1000")        # respect rate limits
```

Content discovery — chain with httpx output:

```text
run_tool("ffuf", "-w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u https://FUZZ.target.com -mc 200,301,302,403")
# OR per-host
run_tool("ffuf", "-w /opt/SecLists/Discovery/Web-Content/common.txt -u https://target.com/FUZZ -mc all -fc 404")
```

## 3. Tech fingerprinting

```text
run_tool("whatweb", "-a 3 https://target.com")
run_tool("nuclei", "-u https://target.com -t technologies/")     # nuclei tech detection; -l is blocked, run per host
```

JS analysis (where modern apps leak the most):

```text
# Endpoint extraction
run_tool("katana", "-u https://target.com -jc -silent")
run_tool("LinkFinder", "-i https://target.com/main.js -o cli")

# Secret in JS bundles
run_tool("trufflehog", "filesystem ./js_dumps/")
run_tool("nuclei", "-u https://target.com -t exposures/")
```

## 4. Attribution

When you find a subdomain/asset, confirm it belongs to the target:

- WHOIS
- ASN / IP block ownership
- TLS cert SAN list
- Page footer / copyright
- Linked auth provider (SSO)

Out-of-scope reporting wastes the program's time and your reputation.

## 5. Output structure

Track everything in a flat directory:

```text
target/
├── domains.txt                # all subdomains (passive + active)
├── live.txt                   # 200/301/403 alive
├── tech.txt                   # whatweb output
├── endpoints.txt              # crawled URLs
├── js_secrets.txt             # trufflehog hits
├── ports.txt                  # naabu/masscan
└── notes.md                   # running observations
```

## 6. Pivot to the right testing skill

Once recon settles:

- Web app → `bounty-web`
- API → `bounty-api`
- Mobile (APK / IPA) → `bounty-mobile`
- Cloud (S3, IAM) → cloud-specific tools

## 7. Don't

- Run aggressive scans on production without explicit permission
- Report subdomain takeovers without confirming the dangling DNS yourself
- Submit "I found a subdomain" — that's not a finding, it's recon
