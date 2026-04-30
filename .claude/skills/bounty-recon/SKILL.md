---
name: bounty-recon
description: Use at the start of a bug bounty engagement. Provides scope-aware recon methodology — passive enumeration, subdomain discovery, asset attribution, tech stack fingerprinting, content discovery. Respects scope and program rules. Triggers on "bounty recon", "subdomain enum", "attack surface map", "h1 recon", "bug bounty start".
---

# Bug bounty recon methodology

## 0. Read the scope, twice

Before running any tool:

- In-scope domains, IPs, mobile apps?
- Out-of-scope (often: blogs, marketing sites, third-party SaaS, login portals with rate limits)?
- Allowed test types (active scanning? brute force? social engineering?)?
- Reporting requirements (PoC format, CVSS, screenshots)?

If on HackerOne / Bugcrowd, parse the scope CSV. Out-of-scope hits cost reputation.

## 1. Passive (no traffic to target)

```bash
# Subdomain via cert transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Subdomain via passive sources
amass enum -passive -d target.com
subfinder -d target.com -all -silent
assetfinder --subs-only target.com
findomain -t target.com

# Combined
echo target.com | tlsx -san -cn -silent | sort -u
```

GitHub / GitLab / Postman dorking:

```bash
# tools in registry
gitleaks detect --source=. --no-git
trufflehog github --org=target-org

# Manual:
# site:github.com "target.com" password
# site:postman.com "target.com"
```

OSINT layer:

- `whois target.com`
- ASN: `whois -h whois.cymru.com " -v target.com"`
- Reverse DNS / reverse whois — `domainmonster`, `viewdns.info`
- Wayback: `waybackurls target.com | sort -u > wayback.txt`
- Common Crawl: `gau target.com`

## 2. Active (only after passive sweep)

Subdomain bruteforcing — only if scope allows:

```bash
# DNS bruteforce
shuffledns -d target.com -w wordlists/dns.txt -r resolvers.txt

# Permutation
gotator -sub subs.txt -perm permutations.txt | shuffledns -r resolvers.txt
```

Live host probing:

```bash
cat all_subs.txt | httpx -silent -title -tech-detect -status-code -ip > live.txt
```

Port scan (only if scope allows full port range):

```bash
# Top ports
naabu -list ips.txt -top-ports 1000 -silent

# Full
masscan -iL ips.txt -p 1-65535 --rate=1000        # respect rate limits
```

Content discovery — chain with httpx output:

```bash
ffuf -w wordlist.txt -u https://FUZZ.target.com -mc 200,301,302,403
# OR per-host
ffuf -w wordlist.txt -u https://target.com/FUZZ -mc all -fc 404
```

## 3. Tech fingerprinting

```bash
whatweb -a 3 https://target.com
nuclei -l live.txt -t technologies/                # nuclei tech detection
wappalyzer-cli https://target.com
```

JS analysis (where modern apps leak the most):

```bash
# Endpoint extraction
katana -u https://target.com -jc -silent | tee endpoints.txt
LinkFinder -i https://target.com/main.js -o cli

# Secret in JS bundles
trufflehog filesystem ./js_dumps/
nuclei -l live.txt -t exposures/
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
