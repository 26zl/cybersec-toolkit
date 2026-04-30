---
name: recon-dominator
description: Automated full-scope reconnaissance starting from a domain or domain list. Performs subdomain enumeration, port scanning, technology fingerprinting, OSINT correlation, Google dorking, and Wayback analysis. Use when user provides a domain or list of domains and asks for "recon", "reconnaissance", "attack surface mapping", "subdomain enumeration", "footprinting", or "information gathering". Designed for authorized penetration testing and bug bounty.
metadata:
  author: orizon.one
  version: 1.0.0
---

# Recon Dominator

Full-scope reconnaissance orchestrator. From a single domain to a complete attack surface map.

## Important

CRITICAL: Only use on domains you have explicit authorization to test. Verify scope before every engagement.

## Instructions

### Step 1: Scope Validation
Before ANY reconnaissance activity:
1. Ask the user to confirm they have written authorization to test the target domain(s)
2. Confirm the scope boundaries (wildcard subdomains? specific IPs only? out-of-scope assets?)
3. Document the scope in the output

### Step 2: Passive Subdomain Enumeration
Run passive enumeration first (no direct contact with target):

```bash
python scripts/passive_recon.py --domain {target_domain}
```

This collects subdomains from:
- Certificate Transparency logs (crt.sh)
- DNS datasets (SecurityTrails, DNSDumpster)
- Search engine results
- Wayback Machine archives

Expected output: JSON list of discovered subdomains with source attribution.

### Step 3: Active Subdomain Enumeration
After passive phase, run active enumeration:

```bash
python scripts/active_recon.py --domain {target_domain} --wordlist references/subdomains-wordlist.txt
```

This performs:
- DNS brute-force with common subdomain wordlist
- DNS zone transfer attempts
- Virtual host discovery
- Permutation/alteration scanning (dev-, staging-, api-, etc.)

### Step 4: Live Host Detection and Port Scanning

```bash
python scripts/port_scanner.py --input {subdomains_file} --top-ports 1000
```

For each live subdomain:
1. HTTP/HTTPS probe (status codes, redirects, titles)
2. Top 1000 port scan with service version detection
3. Banner grabbing on open ports
4. WAF/CDN detection (Cloudflare, Akamai, AWS CloudFront)

### Step 5: Technology Fingerprinting

```bash
python scripts/tech_fingerprint.py --input {live_hosts_file}
```

Detect:
- Web server (Apache, Nginx, IIS, etc.)
- Programming language/framework (PHP, Django, Rails, Spring, etc.)
- CMS (WordPress, Drupal, Joomla)
- JavaScript frameworks (React, Angular, Vue)
- Third-party services and integrations
- HTTP security headers (or lack thereof)

### Step 6: OSINT Correlation

```bash
python scripts/osint_correlator.py --domain {target_domain}
```

Gather:
- WHOIS history and registrant patterns
- ASN mapping and IP range ownership
- Reverse IP lookups (shared hosting)
- Email addresses associated with the domain
- Social media and GitHub references
- Leaked credentials databases (public sources only)

### Step 7: Google Dorking

```bash
python scripts/google_dorker.py --domain {target_domain} --dork-file references/dorks-database.txt
```

Automated searches for:
- Exposed files: `site:{domain} filetype:pdf|doc|xls|sql|bak|log|env`
- Login panels: `site:{domain} inurl:admin|login|dashboard`
- Directory listings: `site:{domain} intitle:"index of"`
- Error messages: `site:{domain} "sql syntax" | "warning" | "error"`
- Sensitive endpoints: `site:{domain} inurl:api|graphql|swagger|config`

### Step 8: Wayback Machine Analysis

```bash
python scripts/wayback_analyzer.py --domain {target_domain}
```

Extract:
- Historical endpoints no longer linked but still active
- Removed pages with sensitive information
- Old API versions still responding
- Parameter names from archived URLs
- JavaScript files with hardcoded secrets

### Step 9: Output Generation
Compile all findings into a structured report:

```bash
python scripts/generate_report.py --project {project_name}
```

Output format:
1. **Executive Summary**: domain count, subdomain count, live hosts, open ports, technologies
2. **Asset Inventory**: full list with metadata per asset
3. **Technology Matrix**: tech stack per subdomain
4. **Potential Entry Points**: ranked by interest level
5. **Relationship Graph**: JSON graph of domain relationships
6. **Raw Data**: all collected data in JSON for pipeline consumption

## Output Files Structure
```
output/{project_name}/
  summary.md           # Human-readable report
  assets.json          # Full asset inventory
  subdomains.json      # All discovered subdomains
  ports.json           # Port scan results
  technologies.json    # Tech fingerprinting
  osint.json           # OSINT findings
  wayback.json         # Historical data
  graph.json           # Relationship graph
  dorking_results.json # Google dork findings
```

## Error Handling

### Common Issues

#### Rate Limiting on External APIs
If you see "429 Too Many Requests":
1. The scripts have built-in rate limiting and backoff
2. If persistent, increase delay: `--delay 5`
3. For crt.sh: wait 60 seconds between requests

#### DNS Resolution Failures
If subdomains fail to resolve:
1. Try alternative DNS resolvers: `--resolvers 8.8.8.8,1.1.1.1,9.9.9.9`
2. Check if target uses split-horizon DNS
3. Some subdomains may be internal-only

#### Timeout on Port Scanning
For large scope (100+ subdomains):
1. Reduce port count: `--top-ports 100`
2. Increase timeout: `--timeout 10`
3. Run in batches: `--batch-size 20`

## Examples

### Example 1: Single Domain Recon
User says: "Run full recon on example.com"

Actions:
1. Confirm authorization
2. Run all steps sequentially on example.com
3. Generate consolidated report

Result: Complete attack surface map with all subdomains, services, and technologies.

### Example 2: Multi-Domain Bug Bounty Scope
User says: "I have a bug bounty scope: *.example.com, api.example.org, app.example.io"

Actions:
1. Confirm bug bounty program and scope rules
2. Run passive + active enum on each wildcard domain
3. For specific subdomains, skip enumeration, go directly to port scan
4. Cross-correlate findings between domains
5. Generate unified report

### Example 3: Quick Passive Only
User says: "Do passive recon only on example.com, no active scanning"

Actions:
1. Run only Steps 2, 6, 7, 8 (no direct target contact)
2. Skip active DNS brute, port scanning, tech fingerprinting
3. Generate report with passive findings only
