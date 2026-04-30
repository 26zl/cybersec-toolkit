---
name: attack-path-architect
description: Generates strategic attack trees and kill chains from reconnaissance data or domain input. Maps MITRE ATT&CK TTPs, identifies chaining opportunities, trust relationships, and prioritizes attack paths by feasibility and impact. Use when user asks for "attack path", "kill chain", "attack tree", "threat modeling from recon", "attack surface analysis", or "prioritize targets". Requires prior recon data or a domain to analyze. For authorized pentesting and red team engagements only.
metadata:
  author: orizon.one
  version: 1.0.0
---

# Attack Path Architect

Strategic attack path generator. Transforms reconnaissance data into actionable kill chains mapped to MITRE ATT&CK.

## Important

CRITICAL: This skill is for authorized penetration testing and red team engagements ONLY. Confirm authorization before generating attack paths.

## Instructions

### Step 1: Input Collection
Accept one of these inputs:
1. **Recon JSON data** from recon-dominator (consolidated.json or individual module outputs)
2. **Raw domain** - will perform lightweight recon first to gather data
3. **Manual asset list** - user provides hostnames, IPs, services, technologies

If the user provides only a domain, run a quick recon summary first using recon-dominator scripts, then proceed.

### Step 2: Asset Classification

```bash
python scripts/classify_assets.py --input {recon_data}
```

Classify every discovered asset by:

**Exposure Level:**
- EXTERNAL: Internet-facing, directly reachable
- SEMI-EXTERNAL: Behind CDN/WAF but still reachable
- INTERNAL-EXPOSED: Internal service accidentally exposed (common with cloud misconfig)

**Asset Type:**
- WEB_APP: Web applications (highest attack surface)
- API: REST/GraphQL/SOAP endpoints
- MAIL: Email infrastructure
- DNS: DNS servers
- VPN: VPN gateways
- DATABASE: Exposed database services
- ADMIN_PANEL: Management interfaces
- CI_CD: Build/deploy infrastructure
- MONITORING: Grafana, Kibana, Prometheus, etc.
- STORAGE: S3, GCS, Azure Blob, etc.
- LEGACY: Old/deprecated systems still running

**Risk Score (1-10):** Based on technology age, known CVE count, misconfiguration signals, exposure level.

### Step 3: Trust Relationship Mapping

```bash
python scripts/map_trust.py --input {recon_data}
```

Identify trust relationships between assets:
- **SSO/OAuth connections**: Shared authentication across subdomains
- **Cookie scope**: Wildcard cookies (.domain.com) enabling session sharing
- **API dependencies**: Internal APIs called by external apps
- **DNS relationships**: CNAME chains, shared nameservers
- **Certificate sharing**: Shared TLS certificates (SAN entries)
- **IP proximity**: Assets in same subnet/ASN suggesting shared infrastructure

Output: Directed graph of trust relationships in JSON format.

### Step 4: Attack Tree Generation

```bash
python scripts/generate_attack_tree.py --input {classified_assets} --trust-map {trust_map} --objective {objective}
```

For each objective (RCE, Data Access, Lateral Movement, Privilege Escalation), generate attack trees:

**Tree Structure:**
```
OBJECTIVE: Remote Code Execution on production
|
+-- PATH 1: Web Application Exploitation (Feasibility: HIGH)
|   +-- Step 1: Identify injectable parameter on app.target.com
|   |   TTP: T1190 - Exploit Public-Facing Application
|   |   Tools: sqlmap, Burp Suite
|   +-- Step 2: Achieve SQL injection -> OS command execution
|   |   TTP: T1059 - Command and Scripting Interpreter
|   +-- Step 3: Establish reverse shell
|       TTP: T1059.004 - Unix Shell
|
+-- PATH 2: Cloud Pivot via SSRF (Feasibility: MEDIUM)
|   +-- Step 1: Find SSRF in PDF generator on docs.target.com
|   |   TTP: T1190 - Exploit Public-Facing Application
|   +-- Step 2: Access cloud metadata (169.254.169.254)
|   |   TTP: T1552.005 - Cloud Instance Metadata API
|   +-- Step 3: Extract IAM credentials
|   |   TTP: T1078.004 - Cloud Accounts
|   +-- Step 4: Use credentials to access EC2/Lambda
|       TTP: T1078 - Valid Accounts
```

### Step 5: Chaining Opportunity Analysis

```bash
python scripts/find_chains.py --attack-tree {tree_file} --trust-map {trust_map}
```

Identify where vulnerabilities on different assets can be chained:
- XSS on subdomain A -> cookie theft -> session on subdomain B (shared cookie scope)
- SSRF on app -> cloud metadata -> credentials -> S3 bucket access
- SQL injection -> database credentials -> access to internal API
- Admin panel default creds -> CI/CD access -> code deployment -> RCE
- DNS takeover -> phishing page -> credential capture -> internal access

For each chain:
1. List all steps with specific assets
2. Assign overall feasibility score
3. Estimate impact (what access is gained)
4. Map full MITRE ATT&CK path

### Step 6: Priority Ranking

Score each attack path on:
- **Feasibility** (1-10): How likely is successful exploitation?
  - Known CVEs: +3
  - Default credentials: +3
  - Missing security headers: +1
  - Outdated software: +2
  - Exposed admin panel: +2
- **Impact** (1-10): What access does this provide?
  - RCE on production: 10
  - Database access: 9
  - Admin panel access: 7
  - User data exposure: 8
  - Internal network pivot: 9
- **Stealth** (1-10): How likely to avoid detection?
  - No WAF: +3
  - No monitoring visible: +2
  - Uses legitimate protocols: +2
- **Combined Score**: (Feasibility * 0.4) + (Impact * 0.4) + (Stealth * 0.2)

### Step 7: Report Generation

```bash
python scripts/generate_attack_report.py --project {name}
```

Output:
1. **Attack Surface Summary**: Asset count by type and exposure
2. **Trust Relationship Graph**: Visual representation of connections
3. **Prioritized Attack Paths**: Ranked by combined score
4. **MITRE ATT&CK Mapping**: Full TTP matrix for all paths
5. **Recommended Testing Order**: Which paths to test first
6. **Detection Opportunities**: What the blue team should monitor for each path

## Examples

### Example 1: Full Analysis from Recon Data
User says: "Analyze attack paths from this recon data"

Actions:
1. Load consolidated.json from recon-dominator
2. Classify all assets
3. Map trust relationships
4. Generate attack trees for RCE, data access, lateral movement
5. Find chaining opportunities
6. Rank and report

### Example 2: Quick Assessment from Domain
User says: "What are the most likely attack paths for example.com?"

Actions:
1. Quick recon (passive only for speed)
2. Classify discovered assets
3. Generate attack trees based on visible technology stack
4. Prioritize by feasibility
5. Provide top 5 attack paths with rationale

### Example 3: Targeted Objective
User says: "Find paths to access the database from external for target.com"

Actions:
1. Load existing recon or perform quick recon
2. Focus classification on database-adjacent services
3. Generate attack tree with single objective: database access
4. Map all possible paths (direct exposure, SQL injection, SSRF chains, credential reuse)
5. Rank by feasibility

## Error Handling

### No recon data available
If no prior recon exists:
1. Suggest running recon-dominator first for best results
2. Offer to do lightweight passive recon inline
3. Work with whatever information the user provides manually

### Insufficient data for path generation
If assets lack detail:
1. Note assumptions clearly in output
2. Mark paths as "requires validation"
3. Suggest specific additional recon to fill gaps
