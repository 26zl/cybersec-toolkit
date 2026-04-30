#!/usr/bin/env python3
"""
Attack Tree Generator - attack-path-architect
Generates prioritized attack trees with MITRE ATT&CK mapping.
Author: orizon.one
"""

import argparse
import json
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


# MITRE ATT&CK TTP Library (relevant subset)
MITRE_TTPS = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1078.004": {"name": "Cloud Accounts", "tactic": "Initial Access"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Lateral Movement"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1552.005": {"name": "Cloud Instance Metadata API", "tactic": "Credential Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1539": {"name": "Steal Web Session Cookie", "tactic": "Credential Access"},
    "T1530": {"name": "Data from Cloud Storage", "tactic": "Collection"},
    "T1213": {"name": "Data from Information Repositories", "tactic": "Collection"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact"},
}

# Attack patterns based on asset type and technology
ATTACK_PATTERNS = {
    "WEB_APP": [
        {
            "name": "SQL Injection to RCE",
            "feasibility_base": 6,
            "impact": 9,
            "steps": [
                {"action": "Identify injectable parameters via fuzzing", "ttp": "T1190", "tools": ["sqlmap", "Burp Suite"]},
                {"action": "Exploit SQL injection for data extraction", "ttp": "T1190", "tools": ["sqlmap"]},
                {"action": "Escalate to OS command execution (xp_cmdshell, LOAD_FILE, INTO OUTFILE)", "ttp": "T1059", "tools": ["sqlmap --os-shell"]},
                {"action": "Establish reverse shell", "ttp": "T1059.004", "tools": ["netcat", "bash"]},
            ],
            "conditions": ["PHP", "MySQL", "WordPress", "Laravel", "ASP.NET", "MSSQL"]
        },
        {
            "name": "SSRF to Cloud Credential Theft",
            "feasibility_base": 5,
            "impact": 9,
            "steps": [
                {"action": "Identify SSRF vectors (URL parameters, PDF generators, webhooks)", "ttp": "T1190", "tools": ["Burp Suite"]},
                {"action": "Access cloud metadata endpoint (169.254.169.254)", "ttp": "T1552.005", "tools": ["curl"]},
                {"action": "Extract IAM role credentials from metadata", "ttp": "T1552", "tools": ["curl", "aws-cli"]},
                {"action": "Use stolen credentials to access cloud resources", "ttp": "T1078.004", "tools": ["aws-cli", "gcloud"]},
            ],
            "conditions": []  # Applicable to any web app on cloud
        },
        {
            "name": "XSS to Session Hijacking",
            "feasibility_base": 7,
            "impact": 6,
            "steps": [
                {"action": "Find reflected/stored XSS in user input fields", "ttp": "T1190", "tools": ["Burp Suite", "XSStrike"]},
                {"action": "Craft payload to steal session cookies", "ttp": "T1539", "tools": ["custom JS payload"]},
                {"action": "Use stolen session on target application", "ttp": "T1550", "tools": ["browser"]},
            ],
            "conditions": []
        },
        {
            "name": "Authentication Bypass via JWT Manipulation",
            "feasibility_base": 4,
            "impact": 8,
            "steps": [
                {"action": "Intercept JWT token from authentication flow", "ttp": "T1552", "tools": ["Burp Suite"]},
                {"action": "Test none algorithm bypass", "ttp": "T1190", "tools": ["jwt_tool"]},
                {"action": "Test key confusion (RS256->HS256)", "ttp": "T1190", "tools": ["jwt_tool"]},
                {"action": "Brute-force weak JWT secret", "ttp": "T1110", "tools": ["jwt_tool", "hashcat"]},
                {"action": "Forge admin JWT token", "ttp": "T1078", "tools": ["jwt_tool"]},
            ],
            "conditions": ["React", "Angular", "Vue.js", "Express.js", "Next.js"]
        },
    ],
    "API": [
        {
            "name": "BOLA/IDOR to Data Exfiltration",
            "feasibility_base": 7,
            "impact": 8,
            "steps": [
                {"action": "Map API endpoints and identify object references", "ttp": "T1190", "tools": ["Burp Suite", "Postman"]},
                {"action": "Test horizontal privilege escalation (access other users' objects)", "ttp": "T1190", "tools": ["Burp Intruder"]},
                {"action": "Enumerate and exfiltrate accessible data", "ttp": "T1213", "tools": ["custom script"]},
            ],
            "conditions": []
        },
        {
            "name": "GraphQL Introspection to Full Schema Leak",
            "feasibility_base": 8,
            "impact": 7,
            "steps": [
                {"action": "Send introspection query to GraphQL endpoint", "ttp": "T1190", "tools": ["GraphQL Voyager", "Insomnia"]},
                {"action": "Map all queries, mutations, and types", "ttp": "T1213", "tools": ["GraphQL Voyager"]},
                {"action": "Identify sensitive mutations (admin operations, data deletion)", "ttp": "T1190", "tools": ["Burp Suite"]},
                {"action": "Test authorization on privileged mutations", "ttp": "T1548", "tools": ["Burp Suite"]},
            ],
            "conditions": ["GraphQL"]
        },
    ],
    "ADMIN_PANEL": [
        {
            "name": "Default/Weak Credentials on Admin Panel",
            "feasibility_base": 6,
            "impact": 9,
            "steps": [
                {"action": "Identify admin panel technology", "ttp": "T1190", "tools": ["browser"]},
                {"action": "Test default credentials for the platform", "ttp": "T1110", "tools": ["hydra", "custom wordlist"]},
                {"action": "Access admin functionality", "ttp": "T1078", "tools": ["browser"]},
                {"action": "Leverage admin access for RCE (file upload, plugin install, template edit)", "ttp": "T1059", "tools": ["platform-specific"]},
            ],
            "conditions": []
        },
    ],
    "DATABASE": [
        {
            "name": "Direct Database Access via Exposed Port",
            "feasibility_base": 5,
            "impact": 10,
            "steps": [
                {"action": "Connect to exposed database port", "ttp": "T1133", "tools": ["mysql", "psql", "mongo"]},
                {"action": "Test default/empty credentials", "ttp": "T1110", "tools": ["hydra", "medusa"]},
                {"action": "Enumerate databases and tables", "ttp": "T1213", "tools": ["native client"]},
                {"action": "Exfiltrate sensitive data", "ttp": "T1048", "tools": ["native client"]},
            ],
            "conditions": []
        },
    ],
    "CI_CD": [
        {
            "name": "CI/CD Pipeline Compromise for Code Execution",
            "feasibility_base": 5,
            "impact": 10,
            "steps": [
                {"action": "Access exposed CI/CD interface (Jenkins, GitLab)", "ttp": "T1133", "tools": ["browser"]},
                {"action": "Test default credentials or unauthenticated access", "ttp": "T1110", "tools": ["browser"]},
                {"action": "Access build configuration and secrets", "ttp": "T1552", "tools": ["CI platform"]},
                {"action": "Modify pipeline to inject malicious code", "ttp": "T1059", "tools": ["CI platform"]},
                {"action": "Code deployed to production = RCE", "ttp": "T1059", "tools": ["CI platform"]},
            ],
            "conditions": ["Jenkins", "GitLab"]
        },
    ],
    "STORAGE": [
        {
            "name": "Public Cloud Storage Data Leak",
            "feasibility_base": 6,
            "impact": 8,
            "steps": [
                {"action": "Enumerate cloud storage buckets via naming patterns", "ttp": "T1530", "tools": ["aws-cli", "gcloud"]},
                {"action": "Test for public read access", "ttp": "T1530", "tools": ["aws s3 ls"]},
                {"action": "Download exposed files", "ttp": "T1530", "tools": ["aws s3 cp"]},
                {"action": "Test for public write access (defacement/supply chain risk)", "ttp": "T1530", "tools": ["aws s3 cp"]},
            ],
            "conditions": []
        },
    ],
    "LEGACY": [
        {
            "name": "Exploit Known Vulnerabilities in Legacy System",
            "feasibility_base": 8,
            "impact": 8,
            "steps": [
                {"action": "Identify software version from banners/headers", "ttp": "T1190", "tools": ["nmap", "whatweb"]},
                {"action": "Search for known CVEs for the version", "ttp": "T1190", "tools": ["searchsploit", "CVE databases"]},
                {"action": "Download and adapt public exploit", "ttp": "T1190", "tools": ["exploit-db", "GitHub"]},
                {"action": "Execute exploit for initial access", "ttp": "T1190", "tools": ["metasploit", "custom script"]},
            ],
            "conditions": []
        },
    ],
}


def generate_paths(assets, trust_map=None):
    """Generate attack paths for all assets."""
    paths = []

    trust_relationships = []
    if trust_map:
        trust_relationships = trust_map.get("relationships", [])

    for asset in assets:
        host = asset.get("host", "")
        asset_type = asset.get("asset_type", "WEB_APP")
        technologies = asset.get("technologies", [])
        risk_score = asset.get("risk_score", 1)

        # Get applicable attack patterns
        type_patterns = ATTACK_PATTERNS.get(asset_type, [])
        # Also always check WEB_APP patterns for any HTTP-serving asset
        if asset_type != "WEB_APP" and any(p.get("port") in [80, 443, 8080, 8443] for p in asset.get("open_ports", [])):
            type_patterns = type_patterns + ATTACK_PATTERNS.get("WEB_APP", [])

        for pattern in type_patterns:
            # Check conditions
            conditions = pattern.get("conditions", [])
            condition_met = not conditions or any(tech in technologies for tech in conditions)

            feasibility = pattern["feasibility_base"]

            # Adjust feasibility based on asset characteristics
            if risk_score >= 7:
                feasibility = min(feasibility + 2, 10)
            elif risk_score >= 5:
                feasibility = min(feasibility + 1, 10)

            if asset.get("waf_cdn", "none_detected") not in ["none_detected", "none", ""]:
                feasibility = max(feasibility - 2, 1)

            if condition_met and conditions:
                feasibility = min(feasibility + 1, 10)

            # Stealth score
            stealth = 5
            if asset.get("waf_cdn") in ["none_detected", "none", ""]:
                stealth += 2
            if asset_type in ["LEGACY", "MONITORING"]:
                stealth += 1  # Less likely to be monitored

            impact = pattern["impact"]
            combined_score = (feasibility * 0.4) + (impact * 0.4) + (stealth * 0.2)

            # Build steps with MITRE mapping
            detailed_steps = []
            for step in pattern["steps"]:
                ttp_id = step["ttp"]
                ttp_info = MITRE_TTPS.get(ttp_id, {"name": "Unknown", "tactic": "Unknown"})
                detailed_steps.append({
                    "action": step["action"],
                    "ttp_id": ttp_id,
                    "ttp_name": ttp_info["name"],
                    "tactic": ttp_info["tactic"],
                    "tools": step["tools"],
                })

            paths.append({
                "target": host,
                "asset_type": asset_type,
                "attack_name": pattern["name"],
                "feasibility": round(feasibility, 1),
                "impact": impact,
                "stealth": stealth,
                "combined_score": round(combined_score, 2),
                "condition_matched": condition_met,
                "matched_technologies": [t for t in technologies if t in conditions] if conditions else [],
                "steps": detailed_steps,
                "mitre_tactics": list(dict.fromkeys(s["tactic"] for s in detailed_steps)),
            })

    # Sort by combined score
    paths.sort(key=lambda x: x["combined_score"], reverse=True)
    return paths


def generate_chain_opportunities(paths, trust_relationships):
    """Identify where separate attack paths can be chained."""
    chains = []

    # Find cross-subdomain chains via shared cookies
    cookie_sharing = [r for r in trust_relationships if r["type"] == "SHARED_COOKIE_SCOPE"]
    xss_paths = [p for p in paths if "XSS" in p["attack_name"]]

    if cookie_sharing and xss_paths:
        for xss in xss_paths:
            chains.append({
                "name": f"XSS on {xss['target']} -> Session Hijacking across all subdomains",
                "score": xss["combined_score"] + 2,
                "steps": [
                    f"Exploit XSS on {xss['target']}",
                    "Steal session cookie (scoped to wildcard domain)",
                    "Use stolen cookie on higher-value subdomain",
                ],
                "risk": "HIGH",
            })

    # Find SSRF -> cloud chains
    ssrf_paths = [p for p in paths if "SSRF" in p["attack_name"]]
    storage_paths = [p for p in paths if p["asset_type"] == "STORAGE"]

    if ssrf_paths and storage_paths:
        for ssrf in ssrf_paths:
            chains.append({
                "name": f"SSRF on {ssrf['target']} -> Cloud credentials -> Storage access",
                "score": ssrf["combined_score"] + 3,
                "steps": [
                    f"Exploit SSRF on {ssrf['target']}",
                    "Access cloud metadata for IAM credentials",
                    "Use credentials to access cloud storage buckets",
                ],
                "risk": "CRITICAL",
            })

    # Find admin panel -> RCE chains
    admin_paths = [p for p in paths if p["asset_type"] == "ADMIN_PANEL"]
    cicd_paths = [p for p in paths if p["asset_type"] == "CI_CD"]

    if admin_paths and cicd_paths:
        chains.append({
            "name": "Admin Panel -> CI/CD -> Production RCE",
            "score": 9.0,
            "steps": [
                f"Compromise admin panel ({admin_paths[0]['target']})",
                f"Pivot to CI/CD system ({cicd_paths[0]['target']})",
                "Modify deployment pipeline",
                "Deploy malicious code to production",
            ],
            "risk": "CRITICAL",
        })

    # Dangling CNAME chains
    dangling = [r for r in trust_relationships if r["type"] == "DANGLING_CNAME"]
    for d in dangling:
        chains.append({
            "name": f"Subdomain Takeover on {d['source']} -> Phishing/Cookie theft",
            "score": 8.5,
            "steps": [
                f"Register/claim the dangling target: {d['target']}",
                f"Host malicious content on {d['source']}",
                "Phish users or steal cookies via trusted subdomain",
            ],
            "risk": "CRITICAL",
        })

    chains.sort(key=lambda x: x["score"], reverse=True)
    return chains


def main():
    parser = argparse.ArgumentParser(description="Attack Tree Generator - orizon.one")
    parser.add_argument("--input", "-i", required=True, help="Classified assets JSON")
    parser.add_argument("--trust-map", "-t", help="Trust map JSON from map_trust.py")
    parser.add_argument("--objective", choices=["rce", "data", "lateral", "all"], default="all",
                        help="Attack objective filter")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    log("Generating attack trees...")

    with open(args.input) as f:
        asset_data = json.load(f)
    assets = asset_data.get("assets", [])

    trust_map = {}
    trust_relationships = []
    if args.trust_map:
        with open(args.trust_map) as f:
            trust_map = json.load(f)
        trust_relationships = trust_map.get("relationships", [])

    # Generate paths
    paths = generate_paths(assets, trust_map)

    # Generate chains
    chains = generate_chain_opportunities(paths, trust_relationships)

    # MITRE ATT&CK matrix
    tactic_coverage = {}
    for path in paths:
        for step in path["steps"]:
            tactic = step["tactic"]
            ttp = step["ttp_id"]
            if tactic not in tactic_coverage:
                tactic_coverage[tactic] = set()
            tactic_coverage[tactic].add(ttp)
    # Convert sets to lists for JSON
    tactic_coverage = {k: sorted(v) for k, v in tactic_coverage.items()}

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "attack_tree",
            "tool": "attack-path-architect by orizon.one",
            "total_paths": len(paths),
            "total_chains": len(chains),
        },
        "attack_paths": paths,
        "chain_opportunities": chains,
        "mitre_coverage": tactic_coverage,
        "recommended_testing_order": [
            {"rank": i+1, "target": p["target"], "attack": p["attack_name"], "score": p["combined_score"]}
            for i, p in enumerate(paths[:20])
        ],
    }

    output_path = args.output or "attack_tree.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  ATTACK TREE SUMMARY")
    print(f"{'='*60}")
    print(f"  Total attack paths  : {len(paths)}")
    print(f"  Chain opportunities : {len(chains)}")
    print(f"  MITRE tactics hit   : {len(tactic_coverage)}")
    print(f"{'='*60}")

    print(f"\n  TOP 10 ATTACK PATHS (by combined score):")
    for i, p in enumerate(paths[:10]):
        print(f"  {i+1:2d}. [{p['combined_score']:.1f}] {p['target']}")
        print(f"      {p['attack_name']} (F:{p['feasibility']} I:{p['impact']} S:{p['stealth']})")

    if chains:
        print(f"\n  CHAIN OPPORTUNITIES:")
        for c in chains[:5]:
            print(f"  [{c['risk']:8s}] {c['name']}")
            for step in c["steps"]:
                print(f"             -> {step}")
    print()


if __name__ == "__main__":
    main()
