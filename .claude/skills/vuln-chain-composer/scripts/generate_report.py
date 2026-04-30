#!/usr/bin/env python3
"""
Bug Bounty Report Generator - vuln-chain-composer
Generates HackerOne/Bugcrowd-ready reports with full chain details.
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


def warn(msg):
    print(f"[!] {msg}")


# VRT (Vulnerability Rating Taxonomy) mapping for Bugcrowd
VRT_MAP = {
    "sqli": "Server-Side Injection > SQL Injection",
    "xss": "Cross-Site Scripting (XSS) > Reflected / Stored",
    "ssrf": "Server-Side Injection > SSRF",
    "idor": "Broken Access Control (BAC) > IDOR",
    "bola": "Broken Access Control (BAC) > IDOR",
    "bfla": "Broken Access Control (BAC) > Privilege Escalation",
    "jwt": "Broken Authentication > JWT",
    "takeover": "Server Security Misconfiguration > Subdomain Takeover",
    "bucket": "Server Security Misconfiguration > Cloud Storage",
    "redirect": "Unvalidated Redirects and Forwards > Open Redirect",
    "ssti": "Server-Side Injection > SSTI",
    "upload": "Server-Side Injection > File Upload leading to RCE",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "info": "Information Disclosure",
}

# Remediation recommendations by vulnerability type
REMEDIATION_MAP = {
    "sqli": [
        "Use parameterized queries / prepared statements for ALL database interactions",
        "Implement input validation with allowlists for expected data types",
        "Apply the principle of least privilege to database accounts",
        "Deploy a Web Application Firewall (WAF) as defense-in-depth",
    ],
    "xss": [
        "Implement context-aware output encoding (HTML, JavaScript, URL, CSS)",
        "Deploy Content-Security-Policy (CSP) headers with strict nonce/hash-based policies",
        "Use HTTPOnly and Secure flags on session cookies",
        "Validate and sanitize all user input on the server side",
    ],
    "ssrf": [
        "Implement allowlist-based URL validation for outbound requests",
        "Block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)",
        "Use a dedicated HTTP proxy for server-side requests with restricted access",
        "Disable unnecessary URL schemes (file://, gopher://, dict://)",
    ],
    "idor": [
        "Implement proper authorization checks on every request (not just authentication)",
        "Use unpredictable identifiers (UUIDs) instead of sequential integers",
        "Validate that the authenticated user has permission to access the requested resource",
        "Implement rate limiting on enumerable endpoints",
    ],
    "bola": [
        "Implement object-level authorization checks on every API endpoint",
        "Use the authenticated user's identity from the session (not from request parameters)",
        "Log and alert on access pattern anomalies",
    ],
    "jwt": [
        "Enforce algorithm validation on the server (reject 'none' and unexpected algorithms)",
        "Use strong, randomly generated secrets (256+ bits) for HMAC-based JWTs",
        "Implement short expiration times and token rotation",
        "Validate all JWT claims (iss, aud, exp, nbf) on the server",
    ],
    "takeover": [
        "Audit and remove dangling DNS records (CNAME, A, AAAA) pointing to unclaimed resources",
        "Implement automated monitoring for subdomain takeover conditions",
        "Scope cookies to specific subdomains rather than using wildcard (*.domain.com) scoping",
    ],
    "bucket": [
        "Review and restrict bucket ACLs - disable public read/write access",
        "Enable server-side encryption for all stored objects",
        "Implement bucket policies that deny public access",
        "Enable access logging and monitoring for sensitive buckets",
    ],
    "redirect": [
        "Implement allowlist-based redirect URL validation",
        "Reject absolute URLs and external domains in redirect parameters",
        "Use indirect reference maps instead of direct URL parameters",
    ],
    "ssti": [
        "Use a logic-less template engine or sandbox template execution",
        "Never pass user input directly into template rendering functions",
        "Implement strict input validation and sanitization",
    ],
    "csrf": [
        "Implement anti-CSRF tokens (synchronizer token pattern) on all state-changing requests",
        "Use SameSite=Strict or SameSite=Lax cookie attribute",
        "Verify Origin and Referer headers on state-changing requests",
    ],
    "info": [
        "Remove sensitive information from error messages and responses",
        "Disable directory listing and debug modes in production",
        "Audit and rotate any exposed credentials or API keys immediately",
    ],
}


def get_remediation(vuln_type):
    """Get remediation recommendations for a vulnerability type."""
    for key, recs in REMEDIATION_MAP.items():
        if key in vuln_type.lower():
            return recs
    return ["Review and remediate the identified vulnerability according to security best practices."]


def get_vrt(vuln_type):
    """Get Bugcrowd VRT classification."""
    for key, vrt in VRT_MAP.items():
        if key in vuln_type.lower():
            return vrt
    return "Other"


def generate_ascii_chain_diagram(chain):
    """Generate an ASCII diagram of the attack flow."""
    phases = chain.get("phases", [])
    steps = chain.get("steps", [])

    nodes = []
    if phases:
        for phase in phases:
            nodes.append(phase.get("technique", phase.get("phase", "Step")))
    elif steps:
        for step in steps:
            # Truncate long step text
            nodes.append(step[:40] + "..." if len(step) > 40 else step)

    if not nodes:
        return "  [No chain steps available]"

    lines = []
    max_width = max(len(n) for n in nodes) + 4

    for i, node in enumerate(nodes):
        box_content = f"| {node:<{max_width - 4}} |"
        border = "+" + "-" * (max_width - 2) + "+"
        lines.append(f"  {border}")
        lines.append(f"  {box_content}")
        lines.append(f"  {border}")
        if i < len(nodes) - 1:
            center = max_width // 2
            lines.append(f"  {' ' * center}|")
            lines.append(f"  {' ' * center}v")

    return "\n".join(lines)


def generate_hackerone_report(chain, poc_data=None):
    """Generate a HackerOne-formatted report."""
    chain_name = chain.get("name", "Vulnerability Chain")
    severity = chain.get("chain_severity", chain.get("overall_severity", "HIGH"))
    cvss_score = chain.get("cvss_score", "N/A")
    cvss_vector = chain.get("cvss_vector", "N/A")
    description = chain.get("description", "")
    primary = chain.get("primary_finding", chain.get("original_correlation", {}).get("primary_finding", {}))
    supporting = chain.get("supporting_findings", chain.get("original_correlation", {}).get("supporting_findings", []))
    impact_analysis = chain.get("impact_analysis", {})

    # Collect all affected domains/URLs
    affected_assets = set()
    if primary.get("url"):
        affected_assets.add(primary["url"])
    if primary.get("domain"):
        affected_assets.add(primary["domain"])
    for sf in supporting:
        if sf.get("url"):
            affected_assets.add(sf["url"])
        if sf.get("domain"):
            affected_assets.add(sf["domain"])

    # Build steps to reproduce
    steps_text = []
    phases = chain.get("phases", [])
    steps = chain.get("steps", [])
    step_num = 0

    if phases:
        for phase in phases:
            for step in phase.get("detailed_steps", []):
                step_num += 1
                steps_text.append(f"{step_num}. {step.get('action', '')}")
    elif steps:
        for i, step in enumerate(steps):
            steps_text.append(f"{i+1}. {step}")

    # Build PoC section
    poc_section = ""
    if poc_data:
        curl_poc = poc_data.get("curl_poc", "")
        if curl_poc:
            poc_section = f"```bash\n{curl_poc}\n```"
    if not poc_section:
        poc_section = "```\n# PoC scripts available in the generated output\n# Run generate_chain_poc.py for full exploitation scripts\n```"

    # Collect unique vuln types for remediation
    vuln_types = set()
    if primary.get("type"):
        vuln_types.add(primary["type"])
    for sf in supporting:
        if sf.get("type"):
            vuln_types.add(sf["type"])

    remediation_lines = []
    seen_recs = set()
    for vt in vuln_types:
        recs = get_remediation(vt)
        for rec in recs:
            if rec not in seen_recs:
                seen_recs.add(rec)
                remediation_lines.append(f"- {rec}")

    diagram = generate_ascii_chain_diagram(chain)

    justification = impact_analysis.get("justification", description)

    report = f"""## {chain_name}

**Severity:** {severity} (CVSS {cvss_score})
**CVSS Vector:** `{cvss_vector}`

## Summary

{description}

This vulnerability chain combines {len(supporting) + 1} individual finding(s) to achieve {severity}-severity impact. The chain amplifies the impact of each individual vulnerability beyond its standalone severity rating.

## Affected Assets

{chr(10).join(f"- `{asset}`" for asset in sorted(affected_assets)) if affected_assets else "- See steps to reproduce for target details"}

## Steps to Reproduce

{chr(10).join(steps_text) if steps_text else "1. See detailed chain phases in the attached report"}

## Proof of Concept

{poc_section}

## Impact

{justification}

**Business Impact:**
- Confidentiality: {_impact_detail(chain, "C")}
- Integrity: {_impact_detail(chain, "I")}
- Availability: {_impact_detail(chain, "A")}

## Attack Scenario

An attacker could exploit this vulnerability chain as follows:

1. **Initial Access:** Exploit {primary.get('type', 'the primary vulnerability')} on `{primary.get('domain', primary.get('url', 'the target'))}`
2. **Escalation:** Leverage gained access/data to exploit supporting vulnerabilities across the target's infrastructure
3. **Impact:** Achieve {severity.lower()}-severity impact as described above

This is a realistic attack scenario that could be executed by a motivated attacker with network access to the target.

## Chain Visualization

```
{diagram}
```

## Remediation

To fully remediate this chain, ALL of the following should be addressed:

{chr(10).join(remediation_lines)}

**Note:** Fixing any single vulnerability in the chain may break this specific attack path, but defense-in-depth requires addressing all findings.
"""
    return report


def _impact_detail(chain, metric):
    """Get impact detail for a CIA metric."""
    impact_analysis = chain.get("impact_analysis", {})
    metrics = impact_analysis.get("metrics", {})
    value = metrics.get(metric, "N")
    descriptions = {
        "C": {"H": "Full access to sensitive data including credentials and PII",
               "L": "Limited access to non-critical information",
               "N": "No confidentiality impact"},
        "I": {"H": "Full ability to modify data and system configuration",
               "L": "Limited ability to modify non-critical data",
               "N": "No integrity impact"},
        "A": {"H": "Full disruption of service availability",
               "L": "Limited disruption to non-critical services",
               "N": "No availability impact"},
    }
    return descriptions.get(metric, {}).get(value, "See CVSS vector for details")


def generate_bugcrowd_report(chain, poc_data=None):
    """Generate a Bugcrowd-formatted report."""
    chain_name = chain.get("name", "Vulnerability Chain")
    severity = chain.get("chain_severity", chain.get("overall_severity", "HIGH"))
    primary = chain.get("primary_finding", chain.get("original_correlation", {}).get("primary_finding", {}))
    supporting = chain.get("supporting_findings", chain.get("original_correlation", {}).get("supporting_findings", []))

    # Get VRT classification
    vrt_classes = set()
    if primary.get("type"):
        vrt_classes.add(get_vrt(primary["type"]))
    for sf in supporting:
        if sf.get("type"):
            vrt_classes.add(get_vrt(sf["type"]))

    # Build the hackerone-style report and add Bugcrowd-specific fields
    base_report = generate_hackerone_report(chain, poc_data)

    bugcrowd_header = f"""**VRT Classification:** {" + ".join(sorted(vrt_classes))}
**Priority:** P{1 if severity == "CRITICAL" else 2 if severity == "HIGH" else 3 if severity == "MEDIUM" else 4}

"""
    # Insert after the first line (title)
    lines = base_report.split("\n", 1)
    return lines[0] + "\n" + bugcrowd_header + lines[1] if len(lines) > 1 else base_report


def generate_generic_report(chain, poc_data=None):
    """Generate a generic pentest report format."""
    # Use HackerOne format as base with slight modifications
    report = generate_hackerone_report(chain, poc_data)
    header = f"""---
Report Type: Penetration Test Finding
Classification: CONFIDENTIAL
Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
Tool: vuln-chain-composer by orizon.one
---

"""
    return header + report


def main():
    parser = argparse.ArgumentParser(description="Report Generator - orizon.one")
    parser.add_argument("--input", "-i", required=True, help="Chains JSON file (with impact analysis)")
    parser.add_argument("--pocs", "-p", help="PoC JSON file (output of generate_chain_poc.py)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--format", "-f", choices=["hackerone", "bugcrowd", "generic", "all"],
                        default="all", help="Report format (default: all)")
    parser.add_argument("--output-dir", "-d", help="Directory to write individual report files")
    args = parser.parse_args()

    log("Generating bug bounty reports...")

    with open(args.input) as f:
        data = json.load(f)

    chains = data.get("chains", [])
    log(f"Loaded {len(chains)} chains for report generation")

    # Load PoC data if available
    poc_map = {}
    if args.pocs:
        try:
            with open(args.pocs) as f:
                poc_data = json.load(f)
            for poc in poc_data.get("pocs", []):
                poc_map[poc["chain_name"]] = poc
            log(f"Loaded PoC data for {len(poc_map)} chains")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            warn(f"Could not load PoC file: {e}")

    if not chains:
        warn("No chains found in input.")
        return

    output_dir = None
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    report_results = []
    formats_to_generate = ["hackerone", "bugcrowd", "generic"] if args.format == "all" else [args.format]

    for i, chain in enumerate(chains):
        chain_name = chain.get("name", f"chain_{i+1}")
        safe_name = chain_name.lower().replace(" ", "_").replace("+", "and").replace("=", "eq")[:50]
        poc_data = poc_map.get(chain_name)

        entry = {
            "chain_name": chain_name,
            "chain_severity": chain.get("chain_severity", chain.get("overall_severity", "HIGH")),
            "cvss_score": chain.get("cvss_score", "N/A"),
            "reports": {},
        }

        for fmt in formats_to_generate:
            if fmt == "hackerone":
                report = generate_hackerone_report(chain, poc_data)
            elif fmt == "bugcrowd":
                report = generate_bugcrowd_report(chain, poc_data)
            else:
                report = generate_generic_report(chain, poc_data)

            entry["reports"][fmt] = report

            if output_dir:
                report_path = output_dir / f"report_{safe_name}_{fmt}.md"
                with open(report_path, "w") as f:
                    f.write(report)
                success(f"Written: {report_path}")

        report_results.append(entry)
        success(f"Generated reports for: {chain_name} ({', '.join(formats_to_generate)})")

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "bug_bounty_reports",
            "tool": "vuln-chain-composer by orizon.one",
            "chains_reported": len(report_results),
            "formats": formats_to_generate,
        },
        "reports": report_results,
    }

    output_path = args.output or "chain_reports.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  REPORT GENERATION SUMMARY")
    print(f"{'='*60}")
    print(f"  Chains reported   : {len(report_results)}")
    print(f"  Report formats    : {', '.join(formats_to_generate)}")
    if output_dir:
        print(f"  Output directory  : {output_dir}")
    print(f"\n  Reports Generated:")
    for i, r in enumerate(report_results):
        score = r['cvss_score']
        score_str = f"CVSS {score}" if score != "N/A" else ""
        print(f"    {i+1}. {r['chain_name']} [{r['chain_severity']}] {score_str}")
        for fmt in r["reports"]:
            line_count = len(r["reports"][fmt].splitlines())
            print(f"       {fmt:12s}: {line_count} lines")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
