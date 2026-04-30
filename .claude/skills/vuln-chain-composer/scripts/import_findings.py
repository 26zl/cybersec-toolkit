#!/usr/bin/env python3
"""
Findings Importer - vuln-chain-composer
Normalizes vulnerability findings from multiple sources.
Author: orizon.one
"""

import argparse
import json
import glob
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


# Severity mapping
SEVERITY_MAP = {
    "error_based_sqli": "HIGH",
    "boolean_based_sqli": "MEDIUM",
    "time_based_sqli": "HIGH",
    "reflected_xss": "MEDIUM",
    "stored_xss": "HIGH",
    "dom_xss": "MEDIUM",
    "ssrf": "HIGH",
    "ssrf_cloud_metadata": "CRITICAL",
    "idor": "MEDIUM",
    "bola": "HIGH",
    "bfla": "HIGH",
    "mass_assignment": "MEDIUM",
    "jwt_none_algorithm": "CRITICAL",
    "jwt_weak_secret": "HIGH",
    "subdomain_takeover": "HIGH",
    "public_bucket": "HIGH",
    "ssti": "CRITICAL",
    "file_upload_rce": "CRITICAL",
    "open_redirect": "LOW",
    "info_disclosure": "LOW",
    "missing_headers": "INFO",
}

# OWASP API Top 10 / Web Top 10 mapping
OWASP_MAP = {
    "sqli": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "ssrf": "A10:2021 - SSRF",
    "idor": "API1:2023 - BOLA",
    "bola": "API1:2023 - BOLA",
    "bfla": "API5:2023 - BFLA",
    "mass_assignment": "API6:2023 - Mass Assignment",
    "jwt": "API2:2023 - Broken Authentication",
    "ssti": "A03:2021 - Injection",
    "subdomain_takeover": "A05:2021 - Security Misconfiguration",
    "public_bucket": "A01:2021 - Broken Access Control",
    "open_redirect": "A01:2021 - Broken Access Control",
    "file_upload": "A04:2021 - Insecure Design",
}


def normalize_finding(finding, source_tool):
    """Normalize a finding to common format."""
    vuln_type = finding.get("type", "unknown")
    param = finding.get("param", finding.get("parameter", ""))
    url = finding.get("url", finding.get("target", ""))

    # Extract domain from URL
    domain = ""
    if url:
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).hostname or ""
        except Exception:
            pass

    severity = finding.get("severity", SEVERITY_MAP.get(vuln_type, "MEDIUM"))

    # Map to OWASP
    owasp = "Unknown"
    for key, mapping in OWASP_MAP.items():
        if key in vuln_type.lower():
            owasp = mapping
            break

    normalized = {
        "id": f"{vuln_type}_{domain}_{param}".replace(".", "_").replace("/", "_")[:100],
        "type": vuln_type,
        "category": vuln_type.split("_")[0] if "_" in vuln_type else vuln_type,
        "severity": severity,
        "owasp": owasp,
        "domain": domain,
        "url": url,
        "parameter": param,
        "method": finding.get("method", "GET"),
        "payload": finding.get("payload", ""),
        "evidence": finding.get("evidence", ""),
        "poc_curl": finding.get("poc_curl", ""),
        "source_tool": source_tool,
        "chainable_as": [],  # Populated in correlation step
        "raw": finding,
    }

    # Determine what this finding enables (for chaining)
    if "sqli" in vuln_type:
        normalized["chainable_as"] = ["data_access", "credential_theft", "rce_potential"]
    elif "xss" in vuln_type:
        normalized["chainable_as"] = ["session_theft", "phishing", "keylogging"]
    elif "ssrf" in vuln_type:
        normalized["chainable_as"] = ["internal_access", "cloud_metadata", "port_scan"]
    elif "idor" in vuln_type or "bola" in vuln_type:
        normalized["chainable_as"] = ["data_access", "privilege_escalation"]
    elif "jwt" in vuln_type or "auth" in vuln_type:
        normalized["chainable_as"] = ["authentication_bypass", "impersonation"]
    elif "takeover" in vuln_type:
        normalized["chainable_as"] = ["phishing", "session_theft", "cookie_theft"]
    elif "bucket" in vuln_type or "storage" in vuln_type:
        normalized["chainable_as"] = ["data_access", "data_modification"]
    elif "ssti" in vuln_type:
        normalized["chainable_as"] = ["rce", "data_access"]
    elif "upload" in vuln_type:
        normalized["chainable_as"] = ["rce", "webshell"]
    elif "redirect" in vuln_type:
        normalized["chainable_as"] = ["phishing", "token_theft"]

    return normalized


def load_findings_from_file(filepath):
    """Load and normalize findings from a JSON file."""
    try:
        with open(filepath) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        warn(f"Could not load {filepath}: {e}")
        return []

    # Detect source tool
    tool = data.get("meta", {}).get("tool", "unknown")
    finding_type = data.get("meta", {}).get("type", "")

    # Infer vulnerability type from filename when data lacks explicit type info
    fname = Path(filepath).stem.lower()
    inferred_type = ""
    if "sqli" in fname:
        inferred_type = "sqli"
    elif "xss" in fname:
        inferred_type = "xss"
    elif "ssrf" in fname:
        inferred_type = "ssrf"
    elif "api_discovery" in fname or "api-discovery" in fname:
        inferred_type = "info_disclosure"
    elif "bucket" in fname:
        inferred_type = "public_bucket"
    elif "trust_map" in fname or "trust-map" in fname:
        inferred_type = "trust_relationship"
    elif "attack_tree" in fname or "attack-tree" in fname:
        inferred_type = "attack_path"

    findings = data.get("findings", [])
    if not findings:
        # Try other common keys
        for key in ["vulnerabilities", "results", "issues"]:
            if key in data:
                findings = data[key]
                break

    # Handle recon-dominator consolidated.json format
    # Structure: {"meta": {...}, "data": {"passive_recon": {...}, "port_scan": {"results": [...]}, "tech_fingerprint": {...}}}
    if "data" in data and isinstance(data["data"], dict):
        consolidated = data["data"]

        # Import port scan results
        port_scan = consolidated.get("port_scan", {})
        for result in port_scan.get("results", []):
            host = result.get("host", result.get("ip", ""))
            for port_info in result.get("ports", result.get("open_ports", [])):
                port = port_info if isinstance(port_info, (int, str)) else port_info.get("port", "")
                service = port_info.get("service", "unknown") if isinstance(port_info, dict) else "unknown"
                findings.append({
                    "type": "info_disclosure",
                    "url": f"https://{host}:{port}",
                    "severity": "INFO",
                    "evidence": f"Open port {port} ({service}) on {host}",
                })

        # Import tech fingerprint findings
        tech = consolidated.get("tech_fingerprint", {})
        for target, tech_info in (tech.items() if isinstance(tech, dict) else []):
            if isinstance(tech_info, dict):
                for tech_name, details in tech_info.items():
                    version = details.get("version", "") if isinstance(details, dict) else str(details)
                    if version:
                        findings.append({
                            "type": "info_disclosure",
                            "url": f"https://{target}",
                            "severity": "LOW",
                            "evidence": f"Technology detected: {tech_name} {version}",
                        })

        # Import passive recon data (subdomains, DNS records, etc.)
        passive = consolidated.get("passive_recon", {})
        for sub in passive.get("subdomains", []):
            subdomain = sub if isinstance(sub, str) else sub.get("hostname", sub.get("subdomain", ""))
            if subdomain:
                findings.append({
                    "type": "info_disclosure",
                    "url": f"https://{subdomain}",
                    "severity": "INFO",
                    "evidence": f"Subdomain discovered: {subdomain}",
                })

        # Import any vulnerability data nested inside consolidated data sections
        for section_key, section_val in consolidated.items():
            if isinstance(section_val, dict):
                for nested_key in ["findings", "vulnerabilities", "results", "issues"]:
                    nested = section_val.get(nested_key, [])
                    if isinstance(nested, list):
                        findings.extend(nested)

    # Also import from attack trees
    if "attack_paths" in data:
        for path in data["attack_paths"]:
            findings.append({
                "type": f"attack_path_{path.get('attack_name', 'unknown').lower().replace(' ', '_')}",
                "url": f"https://{path.get('target', '')}",
                "severity": "HIGH" if path.get("combined_score", 0) >= 7 else "MEDIUM",
                "evidence": json.dumps(path.get("steps", [])[:3]),
            })

    # Import bucket findings
    if "public_buckets" in data:
        for bucket in data["public_buckets"]:
            findings.append({
                "type": "public_bucket",
                "url": f"https://{bucket['name']}.s3.amazonaws.com/" if bucket.get("provider") == "aws_s3" else bucket["name"],
                "severity": "HIGH",
                "evidence": f"Public listing with {bucket.get('files_visible', '?')} files",
            })

    # Import subdomain takeover findings
    if "relationships" in data:
        for rel in data["relationships"]:
            if rel.get("type") == "DANGLING_CNAME":
                findings.append({
                    "type": "subdomain_takeover",
                    "url": f"https://{rel.get('source', '')}",
                    "severity": "HIGH",
                    "evidence": f"Dangling CNAME to {rel.get('target', '')}",
                    "param": rel.get("target", ""),
                })

    # Import trust map data (trust_map.json)
    if "trust_relationships" in data or "trust_map" in data:
        trust_data = data.get("trust_relationships", data.get("trust_map", []))
        if isinstance(trust_data, list):
            for rel in trust_data:
                findings.append({
                    "type": "trust_relationship",
                    "url": f"https://{rel.get('source', rel.get('from', ''))}",
                    "severity": "INFO",
                    "evidence": f"Trust: {rel.get('source', rel.get('from', ''))} -> {rel.get('target', rel.get('to', ''))} ({rel.get('type', 'unknown')})",
                })
        elif isinstance(trust_data, dict):
            for source, targets in trust_data.items():
                target_list = targets if isinstance(targets, list) else [targets]
                for t in target_list:
                    target_name = t if isinstance(t, str) else t.get("target", t.get("to", str(t)))
                    findings.append({
                        "type": "trust_relationship",
                        "url": f"https://{source}",
                        "severity": "INFO",
                        "evidence": f"Trust: {source} -> {target_name}",
                    })

    # Import attack tree data (attack_tree.json)
    if "attack_tree" in data or "trees" in data:
        trees = data.get("attack_tree", data.get("trees", []))
        tree_list = trees if isinstance(trees, list) else [trees]
        for tree in tree_list:
            if isinstance(tree, dict):
                goal = tree.get("goal", tree.get("name", "unknown"))
                target = tree.get("target", "")
                score = tree.get("score", tree.get("risk_score", 5))
                findings.append({
                    "type": f"attack_path_{goal.lower().replace(' ', '_')[:50]}",
                    "url": f"https://{target}" if target else "",
                    "severity": "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM",
                    "evidence": json.dumps(tree.get("steps", tree.get("nodes", []))[:5]),
                })

    # Import API discovery data (api_discovery_*.json)
    if "endpoints" in data or "apis" in data:
        endpoints = data.get("endpoints", data.get("apis", []))
        for ep in endpoints:
            if isinstance(ep, dict):
                url = ep.get("url", ep.get("endpoint", ""))
                method = ep.get("method", "GET")
                auth_required = ep.get("auth_required", ep.get("authenticated", True))
                if not auth_required:
                    findings.append({
                        "type": "info_disclosure",
                        "url": url,
                        "method": method,
                        "severity": "MEDIUM",
                        "evidence": f"Unauthenticated API endpoint: {method} {url}",
                    })
                else:
                    findings.append({
                        "type": "info_disclosure",
                        "url": url,
                        "method": method,
                        "severity": "INFO",
                        "evidence": f"API endpoint discovered: {method} {url}",
                    })

    # Apply inferred type from filename to findings that lack a type
    if inferred_type:
        for f in findings:
            if not f.get("type") or f["type"] == "unknown":
                f["type"] = inferred_type

    normalized = []
    for finding in findings:
        normalized.append(normalize_finding(finding, tool))

    return normalized


def main():
    parser = argparse.ArgumentParser(description="Findings Importer - orizon.one")
    parser.add_argument("--input", "-i", required=True, nargs="+",
                        help="JSON files or directories with findings")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    log("Importing and normalizing findings...")

    all_findings = []
    files_processed = 0

    for input_path in args.input:
        path = Path(input_path)
        if path.is_dir():
            json_files = list(path.glob("**/*.json"))
            for jf in json_files:
                findings = load_findings_from_file(str(jf))
                if findings:
                    all_findings.extend(findings)
                    files_processed += 1
                    success(f"Loaded {len(findings)} findings from {jf.name}")
        elif path.is_file():
            findings = load_findings_from_file(str(path))
            if findings:
                all_findings.extend(findings)
                files_processed += 1
                success(f"Loaded {len(findings)} findings from {path.name}")

    # Deduplicate by ID
    seen = set()
    unique_findings = []
    for f in all_findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            unique_findings.append(f)

    # Stats
    by_severity = {}
    by_type = {}
    by_domain = {}
    for f in unique_findings:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
        typ = f["category"]
        by_type[typ] = by_type.get(typ, 0) + 1
        dom = f["domain"]
        by_domain[dom] = by_domain.get(dom, 0) + 1

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "normalized_findings",
            "tool": "vuln-chain-composer by orizon.one",
            "files_processed": files_processed,
            "total_findings": len(unique_findings),
        },
        "stats": {
            "by_severity": by_severity,
            "by_type": by_type,
            "by_domain": by_domain,
        },
        "findings": unique_findings,
    }

    output_path = args.output or "normalized_findings.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  FINDINGS IMPORT SUMMARY")
    print(f"{'='*60}")
    print(f"  Files processed : {files_processed}")
    print(f"  Total findings  : {len(unique_findings)}")
    print(f"\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in by_severity:
            print(f"    {sev:10s} : {by_severity[sev]}")
    print(f"\n  By Type:")
    for typ, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {typ:25s} : {count}")
    print(f"\n  By Domain:")
    for dom, count in sorted(by_domain.items(), key=lambda x: -x[1])[:10]:
        print(f"    {dom:35s} : {count}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
