#!/usr/bin/env python3
"""
Cloud Security Report Generator - cloud-pivot-finder
Consolidates all cloud security findings into a prioritized report.
Author: orizon.one
"""

import argparse
import json
import os
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def vuln(msg):
    print(f"[!!] {msg}")


# Severity weights for prioritization
SEVERITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def find_report_files(project, search_dir="."):
    """Find all cloud-pivot-finder output files for a project."""
    files = {}
    search_path = Path(search_dir)

    # Patterns to look for
    file_patterns = {
        "cloud_detection": [
            f"cloud_detection_{project.replace('.', '_')}.json",
            f"cloud_detection_multi.json",
            "cloud_detection_*.json",
        ],
        "bucket_enumeration": [
            f"buckets_{project.replace('.', '_')}.json",
            "buckets_*.json",
        ],
        "takeover_scan": [
            "takeover_results.json",
            f"takeover_{project.replace('.', '_')}.json",
        ],
        "serverless_discovery": [
            f"serverless_{project.replace('.', '_')}.json",
            "serverless_*.json",
        ],
        "cicd_exposure": [
            f"cicd_exposure_{project.replace('.', '_')}.json",
            "cicd_exposure_*.json",
        ],
        "metadata_pivot_paths": [
            "metadata_pivot_paths.json",
            f"metadata_paths_{project.replace('.', '_')}.json",
        ],
    }

    for report_type, patterns in file_patterns.items():
        for pattern in patterns:
            if "*" in pattern:
                matches = list(search_path.glob(pattern))
                if matches:
                    # Use most recently modified
                    files[report_type] = max(matches, key=lambda p: p.stat().st_mtime)
                    break
            else:
                candidate = search_path / pattern
                if candidate.exists():
                    files[report_type] = candidate
                    break

    return files


def load_json_safe(path):
    """Load a JSON file, returning empty dict on failure."""
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
        warn(f"Could not load {path}: {e}")
        return {}


def build_infrastructure_map(cloud_data):
    """Build cloud infrastructure map from detection results."""
    infra_map = {
        "providers": {},
        "services": {},
        "hosts": [],
    }

    if not cloud_data:
        return infra_map

    # Provider summary
    infra_map["providers"] = cloud_data.get("provider_summary", {})

    # Per-host details
    for result in cloud_data.get("results", []):
        host_entry = {
            "hostname": result.get("hostname", ""),
            "ip": result.get("ip", ""),
            "providers": result.get("providers_detected", []),
            "services": [],
        }

        for svc in result.get("cloud_services", []):
            service_name = svc.get("service", svc.get("provider", "unknown"))
            host_entry["services"].append(service_name)

            if service_name not in infra_map["services"]:
                infra_map["services"][service_name] = []
            infra_map["services"][service_name].append(result.get("hostname", ""))

        infra_map["hosts"].append(host_entry)

    return infra_map


def build_bucket_summary(bucket_data):
    """Build bucket findings summary."""
    summary = {
        "total_found": 0,
        "public_listing": 0,
        "private": 0,
        "critical_buckets": [],
        "all_buckets": [],
    }

    if not bucket_data:
        return summary

    stats = bucket_data.get("stats", {})
    summary["total_found"] = stats.get("total_found", 0)
    summary["public_listing"] = stats.get("public_listing", 0)
    summary["private"] = stats.get("private", 0)

    for bucket in bucket_data.get("public_buckets", []):
        summary["critical_buckets"].append({
            "name": bucket.get("name", ""),
            "provider": bucket.get("provider", ""),
            "files_visible": bucket.get("files_visible", 0),
            "sample_files": bucket.get("sample_files", []),
            "severity": "critical",
        })

    summary["all_buckets"] = (
        bucket_data.get("public_buckets", []) +
        bucket_data.get("private_buckets", [])
    )

    return summary


def build_takeover_summary(takeover_data):
    """Build subdomain takeover summary."""
    summary = {
        "total_scanned": 0,
        "vulnerable": 0,
        "findings": [],
    }

    if not takeover_data:
        return summary

    stats = takeover_data.get("stats", {})
    summary["total_scanned"] = stats.get("total_scanned", 0)
    summary["vulnerable"] = stats.get("vulnerable", 0)

    for v in takeover_data.get("vulnerable", []):
        summary["findings"].append({
            "subdomain": v.get("subdomain", ""),
            "cname": v.get("cname", ""),
            "service": v.get("service", ""),
            "impact": v.get("impact", ""),
            "evidence": v.get("evidence", ""),
            "method": v.get("method", ""),
            "severity": "critical" if v.get("impact") == "high" else "high",
        })

    return summary


def build_serverless_summary(serverless_data):
    """Build serverless exposure summary."""
    summary = {
        "endpoints_found": 0,
        "accessible": 0,
        "with_issues": 0,
        "findings": [],
    }

    if not serverless_data:
        return summary

    stats = serverless_data.get("stats", {})
    summary["endpoints_found"] = stats.get("endpoints_discovered", 0)
    summary["accessible"] = stats.get("endpoints_accessible", 0)
    summary["with_issues"] = stats.get("endpoints_with_issues", 0)

    for ep in serverless_data.get("accessible_endpoints", []):
        severity = "high"
        if any(i.get("type", "").startswith("info_leak_credentials") for i in ep.get("issues", [])):
            severity = "critical"

        summary["findings"].append({
            "hostname": ep.get("hostname", ""),
            "service": ep.get("service", ""),
            "issues": ep.get("issues", []),
            "severity": severity,
        })

    return summary


def build_cicd_summary(cicd_data):
    """Build CI/CD exposure summary."""
    summary = {
        "total_findings": 0,
        "by_severity": {},
        "findings": [],
    }

    if not cicd_data:
        return summary

    stats = cicd_data.get("stats", {})
    summary["total_findings"] = stats.get("total_findings", 0)
    summary["by_severity"] = {
        "critical": stats.get("critical", 0),
        "high": stats.get("high", 0),
        "medium": stats.get("medium", 0),
        "low": stats.get("low", 0),
    }

    for sev in ["critical", "high", "medium", "low"]:
        for finding in cicd_data.get("findings_by_severity", {}).get(sev, []):
            summary["findings"].append({
                "host": finding.get("host", ""),
                "category": finding.get("category", ""),
                "description": finding.get("description", ""),
                "severity": sev,
                "url": finding.get("probe", {}).get("url", finding.get("url", "")),
            })

    return summary


def build_pivot_summary(pivot_data):
    """Build metadata pivot path summary."""
    summary = {
        "ssrf_vectors": 0,
        "pivot_paths": 0,
        "paths": [],
    }

    if not pivot_data:
        return summary

    stats = pivot_data.get("stats", {})
    summary["ssrf_vectors"] = stats.get("ssrf_vectors_found", 0)
    summary["pivot_paths"] = stats.get("pivot_paths_mapped", 0)

    for path in pivot_data.get("pivot_paths", []):
        summary["paths"].append({
            "host": path.get("host", ""),
            "provider": path.get("provider", ""),
            "ssrf_vectors": [v.get("vector_type", "") for v in path.get("ssrf_vectors", [])],
            "pivot_description": path.get("pivot_description", ""),
            "severity": "critical",
        })

    return summary


def generate_remediation_plan(sections):
    """Generate prioritized remediation plan from all findings."""
    actions = []

    # Collect all findings with severity
    # Public buckets
    for bucket in sections.get("buckets", {}).get("critical_buckets", []):
        actions.append({
            "priority": 1,
            "severity": "critical",
            "category": "Storage",
            "title": f"Restrict public access on bucket: {bucket['name']}",
            "description": (
                f"Bucket {bucket['name']} ({bucket['provider']}) allows public listing. "
                f"{bucket.get('files_visible', 'Unknown number of')} files are exposed. "
                f"Disable public access and review bucket policy."
            ),
            "remediation": [
                "Disable public access at the account/bucket level",
                "Review and restrict bucket policy",
                "Enable access logging",
                "Audit exposed files for sensitive data",
                "Rotate any exposed credentials",
            ],
        })

    # Subdomain takeovers
    for finding in sections.get("takeover", {}).get("findings", []):
        actions.append({
            "priority": 1 if finding.get("impact") == "high" else 2,
            "severity": finding.get("severity", "high"),
            "category": "DNS/Subdomain",
            "title": f"Fix dangling CNAME: {finding['subdomain']}",
            "description": (
                f"Subdomain {finding['subdomain']} has a dangling CNAME to {finding['cname']} "
                f"({finding['service']}). An attacker could claim this resource and serve "
                f"content under your domain."
            ),
            "remediation": [
                "Remove the dangling DNS record if the service is no longer needed",
                "Re-provision the cloud resource to reclaim it",
                "Audit cookies and same-origin implications",
            ],
        })

    # CI/CD exposure
    for finding in sections.get("cicd", {}).get("findings", []):
        prio = 1 if finding["severity"] == "critical" else 2
        actions.append({
            "priority": prio,
            "severity": finding["severity"],
            "category": "CI/CD & IaC",
            "title": f"Remove exposed {finding['category']}: {finding.get('url', finding['host'])}",
            "description": finding.get("description", ""),
            "remediation": [
                "Remove or restrict access to exposed configuration files",
                "Ensure CI/CD interfaces are not publicly accessible",
                "Rotate any credentials found in exposed files",
                "Implement network-level access controls",
            ],
        })

    # Serverless exposure
    for finding in sections.get("serverless", {}).get("findings", []):
        actions.append({
            "priority": 2,
            "severity": finding.get("severity", "high"),
            "category": "Serverless",
            "title": f"Secure serverless endpoint: {finding['hostname']}",
            "description": (
                f"Serverless endpoint {finding['hostname']} ({finding['service']}) "
                f"has {len(finding.get('issues', []))} issue(s) including potential "
                f"unauthenticated access."
            ),
            "remediation": [
                "Enable authentication/authorization on the endpoint",
                "Disable debug mode and verbose error messages",
                "Apply least-privilege IAM policies",
                "Enable request logging and monitoring",
            ],
        })

    # Pivot paths
    for path in sections.get("pivot_paths", {}).get("paths", []):
        actions.append({
            "priority": 1,
            "severity": "critical",
            "category": "Cloud Pivot",
            "title": f"Mitigate SSRF-to-cloud pivot: {path['host']} -> {path['provider']}",
            "description": (
                f"Host {path['host']} on {path['provider']} infrastructure has potential SSRF "
                f"vectors ({', '.join(path.get('ssrf_vectors', ['unknown']))}) that could be "
                f"exploited to access cloud metadata and steal credentials."
            ),
            "remediation": [
                "Fix identified SSRF vulnerabilities",
                f"Enable IMDSv2 (AWS) or equivalent metadata protection",
                "Apply least-privilege IAM roles",
                "Implement network-level metadata endpoint restrictions",
                "Monitor for unusual metadata service access patterns",
            ],
        })

    # Sort by priority then severity weight
    actions.sort(key=lambda a: (a["priority"], -SEVERITY_WEIGHTS.get(a["severity"], 0)))

    return actions


def main():
    parser = argparse.ArgumentParser(description="Cloud Security Report Generator - orizon.one")
    parser.add_argument("--project", "-p", required=True,
                        help="Project name (used to find result files)")
    parser.add_argument("--dir", "-d", default=".",
                        help="Directory containing result files (default: current)")
    parser.add_argument("--cloud-detection", help="Path to cloud detection JSON")
    parser.add_argument("--buckets", help="Path to bucket enumeration JSON")
    parser.add_argument("--takeover", help="Path to takeover scan JSON")
    parser.add_argument("--serverless", help="Path to serverless discovery JSON")
    parser.add_argument("--cicd", help="Path to CI/CD exposure JSON")
    parser.add_argument("--pivot-paths", help="Path to metadata pivot paths JSON")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--format", choices=["json", "text", "both"], default="both",
                        help="Output format (default: both)")
    args = parser.parse_args()

    log(f"Generating cloud security report for project: {args.project}")

    # Find or use specified report files
    auto_files = find_report_files(args.project, args.dir)

    file_map = {
        "cloud_detection": args.cloud_detection or auto_files.get("cloud_detection"),
        "bucket_enumeration": args.buckets or auto_files.get("bucket_enumeration"),
        "takeover_scan": args.takeover or auto_files.get("takeover_scan"),
        "serverless_discovery": args.serverless or auto_files.get("serverless_discovery"),
        "cicd_exposure": args.cicd or auto_files.get("cicd_exposure"),
        "metadata_pivot_paths": args.pivot_paths or auto_files.get("metadata_pivot_paths"),
    }

    # Load data
    loaded_data = {}
    for report_type, path in file_map.items():
        if path:
            log(f"Loading {report_type}: {path}")
            loaded_data[report_type] = load_json_safe(str(path))
        else:
            warn(f"No {report_type} file found")
            loaded_data[report_type] = {}

    # Build report sections
    sections = {
        "infrastructure": build_infrastructure_map(loaded_data["cloud_detection"]),
        "buckets": build_bucket_summary(loaded_data["bucket_enumeration"]),
        "takeover": build_takeover_summary(loaded_data["takeover_scan"]),
        "serverless": build_serverless_summary(loaded_data["serverless_discovery"]),
        "cicd": build_cicd_summary(loaded_data["cicd_exposure"]),
        "pivot_paths": build_pivot_summary(loaded_data["metadata_pivot_paths"]),
    }

    # Generate remediation plan
    remediation = generate_remediation_plan(sections)

    # Compute overall risk score
    total_critical = (
        sections["buckets"]["public_listing"] +
        sections["takeover"]["vulnerable"] +
        len([f for f in sections["cicd"].get("findings", []) if f["severity"] == "critical"]) +
        sections["pivot_paths"]["pivot_paths"]
    )
    total_high = (
        len([f for f in sections["serverless"].get("findings", [])]) +
        len([f for f in sections["cicd"].get("findings", []) if f["severity"] == "high"]) +
        len([f for f in sections["takeover"].get("findings", []) if f.get("severity") == "high"])
    )

    if total_critical > 0:
        risk_level = "CRITICAL"
    elif total_high > 0:
        risk_level = "HIGH"
    elif sections["buckets"]["total_found"] > 0 or sections["serverless"]["endpoints_found"] > 0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    report = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "cloud_security_report",
            "tool": "cloud-pivot-finder by orizon.one",
            "project": args.project,
        },
        "executive_summary": {
            "risk_level": risk_level,
            "total_critical_findings": total_critical,
            "total_high_findings": total_high,
            "cloud_providers_detected": list(sections["infrastructure"].get("providers", {}).keys()),
            "hosts_on_cloud": len(sections["infrastructure"].get("hosts", [])),
            "key_findings": [],
        },
        "sections": sections,
        "remediation_plan": remediation,
        "data_sources": {k: str(v) for k, v in file_map.items() if v},
    }

    # Build key findings for executive summary
    key = report["executive_summary"]["key_findings"]
    if sections["buckets"]["public_listing"] > 0:
        key.append(f"{sections['buckets']['public_listing']} publicly accessible storage bucket(s)")
    if sections["takeover"]["vulnerable"] > 0:
        key.append(f"{sections['takeover']['vulnerable']} subdomain(s) vulnerable to takeover")
    if sections["serverless"]["accessible"] > 0:
        key.append(f"{sections['serverless']['accessible']} serverless endpoint(s) with unauthenticated access")
    if sections["cicd"]["total_findings"] > 0:
        key.append(f"{sections['cicd']['total_findings']} CI/CD or IaC exposure(s)")
    if sections["pivot_paths"]["pivot_paths"] > 0:
        key.append(f"{sections['pivot_paths']['pivot_paths']} cloud pivot path(s) via SSRF")

    # Output
    output_base = args.output or f"cloud_report_{args.project.replace('.', '_')}"

    if args.format in ("json", "both"):
        json_path = output_base if output_base.endswith(".json") else f"{output_base}.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        success(f"JSON report saved to: {json_path}")

    if args.format in ("text", "both"):
        txt_path = output_base.replace(".json", "") + ".txt"
        _write_text_report(report, txt_path)
        success(f"Text report saved to: {txt_path}")

    # Print summary to console
    _print_summary(report)


def _write_text_report(report, path):
    """Write a human-readable text report."""
    lines = []
    w = lines.append

    w("=" * 70)
    w("  CLOUD SECURITY ASSESSMENT REPORT")
    w(f"  Project: {report['meta']['project']}")
    w(f"  Date: {report['meta']['timestamp']}")
    w(f"  Tool: cloud-pivot-finder by orizon.one")
    w("=" * 70)

    # Executive Summary
    es = report["executive_summary"]
    w("")
    w("EXECUTIVE SUMMARY")
    w("-" * 40)
    w(f"  Overall Risk Level : {es['risk_level']}")
    w(f"  Critical Findings  : {es['total_critical_findings']}")
    w(f"  High Findings      : {es['total_high_findings']}")
    w(f"  Cloud Providers    : {', '.join(es['cloud_providers_detected']) or 'None detected'}")
    w(f"  Cloud Hosts        : {es['hosts_on_cloud']}")
    if es["key_findings"]:
        w("")
        w("  Key Findings:")
        for kf in es["key_findings"]:
            w(f"    - {kf}")

    sections = report["sections"]

    # Infrastructure Map
    w("")
    w("=" * 70)
    w("  1. CLOUD INFRASTRUCTURE MAP")
    w("=" * 70)
    infra = sections["infrastructure"]
    if infra["providers"]:
        w("  Providers:")
        for prov, count in infra["providers"].items():
            w(f"    {prov:25s}: {count} host(s)")
    if infra["hosts"]:
        w(f"\n  Hosts ({len(infra['hosts'])}):")
        for h in infra["hosts"][:20]:
            svcs = ", ".join(h["services"][:3]) if h["services"] else "no services identified"
            w(f"    {h['hostname']:40s} [{', '.join(h['providers'])}] - {svcs}")
        if len(infra["hosts"]) > 20:
            w(f"    ... and {len(infra['hosts']) - 20} more")

    # Buckets
    w("")
    w("=" * 70)
    w("  2. STORAGE BUCKETS")
    w("=" * 70)
    bkt = sections["buckets"]
    w(f"  Found: {bkt['total_found']} | Public: {bkt['public_listing']} | Private: {bkt['private']}")
    if bkt["critical_buckets"]:
        w("\n  PUBLIC BUCKETS (CRITICAL):")
        for b in bkt["critical_buckets"]:
            w(f"    {b['name']} ({b['provider']}) - {b.get('files_visible', '?')} files exposed")

    # Takeover
    w("")
    w("=" * 70)
    w("  3. SUBDOMAIN TAKEOVER")
    w("=" * 70)
    tk = sections["takeover"]
    w(f"  Scanned: {tk['total_scanned']} | Vulnerable: {tk['vulnerable']}")
    if tk["findings"]:
        w("\n  VULNERABLE SUBDOMAINS:")
        for f in tk["findings"]:
            w(f"    {f['subdomain']} -> {f['cname']} ({f['service']}, {f['impact']} impact)")

    # Serverless
    w("")
    w("=" * 70)
    w("  4. SERVERLESS EXPOSURE")
    w("=" * 70)
    sl = sections["serverless"]
    w(f"  Endpoints: {sl['endpoints_found']} | Accessible: {sl['accessible']} | Issues: {sl['with_issues']}")
    if sl["findings"]:
        w("\n  EXPOSED ENDPOINTS:")
        for f in sl["findings"]:
            w(f"    {f['hostname']} ({f['service']}) - {len(f.get('issues', []))} issue(s)")

    # CI/CD
    w("")
    w("=" * 70)
    w("  5. CI/CD AND IaC EXPOSURE")
    w("=" * 70)
    ci = sections["cicd"]
    w(f"  Total findings: {ci['total_findings']}")
    if ci.get("by_severity"):
        for sev, count in ci["by_severity"].items():
            if count > 0:
                w(f"    {sev.upper():10s}: {count}")
    if ci["findings"]:
        w("\n  FINDINGS:")
        for f in ci["findings"][:15]:
            w(f"    [{f['severity'].upper()}] {f['host']}: {f['description']}")
        if len(ci["findings"]) > 15:
            w(f"    ... and {len(ci['findings']) - 15} more")

    # Pivot Paths
    w("")
    w("=" * 70)
    w("  6. CLOUD PIVOT PATHS")
    w("=" * 70)
    pp = sections["pivot_paths"]
    w(f"  SSRF vectors: {pp['ssrf_vectors']} | Pivot paths: {pp['pivot_paths']}")
    if pp["paths"]:
        w("\n  PIVOT CHAINS:")
        for p in pp["paths"]:
            w(f"    {p['host']} -> {p['provider']}:")
            for line in p.get("pivot_description", "").split("\n"):
                w(f"      {line}")

    # Remediation
    w("")
    w("=" * 70)
    w("  7. PRIORITIZED REMEDIATION PLAN")
    w("=" * 70)
    remediation = report["remediation_plan"]
    if remediation:
        for i, action in enumerate(remediation, 1):
            w(f"\n  {i}. [{action['severity'].upper()}] {action['title']}")
            w(f"     Category: {action['category']}")
            w(f"     {action['description'][:200]}")
            w(f"     Remediation steps:")
            for step in action.get("remediation", []):
                w(f"       - {step}")
    else:
        w("  No critical or high findings requiring immediate remediation.")

    w("")
    w("=" * 70)
    w("  END OF REPORT")
    w("=" * 70)

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def _print_summary(report):
    """Print report summary to console."""
    es = report["executive_summary"]

    print(f"\n{'='*60}")
    print(f"  CLOUD SECURITY REPORT - {report['meta']['project']}")
    print(f"{'='*60}")
    print(f"  Risk Level        : {es['risk_level']}")
    print(f"  Critical findings : {es['total_critical_findings']}")
    print(f"  High findings     : {es['total_high_findings']}")
    print(f"  Cloud providers   : {', '.join(es['cloud_providers_detected']) or 'None'}")

    if es["key_findings"]:
        print(f"\n  Key Findings:")
        for kf in es["key_findings"]:
            print(f"    - {kf}")

    remediation = report["remediation_plan"]
    if remediation:
        print(f"\n  Top Remediation Actions:")
        for action in remediation[:5]:
            print(f"    [{action['severity'].upper()}] {action['title']}")

    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
