#!/usr/bin/env python3
"""
API Security Report Generator Module - api-breaker
Generates per-finding reports with OWASP API Top 10 mapping and remediation.
Author: orizon.one
"""

import argparse
import json
import os
import urllib.parse
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def vuln(msg):
    print(f"[VULN] {msg}")


# OWASP API Security Top 10 (2023) mapping
OWASP_API_TOP10 = {
    "API1": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "description": "APIs expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues.",
    },
    "API2": {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "description": "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.",
    },
    "API3": {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "description": "Lack of or improper authorization validation at the object property level leads to information exposure or manipulation.",
    },
    "API4": {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "description": "APIs do not restrict the size or number of resources that can be requested, leading to Denial of Service and financial impact.",
    },
    "API5": {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "description": "Complex access control policies with different hierarchies, groups, and roles, lead to authorization flaws.",
    },
    "API6": {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": "APIs that are vulnerable to this risk expose business flows without compensating for the damage if used excessively.",
    },
    "API7": {
        "id": "API7:2023",
        "name": "Server Side Request Forgery",
        "description": "SSRF flaws can occur when an API is fetching a remote resource without validating the user-supplied URL.",
    },
    "API8": {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "description": "APIs and supporting systems typically contain complex configurations that can be improperly secured.",
    },
    "API9": {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "description": "APIs tend to expose more endpoints than traditional web applications. Proper and updated documentation is important.",
    },
    "API10": {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "description": "Developers tend to trust data received from third-party APIs more than user input, adopting weaker security standards.",
    },
}

# Map finding types to OWASP categories
FINDING_TO_OWASP = {
    # BOLA findings -> API1
    "bola": "API1",
    "bola_idor": "API1",

    # Auth findings -> API2
    "jwt_none_bypass": "API2",
    "jwt_key_confusion": "API2",
    "jwt_weak_secret": "API2",
    "jwt_none_alg": "API2",
    "jwt_no_expiry": "API2",
    "jwt_long_expiry": "API2",
    "jwt_sensitive_data": "API2",
    "no_auth_required": "API2",
    "api_key_position": "API2",

    # Mass assignment -> API3
    "mass_assignment": "API3",
    "mass_assignment_nested": "API3",

    # Rate limiting -> API4
    "no_rate_limit": "API4",
    "rate_limit_bypass": "API4",
    "graphql_batching": "API4",
    "graphql_alias_batching": "API4",

    # BFLA -> API5
    "bfla": "API5",
    "bfla_method_override": "API5",

    # Business logic -> API6
    "price_manipulation": "API6",
    "quantity_overflow": "API6",
    "coupon_stacking": "API6",
    "race_condition": "API6",
    "negative_amount": "API6",

    # Privilege escalation -> API5 / API3
    "privilege_escalation": "API5",

    # JWT claims info -> API2
    "jwt_symmetric_alg": "API2",
    "jwt_privilege_claims": "API8",
}

# Remediation recommendations
REMEDIATIONS = {
    "bola": "Implement proper object-level authorization checks. Verify the logged-in user has permission to access the requested object. Use random, unpredictable IDs (UUIDs) instead of sequential integers.",
    "bola_idor": "Implement proper object-level authorization checks. Verify the logged-in user has permission to access the requested object. Use random, unpredictable IDs (UUIDs) instead of sequential integers.",
    "jwt_none_bypass": "Reject JWTs with 'none' algorithm. Always validate the algorithm against a whitelist of allowed algorithms on the server side. Never trust the algorithm specified in the JWT header.",
    "jwt_key_confusion": "Use separate code paths for symmetric and asymmetric algorithms. Explicitly specify the expected algorithm when verifying JWTs. Never use the algorithm from the JWT header for verification.",
    "jwt_weak_secret": "Use a cryptographically strong random secret (at least 256 bits) for HMAC-based JWT signing. Consider using asymmetric algorithms (RS256, ES256) instead.",
    "jwt_none_alg": "Configure the JWT library to reject tokens with 'none' algorithm. Always require a valid signature.",
    "jwt_no_expiry": "Always include an 'exp' (expiration) claim in JWTs. Set a reasonable expiration time based on the use case.",
    "jwt_long_expiry": "Reduce JWT expiration time. Use refresh tokens for long-lived sessions. Implement token rotation.",
    "jwt_sensitive_data": "Never store sensitive data in JWT payloads. JWTs are base64-encoded, not encrypted. Use server-side session storage for sensitive data.",
    "no_auth_required": "Implement authentication for all sensitive endpoints. Use API gateway or middleware to enforce authentication globally.",
    "mass_assignment": "Use an allowlist of permitted fields for each endpoint. Never bind request data directly to internal objects. Implement a DTO (Data Transfer Object) pattern.",
    "mass_assignment_nested": "Validate nested objects against a strict schema. Use allowlists for nested object fields. Implement deep input validation.",
    "no_rate_limit": "Implement rate limiting on all API endpoints. Use sliding window or token bucket algorithms. Return 429 status with Retry-After header.",
    "rate_limit_bypass": "Implement rate limiting based on authenticated user identity, not IP address. Do not trust X-Forwarded-For or similar headers for rate limiting decisions.",
    "graphql_batching": "Limit the number of queries per batch request. Implement query cost analysis. Set maximum query depth and complexity limits.",
    "graphql_alias_batching": "Implement query complexity analysis that accounts for aliases. Limit the number of aliases per query. Set maximum query cost limits.",
    "bfla": "Implement role-based access control (RBAC). Enforce function-level authorization on every endpoint. Deny by default and explicitly grant permissions.",
    "bfla_method_override": "Disable HTTP method override headers in production. If method override is needed, ensure authorization is checked against the overridden method.",
    "price_manipulation": "Always calculate prices on the server side. Never trust client-provided prices, totals, or discounts. Validate all financial values against server-side records.",
    "quantity_overflow": "Validate quantity ranges on the server side. Set minimum (1) and maximum bounds. Use appropriate data types to prevent integer overflow.",
    "coupon_stacking": "Implement server-side coupon validation. Prevent duplicate coupon usage. Define clear rules for coupon stacking and enforce them server-side.",
    "race_condition": "Use database-level locking or atomic operations for critical business logic. Implement idempotency keys. Use optimistic locking with version numbers.",
    "negative_amount": "Validate that all monetary amounts are positive on the server side. Implement minimum value constraints. Use absolute values or reject negative inputs.",
    "privilege_escalation": "Prevent users from modifying their own role or privilege fields. Use a separate admin-only endpoint for privilege changes. Validate all privilege-related fields server-side.",
    "api_key_position": "Standardize API key transmission method. Prefer Authorization header. Avoid accepting API keys in query parameters (they may be logged in server logs and browser history).",
    "jwt_symmetric_alg": "Consider using asymmetric algorithms (RS256, ES256) for better key management. If using symmetric algorithms, ensure the secret is strong and properly managed.",
    "jwt_privilege_claims": "Validate privilege claims against the authorization server on each request. Do not solely rely on JWT claims for authorization decisions.",
}


def build_curl_command(finding):
    """Build a curl command for reproducing the finding."""
    url = finding.get("url", "")
    method = finding.get("method", "GET")
    payload = finding.get("payload")

    parts = [f"curl -X {method}"]
    parts.append(f"'{url}'")
    parts.append("-H 'Content-Type: application/json'")
    parts.append("-H 'Accept: application/json'")

    if payload:
        payload_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)
        parts.append(f"-d '{payload_str}'")

    return " \\\n  ".join(parts)


def assess_impact(finding):
    """Assess the impact of a finding."""
    severity = finding.get("severity", "medium")
    finding_type = finding.get("type", "")

    impacts = {
        "bola": "Unauthorized access to other users' data. Potential data breach, privacy violation, and regulatory non-compliance.",
        "bola_idor": "Unauthorized access to other users' data via predictable identifiers. Full data exposure risk.",
        "jwt_none_bypass": "Complete authentication bypass. Attacker can forge tokens for any user, gaining full system access.",
        "jwt_key_confusion": "Complete authentication bypass via algorithm confusion. Attacker can forge valid tokens.",
        "jwt_weak_secret": "Authentication bypass via known secret. Attacker can create valid tokens for any user.",
        "no_auth_required": "Sensitive data exposed without authentication. Any anonymous user can access protected resources.",
        "mass_assignment": "Unauthorized modification of protected fields. May lead to privilege escalation, financial fraud, or data integrity issues.",
        "mass_assignment_nested": "Unauthorized modification via nested objects. May bypass flat-field protections.",
        "no_rate_limit": "API vulnerable to brute-force attacks, credential stuffing, and denial of service.",
        "rate_limit_bypass": "Rate limiting can be bypassed, negating brute-force and DoS protections.",
        "bfla": "Unauthorized access to admin/privileged functionality. Regular users can perform administrative actions.",
        "price_manipulation": "Financial fraud via manipulated prices. Direct monetary loss to the business.",
        "race_condition": "Double spending or duplicate operations. Financial loss and data integrity issues.",
        "negative_amount": "Financial manipulation via negative values. May result in unauthorized fund transfers.",
        "privilege_escalation": "Users can elevate their own privileges. Complete system compromise possible.",
    }

    return impacts.get(finding_type, f"Security vulnerability with {severity} severity. Potential for unauthorized access or data manipulation.")


def generate_finding_report(finding, index):
    """Generate a detailed report for a single finding."""
    finding_type = finding.get("type", "unknown")
    owasp_key = FINDING_TO_OWASP.get(finding_type, "API8")
    owasp = OWASP_API_TOP10.get(owasp_key, OWASP_API_TOP10["API8"])

    report = {
        "finding_id": f"F-{index:03d}",
        "title": f"{finding_type.replace('_', ' ').title()} - {finding.get('url', 'N/A')}",
        "severity": finding.get("severity", "medium"),
        "type": finding_type,
        "owasp_mapping": {
            "id": owasp["id"],
            "name": owasp["name"],
            "description": owasp["description"],
        },
        "affected_endpoint": {
            "url": finding.get("url", "N/A"),
            "method": finding.get("method", "N/A"),
            "path": finding.get("path", "N/A"),
        },
        "details": {
            k: v for k, v in finding.items()
            if k not in ("type", "severity", "url", "method", "path")
        },
        "curl_command": build_curl_command(finding),
        "impact": assess_impact(finding),
        "remediation": REMEDIATIONS.get(finding_type, "Review and fix the identified vulnerability. Implement proper input validation and access controls."),
    }

    return report


def load_findings_from_dir(findings_dir):
    """Load findings from all JSON files in a directory."""
    all_findings = []

    if not os.path.isdir(findings_dir):
        # Treat as a single file
        if os.path.isfile(findings_dir):
            with open(findings_dir) as f:
                data = json.load(f)
            return data.get("findings", [data] if "type" in data else [])
        return []

    for filename in sorted(os.listdir(findings_dir)):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(findings_dir, filename)
        try:
            with open(filepath) as f:
                data = json.load(f)
            findings = data.get("findings", [])
            if findings:
                log(f"Loaded {len(findings)} findings from {filename}")
                all_findings.extend(findings)
        except (json.JSONDecodeError, IOError) as e:
            warn(f"Failed to load {filename}: {e}")

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="API Security Report Generator - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON file or directory with findings")
    parser.add_argument("--output", "-o", help="Output JSON report file")
    parser.add_argument("--token", help="(unused, for CLI consistency)")
    parser.add_argument("--cookie", help="(unused, for CLI consistency)")
    parser.add_argument("--delay", type=float, default=0, help="(unused, for CLI consistency)")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Output format")
    args = parser.parse_args()

    if not args.input:
        parser.error("--input is required (JSON file or directory)")

    log(f"Loading findings from: {args.input}")
    all_findings = load_findings_from_dir(args.input)

    if not all_findings:
        warn("No findings loaded. Nothing to report.")
        return

    log(f"Processing {len(all_findings)} findings...")

    # Generate per-finding reports
    finding_reports = []
    for idx, finding in enumerate(all_findings, 1):
        report = generate_finding_report(finding, idx)
        finding_reports.append(report)

    # Statistics
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    owasp_counts = {}
    type_counts = {}

    for report in finding_reports:
        sev = report.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        owasp_id = report["owasp_mapping"]["id"]
        owasp_counts[owasp_id] = owasp_counts.get(owasp_id, 0) + 1

        ftype = report["type"]
        type_counts[ftype] = type_counts.get(ftype, 0) + 1

    # Determine overall risk
    if severity_counts["critical"] > 0:
        overall_risk = "CRITICAL"
    elif severity_counts["high"] > 0:
        overall_risk = "HIGH"
    elif severity_counts["medium"] > 0:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "api_security_report",
            "tool": "api-breaker by orizon.one",
            "findings_source": args.input,
        },
        "executive_summary": {
            "overall_risk": overall_risk,
            "total_findings": len(finding_reports),
            "severity_distribution": severity_counts,
            "owasp_coverage": owasp_counts,
            "finding_types": type_counts,
        },
        "owasp_api_top10_mapping": {
            owasp_id: {
                "name": OWASP_API_TOP10[owasp_id.replace(":2023", "")]["name"],
                "findings_count": count,
            }
            for owasp_id, count in sorted(owasp_counts.items())
        },
        "findings": finding_reports,
    }

    output_path = args.output or "api_security_report.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Report saved to: {output_path}")

    # Print text summary
    print(f"\n{'='*60}")
    print(f"  API SECURITY REPORT")
    print(f"{'='*60}")
    print(f"  Overall Risk        : {overall_risk}")
    print(f"  Total Findings      : {len(finding_reports)}")
    print(f"  Critical            : {severity_counts['critical']}")
    print(f"  High                : {severity_counts['high']}")
    print(f"  Medium              : {severity_counts['medium']}")
    print(f"  Low/Info            : {severity_counts['low'] + severity_counts['info']}")
    print(f"{'='*60}")
    print(f"  OWASP API Top 10 Coverage:")
    for owasp_id, count in sorted(owasp_counts.items()):
        key = owasp_id.replace(":2023", "")
        name = OWASP_API_TOP10.get(key, {}).get("name", "Unknown")
        print(f"    {owasp_id} - {name}: {count} findings")
    print(f"{'='*60}")

    if args.format == "text":
        print(f"\n{'='*60}")
        print("  DETAILED FINDINGS")
        print(f"{'='*60}")
        for report in finding_reports:
            print(f"\n--- {report['finding_id']}: {report['title']} ---")
            print(f"  Severity: {report['severity'].upper()}")
            print(f"  OWASP: {report['owasp_mapping']['id']} - {report['owasp_mapping']['name']}")
            print(f"  Endpoint: {report['affected_endpoint']['method']} {report['affected_endpoint']['url']}")
            print(f"  Impact: {report['impact']}")
            print(f"  Remediation: {report['remediation']}")
            print(f"  Curl: {report['curl_command']}")

    print()


if __name__ == "__main__":
    main()
