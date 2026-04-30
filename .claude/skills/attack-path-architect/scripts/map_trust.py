#!/usr/bin/env python3
"""
Trust Relationship Mapper - attack-path-architect
Maps trust relationships between assets for attack chaining.
Author: orizon.one
"""

import argparse
import json
import re
import socket
import subprocess
import ssl
import urllib.request
from pathlib import Path
from datetime import datetime
from collections import defaultdict


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def http_get_headers(url, timeout=5):
    """Get HTTP headers from a URL."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return dict(resp.headers)
    except Exception:
        return {}


def check_cookie_scope(assets, domain):
    """Detect wildcard cookie scopes across subdomains."""
    log("Checking cookie scopes...")
    relationships = []

    for asset in assets:
        host = asset.get("host", "")
        for scheme in ["https", "http"]:
            headers = http_get_headers(f"{scheme}://{host}/")
            if not headers:
                continue

            cookies = headers.get("Set-Cookie", "")
            if not cookies:
                continue

            # Check for domain-wide cookies
            if f".{domain}" in cookies or f"domain={domain}" in cookies.lower():
                relationships.append({
                    "type": "SHARED_COOKIE_SCOPE",
                    "source": host,
                    "scope": f".{domain}",
                    "detail": f"Cookie scoped to .{domain} - session sharing possible across all subdomains",
                    "risk": "HIGH",
                    "attack_implication": "XSS on any subdomain can steal sessions valid on all subdomains"
                })
            break

    return relationships


def check_ip_proximity(assets):
    """Identify assets sharing IPs or subnets."""
    log("Checking IP proximity...")
    relationships = []

    ip_to_hosts = defaultdict(list)
    subnet_to_hosts = defaultdict(list)

    for asset in assets:
        ip = asset.get("ip", "")
        if not ip:
            continue
        ip_to_hosts[ip].append(asset["host"])
        # /24 subnet
        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        subnet_to_hosts[subnet].append(asset["host"])

    # Same IP
    for ip, hosts in ip_to_hosts.items():
        if len(hosts) > 1:
            relationships.append({
                "type": "SHARED_IP",
                "hosts": hosts,
                "ip": ip,
                "detail": f"{len(hosts)} assets on same IP - likely same server",
                "risk": "MEDIUM",
                "attack_implication": "Compromise of one may give access to all co-hosted services"
            })

    # Same subnet
    for subnet, hosts in subnet_to_hosts.items():
        if len(hosts) > 2:
            relationships.append({
                "type": "SAME_SUBNET",
                "hosts": hosts,
                "subnet": subnet,
                "detail": f"{len(hosts)} assets in same /24 subnet",
                "risk": "LOW",
                "attack_implication": "Network-level lateral movement possible after initial foothold"
            })

    return relationships


def check_dns_relationships(assets, domain):
    """Identify DNS-based trust relationships (CNAMEs, shared NS)."""
    log("Checking DNS relationships...")
    relationships = []

    cname_targets = defaultdict(list)

    for asset in assets:
        host = asset.get("host", "")
        try:
            result = subprocess.run(
                ["dig", "CNAME", host, "+short"],
                capture_output=True, text=True, timeout=5
            )
            cname = result.stdout.strip().rstrip(".")
            if cname and cname != host:
                cname_targets[cname].append(host)

                # Check for dangling CNAMEs (subdomain takeover)
                try:
                    socket.gethostbyname(cname)
                except socket.gaierror:
                    relationships.append({
                        "type": "DANGLING_CNAME",
                        "source": host,
                        "target": cname,
                        "detail": f"CNAME points to {cname} which does not resolve",
                        "risk": "CRITICAL",
                        "attack_implication": "Potential subdomain takeover - register the target to hijack traffic"
                    })

                # CNAME to external service
                if domain not in cname:
                    relationships.append({
                        "type": "EXTERNAL_CNAME",
                        "source": host,
                        "target": cname,
                        "detail": f"Points to external service: {cname}",
                        "risk": "LOW",
                        "attack_implication": "Trust dependency on external service"
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Multiple hosts pointing to same CNAME target
    for target, sources in cname_targets.items():
        if len(sources) > 1:
            relationships.append({
                "type": "SHARED_CNAME_TARGET",
                "sources": sources,
                "target": target,
                "detail": f"{len(sources)} subdomains resolve to same target",
                "risk": "LOW",
                "attack_implication": "Shared backend infrastructure"
            })

    return relationships


def check_certificate_sharing(assets):
    """Check for shared TLS certificates (SAN entries)."""
    log("Checking TLS certificate sharing...")
    relationships = []

    cert_hosts = defaultdict(list)

    for asset in assets:
        host = asset.get("host", "")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Extract SAN entries
                        san_entries = []
                        for entry_type, entry_value in cert.get("subjectAltName", []):
                            if entry_type == "DNS":
                                san_entries.append(entry_value)

                        # Use certificate serial as grouping key
                        serial = cert.get("serialNumber", "")
                        if serial:
                            cert_hosts[serial].extend(san_entries)
        except Exception:
            pass

    for serial, hosts in cert_hosts.items():
        unique_hosts = sorted(set(hosts))
        if len(unique_hosts) > 1:
            relationships.append({
                "type": "SHARED_CERTIFICATE",
                "hosts": unique_hosts,
                "serial": serial,
                "detail": f"Shared TLS certificate covering {len(unique_hosts)} domains",
                "risk": "LOW",
                "attack_implication": "Confirms organizational relationship between domains"
            })

    return relationships


def detect_sso_patterns(assets):
    """Detect SSO/OAuth patterns from redirect behavior."""
    log("Detecting SSO/authentication patterns...")
    relationships = []

    auth_endpoints = []

    for asset in assets:
        host = asset.get("host", "")
        for scheme in ["https", "http"]:
            headers = http_get_headers(f"{scheme}://{host}/login")
            location = headers.get("Location", "")
            if location:
                # Check if redirect to SSO
                sso_patterns = ["sso.", "auth.", "login.", "id.", "identity.", "accounts.",
                               "oauth", "saml", "cas", "okta", "auth0", "cognito"]
                for pattern in sso_patterns:
                    if pattern in location.lower():
                        auth_endpoints.append({
                            "source": host,
                            "sso_target": location,
                            "pattern": pattern
                        })
                        break
            break

    if auth_endpoints:
        # Group by SSO target
        sso_groups = defaultdict(list)
        for ep in auth_endpoints:
            target_domain = ep["sso_target"].split("/")[2] if "//" in ep["sso_target"] else ep["sso_target"]
            sso_groups[target_domain].append(ep["source"])

        for sso_target, sources in sso_groups.items():
            relationships.append({
                "type": "SHARED_SSO",
                "sso_provider": sso_target,
                "relying_parties": sources,
                "detail": f"{len(sources)} services use same SSO: {sso_target}",
                "risk": "MEDIUM",
                "attack_implication": "Compromising SSO grants access to all relying services. "
                                     "Token theft on one service may work across all."
            })

    return relationships


def build_trust_graph(all_relationships):
    """Build a directed graph representation of trust relationships."""
    nodes = set()
    edges = []

    for rel in all_relationships:
        rel_type = rel["type"]

        if "source" in rel and "target" in rel:
            nodes.add(rel["source"])
            nodes.add(rel["target"])
            edges.append({
                "from": rel["source"],
                "to": rel["target"],
                "type": rel_type,
                "risk": rel["risk"]
            })
        elif "hosts" in rel:
            for host in rel["hosts"]:
                nodes.add(host)
            # Fully connected
            hosts = rel["hosts"]
            for i, h1 in enumerate(hosts):
                for h2 in hosts[i+1:]:
                    edges.append({
                        "from": h1,
                        "to": h2,
                        "type": rel_type,
                        "risk": rel["risk"],
                        "bidirectional": True
                    })

    return {"nodes": sorted(nodes), "edges": edges}


def main():
    parser = argparse.ArgumentParser(description="Trust Relationship Mapper - orizon.one")
    parser.add_argument("--input", "-i", required=True, help="Classified assets JSON or consolidated recon JSON")
    parser.add_argument("--domain", "-d", help="Target domain (auto-detected if not specified)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--skip-tls", action="store_true", help="Skip TLS certificate checks")
    parser.add_argument("--skip-sso", action="store_true", help="Skip SSO detection")
    args = parser.parse_args()

    log("Starting trust relationship mapping...")

    with open(args.input) as f:
        data = json.load(f)

    # Extract assets list
    assets = data.get("assets", [])
    if not assets and "data" in data:
        # Try consolidated format
        port_data = data["data"].get("port_scan", {})
        assets = [{"host": r["host"], "ip": r.get("ip", "")} for r in port_data.get("results", [])]

    domain = args.domain
    if not domain:
        # Auto-detect from data
        domain = data.get("meta", {}).get("domain", "")
        if not domain and assets:
            # Guess from longest common suffix
            hosts = [a["host"] for a in assets]
            if hosts:
                parts = hosts[0].split(".")
                domain = ".".join(parts[-2:]) if len(parts) >= 2 else hosts[0]

    log(f"Domain: {domain}")
    log(f"Assets to analyze: {len(assets)}")

    all_relationships = []

    # Run all checks
    all_relationships.extend(check_cookie_scope(assets[:50], domain))  # Limit to avoid too many requests
    all_relationships.extend(check_ip_proximity(assets))
    all_relationships.extend(check_dns_relationships(assets[:30], domain))

    if not args.skip_tls:
        all_relationships.extend(check_certificate_sharing(assets[:30]))

    if not args.skip_sso:
        all_relationships.extend(detect_sso_patterns(assets[:30]))

    # Build graph
    graph = build_trust_graph(all_relationships)

    # Categorize by risk
    critical = [r for r in all_relationships if r["risk"] == "CRITICAL"]
    high = [r for r in all_relationships if r["risk"] == "HIGH"]
    medium = [r for r in all_relationships if r["risk"] == "MEDIUM"]
    low = [r for r in all_relationships if r["risk"] == "LOW"]

    output = {
        "meta": {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "trust_mapping",
            "tool": "attack-path-architect by orizon.one",
            "total_relationships": len(all_relationships),
        },
        "risk_summary": {
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
        },
        "relationships": all_relationships,
        "graph": graph,
    }

    output_path = args.output or "trust_map.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  TRUST RELATIONSHIP MAP - {domain}")
    print(f"{'='*60}")
    print(f"  Total relationships : {len(all_relationships)}")
    print(f"  CRITICAL            : {len(critical)}")
    print(f"  HIGH                : {len(high)}")
    print(f"  MEDIUM              : {len(medium)}")
    print(f"  LOW                 : {len(low)}")
    print(f"  Graph nodes         : {len(graph['nodes'])}")
    print(f"  Graph edges         : {len(graph['edges'])}")
    print(f"{'='*60}")

    if critical:
        print(f"\n  CRITICAL Findings:")
        for r in critical:
            print(f"    [{r['type']}] {r['detail']}")
            print(f"      Impact: {r['attack_implication']}")
    if high:
        print(f"\n  HIGH Risk Findings:")
        for r in high:
            print(f"    [{r['type']}] {r['detail']}")
            print(f"      Impact: {r['attack_implication']}")
    print()


if __name__ == "__main__":
    main()
