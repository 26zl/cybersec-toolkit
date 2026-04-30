#!/usr/bin/env python3
"""
Asset Classifier - attack-path-architect
Classifies discovered assets by type, exposure, and risk score.
Author: orizon.one
"""

import argparse
import json
import re
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


# Technology -> known risk indicators
TECH_RISK_SCORES = {
    "WordPress": 3, "Drupal": 3, "Joomla": 4, "phpMyAdmin": 5,
    "Jenkins": 4, "GitLab": 3, "Grafana": 3, "Kibana": 3,
    "Apache": 2, "Nginx": 1, "IIS": 3, "Tomcat": 3,
    "PHP": 2, "ASP.NET": 2, "Java Servlet": 2,
    "GraphQL": 2, "Swagger/OpenAPI": 2,
    "MinIO": 3, "Redis": 4, "MongoDB": 4,
    "Express.js": 1, "Django": 1, "Flask": 2,
    "Spring": 2, "Ruby on Rails": 2, "Laravel": 2,
    "jQuery": 1, "React": 0, "Vue.js": 0, "Angular": 0,
}

# Port -> service type mapping
PORT_SERVICE_MAP = {
    21: ("FTP", "LEGACY"),
    22: ("SSH", "INFRASTRUCTURE"),
    23: ("Telnet", "LEGACY"),
    25: ("SMTP", "MAIL"),
    53: ("DNS", "DNS"),
    80: ("HTTP", "WEB_APP"),
    110: ("POP3", "MAIL"),
    143: ("IMAP", "MAIL"),
    443: ("HTTPS", "WEB_APP"),
    445: ("SMB", "INFRASTRUCTURE"),
    993: ("IMAPS", "MAIL"),
    995: ("POP3S", "MAIL"),
    1433: ("MSSQL", "DATABASE"),
    1521: ("Oracle", "DATABASE"),
    3306: ("MySQL", "DATABASE"),
    3389: ("RDP", "INFRASTRUCTURE"),
    5432: ("PostgreSQL", "DATABASE"),
    5900: ("VNC", "INFRASTRUCTURE"),
    6379: ("Redis", "DATABASE"),
    6443: ("Kubernetes API", "CI_CD"),
    8080: ("HTTP-Alt", "WEB_APP"),
    8443: ("HTTPS-Alt", "WEB_APP"),
    9090: ("Prometheus", "MONITORING"),
    9200: ("Elasticsearch", "DATABASE"),
    9300: ("Elasticsearch", "DATABASE"),
    10250: ("Kubelet", "CI_CD"),
    27017: ("MongoDB", "DATABASE"),
}

# Subdomain patterns -> asset type
SUBDOMAIN_PATTERNS = {
    r"^(api|rest|graphql|ws)": "API",
    r"^(mail|smtp|imap|pop|mx|webmail|autodiscover)": "MAIL",
    r"^(ns\d*|dns)": "DNS",
    r"^(vpn|openvpn|wireguard|ipsec|remote)": "VPN",
    r"^(db|database|mysql|postgres|mongo|redis|elastic)": "DATABASE",
    r"^(admin|panel|dashboard|console|manage|cpanel)": "ADMIN_PANEL",
    r"^(jenkins|gitlab|ci|cd|deploy|build|bamboo|travis|circleci|registry|docker|k8s|kube)": "CI_CD",
    r"^(grafana|kibana|prometheus|nagios|zabbix|monitor|sentry|status)": "MONITORING",
    r"^(s3|storage|bucket|blob|cdn|static|assets|media|files)": "STORAGE",
    r"^(old|legacy|archive|bak|backup|v1|deprecated)": "LEGACY",
    r"^(dev|test|staging|stage|qa|uat|sandbox|demo|beta|alpha|canary)": "WEB_APP",
}


def classify_by_subdomain(hostname, domain):
    """Classify asset type based on subdomain name."""
    subdomain = hostname.replace(f".{domain}", "").lower()

    for pattern, asset_type in SUBDOMAIN_PATTERNS.items():
        if re.match(pattern, subdomain):
            return asset_type

    return "WEB_APP"  # Default


def classify_by_ports(open_ports):
    """Classify based on open ports."""
    types = set()
    services = []

    for port_info in open_ports:
        port = port_info.get("port", 0)
        if port in PORT_SERVICE_MAP:
            service_name, service_type = PORT_SERVICE_MAP[port]
            types.add(service_type)
            services.append({"port": port, "service": service_name, "type": service_type})

    return types, services


def calculate_risk_score(asset):
    """Calculate risk score (1-10) for an asset."""
    score = 0
    reasons = []

    # Technology-based risk
    for tech in asset.get("technologies", []):
        if tech in TECH_RISK_SCORES:
            tech_score = TECH_RISK_SCORES[tech]
            score += tech_score
            if tech_score >= 3:
                reasons.append(f"High-risk technology: {tech}")

    # Exposure-based risk
    exposure = asset.get("exposure", "EXTERNAL")
    if exposure == "EXTERNAL":
        score += 2
        reasons.append("Directly internet-facing")
    elif exposure == "INTERNAL-EXPOSED":
        score += 3
        reasons.append("Internal service exposed externally")

    # Port-based risk
    dangerous_ports = [21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017]
    for port_info in asset.get("open_ports", []):
        if port_info.get("port") in dangerous_ports:
            score += 2
            reasons.append(f"Dangerous port exposed: {port_info['port']}")

    # Missing security headers
    missing_headers = asset.get("missing_security_headers", [])
    if len(missing_headers) >= 5:
        score += 2
        reasons.append(f"Missing {len(missing_headers)} security headers")
    elif len(missing_headers) >= 3:
        score += 1

    # Admin panel / sensitive service
    asset_type = asset.get("asset_type", "")
    if asset_type == "ADMIN_PANEL":
        score += 3
        reasons.append("Exposed admin panel")
    elif asset_type == "DATABASE":
        score += 3
        reasons.append("Exposed database service")
    elif asset_type == "CI_CD":
        score += 2
        reasons.append("Exposed CI/CD infrastructure")
    elif asset_type == "LEGACY":
        score += 2
        reasons.append("Legacy/deprecated system")

    # WAF detection
    waf = asset.get("waf_cdn", "none_detected")
    if waf == "none_detected":
        score += 1
        reasons.append("No WAF detected")

    # Normalize to 1-10
    score = min(max(score, 1), 10)

    return score, reasons


def determine_exposure(asset, waf_cdn="none_detected"):
    """Determine exposure level of an asset."""
    if waf_cdn and waf_cdn not in ["none_detected", "none", "unknown", ""]:
        return "SEMI-EXTERNAL"

    # Check for internal-looking subdomains exposed externally
    internal_patterns = [
        "internal", "intranet", "private", "corp", "local",
        "dev", "staging", "test", "debug"
    ]
    hostname = asset.get("host", "").lower()
    for pattern in internal_patterns:
        if pattern in hostname:
            return "INTERNAL-EXPOSED"

    return "EXTERNAL"


def classify_assets(recon_data):
    """Main classification logic."""
    assets = []

    # Extract domain
    domain = ""
    for key in ["passive_recon", "active_recon", "osint"]:
        if key in recon_data.get("data", recon_data):
            src = recon_data.get("data", recon_data).get(key, {})
            domain = src.get("meta", {}).get("domain", "")
            if domain:
                break

    data = recon_data.get("data", recon_data)

    # Build host map from port scan results
    host_map = {}
    port_data = data.get("port_scan", {})
    for result in port_data.get("results", []):
        host = result.get("host", "")
        host_map[host] = {
            "host": host,
            "ip": result.get("ip", ""),
            "open_ports": result.get("open_ports", []),
            "http": result.get("http"),
            "https": result.get("https"),
            "waf_cdn": result.get("waf_cdn", "none_detected"),
        }

    # Merge tech fingerprint data
    tech_data = data.get("tech_fingerprint", {})
    for result in tech_data.get("results", []):
        host = result.get("host", "")
        if host in host_map:
            host_map[host]["technologies"] = result.get("technologies", [])
            details = result.get("details", {})
            host_map[host]["missing_security_headers"] = details.get("missing_security_headers", [])
        else:
            host_map[host] = {
                "host": host,
                "technologies": result.get("technologies", []),
                "missing_security_headers": details.get("missing_security_headers", []) if "details" in result else [],
                "open_ports": [],
            }

    # Add subdomains without port/tech data
    for source in ["passive_recon", "active_recon"]:
        src_data = data.get(source, {})
        for sub in src_data.get("subdomains", []):
            host = sub.get("host", "")
            if host and host not in host_map:
                host_map[host] = {
                    "host": host,
                    "ips": sub.get("ips", []),
                    "open_ports": [],
                    "technologies": [],
                }

    # Classify each host
    for host, info in host_map.items():
        # Determine asset type
        port_types, services = classify_by_ports(info.get("open_ports", []))
        subdomain_type = classify_by_subdomain(host, domain)

        # Port-based type takes priority if it's specific
        if port_types - {"WEB_APP", "INFRASTRUCTURE"}:
            primary_type = next(iter(port_types - {"WEB_APP", "INFRASTRUCTURE"}))
        elif port_types:
            primary_type = next(iter(port_types))
        else:
            primary_type = subdomain_type

        # Determine exposure
        exposure = determine_exposure(info, info.get("waf_cdn"))

        asset = {
            "host": host,
            "ip": info.get("ip", ""),
            "asset_type": primary_type,
            "all_types": sorted(port_types | {subdomain_type}),
            "exposure": exposure,
            "open_ports": info.get("open_ports", []),
            "services": services,
            "technologies": info.get("technologies", []),
            "waf_cdn": info.get("waf_cdn", ""),
            "missing_security_headers": info.get("missing_security_headers", []),
        }

        risk_score, risk_reasons = calculate_risk_score(asset)
        asset["risk_score"] = risk_score
        asset["risk_reasons"] = risk_reasons

        assets.append(asset)

    # Sort by risk score descending
    assets.sort(key=lambda x: x["risk_score"], reverse=True)

    return assets


def main():
    parser = argparse.ArgumentParser(description="Asset Classifier - orizon.one")
    parser.add_argument("--input", "-i", required=True, help="Consolidated recon JSON or directory")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    log("Starting asset classification...")

    with open(args.input) as f:
        recon_data = json.load(f)

    assets = classify_assets(recon_data)

    # Stats
    type_counts = {}
    exposure_counts = {}
    for a in assets:
        t = a["asset_type"]
        e = a["exposure"]
        type_counts[t] = type_counts.get(t, 0) + 1
        exposure_counts[e] = exposure_counts.get(e, 0) + 1

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "asset_classification",
            "tool": "attack-path-architect by orizon.one",
            "total_assets": len(assets),
        },
        "summary": {
            "by_type": type_counts,
            "by_exposure": exposure_counts,
            "high_risk": len([a for a in assets if a["risk_score"] >= 7]),
            "medium_risk": len([a for a in assets if 4 <= a["risk_score"] < 7]),
            "low_risk": len([a for a in assets if a["risk_score"] < 4]),
        },
        "assets": assets
    }

    output_path = args.output or "classified_assets.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  ASSET CLASSIFICATION SUMMARY")
    print(f"{'='*60}")
    print(f"  Total assets: {len(assets)}")
    print(f"")
    print(f"  By Type:")
    for t, c in sorted(type_counts.items()):
        print(f"    {t:25s} : {c}")
    print(f"")
    print(f"  By Exposure:")
    for e, c in sorted(exposure_counts.items()):
        print(f"    {e:25s} : {c}")
    print(f"")
    print(f"  Risk Distribution:")
    print(f"    HIGH (7-10)  : {output['summary']['high_risk']}")
    print(f"    MEDIUM (4-6) : {output['summary']['medium_risk']}")
    print(f"    LOW (1-3)    : {output['summary']['low_risk']}")
    print(f"{'='*60}")

    if assets:
        print(f"\n  Top 5 Highest Risk Assets:")
        for a in assets[:5]:
            print(f"    [{a['risk_score']:2d}] {a['host']} ({a['asset_type']}, {a['exposure']})")
            for reason in a["risk_reasons"][:3]:
                print(f"         - {reason}")
    print()


if __name__ == "__main__":
    main()
