#!/usr/bin/env python3
"""
OSINT Correlation Module - recon-dominator
Gathers WHOIS, ASN, reverse IP, and public intelligence.
Author: orizon.one
"""

import argparse
import json
import socket
import subprocess
import ssl
import urllib.request
import urllib.parse
import re
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def success(msg):
    print(f"[+] {msg}")


def http_get(url, timeout=15):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        warn(f"Request failed: {url} - {e}")
        return None


def whois_lookup(domain):
    """Perform WHOIS lookup."""
    log(f"Running WHOIS lookup for {domain}...")
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            raw = result.stdout
            info = {}

            patterns = {
                "registrar": r"Registrar:\s*(.+)",
                "creation_date": r"Creation Date:\s*(.+)",
                "expiry_date": r"Expir.*Date:\s*(.+)",
                "updated_date": r"Updated Date:\s*(.+)",
                "registrant_org": r"Registrant Organization:\s*(.+)",
                "registrant_country": r"Registrant Country:\s*(.+)",
                "name_servers": r"Name Server:\s*(.+)",
                "dnssec": r"DNSSEC:\s*(.+)",
            }

            for key, pattern in patterns.items():
                matches = re.findall(pattern, raw, re.IGNORECASE)
                if matches:
                    if key == "name_servers":
                        info[key] = [m.strip().lower() for m in matches]
                    else:
                        info[key] = matches[0].strip()

            info["raw"] = raw[:2000]
            success(f"WHOIS data collected for {domain}")
            return info
        return {}
    except FileNotFoundError:
        warn("whois command not found")
        return {}
    except subprocess.TimeoutExpired:
        warn("WHOIS lookup timed out")
        return {}


def get_dns_records(domain):
    """Get various DNS record types."""
    log(f"Collecting DNS records for {domain}...")
    records = {}
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV"]

    for rtype in record_types:
        try:
            result = subprocess.run(
                ["dig", rtype, domain, "+short"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                records[rtype] = [line.strip() for line in result.stdout.strip().split("\n")]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Check for SPF, DMARC, DKIM
    for special in [("_dmarc", "DMARC"), ("_domainkey", "DKIM")]:
        try:
            result = subprocess.run(
                ["dig", "TXT", f"{special[0]}.{domain}", "+short"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                records[special[1]] = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Extract SPF from TXT records
    if "TXT" in records:
        for txt in records["TXT"]:
            if "v=spf1" in txt:
                records["SPF"] = txt

    success(f"Collected {len(records)} DNS record types")
    return records


def resolve_to_ip(domain):
    """Resolve domain to IP."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def reverse_ip_lookup(ip):
    """Find other domains on the same IP."""
    log(f"Running reverse IP lookup on {ip}...")
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    data = http_get(url)
    if not data or "error" in data.lower() or "API count" in data:
        return []
    domains = [line.strip() for line in data.strip().split("\n") if line.strip()]
    success(f"Reverse IP: {len(domains)} domains found on {ip}")
    return domains


def get_asn_info(ip):
    """Get ASN information for an IP."""
    log(f"Looking up ASN for {ip}...")

    # Using ip-api.com (free, no key needed)
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query"
    data = http_get(url)
    if not data:
        return {}
    try:
        info = json.loads(data)
        if info.get("status") == "success":
            success(f"ASN: {info.get('as', 'unknown')} ({info.get('org', 'unknown')})")
            return info
    except json.JSONDecodeError:
        pass
    return {}


def search_github_dorks(domain):
    """Generate GitHub dork URLs for manual review."""
    log(f"Generating GitHub dork URLs for {domain}...")

    dorks = [
        f'"{domain}" password',
        f'"{domain}" api_key',
        f'"{domain}" secret',
        f'"{domain}" token',
        f'"{domain}" credentials',
        f'"{domain}" config',
        f'"{domain}" database_url',
        f'"{domain}" AWS_SECRET',
        f'"{domain}" PRIVATE_KEY',
        f'"{domain}" .env',
    ]

    urls = []
    for dork in dorks:
        search_url = f"https://github.com/search?q={urllib.parse.quote(dork)}&type=code"
        urls.append({"query": dork, "url": search_url})

    success(f"Generated {len(urls)} GitHub dork URLs")
    return urls


def check_email_patterns(domain):
    """Detect common email patterns from MX records."""
    log(f"Analyzing email configuration for {domain}...")
    result = {}

    try:
        mx_result = subprocess.run(
            ["dig", "MX", domain, "+short"],
            capture_output=True, text=True, timeout=10
        )
        mx_records = mx_result.stdout.strip()
        if mx_records:
            result["mx_records"] = mx_records.split("\n")

            mx_lower = mx_records.lower()
            if "google" in mx_lower or "gmail" in mx_lower:
                result["email_provider"] = "Google Workspace"
            elif "outlook" in mx_lower or "microsoft" in mx_lower:
                result["email_provider"] = "Microsoft 365"
            elif "protonmail" in mx_lower:
                result["email_provider"] = "ProtonMail"
            elif "zoho" in mx_lower:
                result["email_provider"] = "Zoho"
            elif "mimecast" in mx_lower:
                result["email_provider"] = "Mimecast"
            elif "barracuda" in mx_lower:
                result["email_provider"] = "Barracuda"
            else:
                result["email_provider"] = "Custom/Self-hosted"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return result


def main():
    parser = argparse.ArgumentParser(description="OSINT Correlator - orizon.one")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    log(f"Starting OSINT correlation on: {domain}")
    log(f"Timestamp: {datetime.utcnow().isoformat()}Z")

    # Collect all intelligence
    ip = resolve_to_ip(domain)
    whois_data = whois_lookup(domain)
    dns_records = get_dns_records(domain)
    asn_info = get_asn_info(ip) if ip else {}
    reverse_domains = reverse_ip_lookup(ip) if ip else []
    github_dorks = search_github_dorks(domain)
    email_info = check_email_patterns(domain)

    output = {
        "meta": {
            "domain": domain,
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "osint_correlation",
            "tool": "recon-dominator by orizon.one"
        },
        "whois": whois_data,
        "dns_records": dns_records,
        "asn": asn_info,
        "reverse_ip": {
            "ip": ip,
            "shared_domains": reverse_domains,
            "count": len(reverse_domains)
        },
        "email": email_info,
        "github_dorks": github_dorks,
    }

    output_path = args.output or f"osint_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  OSINT CORRELATION SUMMARY - {domain}")
    print(f"{'='*60}")
    print(f"  IP Address    : {ip or 'unresolved'}")
    print(f"  ASN           : {asn_info.get('as', 'unknown')}")
    print(f"  Organization  : {asn_info.get('org', 'unknown')}")
    print(f"  Registrar     : {whois_data.get('registrar', 'unknown')}")
    print(f"  Created       : {whois_data.get('creation_date', 'unknown')}")
    print(f"  Email provider: {email_info.get('email_provider', 'unknown')}")
    print(f"  Shared hosting: {len(reverse_domains)} domains on same IP")
    print(f"  DNS records   : {len(dns_records)} types collected")
    print(f"  GitHub dorks  : {len(github_dorks)} search URLs generated")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
