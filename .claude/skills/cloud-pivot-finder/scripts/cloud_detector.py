#!/usr/bin/env python3
"""
Cloud Provider Detector - cloud-pivot-finder
Identifies cloud hosting from domain analysis.
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


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


# Cloud service CNAME patterns
CNAME_PATTERNS = {
    "AWS S3": [r"\.s3[-.].*\.amazonaws\.com", r"\.s3\.amazonaws\.com"],
    "AWS CloudFront": [r"\.cloudfront\.net"],
    "AWS ELB": [r"\.elb\.amazonaws\.com"],
    "AWS Elastic Beanstalk": [r"\.elasticbeanstalk\.com"],
    "AWS API Gateway": [r"\.execute-api\..*\.amazonaws\.com"],
    "AWS Lambda URL": [r"\.lambda-url\..*\.on\.aws"],
    "AWS Amplify": [r"\.amplifyapp\.com"],
    "GCP Storage": [r"\.storage\.googleapis\.com"],
    "GCP App Engine": [r"\.appspot\.com"],
    "GCP Cloud Run": [r"\.run\.app"],
    "GCP Cloud Functions": [r"\.cloudfunctions\.net"],
    "GCP Firebase": [r"\.firebaseapp\.com", r"\.web\.app"],
    "Azure Websites": [r"\.azurewebsites\.net"],
    "Azure CDN": [r"\.azureedge\.net"],
    "Azure Traffic Manager": [r"\.trafficmanager\.net"],
    "Azure Blob Storage": [r"\.blob\.core\.windows\.net"],
    "Azure Front Door": [r"\.azurefd\.net"],
    "Heroku": [r"\.herokuapp\.com", r"\.herokudns\.com"],
    "Netlify": [r"\.netlify\.app", r"\.netlify\.com"],
    "Vercel": [r"\.vercel\.app", r"\.now\.sh"],
    "GitHub Pages": [r"\.github\.io"],
    "Cloudflare Pages": [r"\.pages\.dev"],
    "Fastly": [r"\.fastly\.net", r"\.fastlylb\.net"],
    "DigitalOcean Spaces": [r"\.digitaloceanspaces\.com"],
    "DigitalOcean App": [r"\.ondigitalocean\.app"],
}

# Response header patterns
HEADER_PATTERNS = {
    "AWS": ["x-amz-", "x-amzn-", "AmazonS3", "awselb", "cloudfront"],
    "GCP": ["x-guploader-", "x-goog-", "x-cloud-trace", "google"],
    "Azure": ["x-ms-", "x-azure-", "windows-azure", "microsoft"],
    "Cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
    "Fastly": ["x-fastly-", "fastly", "x-served-by"],
    "Akamai": ["x-akamai-", "akamai"],
}


def resolve_cname(hostname):
    """Get CNAME record for a hostname."""
    try:
        result = subprocess.run(
            ["dig", "CNAME", hostname, "+short"],
            capture_output=True, text=True, timeout=5
        )
        cname = result.stdout.strip().rstrip(".")
        return cname if cname else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def resolve_ip(hostname):
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def detect_from_cname(hostname):
    """Detect cloud provider from CNAME chain."""
    findings = []
    cname = resolve_cname(hostname)
    seen = set()

    while cname and cname not in seen:
        seen.add(cname)
        for service, patterns in CNAME_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, cname, re.IGNORECASE):
                    findings.append({
                        "type": "cname",
                        "hostname": hostname,
                        "cname": cname,
                        "service": service,
                    })
        # Follow CNAME chain
        next_cname = resolve_cname(cname)
        if next_cname == cname:
            break
        cname = next_cname

    return findings


def detect_from_headers(hostname):
    """Detect cloud provider from HTTP response headers."""
    findings = []

    for scheme in ["https", "http"]:
        url = f"{scheme}://{hostname}/"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                headers = dict(resp.headers)
                headers_str = json.dumps(headers).lower()

                for provider, patterns in HEADER_PATTERNS.items():
                    for pattern in patterns:
                        if pattern.lower() in headers_str:
                            findings.append({
                                "type": "header",
                                "hostname": hostname,
                                "provider": provider,
                                "header_match": pattern,
                            })
                            break
                break
        except Exception:
            continue

    return findings


def detect_from_ip_whois(ip):
    """Check IP ownership for cloud provider."""
    if not ip:
        return None

    try:
        result = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=10
        )
        output = result.stdout.lower()

        if "amazon" in output or "aws" in output:
            return "AWS"
        elif "google" in output or "gcp" in output:
            return "GCP"
        elif "microsoft" in output or "azure" in output:
            return "Azure"
        elif "digitalocean" in output:
            return "DigitalOcean"
        elif "hetzner" in output:
            return "Hetzner"
        elif "ovh" in output:
            return "OVH"
        elif "linode" in output or "akamai" in output:
            return "Akamai/Linode"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def analyze_host(hostname):
    """Full cloud detection analysis on a single host."""
    result = {
        "hostname": hostname,
        "ip": resolve_ip(hostname),
        "cloud_services": [],
        "providers_detected": set(),
    }

    # CNAME analysis
    cname_findings = detect_from_cname(hostname)
    for f in cname_findings:
        result["cloud_services"].append(f)
        provider = f["service"].split()[0]  # First word is usually the provider
        result["providers_detected"].add(provider)

    # Header analysis
    header_findings = detect_from_headers(hostname)
    for f in header_findings:
        result["cloud_services"].append(f)
        result["providers_detected"].add(f["provider"])

    # IP whois
    if result["ip"]:
        ip_provider = detect_from_ip_whois(result["ip"])
        if ip_provider:
            result["providers_detected"].add(ip_provider)
            result["cloud_services"].append({
                "type": "ip_whois",
                "ip": result["ip"],
                "provider": ip_provider,
            })

    result["providers_detected"] = sorted(result["providers_detected"])
    return result


def _extract_hosts_from_json(data):
    """Extract hostnames from various recon JSON formats.

    Supported formats:
      - consolidated.json: {"subdomains": [{"host": ...}, ...], "results": [...]}
      - passive_recon_*.json: {"subdomains": [...], "hosts": [...]}
      - active_recon_*.json: {"results": [{"host": ...}, ...], "hosts": [...]}
      - port_scan_results.json: {"hosts": [{"ip": ..., "hostname": ...}, ...], "results": {...}}
      - Simple list: ["host1", "host2", ...]
      - Dict with domain keys: {"example.com": {...}, ...}
    """
    hosts = []

    if isinstance(data, list):
        # Plain list of strings or dicts
        for item in data:
            if isinstance(item, str):
                hosts.append(item)
            elif isinstance(item, dict):
                for key in ("host", "hostname", "domain", "name", "subdomain", "target"):
                    if key in item and isinstance(item[key], str):
                        hosts.append(item[key])
                        break
        return hosts

    if not isinstance(data, dict):
        return hosts

    # consolidated.json / passive_recon / active_recon: "subdomains" key
    if "subdomains" in data:
        subs = data["subdomains"]
        if isinstance(subs, list):
            for item in subs:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "name", "subdomain"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break

    # "results" key (active_recon, consolidated)
    if "results" in data:
        results = data["results"]
        if isinstance(results, list):
            for item in results:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "name", "target"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break
        elif isinstance(results, dict):
            # port_scan_results format: {"results": {"host_ip": {data}}}
            for key in results:
                if isinstance(results[key], dict):
                    inner = results[key]
                    for hk in ("hostname", "host", "domain"):
                        if hk in inner and isinstance(inner[hk], str):
                            hosts.append(inner[hk])
                            break
                    else:
                        # Use the key itself if it looks like a hostname
                        if not key.replace(".", "").isdigit():
                            hosts.append(key)

    # "hosts" key (passive_recon, port_scan_results)
    if "hosts" in data:
        h_list = data["hosts"]
        if isinstance(h_list, list):
            for item in h_list:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("hostname", "host", "domain", "ip", "name", "target"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break

    # "domains" key
    if "domains" in data:
        d_list = data["domains"]
        if isinstance(d_list, list):
            for item in d_list:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "name"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break

    # "targets" key
    if "targets" in data:
        t_list = data["targets"]
        if isinstance(t_list, list):
            for item in t_list:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "target"):
                        if key in item and isinstance(item[key], str):
                            hosts.append(item[key])
                            break

    return hosts


def main():
    parser = argparse.ArgumentParser(description="Cloud Detector - orizon.one")
    parser.add_argument("--domain", "-d", help="Single domain to analyze")
    parser.add_argument("--input", "-i", help="File with hostnames (one per line) or recon JSON")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--threads", type=int, default=10)
    args = parser.parse_args()

    log("Starting cloud provider detection...")

    hosts = []
    if args.domain:
        hosts = [args.domain.strip().lower()]

    if args.input:
        input_path = Path(args.input)
        if input_path.suffix == ".json":
            with open(input_path) as f:
                data = json.load(f)
            hosts.extend(_extract_hosts_from_json(data))
        else:
            hosts.extend([h.strip() for h in input_path.read_text().strip().split("\n") if h.strip()])

    # Deduplicate while preserving order
    seen = set()
    unique_hosts = []
    for h in hosts:
        h_lower = h.lower().strip()
        if h_lower and h_lower not in seen:
            seen.add(h_lower)
            unique_hosts.append(h_lower)
    hosts = unique_hosts

    log(f"Analyzing {len(hosts)} host(s)...")

    results = []
    provider_summary = {}

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(analyze_host, host): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            for provider in result["providers_detected"]:
                provider_summary[provider] = provider_summary.get(provider, 0) + 1
            if result["providers_detected"]:
                success(f"{result['hostname']}: {', '.join(result['providers_detected'])}")

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "cloud_detection",
            "tool": "cloud-pivot-finder by orizon.one",
            "hosts_analyzed": len(hosts),
        },
        "provider_summary": provider_summary,
        "results": results,
    }

    domain = args.domain or "multi"
    output_path = args.output or f"cloud_detection_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=list)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  CLOUD DETECTION SUMMARY")
    print(f"{'='*60}")
    print(f"  Hosts analyzed: {len(hosts)}")
    print(f"  Cloud-hosted  : {sum(1 for r in results if r['providers_detected'])}")
    print(f"\n  Providers:")
    for provider, count in sorted(provider_summary.items(), key=lambda x: -x[1]):
        print(f"    {provider:25s} : {count} hosts")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
