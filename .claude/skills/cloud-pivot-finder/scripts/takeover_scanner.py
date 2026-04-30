#!/usr/bin/env python3
"""
Subdomain Takeover Scanner - cloud-pivot-finder
Checks subdomains for dangling CNAME records that may be claimable.
Author: orizon.one
"""

import argparse
import json
import re
import socket
import ssl
import subprocess
import urllib.request
import urllib.error
import concurrent.futures
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


# Fingerprints: service -> {cname_patterns, response_fingerprints, info}
TAKEOVER_FINGERPRINTS = {
    "AWS S3": {
        "cnames": [r"\.s3[.-].*\.amazonaws\.com", r"\.s3\.amazonaws\.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "impact": "high",
        "method": "Create an S3 bucket with the matching name in any AWS account.",
    },
    "AWS CloudFront": {
        "cnames": [r"\.cloudfront\.net"],
        "fingerprints": ["Bad request", "ERROR: The request could not be satisfied"],
        "impact": "high",
        "method": "Create a CloudFront distribution and add the subdomain as an alternate domain name (CNAME).",
    },
    "AWS Elastic Beanstalk": {
        "cnames": [r"\.elasticbeanstalk\.com"],
        "fingerprints": ["NXDOMAIN"],
        "nxdomain": True,
        "impact": "high",
        "method": "Create an Elastic Beanstalk environment with the matching subdomain prefix.",
    },
    "AWS ELB": {
        "cnames": [r"\.elb\.amazonaws\.com"],
        "fingerprints": ["NXDOMAIN"],
        "nxdomain": True,
        "impact": "medium",
        "method": "Create a load balancer in the same region with a matching DNS name.",
    },
    "Azure Websites": {
        "cnames": [r"\.azurewebsites\.net"],
        "fingerprints": ["404 - Web Site not found", "404 Web Site not found"],
        "impact": "high",
        "method": "Create an Azure App Service with the matching name and add a custom domain.",
    },
    "Azure CDN": {
        "cnames": [r"\.azureedge\.net"],
        "fingerprints": ["<h2>Our services aren't available right now", "404"],
        "impact": "medium",
        "method": "Create an Azure CDN endpoint with the matching name.",
    },
    "Azure Blob Storage": {
        "cnames": [r"\.blob\.core\.windows\.net"],
        "fingerprints": ["BlobNotFound", "The specified blob does not exist", "ContainerNotFound"],
        "nxdomain": True,
        "impact": "medium",
        "method": "Create an Azure Storage account with the matching name.",
    },
    "Azure Traffic Manager": {
        "cnames": [r"\.trafficmanager\.net"],
        "fingerprints": ["NXDOMAIN"],
        "nxdomain": True,
        "impact": "high",
        "method": "Create a Traffic Manager profile with the matching name.",
    },
    "GCP Cloud Storage": {
        "cnames": [r"\.storage\.googleapis\.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "impact": "high",
        "method": "Create a GCS bucket with the matching name.",
    },
    "GCP App Engine": {
        "cnames": [r"\.appspot\.com"],
        "fingerprints": ["Error: Not Found", "The requested URL was not found on this server"],
        "nxdomain": True,
        "impact": "high",
        "method": "Create a GCP project with the matching App Engine application ID.",
    },
    "GCP Firebase": {
        "cnames": [r"\.firebaseapp\.com", r"\.web\.app"],
        "fingerprints": ["Site Not Found", "Firebase Hosting Setup"],
        "impact": "medium",
        "method": "Create a Firebase project with the matching project ID.",
    },
    "Heroku": {
        "cnames": [r"\.herokuapp\.com", r"\.herokudns\.com"],
        "fingerprints": ["No such app", "no-such-app", "herokucdn.com/error-pages/no-such-app"],
        "impact": "high",
        "method": "Create a Heroku app with the matching name and add the subdomain as a custom domain.",
    },
    "GitHub Pages": {
        "cnames": [r"\.github\.io"],
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs"],
        "impact": "high",
        "method": "Create a GitHub repository matching the CNAME target and enable GitHub Pages.",
    },
    "Fastly": {
        "cnames": [r"\.fastly\.net", r"\.fastlylb\.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "impact": "high",
        "method": "Add the subdomain to a Fastly service configuration.",
    },
    "Shopify": {
        "cnames": [r"\.myshopify\.com", r"shops\.myshopify\.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "impact": "medium",
        "method": "Create a Shopify store and add the subdomain as a custom domain.",
    },
    "Zendesk": {
        "cnames": [r"\.zendesk\.com"],
        "fingerprints": ["Help Center Closed", "this help center no longer exists"],
        "impact": "medium",
        "method": "Create a Zendesk account and configure the subdomain as a host mapping.",
    },
    "Netlify": {
        "cnames": [r"\.netlify\.app", r"\.netlify\.com"],
        "fingerprints": ["Not Found - Request ID"],
        "impact": "high",
        "method": "Create a Netlify site and add the subdomain as a custom domain.",
    },
    "Vercel": {
        "cnames": [r"\.vercel\.app", r"\.now\.sh"],
        "fingerprints": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "impact": "high",
        "method": "Create a Vercel project and add the subdomain as a custom domain.",
    },
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
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def check_nxdomain(hostname):
    """Check if a hostname resolves to NXDOMAIN."""
    try:
        socket.gethostbyname(hostname)
        return False
    except socket.gaierror:
        return True


def http_probe(hostname, timeout=5):
    """Probe a hostname via HTTP/HTTPS and return status + body."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme in ["https", "http"]:
        url = f"{scheme}://{hostname}/"
        req = urllib.request.Request(url, headers={
            "User-Agent": "orizon-recon/1.0",
            "Host": hostname,
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(16384).decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(16384).decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, body
        except Exception:
            continue

    return 0, ""


def scan_subdomain(subdomain):
    """Scan a single subdomain for takeover vulnerability."""
    finding = {
        "subdomain": subdomain,
        "vulnerable": False,
        "cname": None,
        "cname_chain": [],
        "service": None,
        "evidence": None,
        "impact": None,
        "method": None,
    }

    # Resolve CNAME chain
    cname = resolve_cname(subdomain)
    seen = set()
    chain = []

    current = cname
    while current and current not in seen:
        seen.add(current)
        chain.append(current)
        next_cname = resolve_cname(current)
        if next_cname == current:
            break
        current = next_cname

    finding["cname"] = cname
    finding["cname_chain"] = chain

    if not cname:
        return finding

    # Check each CNAME in the chain against fingerprints
    for service, fp in TAKEOVER_FINGERPRINTS.items():
        matched_cname = None
        for c in chain:
            for pattern in fp["cnames"]:
                if re.search(pattern, c, re.IGNORECASE):
                    matched_cname = c
                    break
            if matched_cname:
                break

        if not matched_cname:
            continue

        # Check for NXDOMAIN on the CNAME target
        if fp.get("nxdomain"):
            if check_nxdomain(matched_cname):
                finding["vulnerable"] = True
                finding["service"] = service
                finding["evidence"] = f"CNAME target {matched_cname} returns NXDOMAIN"
                finding["impact"] = fp["impact"]
                finding["method"] = fp["method"]
                return finding

        # HTTP probe for error signatures
        status, body = http_probe(subdomain)
        if body:
            for sig in fp["fingerprints"]:
                if sig.lower() in body.lower():
                    finding["vulnerable"] = True
                    finding["service"] = service
                    finding["evidence"] = f"HTTP response contains '{sig}'"
                    finding["impact"] = fp["impact"]
                    finding["method"] = fp["method"]
                    finding["http_status"] = status
                    return finding

    return finding


def load_subdomains(path):
    """Load subdomains from a file (text or JSON)."""
    p = Path(path)
    if p.suffix == ".json":
        with open(p) as f:
            data = json.load(f)
        subs = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    subs.append(item)
                elif isinstance(item, dict):
                    for key in ("host", "hostname", "domain", "subdomain", "name"):
                        if key in item and isinstance(item[key], str):
                            subs.append(item[key])
                            break
        elif isinstance(data, dict):
            for key in ("subdomains", "hosts", "domains", "results", "targets"):
                if key in data and isinstance(data[key], list):
                    for item in data[key]:
                        if isinstance(item, str):
                            subs.append(item)
                        elif isinstance(item, dict):
                            for k in ("host", "hostname", "domain", "subdomain", "name"):
                                if k in item and isinstance(item[k], str):
                                    subs.append(item[k])
                                    break
        return subs
    else:
        return [line.strip() for line in p.read_text().strip().split("\n") if line.strip()]


def main():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Scanner - orizon.one")
    parser.add_argument("--subdomains", "-s", required=True,
                        help="File with subdomains (one per line or JSON)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--threads", type=int, default=15,
                        help="Number of concurrent threads (default: 15)")
    args = parser.parse_args()

    log("Starting subdomain takeover scan...")

    subdomains = load_subdomains(args.subdomains)
    # Deduplicate
    subdomains = list(dict.fromkeys(s.lower().strip() for s in subdomains if s.strip()))

    log(f"Scanning {len(subdomains)} subdomain(s) for takeover vulnerabilities...")

    results = []
    vulnerable = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_subdomain, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if result["vulnerable"]:
                vulnerable.append(result)
                vuln(f"TAKEOVER: {result['subdomain']} -> {result['cname']} "
                     f"({result['service']}, impact: {result['impact']})")
            elif result["cname"]:
                log(f"{result['subdomain']} -> {result['cname']} (not vulnerable)")

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "subdomain_takeover_scan",
            "tool": "cloud-pivot-finder by orizon.one",
            "subdomains_scanned": len(subdomains),
        },
        "stats": {
            "total_scanned": len(subdomains),
            "with_cname": sum(1 for r in results if r["cname"]),
            "vulnerable": len(vulnerable),
        },
        "vulnerable": vulnerable,
        "all_results": results,
    }

    output_path = args.output or "takeover_results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  SUBDOMAIN TAKEOVER SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Subdomains scanned : {len(subdomains)}")
    print(f"  With CNAME         : {sum(1 for r in results if r['cname'])}")
    print(f"  VULNERABLE         : {len(vulnerable)}")
    if vulnerable:
        print(f"\n  VULNERABLE SUBDOMAINS:")
        for v in vulnerable:
            print(f"    {v['subdomain']}")
            print(f"      CNAME   : {v['cname']}")
            print(f"      Service : {v['service']}")
            print(f"      Impact  : {v['impact']}")
            print(f"      Evidence: {v['evidence']}")
            print(f"      Method  : {v['method']}")
            print()
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
