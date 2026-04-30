#!/usr/bin/env python3
"""
Serverless and Container Endpoint Finder - cloud-pivot-finder
Discovers Lambda URLs, API Gateways, Cloud Functions, Cloud Run, Azure Functions.
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


# Serverless endpoint patterns
SERVERLESS_PATTERNS = {
    "AWS Lambda Function URL": {
        "pattern": r"[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws",
        "provider": "AWS",
    },
    "AWS API Gateway": {
        "pattern": r"[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com",
        "provider": "AWS",
    },
    "GCP Cloud Functions": {
        "pattern": r"[a-z0-9-]+-[a-z0-9]+\.cloudfunctions\.net",
        "provider": "GCP",
    },
    "GCP Cloud Run": {
        "pattern": r"[a-z0-9-]+\.run\.app",
        "provider": "GCP",
    },
    "Azure Functions": {
        "pattern": r"[a-z0-9-]+\.azurewebsites\.net",
        "provider": "Azure",
    },
}

# Common API paths to probe on serverless endpoints
API_PROBE_PATHS = [
    "/",
    "/api",
    "/api/v1",
    "/api/health",
    "/health",
    "/healthz",
    "/status",
    "/debug",
    "/info",
    "/version",
    "/env",
    "/config",
    "/.env",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/graphql",
]

# Azure Functions specific paths
AZURE_FUNCTION_PATHS = [
    "/api/",
    "/api/HttpTrigger",
    "/api/health",
    "/api/status",
    "/api/version",
]

# Error patterns that reveal internals
ERROR_SIGNATURES = {
    "stack_trace": [
        r"Traceback \(most recent call last\)",
        r"at [\w.]+\([\w.]+:\d+\)",
        r"Exception in thread",
        r"Error: Cannot find module",
        r"RuntimeError:",
    ],
    "debug_info": [
        r"DEBUG",
        r"X-Amzn-Trace-Id",
        r"x-amz-apigw-id",
        r"x-amz-cf-id",
        r"x-cloud-trace-context",
        r"x-ms-request-id",
    ],
    "internal_details": [
        r"Internal Server Error",
        r"Task timed out after",
        r"Function execution took",
        r"memory size.*configured",
        r"Runtime\.\w+Error",
        r"AccessDeniedException",
        r"ResourceNotFoundException",
        r"FUNCTION_INVOCATION_FAILED",
    ],
    "credentials_leak": [
        r"AWS_ACCESS_KEY",
        r"AWS_SECRET",
        r"GOOGLE_APPLICATION_CREDENTIALS",
        r"AZURE_CLIENT_SECRET",
        r"DATABASE_URL",
        r"DB_PASSWORD",
    ],
}


def http_get(url, timeout=8):
    """HTTP GET with SSL bypass."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = dict(resp.headers)
            body = resp.read(32768).decode("utf-8", errors="replace")
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if hasattr(e, "headers") else {}
        body = ""
        try:
            body = e.read(16384).decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, headers, body
    except Exception:
        return 0, {}, ""


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


def identify_serverless_type(hostname):
    """Check if a hostname matches a serverless pattern."""
    for service, info in SERVERLESS_PATTERNS.items():
        if re.search(info["pattern"], hostname, re.IGNORECASE):
            return service, info["provider"]
    return None, None


def check_error_signatures(body, headers):
    """Check response for error signatures revealing internals."""
    findings = []
    combined = body + " " + json.dumps(headers)

    for category, patterns in ERROR_SIGNATURES.items():
        for pattern in patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                findings.append({
                    "category": category,
                    "pattern": pattern,
                    "match": match.group(0)[:200],
                })
                break  # One match per category is enough

    return findings


def probe_endpoint(url):
    """Probe a single URL and analyze the response."""
    status, headers, body = http_get(url)
    if status == 0:
        return None

    result = {
        "url": url,
        "status": status,
        "content_length": len(body),
    }

    # Check for unauthenticated access
    if status == 200:
        result["unauthenticated_access"] = True
        result["response_preview"] = body[:500]
    else:
        result["unauthenticated_access"] = False

    # Check for error signatures
    errors = check_error_signatures(body, headers)
    if errors:
        result["error_signatures"] = errors

    # Check for debug headers
    debug_headers = {}
    for h_name, h_val in headers.items():
        h_lower = h_name.lower()
        if any(p in h_lower for p in ["x-amz", "x-goog", "x-ms-", "x-cloud-trace",
                                       "x-debug", "x-request-id", "x-function"]):
            debug_headers[h_name] = h_val
    if debug_headers:
        result["debug_headers"] = debug_headers

    return result


def scan_endpoint(hostname):
    """Scan a serverless endpoint thoroughly."""
    service, provider = identify_serverless_type(hostname)

    finding = {
        "hostname": hostname,
        "service": service,
        "provider": provider,
        "accessible": False,
        "probes": [],
        "issues": [],
    }

    # Select paths based on service type
    paths = list(API_PROBE_PATHS)
    if service == "Azure Functions":
        paths.extend(AZURE_FUNCTION_PATHS)

    for path in paths:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{hostname}{path}"
            result = probe_endpoint(url)
            if result and result["status"] != 0:
                finding["probes"].append(result)
                if result.get("unauthenticated_access"):
                    finding["accessible"] = True
                    finding["issues"].append({
                        "type": "unauthenticated_access",
                        "path": path,
                        "status": result["status"],
                    })
                if result.get("error_signatures"):
                    for sig in result["error_signatures"]:
                        finding["issues"].append({
                            "type": f"info_leak_{sig['category']}",
                            "path": path,
                            "detail": sig["match"],
                        })
                break  # If HTTPS worked, skip HTTP

    return finding


def discover_from_dns(domain, wordlist=None):
    """Discover serverless endpoints via DNS enumeration."""
    discovered = []

    # Check the domain itself and its CNAME chain
    cname = resolve_cname(domain)
    seen = set()
    current = cname
    while current and current not in seen:
        seen.add(current)
        svc, prov = identify_serverless_type(current)
        if svc:
            discovered.append({
                "hostname": current,
                "source": f"CNAME from {domain}",
                "service": svc,
                "provider": prov,
            })
        current = resolve_cname(current)
        if current and current in seen:
            break

    # Common serverless prefixes to try
    prefixes = wordlist or [
        "api", "app", "func", "function", "lambda", "webhook",
        "backend", "service", "auth", "gateway", "graphql",
        "rest", "v1", "v2", "internal", "admin", "dev", "staging",
    ]

    for prefix in prefixes:
        sub = f"{prefix}.{domain}"
        cname = resolve_cname(sub)
        if cname:
            svc, prov = identify_serverless_type(cname)
            if svc:
                discovered.append({
                    "hostname": cname,
                    "source": f"CNAME from {sub}",
                    "service": svc,
                    "provider": prov,
                })

    return discovered


def load_hosts_from_json(path):
    """Load hosts from recon JSON files."""
    with open(path) as f:
        data = json.load(f)

    hosts = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                hosts.append(item)
            elif isinstance(item, dict):
                for key in ("host", "hostname", "domain", "name"):
                    if key in item and isinstance(item[key], str):
                        hosts.append(item[key])
                        break
    elif isinstance(data, dict):
        for key in ("subdomains", "hosts", "domains", "results", "targets"):
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, str):
                        hosts.append(item)
                    elif isinstance(item, dict):
                        for k in ("host", "hostname", "domain", "name"):
                            if k in item and isinstance(item[k], str):
                                hosts.append(item[k])
                                break
    return hosts


def main():
    parser = argparse.ArgumentParser(description="Serverless Finder - orizon.one")
    parser.add_argument("--domain", "-d", help="Target domain to scan")
    parser.add_argument("--input", "-i", help="File with hostnames or recon JSON")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of concurrent threads (default: 10)")
    parser.add_argument("--deep", action="store_true",
                        help="Enable deep probing with more paths")
    args = parser.parse_args()

    if not args.domain and not args.input:
        parser.error("Provide --domain or --input")

    log("Starting serverless endpoint discovery...")

    # Collect endpoints to scan
    endpoints = []
    scan_targets = set()

    # DNS-based discovery for the domain
    if args.domain:
        domain = args.domain.strip().lower()
        log(f"Discovering serverless endpoints for: {domain}")
        discovered = discover_from_dns(domain)
        for d in discovered:
            if d["hostname"] not in scan_targets:
                scan_targets.add(d["hostname"])
                endpoints.append(d)
                success(f"Discovered: {d['hostname']} ({d['service']})")

    # Load additional hosts from input
    if args.input:
        input_path = Path(args.input)
        if input_path.suffix == ".json":
            hosts = load_hosts_from_json(args.input)
        else:
            hosts = [h.strip() for h in input_path.read_text().strip().split("\n") if h.strip()]

        for host in hosts:
            host = host.lower().strip()
            svc, prov = identify_serverless_type(host)
            if svc and host not in scan_targets:
                scan_targets.add(host)
                endpoints.append({
                    "hostname": host,
                    "source": "input",
                    "service": svc,
                    "provider": prov,
                })
            elif host not in scan_targets:
                # Check CNAME
                cname = resolve_cname(host)
                if cname:
                    svc, prov = identify_serverless_type(cname)
                    if svc and cname not in scan_targets:
                        scan_targets.add(cname)
                        endpoints.append({
                            "hostname": cname,
                            "source": f"CNAME from {host}",
                            "service": svc,
                            "provider": prov,
                        })

    log(f"Found {len(endpoints)} serverless endpoint(s) to probe...")

    # Scan each endpoint
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_endpoint, ep["hostname"]): ep for ep in endpoints}
        for future in concurrent.futures.as_completed(futures):
            ep = futures[future]
            result = future.result()
            result["source"] = ep.get("source", "unknown")
            results.append(result)

            if result["accessible"]:
                vuln(f"ACCESSIBLE: {result['hostname']} ({result['service']})")
            if result["issues"]:
                for issue in result["issues"]:
                    if "info_leak" in issue["type"]:
                        warn(f"  Info leak at {result['hostname']}{issue.get('path', '')}: "
                             f"{issue.get('detail', '')[:100]}")

    # Categorize
    accessible = [r for r in results if r["accessible"]]
    with_issues = [r for r in results if r["issues"]]

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "serverless_discovery",
            "tool": "cloud-pivot-finder by orizon.one",
            "domain": args.domain or "multi",
        },
        "stats": {
            "endpoints_discovered": len(endpoints),
            "endpoints_accessible": len(accessible),
            "endpoints_with_issues": len(with_issues),
        },
        "accessible_endpoints": accessible,
        "all_results": results,
    }

    domain_label = (args.domain or "multi").replace(".", "_")
    output_path = args.output or f"serverless_{domain_label}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  SERVERLESS DISCOVERY SUMMARY")
    print(f"{'='*60}")
    print(f"  Endpoints found      : {len(endpoints)}")
    print(f"  Accessible (no auth) : {len(accessible)}")
    print(f"  With info leaks      : {len(with_issues)}")
    if accessible:
        print(f"\n  ACCESSIBLE ENDPOINTS:")
        for ep in accessible:
            print(f"    {ep['hostname']} ({ep['service']})")
    if with_issues:
        print(f"\n  ENDPOINTS WITH ISSUES:")
        for ep in with_issues:
            for issue in ep["issues"]:
                print(f"    {ep['hostname']}: {issue['type']} at {issue.get('path', '/')}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
