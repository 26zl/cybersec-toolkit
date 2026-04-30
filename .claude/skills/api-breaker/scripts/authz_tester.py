#!/usr/bin/env python3
"""
Authorization Tester Module - api-breaker
Tests for BOLA (Broken Object Level Authorization) and BFLA (Broken Function Level Authorization).
Author: orizon.one
"""

import argparse
import json
import re
import ssl
import time
import urllib.request
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


def http_request(url, method="GET", headers=None, data=None, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    default_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; orizon-hunter/1.0)",
        "Accept": "application/json, text/html, */*",
    }
    if headers:
        default_headers.update(headers)
    if data and isinstance(data, str):
        data = data.encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=default_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        body = e.read(32768).decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return e.code, dict(e.headers) if hasattr(e, "headers") else {}, body
    except Exception:
        return 0, {}, ""


# Admin/privileged endpoint patterns
ADMIN_PATTERNS = [
    "/admin", "/admin/", "/api/admin", "/api/v1/admin",
    "/manage", "/management", "/dashboard",
    "/api/users", "/api/v1/users", "/api/accounts",
    "/api/roles", "/api/permissions",
    "/api/settings", "/api/config", "/api/configuration",
    "/internal", "/api/internal",
    "/api/logs", "/api/audit",
    "/api/billing", "/api/subscriptions",
    "/api/export", "/api/import",
    "/api/reports", "/api/analytics",
    "/api/webhooks",
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]

# Common IDOR test IDs
TEST_IDS = ["1", "2", "0", "100", "999", "1000", "admin"]


def extract_object_ids(body):
    """Extract potential object IDs from a response body."""
    ids = set()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return ids

    def walk(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key.lower() in ("id", "uid", "user_id", "userid", "account_id",
                                    "accountid", "order_id", "orderid", "object_id"):
                    ids.add(str(val))
                walk(val)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return ids


def find_id_endpoints(base_url, endpoints):
    """Find endpoints that contain ID placeholders or patterns."""
    id_endpoints = []

    for ep in endpoints:
        path = ep.get("path", "") if isinstance(ep, dict) else ep
        url = ep.get("url", "") if isinstance(ep, dict) else ""

        # Match patterns like /users/1, /api/v1/orders/123
        if re.search(r'/\d+(?:/|$)', path) or re.search(r'/\{[^}]+\}', path):
            id_endpoints.append(ep)
        # Match common resource/id patterns
        elif re.search(r'/(?:users|accounts|orders|items|products|posts|messages|documents|files|tickets)/\w+', path):
            id_endpoints.append(ep)

    return id_endpoints


def test_bola(base_url, endpoints, token_a, token_b=None, extra_headers=None, delay=0):
    """Test for Broken Object Level Authorization (BOLA/IDOR)."""
    log("Testing for BOLA (Broken Object Level Authorization)...")
    findings = []

    headers_a = {"Authorization": token_a if " " in token_a else f"Bearer {token_a}"}
    if extra_headers:
        headers_a.update(extra_headers)

    headers_b = {}
    if token_b:
        headers_b = {"Authorization": token_b if " " in token_b else f"Bearer {token_b}"}
        if extra_headers:
            headers_b.update(extra_headers)

    # Phase 1: Get objects owned by user A
    tested = 0
    for ep in endpoints:
        url = ep.get("url", "") if isinstance(ep, dict) else ep
        path = ep.get("path", "") if isinstance(ep, dict) else ep
        if not url:
            url = urllib.parse.urljoin(base_url, path)

        # Get resources as User A
        status_a, _, body_a = http_request(url, headers=headers_a)
        if delay:
            time.sleep(delay)

        if status_a != 200:
            continue

        # Extract IDs from response
        ids_found = extract_object_ids(body_a)
        if not ids_found:
            continue

        log(f"Found {len(ids_found)} object IDs at {path}")

        # Phase 2: Try accessing those IDs from User B (or no auth)
        for obj_id in list(ids_found)[:5]:
            # Build URL with ID
            id_url = url.rstrip("/") + f"/{obj_id}"

            for method in HTTP_METHODS:
                # Test with User B token
                if token_b:
                    status_b, _, body_b = http_request(id_url, method=method, headers=headers_b)
                    if delay:
                        time.sleep(delay)

                    if status_b in (200, 201, 204):
                        vuln(f"BOLA: {method} {id_url} accessible with different user token (status={status_b})")
                        findings.append({
                            "type": "bola",
                            "severity": "high",
                            "method": method,
                            "url": id_url,
                            "object_id": obj_id,
                            "access": "different_user",
                            "status": status_b,
                            "response_preview": body_b[:200],
                        })
                        tested += 1

                # Test without auth
                status_noauth, _, body_noauth = http_request(id_url, method=method)
                if delay:
                    time.sleep(delay)

                if status_noauth in (200, 201, 204):
                    vuln(f"BOLA: {method} {id_url} accessible without auth (status={status_noauth})")
                    findings.append({
                        "type": "bola",
                        "severity": "critical",
                        "method": method,
                        "url": id_url,
                        "object_id": obj_id,
                        "access": "no_auth",
                        "status": status_noauth,
                        "response_preview": body_noauth[:200],
                    })
                    tested += 1

        if tested >= 50:
            break

    # Phase 3: Test with common IDs on known resource paths
    resource_paths = ["/api/users/", "/api/v1/users/", "/api/accounts/",
                      "/api/orders/", "/api/v1/orders/", "/api/products/"]

    for rpath in resource_paths:
        for test_id in TEST_IDS:
            url = urllib.parse.urljoin(base_url, f"{rpath}{test_id}")

            if token_b:
                status, _, body = http_request(url, headers=headers_b)
                if delay:
                    time.sleep(delay)
                if status == 200 and len(body) > 20:
                    vuln(f"BOLA: GET {url} accessible with alternate token")
                    findings.append({
                        "type": "bola_idor",
                        "severity": "high",
                        "url": url,
                        "test_id": test_id,
                        "status": status,
                        "response_preview": body[:200],
                    })

            status, _, body = http_request(url)
            if delay:
                time.sleep(delay)
            if status == 200 and len(body) > 20:
                vuln(f"BOLA: GET {url} accessible without auth")
                findings.append({
                    "type": "bola_idor",
                    "severity": "critical",
                    "url": url,
                    "test_id": test_id,
                    "status": status,
                    "response_preview": body[:200],
                })

    return findings


def test_bfla(base_url, token, extra_headers=None, delay=0):
    """Test for Broken Function Level Authorization (BFLA)."""
    log("Testing for BFLA (Broken Function Level Authorization)...")
    findings = []

    headers_user = {"Authorization": token if " " in token else f"Bearer {token}"}
    if extra_headers:
        headers_user.update(extra_headers)

    for admin_path in ADMIN_PATTERNS:
        url = urllib.parse.urljoin(base_url, admin_path)

        for method in HTTP_METHODS:
            data = None
            req_headers = dict(headers_user)
            if method in ("POST", "PUT", "PATCH"):
                req_headers["Content-Type"] = "application/json"
                data = json.dumps({"test": "bfla_probe"})

            status, resp_headers, body = http_request(url, method=method, headers=req_headers, data=data)
            if delay:
                time.sleep(delay)

            if status in (200, 201, 204):
                has_data = len(body) > 20
                vuln(f"BFLA: {method} {admin_path} accessible with user token (status={status})")
                findings.append({
                    "type": "bfla",
                    "severity": "high",
                    "method": method,
                    "path": admin_path,
                    "url": url,
                    "status": status,
                    "has_data": has_data,
                    "response_preview": body[:200],
                })

    # Test method override (X-HTTP-Method-Override)
    log("Testing HTTP method override headers...")
    override_headers_list = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
    ]

    for admin_path in ADMIN_PATTERNS[:5]:
        url = urllib.parse.urljoin(base_url, admin_path)
        for override_header in override_headers_list:
            for target_method in ["PUT", "DELETE", "PATCH"]:
                req_headers = dict(headers_user)
                req_headers[override_header] = target_method
                req_headers["Content-Type"] = "application/json"

                status, _, body = http_request(url, method="POST", headers=req_headers,
                                                data=json.dumps({"test": "override"}))
                if delay:
                    time.sleep(delay)

                if status in (200, 201, 204):
                    vuln(f"BFLA via method override: {override_header}: {target_method} on {admin_path}")
                    findings.append({
                        "type": "bfla_method_override",
                        "severity": "high",
                        "override_header": override_header,
                        "target_method": target_method,
                        "path": admin_path,
                        "status": status,
                    })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Authorization Tester - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from schema_builder.py or api_discovery.py")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--token", required=True, help="User A auth token")
    parser.add_argument("--token-b", help="User B auth token (for BOLA cross-user testing)")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--api-base", help="API base URL")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    args = parser.parse_args()

    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie

    base_url = args.api_base or ""
    endpoints = []

    if args.input:
        log(f"Loading data from {args.input}")
        with open(args.input) as f:
            input_data = json.load(f)
        base_url = base_url or input_data.get("meta", {}).get("base_url", "")
        for api in input_data.get("discovered_apis", []):
            endpoints.append(api)
        for ep in input_data.get("endpoints", []):
            endpoints.append(ep)
        for ep in input_data.get("openapi_endpoints", []):
            endpoints.append(ep)

    if not base_url:
        parser.error("--api-base or --input with base_url is required")

    log(f"Testing authorization for: {base_url}")
    log(f"Endpoints loaded: {len(endpoints)}")

    all_findings = []

    # Test BOLA
    bola_findings = test_bola(base_url, endpoints, args.token, args.token_b, extra_headers, args.delay)
    all_findings.extend(bola_findings)

    # Test BFLA
    bfla_findings = test_bfla(base_url, args.token, extra_headers, args.delay)
    all_findings.extend(bfla_findings)

    # Categorize
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    medium = [f for f in all_findings if f.get("severity") == "medium"]

    bola_count = len([f for f in all_findings if f["type"].startswith("bola")])
    bfla_count = len([f for f in all_findings if f["type"].startswith("bfla")])

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "authz_testing",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "total_findings": len(all_findings),
            "bola_findings": bola_count,
            "bfla_findings": bfla_count,
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "endpoints_tested": len(endpoints),
        },
        "findings": all_findings,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown"
    output_path = args.output or f"authz_test_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  AUTHORIZATION TEST SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  Endpoints tested    : {len(endpoints)}")
    print(f"  Total findings      : {len(all_findings)}")
    print(f"  BOLA findings       : {bola_count}")
    print(f"  BFLA findings       : {bfla_count}")
    print(f"  Critical            : {len(critical)}")
    print(f"  High                : {len(high)}")
    print(f"  Medium              : {len(medium)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
