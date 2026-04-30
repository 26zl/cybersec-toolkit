#!/usr/bin/env python3
"""
Rate Limiter Tester Module - api-breaker
Tests API rate limiting enforcement and bypass techniques.
Author: orizon.one
"""

import argparse
import json
import ssl
import time
import urllib.request
import urllib.parse
import concurrent.futures
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


# IP spoofing headers for rate limit bypass
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Real-IP": "10.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
]

# Rate limit related response headers
RATE_LIMIT_HEADERS = [
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "X-Rate-Limit-Limit",
    "X-Rate-Limit-Remaining",
    "X-Rate-Limit-Reset",
    "RateLimit-Limit",
    "RateLimit-Remaining",
    "RateLimit-Reset",
    "Retry-After",
]


def extract_rate_limit_info(headers):
    """Extract rate limiting information from response headers."""
    info = {}
    for header_name in RATE_LIMIT_HEADERS:
        for key, val in headers.items():
            if key.lower() == header_name.lower():
                info[header_name] = val
    return info


def send_rapid_requests(url, count, extra_headers=None, delay=0):
    """Send rapid requests and track responses."""
    results = {
        "total_sent": 0,
        "status_codes": {},
        "rate_limited_at": None,
        "rate_limit_headers": {},
        "response_times": [],
    }

    for i in range(count):
        start_time = time.time()
        status, headers, body = http_request(url, headers=extra_headers)
        elapsed = time.time() - start_time

        results["total_sent"] += 1
        results["status_codes"][str(status)] = results["status_codes"].get(str(status), 0) + 1
        results["response_times"].append(round(elapsed, 3))

        rl_info = extract_rate_limit_info(headers)
        if rl_info:
            results["rate_limit_headers"] = rl_info

        if status == 429:
            if results["rate_limited_at"] is None:
                results["rate_limited_at"] = i + 1
            if delay:
                time.sleep(delay)
            continue

        if delay:
            time.sleep(delay)

    return results


def send_concurrent_requests(url, count, workers=20, extra_headers=None):
    """Send concurrent requests using thread pool."""
    results = {
        "total_sent": 0,
        "status_codes": {},
        "rate_limited_at": None,
        "rate_limit_headers": {},
    }

    def make_request(_):
        return http_request(url, headers=extra_headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(make_request, i) for i in range(count)]
        for idx, future in enumerate(concurrent.futures.as_completed(futures)):
            status, headers, body = future.result()
            results["total_sent"] += 1
            results["status_codes"][str(status)] = results["status_codes"].get(str(status), 0) + 1

            rl_info = extract_rate_limit_info(headers)
            if rl_info:
                results["rate_limit_headers"] = rl_info

            if status == 429 and results["rate_limited_at"] is None:
                results["rate_limited_at"] = idx + 1

    return results


def test_rate_limit_bypass(url, extra_headers=None, delay=0):
    """Test rate limit bypass using IP spoofing headers."""
    log("Testing rate limit bypass via IP spoofing headers...")
    findings = []

    for bypass in BYPASS_HEADERS:
        bypass_name = list(bypass.keys())[0]
        headers = dict(bypass)
        if extra_headers:
            headers.update(extra_headers)
            headers.update(bypass)  # Ensure bypass header takes precedence

        # Send a burst of requests with the bypass header
        got_429 = False
        success_after_limit = 0

        for i in range(30):
            # Rotate the IP for X-Forwarded-For style headers
            if bypass_name in ("X-Forwarded-For", "X-Real-IP", "X-Client-IP",
                               "X-Originating-IP", "True-Client-IP", "CF-Connecting-IP"):
                headers[bypass_name] = f"10.{i % 256}.{(i * 7) % 256}.{(i * 13) % 256}"

            status, _, _ = http_request(url, headers=headers)
            if delay:
                time.sleep(delay)

            if status == 429:
                got_429 = True
            elif got_429 and status in (200, 201):
                success_after_limit += 1

        if got_429 and success_after_limit > 0:
            vuln(f"Rate limit bypass via {bypass_name} header rotation")
            findings.append({
                "type": "rate_limit_bypass",
                "severity": "medium",
                "bypass_header": bypass_name,
                "success_after_limit": success_after_limit,
            })
        elif not got_429:
            # Never rate limited even with bypass headers - might indicate no rate limiting
            pass

    return findings


def test_graphql_batching(url, extra_headers=None, delay=0):
    """Test GraphQL query batching to bypass rate limits."""
    log("Testing GraphQL batching...")
    findings = []

    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    # Test array-based batching
    batch_query = json.dumps([
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ] * 20)  # 100 queries in one request

    status, resp_headers, body = http_request(url, "POST", headers, batch_query)
    if delay:
        time.sleep(delay)

    if status == 200:
        try:
            data = json.loads(body)
            if isinstance(data, list) and len(data) > 1:
                vuln(f"GraphQL batching accepted: {len(data)} responses in single request")
                findings.append({
                    "type": "graphql_batching",
                    "severity": "medium",
                    "url": url,
                    "queries_sent": 100,
                    "responses_received": len(data),
                    "description": "GraphQL allows query batching which can bypass per-request rate limits",
                })
        except (json.JSONDecodeError, ValueError):
            pass

    # Test alias-based batching
    aliases = " ".join([f"q{i}: __typename" for i in range(100)])
    alias_query = json.dumps({"query": f"{{ {aliases} }}"})

    status, _, body = http_request(url, "POST", headers, alias_query)
    if delay:
        time.sleep(delay)

    if status == 200 and "q99" in body:
        vuln("GraphQL alias-based batching accepted (100 aliases)")
        findings.append({
            "type": "graphql_alias_batching",
            "severity": "medium",
            "url": url,
            "aliases_sent": 100,
            "description": "GraphQL allows alias-based query multiplication",
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Rate Limiter Tester - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from api_discovery.py or schema_builder.py")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--api-base", help="API base URL")
    parser.add_argument("--endpoint", help="Specific endpoint to test")
    parser.add_argument("--token", help="Auth token (Bearer)")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--count", type=int, default=120, help="Number of requests to send (default: 120)")
    parser.add_argument("--concurrent", action="store_true", help="Send requests concurrently")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    args = parser.parse_args()

    if not args.input and not args.api_base:
        parser.error("Either --input or --api-base is required")

    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie
    if args.token:
        extra_headers["Authorization"] = args.token if " " in args.token else f"Bearer {args.token}"

    base_url = args.api_base or ""
    endpoints = []
    graphql_endpoints = []

    if args.input:
        log(f"Loading data from {args.input}")
        with open(args.input) as f:
            input_data = json.load(f)
        base_url = base_url or input_data.get("meta", {}).get("base_url", "")
        for api in input_data.get("discovered_apis", []):
            url = api.get("url", "")
            if url:
                endpoints.append(url)
                if api.get("api_type") == "graphql":
                    graphql_endpoints.append(url)
        for ep in input_data.get("endpoints", []):
            url = ep.get("url", "")
            if url:
                endpoints.append(url)

    if args.endpoint:
        url = urllib.parse.urljoin(base_url, args.endpoint) if base_url else args.endpoint
        endpoints.insert(0, url)

    if not endpoints and base_url:
        endpoints = [base_url]

    log(f"Testing rate limiting for: {base_url}")
    log(f"Endpoints to test: {len(endpoints)}")
    log(f"Requests per endpoint: {args.count}")

    all_findings = []
    endpoint_results = []

    # Test each endpoint
    for url in endpoints[:15]:
        log(f"\nTesting rate limit: {url}")

        if args.concurrent:
            results = send_concurrent_requests(url, args.count, extra_headers=extra_headers)
        else:
            results = send_rapid_requests(url, args.count, extra_headers, args.delay)

        results["url"] = url
        endpoint_results.append(results)

        if results["rate_limited_at"]:
            success(f"  Rate limited at request #{results['rate_limited_at']}")
            if results.get("rate_limit_headers"):
                log(f"  Rate limit headers: {results['rate_limit_headers']}")
        else:
            count_429 = results["status_codes"].get("429", 0)
            if count_429 == 0:
                vuln(f"No rate limiting detected on {url} after {args.count} requests")
                all_findings.append({
                    "type": "no_rate_limit",
                    "severity": "medium",
                    "url": url,
                    "requests_sent": args.count,
                    "status_distribution": results["status_codes"],
                    "description": f"No 429 response after {args.count} rapid requests",
                })

        log(f"  Status distribution: {results['status_codes']}")

    # Test bypass techniques on rate-limited endpoints
    rate_limited_urls = [r["url"] for r in endpoint_results if r.get("rate_limited_at")]
    for url in rate_limited_urls[:5]:
        bypass_findings = test_rate_limit_bypass(url, extra_headers, args.delay)
        all_findings.extend(bypass_findings)

    # Test GraphQL batching
    for gql_url in graphql_endpoints[:3]:
        gql_findings = test_graphql_batching(gql_url, extra_headers, args.delay)
        all_findings.extend(gql_findings)

    # Also test common GraphQL paths
    if not graphql_endpoints:
        for path in ["/graphql", "/api/graphql", "/v1/graphql"]:
            gql_url = urllib.parse.urljoin(base_url, path)
            status, _, _ = http_request(gql_url, "POST",
                                         {"Content-Type": "application/json"},
                                         json.dumps({"query": "{__typename}"}))
            if status in (200, 400):
                gql_findings = test_graphql_batching(gql_url, extra_headers, args.delay)
                all_findings.extend(gql_findings)

    # Summary stats
    rate_limited_count = sum(1 for r in endpoint_results if r.get("rate_limited_at"))
    no_limit_count = len(endpoint_results) - rate_limited_count

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "rate_limit_testing",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "endpoints_tested": len(endpoint_results),
            "rate_limited": rate_limited_count,
            "not_rate_limited": no_limit_count,
            "total_findings": len(all_findings),
            "requests_per_endpoint": args.count,
        },
        "endpoint_results": endpoint_results,
        "findings": all_findings,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown" if base_url else "unknown"
    output_path = args.output or f"rate_limit_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  RATE LIMIT TEST SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  Endpoints tested    : {len(endpoint_results)}")
    print(f"  Requests per test   : {args.count}")
    print(f"  Rate limited        : {rate_limited_count}")
    print(f"  NOT rate limited    : {no_limit_count}")
    print(f"  Total findings      : {len(all_findings)}")
    print(f"  Bypass techniques   : {len([f for f in all_findings if 'bypass' in f.get('type', '')])}")
    print(f"  GraphQL batching    : {len([f for f in all_findings if 'graphql' in f.get('type', '')])}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
