#!/usr/bin/env python3
"""
API Discovery Module - api-breaker
Discovers REST, GraphQL, and SOAP API endpoints from domains.
Author: orizon.one
"""

import argparse
import json
import re
import ssl
import urllib.request
import urllib.parse
import concurrent.futures
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


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


# Common API paths to fuzz
API_PATHS = [
    # Documentation
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json", "/docs", "/redoc",
    "/swagger-ui.html", "/swagger-ui/", "/swagger-resources",
    "/.well-known/openapi", "/api/swagger.json",

    # GraphQL
    "/graphql", "/graphiql", "/playground", "/api/graphql",
    "/graphql/console", "/v1/graphql", "/v2/graphql",

    # REST common
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/rest/", "/rest/v1/", "/rest/v2/",
    "/v1/", "/v2/", "/v3/",

    # Common resources
    "/api/users", "/api/v1/users", "/api/accounts",
    "/api/products", "/api/orders", "/api/items",
    "/api/posts", "/api/comments", "/api/messages",
    "/api/config", "/api/settings", "/api/status",
    "/api/health", "/api/version", "/api/info",
    "/api/auth/login", "/api/auth/register",
    "/api/auth/token", "/api/auth/refresh",
    "/api/search", "/api/upload", "/api/download",

    # Health/monitoring
    "/health", "/healthz", "/ready", "/alive",
    "/status", "/ping", "/metrics",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/mappings",

    # SOAP/WSDL
    "/ws", "/wsdl", "/soap", "/service.asmx",
    "/?wsdl", "/ws?wsdl",
]


def probe_path(base_url, path, extra_headers=None):
    """Probe a single path and return details if found."""
    url = urllib.parse.urljoin(base_url, path)
    status, headers, body = http_request(url, headers=extra_headers)

    if status in (200, 201, 301, 302, 401, 403, 405):
        content_type = headers.get("Content-Type", "").lower()
        api_type = "unknown"

        if "graphql" in path.lower() or "graphql" in body.lower():
            api_type = "graphql"
        elif "swagger" in path.lower() or "openapi" in body.lower():
            api_type = "openapi_docs"
        elif "wsdl" in body.lower() or "soap" in body.lower():
            api_type = "soap"
        elif "json" in content_type:
            api_type = "rest_json"
        elif "xml" in content_type:
            api_type = "rest_xml"

        return {
            "url": url,
            "path": path,
            "status": status,
            "content_type": content_type,
            "api_type": api_type,
            "response_length": len(body),
            "auth_required": status in (401, 403),
            "methods_tested": ["GET"],
        }
    return None


def test_graphql(url, extra_headers=None):
    """Test if a GraphQL endpoint supports introspection."""
    log(f"Testing GraphQL introspection on {url}...")

    introspection_query = json.dumps({
        "query": "{ __schema { types { name } } }"
    })

    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    status, resp_headers, body = http_request(url, "POST", headers, introspection_query)

    if status == 200 and "__schema" in body:
        try:
            data = json.loads(body)
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            type_names = [t["name"] for t in types if not t["name"].startswith("__")]
            return {
                "introspection_enabled": True,
                "types_found": len(type_names),
                "type_names": type_names[:50],
            }
        except (json.JSONDecodeError, KeyError):
            pass

    return {"introspection_enabled": False}


def extract_openapi_endpoints(url, extra_headers=None):
    """Parse OpenAPI/Swagger documentation for endpoints."""
    log(f"Parsing OpenAPI docs from {url}...")
    status, _, body = http_request(url, headers=extra_headers)

    if status != 200:
        return []

    try:
        spec = json.loads(body)
    except json.JSONDecodeError:
        return []

    endpoints = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                params = []
                for param in details.get("parameters", []):
                    params.append({
                        "name": param.get("name"),
                        "in": param.get("in"),
                        "required": param.get("required", False),
                        "type": param.get("schema", {}).get("type", "string"),
                    })

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "parameters": params,
                    "auth_required": bool(details.get("security")),
                    "tags": details.get("tags", []),
                })

    success(f"Parsed {len(endpoints)} endpoints from OpenAPI spec")
    return endpoints


def discover_from_js(base_url, js_urls, extra_headers=None):
    """Extract API endpoints from JavaScript files."""
    log("Analyzing JavaScript files for API endpoints...")
    endpoints = set()

    patterns = [
        r'["\'](\/api\/[^"\']+)["\']',
        r'["\'](\/v[0-9]+\/[^"\']+)["\']',
        r'["\'](\/graphql[^"\']*)["\']',
        r'["\'](\/rest\/[^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.\w+\(["\']([^"\']+)["\']',
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
    ]

    for js_url in js_urls[:20]:
        _, _, js_body = http_request(js_url, headers=extra_headers)
        if not js_body:
            continue
        for pattern in patterns:
            for match in re.finditer(pattern, js_body):
                ep = match.group(1)
                if ep.startswith("/"):
                    endpoints.add(ep)
                elif ep.startswith("http"):
                    parsed = urllib.parse.urlparse(ep)
                    endpoints.add(parsed.path)

    success(f"Found {len(endpoints)} endpoints from JS analysis")
    return list(endpoints)


def test_http_methods(url, extra_headers=None):
    """Test which HTTP methods are allowed on an endpoint."""
    methods = []
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
        status, headers, _ = http_request(url, method=method, headers=extra_headers)
        if status not in (0, 404, 501, 405):
            methods.append(method)

        # Also check OPTIONS Allow header
        if method == "OPTIONS" and "Allow" in headers:
            allowed = headers["Allow"]
            methods.extend([m.strip() for m in allowed.split(",")])

    return list(set(methods))


def main():
    parser = argparse.ArgumentParser(description="API Discovery - orizon.one")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--token", help="Auth token (Bearer)")
    parser.add_argument("--threads", type=int, default=15, help="Concurrent threads")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    if not domain.startswith("http"):
        base_url = f"https://{domain}"
    else:
        base_url = domain
        domain = urllib.parse.urlparse(domain).hostname

    log(f"Starting API discovery on: {domain}")

    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie
    if args.token:
        extra_headers["Authorization"] = args.token if " " in args.token else f"Bearer {args.token}"

    # Phase 1: Fuzz API paths
    log(f"Fuzzing {len(API_PATHS)} common API paths...")
    discovered = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(probe_path, base_url, path, extra_headers): path
            for path in API_PATHS
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                discovered.append(result)
                success(f"Found: {result['path']} ({result['status']}, {result['api_type']})")

    # Phase 2: Test GraphQL endpoints
    graphql_results = {}
    graphql_endpoints = [d for d in discovered if d["api_type"] == "graphql"]
    for gql in graphql_endpoints:
        graphql_results[gql["url"]] = test_graphql(gql["url"], extra_headers)

    # Phase 3: Parse OpenAPI docs
    openapi_endpoints = []
    doc_endpoints = [d for d in discovered if d["api_type"] == "openapi_docs"]
    for doc in doc_endpoints:
        openapi_endpoints.extend(extract_openapi_endpoints(doc["url"], extra_headers))

    # Phase 4: Test HTTP methods on key endpoints
    for endpoint in discovered[:20]:
        if endpoint["status"] == 200:
            methods = test_http_methods(endpoint["url"], extra_headers)
            endpoint["methods_available"] = methods

    output = {
        "meta": {
            "domain": domain,
            "base_url": base_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "api_discovery",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "paths_tested": len(API_PATHS),
            "apis_found": len(discovered),
            "graphql_endpoints": len(graphql_endpoints),
            "openapi_docs": len(doc_endpoints),
            "documented_endpoints": len(openapi_endpoints),
        },
        "discovered_apis": discovered,
        "graphql": graphql_results,
        "openapi_endpoints": openapi_endpoints,
    }

    output_path = args.output or f"api_discovery_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  API DISCOVERY SUMMARY - {domain}")
    print(f"{'='*60}")
    print(f"  APIs found          : {len(discovered)}")
    print(f"  GraphQL endpoints   : {len(graphql_endpoints)}")
    print(f"  OpenAPI docs        : {len(doc_endpoints)}")
    print(f"  Documented endpoints: {len(openapi_endpoints)}")
    print(f"  Auth-required APIs  : {sum(1 for d in discovered if d.get('auth_required'))}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
