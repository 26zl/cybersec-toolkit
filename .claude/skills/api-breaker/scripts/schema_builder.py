#!/usr/bin/env python3
"""
Schema Builder Module - api-breaker
Reconstructs API schema from observed behavior, even without documentation.
Author: orizon.one
"""

import argparse
import json
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


# Common field names to probe
PROBE_FIELDS = [
    "id", "name", "email", "username", "password", "title", "description",
    "status", "type", "role", "created_at", "updated_at", "price", "amount",
    "quantity", "url", "address", "phone", "message", "content", "body",
    "first_name", "last_name", "age", "date", "token", "key", "value",
    "is_active", "is_admin", "verified", "approved", "permissions",
]

# Common REST resource names
RESOURCE_NAMES = [
    "users", "accounts", "products", "orders", "items", "posts", "comments",
    "messages", "notifications", "settings", "categories", "tags", "files",
    "images", "documents", "payments", "transactions", "invoices", "tickets",
    "events", "groups", "roles", "permissions", "sessions", "tokens",
    "customers", "projects", "tasks", "reports", "logs", "webhooks",
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


def discover_methods(url, extra_headers=None, delay=0):
    """Discover allowed HTTP methods on an endpoint."""
    allowed = []

    # Try OPTIONS first for Allow header
    status, headers, _ = http_request(url, method="OPTIONS", headers=extra_headers)
    if delay:
        time.sleep(delay)
    if "Allow" in headers:
        allowed = [m.strip().upper() for m in headers["Allow"].split(",")]
        return allowed

    # Probe each method
    for method in HTTP_METHODS:
        status, headers, body = http_request(url, method=method, headers=extra_headers)
        if delay:
            time.sleep(delay)
        if status not in (0, 404, 501):
            allowed.append(method)
            if method == "OPTIONS" and "Allow" in headers:
                extra = [m.strip().upper() for m in headers["Allow"].split(",")]
                allowed.extend(extra)

    return list(set(allowed))


def probe_content_types(url, extra_headers=None, delay=0):
    """Test content negotiation to find accepted content types."""
    accepted = []
    content_types = [
        ("application/json", "json"),
        ("application/xml", "xml"),
        ("application/x-www-form-urlencoded", "form"),
        ("multipart/form-data", "multipart"),
        ("text/plain", "text"),
    ]

    for ct, label in content_types:
        headers = {"Accept": ct, "Content-Type": ct}
        if extra_headers:
            headers.update(extra_headers)
        status, resp_headers, body = http_request(url, headers=headers)
        if delay:
            time.sleep(delay)
        resp_ct = resp_headers.get("Content-Type", "").lower()
        if status not in (0, 404, 406, 415):
            accepted.append({
                "content_type": ct,
                "label": label,
                "status": status,
                "response_content_type": resp_ct,
            })

    return accepted


def extract_fields_from_response(body):
    """Extract field names and infer types from a JSON response."""
    fields = {}
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return fields

    def extract(obj, prefix=""):
        if isinstance(obj, dict):
            for key, val in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                fields[full_key] = infer_type(val)
                if isinstance(val, dict):
                    extract(val, full_key)
                elif isinstance(val, list) and val:
                    if isinstance(val[0], dict):
                        extract(val[0], full_key + "[]")
        elif isinstance(obj, list) and obj:
            if isinstance(obj[0], dict):
                extract(obj[0], prefix + "[]" if prefix else "[]")

    extract(data)
    return fields


def infer_type(value):
    """Infer OpenAPI type from a Python value."""
    if value is None:
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def extract_fields_from_errors(body):
    """Extract field names from error messages."""
    import re
    fields = set()

    patterns = [
        r"['\"](\w+)['\"]\s+is\s+required",
        r"missing\s+(?:required\s+)?(?:field|param|parameter|key)\s+['\"]?(\w+)['\"]?",
        r"['\"](\w+)['\"]\s+(?:must|should)\s+be",
        r"(?:field|param|parameter)\s+['\"](\w+)['\"]",
        r"expected\s+['\"]?(\w+)['\"]?",
        r"['\"](\w+)['\"]\s+(?:not found|invalid|unknown)",
        r"validation.*?['\"](\w+)['\"]",
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, body, re.IGNORECASE):
            field = match.group(1)
            if len(field) > 1 and field.lower() not in ("the", "a", "an", "is", "be"):
                fields.add(field)

    return fields


def probe_fields_via_errors(url, method="POST", extra_headers=None, delay=0):
    """Send payloads to discover accepted fields via error responses."""
    discovered_fields = {}

    # Send empty body
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    status, _, body = http_request(url, method=method, headers=headers, data="{}")
    if delay:
        time.sleep(delay)

    error_fields = extract_fields_from_errors(body)
    for field in error_fields:
        discovered_fields[field] = "string"

    # Send each probe field individually to detect accepted ones
    for field in PROBE_FIELDS:
        test_payloads = [
            {field: "test_value"},
            {field: 12345},
            {field: True},
        ]

        for payload in test_payloads:
            data = json.dumps(payload)
            status, _, resp_body = http_request(url, method=method, headers=headers, data=data)
            if delay:
                time.sleep(delay)

            if status in (200, 201, 422, 400):
                # If 422/400 mentions the field differently than "unknown field", it's recognized
                lower_body = resp_body.lower()
                if status in (200, 201):
                    discovered_fields[field] = infer_type(payload[field])
                    break
                elif field.lower() in lower_body and "unknown" not in lower_body:
                    discovered_fields[field] = infer_type(payload[field])
                    break

                # Check error response for additional field hints
                more_fields = extract_fields_from_errors(resp_body)
                for f in more_fields:
                    if f not in discovered_fields:
                        discovered_fields[f] = "string"

    return discovered_fields


def discover_resources(base_url, extra_headers=None, delay=0):
    """Discover API resources by probing common paths."""
    found = []

    for resource in RESOURCE_NAMES:
        for prefix in ["/api/", "/api/v1/", "/api/v2/", "/v1/", "/v2/", "/"]:
            url = urllib.parse.urljoin(base_url, f"{prefix}{resource}")
            status, headers, body = http_request(url, headers=extra_headers)
            if delay:
                time.sleep(delay)

            if status in (200, 201, 401, 403):
                entry = {
                    "resource": resource,
                    "url": url,
                    "path": f"{prefix}{resource}",
                    "status": status,
                    "auth_required": status in (401, 403),
                }
                # Try to get fields from response
                if status == 200:
                    fields = extract_fields_from_response(body)
                    if fields:
                        entry["fields"] = fields
                found.append(entry)
                success(f"Resource: {prefix}{resource} (status={status})")
                break  # Found at this prefix, skip others

    return found


def build_graphql_schema(url, extra_headers=None, delay=0):
    """Attempt GraphQL introspection to build schema."""
    log("Attempting GraphQL introspection...")

    introspection_query = json.dumps({
        "query": """{
            __schema {
                queryType { name }
                mutationType { name }
                types {
                    name
                    kind
                    fields {
                        name
                        type { name kind ofType { name kind } }
                        args { name type { name kind } }
                    }
                }
            }
        }"""
    })

    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    status, _, body = http_request(url, "POST", headers, introspection_query)
    if delay:
        time.sleep(delay)

    if status == 200 and "__schema" in body:
        try:
            data = json.loads(body)
            schema = data.get("data", {}).get("__schema", {})
            types = []
            for t in schema.get("types", []):
                if not t["name"].startswith("__"):
                    types.append({
                        "name": t["name"],
                        "kind": t.get("kind", ""),
                        "fields": [
                            {
                                "name": f["name"],
                                "type": f.get("type", {}).get("name", ""),
                                "args": [a["name"] for a in f.get("args", [])],
                            }
                            for f in (t.get("fields") or [])
                        ],
                    })
            success(f"GraphQL introspection: {len(types)} types discovered")
            return {"introspection_enabled": True, "types": types}
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    warn("GraphQL introspection disabled or failed")
    return {"introspection_enabled": False}


def build_openapi_spec(base_url, endpoints, resources):
    """Build an OpenAPI 3.0 spec from discovered data."""
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": f"Reconstructed API Schema - {base_url}",
            "version": "1.0.0-reconstructed",
            "description": "Auto-reconstructed by api-breaker (orizon.one)",
        },
        "servers": [{"url": base_url}],
        "paths": {},
    }

    for ep in endpoints:
        path = ep.get("path", "")
        if path not in spec["paths"]:
            spec["paths"][path] = {}

        for method in ep.get("methods", ["get"]):
            method_lower = method.lower()
            entry = {
                "summary": f"Discovered {method} {path}",
                "responses": {
                    str(ep.get("status", 200)): {
                        "description": "Observed response",
                    }
                },
            }
            if ep.get("fields"):
                properties = {}
                for fname, ftype in ep["fields"].items():
                    properties[fname] = {"type": ftype}
                if method_lower in ("post", "put", "patch"):
                    entry["requestBody"] = {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": properties,
                                }
                            }
                        }
                    }
                else:
                    entry["parameters"] = [
                        {"name": fname, "in": "query", "schema": {"type": ftype}}
                        for fname, ftype in ep["fields"].items()
                    ]

            spec["paths"][path][method_lower] = entry

    return spec


def main():
    parser = argparse.ArgumentParser(description="Schema Builder - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from api_discovery.py")
    parser.add_argument("--api-base", help="API base URL (alternative to --input)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--token", help="Auth token (Bearer)")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    args = parser.parse_args()

    if not args.input and not args.api_base:
        parser.error("Either --input or --api-base is required")

    extra_headers = {}
    if args.cookie:
        extra_headers["Cookie"] = args.cookie
    if args.token:
        extra_headers["Authorization"] = args.token if " " in args.token else f"Bearer {args.token}"

    base_url = args.api_base
    discovered_apis = []

    if args.input:
        log(f"Loading discovery data from {args.input}")
        with open(args.input) as f:
            discovery_data = json.load(f)
        base_url = base_url or discovery_data.get("meta", {}).get("base_url", "")
        discovered_apis = discovery_data.get("discovered_apis", [])

    log(f"Reconstructing API schema for: {base_url}")

    # Phase 1: Discover resources
    log("Phase 1: Discovering API resources...")
    resources = discover_resources(base_url, extra_headers, args.delay)

    # Phase 2: Discover methods and content types for each endpoint
    log("Phase 2: Probing HTTP methods and content types...")
    endpoints = []

    all_paths = set()
    for api in discovered_apis:
        all_paths.add(api.get("path", api.get("url", "")))
    for res in resources:
        all_paths.add(res.get("path", ""))

    for path in all_paths:
        if not path:
            continue
        url = urllib.parse.urljoin(base_url, path)
        log(f"Probing: {path}")

        methods = discover_methods(url, extra_headers, args.delay)
        content_types = probe_content_types(url, extra_headers, args.delay)

        endpoint = {
            "path": path,
            "url": url,
            "methods": methods,
            "content_types": content_types,
            "fields": {},
            "status": 0,
        }

        # Get fields from GET response
        if "GET" in methods:
            status, _, body = http_request(url, headers=extra_headers)
            if args.delay:
                time.sleep(args.delay)
            endpoint["status"] = status
            if status == 200:
                endpoint["fields"] = extract_fields_from_response(body)

        # Probe fields via error messages for POST/PUT
        writable_methods = [m for m in methods if m in ("POST", "PUT", "PATCH")]
        if writable_methods:
            error_fields = probe_fields_via_errors(url, writable_methods[0], extra_headers, args.delay)
            for k, v in error_fields.items():
                if k not in endpoint["fields"]:
                    endpoint["fields"][k] = v

        if methods:
            endpoints.append(endpoint)
            success(f"  Methods: {', '.join(methods)} | Fields: {len(endpoint['fields'])}")

    # Phase 3: Check for GraphQL
    graphql_schema = {}
    for path in ["/graphql", "/api/graphql", "/v1/graphql"]:
        url = urllib.parse.urljoin(base_url, path)
        status, _, _ = http_request(url, method="POST", headers=extra_headers,
                                     data=json.dumps({"query": "{__typename}"}))
        if status in (200, 400):
            graphql_schema = build_graphql_schema(url, extra_headers, args.delay)
            if graphql_schema.get("introspection_enabled"):
                break

    # Phase 4: Build OpenAPI spec
    log("Phase 4: Building OpenAPI specification...")
    openapi_spec = build_openapi_spec(base_url, endpoints, resources)

    # Count totals
    total_fields = sum(len(ep.get("fields", {})) for ep in endpoints)
    total_methods = sum(len(ep.get("methods", [])) for ep in endpoints)

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "schema_reconstruction",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "resources_discovered": len(resources),
            "endpoints_mapped": len(endpoints),
            "total_fields": total_fields,
            "total_methods": total_methods,
            "graphql_introspection": graphql_schema.get("introspection_enabled", False),
        },
        "resources": resources,
        "endpoints": endpoints,
        "graphql_schema": graphql_schema,
        "openapi_spec": openapi_spec,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown"
    output_path = args.output or f"schema_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  SCHEMA RECONSTRUCTION SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  Resources discovered : {len(resources)}")
    print(f"  Endpoints mapped     : {len(endpoints)}")
    print(f"  Total fields found   : {total_fields}")
    print(f"  HTTP methods mapped  : {total_methods}")
    print(f"  GraphQL introspection: {graphql_schema.get('introspection_enabled', False)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
