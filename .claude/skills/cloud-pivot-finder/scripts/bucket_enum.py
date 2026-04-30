#!/usr/bin/env python3
"""
Cloud Storage Bucket Enumerator - cloud-pivot-finder
Discovers and tests S3, GCS, and Azure Blob storage.
Author: orizon.one
"""

import argparse
import json
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


def vuln(msg):
    print(f"[!!] {msg}")


def http_get(url, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(32768).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read(8192).decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        return e.code, body
    except Exception:
        return 0, ""


def generate_bucket_names(domain, company_name=None):
    """Generate potential bucket names from domain and company name."""
    base = domain.replace(".", "-")
    parts = domain.split(".")
    name = parts[0]  # e.g., "example" from "example.com"

    names = set()

    bases = [name, base]
    if company_name:
        bases.append(company_name.lower().replace(" ", "-"))
        bases.append(company_name.lower().replace(" ", ""))

    for b in bases:
        # Direct names
        names.add(b)

        # Environment suffixes
        for env in ["dev", "staging", "stage", "prod", "production", "test", "qa", "uat", "demo", "sandbox"]:
            names.add(f"{b}-{env}")
            names.add(f"{env}-{b}")

        # Purpose suffixes
        for purpose in ["assets", "uploads", "media", "images", "static", "files",
                        "backup", "backups", "data", "db", "database", "logs",
                        "reports", "docs", "documents", "exports", "imports",
                        "public", "private", "internal", "web", "app", "api",
                        "config", "secrets", "keys", "certs", "ssl",
                        "builds", "artifacts", "deploy", "release"]:
            names.add(f"{b}-{purpose}")
            names.add(f"{purpose}-{b}")

        # Numbered variants
        for i in range(1, 4):
            names.add(f"{b}{i}")
            names.add(f"{b}-{i}")

    return sorted(names)


def check_s3_bucket(name):
    """Check if an S3 bucket exists and its permissions."""
    findings = {"name": name, "provider": "aws_s3", "exists": False}

    # Method 1: Direct URL access
    url = f"https://{name}.s3.amazonaws.com/"
    status, body = http_get(url)

    if status == 200:
        findings["exists"] = True
        findings["public_list"] = True
        findings["status"] = status
        # Count files if listing succeeded
        if "<Key>" in body:
            import re
            keys = re.findall(r"<Key>([^<]+)</Key>", body)
            findings["files_visible"] = len(keys)
            findings["sample_files"] = keys[:10]
        return findings
    elif status == 403:
        findings["exists"] = True
        findings["public_list"] = False
        findings["status"] = status
        return findings
    elif status == 404 or "NoSuchBucket" in body:
        return findings  # Doesn't exist

    # Method 2: Region-specific check
    url2 = f"https://s3.amazonaws.com/{name}/"
    status2, body2 = http_get(url2)
    if status2 in (200, 403):
        findings["exists"] = True
        findings["public_list"] = status2 == 200
        findings["status"] = status2

    return findings


def check_gcs_bucket(name):
    """Check if a GCS bucket exists and its permissions."""
    findings = {"name": name, "provider": "gcp_gcs", "exists": False}

    url = f"https://storage.googleapis.com/{name}/"
    status, body = http_get(url)

    if status == 200:
        findings["exists"] = True
        findings["public_list"] = True
        findings["status"] = status
    elif status == 403:
        findings["exists"] = True
        findings["public_list"] = False
        findings["status"] = status

    return findings


def check_azure_blob(name):
    """Check if an Azure Blob container exists."""
    findings = {"name": name, "provider": "azure_blob", "exists": False}

    # Azure blob: {account}.blob.core.windows.net/{container}
    # Try with name as account, "public" as container
    url = f"https://{name}.blob.core.windows.net/?comp=list"
    status, body = http_get(url)

    if status == 200:
        findings["exists"] = True
        findings["public_list"] = True
        findings["status"] = status
    elif status == 403:
        findings["exists"] = True
        findings["public_list"] = False
        findings["status"] = status

    return findings


def check_bucket(name, providers):
    """Check a bucket name across specified providers."""
    results = []

    if "aws" in providers or "all" in providers:
        r = check_s3_bucket(name)
        if r["exists"]:
            results.append(r)

    if "gcp" in providers or "all" in providers:
        r = check_gcs_bucket(name)
        if r["exists"]:
            results.append(r)

    if "azure" in providers or "all" in providers:
        r = check_azure_blob(name)
        if r["exists"]:
            results.append(r)

    return results


def main():
    parser = argparse.ArgumentParser(description="Bucket Enumerator - orizon.one")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--company", "-c", help="Company name for additional patterns")
    parser.add_argument("--provider", default="all", choices=["aws", "gcp", "azure", "all"])
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--custom-names", help="File with additional bucket names to try")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    log(f"Starting bucket enumeration for: {domain}")

    # Generate names
    names = generate_bucket_names(domain, args.company)

    if args.custom_names:
        custom = Path(args.custom_names).read_text().strip().split("\n")
        names.extend([n.strip() for n in custom if n.strip()])
        names = sorted(set(names))

    log(f"Testing {len(names)} bucket names against {args.provider} provider(s)...")

    all_found = []
    providers = [args.provider]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_bucket, name, providers): name for name in names}
        for future in concurrent.futures.as_completed(futures):
            results = future.result()
            for r in results:
                all_found.append(r)
                if r.get("public_list"):
                    vuln(f"PUBLIC BUCKET: {r['name']} ({r['provider']}) - Listing allowed!")
                else:
                    success(f"Bucket exists: {r['name']} ({r['provider']}) - Access denied (good)")

    # Categorize
    public_buckets = [b for b in all_found if b.get("public_list")]
    private_buckets = [b for b in all_found if not b.get("public_list")]

    output = {
        "meta": {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "bucket_enumeration",
            "tool": "cloud-pivot-finder by orizon.one",
            "names_tested": len(names),
        },
        "stats": {
            "total_found": len(all_found),
            "public_listing": len(public_buckets),
            "private": len(private_buckets),
        },
        "public_buckets": public_buckets,
        "private_buckets": private_buckets,
    }

    output_path = args.output or f"buckets_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  BUCKET ENUMERATION SUMMARY - {domain}")
    print(f"{'='*60}")
    print(f"  Names tested    : {len(names)}")
    print(f"  Buckets found   : {len(all_found)}")
    print(f"  PUBLIC (listing): {len(public_buckets)}")
    print(f"  Private         : {len(private_buckets)}")
    if public_buckets:
        print(f"\n  PUBLIC BUCKETS (CRITICAL):")
        for b in public_buckets:
            files = b.get("files_visible", "?")
            print(f"    {b['name']} ({b['provider']}) - {files} files visible")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
