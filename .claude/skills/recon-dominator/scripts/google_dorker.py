#!/usr/bin/env python3
"""
Google Dorking Module - recon-dominator
Generates and organizes Google dork queries for target domains.
Author: orizon.one
"""

import argparse
import json
import urllib.parse
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


# Dork categories with templates
DORK_DATABASE = {
    "sensitive_files": [
        'site:{domain} filetype:sql',
        'site:{domain} filetype:env',
        'site:{domain} filetype:log',
        'site:{domain} filetype:bak',
        'site:{domain} filetype:old',
        'site:{domain} filetype:conf',
        'site:{domain} filetype:cfg',
        'site:{domain} filetype:ini',
        'site:{domain} filetype:xml',
        'site:{domain} filetype:json',
        'site:{domain} filetype:yml OR filetype:yaml',
        'site:{domain} filetype:pem OR filetype:key',
        'site:{domain} filetype:csv',
        'site:{domain} filetype:xls OR filetype:xlsx',
        'site:{domain} filetype:doc OR filetype:docx',
        'site:{domain} filetype:pdf confidential OR internal',
    ],
    "exposed_panels": [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:portal',
        'site:{domain} inurl:panel',
        'site:{domain} inurl:manager',
        'site:{domain} inurl:console',
        'site:{domain} inurl:cpanel',
        'site:{domain} inurl:webmail',
        'site:{domain} intitle:"admin" inurl:admin',
        'site:{domain} intitle:"login" OR intitle:"sign in"',
        'site:{domain} inurl:wp-admin OR inurl:wp-login',
        'site:{domain} inurl:phpmyadmin',
        'site:{domain} inurl:adminer',
        'site:{domain} intitle:"grafana"',
        'site:{domain} intitle:"kibana"',
        'site:{domain} intitle:"jenkins"',
    ],
    "directory_listings": [
        'site:{domain} intitle:"index of"',
        'site:{domain} intitle:"index of" "parent directory"',
        'site:{domain} intitle:"index of" password',
        'site:{domain} intitle:"index of" backup',
        'site:{domain} intitle:"index of" .git',
        'site:{domain} intitle:"index of" .svn',
        'site:{domain} intitle:"index of" .env',
    ],
    "error_messages": [
        'site:{domain} "sql syntax" OR "mysql_fetch"',
        'site:{domain} "warning" "on line"',
        'site:{domain} "fatal error"',
        'site:{domain} "stack trace" OR "traceback"',
        'site:{domain} "exception" filetype:log',
        'site:{domain} "debug" "true"',
        'site:{domain} "server error" OR "500 internal"',
        'site:{domain} "not found" inurl:api',
    ],
    "api_endpoints": [
        'site:{domain} inurl:api',
        'site:{domain} inurl:graphql',
        'site:{domain} inurl:swagger',
        'site:{domain} inurl:api-docs',
        'site:{domain} inurl:openapi',
        'site:{domain} inurl:rest',
        'site:{domain} inurl:v1 OR inurl:v2 OR inurl:v3',
        'site:{domain} filetype:json inurl:api',
        'site:{domain} intitle:"API documentation"',
        'site:{domain} inurl:webhook',
    ],
    "cloud_exposure": [
        'site:s3.amazonaws.com "{domain}"',
        'site:storage.googleapis.com "{domain}"',
        'site:blob.core.windows.net "{domain}"',
        'site:digitaloceanspaces.com "{domain}"',
        '"{domain}" site:pastebin.com',
        '"{domain}" site:trello.com',
        '"{domain}" site:notion.so',
    ],
    "credentials_exposure": [
        'site:{domain} "password" filetype:txt OR filetype:log',
        'site:{domain} "username" "password"',
        'site:{domain} "api_key" OR "apikey" OR "api-key"',
        'site:{domain} "secret_key" OR "secret"',
        'site:{domain} "access_token" OR "auth_token"',
        'site:{domain} "private_key" OR "private key"',
        'site:{domain} "database_url" OR "db_password"',
        'site:{domain} "AWS_ACCESS_KEY" OR "aws_secret"',
    ],
    "git_exposure": [
        'site:{domain} inurl:.git',
        'site:{domain} intitle:"index of" ".git"',
        'site:{domain} inurl:.gitignore',
        'site:{domain} inurl:".env" -www',
        '"{domain}" site:github.com -site:{domain}',
        '"{domain}" site:gitlab.com',
        '"{domain}" site:bitbucket.org',
    ],
    "technology_specific": [
        'site:{domain} inurl:wp-content',
        'site:{domain} inurl:xmlrpc.php',
        'site:{domain} inurl:wp-json',
        'site:{domain} inurl:server-status',
        'site:{domain} inurl:server-info',
        'site:{domain} inurl:.php?id=',
        'site:{domain} inurl:include OR inurl:file= OR inurl:path=',
        'site:{domain} inurl:redirect= OR inurl:url= OR inurl:next=',
    ],
}


def generate_dorks(domain, categories=None):
    """Generate all dork queries for a domain."""
    results = {}

    cats = categories or DORK_DATABASE.keys()

    for category in cats:
        if category not in DORK_DATABASE:
            continue
        templates = DORK_DATABASE[category]
        results[category] = []
        for template in templates:
            query = template.format(domain=domain)
            search_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
            results[category].append({
                "query": query,
                "url": search_url
            })

    return results


def load_custom_dorks(dork_file):
    """Load custom dorks from file."""
    path = Path(dork_file)
    if not path.exists():
        return []
    dorks = []
    for line in path.read_text().strip().split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            dorks.append(line)
    return dorks


def main():
    parser = argparse.ArgumentParser(description="Google Dorker - orizon.one")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--dork-file", help="Custom dorks file (one per line, use {domain} placeholder)")
    parser.add_argument("--categories", nargs="+", help="Specific categories to run",
                        choices=list(DORK_DATABASE.keys()))
    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    log(f"Generating Google dorks for: {domain}")
    log(f"Timestamp: {datetime.utcnow().isoformat()}Z")

    # Generate dorks
    dorks = generate_dorks(domain, args.categories)

    # Add custom dorks if provided
    if args.dork_file:
        custom = load_custom_dorks(args.dork_file)
        if custom:
            dorks["custom"] = []
            for template in custom:
                query = template.replace("{domain}", domain)
                search_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
                dorks["custom"].append({"query": query, "url": search_url})
            success(f"Loaded {len(custom)} custom dorks")

    total_dorks = sum(len(v) for v in dorks.values())

    output = {
        "meta": {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "google_dorking",
            "tool": "recon-dominator by orizon.one",
            "total_dorks": total_dorks,
            "categories": list(dorks.keys())
        },
        "dorks": dorks
    }

    output_path = args.output or f"dorks_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  GOOGLE DORK SUMMARY - {domain}")
    print(f"{'='*60}")
    for category, queries in dorks.items():
        print(f"  {category:30s} : {len(queries):3d} dorks")
    print(f"{'='*60}")
    print(f"  {'TOTAL':30s} : {total_dorks:3d} dorks")
    print(f"{'='*60}")
    print(f"\n  NOTE: Open the URLs in a browser to execute searches.")
    print(f"  Results require manual review for relevance.\n")


if __name__ == "__main__":
    main()
