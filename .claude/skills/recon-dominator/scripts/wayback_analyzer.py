#!/usr/bin/env python3
"""
Wayback Machine Analyzer - recon-dominator
Extracts historical endpoints, parameters, JS files, and removed content.
Author: orizon.one
"""

import argparse
import json
import re
import ssl
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime
from collections import Counter


def log(msg):
    print(f"[*] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def success(msg):
    print(f"[+] {msg}")


def http_get(url, timeout=30):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        warn(f"Request failed: {e}")
        return None


def fetch_wayback_urls(domain, limit=10000):
    """Fetch all archived URLs for a domain from Wayback CDX API."""
    log(f"Fetching Wayback Machine URLs for {domain}...")
    url = (
        f"https://web.archive.org/cdx/search/cdx?"
        f"url=*.{urllib.parse.quote(domain)}/*"
        f"&output=json&fl=original,timestamp,statuscode,mimetype"
        f"&collapse=urlkey&limit={limit}"
    )
    data = http_get(url)
    if not data:
        return []
    try:
        rows = json.loads(data)
        if len(rows) < 2:
            return []
        headers = rows[0]
        entries = []
        for row in rows[1:]:
            entry = dict(zip(headers, row))
            entries.append(entry)
        success(f"Fetched {len(entries)} archived URLs")
        return entries
    except json.JSONDecodeError:
        warn("Failed to parse Wayback response")
        return []


def categorize_urls(entries, domain):
    """Categorize URLs by type and extract interesting patterns."""

    categories = {
        "api_endpoints": [],
        "javascript_files": [],
        "config_files": [],
        "backup_files": [],
        "admin_panels": [],
        "sensitive_paths": [],
        "parameters": [],
        "all_endpoints": [],
    }

    param_counter = Counter()
    path_counter = Counter()

    for entry in entries:
        url = entry.get("original", "")
        if not url:
            continue

        categories["all_endpoints"].append(url)

        # Parse URL
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        query = parsed.query

        # Extract parameters
        if query:
            params = urllib.parse.parse_qs(query)
            for param_name in params:
                param_counter[param_name] += 1
                categories["parameters"].append({
                    "url": url,
                    "parameter": param_name,
                    "values_seen": params[param_name][:3]
                })

        # Track unique paths
        path_counter[path] += 1

        # JavaScript files
        if path.endswith(".js") or ".js?" in path:
            categories["javascript_files"].append(url)

        # API endpoints
        if any(p in path for p in ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/ws/"]):
            categories["api_endpoints"].append(url)

        # Config / sensitive files
        sensitive_ext = [".env", ".config", ".cfg", ".ini", ".yml", ".yaml",
                        ".toml", ".xml", ".json", ".sql", ".bak", ".backup",
                        ".old", ".orig", ".save", ".swp", ".log"]
        if any(path.endswith(ext) for ext in sensitive_ext):
            categories["config_files"].append(url)

        # Backup patterns
        if any(p in path for p in ["/backup", "/bak/", ".bak", ".old", ".orig",
                                    "/dump", ".sql", ".tar", ".zip", ".gz"]):
            categories["backup_files"].append(url)

        # Admin panels
        if any(p in path for p in ["/admin", "/manager", "/dashboard", "/panel",
                                    "/console", "/cpanel", "/phpmyadmin", "/wp-admin"]):
            categories["admin_panels"].append(url)

        # Sensitive paths
        sensitive_paths = [
            "/.git/", "/.svn/", "/.env", "/.htaccess", "/.htpasswd",
            "/server-status", "/server-info", "/.well-known/",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/debug", "/trace", "/test", "/temp", "/tmp",
            "/internal", "/private", "/secret",
            "/phpinfo", "/info.php", "/elmah",
            "/.DS_Store", "/Thumbs.db", "/web.config",
        ]
        if any(p in path for p in sensitive_paths):
            categories["sensitive_paths"].append(url)

    # Deduplicate
    for key in categories:
        if key == "parameters":
            continue
        categories[key] = sorted(set(categories[key]))

    # Top parameters (potential injection points)
    categories["top_parameters"] = [
        {"name": name, "occurrences": count}
        for name, count in param_counter.most_common(50)
    ]

    return categories


def find_interesting_js(js_urls, domain):
    """Identify JS files that might contain secrets or API info."""
    interesting = []

    patterns_of_interest = [
        r"api[_-]?key", r"api[_-]?secret", r"token", r"auth",
        r"password", r"credential", r"secret", r"private",
        r"endpoint", r"base[_-]?url", r"internal",
        r"admin", r"debug", r"config", r"setting",
    ]

    for url in js_urls[:100]:  # Limit to avoid excessive requests
        # Just categorize by filename patterns (not fetching content to avoid detection)
        filename = url.split("/")[-1].split("?")[0].lower()
        for pattern in patterns_of_interest:
            if re.search(pattern, filename):
                interesting.append({
                    "url": url,
                    "matched_pattern": pattern,
                    "note": "Filename suggests potential sensitive content - manual review recommended"
                })
                break

    return interesting


def identify_removed_content(entries):
    """Find URLs that returned 200 before but are now likely removed."""
    log("Identifying potentially removed content...")

    url_history = {}
    for entry in entries:
        url = entry.get("original", "")
        status = entry.get("statuscode", "")
        timestamp = entry.get("timestamp", "")
        if url not in url_history:
            url_history[url] = []
        url_history[url].append({"timestamp": timestamp, "status": status})

    removed = []
    for url, history in url_history.items():
        if len(history) < 2:
            continue
        sorted_history = sorted(history, key=lambda x: x["timestamp"])
        if sorted_history[-1]["status"] in ["404", "403", "410"] and \
           any(h["status"] == "200" for h in sorted_history[:-1]):
            removed.append({
                "url": url,
                "was_available": True,
                "last_seen_live": next(h["timestamp"] for h in reversed(sorted_history) if h["status"] == "200"),
                "current_status": sorted_history[-1]["status"],
            })

    success(f"Found {len(removed)} potentially removed URLs")
    return removed[:200]  # Limit output


def main():
    parser = argparse.ArgumentParser(description="Wayback Analyzer - orizon.one")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--limit", type=int, default=10000, help="Max URLs to fetch from Wayback")
    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    log(f"Starting Wayback Machine analysis for: {domain}")
    log(f"Timestamp: {datetime.utcnow().isoformat()}Z")

    # Fetch archived URLs
    entries = fetch_wayback_urls(domain, args.limit)
    if not entries:
        warn("No Wayback data found")
        return

    # Categorize
    categories = categorize_urls(entries, domain)

    # Analyze JS files
    interesting_js = find_interesting_js(categories["javascript_files"], domain)

    # Find removed content
    removed = identify_removed_content(entries)

    output = {
        "meta": {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "wayback_analysis",
            "tool": "recon-dominator by orizon.one",
            "total_archived_urls": len(entries)
        },
        "categories": {
            "api_endpoints": categories["api_endpoints"][:200],
            "javascript_files": categories["javascript_files"][:200],
            "config_files": categories["config_files"],
            "backup_files": categories["backup_files"],
            "admin_panels": categories["admin_panels"],
            "sensitive_paths": categories["sensitive_paths"],
        },
        "parameters": {
            "top_parameters": categories["top_parameters"],
            "total_unique_params": len(set(p["parameter"] for p in categories["parameters"])),
        },
        "interesting_js": interesting_js,
        "removed_content": removed,
        "stats": {
            "total_urls": len(categories["all_endpoints"]),
            "unique_endpoints": len(set(categories["all_endpoints"])),
            "api_endpoints": len(categories["api_endpoints"]),
            "js_files": len(categories["javascript_files"]),
            "config_files": len(categories["config_files"]),
            "admin_panels": len(categories["admin_panels"]),
            "sensitive_paths": len(categories["sensitive_paths"]),
            "removed_pages": len(removed),
        }
    }

    output_path = args.output or f"wayback_{domain.replace('.', '_')}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Summary
    stats = output["stats"]
    print(f"\n{'='*60}")
    print(f"  WAYBACK ANALYSIS SUMMARY - {domain}")
    print(f"{'='*60}")
    print(f"  Total archived URLs : {stats['total_urls']}")
    print(f"  Unique endpoints    : {stats['unique_endpoints']}")
    print(f"  API endpoints       : {stats['api_endpoints']}")
    print(f"  JavaScript files    : {stats['js_files']}")
    print(f"  Config/sensitive    : {stats['config_files']}")
    print(f"  Admin panels        : {stats['admin_panels']}")
    print(f"  Sensitive paths     : {stats['sensitive_paths']}")
    print(f"  Removed content     : {stats['removed_pages']}")
    print(f"  Unique parameters   : {output['parameters']['total_unique_params']}")
    print(f"{'='*60}\n")

    if categories["top_parameters"][:5]:
        print("  Top parameters (potential injection points):")
        for p in categories["top_parameters"][:10]:
            print(f"    {p['name']:30s} ({p['occurrences']} occurrences)")
        print()


if __name__ == "__main__":
    main()
