#!/usr/bin/env python3
"""
Passive Reconnaissance Module - recon-dominator
Collects subdomains and intelligence without direct target contact.
Author: orizon.one
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.request
import urllib.parse
import ssl
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def error(msg):
    print(f"[-] {msg}")


def success(msg):
    print(f"[+] {msg}")


def http_get(url, timeout=15):
    """Simple HTTP GET without external dependencies."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        warn(f"HTTP request failed for {url}: {e}")
        return None


def query_crtsh(domain, delay=2):
    """Query Certificate Transparency logs via crt.sh."""
    log(f"Querying crt.sh for {domain}...")
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    data = http_get(url, timeout=30)
    if not data:
        return []
    try:
        entries = json.loads(data)
    except json.JSONDecodeError:
        warn("Failed to parse crt.sh response")
        return []
    subdomains = set()
    for entry in entries:
        name = entry.get("name_value", "")
        for line in name.split("\n"):
            line = line.strip().lower()
            if line.endswith(f".{domain}") or line == domain:
                if "*" not in line:
                    subdomains.add(line)
    success(f"crt.sh: found {len(subdomains)} unique subdomains")
    time.sleep(delay)
    return list(subdomains)


def query_hackertarget(domain, delay=2):
    """Query HackerTarget free API for subdomains."""
    log(f"Querying HackerTarget for {domain}...")
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    data = http_get(url)
    if not data or "error" in data.lower():
        return []
    subdomains = set()
    for line in data.strip().split("\n"):
        parts = line.split(",")
        if parts:
            host = parts[0].strip().lower()
            if host.endswith(f".{domain}") or host == domain:
                subdomains.add(host)
    success(f"HackerTarget: found {len(subdomains)} unique subdomains")
    time.sleep(delay)
    return list(subdomains)


def query_rapiddns(domain, delay=2):
    """Query RapidDNS for subdomains."""
    log(f"Querying RapidDNS for {domain}...")
    url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1"
    data = http_get(url, timeout=20)
    if not data:
        return []
    subdomains = set()
    import re
    pattern = re.compile(r"([a-zA-Z0-9\-\.]+\." + re.escape(domain) + r")")
    for match in pattern.finditer(data):
        sub = match.group(1).lower()
        subdomains.add(sub)
    success(f"RapidDNS: found {len(subdomains)} unique subdomains")
    time.sleep(delay)
    return list(subdomains)


def run_subfinder(domain):
    """Run subfinder if installed (ProjectDiscovery Go tool)."""
    log("Checking for subfinder...")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-json"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            warn(f"subfinder error: {result.stderr.strip()}")
            return []
        subdomains = set()
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get("host", "").lower()
                if host:
                    subdomains.add(host)
            except json.JSONDecodeError:
                host = line.strip().lower()
                if host:
                    subdomains.add(host)
        success(f"subfinder: found {len(subdomains)} unique subdomains")
        return list(subdomains)
    except FileNotFoundError:
        warn("subfinder not installed. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return []
    except subprocess.TimeoutExpired:
        warn("subfinder timed out")
        return []


def run_amass_passive(domain):
    """Run amass passive enum if installed."""
    log("Checking for amass...")
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-json", "-"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return []
        subdomains = set()
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                entry = json.loads(line)
                name = entry.get("name", "").lower()
                if name:
                    subdomains.add(name)
            except json.JSONDecodeError:
                pass
        success(f"amass: found {len(subdomains)} unique subdomains")
        return list(subdomains)
    except FileNotFoundError:
        warn("amass not installed. Install: go install -v github.com/owasp-amass/amass/v4/...@master")
        return []
    except subprocess.TimeoutExpired:
        warn("amass timed out")
        return []


def query_wayback_subdomains(domain, delay=2):
    """Extract subdomains from Wayback Machine."""
    log(f"Querying Wayback Machine for {domain}...")
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{urllib.parse.quote(domain)}/*&output=json&fl=original&collapse=urlkey&limit=5000"
    data = http_get(url, timeout=30)
    if not data:
        return []
    try:
        entries = json.loads(data)
    except json.JSONDecodeError:
        return []
    subdomains = set()
    import re
    pattern = re.compile(r"https?://([a-zA-Z0-9\-\.]+\." + re.escape(domain) + r")")
    for entry in entries:
        if isinstance(entry, list) and entry:
            url_str = entry[0]
            match = pattern.match(url_str)
            if match:
                subdomains.add(match.group(1).lower())
    success(f"Wayback: found {len(subdomains)} unique subdomains")
    time.sleep(delay)
    return list(subdomains)


def merge_results(all_results):
    """Merge and deduplicate results from all sources."""
    merged = {}
    for source, subdomains in all_results.items():
        for sub in subdomains:
            sub = sub.strip().lower().rstrip(".")
            if sub not in merged:
                merged[sub] = []
            merged[sub].append(source)
    return merged


def main():
    parser = argparse.ArgumentParser(description="Passive Reconnaissance - orizon.one")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--output", "-o", help="Output JSON file path")
    parser.add_argument("--delay", type=int, default=2, help="Delay between API calls (seconds)")
    parser.add_argument("--skip-tools", action="store_true", help="Skip external tools (subfinder, amass)")
    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    log(f"Starting passive reconnaissance on: {domain}")
    log(f"Timestamp: {datetime.utcnow().isoformat()}Z")

    all_results = {}

    # Built-in sources (no external tools needed)
    all_results["crt.sh"] = query_crtsh(domain, args.delay)
    all_results["hackertarget"] = query_hackertarget(domain, args.delay)
    all_results["rapiddns"] = query_rapiddns(domain, args.delay)
    all_results["wayback"] = query_wayback_subdomains(domain, args.delay)

    # External Go tools (optional)
    if not args.skip_tools:
        all_results["subfinder"] = run_subfinder(domain)
        all_results["amass"] = run_amass_passive(domain)

    # Merge
    merged = merge_results(all_results)
    total = len(merged)

    success(f"Total unique subdomains found: {total}")

    # Build output
    output = {
        "meta": {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "passive_recon",
            "tool": "recon-dominator by orizon.one",
            "sources_used": list(all_results.keys()),
            "total_unique": total
        },
        "source_counts": {src: len(subs) for src, subs in all_results.items()},
        "subdomains": [
            {"host": sub, "sources": sources}
            for sub, sources in sorted(merged.items())
        ]
    }

    # Output
    output_path = args.output
    if not output_path:
        output_path = f"passive_recon_{domain.replace('.', '_')}.json"

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Print summary
    print(f"\n{'='*60}")
    print(f"  PASSIVE RECON SUMMARY - {domain}")
    print(f"{'='*60}")
    for source, count in output["source_counts"].items():
        print(f"  {source:20s} : {count:5d} subdomains")
    print(f"{'='*60}")
    print(f"  {'TOTAL UNIQUE':20s} : {total:5d} subdomains")
    print(f"{'='*60}\n")

    return output


if __name__ == "__main__":
    main()
