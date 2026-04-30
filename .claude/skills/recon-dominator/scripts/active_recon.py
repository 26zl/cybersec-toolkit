#!/usr/bin/env python3
"""
Active Reconnaissance Module - recon-dominator
DNS brute-force, zone transfers, and virtual host discovery.
Author: orizon.one
"""

import argparse
import json
import socket
import subprocess
import sys
import time
import concurrent.futures
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def success(msg):
    print(f"[+] {msg}")


def resolve_dns(hostname, timeout=3):
    """Resolve a hostname to IP addresses."""
    try:
        socket.setdefaulttimeout(timeout)
        answers = socket.getaddrinfo(hostname, None)
        ips = set()
        for answer in answers:
            ip = answer[4][0]
            ips.add(ip)
        return list(ips)
    except (socket.gaierror, socket.timeout, OSError):
        return []


def dns_bruteforce(domain, wordlist_path, threads=50, timeout=3):
    """Brute-force subdomains using a wordlist."""
    log(f"Starting DNS brute-force on {domain}...")

    wordlist = Path(wordlist_path)
    if not wordlist.exists():
        warn(f"Wordlist not found: {wordlist_path}")
        return []

    words = wordlist.read_text().strip().split("\n")
    words = [w.strip() for w in words if w.strip() and not w.startswith("#")]
    log(f"Loaded {len(words)} words from wordlist")

    found = {}

    def check_subdomain(word):
        hostname = f"{word}.{domain}"
        ips = resolve_dns(hostname, timeout)
        if ips:
            return (hostname, ips)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, word): word for word in words}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if done % 500 == 0:
                log(f"Progress: {done}/{len(words)} checked...")
            result = future.result()
            if result:
                hostname, ips = result
                found[hostname] = ips
                success(f"Found: {hostname} -> {', '.join(ips)}")

    success(f"DNS brute-force complete: {len(found)} subdomains found")
    return found


def attempt_zone_transfer(domain):
    """Attempt DNS zone transfer (AXFR)."""
    log(f"Attempting zone transfer on {domain}...")

    try:
        # Get nameservers
        result = subprocess.run(
            ["dig", "NS", domain, "+short"],
            capture_output=True, text=True, timeout=10
        )
        nameservers = [ns.strip().rstrip(".") for ns in result.stdout.strip().split("\n") if ns.strip()]

        if not nameservers:
            warn("No nameservers found")
            return []

        findings = []
        for ns in nameservers:
            log(f"Trying AXFR against {ns}...")
            result = subprocess.run(
                ["dig", "AXFR", domain, f"@{ns}"],
                capture_output=True, text=True, timeout=15
            )
            if "Transfer failed" not in result.stdout and "XFR size" in result.stdout:
                success(f"Zone transfer successful on {ns}!")
                findings.append({
                    "nameserver": ns,
                    "records": result.stdout
                })
            else:
                log(f"Zone transfer denied by {ns} (expected)")

        return findings
    except FileNotFoundError:
        warn("dig not installed, skipping zone transfer")
        return []
    except subprocess.TimeoutExpired:
        warn("Zone transfer timed out")
        return []


def permutation_scan(domain, base_subdomains=None, threads=30):
    """Generate and test subdomain permutations."""
    log("Running permutation scan...")

    prefixes = [
        "dev", "staging", "stage", "test", "testing", "qa", "uat",
        "api", "api-dev", "api-staging", "api-v2", "api-internal",
        "admin", "internal", "intranet", "vpn", "mail", "smtp",
        "ftp", "ssh", "db", "database", "redis", "mongo", "elastic",
        "jenkins", "gitlab", "git", "ci", "cd", "deploy", "build",
        "grafana", "kibana", "prometheus", "monitoring", "logs",
        "backup", "bak", "old", "new", "beta", "alpha", "canary",
        "cdn", "static", "assets", "media", "img", "images",
        "ws", "websocket", "socket", "realtime",
        "auth", "sso", "login", "oauth", "id", "identity",
        "sandbox", "demo", "poc", "temp", "tmp",
        "k8s", "kube", "docker", "swarm", "consul", "vault",
        "aws", "gcp", "azure", "cloud", "s3",
        "prod", "production", "live",
        "docs", "doc", "wiki", "help", "support",
        "shop", "store", "pay", "payment", "checkout",
    ]

    suffixes = ["-dev", "-staging", "-prod", "-api", "-internal", "-old", "-new", "-v2"]

    candidates = set()

    # prefix.domain
    for prefix in prefixes:
        candidates.add(f"{prefix}.{domain}")

    # If we have known subdomains, generate permutations
    if base_subdomains:
        for sub in base_subdomains[:50]:  # Limit to avoid explosion
            name = sub.replace(f".{domain}", "")
            for suffix in suffixes:
                candidates.add(f"{name}{suffix}.{domain}")
            for prefix in ["dev-", "staging-", "api-"]:
                candidates.add(f"{prefix}{name}.{domain}")

    log(f"Testing {len(candidates)} permutations...")
    found = {}

    def check(hostname):
        ips = resolve_dns(hostname, 3)
        if ips:
            return (hostname, ips)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check, c): c for c in candidates}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                hostname, ips = result
                found[hostname] = ips
                success(f"Permutation found: {hostname} -> {', '.join(ips)}")

    success(f"Permutation scan complete: {len(found)} found")
    return found


def run_puredns(domain, wordlist_path):
    """Run puredns if installed (fast massdns-based resolver)."""
    log("Checking for puredns...")
    try:
        result = subprocess.run(
            ["puredns", "bruteforce", wordlist_path, domain, "--quiet"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return {}
        found = {}
        for line in result.stdout.strip().split("\n"):
            host = line.strip().lower()
            if host:
                ips = resolve_dns(host, 3)
                found[host] = ips
        success(f"puredns: found {len(found)} subdomains")
        return found
    except FileNotFoundError:
        warn("puredns not installed. Install: go install github.com/d3mondev/puredns/v2@latest")
        return {}
    except subprocess.TimeoutExpired:
        warn("puredns timed out")
        return {}


def main():
    parser = argparse.ArgumentParser(description="Active Reconnaissance - orizon.one")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--wordlist", "-w", help="Subdomain wordlist path")
    parser.add_argument("--passive-results", "-p", help="JSON from passive_recon.py to enhance permutations")
    parser.add_argument("--output", "-o", help="Output JSON file path")
    parser.add_argument("--threads", "-t", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--skip-bruteforce", action="store_true", help="Skip DNS brute-force")
    parser.add_argument("--skip-permutations", action="store_true", help="Skip permutation scan")
    parser.add_argument("--skip-zone-transfer", action="store_true", help="Skip zone transfer attempt")
    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    log(f"Starting active reconnaissance on: {domain}")
    log(f"Timestamp: {datetime.utcnow().isoformat()}Z")

    all_found = {}

    # Load passive results for permutation enhancement
    base_subdomains = []
    if args.passive_results:
        try:
            with open(args.passive_results) as f:
                passive = json.load(f)
            base_subdomains = [s["host"] for s in passive.get("subdomains", [])]
            log(f"Loaded {len(base_subdomains)} subdomains from passive results")
        except Exception as e:
            warn(f"Could not load passive results: {e}")

    # Zone transfer
    zone_transfer_results = []
    if not args.skip_zone_transfer:
        zone_transfer_results = attempt_zone_transfer(domain)

    # DNS brute-force
    if not args.skip_bruteforce:
        wordlist = args.wordlist
        if not wordlist:
            # Use default wordlist
            default_wl = Path(__file__).parent.parent / "references" / "subdomains-wordlist.txt"
            if default_wl.exists():
                wordlist = str(default_wl)
            else:
                warn("No wordlist specified and default not found. Skipping brute-force.")
                wordlist = None

        if wordlist:
            # Try puredns first (faster), fallback to built-in
            puredns_results = run_puredns(domain, wordlist)
            if puredns_results:
                all_found.update(puredns_results)
            else:
                bruteforce_results = dns_bruteforce(domain, wordlist, args.threads)
                all_found.update(bruteforce_results)

    # Permutation scan
    if not args.skip_permutations:
        perm_results = permutation_scan(domain, base_subdomains, args.threads)
        all_found.update(perm_results)

    success(f"Total unique subdomains from active recon: {len(all_found)}")

    # Build output
    output = {
        "meta": {
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "active_recon",
            "tool": "recon-dominator by orizon.one",
            "total_unique": len(all_found)
        },
        "zone_transfer": zone_transfer_results,
        "subdomains": [
            {"host": host, "ips": ips, "source": "active"}
            for host, ips in sorted(all_found.items())
        ]
    }

    output_path = args.output
    if not output_path:
        output_path = f"active_recon_{domain.replace('.', '_')}.json"

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  ACTIVE RECON SUMMARY - {domain}")
    print(f"{'='*60}")
    if zone_transfer_results:
        print(f"  ZONE TRANSFER: SUCCESSFUL ({len(zone_transfer_results)} servers)")
    else:
        print(f"  Zone transfer: denied (normal)")
    print(f"  Subdomains found: {len(all_found)}")
    print(f"{'='*60}\n")

    return output


if __name__ == "__main__":
    main()
