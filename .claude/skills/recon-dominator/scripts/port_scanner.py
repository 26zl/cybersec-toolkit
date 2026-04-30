#!/usr/bin/env python3
"""
Port Scanner & Live Host Detection - recon-dominator
Probes hosts for open ports, services, and HTTP responses.
Author: orizon.one
"""

import argparse
import json
import socket
import subprocess
import ssl
import urllib.request
import concurrent.futures
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def success(msg):
    print(f"[+] {msg}")


TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000,
    8008, 8080, 8443, 8888, 9090, 9200, 9300, 27017
]

TOP_1000_PORTS = list(range(1, 1001)) + [
    1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2096, 3000, 3306,
    3389, 4443, 4567, 5000, 5432, 5900, 5985, 5986, 6379, 6443, 7443,
    8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9443,
    10000, 10250, 11211, 27017, 28017
]


def tcp_connect(host, port, timeout=3):
    """Basic TCP connect scan."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            # Try banner grab
            banner = ""
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            sock.close()
            return {"port": port, "state": "open", "banner": banner}
        sock.close()
        return None
    except (socket.timeout, OSError):
        return None


def http_probe(host, port=80, use_https=False, timeout=5):
    """Probe HTTP/HTTPS service for details."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            title = ""
            if "<title>" in body.lower():
                start = body.lower().index("<title>") + 7
                end = body.lower().index("</title>", start) if "</title>" in body.lower() else start + 100
                title = body[start:end].strip()

            headers = dict(resp.headers)

            return {
                "url": url,
                "status_code": resp.status,
                "title": title,
                "server": headers.get("Server", ""),
                "content_length": headers.get("Content-Length", ""),
                "x_powered_by": headers.get("X-Powered-By", ""),
                "content_type": headers.get("Content-Type", ""),
                "security_headers": {
                    "strict_transport_security": headers.get("Strict-Transport-Security", ""),
                    "content_security_policy": headers.get("Content-Security-Policy", ""),
                    "x_frame_options": headers.get("X-Frame-Options", ""),
                    "x_content_type_options": headers.get("X-Content-Type-Options", ""),
                    "x_xss_protection": headers.get("X-XSS-Protection", ""),
                },
                "redirect": headers.get("Location", ""),
            }
    except Exception as e:
        return None


def detect_waf(http_info):
    """Basic WAF/CDN detection from headers."""
    if not http_info:
        return "unknown"
    server = (http_info.get("server", "") or "").lower()
    headers_str = json.dumps(http_info).lower()

    waf_signatures = {
        "cloudflare": ["cloudflare", "cf-ray"],
        "akamai": ["akamai", "akamaighost"],
        "aws_cloudfront": ["cloudfront", "amz"],
        "aws_waf": ["awswaf", "aws-waf"],
        "imperva": ["imperva", "incapsula"],
        "f5_bigip": ["bigip", "f5"],
        "sucuri": ["sucuri"],
        "fastly": ["fastly"],
        "varnish": ["varnish"],
    }

    for waf_name, signatures in waf_signatures.items():
        for sig in signatures:
            if sig in headers_str:
                return waf_name
    return "none_detected"


def scan_host(host, ports, timeout=3):
    """Scan a single host across specified ports."""
    ip = None
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(tcp_connect, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    # HTTP probe on common web ports
    http_info = None
    https_info = None
    web_ports = [p["port"] for p in open_ports if p["port"] in [80, 8080, 8000, 8008, 8888]]
    ssl_ports = [p["port"] for p in open_ports if p["port"] in [443, 8443, 9443, 4443]]

    for port in web_ports[:1]:
        http_info = http_probe(host, port, use_https=False)
    for port in ssl_ports[:1]:
        https_info = http_probe(host, port, use_https=True)

    web_info = https_info or http_info
    waf = detect_waf(web_info)

    return {
        "host": host,
        "ip": ip,
        "open_ports": open_ports,
        "http": http_info,
        "https": https_info,
        "waf_cdn": waf,
    }


def run_nmap(host, ports_str="--top-ports 1000"):
    """Run nmap if available for more accurate results."""
    try:
        cmd = ["nmap", "-sV", "--open", "-T4", ports_str, host, "-oX", "-"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return result.stdout
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def run_httpx(hosts_file):
    """Run httpx (ProjectDiscovery) if installed for fast HTTP probing."""
    log("Checking for httpx...")
    try:
        result = subprocess.run(
            ["httpx", "-l", hosts_file, "-silent", "-json",
             "-status-code", "-title", "-tech-detect", "-server", "-follow-redirects"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            return []
        results = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        success(f"httpx: probed {len(results)} live hosts")
        return results
    except FileNotFoundError:
        warn("httpx not installed. Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return []
    except subprocess.TimeoutExpired:
        warn("httpx timed out")
        return []


def main():
    parser = argparse.ArgumentParser(description="Port Scanner - orizon.one")
    parser.add_argument("--input", "-i", required=True, help="File with hostnames (one per line) or JSON from recon")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--top-ports", type=int, default=100, choices=[100, 1000], help="Port count: 100 or 1000")
    parser.add_argument("--timeout", type=int, default=3, help="Connection timeout in seconds")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent hosts to scan")
    parser.add_argument("--batch-size", type=int, default=50, help="Process hosts in batches")
    args = parser.parse_args()

    log(f"Starting port scan...")
    log(f"Timestamp: {datetime.utcnow().isoformat()}Z")

    # Load hosts
    input_path = Path(args.input)
    hosts = []
    if input_path.suffix == ".json":
        with open(input_path) as f:
            data = json.load(f)
        if "subdomains" in data:
            hosts = [s["host"] for s in data["subdomains"]]
        else:
            hosts = [s.get("host", s) for s in data if isinstance(s, (str, dict))]
    else:
        hosts = [h.strip() for h in input_path.read_text().strip().split("\n") if h.strip()]

    log(f"Loaded {len(hosts)} hosts to scan")

    ports = TOP_100_PORTS if args.top_ports == 100 else TOP_1000_PORTS

    # Scan
    results = []
    for batch_start in range(0, len(hosts), args.batch_size):
        batch = hosts[batch_start:batch_start + args.batch_size]
        log(f"Scanning batch {batch_start // args.batch_size + 1} ({len(batch)} hosts)...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_host, host, ports, args.timeout): host for host in batch}
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                result = future.result()
                if result and result["open_ports"]:
                    port_list = [p["port"] for p in result["open_ports"]]
                    success(f"{host} ({result['ip']}): {len(result['open_ports'])} open ports: {port_list}")
                    results.append(result)
                elif result:
                    log(f"{host}: no open ports found")

    # Build output
    live_hosts = len(results)
    total_open = sum(len(r["open_ports"]) for r in results)

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "port_scan",
            "tool": "recon-dominator by orizon.one",
            "hosts_scanned": len(hosts),
            "live_hosts": live_hosts,
            "total_open_ports": total_open,
            "port_range": f"top-{args.top_ports}"
        },
        "results": results
    }

    output_path = args.output or "port_scan_results.json"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  PORT SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Hosts scanned : {len(hosts)}")
    print(f"  Live hosts    : {live_hosts}")
    print(f"  Open ports    : {total_open}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
