#!/usr/bin/env python3
"""
CI/CD and IaC Exposure Finder - cloud-pivot-finder
Discovers exposed CI/CD interfaces, Terraform state, CloudFormation templates,
Docker/K8s configs, and environment files on target hosts.
Author: orizon.one
"""

import argparse
import json
import re
import ssl
import urllib.request
import urllib.error
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


# Paths to probe for CI/CD and IaC exposure
PROBE_PATHS = {
    "jenkins": {
        "paths": [
            "/jenkins/",
            "/jenkins/login",
            "/jenkins/api/json",
            "/jenkins/script",
            "/jenkins/manage",
            "/j/",
            "/ci/",
            "/build/",
        ],
        "signatures": ["Dashboard [Jenkins]", "Jenkins", "X-Jenkins", "jenkins-hierarchical"],
        "severity": "critical",
        "description": "Exposed Jenkins CI/CD server",
    },
    "gitlab_ci": {
        "paths": [
            "/.gitlab-ci.yml",
            "/gitlab/",
            "/gitlab/users/sign_in",
            "/api/v4/projects",
        ],
        "signatures": ["gitlab", "GitLab", "stages:", "script:"],
        "severity": "high",
        "description": "Exposed GitLab CI configuration or instance",
    },
    "github_actions": {
        "paths": [
            "/.github/workflows/",
            "/.github/workflows/ci.yml",
            "/.github/workflows/deploy.yml",
            "/.github/workflows/build.yml",
            "/.github/workflows/main.yml",
            "/.github/workflows/release.yml",
        ],
        "signatures": ["on:", "jobs:", "runs-on:", "steps:", "uses:"],
        "severity": "medium",
        "description": "Exposed GitHub Actions workflow files",
    },
    "terraform_state": {
        "paths": [
            "/terraform.tfstate",
            "/terraform.tfstate.backup",
            "/.terraform/",
            "/tfstate",
            "/state.tf",
            "/main.tf",
            "/variables.tf",
            "/backend.tf",
        ],
        "signatures": ["terraform", "tfstate", "aws_", "google_", "azurerm_",
                       "resource", "provider", "module"],
        "severity": "critical",
        "description": "Exposed Terraform state or configuration files",
    },
    "cloudformation": {
        "paths": [
            "/template.yaml",
            "/template.json",
            "/cloudformation.yaml",
            "/cloudformation.json",
            "/cfn-template.yaml",
            "/stack.yaml",
            "/sam-template.yaml",
        ],
        "signatures": ["AWSTemplateFormatVersion", "Resources:", "AWS::"],
        "severity": "high",
        "description": "Exposed CloudFormation/SAM templates",
    },
    "docker_compose": {
        "paths": [
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/docker-compose.prod.yml",
            "/docker-compose.dev.yml",
            "/docker-compose.override.yml",
            "/Dockerfile",
            "/.dockerenv",
        ],
        "signatures": ["services:", "version:", "image:", "volumes:", "FROM ", "RUN "],
        "severity": "high",
        "description": "Exposed Docker configuration files",
    },
    "kubernetes": {
        "paths": [
            "/k8s/",
            "/kubernetes/",
            "/deployment.yaml",
            "/deployment.yml",
            "/service.yaml",
            "/ingress.yaml",
            "/configmap.yaml",
            "/secret.yaml",
            "/kustomization.yaml",
            "/values.yaml",
            "/Chart.yaml",
            "/helmfile.yaml",
        ],
        "signatures": ["apiVersion:", "kind:", "metadata:", "spec:", "containers:",
                       "replicas:", "selector:"],
        "severity": "high",
        "description": "Exposed Kubernetes manifests or Helm charts",
    },
    "env_files": {
        "paths": [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.staging",
            "/.env.development",
            "/.env.backup",
            "/.env.example",
            "/env",
            "/config/.env",
            "/app/.env",
        ],
        "signatures": ["AWS_ACCESS_KEY", "AWS_SECRET", "DATABASE_URL", "DB_PASSWORD",
                       "API_KEY", "SECRET_KEY", "PRIVATE_KEY", "TOKEN",
                       "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
                       "REDIS_URL", "MONGO_URI", "SMTP_PASSWORD"],
        "severity": "critical",
        "description": "Exposed environment files with potential credentials",
    },
    "git_exposure": {
        "paths": [
            "/.git/config",
            "/.git/HEAD",
            "/.gitignore",
            "/.git/logs/HEAD",
        ],
        "signatures": ["[core]", "[remote", "ref:", "repositoryformatversion",
                       ".env", "node_modules"],
        "severity": "high",
        "description": "Exposed Git repository metadata",
    },
    "ci_artifacts": {
        "paths": [
            "/artifacts/",
            "/builds/",
            "/releases/",
            "/dist/",
            "/build/",
            "/output/",
            "/.circleci/config.yml",
            "/Jenkinsfile",
            "/Makefile",
            "/Rakefile",
            "/Gruntfile.js",
            "/Gulpfile.js",
            "/webpack.config.js",
        ],
        "signatures": ["pipeline", "stage", "deploy", "build", "test",
                       "npm run", "make ", "rake "],
        "severity": "medium",
        "description": "Exposed CI/CD artifacts or build configurations",
    },
    "package_managers": {
        "paths": [
            "/package.json",
            "/package-lock.json",
            "/yarn.lock",
            "/Gemfile",
            "/Gemfile.lock",
            "/requirements.txt",
            "/Pipfile",
            "/Pipfile.lock",
            "/go.mod",
            "/go.sum",
            "/composer.json",
            "/composer.lock",
        ],
        "signatures": ["dependencies", "devDependencies", "scripts", "gem ",
                       "require", "module "],
        "severity": "low",
        "description": "Exposed package manager files (dependency information)",
    },
}

# S3/GCS paths for Terraform state
CLOUD_STATE_URLS = {
    "s3_tfstate": [
        "https://{name}.s3.amazonaws.com/terraform.tfstate",
        "https://{name}.s3.amazonaws.com/env/prod/terraform.tfstate",
        "https://{name}.s3.amazonaws.com/env/dev/terraform.tfstate",
        "https://{name}.s3.amazonaws.com/state/terraform.tfstate",
    ],
    "gcs_tfstate": [
        "https://storage.googleapis.com/{name}/terraform.tfstate",
        "https://storage.googleapis.com/{name}/default.tfstate",
    ],
}


def http_get(url, timeout=5):
    """HTTP GET with SSL bypass."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "orizon-recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = dict(resp.headers)
            body = resp.read(32768).decode("utf-8", errors="replace")
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if hasattr(e, "headers") else {}
        body = ""
        try:
            body = e.read(8192).decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, headers, body
    except Exception:
        return 0, {}, ""


def probe_host_path(host, path, category_info):
    """Probe a single host+path combination."""
    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}{path}"
        status, headers, body = http_get(url)

        if status == 0:
            continue

        # Skip generic 404 pages and redirects to login
        if status == 404:
            continue
        if status in (301, 302) and "/login" in headers.get("Location", ""):
            # Redirect to login means something exists there
            pass

        # Check for signature matches
        matched_signatures = []
        combined = body + " " + json.dumps(headers)
        for sig in category_info["signatures"]:
            if sig.lower() in combined.lower():
                matched_signatures.append(sig)

        if status == 200 and matched_signatures:
            return {
                "url": url,
                "status": status,
                "matched_signatures": matched_signatures,
                "content_preview": body[:500],
                "content_length": len(body),
            }
        elif status == 200 and len(body) > 50:
            # Got a 200 with content but no signature match - still interesting
            return {
                "url": url,
                "status": status,
                "matched_signatures": [],
                "content_preview": body[:300],
                "content_length": len(body),
                "note": "Response returned but no signature match - manual review needed",
            }
        elif status == 403:
            return {
                "url": url,
                "status": 403,
                "matched_signatures": [],
                "note": "Access denied - resource exists but is protected",
            }

        break  # If HTTPS responded, skip HTTP

    return None


def scan_host(host, categories=None):
    """Scan a single host for CI/CD and IaC exposure."""
    findings = []
    cats = categories or list(PROBE_PATHS.keys())

    for cat_name in cats:
        cat_info = PROBE_PATHS[cat_name]
        for path in cat_info["paths"]:
            result = probe_host_path(host, path, cat_info)
            if result:
                findings.append({
                    "host": host,
                    "category": cat_name,
                    "severity": cat_info["severity"],
                    "description": cat_info["description"],
                    "probe": result,
                })

    return findings


def check_cloud_state_files(domain):
    """Check for Terraform state files on cloud storage."""
    findings = []
    base = domain.replace(".", "-")
    name = domain.split(".")[0]

    bucket_names = [name, base, f"{name}-terraform", f"{name}-tfstate",
                    f"{base}-terraform", f"{base}-state", f"{name}-infra"]

    for bucket_name in bucket_names:
        for storage_type, url_templates in CLOUD_STATE_URLS.items():
            for template in url_templates:
                url = template.format(name=bucket_name)
                status, headers, body = http_get(url)
                if status == 200 and ("terraform" in body.lower() or "tfstate" in body.lower()):
                    findings.append({
                        "category": "cloud_terraform_state",
                        "severity": "critical",
                        "description": "Terraform state file exposed on cloud storage",
                        "url": url,
                        "storage_type": storage_type,
                        "content_preview": body[:500],
                    })
                    vuln(f"TERRAFORM STATE EXPOSED: {url}")

    return findings


def load_hosts(args):
    """Load target hosts from arguments."""
    hosts = []
    if args.domain:
        hosts.append(args.domain.strip().lower())

    if args.input:
        p = Path(args.input)
        if p.suffix == ".json":
            with open(p) as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        hosts.append(item)
                    elif isinstance(item, dict):
                        for key in ("host", "hostname", "domain", "name"):
                            if key in item and isinstance(item[key], str):
                                hosts.append(item[key])
                                break
            elif isinstance(data, dict):
                for key in ("subdomains", "hosts", "domains", "results", "targets"):
                    if key in data and isinstance(data[key], list):
                        for item in data[key]:
                            if isinstance(item, str):
                                hosts.append(item)
                            elif isinstance(item, dict):
                                for k in ("host", "hostname", "domain", "name"):
                                    if k in item and isinstance(item[k], str):
                                        hosts.append(item[k])
                                        break
        else:
            hosts.extend([h.strip() for h in p.read_text().strip().split("\n") if h.strip()])

    return list(dict.fromkeys(h.lower().strip() for h in hosts if h.strip()))


def main():
    parser = argparse.ArgumentParser(description="CI/CD and IaC Finder - orizon.one")
    parser.add_argument("--domain", "-d", help="Target domain")
    parser.add_argument("--input", "-i", help="File with hostnames or recon JSON")
    parser.add_argument("--output", "-o", help="Output JSON file")
    parser.add_argument("--threads", type=int, default=15,
                        help="Number of concurrent threads (default: 15)")
    parser.add_argument("--categories", "-c", nargs="+",
                        choices=list(PROBE_PATHS.keys()),
                        help="Specific categories to check")
    parser.add_argument("--check-cloud-state", action="store_true",
                        help="Also check cloud storage for Terraform state files")
    args = parser.parse_args()

    if not args.domain and not args.input:
        parser.error("Provide --domain or --input")

    log("Starting CI/CD and IaC exposure scan...")

    hosts = load_hosts(args)
    log(f"Scanning {len(hosts)} host(s) for CI/CD and IaC exposure...")

    all_findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_host, host, args.categories): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            findings = future.result()
            for f in findings:
                all_findings.append(f)
                sev = f["severity"].upper()
                if sev == "CRITICAL":
                    vuln(f"[{sev}] {f['host']}: {f['description']} - {f['probe']['url']}")
                elif sev == "HIGH":
                    warn(f"[{sev}] {f['host']}: {f['description']} - {f['probe']['url']}")
                else:
                    success(f"[{sev}] {f['host']}: {f['description']} - {f['probe']['url']}")

    # Cloud state file checks
    cloud_state_findings = []
    if args.check_cloud_state and args.domain:
        log("Checking cloud storage for Terraform state files...")
        cloud_state_findings = check_cloud_state_files(args.domain)
        all_findings.extend(cloud_state_findings)

    # Categorize by severity
    critical = [f for f in all_findings if f["severity"] == "critical"]
    high = [f for f in all_findings if f["severity"] == "high"]
    medium = [f for f in all_findings if f["severity"] == "medium"]
    low = [f for f in all_findings if f["severity"] == "low"]

    # Categorize by type
    by_category = {}
    for f in all_findings:
        cat = f["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(f)

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "cicd_iac_exposure",
            "tool": "cloud-pivot-finder by orizon.one",
            "domain": args.domain or "multi",
            "hosts_scanned": len(hosts),
        },
        "stats": {
            "total_findings": len(all_findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
        },
        "findings_by_severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "findings_by_category": by_category,
    }

    domain_label = (args.domain or "multi").replace(".", "_")
    output_path = args.output or f"cicd_exposure_{domain_label}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  CI/CD AND IaC EXPOSURE SUMMARY")
    print(f"{'='*60}")
    print(f"  Hosts scanned : {len(hosts)}")
    print(f"  Total findings: {len(all_findings)}")
    print(f"    Critical    : {len(critical)}")
    print(f"    High        : {len(high)}")
    print(f"    Medium      : {len(medium)}")
    print(f"    Low         : {len(low)}")
    if critical:
        print(f"\n  CRITICAL FINDINGS:")
        for f in critical:
            print(f"    {f['host']}: {f['description']}")
            print(f"      URL: {f['probe']['url'] if 'probe' in f else f.get('url', 'N/A')}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
