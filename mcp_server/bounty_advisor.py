"""Bug bounty target-type to module/tool mapping with curated suggestions."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Optional

_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server.ctf_advisor import TOOL_ALIASES  # noqa: E402
from mcp_server.tools_db import ToolsDatabase  # noqa: E402

# Maps target type -> description, relevant modules, top tools, methodology,
# quick_wins, and common_vulns.
BOUNTY_TARGET_MAP: dict[str, dict] = {
    "web_app": {
        "description": "Web app testing — OWASP Top 10, business logic, auth bypass, deserialization",
        "modules": ["web", "recon", "networking"],
        "tools": [
            ("mitmproxy", "Intercepting HTTP/HTTPS proxy for request tampering"),
            ("sqlmap", "Automatic SQL injection detection and exploitation"),
            ("nuclei", "Template-based vulnerability scanner with community rules"),
            ("ffuf", "Fast web fuzzer for directories, parameters, and vhosts"),
            ("gobuster", "Directory/DNS/vhost brute-forcing"),
            ("nikto", "Web server vulnerability scanner"),
            ("httpx", "Fast HTTP toolkit for probing and tech detection"),
            ("whatweb", "Web technology fingerprinting"),
            ("dalfox", "XSS parameter analysis and scanning"),
            ("arjun", "HTTP parameter discovery"),
            ("jwt-tool", "JWT token testing and exploitation"),
            ("feroxbuster", "Fast recursive content discovery"),
            ("subfinder", "Subdomain discovery for attack surface mapping"),
            ("amass", "In-depth attack surface mapping and asset discovery"),
        ],
        "methodology": [
            "0. SCOPE: Verify target is in scope — check program rules, domain/IP boundaries",
            "1. RECON: Subdomain enum (subfinder, amass), tech fingerprint (whatweb, httpx). "
            "Note exact framework + version from X-Powered-By, Server, JS bundle paths",
            "2. ENUMERATE: ffuf/gobuster for dirs, arjun for hidden params. "
            "Read JS bundles for internal API routes, server action IDs, build manifests",
            "3. ANALYZE: Map auth flows, session handling, API structure. "
            "Check if reverse proxy (nginx/cloudflare) and backend disagree on path parsing",
            "4. TEST: SQLi, XSS, SSTI, SSRF, IDOR, deserialization, prototype pollution, "
            "file upload, race conditions. If WAF blocks: fuzz which keywords trigger it, "
            "then bypass with encoding, string concat, or alternate APIs",
            "5. VALIDATE: Minimal PoC only — respect rate limits (back off on 429s), "
            "do not exfiltrate data beyond proof of access",
            "6. REPORT: Clear title, repro steps, impact, remediation — redact creds and PII",
        ],
        "quick_wins": [
            "Run nuclei with default templates on all discovered endpoints",
            "Test for IDOR by changing numeric IDs in authenticated requests",
            "Check for exposed .git, .env, backup files, and admin panels",
            "Test all input fields for reflected XSS with basic payloads",
            "Check CORS configuration and CSP headers",
        ],
        "common_vulns": [
            "SQL Injection (SQLi)",
            "Cross-Site Scripting (XSS) — reflected, stored, DOM-based",
            "Insecure Direct Object Reference (IDOR)",
            "Server-Side Request Forgery (SSRF) — to internal services or cloud metadata (169.254.169.254)",
            "Broken Authentication and Session Management",
            "Cross-Site Request Forgery (CSRF)",
            "Server-Side Template Injection (SSTI)",
            "Unsafe Deserialization — Java (readObject), PHP (unserialize), Python (pickle), "
            "Node.js (prototype pollution via JSON merge, React Flight payloads)",
            "File Upload vulnerabilities",
            "Race conditions / TOCTOU",
            "Information disclosure via error messages, headers, or stack traces",
        ],
        "notable_cves": [
            "CVE-2025-55182 — React2Shell: RCE via React Flight protocol deserialization. "
            "Multipart POST with __proto__/constructor chain reaches Function constructor. "
            "Affects any app with React Server Components (Next.js App Router, etc.)",
            "CVE-2025-29927 — Next.js middleware bypass via x-middleware-subrequest header. "
            "Skips auth middleware, exposes protected API routes and server actions",
            "CVE-2021-44228 — Log4Shell: Java JNDI injection via ${jndi:ldap://...}. "
            "Test in all headers, form fields, and URL parameters",
            "CVE-2023-44487 — HTTP/2 Rapid Reset DoS (report existence, do not exploit)",
            "CVE-2023-46747 — F5 BIG-IP unauthenticated RCE via /mgmt/tm/util/bash",
            "CVE-2024-34102 — Adobe Commerce/Magento XXE to RCE via crafted XML layout",
        ],
    },
    "api": {
        "description": "REST/GraphQL API testing — authentication, authorization, rate limiting, injection",
        "modules": ["web", "recon"],
        "tools": [
            ("mitmproxy", "API traffic interception and modification"),
            ("nuclei", "Template-based API vulnerability scanning"),
            ("ffuf", "API endpoint and parameter fuzzing"),
            ("arjun", "Hidden parameter discovery"),
            ("jwt-tool", "JWT token manipulation and attack"),
            ("sqlmap", "SQL injection via API parameters"),
            ("httpx", "Fast HTTP probing for API endpoints"),
            ("gobuster", "API endpoint enumeration"),
            ("dalfox", "XSS testing in API responses"),
            ("trufflehog", "Secret scanning in API responses and docs"),
        ],
        "methodology": [
            "0. SCOPE: Verify API endpoints are in scope — check versioned paths, staging vs production",
            "1. RECON: Map API endpoints from docs (Swagger/OpenAPI), JS source, mobile app traffic",
            "2. ENUMERATE: Fuzz endpoints (ffuf), discover hidden parameters (arjun), test HTTP methods",
            "3. AUTH: Test JWT manipulation (jwt-tool), token reuse, session fixation, OAuth flaws",
            "4. AUTHZ: Test IDOR, privilege escalation, horizontal/vertical access control bypass",
            "5. INJECT: SQL injection, NoSQL injection, GraphQL injection, mass assignment "
            "— respect rate limits, back off on 429 responses",
            "6. REPORT: Document endpoint, method, payload, response, and business impact "
            "— redact tokens and credentials from examples",
        ],
        "quick_wins": [
            "Check for exposed API documentation (Swagger UI, /api-docs, /graphql)",
            "Test IDOR by modifying resource IDs in authenticated requests",
            "Try accessing admin endpoints with regular user tokens",
            "Test rate limiting on sensitive endpoints (login, password reset)",
            "Check for mass assignment by adding extra fields to POST/PUT requests",
            "Look for verbose error messages leaking stack traces or internal paths",
        ],
        "common_vulns": [
            "Broken Object Level Authorization (BOLA/IDOR)",
            "Broken Authentication (weak tokens, no expiry)",
            "Broken Function Level Authorization (admin endpoints)",
            "Mass Assignment / Excessive Data Exposure",
            "Rate Limiting bypass",
            "SQL/NoSQL Injection via API parameters",
            "GraphQL introspection and injection",
            "JWT algorithm confusion (none, HS256 vs RS256)",
            "SSRF via URL parameters",
            "Improper inventory management (shadow/deprecated APIs)",
        ],
    },
    "mobile_app": {
        "description": "Mobile application testing — APK analysis, API interception, local storage, binary protections",
        "modules": ["mobile", "web", "reversing"],
        "tools": [
            ("apktool", "APK reverse engineering and resource extraction"),
            ("jadx", "DEX to Java decompiler for source review"),
            ("frida-tools", "Dynamic instrumentation and runtime hooking"),
            ("objection", "Runtime mobile exploration (SSL bypass, root bypass)"),
            ("androguard", "Android app static analysis"),
            ("mitmproxy", "API traffic interception from mobile apps"),
            ("nuclei", "Scanning discovered API endpoints"),
            ("trufflehog", "Secret scanning in decompiled source"),
            ("sqlmap", "SQL injection on discovered API endpoints"),
            ("httpx", "Probing discovered backend endpoints"),
        ],
        "methodology": [
            "0. SCOPE: Verify app and its backend APIs are in scope — check app store listing, program rules",
            "1. STATIC: Decompile APK (apktool, jadx), search for hardcoded secrets, API keys, endpoints",
            "2. CONFIG: Check AndroidManifest.xml for exported components, debug flags, backup settings",
            "3. INTERCEPT: Set up proxy (mitmproxy), bypass SSL pinning (frida/objection), capture API traffic",
            "4. DYNAMIC: Hook runtime methods (frida), bypass root detection, inspect local storage",
            "5. API: Test discovered backend APIs for IDOR, auth bypass, injection "
            "— respect rate limits, use test accounts when available",
            "6. REPORT: Document findings with app version, device info, and reproduction steps "
            "— redact hardcoded secrets found in source",
        ],
        "quick_wins": [
            "Decompile APK and grep for API keys, passwords, tokens, and URLs",
            "Check AndroidManifest.xml for android:debuggable and exported components",
            "Bypass SSL pinning with objection and inspect all API traffic",
            "Check local storage (SharedPreferences, SQLite) for sensitive data",
            "Test deeplinks for intent injection",
        ],
        "common_vulns": [
            "Hardcoded secrets (API keys, credentials, tokens)",
            "Insecure local data storage (SharedPreferences, SQLite)",
            "Missing or bypassable SSL/TLS pinning",
            "Exported activities/providers/receivers without proper permissions",
            "Insecure backend API (IDOR, broken auth)",
            "Insufficient binary protections (no obfuscation, debuggable)",
            "Deeplink/intent injection",
            "WebView vulnerabilities (JavaScript interface abuse)",
            "Improper session management",
            "Sensitive data in application logs",
        ],
    },
    "cloud": {
        "description": "Cloud infrastructure testing — AWS/Azure/GCP misconfigurations, IAM, exposed services",
        "modules": ["cloud", "containers", "recon"],
        "tools": [
            ("scoutsuite", "Multi-cloud security auditing"),
            ("prowler", "AWS/Azure/GCP security assessments"),
            ("pacu", "AWS exploitation framework"),
            ("cloudfox", "Cloud penetration testing automation"),
            ("trufflehog", "Secret scanning in repos and cloud configs"),
            ("trivy", "Container and cloud vulnerability scanning"),
            ("kube-hunter", "Kubernetes penetration testing"),
            ("deepce", "Docker/container enumeration and escape"),
            ("cloudsplaining", "AWS IAM policy analysis"),
            ("subfinder", "Subdomain discovery for cloud-hosted assets"),
            ("nuclei", "Cloud service misconfiguration scanning"),
            ("httpx", "Probing discovered cloud endpoints"),
        ],
        "methodology": [
            "0. SCOPE: Verify cloud accounts, regions, and services are in scope "
            "— check for shared tenancy restrictions",
            "1. ENUMERATE: Discover cloud assets — S3 buckets, Azure blobs, GCP storage, subdomains, IPs",
            "2. SCAN: Run prowler/scoutsuite for misconfigurations, trivy for container/IaC vulnerabilities",
            "3. IAM: Analyze IAM policies (cloudsplaining), test for privilege escalation paths (pacu)",
            "4. SECRETS: Scan for exposed keys (trufflehog), check metadata endpoints (169.254.169.254)",
            "5. EXPLOIT: Test discovered misconfigurations — public buckets, overprivileged roles, "
            "exposed services — do NOT modify or delete cloud resources",
            "6. REPORT: Document cloud provider, service, region, misconfiguration, and remediation "
            "— redact access keys and account IDs",
        ],
        "quick_wins": [
            "Check for public S3 buckets / Azure blobs / GCP storage",
            "Test metadata endpoint (169.254.169.254) for credential exposure",
            "Run trufflehog on git repos for leaked cloud credentials",
            "Check for overly permissive IAM policies (*, admin access)",
            "Scan for exposed management consoles and dashboards",
            "Test for subdomain takeover on cloud-hosted services",
        ],
        "common_vulns": [
            "Public cloud storage (S3 buckets, Azure blobs, GCP storage)",
            "Overprivileged IAM roles and policies",
            "Exposed cloud metadata endpoints",
            "Leaked access keys in code repositories",
            "Misconfigured security groups / firewall rules",
            "Subdomain takeover on deprovisioned cloud services",
            "Container escape via misconfigurations",
            "Kubernetes RBAC misconfigurations",
            "Insecure serverless function configurations",
            "Missing encryption at rest or in transit",
        ],
        "notable_cves": [
            "CVE-2024-21626 — Leaky Vessels: runc container escape via /proc/self/fd race. "
            "Attacker in container can overwrite host binaries and escape",
            "CVE-2023-22527 — Confluence Server RCE: OGNL injection in template engine. "
            "Unauthenticated RCE on Atlassian Confluence (often on cloud/internal infra)",
        ],
    },
    "network": {
        "description": "Network/infrastructure testing — service enumeration, protocol exploitation, lateral movement",
        "modules": ["networking", "enterprise", "recon"],
        "tools": [
            ("nmap", "Network scanner and service/version detection"),
            ("masscan", "Fast port scanner for large ranges"),
            ("nuclei", "Network service vulnerability scanning"),
            ("nikto", "Web server vulnerability scanner"),
            ("responder", "LLMNR/NBT-NS/MDNS poisoner for credential capture"),
            ("impacket", "Network protocol exploitation toolkit"),
            ("netcat", "Network utility for banner grabbing and connections"),
            ("tshark", "CLI packet analyzer for traffic inspection"),
            ("hydra", "Online brute-force for network services"),
        ],
        "methodology": [
            "0. SCOPE: Verify IP ranges, ports, and services are in scope "
            "— check for shared hosting and third-party services",
            "1. DISCOVER: Port scanning (nmap, masscan), service/version detection, OS fingerprinting",
            "2. ENUMERATE: Banner grabbing, NSE scripts, directory enumeration on web services",
            "3. VULNSCAN: Vulnerability scanning (nuclei, nikto), check for known CVEs on discovered versions",
            "4. EXPLOIT: Test default credentials (hydra), protocol-specific attacks (impacket) "
            "— throttle scans to avoid triggering IDS/WAF",
            "5. PIVOT: Document lateral movement paths, check for internal service exposure",
            "6. REPORT: Document IP, port, service, vulnerability, proof of concept, "
            "and remediation — redact internal IPs and credentials",
        ],
        "quick_wins": [
            "Run nmap -sV on top ports for quick service fingerprinting",
            "Test for default credentials on discovered services (admin:admin, etc.)",
            "Check for exposed management interfaces (SSH, RDP, databases)",
            "Run nuclei network templates against discovered services",
            "Check SSL/TLS configuration for weak ciphers and expired certificates",
        ],
        "common_vulns": [
            "Default or weak credentials on services",
            "Outdated software with known CVEs",
            "Exposed management interfaces (SSH, RDP, admin panels)",
            "Weak SSL/TLS configuration",
            "Unencrypted protocols transmitting sensitive data",
            "DNS zone transfer enabled",
            "SNMP with default community strings",
            "Open mail relays",
            "Missing network segmentation",
            "Exposed database ports (MySQL, PostgreSQL, MongoDB, Redis)",
        ],
    },
    "iot": {
        "description": "IoT/firmware testing — binary analysis, default credentials, "
        "protocol fuzzing, hardware interfaces",
        "modules": ["reversing", "pwn", "networking"],
        "tools": [
            ("binwalk", "Firmware extraction and analysis"),
            ("ghidra", "Firmware binary reverse engineering"),
            ("radare2", "RE framework for firmware analysis"),
            ("nmap", "Network scanning for IoT device discovery"),
            ("firmware-mod-kit", "Firmware modification and extraction toolkit"),
            ("boofuzz", "Network protocol fuzzer for IoT protocols"),
            ("strace", "System call tracing for embedded binaries"),
            ("tshark", "IoT protocol traffic analysis"),
            ("hydra", "Default credential testing on IoT services"),
            ("checksec", "Binary security property checker for firmware binaries"),
        ],
        "methodology": [
            "0. SCOPE: Verify device, firmware version, and network interfaces are in scope",
            "1. RECON: Identify device type, firmware version, open ports (nmap), running services",
            "2. FIRMWARE: Extract firmware (binwalk), find filesystem, analyze binaries (ghidra, radare2)",
            "3. SECRETS: Search for hardcoded credentials, API keys, certificates in extracted filesystem",
            "4. PROTOCOL: Analyze and fuzz communication protocols (boofuzz, tshark) "
            "— start with low request rates to avoid bricking the device",
            "5. EXPLOIT: Test default credentials (hydra), command injection, buffer overflows "
            "— work on isolated/lab devices when possible",
            "6. REPORT: Document device model, firmware version, vulnerability, "
            "and access requirements — redact credentials found in firmware",
        ],
        "quick_wins": [
            "Run binwalk -e to extract firmware filesystem",
            "Search extracted filesystem for passwords, keys, and certificates",
            "Test default credentials on web interface and network services",
            "Check for unencrypted update mechanisms",
            "Scan for UPnP, MQTT, CoAP, and other IoT protocols",
        ],
        "common_vulns": [
            "Hardcoded credentials in firmware",
            "Unencrypted firmware update mechanism",
            "Command injection via web interface or API",
            "Buffer overflows in network services",
            "Insecure default configuration",
            "Exposed debug interfaces (UART, JTAG, serial)",
            "Unencrypted communication protocols",
            "Weak or missing authentication on APIs",
            "UPnP/SSDP information disclosure",
            "Outdated embedded Linux kernel with known CVEs",
        ],
    },
}

# Aliases for target type names.
TARGET_ALIASES: dict[str, str] = {
    "web": "web_app",
    "webapp": "web_app",
    "website": "web_app",
    "rest": "api",
    "graphql": "api",
    "api_testing": "api",
    "android": "mobile_app",
    "ios": "mobile_app",
    "mobile": "mobile_app",
    "aws": "cloud",
    "azure": "cloud",
    "gcp": "cloud",
    "kubernetes": "cloud",
    "k8s": "cloud",
    "infra": "network",
    "infrastructure": "network",
    "internal": "network",
    "firmware": "iot",
    "embedded": "iot",
    "hardware": "iot",
}


def resolve_target_type(target_type: str) -> Optional[str]:
    """Resolve a target type string to a canonical target type name."""
    normalized = target_type.lower().strip()
    if normalized in BOUNTY_TARGET_MAP:
        return normalized
    return TARGET_ALIASES.get(normalized)


def _check_tool_installed(tool_name: str, tools_db: ToolsDatabase) -> tuple[bool, bool]:
    """Check if a tool is installed. Returns (installed, in_registry).

    Uses TOOL_ALIASES to map display names to registry names, and falls
    back to PATH check for tools not in the registry.
    """
    # Resolve display name to registry name
    registry_name = TOOL_ALIASES.get(tool_name, tool_name)

    # Check if it's in the registry
    in_registry = registry_name in tools_db.tools_by_name

    if in_registry:
        status = tools_db.check_installed(registry_name)
        if status["installed"]:
            return True, True

    # PATH check using the display name (the binary users actually run)
    if shutil.which(tool_name):
        return True, in_registry

    return False, in_registry


def suggest_for_bounty(target_type: str, tools_db: ToolsDatabase) -> dict:
    """Return tool suggestions for a bug bounty target type with install status.

    Returns dict with: target_type, description, modules, tools (with install
    status), methodology, quick_wins, common_vulns, scope_warning, summary.
    """
    resolved = resolve_target_type(target_type)
    if not resolved:
        available = sorted(BOUNTY_TARGET_MAP.keys())
        aliases = sorted(TARGET_ALIASES.keys())
        return {
            "error": f"Unknown target type: '{target_type}'",
            "available_target_types": available,
            "available_aliases": aliases,
        }

    target_info = BOUNTY_TARGET_MAP[resolved]
    tools_with_status = []
    for tool_name, description in target_info["tools"]:
        installed, in_registry = _check_tool_installed(tool_name, tools_db)
        entry = {
            "name": tool_name,
            "description": description,
            "installed": installed,
            "in_registry": in_registry,
        }
        # Add registry name if different from display name
        registry_name = TOOL_ALIASES.get(tool_name)
        if registry_name:
            entry["registry_name"] = registry_name
        tools_with_status.append(entry)

    installed_count = sum(1 for t in tools_with_status if t["installed"])

    result = {
        "target_type": resolved,
        "description": target_info["description"],
        "modules": target_info["modules"],
        "tools": tools_with_status,
        "methodology": target_info.get("methodology", []),
        "quick_wins": target_info.get("quick_wins", []),
        "common_vulns": target_info.get("common_vulns", []),
        "scope_warning": (
            "IMPORTANT: Always verify that your target is within the program's scope "
            "before testing. Check the program's rules for out-of-scope assets, "
            "rate limiting requirements, and testing restrictions. Do NOT access, "
            "modify, or exfiltrate real user data. Use test accounts when available. "
            "Respect rate limits and back off on 429 responses. Unauthorized testing "
            "may have legal consequences."
        ),
        "summary": f"{installed_count}/{len(tools_with_status)} tools installed",
    }
    if "notable_cves" in target_info:
        result["notable_cves"] = target_info["notable_cves"]
    return result
