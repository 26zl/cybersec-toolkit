"""CVE → registry tool / skill / module mapping with live-lookup command hints.

Local-first by design: the curated map runs offline and is deterministic. When a
live CVSS / KEV / EPSS lookup is wanted, this advisor hands back the exact
``run_tool("curl", ...)`` invocations the AI should execute — it does NOT make
network calls itself. Those curl calls hit external hosts, so they are subject to
the same ``CYBERSEC_MCP_ALLOW_EXTERNAL`` policy as any other network tool.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server.advisor_utils import check_tool_installed  # noqa: E402
from mcp_server.tools_db import ToolsDatabase  # noqa: E402

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Common vulnerability nicknames → canonical CVE id (lowercased keys).
NAME_ALIASES: dict[str, str] = {
    "eternalblue": "CVE-2017-0144",
    "ms17-010": "CVE-2017-0144",
    "wannacry": "CVE-2017-0144",
    "zerologon": "CVE-2020-1472",
    "nopac": "CVE-2021-42278",
    "sam-the-admin": "CVE-2021-42278",
    "samaccountname-spoofing": "CVE-2021-42278",
    "printnightmare": "CVE-2021-34527",
    "log4shell": "CVE-2021-44228",
    "log4j": "CVE-2021-44228",
    "proxyshell": "CVE-2021-34473",
    "proxylogon": "CVE-2021-26855",
    "heartbleed": "CVE-2014-0160",
    "shellshock": "CVE-2014-6271",
    "dirtycow": "CVE-2016-5195",
    "spring4shell": "CVE-2022-22965",
    "petitpotam": "CVE-2021-36942",
    "bluekeep": "CVE-2019-0708",
}

# Curated CVE → toolkit assets. Tool display names resolve through TOOL_ALIASES;
# skill / module names are validated against the repo by tests.
KNOWN_CVES: dict[str, dict] = {
    "CVE-2017-0144": {
        "name": "EternalBlue (MS17-010)",
        "severity": "Critical",
        "summary": "SMBv1 remote code execution in Windows; weaponized by WannaCry and NotPetya.",
        "tools": ["nmap", "metasploit"],
        "skills": [
            "exploiting-ms17-010-eternalblue-vulnerability",
            "exploiting-smb-vulnerabilities-with-metasploit",
        ],
        "modules": ["networking", "enterprise"],
    },
    "CVE-2020-1472": {
        "name": "Zerologon",
        "severity": "Critical",
        "summary": "Netlogon privilege escalation — resets a domain controller's machine account password.",
        "tools": ["impacket", "netexec"],
        "skills": ["exploiting-zerologon-vulnerability-cve-2020-1472"],
        "modules": ["enterprise"],
    },
    "CVE-2021-42278": {
        "name": "noPac / sAMAccountName spoofing (with CVE-2021-42287)",
        "severity": "High",
        "summary": "AD privilege escalation chaining sAMAccountName spoofing and KDC ticket confusion to domain admin.",
        "tools": ["impacket", "netexec"],
        "skills": ["exploiting-nopac-cve-2021-42278-42287"],
        "modules": ["enterprise"],
    },
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "severity": "Critical",
        "summary": "Apache Log4j2 JNDI lookup remote code execution via attacker-controlled log strings.",
        "tools": ["nuclei", "metasploit"],
        "skills": ["cve-poc-generator", "performing-cve-prioritization-with-kev-catalog"],
        "modules": ["web", "networking"],
    },
    "CVE-2021-34527": {
        "name": "PrintNightmare",
        "severity": "Critical",
        "summary": "Windows Print Spooler remote code execution / local privilege escalation.",
        "tools": ["impacket", "netexec"],
        "skills": ["cve-poc-generator", "exploiting-vulnerabilities-with-metasploit-framework"],
        "modules": ["enterprise"],
    },
    "CVE-2021-26855": {
        "name": "ProxyLogon",
        "severity": "Critical",
        "summary": "Microsoft Exchange SSRF leading to authenticated RCE chain.",
        "tools": ["nuclei", "metasploit"],
        "skills": ["cve-poc-generator", "performing-cve-prioritization-with-kev-catalog"],
        "modules": ["web", "networking"],
    },
    "CVE-2014-0160": {
        "name": "Heartbleed",
        "severity": "High",
        "summary": "OpenSSL TLS heartbeat out-of-bounds read leaking process memory (keys, sessions).",
        "tools": ["nmap", "nuclei"],
        "skills": ["performing-ssl-tls-security-assessment", "cve-poc-generator"],
        "modules": ["networking", "web"],
    },
    "CVE-2014-6271": {
        "name": "Shellshock",
        "severity": "Critical",
        "summary": "GNU Bash environment-variable function parsing allows remote command execution.",
        "tools": ["nuclei", "metasploit"],
        "skills": ["cve-poc-generator", "exploiting-vulnerabilities-with-metasploit-framework"],
        "modules": ["web", "networking"],
    },
    "CVE-2016-5195": {
        "name": "Dirty COW",
        "severity": "High",
        "summary": "Linux kernel copy-on-write race condition enabling local privilege escalation.",
        "tools": ["metasploit"],
        "skills": ["performing-privilege-escalation-on-linux", "cve-poc-generator"],
        "modules": ["pwn"],
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell",
        "severity": "Critical",
        "summary": "Spring Framework data-binding remote code execution on JDK 9+ / Tomcat deployments.",
        "tools": ["nuclei", "metasploit"],
        "skills": ["cve-poc-generator", "performing-cve-prioritization-with-kev-catalog"],
        "modules": ["web"],
    },
    "CVE-2019-0708": {
        "name": "BlueKeep",
        "severity": "Critical",
        "summary": "Windows RDP pre-auth remote code execution (wormable).",
        "tools": ["nmap", "metasploit"],
        "skills": ["exploiting-vulnerabilities-with-metasploit-framework", "cve-poc-generator"],
        "modules": ["networking", "enterprise"],
    },
    "CVE-2021-36942": {
        "name": "PetitPotam",
        "severity": "High",
        "summary": "Windows EFSRPC NTLM relay coercion, often chained to AD CS for domain takeover.",
        "tools": ["impacket", "responder"],
        "skills": [
            "exploiting-active-directory-certificate-services-esc1",
            "cve-poc-generator",
        ],
        "modules": ["enterprise"],
    },
    "CVE-2021-34473": {
        "name": "ProxyShell",
        "severity": "Critical",
        "summary": "Microsoft Exchange pre-auth RCE chain (with CVE-2021-34523 / CVE-2021-31207).",
        "tools": ["nuclei", "metasploit"],
        "skills": ["cve-poc-generator", "performing-cve-prioritization-with-kev-catalog"],
        "modules": ["web", "networking"],
    },
}

# Generic fallback for a valid CVE we have no curated entry for.
_FALLBACK_SKILLS = [
    "cve-poc-generator",
    "performing-cve-prioritization-with-kev-catalog",
    "exploiting-vulnerabilities-with-metasploit-framework",
]

# Chain "partner" CVE ids -> the primary curated id they are documented under, so
# querying a well-known partner CVE of a chain returns the curated mapping rather
# than the generic fallback.
ID_ALIASES: dict[str, str] = {
    "CVE-2021-42287": "CVE-2021-42278",  # noPac chain
    "CVE-2021-34523": "CVE-2021-34473",  # ProxyShell chain
    "CVE-2021-31207": "CVE-2021-34473",  # ProxyShell chain
}


def resolve_cve(query: str) -> str | None:
    """Resolve a query to a canonical CVE id, or None if it isn't a CVE."""
    normalized = query.strip()
    alias = NAME_ALIASES.get(normalized.lower())
    if alias:
        return alias
    if CVE_ID_RE.match(normalized):
        canonical = normalized.upper()
        return ID_ALIASES.get(canonical, canonical)
    return None


def _live_lookup(cve_id: str, external_enabled: bool) -> dict:
    """Ready-to-run curl commands for live enrichment (executed via run_tool)."""
    nvd = f'run_tool("curl", "-s https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")'
    epss = f'run_tool("curl", "-s https://api.first.org/data/v1/epss?cve={cve_id}")'
    kev = 'run_tool("curl", "-s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")'
    note = (
        "External network is enabled — run these via run_tool to fetch live data."
        if external_enabled
        else "External network is disabled (CYBERSEC_MCP_ALLOW_EXTERNAL=0). These curl "
        "calls are blocked until the operator enables external scope and restarts the server."
    )
    return {
        "external_enabled": external_enabled,
        "nvd_cvss_and_refs": nvd,
        "epss_exploit_probability": epss,
        "cisa_kev_catalog": kev,
        "note": note,
    }


def get_cve_info(query: str, tools_db: ToolsDatabase, external_enabled: bool = False) -> dict:
    """Map a CVE (id or common nickname) to toolkit assets and live-lookup commands.

    Returns dict with: cve, known, name/severity/summary (when curated), tools with
    install status, recommended_skills, modules, live_lookup, and next_steps.
    """
    cve_id = resolve_cve(query)
    if cve_id is None:
        return {
            "error": f"Not a recognized CVE id or nickname: '{query}'",
            "expected_format": "CVE-YYYY-NNNN (e.g. CVE-2021-44228) or a nickname like 'log4shell'.",
            "known_nicknames": sorted(NAME_ALIASES.keys()),
        }

    entry = KNOWN_CVES.get(cve_id)
    skills = entry["skills"] if entry else list(_FALLBACK_SKILLS)
    tool_names = entry["tools"] if entry else []
    modules = entry["modules"] if entry else []

    tools_with_status = []
    for name in tool_names:
        installed, in_registry = check_tool_installed(name, tools_db)
        tools_with_status.append({"name": name, "installed": installed, "in_registry": in_registry})
    installed_count = sum(1 for t in tools_with_status if t["installed"])

    result: dict = {
        "cve": cve_id,
        "input": query,
        "known": entry is not None,
        "tools": tools_with_status,
        "recommended_skills": skills,
        "modules": modules,
        "live_lookup": _live_lookup(cve_id, external_enabled),
    }
    if entry:
        result["name"] = entry["name"]
        result["severity"] = entry["severity"]
        result["summary"] = entry["summary"]
        result["summary_line"] = f"{installed_count}/{len(tools_with_status)} mapped tools installed"
        result["next_steps"] = [
            f"Review the '{skills[0]}' skill for the exploitation methodology.",
            "Fetch live CVSS/KEV/EPSS with the live_lookup commands (needs external network).",
            "Confirm authorization and scope before testing — see the 'authorization-gate' skill.",
        ]
    else:
        result["next_steps"] = [
            "No curated mapping for this CVE — use the 'cve-poc-generator' skill to build a PoC.",
            "Fetch live CVSS/KEV/EPSS with the live_lookup commands (needs external network).",
            "Prioritize with 'performing-cve-prioritization-with-kev-catalog' before acting.",
            "Confirm authorization and scope first — see the 'authorization-gate' skill.",
        ]
    return result
