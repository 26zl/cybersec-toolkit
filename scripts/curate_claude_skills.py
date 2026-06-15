#!/usr/bin/env python3
"""Rank and curate local Claude Code skills."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _skill_frontmatter import frontmatter  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / ".claude" / "skills"
CURATION_MD = SKILLS_DIR / "CURATION.md"
CURATION_JSON = SKILLS_DIR / "curation.json"

PROJECT_SKILLS = {
    "add-tool",
    "module-scaffold",
    "validate-all",
    "mcp-sync-check",
    "writeup-template",
    "security-wordlists",
    "security-payloads",
    "guided-assessment",
    "skill-dependency-audit",
    "skill-curation-router",
    "finding-triage",
    "security-comms",
    "authorization-gate",
    "evidence-hygiene",
}

PROJECT_DOMAINS = {
    "add-tool": "project_tooling",
    "module-scaffold": "project_tooling",
    "validate-all": "project_tooling",
    "mcp-sync-check": "project_tooling",
    "writeup-template": "project_tooling",
    "security-wordlists": "project_tooling",
    "security-payloads": "project_tooling",
    "guided-assessment": "project_tooling",
    "skill-dependency-audit": "project_tooling",
    "skill-curation-router": "project_tooling",
    "finding-triage": "security_coordination",
    "security-comms": "security_coordination",
    "authorization-gate": "security_coordination",
    "evidence-hygiene": "security_coordination",
}

COVERAGE_ANCHORS = {
    "grc-compliance-privacy-program",
    "ai-llm-security-review",
    "iot-embedded-hardware-security-assessment",
    "mainframe-security-assessment",
    "telecom-5g-security-assessment",
    "sap-erp-security-assessment",
    "supply-chain-prodsec-hardening",
}

TRAIL_OF_BITS_SKILLS = {
    "yara-rule-authoring",
    "semgrep",
    "semgrep-rule-creator",
    "codeql",
    "sarif-parsing",
    "insecure-defaults",
    "constant-time-analysis",
    "zeroize-audit",
    "fp-check",
    "differential-review",
    "supply-chain-risk-auditor",
    "sharp-edges",
    "dimensional-analysis",
    "variant-analysis",
}

TRANSILIENCE_SKILLS = {
    "cve-poc-generator",
    "dfir",
    "ai-threat-testing",
    "blockchain-security",
}

KARPATHY_SKILLS = {
    "karpathy-guidelines",
}

CLAUDE_RED_SKILLS = {
    "offensive-active-directory",
    "offensive-advanced-redteam",
    "offensive-ai-security",
    "offensive-basic-exploitation",
    "offensive-bluetooth-ble",
    "offensive-bluetooth-classic",
    "offensive-bug-identification",
    "offensive-business-logic",
    "offensive-cloud",
    "offensive-crash-analysis",
    "offensive-deauth-disassoc",
    "offensive-deserialization",
    "offensive-edr-evasion",
    "offensive-evil-twin",
    "offensive-exploit-dev-course",
    "offensive-exploit-development",
    "offensive-fast-checking",
    "offensive-file-upload",
    "offensive-fuzzing",
    "offensive-fuzzing-course",
    "offensive-graphql",
    "offensive-idor",
    "offensive-initial-access",
    "offensive-iot",
    "offensive-jwt",
    "offensive-keylogger-arch",
    "offensive-krack-fragattacks",
    "offensive-lorawan-sub-ghz",
    "offensive-mitigations",
    "offensive-mobile",
    "offensive-oauth",
    "offensive-open-redirect",
    "offensive-osint",
    "offensive-osint-methodology",
    "offensive-parameter-pollution",
    "offensive-race-condition",
    "offensive-rce",
    "offensive-reporting",
    "offensive-request-smuggling",
    "offensive-shellcode",
    "offensive-sqli",
    "offensive-ssrf",
    "offensive-ssti",
    "offensive-toctou",
    "offensive-vuln-classes",
    "offensive-waf-bypass",
    "offensive-wifi",
    "offensive-wifi-recon",
    "offensive-windows-boundaries",
    "offensive-windows-mitigations",
    "offensive-wpa-enterprise",
    "offensive-wpa2-psk",
    "offensive-wpa3-sae",
    "offensive-wps",
    "offensive-xss",
    "offensive-xxe",
    "offensive-z-wave",
    "offensive-zigbee-thread-matter",
}

BUGHUNTER_SKILLS = {
    "bb-methodology",
    "bug-bounty",
    "credential-attack",
    "meme-coin-audit",
    "report-writing",
    "security-arsenal",
    "triage-validation",
    "web2-recon",
    "web2-vuln-classes",
    "web3-audit",
}

BUGHUNTER_DOMAIN_OVERRIDES = {
    "ctf_bounty": {
        "bb-methodology",
        "bug-bounty",
        "credential-attack",
        "report-writing",
        "triage-validation",
        "web2-recon",
    },
    "appsec_web_api": {
        "security-arsenal",
        "web2-vuln-classes",
    },
    "crypto_blockchain": {
        "meme-coin-audit",
        "web3-audit",
    },
}

CLAUDE_RED_DOMAIN_OVERRIDES = {
    "ai_llm_security": {
        "offensive-ai-security",
    },
    "appsec_web_api": {
        "offensive-business-logic",
        "offensive-deserialization",
        "offensive-file-upload",
        "offensive-graphql",
        "offensive-idor",
        "offensive-open-redirect",
        "offensive-parameter-pollution",
        "offensive-race-condition",
        "offensive-rce",
        "offensive-request-smuggling",
        "offensive-sqli",
        "offensive-ssrf",
        "offensive-ssti",
        "offensive-waf-bypass",
        "offensive-xss",
        "offensive-xxe",
    },
    "cloud_security": {
        "offensive-cloud",
    },
    "identity_access": {
        "offensive-active-directory",
        "offensive-jwt",
        "offensive-oauth",
    },
    "iot_embedded_hardware": {
        "offensive-iot",
    },
    "mobile_security": {
        "offensive-mobile",
    },
    "network_wireless": {
        "offensive-bluetooth-ble",
        "offensive-bluetooth-classic",
        "offensive-deauth-disassoc",
        "offensive-evil-twin",
        "offensive-krack-fragattacks",
        "offensive-lorawan-sub-ghz",
        "offensive-wifi",
        "offensive-wifi-recon",
        "offensive-wpa-enterprise",
        "offensive-wpa2-psk",
        "offensive-wpa3-sae",
        "offensive-wps",
        "offensive-z-wave",
        "offensive-zigbee-thread-matter",
    },
    "redteam_pentest": {
        "offensive-advanced-redteam",
        "offensive-basic-exploitation",
        "offensive-bug-identification",
        "offensive-crash-analysis",
        "offensive-edr-evasion",
        "offensive-exploit-dev-course",
        "offensive-exploit-development",
        "offensive-fast-checking",
        "offensive-fuzzing",
        "offensive-fuzzing-course",
        "offensive-initial-access",
        "offensive-keylogger-arch",
        "offensive-mitigations",
        "offensive-osint",
        "offensive-osint-methodology",
        "offensive-reporting",
        "offensive-shellcode",
        "offensive-toctou",
        "offensive-vuln-classes",
        "offensive-windows-boundaries",
        "offensive-windows-mitigations",
    },
}

DOMAIN_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("agent_workflow", ("agent", "coding-agent", "llm coding", "refactoring", "surgical", "overcomplication", "success criteria")),
    ("grc_privacy", ("grc", "governance", "compliance", "privacy", "legal", "audit", "policy", "soc2", "iso", "nist", "pci", "nerc", "gdpr", "risk")),
    ("ai_llm_security", ("ai", "llm", "prompt", "model", "deepfake", "rag", "guardrail")),
    ("supply_chain_prodsec", ("supply-chain", "sbom", "slsa", "provenance", "sigstore", "cosign", "ci-cd", "devsecops", "sast", "dast", "dependency", "typosquatting", "container-registry", "prodsec")),
    ("telecom_mainframe_sap", ("telecom", "5g", "mainframe", "z/os", "racf", "acf2", "cics", "sap", "erp", "s/4hana", "abap", "hana", "diameter", "gtp")),
    ("iot_embedded_hardware", ("iot", "embedded", "hardware", "firmware", "uart", "jtag", "swd", "ota", "ble", "bluetooth")),
    ("cloud_security", ("aws", "azure", "gcp", "cloud", "guardduty", "lambda", "s3", "iam", "office365", "kubernetes", "container", "docker")),
    ("identity_access", ("identity", "active-directory", "kerberos", "oauth", "saml", "okta", "entra", "pam", "mfa", "passwordless", "privileged", "ldap", "bloodhound")),
    ("appsec_web_api", ("api", "web", "xss", "sqli", "sql-injection", "injection", "graphql", "jwt", "websocket", "cors", "ssrf", "xxe", "deserialization", "template")),
    ("dfir_malware", ("forensic", "forensics", "malware", "ransomware", "memory", "disk", "registry", "volatility", "yara", "incident", "timeline", "artifact")),
    ("detection_soc_hunting", ("detecting", "detection", "hunting", "splunk", "sigma", "siem", "soc", "alert", "zeek", "suricata", "ueba")),
    ("ot_ics_security", ("ot", "ics", "scada", "modbus", "dnp3", "plc", "s7comm", "purdue", "historian", "nerc-cip")),
    ("redteam_pentest", ("red-team", "pentest", "penetration", "exploiting", "exploit", "attack", "c2", "phishing-simulation", "evilginx", "metasploit")),
    ("network_wireless", ("network", "wireless", "wifi", "dns", "tls", "firewall", "packet", "nmap", "pcap", "bluetooth")),
    ("mobile_security", ("mobile", "android", "ios", "apk", "ipa", "frida", "objection")),
    ("crypto_blockchain", ("crypto", "cryptography", "rsa", "aes", "tls", "certificate", "blockchain", "ethereum", "smart-contract", "defi")),
    ("ctf_bounty", ("ctf", "bounty", "bug-bounty")),
]

BROAD_WORKFLOW_TERMS = (
    "program",
    "review",
    "assessment",
    "hardening",
    "audit",
    "playbook",
    "workflow",
    "framework",
    "lifecycle",
    "governance",
    "management",
    "incident-response",
    "threat-hunting",
    "security-review",
)

SPECIALIST_MARKERS = (
    "-with-",
    "cve-",
    "exploiting-",
    "deploying-",
    "configuring-",
    "performing-",
)

OFFENSIVE_TERMS = (
    "exploiting",
    "attack",
    "red-team",
    "penetration",
    "phishing",
    "credential",
    "kerberoasting",
    "metasploit",
    "evilginx",
    "c2",
    "bypass",
)

GENERIC_QUERY_TERMS = {
    "audit",
    "assessment",
    "hardening",
    "management",
    "program",
    "response",
    "review",
    "security",
    "test",
    "testing",
    "workflow",
}


@dataclass
class Skill:
    name: str
    description: str
    source: str
    domain: str
    priority: int
    tier: str
    sensitivity: str
    reasons: list[str] = field(default_factory=list)


def source_for(name: str) -> str:
    if name in PROJECT_SKILLS:
        return "project"
    if name in COVERAGE_ANCHORS:
        return "coverage-anchor"
    if name.startswith("ctf-"):
        return "ctf"
    if name.startswith("bounty-"):
        return "bug-bounty"
    if name in TRAIL_OF_BITS_SKILLS:
        return "trail-of-bits"
    if name in TRANSILIENCE_SKILLS:
        return "transilience"
    if name in KARPATHY_SKILLS:
        return "karpathy"
    if name in CLAUDE_RED_SKILLS:
        return "claude-red"
    if name in BUGHUNTER_SKILLS:
        return "bughunter"
    return "anthropic"


def has_term(text: str, term: str) -> bool:
    if len(term) <= 3 and re.fullmatch(r"[a-z0-9]+", term):
        return re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", text) is not None
    return term in text


def domain_for(name: str, description: str) -> str:
    if name in PROJECT_DOMAINS:
        return PROJECT_DOMAINS[name]
    if name.startswith(("ctf-", "bounty-")):
        return "ctf_bounty"
    if name in TRAIL_OF_BITS_SKILLS:
        return "code_audit"
    if name in KARPATHY_SKILLS:
        return "agent_workflow"
    for domain, names in CLAUDE_RED_DOMAIN_OVERRIDES.items():
        if name in names:
            return domain
    for domain, names in BUGHUNTER_DOMAIN_OVERRIDES.items():
        if name in names:
            return domain

    haystack = f"{name} {description}".lower()
    scores: Counter[str] = Counter()
    for domain, terms in DOMAIN_RULES:
        for term in terms:
            if has_term(haystack, term):
                scores[domain] += 1
    if not scores:
        return "general_security"
    return scores.most_common(1)[0][0]


def sensitivity_for(name: str, description: str) -> str:
    haystack = f"{name} {description}".lower()
    if any(has_term(haystack, term) for term in OFFENSIVE_TERMS):
        return "sensitive-offensive"
    if any(has_term(haystack, term) for term in ("legal", "privacy", "compliance", "regulatory")):
        return "advisory-verify-current-sources"
    if any(has_term(haystack, term) for term in ("atomic", "execute", "run tool", "deploying", "simulation")):
        return "requires-environment-check"
    return "normal"


def score_skill(name: str, description: str, source: str) -> tuple[int, list[str]]:
    score = 50
    reasons: list[str] = []

    source_scores = {
        "project": 94,
        "coverage-anchor": 90,
        "trail-of-bits": 86,
        "transilience": 82,
        "karpathy": 84,
        "claude-red": 80,
        "ctf": 78,
        "bug-bounty": 78,
        "bughunter": 78,
        "anthropic": 58,
    }
    score = source_scores[source]
    reasons.append(f"source:{source}")

    haystack = f"{name} {description}".lower()
    if any(has_term(haystack, term) for term in BROAD_WORKFLOW_TERMS):
        score += 8
        reasons.append("broad-workflow")
    if "use when" in description.lower():
        score += 3
        reasons.append("clear-trigger")
    if len(description) >= 80:
        score += 2
        reasons.append("descriptive")
    if name.startswith(("detecting-", "hunting-", "analyzing-", "triaging-", "hardening-", "securing-")):
        score += 3
        reasons.append("defensive-operational")
    if name.startswith(("exploiting-", "performing-", "deploying-", "configuring-")):
        score -= 2
        reasons.append("specialist-action")
    if any(marker in name for marker in SPECIALIST_MARKERS):
        score -= 4
        reasons.append("exact-match-specialist")
    if "cve-" in name:
        score -= 6
        reasons.append("single-cve")
    if len(name.split("-")) >= 7:
        score -= 2
        reasons.append("narrow-name")

    return max(1, min(100, score)), reasons


def tier_for(priority: int, source: str) -> str:
    if source == "project":
        return "T0-router-and-project"
    if source == "coverage-anchor":
        return "T1-coverage-anchor"
    if priority >= 86:
        return "T1-core"
    if priority >= 68:
        return "T2-operational"
    return "T3-specialist"


def load_skills() -> list[Skill]:
    skills: list[Skill] = []
    for skill_dir in sorted(path for path in SKILLS_DIR.iterdir() if path.is_dir()):
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.is_file():
            continue
        fields = frontmatter(skill_file.read_text(encoding="utf-8", errors="replace")) or {}
        name = fields.get("name", skill_dir.name)
        description = fields.get("description", "")
        source = source_for(name)
        # Guardrail: "anthropic"/Apache-2.0 is the name-derived catch-all default.
        # If a skill falls through to it but its frontmatter declares a different
        # license, that's a misclassification — fail loudly so a newly vendored skill
        # gets added to the correct *_SKILLS set in source_for() and to
        # THIRD_PARTY_NOTICES.md rather than being silently mislabeled Apache-2.0.
        fm_license = fields.get("license", "")
        if source == "anthropic" and fm_license and fm_license != "Apache-2.0":
            raise SystemExit(
                f"curate: '{name}' falls through to 'anthropic'/Apache-2.0 but its "
                f"SKILL.md declares license={fm_license!r}. Add it to the correct "
                f"*_SKILLS set in source_for() and update THIRD_PARTY_NOTICES.md."
            )
        domain = domain_for(name, description)
        priority, reasons = score_skill(name, description, source)
        skills.append(
            Skill(
                name=name,
                description=description,
                source=source,
                domain=domain,
                priority=priority,
                tier=tier_for(priority, source),
                sensitivity=sensitivity_for(name, description),
                reasons=reasons,
            )
        )
    return sorted(skills, key=lambda item: (-item.priority, item.domain, item.name))


def query_score(skill: Skill, query: str) -> int:
    query_terms = {term for term in re.split(r"[^a-z0-9]+", query.lower()) if len(term) >= 3}
    specific_query_terms = query_terms - GENERIC_QUERY_TERMS
    name = skill.name.lower()
    description = skill.description.lower()
    lexical = 0
    matched_terms = 0
    matched_specific_terms = 0
    for term in query_terms:
        term_score = 0
        generic = term in GENERIC_QUERY_TERMS
        if has_term(name, term):
            term_score = 8 if generic else 14
        elif has_term(description, term):
            term_score = 1 if generic else 4
        if term_score:
            lexical += term_score
            matched_terms += 1
            if not generic:
                matched_specific_terms += 1
    haystack = f"{name} {description}"
    if query_terms and all(has_term(haystack, term) for term in query_terms):
        lexical += 10
    if not matched_terms:
        return skill.priority - 100
    if len(specific_query_terms) >= 2 and matched_specific_terms == 1:
        lexical -= 12
    if not matched_specific_terms:
        return lexical * 10 + skill.priority - 80
    return lexical * 10 + skill.priority


def build_json(skills: list[Skill]) -> dict:
    return {
        "schema": 1,
        "generated_by": "scripts/curate_claude_skills.py",
        "total_skills": len(skills),
        "tier_counts": dict(sorted(Counter(skill.tier for skill in skills).items())),
        "domain_counts": dict(sorted(Counter(skill.domain for skill in skills).items())),
        "skills": [
            {
                "name": skill.name,
                "domain": skill.domain,
                "tier": skill.tier,
                "priority": skill.priority,
                "source": skill.source,
                "sensitivity": skill.sensitivity,
                "reasons": skill.reasons,
            }
            for skill in skills
        ],
    }


def table_row(values: list[str | int]) -> str:
    return "| " + " | ".join(str(value) for value in values) + " |"


def render_md(skills: list[Skill]) -> str:
    tier_counts = Counter(skill.tier for skill in skills)
    domain_counts = Counter(skill.domain for skill in skills)
    by_domain: dict[str, list[Skill]] = defaultdict(list)
    for skill in skills:
        by_domain[skill.domain].append(skill)

    lines: list[str] = [
        "# Claude Skill Curation",
        "",
        "Generated from local `SKILL.md` frontmatter by `scripts/curate_claude_skills.py --write`.",
        "Edit the script rules, then regenerate this file when skill inventory changes.",
        "",
        "## How to use this index",
        "",
        "1. Start broad work with T0/T1 skills, then add a specialist only when the target platform or tool is clear.",
        "1. Prefer coverage anchors for GRC, AI/LLM, IoT/embedded, mainframe, telecom/5G, SAP/ERP, and supply-chain work.",
        "1. Treat T3 skills as exact-match playbooks. They are useful, but noisy for open-ended prompts.",
        "1. For offensive or simulation skills, confirm authorization and environment before acting.",
        "",
        "## Tier Counts",
        "",
        table_row(["Tier", "Skills"]),
        table_row(["---", "---:"]),
    ]

    for tier, count in sorted(tier_counts.items()):
        lines.append(table_row([tier, count]))

    lines.extend([
        "",
        "## Domain Counts",
        "",
        table_row(["Domain", "Skills"]),
        table_row(["---", "---:"]),
    ])
    for domain, count in sorted(domain_counts.items()):
        lines.append(table_row([domain, count]))

    lines.extend([
        "",
        "## Highest Priority Skills",
        "",
        table_row(["Priority", "Skill", "Domain", "Tier"]),
        table_row(["---:", "---", "---", "---"]),
    ])
    for skill in skills[:30]:
        lines.append(table_row([skill.priority, f"`{skill.name}`", skill.domain, skill.tier]))

    lines.extend([
        "",
        "## Domain Anchors",
        "",
        "Top skills per domain. Use these as the first candidates before searching the long tail.",
        "",
    ])

    for domain in sorted(by_domain):
        lines.extend([
            f"### {domain}",
            "",
            table_row(["Priority", "Skill", "Tier", "Sensitivity"]),
            table_row(["---:", "---", "---", "---"]),
        ])
        for skill in sorted(by_domain[domain], key=lambda item: (-item.priority, item.name))[:10]:
            lines.append(table_row([skill.priority, f"`{skill.name}`", skill.tier, skill.sensitivity]))
        lines.append("")

    lines.extend([
        "## Query helper",
        "",
        "Use the script when the prompt is broad or many skills look similar:",
        "",
        "```bash",
        "python3 scripts/curate_claude_skills.py --query \"cloud incident response\" --top 10",
        "```",
    ])
    return "\n".join(lines) + "\n"


def print_query(skills: list[Skill], query: str, top: int) -> None:
    query_terms = {term for term in re.split(r"[^a-z0-9]+", query.lower()) if len(term) >= 3}
    min_score = 120 if len(query_terms - GENERIC_QUERY_TERMS) >= 2 else 50
    scored = sorted(
        ((query_score(skill, query), skill) for skill in skills),
        key=lambda item: (-item[0], -item[1].priority, item[1].name),
    )
    ranked = [(score, skill) for score, skill in scored if score >= min_score][:top]
    if not ranked:
        ranked = scored[:top]
    for score, skill in ranked:
        print(f"{score:3d}  p{skill.priority:03d}  {skill.tier:24s}  {skill.domain:24s}  {skill.name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Write .claude/skills/CURATION.md and curation.json")
    parser.add_argument("--json", action="store_true", help="Print curation JSON to stdout")
    parser.add_argument("--query", help="Rank skills for a query")
    parser.add_argument("--top", type=int, default=15, help="Number of query results or summary rows")
    args = parser.parse_args()

    skills = load_skills()
    data = build_json(skills)

    if args.write:
        CURATION_JSON.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        CURATION_MD.write_text(render_md(skills), encoding="utf-8")
        print(f"Wrote {CURATION_JSON.relative_to(ROOT)}")
        print(f"Wrote {CURATION_MD.relative_to(ROOT)}")

    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    elif args.query:
        print_query(skills, args.query, args.top)
    elif not args.write:
        print(f"Skills: {len(skills)}")
        print("Tier counts:")
        for tier, count in data["tier_counts"].items():
            print(f"  {tier}: {count}")
        print("Top skills:")
        for skill in skills[: args.top]:
            print(f"  {skill.priority:3d} {skill.tier:24s} {skill.name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
