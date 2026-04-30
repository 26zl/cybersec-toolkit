#!/usr/bin/env python3
"""
Impact Calculator - vuln-chain-composer
Recalculates CVSS and severity when vulnerabilities are chained.
Author: orizon.one
"""

import argparse
import json
import math
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


# CVSS v3.1 metric values
CVSS_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

# Severity impact amplification rules
AMPLIFICATION_RULES = {
    "Self-XSS + CSRF = Weaponized Stored XSS": {
        "original_severity": "LOW",
        "chain_severity": "HIGH",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "R",
            "S": "C", "C": "L", "I": "L", "A": "N",
        },
        "justification": "Self-XSS alone requires victim to inject payload into their own session. "
                         "Combined with CSRF, attacker can inject payload into any victim's session, "
                         "converting it to a stored XSS affecting other users.",
    },
    "Info Disclosure + Credential Reuse = Account Takeover": {
        "original_severity": "LOW",
        "chain_severity": "CRITICAL",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "C", "C": "H", "I": "H", "A": "L",
        },
        "justification": "Exposed credentials from info disclosure enable direct authentication "
                         "to other systems. If admin credentials are leaked, full system compromise is possible.",
    },
    "SSRF to Cloud Infrastructure Compromise": {
        "original_severity": "MEDIUM",
        "chain_severity": "CRITICAL",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "C", "C": "H", "I": "H", "A": "H",
        },
        "justification": "SSRF to cloud metadata endpoint exposes IAM credentials with potentially "
                         "broad permissions. This enables access to all cloud resources the instance can reach.",
    },
    "SQLi to Credential Theft to Account Takeover": {
        "original_severity": "HIGH",
        "chain_severity": "CRITICAL",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "C", "C": "H", "I": "H", "A": "L",
        },
        "justification": "SQL injection enables extraction of password hashes. Weak hashing algorithms "
                         "(MD5, SHA1) allow cracking. Cracked admin credentials give full application control.",
    },
    "XSS to Session Hijacking Across Subdomains": {
        "original_severity": "MEDIUM",
        "chain_severity": "CRITICAL",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "R",
            "S": "C", "C": "H", "I": "H", "A": "N",
        },
        "justification": "XSS on any subdomain can steal session cookies scoped to the parent domain, "
                         "enabling session hijacking across ALL subdomains under the same origin.",
    },
    "Subdomain Takeover to Cookie Theft": {
        "original_severity": "HIGH",
        "chain_severity": "CRITICAL",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "R",
            "S": "C", "C": "H", "I": "H", "A": "N",
        },
        "justification": "Subdomain takeover enables hosting attacker content on a trusted domain. "
                         "Wildcard cookies are automatically sent, enabling mass session hijacking.",
    },
    "Open Redirect + OAuth = Token Theft": {
        "original_severity": "LOW",
        "chain_severity": "HIGH",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "R",
            "S": "C", "C": "H", "I": "L", "A": "N",
        },
        "justification": "Open redirect in OAuth flow leaks authorization code/token to attacker. "
                         "This enables full account takeover without victim awareness.",
    },
    "IDOR + PII Exposure = Mass Data Breach": {
        "original_severity": "MEDIUM",
        "chain_severity": "CRITICAL",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "L", "UI": "N",
            "S": "U", "C": "H", "I": "N", "A": "N",
        },
        "justification": "IDOR with sequential IDs enables enumeration of all user records. "
                         "When records contain PII, this constitutes a mass data breach affecting all users.",
    },
    "SSRF + Public Bucket = Data Exfiltration": {
        "original_severity": "HIGH",
        "chain_severity": "CRITICAL",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "C", "C": "H", "I": "L", "A": "N",
        },
        "justification": "SSRF enables access to internal bucket endpoints that may not be directly "
                         "reachable. Combined with bucket misconfiguration, enables full data exfiltration.",
    },
    "CI/CD Access to Production RCE": {
        "original_severity": "HIGH",
        "chain_severity": "CRITICAL",
        "cvss_override": {
            "AV": "N", "AC": "L", "PR": "L", "UI": "N",
            "S": "C", "C": "H", "I": "H", "A": "H",
        },
        "justification": "Access to CI/CD pipeline enables injection of malicious code into the build "
                         "process, which gets deployed to production automatically. Full RCE on production.",
    },
}


def calculate_cvss_score(metrics, scope):
    """Calculate CVSS v3.1 base score from metrics."""
    av = CVSS_VALUES["AV"].get(metrics.get("AV", "N"), 0.85)
    ac = CVSS_VALUES["AC"].get(metrics.get("AC", "L"), 0.77)

    pr_scope = "C" if scope == "C" else "U"
    pr = CVSS_VALUES["PR"].get(metrics.get("PR", "N"), {}).get(pr_scope, 0.85)

    ui = CVSS_VALUES["UI"].get(metrics.get("UI", "N"), 0.85)
    c = CVSS_VALUES["C"].get(metrics.get("C", "N"), 0.0)
    i = CVSS_VALUES["I"].get(metrics.get("I", "N"), 0.0)
    a = CVSS_VALUES["A"].get(metrics.get("A", "N"), 0.0)

    # Impact Sub Score
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if scope == "C":
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)

    # Round up to one decimal
    return math.ceil(score * 10) / 10


def score_to_severity(score):
    """Convert CVSS score to severity string."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "NONE"


def calculate_chain_cvss(chain):
    """Calculate CVSS for a chain based on its combined impact."""
    chain_name = chain.get("name", "")

    # Check if we have a specific amplification rule
    rule = AMPLIFICATION_RULES.get(chain_name)
    if rule:
        metrics = rule["cvss_override"]
        scope = metrics.get("S", "U")
        score = calculate_cvss_score(metrics, scope)
        return {
            "cvss_score": score,
            "severity": score_to_severity(score),
            "cvss_vector": build_vector(metrics),
            "metrics": metrics,
            "justification": rule["justification"],
            "amplification": f"{rule['original_severity']} -> {rule['chain_severity']}",
            "rule_matched": chain_name,
        }

    # Generic CVSS calculation based on chain properties
    num_steps = chain.get("total_steps", len(chain.get("steps", chain.get("phases", []))))
    has_user_interaction = chain.get("requires_user_interaction", False)
    severity = chain.get("overall_severity", "HIGH")
    supporting = chain.get("supporting_findings", [])

    # Determine metrics heuristically
    metrics = {
        "AV": "N",  # Network (web vulns)
        "AC": "H" if num_steps > 5 else "L",
        "PR": "N",  # Assume no privileges required for initial step
        "UI": "R" if has_user_interaction else "N",
        "S": "C" if len(supporting) > 0 or severity == "CRITICAL" else "U",
        "C": "H" if severity in ("CRITICAL", "HIGH") else "L",
        "I": "H" if severity == "CRITICAL" else "L" if severity == "HIGH" else "N",
        "A": "L" if severity == "CRITICAL" else "N",
    }

    # Check primary finding for auth requirements
    primary = chain.get("primary_finding", {})
    if primary:
        vuln_type = primary.get("type", "")
        if "idor" in vuln_type or "bola" in vuln_type or "bfla" in vuln_type:
            metrics["PR"] = "L"  # Requires low-privilege auth

    scope = metrics.get("S", "U")
    score = calculate_cvss_score(metrics, scope)

    justification_parts = []
    if metrics["AC"] == "H":
        justification_parts.append(f"High attack complexity due to {num_steps} exploitation steps")
    if metrics["UI"] == "R":
        justification_parts.append("Requires user interaction (victim must click link or visit page)")
    if metrics["S"] == "C":
        justification_parts.append("Scope changed: chain crosses trust boundaries")
    if metrics["C"] == "H":
        justification_parts.append("High confidentiality impact from combined chain effect")

    return {
        "cvss_score": score,
        "severity": score_to_severity(score),
        "cvss_vector": build_vector(metrics),
        "metrics": metrics,
        "justification": ". ".join(justification_parts) + "." if justification_parts else "Generic chain impact calculation.",
        "amplification": chain.get("impact_amplification", f"-> {score_to_severity(score)}"),
        "rule_matched": None,
    }


def build_vector(metrics):
    """Build CVSS v3.1 vector string."""
    return (
        f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}"
        f"/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}"
        f"/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
    )


def main():
    parser = argparse.ArgumentParser(description="Impact Calculator - orizon.one")
    parser.add_argument("--input", "-i", required=True, help="Chains JSON file (output of build_chains.py or correlate.py)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    log("Calculating chained impact and CVSS scores...")

    with open(args.input) as f:
        data = json.load(f)

    chains = data.get("chains", [])
    log(f"Loaded {len(chains)} chains for impact calculation")

    if not chains:
        warn("No chains found in input.")
        return

    recalculated = []
    severity_changes = 0
    for chain in chains:
        cvss_result = calculate_chain_cvss(chain)
        original_severity = chain.get("overall_severity", chain.get("primary_finding", {}).get("severity", "MEDIUM"))

        chain_result = dict(chain)
        chain_result["impact_analysis"] = cvss_result
        chain_result["original_severity"] = original_severity
        chain_result["chain_severity"] = cvss_result["severity"]
        chain_result["cvss_score"] = cvss_result["cvss_score"]
        chain_result["cvss_vector"] = cvss_result["cvss_vector"]

        if cvss_result["severity"] != original_severity:
            severity_changes += 1

        recalculated.append(chain_result)

    # Sort by CVSS score descending
    recalculated.sort(key=lambda c: c.get("cvss_score", 0), reverse=True)

    # Stats
    by_severity = {}
    scores = []
    for c in recalculated:
        sev = c["chain_severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
        scores.append(c["cvss_score"])

    avg_score = sum(scores) / len(scores) if scores else 0
    max_score = max(scores) if scores else 0

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "impact_analysis",
            "tool": "vuln-chain-composer by orizon.one",
            "chains_analyzed": len(recalculated),
            "severity_amplifications": severity_changes,
            "max_cvss": max_score,
            "avg_cvss": round(avg_score, 1),
        },
        "chains": recalculated,
    }

    output_path = args.output or "impact_analysis.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  IMPACT ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"  Chains analyzed        : {len(recalculated)}")
    print(f"  Severity amplifications: {severity_changes}")
    print(f"  Max CVSS score         : {max_score}")
    print(f"  Avg CVSS score         : {round(avg_score, 1)}")
    print(f"\n  By Chain Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in by_severity:
            print(f"    {sev:10s} : {by_severity[sev]}")
    print(f"\n  Chain Impact Details:")
    for i, c in enumerate(recalculated[:10]):
        amp = c["impact_analysis"].get("amplification", "")
        rule = c["impact_analysis"].get("rule_matched", "")
        rule_info = f" [matched rule]" if rule else " [heuristic]"
        print(f"    {i+1}. {c.get('name', 'Unknown')} - CVSS {c['cvss_score']} ({c['chain_severity']})")
        print(f"       Vector: {c['cvss_vector']}")
        print(f"       Amplification: {amp}{rule_info}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
