"""Guided assessment planning for companion and autonomous MCP workflows."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import shutil
from pathlib import Path
from urllib.parse import urlparse

from mcp_server.advisor_utils import TOOL_ALIASES
from mcp_server.bounty_advisor import resolve_target_type, suggest_for_bounty
from mcp_server.ctf_advisor import resolve_category, suggest_for_ctf
from mcp_server.security import SYSTEM_UTILITIES
from mcp_server.tools_db import C2_TOOLS, ToolsDatabase

MODES = {"companion", "autonomous"}
INTENSITIES = {"low", "medium"}
WORKFLOWS = {"bounty", "ctf", "generic"}
MANUAL_SCRIPTS_DIR = "manual_scripts/"

# The MCP tools the agent drives during a guided assessment. This MUST equal the
# set of @mcp.tool functions registered in server.py — validate_mcp_sync.py asserts
# the two stay in lock-step so a tool rename/add can't silently drift this list.
MCP_TOOLCHAIN: list[str] = [
    "list_tools",
    "check_installed",
    "get_tool_info",
    "get_module_info",
    "get_profile_tools",
    "suggest_for_ctf",
    "suggest_for_bounty",
    "guided_assessment",
    "get_cve_info",
    "recommend_install",
    "list_profiles",
    "run_tool",
    "run_pipeline",
    "run_script",
    "manage_remote_hosts",
]

_FILE_CTF_CATEGORIES = {"crypto", "pwn", "reversing", "forensics", "stego", "misc", "mobile", "blockchain"}
_LOCAL_HOSTS = {"localhost", "localhost.localdomain"}
_SHELL_META_RE = re.compile(r"[;&|`$<>]")
# URL targets carry '&' and ';' legitimately in query strings (?id=1&x=2). There
# is no shell on the execution path (create_subprocess_exec + shlex.quote), so a
# URL only needs the genuinely dangerous shell metacharacters blocked; '&' and ';'
# are allowed for URLs. Non-URL targets keep the stricter _SHELL_META_RE.
# The executor's sanitize_args also allows '&'/';' (they are literals without a
# shell) and blocks only | ` $( ${, so a planned multi-param URL runs as-is.
_URL_META_RE = re.compile(r"[|`$<>]")

_FINDING_TYPE_RULES = [
    ("xss", ("xss", "cross-site scripting", "cross site scripting", "script injection")),
    ("idor_bola", ("idor", "bola", "broken object", "object level", "unauthorized object")),
    ("ssrf", ("ssrf", "server-side request forgery", "metadata service", "169.254.169.254")),
    ("oauth_oidc", ("oauth", "oidc", "open redirect", "redirect_uri", "authorization code")),
    ("graphql", ("graphql", "introspection", "__schema", "resolver")),
    ("file_upload", ("file upload", "upload bypass", "polyglot", "content-type bypass")),
    ("race_condition", ("race", "concurrent", "double spend", "time-of-check", "toc tou", "toctou")),
    ("http_smuggling", ("http request smuggling", "request smuggling", "cl.te", "te.cl", "h2.cl")),
    ("cache_poisoning", ("cache poisoning", "web cache", "cache deception")),
    ("sqli", ("sqli", "sql injection", "union select", "blind sql")),
    ("auth_bypass", ("auth bypass", "authentication bypass", "privilege escalation", "priv-esc")),
    ("csrf", ("csrf", "cross-site request forgery", "cross site request forgery")),
    ("xxe", ("xxe", "xml external entity")),
    ("ssti", ("ssti", "server-side template", "template injection")),
    ("path_traversal", ("path traversal", "directory traversal", "../", "lfi", "local file inclusion")),
    ("rce", ("rce", "remote code execution", "command injection", "shell injection")),
    ("secret_exposure", ("secret", "api key", "token leak", "credential", "password exposed")),
]

_FINDING_SKILL_ROUTES = {
    "xss": ["web2-vuln-classes", "security-arsenal"],
    "idor_bola": ["web2-vuln-classes", "triage-validation"],
    "ssrf": ["web2-vuln-classes", "security-arsenal"],
    "oauth_oidc": ["web2-vuln-classes", "security-arsenal"],
    "graphql": ["web2-vuln-classes", "bounty-api"],
    "file_upload": ["web2-vuln-classes", "security-arsenal"],
    "race_condition": ["web2-vuln-classes"],
    "http_smuggling": ["web2-vuln-classes", "security-arsenal"],
    "cache_poisoning": ["web2-vuln-classes", "security-arsenal"],
    "sqli": ["web2-vuln-classes", "security-arsenal"],
    "auth_bypass": ["web2-vuln-classes", "triage-validation"],
    "csrf": ["web2-vuln-classes"],
    "xxe": ["web2-vuln-classes", "security-arsenal"],
    "ssti": ["web2-vuln-classes", "security-arsenal"],
    "path_traversal": ["web2-vuln-classes", "security-arsenal"],
    "rce": ["web2-vuln-classes", "triage-validation"],
    "secret_exposure": ["evidence-hygiene", "triage-validation"],
}

# Auto-detection: map a local file's extension to the most likely CTF category so the
# default mode can pick the right toolset without the caller specifying target_type.
_FILE_EXT_CATEGORY = {
    ".bin": "pwn",
    ".elf": "pwn",
    ".exe": "reversing",
    ".dll": "reversing",
    ".so": "reversing",
    ".o": "reversing",
    ".axf": "reversing",
    ".jar": "reversing",
    ".war": "reversing",
    ".class": "reversing",
    ".dex": "reversing",
    ".pcap": "forensics",
    ".pcapng": "forensics",
    ".cap": "forensics",
    ".zip": "forensics",
    ".tar": "forensics",
    ".gz": "forensics",
    ".7z": "forensics",
    ".pdf": "forensics",
    ".doc": "forensics",
    ".docx": "forensics",
    ".xls": "forensics",
    ".xlsx": "forensics",
    ".mem": "forensics",
    ".dmp": "forensics",
    ".vmem": "forensics",
    ".raw": "forensics",
    ".img": "forensics",
    ".iso": "forensics",
    ".png": "stego",
    ".jpg": "stego",
    ".jpeg": "stego",
    ".bmp": "stego",
    ".gif": "stego",
    ".wav": "stego",
    ".mp3": "stego",
    ".flac": "stego",
    ".sol": "blockchain",
    ".apk": "mobile",
    ".ipa": "mobile",
    ".pem": "crypto",
    ".pub": "crypto",
    ".key": "crypto",
    ".crt": "crypto",
    ".der": "crypto",
    ".csr": "crypto",
}


def _infer_workflow_type(target: str, kind: str, workflow: str | None = None) -> tuple[str, str]:
    """Best-effort: pick (workflow, target_type) from the target itself.

    Used when workflow/target_type are passed as "auto" so the default mode selects
    the right tools for the problem without the caller knowing the taxonomy.

    When *workflow* is an explicit, non-auto workflow ("ctf"/"bounty"), the inferred
    target_type is constrained to THAT workflow's taxonomy (CTF category vs bounty
    target type). Otherwise a host under workflow="ctf" would yield the bounty type
    "network", _resolve_workflow would reject it, and the plan would silently fall
    back to "generic" (advisor returns 0 tools).
    """
    explicit = workflow if workflow in {"ctf", "bounty"} else None

    if kind == "file":
        ext = Path(target).suffix.lower()
        category = _FILE_EXT_CATEGORY.get(ext, "misc")
        if explicit == "bounty":
            # Files are not a bounty target type. Map mobile bundles to the
            # mobile_app taxonomy; otherwise default to web_app so the bounty
            # advisor still returns a usable toolset instead of resolving to
            # nothing (which would silently degrade to the empty generic plan).
            return "bounty", "mobile_app" if category == "mobile" else "web_app"
        return "ctf", category
    if kind == "url":
        parsed = urlparse(target)
        scheme = (parsed.scheme or "").lower()
        if scheme in ("http", "https"):
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            is_api = host.startswith("api.") or "/api/" in path or "graphql" in path
            if explicit == "ctf":
                return "ctf", "web"
            return "bounty", "api" if is_api else "web_app"
        # Non-web scheme (ftp://, file://, gopher://, ...) — a web toolset is
        # meaningless; classify on the hostname like any other network target.
        if explicit == "ctf":
            return "ctf", "networking"
        return "bounty", "network"
    # host
    if explicit == "ctf":
        return "ctf", "networking"
    return "bounty", "network"


def _quote(value: str) -> str:
    return shlex.quote(value)


def _target_kind(target: str, workflow: str, target_type: str | None) -> str:
    parsed = urlparse(target)
    if parsed.scheme:
        return "url"
    # Treat as a local file ONLY when the target carries an explicit path sigil
    # or separator. A bare token (e.g. "internal-host") must NOT be classified as
    # a file just because a same-named file happens to exist in the server CWD —
    # that would bypass network recon and drop the authorization floor. The CTF
    # file-category path below still covers bare-name challenge files explicitly.
    if target.startswith(("/", "./", "../", "~")) or "/" in target:
        return "file"
    if workflow == "ctf" and target_type in _FILE_CTF_CATEGORIES:
        return "file"
    # A bare token with a known challenge-file extension (e.g. "challenge.bin",
    # "secret.png") is a CTF file, not a host. The extension lookup is purely
    # lexical (no filesystem access) so it can't be tricked by a same-named file
    # in the server CWD. A hostname-shaped token (TLD, no known file ext) still
    # falls through to "host".
    if Path(target).suffix.lower() in _FILE_EXT_CATEGORY:
        return "file"
    return "host"


def _host_from_target(target: str, kind: str) -> str | None:
    if kind == "url":
        return urlparse(target).hostname
    if kind == "host":
        return target.strip("[]")
    return None


def _target_is_external(host: str | None) -> bool:
    if not host:
        return False
    lowered = host.lower().rstrip(".")
    if lowered in _LOCAL_HOSTS:
        return False
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        # DNS can resolve differently at check vs connect time. Treat hostnames as
        # external until the execution policy validates them at run time.
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)


def _normalize_target(target: str, workflow: str, target_type: str | None) -> dict:
    clean = target.strip()
    if not clean:
        raise ValueError("target is required")

    kind = _target_kind(clean, workflow, target_type)
    # URLs may contain '&'/';' in query strings; only genuine shell metacharacters
    # are blocked there. Every other target type stays on the stricter rule.
    meta_re = _URL_META_RE if kind == "url" else _SHELL_META_RE
    if meta_re.search(clean):
        raise ValueError("target contains shell metacharacters; pass a bare URL, host, IP, or file path")

    host = _host_from_target(clean, kind)
    parsed = urlparse(clean)
    return {
        "raw": clean,
        "kind": kind,
        "host": host,
        "scheme": parsed.scheme if kind == "url" else "",
        "network": kind in {"url", "host"},
        "appears_external": _target_is_external(host),
    }


def _resolve_workflow(workflow: str, target_type: str) -> tuple[str, str | None, dict]:
    workflow_norm = workflow.lower().strip()
    if workflow_norm not in WORKFLOWS:
        return (
            workflow_norm,
            None,
            {
                "error": f"Unknown workflow '{workflow}'. Available: {', '.join(sorted(WORKFLOWS))}",
            },
        )

    target_norm = target_type.lower().strip()
    if workflow_norm == "bounty":
        resolved = resolve_target_type(target_norm)
        if not resolved:
            return workflow_norm, None, {"error": f"Unknown bounty target_type '{target_type}'"}
        return workflow_norm, resolved, {}

    if workflow_norm == "ctf":
        resolved = resolve_category(target_norm)
        if not resolved:
            return workflow_norm, None, {"error": f"Unknown CTF target_type '{target_type}'"}
        return workflow_norm, resolved, {}

    return workflow_norm, target_norm or "generic", {}


def _tool_status(tool_name: str, tools_db: ToolsDatabase) -> dict:
    # Shares the TOOL_ALIASES source with advisor_utils.check_tool_installed but
    # intentionally does NOT reuse it: this returns a richer dict (registry_name,
    # details, requires_include_c2) and, for in-registry tools, trusts
    # tools_db.check_installed without the extra shutil.which(tool_name) fallback
    # that check_tool_installed applies. Keep the two in lockstep on aliasing only.
    registry_name = TOOL_ALIASES.get(tool_name, tool_name)
    in_registry = registry_name in tools_db.tools_by_name
    if in_registry:
        status = tools_db.check_installed(registry_name)
        return {
            "installed": bool(status["installed"]),
            "in_registry": True,
            "registry_name": registry_name,
            "details": status["details"],
            "requires_include_c2": registry_name in C2_TOOLS,
        }
    if tool_name in SYSTEM_UTILITIES:
        path = shutil.which(tool_name)
        return {
            "installed": path is not None,
            "in_registry": False,
            "registry_name": None,
            "details": f"found at {path}" if path else "not installed or not in PATH",
            "requires_include_c2": False,
        }
    path = shutil.which(tool_name)
    return {
        "installed": path is not None,
        "in_registry": False,
        "registry_name": None,
        "details": f"found at {path}" if path else "not installed or not in registry",
        "requires_include_c2": False,
    }


def _step(
    step_id: str,
    phase: str,
    tool: str,
    args: str,
    rationale: str,
    *,
    risk: str = "low",
    auto_safe: bool = True,
    network: bool = True,
) -> dict:
    return {
        "id": step_id,
        "phase": phase,
        "tool": tool,
        "args": args,
        "risk": risk,
        "auto_safe": auto_safe,
        "network": network,
        "rationale": rationale,
    }


def _network_steps(target: dict, target_type: str, workflow: str) -> list[dict]:
    raw_q = _quote(target["raw"])
    host = target["host"]
    host_q = _quote(host) if host else raw_q
    steps: list[dict] = []

    if host:
        steps.append(_step("dns_lookup", "recon", "dig", f"+short {host_q}", "Resolve the target host before probing."))

    if target_type in {"web_app", "api", "cloud", "web"} or workflow == "generic":
        steps.extend(
            [
                _step(
                    "http_headers",
                    "recon",
                    "curl",
                    f"-I -L --max-time 15 {raw_q}",
                    "Collect headers, redirects, server hints, and obvious auth boundaries.",
                ),
                _step(
                    "tech_fingerprint",
                    "recon",
                    "whatweb",
                    f"--no-errors {raw_q}",
                    "Fingerprint web technologies without fuzzing or exploitation.",
                ),
                _step(
                    "http_probe",
                    "recon",
                    "httpx",
                    f"-u {raw_q} -status-code -title -tech-detect -follow-redirects -silent",
                    "Probe HTTP metadata and title/technology signals with a single target.",
                ),
            ]
        )

    if target_type in {"network", "iot", "networking"}:
        steps.append(_step("ping_check", "recon", "ping", f"-c 1 {host_q}", "Check basic reachability."))

    if host and target_type in {"web_app", "api", "cloud", "network", "iot", "web", "networking"}:
        steps.append(
            _step(
                "top_ports",
                "recon",
                "nmap",
                f"-sV --top-ports 20 --max-retries 2 -T2 {host_q}",
                "Low-volume service/version discovery for the named target.",
                risk="medium",
                auto_safe=True,
            )
        )

    if target_type in {"web_app", "api", "web"}:
        steps.append(
            _step(
                "template_scan_plan",
                "scan",
                "nuclei",
                f"-u {raw_q} -severity low,medium -rate-limit 5",
                "Template scan with rate limiting. Review scope and impact before running.",
                risk="medium",
                auto_safe=False,
            )
        )

    if target_type == "api":
        steps.append(
            _step(
                "parameter_discovery_plan",
                "scan",
                "arjun",
                f"-u {raw_q}",
                "Parameter discovery can be noisy; run only after confirming allowed test volume.",
                risk="medium",
                auto_safe=False,
            )
        )

    return steps


def _file_steps(target: dict, target_type: str) -> list[dict]:
    path_q = _quote(target["raw"])
    steps = [
        _step(
            "file_type",
            "identify",
            "file",
            path_q,
            "Identify the file type before choosing a deeper workflow.",
            network=False,
        ),
        _step(
            "strings_preview",
            "triage",
            "strings",
            f"-a -n 6 {path_q}",
            "Extract readable strings for quick indicators, secrets, URLs, and flag formats.",
            network=False,
        ),
        _step(
            "hex_header",
            "triage",
            "xxd",
            f"-l 256 {path_q}",
            "Inspect the first bytes for magic values.",
            network=False,
        ),
    ]
    if target_type in {"forensics", "stego", "reversing", "mobile", "misc"}:
        steps.append(
            _step(
                "metadata",
                "triage",
                "exiftool",
                path_q,
                "Read embedded metadata when exiftool is available.",
                network=False,
            )
        )
    if target_type in {"forensics", "stego", "reversing", "mobile"}:
        steps.append(
            _step(
                "embedded_files",
                "triage",
                "binwalk",
                path_q,
                "Check for embedded files or firmware-style containers.",
                risk="medium",
                auto_safe=False,
                network=False,
            )
        )
    return steps


def _generic_steps(target: dict, target_type: str, workflow: str) -> list[dict]:
    if target["kind"] == "file":
        return _file_steps(target, target_type)
    return _network_steps(target, target_type, workflow)


def _advisor(workflow: str, target_type: str, tools_db: ToolsDatabase) -> dict:
    if workflow == "bounty":
        return suggest_for_bounty(target_type, tools_db)
    if workflow == "ctf":
        return suggest_for_ctf(target_type, tools_db)
    return {
        "workflow": "generic",
        "target_type": target_type,
        "summary": "Generic companion workflow; use bounty or ctf for richer methodology.",
        "tools": [],
        "methodology": [
            "1. Confirm authorization and scope.",
            "2. Identify the target type with lightweight tools.",
            "3. Start with low-impact identification and evidence gathering.",
            "4. Review findings before any intrusive testing.",
        ],
    }


def _recommended_next_command(steps: list[dict]) -> dict | None:
    """Pick the next command companion mode should recommend to the user."""
    if not steps:
        return None

    # Prefer installed, low-risk steps. Fall back to the first step so the user
    # still sees what to install or run manually if nothing is available locally.
    chosen = next(
        (step for step in steps if step.get("installed") and step.get("auto_safe") and step.get("risk") == "low"),
        steps[0],
    )
    return {
        "tool": chosen["tool"],
        "args": chosen["args"],
        "command": chosen["command"],
        "installed": chosen["installed"],
        "risk": chosen["risk"],
        "rationale": chosen["rationale"],
        "run_tool_call": f"run_tool({json.dumps(chosen['tool'])}, {json.dumps(chosen['args'])})",
        "recommendation": (
            f"I recommend running run_tool({json.dumps(chosen['tool'])}, {json.dumps(chosen['args'])}) "
            f"because: {chosen['rationale']}"
        ),
    }


def _manual_script_fallback() -> dict:
    """Describe when the agent may create and run custom helper scripts."""
    return {
        "available": True,
        "created_by": "AI/client agent, not the user",
        "persistent_directory": MANUAL_SCRIPTS_DIR,
        "requires_env": "CYBERSEC_MCP_ALLOW_SCRIPTS=1",
        "mode_policy": (
            "companion proposes the script and writes/runs it only after user approval or a clear continue; "
            "autonomous may create, save, and run scoped scripts as part of the explicit auto-solver contract."
        ),
        "when_to_use": [
            "a registry/system tool cannot express the required loop, parser, exploit, solver, or protocol logic",
            "real output has produced a lead, but 2-3 appropriate tool attempts do not make progress",
            "the task needs an agent-created reusable or multi-step helper that should persist "
            "beyond one run_script call",
        ],
        "rules": [
            "use run_tool/run_pipeline first for existing tools and simple command composition",
            "keep simple HTTP/recon commands in run_tool (for example curl) rather than recreating them in scripts",
            "do not use run_script to bypass MCP network, scope, blocked-flag, or authorization policy",
            f"the AI/client agent writes reusable scripts under {MANUAL_SCRIPTS_DIR} with clear names; "
            "keep throwaway code inside run_script",
            "keep scripts scoped to the target and remove temporary secrets/artifacts when done",
        ],
    }


def _finding_classification(finding: str, target_type: str) -> dict:
    """Classify a supplied finding summary without echoing sensitive text."""
    normalized = " ".join(finding.lower().split())
    if not normalized:
        return {
            "provided": False,
            "type": "unknown",
            "confidence": "none",
            "matched_terms": [],
            "note": "No finding summary supplied; collect evidence before report triage.",
        }

    for finding_type, terms in _FINDING_TYPE_RULES:
        matched = [term for term in terms if term in normalized]
        if matched:
            return {
                "provided": True,
                "type": finding_type,
                "confidence": "high",
                "matched_terms": matched[:5],
                "note": "Finding text was classified locally; raw finding text is not echoed in the MCP response.",
            }

    if target_type == "api":
        inferred = "api_security"
    elif target_type in {"web_app", "web"}:
        inferred = "web_security"
    elif target_type == "mobile_app":
        inferred = "mobile_security"
    elif target_type == "cloud":
        inferred = "cloud_security"
    else:
        inferred = "unknown"
    return {
        "provided": True,
        "type": inferred,
        "confidence": "low",
        "matched_terms": [],
        "note": "No specific bug class matched; use triage-validation before report writing.",
    }


def _classification(target: dict, workflow: str, target_type: str, finding: str) -> dict:
    finding_info = _finding_classification(finding, target_type)
    route = "bug_bounty" if workflow == "bounty" else workflow
    return {
        "route": route,
        "workflow": workflow,
        "target_type": target_type,
        "target_kind": target["kind"],
        "target_host": target["host"],
        "network_target": target["network"],
        "external_target": target["appears_external"],
        "finding": finding_info,
    }


def _skill(name: str, reason: str) -> dict:
    return {"name": name, "reason": reason}


def _recommended_skills(workflow: str, target_type: str, classification: dict, target: dict) -> list[dict]:
    skills: list[dict] = []

    def add(name: str, reason: str) -> None:
        if all(entry["name"] != name for entry in skills):
            skills.append(_skill(name, reason))

    if target["network"]:
        add("authorization-gate", "Confirm written authorization and exact in-scope assets before network testing.")

    if workflow == "bounty":
        add("bb-methodology", "Keep the bug bounty session in the recon -> hunt -> validate -> report loop.")
        add("bug-bounty", "Use the master bounty workflow for recon, hunt, validate, chain, and report decisions.")
        if target_type in {"web_app", "api"}:
            add("web2-recon", "Map web/API attack surface before deeper testing.")
            add("web2-vuln-classes", "Route the target or finding to web bug-class-specific checks.")
        if target_type == "api":
            add("bounty-api", "Use API and GraphQL-specific testing methodology.")
        elif target_type == "mobile_app":
            add("bounty-mobile", "Use mobile app static/dynamic testing methodology.")
        elif target_type == "web_app":
            add("bounty-web", "Use web application testing methodology.")

        finding_type = classification["finding"]["type"]
        for routed_skill in _FINDING_SKILL_ROUTES.get(finding_type, []):
            add(routed_skill, f"Supports the classified finding type: {finding_type}.")
        add("triage-validation", "Run the reportability gates before investing in report writing.")
        add(
            "evidence-hygiene",
            "Redact tokens, cookies, PII, HAR secrets, and screenshot leaks before sharing evidence.",
        )
        add("report-writing", "Turn a validated, sanitized finding into a platform-ready bounty report.")
    elif workflow == "ctf":
        ctf_skill = {
            "crypto": "ctf-crypto",
            "pwn": "ctf-pwn",
            "reversing": "ctf-rev",
            "forensics": "ctf-forensics",
            "stego": "ctf-stego",
            "web": "ctf-web",
        }.get(target_type)
        if ctf_skill:
            add(ctf_skill, "Use the category-specific CTF decision tree.")
        add("evidence-hygiene", "Avoid leaking credentials or private challenge artifacts in shared writeups.")
    else:
        add("finding-triage", "Normalize any result into fixed/deferred/accepted-risk/false-positive disposition.")
        add("security-comms", "Translate validated results for the target audience.")
        add("evidence-hygiene", "Sanitize evidence before storing or sharing it.")

    add("writeup-template", "Write the required project writeup after the flag, finding, or result is confirmed.")
    return skills


def _triage_gate(
    *,
    classification: dict,
    authorization_confirmed: bool,
    auth_required: bool,
    target_external_block: bool,
) -> dict:
    gates = [
        {
            "name": "authorization_scope",
            "status": "pass" if authorization_confirmed or not auth_required else "blocked",
            "requirement": "Target is CTF/lab/owned or explicitly in written scope.",
        },
        {
            "name": "external_policy",
            "status": "blocked" if target_external_block else "pass",
            "requirement": "External targets require CYBERSEC_MCP_ALLOW_EXTERNAL=1 after scope is confirmed.",
        },
        {
            "name": "finding_classification",
            "status": "pass" if classification["finding"]["provided"] else "needed",
            "requirement": "Provide or collect a concrete finding summary before report triage.",
        },
        {
            "name": "impact_reproducibility",
            "status": "required",
            "requirement": "Prove affected asset, actor, exact steps, impact, and reproducibility.",
        },
        {
            "name": "evidence_hygiene",
            "status": "required",
            "requirement": "Sanitize cookies, tokens, PII, screenshots, HAR files, logs, and payload output.",
        },
        {
            "name": "reportability",
            "status": "required",
            "requirement": "Run triage-validation before report-writing; one failed gate means do not report.",
        },
    ]

    if auth_required and not authorization_confirmed:
        status = "blocked"
        next_required = "Confirm authorization/scope before running network tools or validating a report."
    elif target_external_block:
        status = "blocked"
        next_required = "Enable CYBERSEC_MCP_ALLOW_EXTERNAL=1 only for authorized external scope, then restart MCP."
    elif not classification["finding"]["provided"]:
        status = "needs_finding"
        next_required = "Collect or pass a concrete finding summary, then run triage-validation."
    else:
        status = "needs_validation"
        next_required = "Run triage-validation, then evidence-hygiene, then report-writing if all gates pass."

    return {
        "status": status,
        "report_ready": False,
        "next_required": next_required,
        "gates": gates,
    }


def _reporting_next_steps(classification: dict, triage_gate: dict) -> list[str]:
    steps = []
    if triage_gate["status"] == "blocked":
        steps.append(triage_gate["next_required"])
    if not classification["finding"]["provided"]:
        steps.append("Collect a concrete finding summary and reproducible evidence before report writing.")
    steps.extend(
        [
            "Run triage-validation: verify scope, affected asset, real impact, reproducibility, and duplicate risk.",
            "Run evidence-hygiene: redact cookies, tokens, PII, secrets, HAR data, screenshots, and noisy logs.",
            "If every triage gate passes, use report-writing for the external report and "
            "writeup-template for the project writeup.",
            "If any gate fails, keep the result as notes or a dead end; do not submit a speculative report.",
        ]
    )
    return steps


def build_guided_plan(
    *,
    target: str,
    finding: str = "",
    target_type: str,
    workflow: str,
    mode: str,
    intensity: str,
    authorization_confirmed: bool,
    max_steps: int,
    external_enabled: bool,
    tools_db: ToolsDatabase,
) -> dict:
    """Build a companion plan and optional autonomous execution candidates."""
    mode_norm = mode.lower().strip()
    if mode_norm not in MODES:
        return {"error": f"Unknown mode '{mode}'. Available: {', '.join(sorted(MODES))}"}
    intensity_norm = intensity.lower().strip()
    if intensity_norm not in INTENSITIES:
        return {"error": f"Unknown intensity '{intensity}'. Available: {', '.join(sorted(INTENSITIES))}"}

    # Auto tool selection: when workflow/target_type are "auto", infer only the
    # field(s) actually set to "auto" so the default mode picks the right tools.
    # When the workflow is explicit (e.g. "ctf") but target_type is "auto", the
    # inference must stay inside THAT workflow's taxonomy — otherwise it produces
    # a cross-taxonomy type (e.g. bounty's "network" under workflow="ctf") that
    # _resolve_workflow rejects, silently degrading to the empty generic plan.
    auto_detected = None
    workflow_is_auto = workflow.lower().strip() == "auto"
    target_type_is_auto = target_type.lower().strip() == "auto"
    if workflow_is_auto or target_type_is_auto:
        kind = _target_kind(target.strip(), "generic", None)
        explicit_workflow = None if workflow_is_auto else workflow.lower().strip()
        inf_workflow, inf_type = _infer_workflow_type(target.strip(), kind, explicit_workflow)
        if workflow_is_auto:
            workflow = inf_workflow
        if target_type_is_auto:
            target_type = inf_type
        auto_detected = {"workflow": workflow, "target_type": target_type, "from_target_kind": kind}

    workflow_norm, resolved_type, workflow_error = _resolve_workflow(workflow, target_type)
    if workflow_error:
        # The genuinely-auto-workflow path must never dead-end on an unrecognized
        # type — fall back to the always-valid "generic" workflow, which still
        # yields useful triage (file → file/strings/xxd, host/url → basic recon)
        # for the agent to build on. An explicit workflow (ctf/bounty) keeps its
        # taxonomy: a bad type there surfaces the error rather than silently
        # degrading to the empty generic plan.
        if workflow_is_auto:
            workflow_norm, resolved_type, workflow_error = _resolve_workflow("generic", target_type)
            if auto_detected is not None:
                auto_detected["fallback"] = "generic"
        if workflow_error:
            return workflow_error

    try:
        target_info = _normalize_target(target, workflow_norm, resolved_type)
    except ValueError as exc:
        return {"error": str(exc)}

    advisor = _advisor(workflow_norm, resolved_type or "generic", tools_db)
    raw_steps = _generic_steps(target_info, resolved_type or "generic", workflow_norm)
    classification = _classification(target_info, workflow_norm, resolved_type or "generic", finding)

    annotated_steps = []
    for step in raw_steps:
        status = _tool_status(step["tool"], tools_db)
        enriched = {
            **step,
            "installed": status["installed"],
            "in_registry": status["in_registry"],
            "registry_name": status["registry_name"],
            "install_details": status["details"],
            "requires_include_c2": status["requires_include_c2"],
            "command": f"{step['tool']} {step['args']}".strip(),
        }
        if status["requires_include_c2"]:
            enriched["auto_safe"] = False
            enriched["blocked_reason"] = "C2/phishing tools are never auto-executed by guided_assessment"
        annotated_steps.append(enriched)

    allowed_risk = {"low"} if intensity_norm == "low" else {"low", "medium"}
    target_external_block = target_info["network"] and target_info["appears_external"] and not external_enabled
    auth_required = target_info["network"]

    execution_candidates = []
    for step in annotated_steps:
        if len(execution_candidates) >= max(0, max_steps):
            break
        if not step["auto_safe"] or step["risk"] not in allowed_risk:
            continue
        if not step["installed"]:
            continue
        if target_external_block and step["network"]:
            continue
        execution_candidates.append(step)

    missing_recommended = [
        tool
        for tool in advisor.get("tools", [])
        if isinstance(tool, dict) and tool.get("in_registry") and not tool.get("installed")
    ][:10]

    # Steps the model must drive itself (exploitation / medium-risk / not auto-run).
    candidate_ids = {step["id"] for step in execution_candidates}
    model_driven_steps = [step for step in annotated_steps if step["id"] not in candidate_ids]
    recommended_next = _recommended_next_command(annotated_steps)

    mcp_toolchain = list(MCP_TOOLCHAIN)
    toolchain_scope = {
        "selection": (
            "Tool selection is not limited to the bootstrap steps. The agent may use the whole "
            "registry, every module/profile, advisor output, and install-status data to decide "
            "what fits the task."
        ),
        "execution": (
            "Execution uses the existing MCP path: run_tool, run_pipeline, and run_script. "
            "Default companion mode does not auto-run commands inside this call; "
            "the agent runs the next command only when the user approves or asks it to continue. "
            "autonomous is the explicit opt-in mode for the full auto-solver loop."
        ),
        "profiles_modules": (
            "All profiles/modules remain discoverable through get_profile_tools, get_module_info, and list_tools."
        ),
        "mcp_tools": mcp_toolchain,
    }
    manual_script_fallback = _manual_script_fallback()
    recommended_skills = _recommended_skills(workflow_norm, resolved_type or "generic", classification, target_info)
    triage_gate = _triage_gate(
        classification=classification,
        authorization_confirmed=authorization_confirmed,
        auth_required=auth_required,
        target_external_block=target_external_block,
    )
    reporting_next_steps = _reporting_next_steps(classification, triage_gate)

    companion = None
    if mode_norm == "companion":
        companion = {
            "directive": (
                "COMPANION MODE — infer the problem type, recommend the right tools from the full "
                "registry/modules/profiles, and help the user solve step by step. Do not auto-run "
                "commands inside guided_assessment itself; continue through run_tool/run_pipeline/"
                "run_script as the user approves each step or asks to proceed."
            ),
            "recommended_next_command": recommended_next,
            "not_limited_to_recon": (
                "Reconnaissance is only the first information-gathering phase. Companion mode may "
                "move into analysis, exploitation validation, forensics, reversing, crypto, cloud, "
                "mobile, reporting, or any other in-scope workflow by choosing the appropriate MCP tools."
            ),
            "script_fallback": manual_script_fallback,
        }

    autonomous: dict | None = None
    if mode_norm == "autonomous":
        autonomous = {
            "directive": (
                "AUTHORIZED AUTONOMOUS SOLVER MODE — guided_assessment is the entry point to the full "
                "MCP toolchain. It auto-runs the selected bootstrap below, then the client "
                "agent should keep solving with MCP tools: inspect install status, choose tools from the "
                "advisor output and registry, run commands with run_tool/run_pipeline, use run_script for "
                "scoped custom logic (pwntools, z3, requests, crypto, parsers), and create persistent "
                f"helper scripts under {MANUAL_SCRIPTS_DIR} for the user when that is the smallest "
                "reliable path forward. "
                "Iterate on real output, pivot after 2-3 failed attempts, and finish with a writeup when "
                "the flag/finding/result is confirmed."
            ),
            "default_contract": (
                "Default guided_assessment mode is companion: it auto-detects the workflow/problem type, "
                "selects the right tools, and helps the user solve step by step without auto-running "
                "commands inside the initial call. Autonomous solving is opt-in only via mode='autonomous' "
                "plus authorization_confirmed=true for network targets."
            ),
            "toolchain_access": toolchain_scope,
            "guardrails": (
                "Stay strictly inside the authorized scope. Never run C2/phishing, DoS/high-volume, "
                "credential-stuffing, or destructive actions. Every command still passes the MCP execution "
                "policy (scope/external/blocked-flag checks). For external targets, authorization_confirmed "
                "must be true and CYBERSEC_MCP_ALLOW_EXTERNAL=1."
            ),
            "use_mcp_tools": mcp_toolchain,
            "use_skills": [entry["name"] for entry in recommended_skills],
            "script_fallback": manual_script_fallback,
        }

    return {
        "target": target_info,
        "classification": classification,
        "workflow": workflow_norm,
        "target_type": resolved_type,
        "auto_detected": auto_detected,
        "mode": mode_norm,
        "intensity": intensity_norm,
        "authorization": {
            "confirmed": authorization_confirmed,
            "required_for_execution": auth_required,
            "status": "cleared" if authorization_confirmed or not auth_required else "required",
            "note": (
                "Network assessment execution requires explicit authorization. "
                "CTF/lab/owned targets clear this by setting authorization_confirmed=true."
            ),
        },
        "external_policy": {
            "allow_external": external_enabled,
            "target_appears_external": target_info["appears_external"],
            "execution_blocked": target_external_block,
            "note": (
                "Set CYBERSEC_MCP_ALLOW_EXTERNAL=1 and restart the MCP server for authorized external targets."
                if target_external_block
                else "External-target policy permits this plan or the target appears local/private."
            ),
        },
        "advisor": advisor,
        "triage_gate": triage_gate,
        "recommended_skills": recommended_skills,
        "reporting_next_steps": reporting_next_steps,
        "toolchain_scope": toolchain_scope,
        "manual_script_fallback": manual_script_fallback,
        "companion": companion,
        "autonomous": autonomous,
        "plan": {
            "steps": annotated_steps,
            "execution_candidates": execution_candidates,
            "model_driven_steps": model_driven_steps,
            "missing_recommended_tools": missing_recommended,
            "recommended_next_command": recommended_next,
        },
        "execution": {
            "status": "not_started",
            "results": [],
            "reason": _execution_reason(mode_norm, authorization_confirmed, auth_required, target_external_block),
        },
        "next_actions": _next_actions(mode_norm, authorization_confirmed, auth_required, target_external_block),
    }


# Modes that auto-execute selected bootstrap steps inside this MCP call.
_EXECUTING_MODES = {"autonomous"}


def _execution_reason(mode: str, authorization_confirmed: bool, auth_required: bool, external_blocked: bool) -> str:
    if mode not in _EXECUTING_MODES:
        if mode == "companion":
            return (
                "mode=companion; no automatic execution inside this call; continue with MCP tools as the user approves"
            )
        return f"mode={mode}; no automatic execution inside this call"
    if auth_required and not authorization_confirmed:
        return "authorization_confirmed=false; no network tools executed"
    if external_blocked:
        return "external target blocked by CYBERSEC_MCP_ALLOW_EXTERNAL=0"
    return "ready"


def _next_actions(mode: str, authorization_confirmed: bool, auth_required: bool, external_blocked: bool) -> list[str]:
    actions = []
    if auth_required and not authorization_confirmed:
        actions.append("Confirm written authorization/scope, then rerun with authorization_confirmed=true.")
    if external_blocked:
        actions.append("For authorized external targets, set CYBERSEC_MCP_ALLOW_EXTERNAL=1 and restart the MCP server.")
    if mode == "companion":
        actions.append(
            "Continue as an interactive companion: recommend the next command, explain why, "
            "run it with run_tool/run_pipeline after user approval, propose agent-created scripts when "
            "scoped custom logic is needed, write/run them after approval or a clear continue, persist "
            f"reusable helpers in {MANUAL_SCRIPTS_DIR}, and keep iterating through the full "
            "registry/modules/profiles until the task is solved or needs explicit escalation."
        )
    elif mode == "autonomous":
        actions.append(
            "Continue the user-approved auto-solver loop (the recon bootstrap above is already done): "
            "for each lead, run tools via run_tool/run_pipeline and create+run scoped helper scripts via "
            f"run_script when needed; persist reusable agent-created helpers in {MANUAL_SCRIPTS_DIR}. "
            "Iterate on real output, pivot after 2-3 failures, stay strictly "
            "inside the authorized scope, pause if scope/risk changes, and write a writeup at the end."
        )
    return actions
