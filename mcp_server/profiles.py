"""Profile recommendation engine — parses profiles/*.conf, recommends profiles or individual tools."""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path
from typing import Optional

_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server.tools_db import MODULE_DESCRIPTIONS, ToolsDatabase  # noqa: E402

# Termux runs without sudo; Linux requires it.
_SUDO = "" if os.environ.get("TERMUX_VERSION") else "sudo "

# All 14 profiles parsed from profiles/*.conf (hardcoded to avoid filesystem
# dependency at import time — these rarely change and must match the .conf files).
PROFILES: dict[str, dict] = {
    "full": {
        "description": "All 568 tools across all 18 modules — the complete arsenal",
        "modules": [
            "misc",
            "networking",
            "recon",
            "web",
            "crypto",
            "pwn",
            "reversing",
            "forensics",
            "enterprise",
            "wireless",
            "cracking",
            "stego",
            "cloud",
            "containers",
            "blueteam",
            "mobile",
            "blockchain",
            "llm",
        ],
        "skip_heavy": False,
        "enable_docker": False,
        "include_c2": True,
    },
    "ctf": {
        "description": "Tools for Capture The Flag competitions",
        "modules": [
            "misc",
            "crypto",
            "pwn",
            "reversing",
            "stego",
            "forensics",
            "cracking",
            "web",
            "mobile",
            "blockchain",
        ],
        "skip_heavy": True,
        "enable_docker": False,
        "include_c2": False,
    },
    "redteam": {
        "description": "Offensive security — red team operations and pentesting",
        "modules": [
            "misc",
            "networking",
            "recon",
            "web",
            "enterprise",
            "pwn",
            "mobile",
            "cracking",
            "cloud",
            "wireless",
            "reversing",
            "crypto",
        ],
        "skip_heavy": True,
        "enable_docker": True,
        "include_c2": True,
    },
    "web": {
        "description": "Web application security testing",
        "modules": ["misc", "networking", "recon", "web"],
        "skip_heavy": True,
        "enable_docker": False,
        "include_c2": False,
    },
    "osint": {
        "description": "Open Source Intelligence gathering",
        "modules": ["misc", "recon"],
        "skip_heavy": True,
        "enable_docker": False,
        "include_c2": False,
    },
    "forensics": {
        "description": "Digital forensics and incident response",
        "modules": ["misc", "forensics", "blueteam", "reversing", "stego", "cracking"],
        "skip_heavy": False,
        "enable_docker": False,
        "include_c2": False,
    },
    "pwn": {
        "description": "Binary exploitation and reverse engineering",
        "modules": ["misc", "pwn", "reversing", "crypto"],
        "skip_heavy": False,
        "enable_docker": False,
        "include_c2": False,
    },
    "mobile": {
        "description": "Android/iOS application security testing",
        "modules": ["misc", "mobile", "web", "reversing"],
        "skip_heavy": True,
        "enable_docker": True,
        "include_c2": False,
    },
    "cloud": {
        "description": "Cloud and container security (AWS/Azure/GCP/K8s)",
        "modules": ["misc", "cloud", "containers", "networking", "recon"],
        "skip_heavy": True,
        "enable_docker": False,
        "include_c2": False,
    },
    "blockchain": {
        "description": "Smart contract auditing and blockchain security",
        "modules": ["misc", "blockchain", "web", "crypto"],
        "skip_heavy": True,
        "enable_docker": True,
        "include_c2": False,
    },
    "wireless": {
        "description": "WiFi, Bluetooth, and SDR security",
        "modules": ["misc", "wireless", "networking"],
        "skip_heavy": False,
        "enable_docker": False,
        "include_c2": False,
    },
    "crackstation": {
        "description": "Password cracking and hash analysis",
        "modules": ["misc", "cracking", "crypto"],
        "skip_heavy": True,
        "enable_docker": False,
        "include_c2": False,
    },
    "lightweight": {
        "description": "Minimal footprint — essential tools only",
        "modules": ["misc", "networking", "recon", "web", "cracking"],
        "skip_heavy": True,
        "enable_docker": False,
        "include_c2": False,
    },
    "blueteam": {
        "description": "Defensive security — IDS, SIEM, IR, malware analysis",
        "modules": [
            "misc",
            "blueteam",
            "forensics",
            "reversing",
            "mobile",
            "containers",
            "networking",
            "cloud",
            "recon",
        ],
        "skip_heavy": True,
        "enable_docker": True,
        "include_c2": False,
    },
}

# Keywords that map to profiles and modules. Each keyword has a list of
# (profile, weight) tuples — higher weight = stronger match.
# Also maps to individual modules for fine-grained recommendation.
_KEYWORD_MAP: dict[str, list[tuple[str, float]]] = {
    # Activity-based
    "ctf": [("ctf", 3.0)],
    "capture the flag": [("ctf", 3.0)],
    "competition": [("ctf", 2.0)],
    "jeopardy": [("ctf", 2.5)],
    "pentest": [("redteam", 3.0)],
    "penetration test": [("redteam", 3.0)],
    "red team": [("redteam", 3.0)],
    "offensive": [("redteam", 2.5)],
    "bug bounty": [("web", 2.5), ("redteam", 1.0)],
    "blue team": [("blueteam", 3.0)],
    "defensive": [("blueteam", 2.5)],
    "incident response": [("blueteam", 2.5), ("forensics", 2.0)],
    "soc": [("blueteam", 2.5)],
    "threat hunting": [("blueteam", 2.0)],
    "malware analysis": [("blueteam", 2.0), ("forensics", 1.5)],
    # Domain-based
    "web": [("web", 3.0)],
    "webapp": [("web", 3.0)],
    "web app": [("web", 3.0)],
    "website": [("web", 2.5)],
    "api": [("web", 2.0)],
    "sql injection": [("web", 2.5)],
    "xss": [("web", 2.5)],
    "osint": [("osint", 3.0)],
    "open source intelligence": [("osint", 3.0)],
    "reconnaissance": [("osint", 2.5)],
    "recon": [("osint", 2.5)],
    "social media": [("osint", 2.0)],
    "forensics": [("forensics", 3.0)],
    "forensic": [("forensics", 3.0)],
    "dfir": [("forensics", 3.0), ("blueteam", 1.0)],
    "disk": [("forensics", 2.0)],
    "memory analysis": [("forensics", 2.5)],
    "file carving": [("forensics", 2.0)],
    "binary exploitation": [("pwn", 3.0)],
    "pwn": [("pwn", 3.0)],
    "exploit": [("pwn", 2.5), ("redteam", 1.0)],
    "buffer overflow": [("pwn", 3.0)],
    "rop": [("pwn", 2.5)],
    "shellcode": [("pwn", 2.5)],
    "heap": [("pwn", 2.0)],
    "reverse engineering": [("pwn", 2.0)],
    "reversing": [("pwn", 2.0)],
    "disassembly": [("pwn", 2.0)],
    "decompile": [("pwn", 1.5)],
    "crypto": [("ctf", 1.5), ("crackstation", 2.0)],
    "cryptography": [("ctf", 1.5), ("crackstation", 2.0)],
    "cipher": [("crackstation", 2.0)],
    "hash": [("crackstation", 2.5)],
    "password": [("crackstation", 2.5)],
    "cracking": [("crackstation", 3.0)],
    "brute force": [("crackstation", 2.5)],
    "wordlist": [("crackstation", 2.0)],
    "steganography": [("ctf", 1.5)],
    "stego": [("ctf", 1.5)],
    "hidden data": [("ctf", 1.0)],
    "wireless": [("wireless", 3.0)],
    "wifi": [("wireless", 3.0)],
    "bluetooth": [("wireless", 2.5)],
    "sdr": [("wireless", 2.5)],
    "aircrack": [("wireless", 2.0)],
    "cloud": [("cloud", 3.0)],
    "aws": [("cloud", 3.0)],
    "azure": [("cloud", 3.0)],
    "gcp": [("cloud", 3.0)],
    "kubernetes": [("cloud", 2.5)],
    "k8s": [("cloud", 2.5)],
    "docker": [("cloud", 2.0)],
    "container": [("cloud", 2.0)],
    "mobile": [("mobile", 3.0)],
    "android": [("mobile", 3.0)],
    "ios": [("mobile", 3.0)],
    "apk": [("mobile", 2.5)],
    "frida": [("mobile", 2.0)],
    "blockchain": [("blockchain", 3.0)],
    "smart contract": [("blockchain", 3.0)],
    "solidity": [("blockchain", 3.0)],
    "ethereum": [("blockchain", 2.5)],
    "defi": [("blockchain", 2.0)],
    "evm": [("blockchain", 2.5)],
    "llm": [("full", 1.0)],
    "ai security": [("full", 1.0)],
    "active directory": [("redteam", 2.5)],
    "kerberos": [("redteam", 2.5)],
    "ldap": [("redteam", 2.0)],
    "lateral movement": [("redteam", 2.5)],
    "c2": [("redteam", 2.5)],
    "command and control": [("redteam", 2.5)],
    # Scope-based
    "everything": [("full", 3.0)],
    "all tools": [("full", 3.0)],
    "complete": [("full", 2.5)],
    "minimal": [("lightweight", 3.0)],
    "lightweight": [("lightweight", 3.0)],
    "quick": [("lightweight", 2.5)],
    "basic": [("lightweight", 2.0)],
    "essential": [("lightweight", 2.0)],
    "beginner": [("lightweight", 2.0), ("ctf", 1.0)],
    "learning": [("lightweight", 1.5), ("ctf", 1.5)],
    "student": [("ctf", 2.0), ("lightweight", 1.0)],
}

# Module keyword map — maps keywords to specific modules for individual tool recommendations.
_MODULE_KEYWORDS: dict[str, list[str]] = {
    "misc": ["utility", "general", "c2", "social engineering", "arsenal"],
    "networking": ["network", "nmap", "packet", "port scan", "tcpdump", "wireshark", "tunnel", "mitm", "proxy"],
    "recon": ["subdomain", "osint", "recon", "enumeration", "reconnaissance", "sherlock", "harvester", "amass"],
    "web": ["web", "http", "sql", "xss", "burp", "fuzzing", "directory", "api", "webapp", "website", "injection"],
    "crypto": ["crypto", "cipher", "rsa", "aes", "encoding", "decryption", "z3"],
    "pwn": ["pwn", "exploit", "binary", "buffer overflow", "rop", "shellcode", "gdb", "heap", "format string"],
    "reversing": ["reverse", "disassembly", "decompile", "ghidra", "radare", "ida", "binary analysis", "malware"],
    "forensics": ["forensic", "memory", "disk", "carving", "volatility", "autopsy", "timeline", "artifact"],
    "enterprise": ["active directory", "kerberos", "ldap", "bloodhound", "impacket", "lateral", "azure ad"],
    "wireless": ["wifi", "wireless", "bluetooth", "sdr", "aircrack", "wpa", "radio"],
    "cracking": ["crack", "hash", "password", "brute force", "wordlist", "hashcat", "john"],
    "stego": ["stego", "steganography", "hidden", "watermark", "lsb"],
    "cloud": ["cloud", "aws", "azure", "gcp", "s3", "iam", "lambda"],
    "containers": ["container", "docker", "kubernetes", "k8s", "pod", "trivy"],
    "blueteam": ["blue team", "defensive", "ids", "ips", "siem", "yara", "sigma", "incident response", "detection"],
    "mobile": ["mobile", "android", "ios", "apk", "frida", "objection"],
    "blockchain": ["blockchain", "smart contract", "solidity", "evm", "ethereum", "defi"],
    "llm": ["llm", "ai security", "prompt injection", "ai red team"],
}


def _score_profiles(task: str) -> dict[str, float]:
    """Score each profile against a task description using keyword matching."""
    task_lower = task.lower()
    scores: dict[str, float] = {name: 0.0 for name in PROFILES}

    for keyword, profile_weights in _KEYWORD_MAP.items():
        if keyword in task_lower:
            for profile_name, weight in profile_weights:
                scores[profile_name] += weight

    return scores


def _match_modules(task: str) -> list[tuple[str, float]]:
    """Score individual modules against a task description."""
    task_lower = task.lower()
    scores: dict[str, float] = {}

    for module, keywords in _MODULE_KEYWORDS.items():
        score = 0.0
        for kw in keywords:
            if kw in task_lower:
                score += 1.0
        if score > 0:
            scores[module] = score

    return sorted(scores.items(), key=lambda x: x[1], reverse=True)


def _match_individual_tools(task: str, tools_db: ToolsDatabase) -> list[dict]:
    """Find specific tools mentioned by name in the task description."""
    task_lower = task.lower()
    matched = []
    for tool in tools_db.tools_by_name.values():
        # Match tool name (at least 3 chars to avoid false positives)
        if len(tool["name"]) >= 3 and tool["name"].lower() in task_lower:
            matched.append(tool)
    return matched


def _count_profile_tools(profile_name: str, tools_db: ToolsDatabase) -> int:
    """Count how many tools a profile would install."""
    profile = PROFILES[profile_name]
    modules = profile["modules"]
    return sum(1 for t in tools_db._tools if t["module"] in modules)


def recommend_install(task: str, tools_db: ToolsDatabase) -> dict:
    """Recommend what to install based on a task description.

    Analyzes the user's description and returns:
    - Best matching profile (if a profile fits well)
    - Alternative: individual modules/tools if only a subset is needed
    - The install commands for the recommendation
    """
    if not task or not task.strip():
        return {
            "error": "Please describe what you want to do (e.g., 'CTF web challenges', "
            "'pentest a web application', 'crack password hashes').",
            "available_profiles": list(PROFILES.keys()),
        }

    # 1. Check if specific tools are mentioned by name
    mentioned_tools = _match_individual_tools(task, tools_db)

    # 2. Score profiles
    profile_scores = _score_profiles(task)
    ranked_profiles = sorted(profile_scores.items(), key=lambda x: x[1], reverse=True)
    top_profiles = [(name, score) for name, score in ranked_profiles if score > 0]

    # 3. Score individual modules
    matched_modules = _match_modules(task)

    # Decision logic: recommend individual tools, a few modules, or a full profile

    # Case A: User mentioned specific tools by name → recommend just those
    if mentioned_tools and not top_profiles:
        modules_needed = sorted(set(t["module"] for t in mentioned_tools))
        return {
            "recommendation": "individual_tools",
            "reason": f"Found {len(mentioned_tools)} specific tool(s) mentioned",
            "tools": [
                {
                    "name": t["name"],
                    "module": t["module"],
                    "method": t["method"],
                    "installed": tools_db.check_installed(t["name"])["installed"],
                }
                for t in mentioned_tools
            ],
            "modules_needed": modules_needed,
            "install_commands": _build_install_commands(
                modules=modules_needed, tools=[t["name"] for t in mentioned_tools]
            ),
        }

    # Case B: Strong profile match
    if top_profiles and top_profiles[0][1] >= 2.0:
        best_name, best_score = top_profiles[0]
        best_profile = PROFILES[best_name]
        tool_count = _count_profile_tools(best_name, tools_db)

        result = {
            "recommendation": "profile",
            "profile": best_name,
            "description": best_profile["description"],
            "score": best_score,
            "modules": best_profile["modules"],
            "module_details": [
                {"name": m, "description": MODULE_DESCRIPTIONS.get(m, "")} for m in best_profile["modules"]
            ],
            "tool_count": tool_count,
            "skip_heavy": best_profile["skip_heavy"],
            "enable_docker": best_profile["enable_docker"],
            "include_c2": best_profile["include_c2"],
            "install_command": f"{_SUDO}./install.sh --profile {best_name}",
        }

        # Add alternatives if close scores
        alternatives = []
        for name, score in top_profiles[1:4]:
            if score >= 1.5:
                alternatives.append(
                    {
                        "profile": name,
                        "description": PROFILES[name]["description"],
                        "score": score,
                        "tool_count": _count_profile_tools(name, tools_db),
                        "install_command": f"{_SUDO}./install.sh --profile {name}",
                    }
                )
        if alternatives:
            result["alternatives"] = alternatives

        # If specific tools were also mentioned, note them
        if mentioned_tools:
            result["mentioned_tools"] = [
                {
                    "name": t["name"],
                    "module": t["module"],
                    "in_profile": t["module"] in best_profile["modules"],
                    "installed": tools_db.check_installed(t["name"])["installed"],
                }
                for t in mentioned_tools
            ]

        return result

    # Case C: Module-level match — user needs a few specific modules, not a full profile
    if matched_modules:
        modules_needed = [m for m, _ in matched_modules[:4]]  # Top 4 max
        tool_count = sum(1 for t in tools_db._tools if t["module"] in modules_needed)

        result = {
            "recommendation": "modules",
            "reason": "Your task maps to specific modules — no need for a full profile",
            "modules": [
                {
                    "name": m,
                    "description": MODULE_DESCRIPTIONS.get(m, ""),
                    "tool_count": sum(1 for t in tools_db._tools if t["module"] == m),
                }
                for m in modules_needed
            ],
            "total_tools": tool_count,
            "install_commands": _build_install_commands(modules=modules_needed),
        }

        # Also suggest the closest profile as alternative
        if top_profiles:
            best_name, best_score = top_profiles[0]
            result["profile_alternative"] = {
                "profile": best_name,
                "description": PROFILES[best_name]["description"],
                "tool_count": _count_profile_tools(best_name, tools_db),
                "install_command": f"{_SUDO}./install.sh --profile {best_name}",
            }

        if mentioned_tools:
            result["mentioned_tools"] = [
                {
                    "name": t["name"],
                    "module": t["module"],
                    "installed": tools_db.check_installed(t["name"])["installed"],
                }
                for t in mentioned_tools
            ]

        return result

    # Case D: No clear match — show available options
    return {
        "recommendation": "unclear",
        "reason": f"Could not determine a clear recommendation from: '{task}'",
        "suggestions": [
            "Try describing your activity: 'CTF competition', 'web pentesting', 'password cracking'",
            "Or mention specific tools: 'nmap and burpsuite'",
            "Or specify a domain: 'cloud security', 'mobile testing', 'forensics'",
        ],
        "available_profiles": {
            name: {
                "description": p["description"],
                "modules": len(p["modules"]),
                "tool_count": _count_profile_tools(name, tools_db),
            }
            for name, p in PROFILES.items()
        },
    }


def list_profiles(tools_db: ToolsDatabase) -> dict:
    """List all available profiles with module counts and tool counts."""
    profiles_info = []
    for name, profile in PROFILES.items():
        tool_count = _count_profile_tools(name, tools_db)
        profiles_info.append(
            {
                "name": name,
                "description": profile["description"],
                "modules": profile["modules"],
                "module_count": len(profile["modules"]),
                "tool_count": tool_count,
                "skip_heavy": profile["skip_heavy"],
                "enable_docker": profile["enable_docker"],
                "include_c2": profile["include_c2"],
                "install_command": f"{_SUDO}./install.sh --profile {name}",
            }
        )

    return {
        "total_profiles": len(profiles_info),
        "profiles": profiles_info,
    }


def _build_install_commands(
    modules: Optional[list[str]] = None,
    tools: Optional[list[str]] = None,
) -> list[str]:
    """Build the install.sh commands for given modules/tools."""
    commands = []
    if modules:
        module_args = " ".join(f"--module {shlex.quote(m)}" for m in modules)
        commands.append(f"{_SUDO}./install.sh {module_args}")
    if tools:
        tool_args = " ".join(f"--tool {shlex.quote(t)}" for t in tools)
        commands.append(f"{_SUDO}./install.sh {tool_args}")
    return commands
