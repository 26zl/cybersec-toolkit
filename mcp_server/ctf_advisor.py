"""CTF challenge-type to module/tool mapping with curated suggestions."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Optional

_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server.tools_db import ToolsDatabase  # noqa: E402

# Display name → tools_config.json registry name.
# Only needed when the user-facing name differs from the registry entry.
# Tools not listed here are assumed to match the registry name exactly.
TOOL_ALIASES: dict[str, str] = {
    # Case mismatches
    "cyberchef": "CyberChef",
    "responder": "Responder",
    "rsactftool": "RsaCtfTool",
    "seclists": "SecLists",
    "theharvester": "theHarvester",
    # Naming mismatches (display name → registry name)
    "jwt-tool": "jwt_tool",
    "afl++": "AFLplusplus",
    "upx": "upx-ucl",
    "exiftool": "libimage-exiftool-perl",
    "wireshark": "wireshark-common",
    "netcat": "netcat-openbsd",
    "wifite": "wifite2",
    "hashid": "hashid",
    "snow": "stegsnow",
    # Sub-components (display name → parent tool in registry)
    "photorec": "testdisk",
}

# Maps challenge type → description, relevant modules, and top tools with descriptions.
CTF_CATEGORY_MAP: dict[str, dict] = {
    "web": {
        "description": "Web application exploitation — SQL injection, XSS, SSRF, auth bypass, deserialization",
        "modules": ["web", "recon"],
        "tools": [
            ("burpsuite", "Intercepting proxy for web app testing"),
            ("sqlmap", "Automatic SQL injection exploitation"),
            ("nikto", "Web server vulnerability scanner"),
            ("gobuster", "Directory/DNS/vhost brute-forcing"),
            ("ffuf", "Fast web fuzzer"),
            ("httpx", "Fast HTTP toolkit for probing"),
            ("nuclei", "Template-based vulnerability scanner"),
            ("whatweb", "Web technology fingerprinting"),
            ("feroxbuster", "Fast content discovery tool"),
            ("arjun", "HTTP parameter discovery"),
            ("jwt-tool", "JWT token testing and exploitation"),
            ("dalfox", "XSS parameter analysis and scanning"),
        ],
    },
    "crypto": {
        "description": "Cryptography — cipher analysis, RSA attacks, hash cracking, encoding",
        "modules": ["crypto"],
        "tools": [
            ("sagemath", "Mathematical computation for crypto"),
            ("z3-solver", "SMT solver for constraint problems"),
            ("rsactftool", "RSA attack toolkit"),
            ("hashcat", "Advanced hash cracking (GPU)"),
            ("john", "John the Ripper password cracker"),
            ("xortool", "XOR cipher analysis"),
            ("factordb-python", "Integer factorization database client"),
            ("hashid", "Hash type identification"),
            ("name-that-hash", "Hash identification tool"),
        ],
    },
    "pwn": {
        "description": "Binary exploitation — buffer overflows, ROP chains, format strings, heap exploits",
        "modules": ["pwn"],
        "tools": [
            ("pwntools", "CTF framework for exploit development"),
            ("gdb", "GNU debugger (with pwndbg/GEF)"),
            ("pwndbg", "GDB plugin for exploit development"),
            ("ropper", "ROP gadget finder"),
            ("one_gadget", "One-shot execve gadget finder"),
            ("seccomp-tools", "Seccomp sandbox analysis"),
            ("boofuzz", "Network protocol fuzzer"),
            ("afl++", "Coverage-guided fuzzer"),
            ("checksec", "Binary security property checker"),
            ("ROPgadget", "ROP gadget search tool"),
        ],
    },
    "reversing": {
        "description": "Reverse engineering — disassembly, decompilation, malware analysis, patching",
        "modules": ["reversing"],
        "tools": [
            ("ghidra", "NSA reverse engineering framework"),
            ("radare2", "RE framework and hex editor"),
            ("rizin", "Fork of radare2 with improved APIs"),
            ("binwalk", "Firmware analysis and extraction"),
            ("strace", "System call tracer"),
            ("ltrace", "Library call tracer"),
            ("upx", "UPX packer/unpacker"),
            ("angr", "Binary analysis framework"),
            ("uncompyle6", "Python bytecode decompiler"),
            ("xrop", "ROP gadget search tool"),
        ],
    },
    "forensics": {
        "description": "Digital forensics — disk/memory analysis, file carving, network forensics, timeline",
        "modules": ["forensics"],
        "tools": [
            ("volatility3", "Memory forensics framework"),
            ("autopsy", "Digital forensics GUI platform"),
            ("sleuthkit", "Filesystem forensics toolkit"),
            ("foremost", "File carving tool"),
            ("binwalk", "Firmware and file extraction"),
            ("exiftool", "Metadata extraction"),
            ("oletools", "Microsoft Office file analysis"),
            ("peepdf-3", "PDF analysis framework"),
            ("hachoir", "Binary stream analysis"),
            ("photorec", "File recovery / carving"),
            ("bulk-extractor", "Bulk data extraction"),
        ],
    },
    "stego": {
        "description": "Steganography — hidden data in images, audio, text, and network protocols",
        "modules": ["stego"],
        "tools": [
            ("steghide", "Hide/extract data in images and audio"),
            ("stegseek", "Fast steghide cracker"),
            ("zsteg", "PNG/BMP steganography detector"),
            ("stegsolve", "Image steganography analysis"),
            ("openstego", "Digital watermarking and data hiding"),
            ("exiftool", "Image metadata analysis"),
            ("stegoveritas", "Multi-tool stego analyzer"),
            ("snow", "Whitespace steganography tool"),
        ],
    },
    "misc": {
        "description": "Miscellaneous CTF — general tools, encoding, scripting, cracking",
        "modules": ["misc", "cracking"],
        "tools": [
            ("cyberchef", "Data transformation Swiss army knife"),
            ("hashcat", "Advanced GPU hash cracker"),
            ("john", "John the Ripper password cracker"),
            ("hydra", "Online brute-force tool"),
            ("crunch", "Wordlist generator"),
            ("arsenal-cli", "Cheatsheet tool for pentesters"),
            ("seclists", "Security wordlists collection"),
            ("patator", "Multi-purpose brute-forcer"),
        ],
    },
    "networking": {
        "description": "Network challenges — packet analysis, protocol exploitation, traffic manipulation",
        "modules": ["networking"],
        "tools": [
            ("wireshark", "Network protocol analyzer (GUI)"),
            ("tshark", "CLI packet analyzer"),
            ("nmap", "Network scanner and service detection"),
            ("tcpdump", "Command-line packet capture"),
            ("scapy", "Packet manipulation framework"),
            ("netcat", "Network utility for reading/writing connections"),
            ("socat", "Multipurpose relay / socket tool"),
            ("masscan", "Fast port scanner"),
            ("responder", "LLMNR/NBT-NS/MDNS poisoner"),
            ("mitmproxy", "Intercepting HTTP/HTTPS proxy"),
        ],
    },
    "wireless": {
        "description": "Wireless security — WiFi cracking, Bluetooth exploitation, SDR",
        "modules": ["wireless"],
        "tools": [
            ("aircrack-ng", "WiFi security auditing suite"),
            ("kismet", "Wireless network detector/sniffer"),
            ("bettercap", "MITM and network attack tool"),
            ("wifite", "Automated WiFi cracking"),
            ("reaver", "WPS brute-force attack tool"),
            ("fluxion", "WiFi social engineering tool"),
            ("bluez", "Bluetooth protocol stack"),
            ("hackrf", "SDR tools for HackRF"),
            ("gnuradio", "Signal processing framework"),
        ],
    },
    "osint": {
        "description": "Open Source Intelligence — social media, domain, email, and people reconnaissance",
        "modules": ["recon"],
        "tools": [
            ("sherlock-project", "Username search across social networks"),
            ("theharvester", "Email/subdomain/IP harvester"),
            ("recon-ng", "OSINT reconnaissance framework"),
            ("spiderfoot", "OSINT automation"),
            ("amass", "Attack surface mapping"),
            ("subfinder", "Subdomain discovery"),
            ("shodan", "Shodan CLI for internet-wide scanning"),
            ("holehe", "Email to social media account checker"),
            ("maigret", "Username search across 2500+ sites"),
            ("maltego-trx", "Maltego transform SDK"),
        ],
    },
    "cloud": {
        "description": "Cloud security — AWS/Azure/GCP exploitation, container escapes, IAM abuse",
        "modules": ["cloud", "containers"],
        "tools": [
            ("scoutsuite", "Multi-cloud security auditing"),
            ("prowler", "AWS/Azure/GCP security assessments"),
            ("pacu", "AWS exploitation framework"),
            ("cloudfox", "Cloud penetration testing"),
            ("trufflehog", "Secret scanning in code/cloud"),
            ("trivy", "Container vulnerability scanner"),
            ("kube-hunter", "Kubernetes penetration testing"),
            ("deepce", "Docker enumeration and escape"),
            ("cloudsplaining", "AWS IAM policy analyzer"),
        ],
    },
    "mobile": {
        "description": "Mobile security — Android/iOS app analysis, APK reversing, dynamic testing",
        "modules": ["mobile"],
        "tools": [
            ("apktool", "APK reverse engineering"),
            ("jadx", "DEX to Java decompiler"),
            ("frida-tools", "Dynamic instrumentation toolkit"),
            ("mvt", "Mobile Verification Toolkit"),
            ("objection", "Runtime mobile exploration"),
            ("androguard", "Android app reverse engineering"),
            ("quark-engine", "Android malware scoring"),
            ("nuclei", "Vulnerability scanner with mobile templates"),
        ],
    },
    "blockchain": {
        "description": "Blockchain security — smart contract auditing, EVM analysis, DeFi exploits",
        "modules": ["blockchain"],
        "tools": [
            ("slither-analyzer", "Solidity static analyzer"),
            ("mythril", "EVM bytecode security analyzer"),
            ("foundry", "Smart contract development toolkit"),
            ("solc-select", "Solidity compiler version manager"),
            ("echidna", "Ethereum smart contract fuzzer"),
        ],
    },
}

# Aliases for category names.
CATEGORY_ALIASES: dict[str, str] = {
    "re": "reversing",
    "rev": "reversing",
    "binary": "pwn",
    "exploitation": "pwn",
    "steganography": "stego",
    "network": "networking",
    "recon": "osint",
    "intelligence": "osint",
    "wifi": "wireless",
    "container": "cloud",
    "kubernetes": "cloud",
    "docker": "cloud",
    "android": "mobile",
    "ios": "mobile",
    "smart-contract": "blockchain",
    "solidity": "blockchain",
    "dfir": "forensics",
    "memory": "forensics",
}


def resolve_category(challenge_type: str) -> Optional[str]:
    """Resolve a challenge type string to a canonical category name."""
    normalized = challenge_type.lower().strip()
    if normalized in CTF_CATEGORY_MAP:
        return normalized
    return CATEGORY_ALIASES.get(normalized)


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


def suggest_for_ctf(
    challenge_type: str, tools_db: ToolsDatabase
) -> dict:
    """Return tool suggestions for a CTF challenge type with install status.

    Returns dict with: category, description, modules, tools (with install status).
    """
    category = resolve_category(challenge_type)
    if not category:
        available = sorted(CTF_CATEGORY_MAP.keys())
        aliases = sorted(CATEGORY_ALIASES.keys())
        return {
            "error": f"Unknown challenge type: '{challenge_type}'",
            "available_categories": available,
            "available_aliases": aliases,
        }

    cat_info = CTF_CATEGORY_MAP[category]
    tools_with_status = []
    for tool_name, description in cat_info["tools"]:
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

    return {
        "category": category,
        "description": cat_info["description"],
        "modules": cat_info["modules"],
        "tools": tools_with_status,
        "summary": f"{installed_count}/{len(tools_with_status)} tools installed",
    }
