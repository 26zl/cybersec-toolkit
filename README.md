# CyberSec Tools Installer

The most comprehensive automated installer for cybersecurity and penetration testing tools on Linux. Installs **440+ tools** across **16 modules** using **10 install methods** with a single command. Modular, profile-based architecture with multi-distro support.

## Supported Distros

| Family | Distros |
| ------ | ------- |
| Debian/Ubuntu | Debian, Ubuntu, Kali, Parrot, Linux Mint, Pop!_OS, Elementary, Zorin, MX |
| Fedora/RHEL | Fedora, RHEL, CentOS, Rocky, Alma, Nobara |
| Arch | Arch, Manjaro, EndeavourOS, Garuda, Artix |
| openSUSE | openSUSE Leap/Tumbleweed, SLES |

## Features

- **440+ tools** across 16 specialized modules
- **9 install profiles** — full, ctf, redteam, web, malware, osint, crackstation, lightweight, blueteam
- **10 install methods** — apt, pipx, go, cargo, gem, git clone, binary release, Docker, snap, build-from-source
- **Multi-distro** — auto-detects your distro and translates package names across apt/dnf/pacman/zypper
- **Modular** — install only the modules you need with `--module`
- **Profile-based** — predefined tool sets for common use cases with `--profile`
- **Safe defaults** — no system upgrade unless `--upgrade-system`, base deps preserved on removal
- **Privilege splitting** — system packages as root, pipx/go/cargo as your user
- **Dry run** — preview what would be installed with `--dry-run`
- **Version tracking** — `.versions` file tracks every installed tool
- **Progress bars** — visual progress tracking with detailed logging
- **Verification** — check what's installed across all methods
- **Update** — keep everything current with per-method skip flags
- **Removal** — clean uninstall by module or everything at once
- **Config backup** — backup/restore tool configs with AES-256-CBC encryption

## Quick Start

```bash
git clone https://github.com/26zl/cybersec-tools-installer.git
cd cybersec-tools-installer
sudo ./install.sh
```

### Common Usage

```bash
# Full install (all 440+ tools)
sudo ./install.sh

# Install a profile
sudo ./install.sh --profile ctf
sudo ./install.sh --profile redteam --enable-docker

# Install specific modules
sudo ./install.sh --module web --module recon
sudo ./install.sh --module ad --module networking

# Preview without installing
sudo ./install.sh --dry-run --profile ctf

# Skip heavy packages (sagemath, gnuradio, etc.)
sudo ./install.sh --skip-heavy

# Also upgrade all system packages before installing
sudo ./install.sh --upgrade-system

# List available profiles and modules
sudo ./install.sh --list-profiles
sudo ./install.sh --list-modules
```

## Profiles

| Profile | Modules | Description |
| ------- | ------- | ----------- |
| `full` | All 16 modules | Everything — complete security toolkit |
| `ctf` | misc, crypto, pwn, reversing, stego, forensics, password, web | Capture The Flag competitions |
| `redteam` | misc, networking, recon, web, ad, pwn | Offensive security operations |
| `web` | misc, networking, recon, web | Web application security testing |
| `malware` | misc, malware, forensics, reversing | Malware analysis and reverse engineering |
| `osint` | misc, recon | Open source intelligence gathering |
| `crackstation` | misc, password, crypto | Password cracking and hash analysis |
| `lightweight` | misc, networking, recon, web | Core tools only for limited disk/laptops |
| `blueteam` | misc, blueteam, forensics, malware, containers | Defensive security and incident response |

## Modules

### `misc` — Base Dependencies, C2, Social Engineering & Resources (~105 tools)

The foundation module, always installed first. Provides build toolchains (gcc, make, python3, ruby, go, java), essential utilities, and large reference collections. Includes **post-exploitation** tools for privilege escalation and lateral movement (PEASS-ng, LinEnum, PowerSploit, LaZagne, mimipenguin), **social engineering** frameworks for phishing campaigns (SET, Zphisher, Gophish, king-phisher, Modlishka), **C2 frameworks** for command-and-control operations (Sliver, Havoc, Mythic, PoshC2, Empire via Docker), **CTF platforms** (CyberChef, Caldera, atomic-red-team), and **wordlists/resources** (SecLists, PayloadsAllTheThings, FuzzDB, GTFOBins). Heavy packages like sagemath can be skipped with `--skip-heavy`.

### `networking` — Port Scanning, Packet Capture, Tunneling & MITM (~50 tools)

Everything for network reconnaissance and manipulation. **Port scanners** (nmap, masscan, RustScan, zmap), **packet capture and analysis** (tcpdump, Wireshark/tshark, netsniff-ng, tcpflow, ngrep), **tunneling and pivoting** for moving through networks (chisel, ligolo-ng, frp, iodine, dns2tcp, sshuttle, redsocks, proxychains4), **MITM attacks** (ettercap, mitmproxy, bettercap, dsniff, sslstrip, sslsplit), **protocol tools** (socat, netcat, cryptcat, hping3, arping, fping), **DNS tools** (dnschef), **enumeration** (smbmap, nbtscan, onesixtyone, arp-scan), and **anonymity** (tor, macchanger). Also includes Snort and Zeek for traffic analysis.

### `recon` — OSINT, Subdomain Enumeration & Intelligence Gathering (~80 tools)

The largest module for reconnaissance and open source intelligence. **Subdomain enumeration** (subfinder, amass, assetfinder, puredns, shuffledns, massdns, Findomain, subbrute), **web discovery** (httpx, gowitness, hakrawler, katana, waybackurls, gau), **DNS tools** (dnsx, dnstwist, dnsrecon, dnsenum, altdns, dnsmap), **OSINT/people search** (sherlock, maigret, holehe, phoneinfoga, h8mail, social-analyzer, ghunt, inspy), **automated recon** (reconftw, autorecon, Sn1per, bbot, finalrecon), **GitHub/cloud recon** (gitleaks, github-subdomains, certSniff, AWSBucketDump), and **frameworks** (recon-ng, theHarvester, Shodan, osrframework). Covers the full recon lifecycle from passive OSINT through active enumeration.

### `web` — Web Application Testing, Scanning & Exploitation (~60 tools)

Comprehensive web application security testing. **Vulnerability scanners** (nikto, nuclei, wapiti, skipfish), **fuzzing and directory brute-force** (ffuf, gobuster, feroxbuster, dirb, dirsearch), **SQL injection** (sqlmap, NoSQLMap), **XSS** (XSStrike, xsser, dalfox, kxss), **SSRF/SSTI** (SSRFmap, tplmap, tinja), **CMS scanners** (wpscan, CMSmap, droopescan, cmseek, joomscan), **API testing** (arjun, paramspider, GraphQLmap, jwt_tool), **web shells** (weevely3, PhpSploit), **deserialization** (phpggc, ysoserial), **WAF detection** (wafw00f), **TLS testing** (testssl.sh, sslyze, tlsx), **proxy tools** (Burp Suite, OWASP ZAP, proxify, mitmproxy2swagger), and **miscellaneous** (LinkFinder, smuggler, Corsy, PadBuster, BeEF via Docker).

### `crypto` — Cryptography Analysis & Cipher Cracking (~17 tools)

Tools for breaking cryptographic implementations, commonly used in CTF challenges and security audits. **RSA attacks** (RsaCtfTool, rsatool, msieve for factorization), **cipher analysis** (ciphey for automated decryption, codext for encoding schemes, featherduster for crypto analysis), **hash attacks** (hash_extender for length extension attacks), **XOR analysis** (xortool), **constraint solving** (z3-solver), **collision attacks** (fastcoll for MD5 collisions), **archive cracking** (PkCrack for zip known-plaintext), **stream cipher analysis** (cribdrag), **PRNG attacks** (foresight), **TLS attacks** (nonce-disrespect), and **PEM cracking** (pemcrack).

### `pwn` — Binary Exploitation, Shellcode & Fuzzing (~54 tools)

Binary exploitation and payload development. **Exploit frameworks** (Metasploit, RouterSploit, exploitdb/searchsploit), **binary exploitation** (pwntools, pwncat-cs, ROPgadget, ropper, one_gadget, pwninit, libformatstr), **fuzzing** (AFL++, honggfuzz, radamsa, boofuzz, spike for protocol fuzzing), **payload generation and evasion** (Veil, Donut, ScareCrow, Freeze, Chimera, unicorn, macro_pack, EvilClippy, inceptor), **shellcode tools** (ShellNoob, ShellPop), **C2/post-exploit** (Hoaxshell, TrevorC2, Penelope), **exfiltration** (DET, DNSExfiltrator, Egress-Assess, QueenSono, PyExfil), **heap visualization** (villoc), **vulnerability scanning** (vulscan, interactsh-client), and **Rust tools** (moonwalk for log clearing). Includes manticore for symbolic execution and scapy for packet crafting.

### `reversing` — Disassembly, Debugging & Binary Analysis (~31 tools)

Reverse engineering and binary analysis. **Disassemblers/decompilers** (radare2, Ghidra, rizin + Cutter), **debuggers** (GDB with three plugin ecosystems: pwndbg, GEF, peda, plus edb-debugger and rr for record-replay debugging), **binary analysis** (binwalk for firmware, binutils, checksec, readelf), **emulation** (QEMU user/system mode, Qiling framework), **Java reversing** (jadx, jd-gui, Krakatau, dex2jar), **Python reversing** (uncompyle6, pyinstxtractor), **dynamic analysis** (frida-tools, angr for symbolic execution, ltrace, strace, valgrind), **binary manipulation** (upx-ucl, patchelf, hexedit), **assembly** (nasm), **ROP/exploit helpers** (rp-lin, ELFkickers, rappel, xrop), and **deobfuscation** (decomp2dbg for bridging decompilers to debuggers).

### `forensics` — Disk/Memory Forensics, File Carving & Incident Response (~44 tools)

Digital forensics and incident response toolkit. **Disk forensics** (Autopsy, Sleuthkit, dc3dd, dcfldd, guymager for imaging, dislocker for BitLocker), **memory forensics** (volatility3, memdump), **file carving and recovery** (foremost, scalpel, magicrescue, recoverjpeg, ext3grep, ext4magic, scrounge-ntfs, testdisk), **timeline analysis** (plaso/log2timeline), **log analysis** (chainsaw for Windows event logs, grokevt), **browser forensics** (dumpzilla for Firefox, galleta/pasco for IE), **Windows forensics** (RegRipper for registry, samdump2, rifiuti2 for recycle bin, vinetto for thumbnails), **file integrity** (ssdeep for fuzzy hashing, hashdeep, bulk-extractor), **firmware analysis** (firmware-mod-kit, unblob, binwalk), **rootkit detection** (unhide), **credential recovery** (firefox_decrypt), **metadata analysis** (exiftool), **document analysis** (oletools, pdf-parser, peepdf), **mobile forensics** (mvt for mobile verification), and **version control forensics** (dvcs-ripper).

### `malware` — Malware Analysis, Sandboxing & Detection (~5 tools)

Core malware analysis tools. **Signature scanning** (YARA for pattern matching, ClamAV antivirus), **Python bindings** (yara-python for scripting custom detections), **network simulation** (inetsim for simulating Internet services during dynamic analysis in sandboxed environments), and **Android malware** (quark-engine for Android APK scoring and analysis). Works best combined with the `reversing` and `forensics` modules for a complete malware analysis lab.

### `ad` — Active Directory, Kerberos & Windows Network Pentesting (~37 tools)

Windows/Active Directory attack tools for internal network pentesting. **Core frameworks** (impacket for protocol attacks, NetExec/CrackMapExec for network-wide exploitation, BloodHound for attack path mapping), **Kerberos attacks** (certipy-ad for ADCS abuse, kerbrute for brute-forcing, krbrelayx for relaying), **credential harvesting** (Responder for LLMNR/NBT-NS poisoning, lsassy, pypykatz, spraykatz, hekatomb for DPAPI, lapsdumper for LAPS passwords), **LDAP** (ldapdomaindump, ldeep, adidnsdump, bloodyad for AD manipulation), **lateral movement** (evil-winrm, Invoke-TheHash, SCShell, WMIOps), **enumeration** (enum4linux-ng, ADRecon, Snaffler for file shares, PCredz for credential sniffing), **Azure/cloud AD** (azurehound, GraphRunner, TokenTactics), **PowerShell tools** (nishang, Invoke-Obfuscation, PowerSploit), **phishing** (MailSniper for Exchange), **coercion** (coercer, mitm6), and **.NET tools** (Rubeus for Kerberos, Snaffler). Optional BloodHound CE via Docker.

### `wireless` — WiFi, Bluetooth & SDR (~26 tools)

Wireless network security testing. **WiFi cracking** (aircrack-ng suite, reaver for WPS, cowpatty for WPA dictionary, pixiewps), **WiFi frameworks** (wifite2, airgeddon, fluxion for evil twin, wifiphisher, wifipumpkin3), **WiFi exploitation** (mdk4 for deauth/DoS, eaphammer for WPA Enterprise, hostapd-mana for rogue AP), **capture/conversion** (hcxtools for converting captures to hashcat format), **Bluetooth** (bluez, spooftooph, crackle for BLE), **SDR** (GNURadio, GQRX), **monitoring** (kismet for wireless IDS, horst), **passive reconnaissance** (pwnagotchi for automated WPA handshake capture, PSKracker), and **authentication attacks** (asleap for LEAP/PPTP, bully for WPS).

### `password` — Hash Cracking, Brute Force & Wordlist Generation (~26 tools)

Password cracking and credential testing. **Hash crackers** (john the Ripper, hashcat with GPU support, ophcrack for rainbow tables, rainbowcrack), **network brute-forcers** (hydra, medusa, patator, sucrack for local su), **wordlist generators** (crunch, maskprocessor, princeprocessor, statsprocessor, rsmangler, cupp for targeted lists, duplicut for deduplication), **hash identification** (hashid, name-that-hash, search-that-hash), **file crackers** (fcrackzip for zip, pdfcrack for PDF), **password spraying** (trevorspray for cloud services), **password analysis** (pipal for statistical analysis of password dumps), **Windows passwords** (chntpw for offline NT password reset), **default credentials** (DefaultCreds-cheat-sheet), and **encoding/hashing** (hashdeep for recursive file hashing).

### `stego` — Steganography (~14 tools)

Hiding and extracting data from images, audio, and other files. **Image stego** (steghide for JPEG/BMP, stegsolve for visual analysis, zsteg for PNG/BMP LSB, stegoveritas for automated extraction, stegseek for fast steghide brute-force, openstego, outguess), **detection** (stegsnow for whitespace, pngcheck for PNG validation, stegextract, stegosaurus for Python bytecode), **metadata** (exiv2 for EXIF data, pngtools), and **audio** (sonic-visualiser for spectrogram analysis). Commonly used in CTF challenges where flags are hidden in media files.

### `cloud` — AWS, Azure & GCP Security Testing (~17 tools)

Cloud infrastructure security auditing and exploitation. **Multi-cloud auditing** (Prowler, ScoutSuite, cloudfox for finding attack paths), **AWS** (pacu for exploitation framework, s3scanner/s3reverse for bucket enumeration, CloudBrute, enumerate-iam, cloudsplaining for IAM analysis), **Azure** (roadrecon for Azure AD recon, azurehound in AD module), **GCP** (GCPBucketBrute), **general** (cloud_enum for multi-cloud enumeration, CloudHunter, cloudlist for asset discovery, endgame for cloud pentesting), and **Kubernetes** (kube-hunter for cluster scanning). Complements the containers module for full cloud-native security testing.

### `containers` — Docker & Kubernetes Security (~7 tools)

Container and orchestration security. **Vulnerability scanning** (Trivy for container images, Grype for SBOMs), **Kubernetes** (kubeaudit for cluster auditing, CDK for container escape/exploitation, peirates for Kubernetes pentesting), **Docker** (deepce for Docker enumeration/escape, docker-bench-security for CIS benchmark auditing). Use alongside the cloud module for complete cloud-native security coverage.

### `blueteam` — Defensive Security, IDS/IPS, SIEM & Incident Response (~21 tools)

Blue team and SOC tools. **Intrusion detection** (Suricata for network IDS/IPS, Zeek for network security monitoring, Snort in networking module), **SIEM/log management** (Wazuh via Docker, sigma-rules with sigma-cli for detection engineering), **incident response** (TheHive + Cortex via Docker for case management, Velociraptor for endpoint visibility and live forensics, LAUREL for enriching Linux audit logs), **threat intelligence** (MISP via Docker, maltrail for malicious traffic detection), **file integrity** (AIDE for host-based integrity monitoring), **hardening** (tiger for security auditing, AppArmor, fail2ban for brute-force protection, UFW firewall), **network monitoring** (darkstat for traffic statistics, chaosreader for session reconstruction, sentrypeer for SIP honeypot), **Windows defense** (CIMSweep for PowerShell-based incident response), and **audit** (auditd for system call logging).

## Install Methods

| Method | Count | Used for |
| ------ | ----- | -------- |
| System packages (apt/dnf/pacman/zypper) | ~160 | Core tools with native packages |
| Git clone | ~130 | GitHub repositories, frameworks, resources |
| pipx | ~100 | Python tools in isolated venvs |
| Go install | ~50 | Go-based tools (ProjectDiscovery, tomnomnom, etc.) |
| Binary release | ~20 | GitHub release binaries (Trivy, ligolo-ng, etc.) |
| Build from source | ~16 | Complex tools requiring compilation (AFL++, yafu, etc.) |
| Docker | ~8 | C2 frameworks, IR platforms (optional, requires `--enable-docker`) |
| Ruby gem | 5 | wpscan, evil-winrm, one_gadget, seccomp-tools, zsteg |
| Special | 3 | Metasploit, Burp Suite, OWASP ZAP |
| Cargo (Rust) | 4 | RustScan, feroxbuster, moonwalk, pwninit |

## Scripts

| Script | Purpose |
| ------ | ------- |
| `install.sh` | Modular installer with profile/module selection, dry-run, privilege splitting |
| `scripts/verify.sh` | Per-module verification with `--module` and `--summary` flags |
| `scripts/update.sh` | Updates all methods with `--skip-system`, `--skip-pipx`, `--skip-go`, etc. |
| `scripts/remove.sh` | Per-module removal with `--module`, `--keep-deps`, `--yes` flags |
| `scripts/backup.sh` | Backup/restore tool configs with AES-256-CBC encryption |

All scripts require root and support `--help`.

## Project Structure

```text
cybersec-tools-installer/
  install.sh                # Main entry point
  lib/
    common.sh               # Shared library (logging, distro detection, pkg abstraction)
    installers.sh           # Batch installers, distro name translation, binary downloads
  modules/
    misc.sh                 # Base deps, C2 frameworks, social engineering, post-exploitation, resources
    networking.sh            # Port scanning, packet capture, tunneling, pivoting, MITM
    recon.sh                 # OSINT, subdomain enumeration, intelligence gathering
    web.sh                   # Web app scanning, fuzzing, injection, CMS testing
    crypto.sh                # Cryptography analysis, cipher/hash cracking
    pwn.sh                   # Binary exploitation, shellcode, fuzzing, payloads, evasion
    reversing.sh             # Disassembly, debugging, decompilation, emulation
    forensics.sh             # Disk/memory forensics, file carving, incident response
    malware.sh               # Malware analysis, YARA rules, sandboxing
    ad.sh                    # Active Directory, Kerberos, LDAP, Windows pentesting
    wireless.sh              # WiFi cracking, Bluetooth, SDR, rogue AP
    password.sh              # Hash cracking, brute force, wordlist generation
    stego.sh                 # Image/audio steganography detection and extraction
    cloud.sh                 # AWS/Azure/GCP security auditing and exploitation
    containers.sh            # Docker/Kubernetes security and container escape
    blueteam.sh              # Defensive security, IDS/IPS, SIEM, incident response
  profiles/
    full.conf                # All 16 modules
    ctf.conf                 # CTF competitions
    redteam.conf             # Offensive security
    web.conf                 # Web app security
    malware.conf             # Malware analysis
    osint.conf               # OSINT gathering
    crackstation.conf        # Password cracking
    lightweight.conf         # Minimal install
    blueteam.conf            # Defensive security
  scripts/
    verify.sh                # Verification script
    update.sh                # Update script
    remove.sh                # Removal script
    backup.sh                # Config backup/restore
  docs/
    ARCHITECTURE.md          # Architecture documentation
    TOOL_ANALYSIS.md         # Tool analysis & research
```

## Configuration

Override defaults via environment variables:

```bash
# Change where GitHub repos are cloned (default: /opt)
export GITHUB_TOOL_DIR="/opt/cybersec"

# Change Burp Suite version
export BURP_VERSION="2024.10.1"

sudo ./install.sh
```

## License

MIT License -- see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Only use these tools on systems you own or have explicit written permission to test. The developers are not responsible for any misuse.
