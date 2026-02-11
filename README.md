```text
   ______      __              _____
  / ____/_  __/ /_  ___  _____/ ___/___  _____
 / /   / / / / __ \/ _ \/ ___/\__ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /   ___/ /  __/ /__
\____/\__, /_.___/\___/_/   /____/\___/\___/
     /____/
              Tools Installer
```

# CyberSec Tools Installer

The most comprehensive automated installer for cybersecurity and penetration testing tools on Linux. Installs **730+ tools** across **17 modules** using **10 install methods** with a single command. Modular, profile-based architecture with multi-distro support.

## Supported Distros

| Family | Distros |
| ------ | ------- |
| Debian/Ubuntu | Debian, Ubuntu, Kali, Parrot, Linux Mint, Pop!_OS, Elementary, Zorin, MX |
| Fedora/RHEL | Fedora, RHEL, CentOS, Rocky, Alma, Nobara |
| Arch | Arch, Manjaro, EndeavourOS, Garuda, Artix |
| openSUSE | openSUSE Leap/Tumbleweed, SLES |

## Prerequisites

Every module automatically installs its own system packages and dependencies via your package manager (apt/dnf/pacman/zypper). When installing by profile or module (`--profile`, `--module`), the `misc` module is always included automatically and installs all required runtimes and build dependencies (Python 3, Go, Ruby, Java JDK, build-essential, dev libraries). Each module then installs its own tools (e.g., `networking` installs nmap/wireshark/tcpdump, `reversing` installs radare2/ghidra/gdb). When installing individual tools with `--tool`, the `misc` module does NOT run — you must ensure runtimes are already installed. The tables below list what runtimes are needed so you know what to expect. **Rust/Cargo is the only runtime not auto-installed via apt** — install it manually if you want the 4 Cargo tools (feroxbuster, RustScan, moonwalk, pwninit). If pipx cannot be installed via the package manager, all pipx tools will be skipped with an error — there are no silent fallbacks to pip.

### System Requirements

| Requirement | Details |
| ----------- | ------- |
| OS | Any supported Linux distro from the table above |
| Root access | Must run as root (`sudo ./install.sh`) |
| Internet | Required for all download-based install methods |
| Disk space | ~50 GB for a full install (all modules), ~10-20 GB for a single profile |

### Required Runtimes

Every tool in the installer depends on one or more of these runtimes. If a runtime is missing, tools that depend on it will be skipped with a logged error.

| Runtime | Min Version | Install (Debian/Ubuntu) | Install (Fedora) | Install (Arch) | Used by |
| ------- | ----------- | ----------------------- | ----------------- | -------------- | ------- |
| Python 3 | 3.8+ | `sudo apt install python3 python3-pip python3-venv python3-dev` | `sudo dnf install python3 python3-pip python3-devel` | `sudo pacman -S python python-pip` | ~178 pipx tools, git repo setup |
| Go | 1.21+ | `sudo apt install golang-go` | `sudo dnf install golang` | `sudo pacman -S go` | ~55 Go tools |
| Ruby | 2.7+ | `sudo apt install ruby ruby-dev` | `sudo dnf install ruby ruby-devel` | `sudo pacman -S ruby` | 6 gems (wpscan, evil-winrm, one_gadget, seccomp-tools, zsteg, xspear) |
| Java JDK | 11+ | `sudo apt install default-jdk` | `sudo dnf install java-17-openjdk-devel` | `sudo pacman -S jdk-openjdk` | Burp Suite, OWASP ZAP, jadx, jd-gui, dex2jar, ysoserial |
| Rust/Cargo | 1.56+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` | Same | Same | 4 cargo tools (feroxbuster, RustScan, moonwalk, pwninit) |
| Build tools | any | `sudo apt install build-essential cmake` | `sudo dnf groupinstall "Development Tools" && sudo dnf install cmake` | `sudo pacman -S base-devel cmake` | ~15 build-from-source tools |
| Git | any | `sudo apt install git` | `sudo dnf install git` | `sudo pacman -S git` | ~130 git-cloned repos |
| curl + wget | any | `sudo apt install curl wget` | `sudo dnf install curl wget` | `sudo pacman -S curl wget` | Binary downloads, release fetching |

### Optional Runtimes

These are only needed if you use specific features or modules.

| Runtime | When needed | Install |
| ------- | ----------- | ------- |
| Docker | `--enable-docker` flag (see Docker section below) | [docs.docker.com/engine/install](https://docs.docker.com/engine/install/) |
| snap | OWASP ZAP install | `sudo apt install snapd` (Debian/Ubuntu only) |

### Docker — Required for C2, IR Platforms & Mobile Sandboxing

Docker is **not required** for the base install. It is only used when you pass `--enable-docker`, which pulls pre-built Docker images for tools that require complex multi-service setups (databases, listeners, web UIs) and cannot run from a simple git clone.

**If `--enable-docker` is set but Docker is not installed, install.sh will log an error and skip all Docker images.** No tools outside the Docker images are affected.

| Docker image | Module | Flag required | Description |
| ------------ | ------ | ------------- | ----------- |
| `bcsecurity/empire` | misc | `--enable-docker --include-c2` | Empire C2 framework |
| `spiderfoot/spiderfoot` | misc | `--enable-docker` | SpiderFoot OSINT automation |
| `beefproject/beef` | web | `--enable-docker` | BeEF browser exploitation framework |
| `opensecurity/mobile-security-framework-mobsf` | mobile | `--enable-docker` | MobSF mobile app security testing |
| `specterops/bloodhound` | ad | `--enable-docker` | BloodHound CE attack path mapping |
| `strangebee/thehive:latest` | blueteam | `--enable-docker` | TheHive incident response platform |
| `thehiveproject/cortex:latest` | blueteam | `--enable-docker` | Cortex observable analysis |

**Usage:**

```bash
# Install Docker first (if not already installed)
# See: https://docs.docker.com/engine/install/

# Then run with Docker enabled
sudo ./install.sh --enable-docker

# Include C2 frameworks (Empire)
sudo ./install.sh --enable-docker --include-c2

# Red team profile with Docker + C2
sudo ./install.sh --profile redteam --enable-docker --include-c2
```

**Updating Docker images:** `sudo ./scripts/update.sh` will update any Docker images that are already pulled locally. Use `--skip-docker` to skip Docker image updates.

### Hardware Requirements

| Module | Hardware | Notes |
| ------ | -------- | ----- |
| `wireless` | WiFi adapter with **monitor mode + packet injection** | Required for aircrack-ng, wifite, reaver, kismet, etc. |
| `wireless` | Bluetooth adapter | Required for bluez, spooftooph, crackle |
| `wireless` | SDR hardware (HackRF, RTL-SDR) | Optional — for GNURadio, GQRX, rtl-433 |
| `wireless` | NFC reader | Optional — for mfcuk, mfoc, libnfc tools |
| `password` | GPU (NVIDIA + CUDA or AMD + ROCm) | Optional but strongly recommended for hashcat |
| `mobile` | Android device or emulator | Required for dynamic analysis with adb, objection, scrcpy |

### Development Libraries

Required for building Python packages and source tools. Install all of these:

**Debian/Ubuntu:**

```bash
sudo apt install libpcap-dev libssl-dev libffi-dev zlib1g-dev libxml2-dev libxslt1-dev
```

**Fedora/RHEL:**

```bash
sudo dnf install libpcap-devel openssl-devel libffi-devel zlib-devel libxml2-devel libxslt-devel
```

**Arch:**

```bash
sudo pacman -S libpcap openssl libffi zlib libxml2 libxslt
```

### One-Liner — Install All Prerequisites (Debian/Ubuntu)

```bash
sudo apt update && sudo apt install -y \
    git curl wget openssl unzip dos2unix rlwrap imagemagick cmake \
    python3 python3-pip python3-venv python3-dev \
    ruby ruby-dev golang-go default-jdk \
    build-essential libpcap-dev libssl-dev libffi-dev \
    zlib1g-dev libxml2-dev libxslt1-dev
```

### One-Liner — Install All Prerequisites (Fedora)

```bash
sudo dnf install -y \
    git curl wget openssl unzip dos2unix rlwrap ImageMagick cmake \
    python3 python3-pip python3-devel \
    ruby ruby-devel golang java-17-openjdk-devel \
    @development-tools libpcap-devel openssl-devel libffi-devel \
    zlib-devel libxml2-devel libxslt-devel
```

### One-Liner — Install All Prerequisites (Arch)

```bash
sudo pacman -S --needed \
    git curl wget openssl unzip dos2unix rlwrap imagemagick cmake \
    python python-pip \
    ruby go jdk-openjdk \
    base-devel libpcap openssl libffi zlib libxml2 libxslt
```

### Distro-Specific Limitations

**Debian/Ubuntu/Kali is the primary target.** All 730+ tools are available and tested on Debian-based distros. Other distros have reduced coverage:

- **Fedora/RHEL/openSUSE**: ~20 apt packages are auto-skipped (spooftooph, cewl, hashid, wapiti, zmap, rizin, sonic-visualiser, sentrypeer, chaosreader, apparmor-utils, smali, apksigner, zipalign, scrcpy, some NFC/SDR packages). Some tools may require enabling EPEL or RPMFusion repos manually.
- **Arch**: ~10 apt packages are auto-skipped (spooftooph, cewl, hashid, wapiti, mfcuk, mfoc, libnfc-dev, some SDR packages). Some tools may need AUR helpers (yay/paru) which the installer does not configure.

Skipped tools can still be installed manually from source on those distros. pipx, Go, cargo, gem, git, and binary installs work identically across all distros.

### What "Plug-and-Play" Means

After installation with all prerequisites present:

| Install method | Plug-and-play? | Details |
| -------------- | -------------- | ------- |
| System packages (apt) | Yes | Installed and in PATH immediately |
| pipx | Yes | Isolated venvs, binaries in `/usr/local/bin` |
| Go install | Yes | Binaries in `/usr/local/bin` |
| Cargo | Yes | Binaries symlinked to `/usr/local/bin` |
| Ruby gems | Yes | Installed system-wide via gem |
| Binary releases | Yes | Binaries in `/usr/local/bin` |
| Build from source | Yes | Built in `/opt`, binaries in place |
| Git clone (Python repos) | Mostly | Venv created + deps installed; entry points symlinked to PATH when detectable |
| Git clone (resources/wordlists) | Reference only | Cloned to `/opt/<name>/` for manual use — no binary to run |
| Git clone (PowerShell/.NET) | Reference only | Cloned to `/opt/<name>/` — requires manual import in Windows/PowerShell contexts |
| Docker | Yes | Images pulled and ready to `docker run` |
| Burp Suite | No | GUI installer downloaded to `/opt/burpsuite-installer/` — requires manual execution |
| C2 frameworks | Docker only | Require `--enable-docker --include-c2`; not available via git clone (complex multi-service setup) |

### Supply Chain Model

This installer downloads and executes code from the internet as root. Understand the trust model:

- **System packages**: Verified by your distro's package manager (GPG-signed repos)
- **pipx**: Downloads from PyPI (no signature verification, but isolated in venvs)
- **Go/Cargo/Gem**: Downloads from module registries (no signature verification)
- **Binary releases**: SHA256 checksum verified when the GitHub release provides a checksum file; **hard-fails on mismatch**, warns if no checksums available
- **Git repos**: Cloned from GitHub at HEAD; dependencies installed into isolated venvs (setup.py is NOT executed to avoid arbitrary code execution)
- **Metasploit**: Prefers apt package when available; falls back to official Rapid7 installer with basic content verification
- **Burp Suite**: Downloaded but NOT auto-executed — requires manual GUI installation
- **Build from source**: Runs `make` in cloned repos as root — review the repos you're building

**Reproducibility**: Git repos track HEAD (latest), binaries use latest releases. The `.versions` file logs what was installed and when, but versions are not pinned. This is by design — security tools need frequent updates.

## Features

- **730+ tools** across 17 specialized modules
- **9 install profiles** — full, ctf, redteam, web, malware, osint, crackstation, lightweight, blueteam
- **10 install methods** — apt, pipx, go, cargo, gem, git clone, binary release, Docker, snap, build-from-source
- **Multi-distro** — primary target is Debian/Ubuntu/Kali; also supports Fedora/RHEL, Arch, openSUSE with auto-translated package names
- **Modular** — install only the modules you need with `--module`
- **Profile-based** — predefined tool sets for common use cases with `--profile`
- **Safe defaults** — no system upgrade unless `--upgrade-system`, base deps preserved on removal
- **Root execution** — all tools installed system-wide for maximum compatibility
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
# Full install (all 730+ tools)
sudo ./install.sh

# Install a profile
sudo ./install.sh --profile ctf
sudo ./install.sh --profile redteam --enable-docker

# Install specific modules
sudo ./install.sh --module web --module recon
sudo ./install.sh --module ad --module networking

# Preview without installing
sudo ./install.sh --dry-run --profile ctf

# Install individual tools by name
sudo ./install.sh --tool sqlmap
sudo ./install.sh --tool subfinder --tool nmap --tool feroxbuster

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
| `full` | All 17 modules | Everything — complete security toolkit (add `--enable-docker` for C2/MobSF/BeEF/TheHive) |
| `ctf` | misc, crypto, pwn, reversing, stego, forensics, password, web, mobile | Capture The Flag competitions |
| `redteam` | misc, networking, recon, web, ad, pwn, mobile | Offensive security operations |
| `web` | misc, networking, recon, web | Web application security testing |
| `malware` | misc, malware, forensics, reversing, mobile | Malware analysis and reverse engineering |
| `osint` | misc, recon | Open source intelligence gathering |
| `crackstation` | misc, password, crypto | Password cracking and hash analysis |
| `lightweight` | misc, networking, recon, web | Core tools only for limited disk/laptops |
| `blueteam` | misc, blueteam, forensics, malware, containers | Defensive security and incident response |

## Modules

### `misc` — Base Dependencies, C2, Social Engineering & Resources (~94 tools)

The foundation module, always installed first. Provides build toolchains (gcc, make, python3, ruby, go, java), essential utilities, and large reference collections. Includes **post-exploitation** tools for privilege escalation and lateral movement (PEASS-ng, LinEnum, PowerSploit, LaZagne, mimipenguin), **social engineering** frameworks for phishing campaigns (SET, Zphisher, Gophish, king-phisher, Modlishka), **C2 frameworks** via Docker only (Empire, requires `--enable-docker --include-c2`), **CTF platforms** (CyberChef, Caldera, atomic-red-team), and **wordlists/resources** (SecLists, PayloadsAllTheThings, FuzzDB, GTFOBins). Heavy packages like sagemath can be skipped with `--skip-heavy`.

### `networking` — Port Scanning, Packet Capture, Tunneling & MITM (~60 tools)

Everything for network reconnaissance and manipulation. **Port scanners** (nmap, masscan, RustScan, zmap), **packet capture and analysis** (tcpdump, Wireshark/tshark, netsniff-ng, tcpflow, ngrep), **tunneling and pivoting** for moving through networks (chisel, ligolo-ng, frp, iodine, dns2tcp, sshuttle, redsocks, proxychains4), **MITM attacks** (ettercap, mitmproxy, bettercap, dsniff, sslstrip, sslsplit), **protocol tools** (socat, netcat, cryptcat, hping3, arping, fping), **DNS tools** (dnschef), **enumeration** (smbmap, nbtscan, onesixtyone, arp-scan), and **anonymity** (tor, macchanger). Also includes Snort and Zeek for traffic analysis.

### `recon` — OSINT, Subdomain Enumeration & Intelligence Gathering (~103 tools)

The largest module for reconnaissance and open source intelligence. **Subdomain enumeration** (subfinder, amass, assetfinder, puredns, shuffledns, massdns, Findomain, subbrute), **web discovery** (httpx, gowitness, hakrawler, katana, waybackurls, gau), **DNS tools** (dnsx, dnstwist, dnsrecon, dnsenum, altdns, dnsmap), **OSINT/people search** (sherlock, maigret, holehe, phoneinfoga, h8mail, social-analyzer, ghunt, inspy), **automated recon** (reconftw, autorecon, Sn1per, bbot, finalrecon), **GitHub/cloud recon** (gitleaks, github-subdomains, certSniff, AWSBucketDump), and **frameworks** (recon-ng, theHarvester, Shodan, osrframework). Covers the full recon lifecycle from passive OSINT through active enumeration.

### `web` — Web Application Testing, Scanning & Exploitation (~79 tools)

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

### `ad` — Active Directory, Kerberos & Windows Network Pentesting (~102 tools)

Windows/Active Directory attack tools for internal network pentesting. **Core frameworks** (impacket for protocol attacks, NetExec/CrackMapExec for network-wide exploitation, BloodHound for attack path mapping), **Kerberos attacks** (certipy-ad for ADCS abuse, kerbrute for brute-forcing, krbrelayx for relaying), **credential harvesting** (Responder for LLMNR/NBT-NS poisoning, lsassy, pypykatz, spraykatz, hekatomb for DPAPI, lapsdumper for LAPS passwords), **LDAP** (ldapdomaindump, ldeep, adidnsdump, bloodyad for AD manipulation), **lateral movement** (evil-winrm, Invoke-TheHash, SCShell, WMIOps), **enumeration** (enum4linux-ng, ADRecon, Snaffler for file shares, PCredz for credential sniffing), **Azure/cloud AD** (azurehound, GraphRunner, TokenTactics), **PowerShell tools** (nishang, Invoke-Obfuscation, PowerSploit), **phishing** (MailSniper for Exchange), **coercion** (coercer, mitm6), and **.NET tools** (Rubeus for Kerberos, Snaffler). Optional BloodHound CE via Docker.

### `wireless` — WiFi, Bluetooth & SDR (~41 tools)

Wireless network security testing. **WiFi cracking** (aircrack-ng suite, reaver for WPS, cowpatty for WPA dictionary, pixiewps), **WiFi frameworks** (wifite2, airgeddon, fluxion for evil twin, wifiphisher, wifipumpkin3), **WiFi exploitation** (mdk4 for deauth/DoS, eaphammer for WPA Enterprise, hostapd-mana for rogue AP), **capture/conversion** (hcxtools for converting captures to hashcat format), **Bluetooth** (bluez, spooftooph, crackle for BLE), **SDR** (GNURadio, GQRX), **monitoring** (kismet for wireless IDS, horst), **passive reconnaissance** (pwnagotchi for automated WPA handshake capture, PSKracker), and **authentication attacks** (asleap for LEAP/PPTP, bully for WPS). Requires compatible wireless hardware — see [Hardware Requirements](#hardware-requirements).

### `password` — Hash Cracking, Brute Force & Wordlist Generation (~33 tools)

Password cracking and credential testing. **Hash crackers** (john the Ripper, hashcat with GPU support, ophcrack for rainbow tables, rainbowcrack), **network brute-forcers** (hydra, medusa, patator, sucrack for local su), **wordlist generators** (crunch, maskprocessor, princeprocessor, statsprocessor, rsmangler, cupp for targeted lists, duplicut for deduplication), **hash identification** (hashid, name-that-hash, search-that-hash), **file crackers** (fcrackzip for zip, pdfcrack for PDF), **password spraying** (trevorspray for cloud services), **password analysis** (pipal for statistical analysis of password dumps), **Windows passwords** (chntpw for offline NT password reset), **default credentials** (DefaultCreds-cheat-sheet), and **encoding/hashing** (hashdeep for recursive file hashing).

### `stego` — Steganography (~14 tools)

Hiding and extracting data from images, audio, and other files. **Image stego** (steghide for JPEG/BMP, stegsolve for visual analysis, zsteg for PNG/BMP LSB, stegoveritas for automated extraction, stegseek for fast steghide brute-force, openstego, outguess), **detection** (stegsnow for whitespace, pngcheck for PNG validation, stegextract, stegosaurus for Python bytecode), **metadata** (exiv2 for EXIF data, pngtools), and **audio** (sonic-visualiser for spectrogram analysis). Commonly used in CTF challenges where flags are hidden in media files.

### `cloud` — AWS, Azure & GCP Security Testing (~17 tools)

Cloud infrastructure security auditing and exploitation. **Multi-cloud auditing** (Prowler, ScoutSuite, cloudfox for finding attack paths), **AWS** (pacu for exploitation framework, s3scanner/s3reverse for bucket enumeration, CloudBrute, enumerate-iam, cloudsplaining for IAM analysis), **Azure** (roadrecon for Azure AD recon, azurehound in AD module), **GCP** (GCPBucketBrute), **general** (cloud_enum for multi-cloud enumeration, CloudHunter, cloudlist for asset discovery, endgame for cloud pentesting), and **Kubernetes** (kube-hunter for cluster scanning). Complements the containers module for full cloud-native security testing.

### `containers` — Docker & Kubernetes Security (~7 tools)

Container and orchestration security. **Vulnerability scanning** (Trivy for container images, Grype for SBOMs), **Kubernetes** (kubeaudit for cluster auditing, CDK for container escape/exploitation, peirates for Kubernetes pentesting), **Docker** (deepce for Docker enumeration/escape, docker-bench-security for CIS benchmark auditing). Use alongside the cloud module for complete cloud-native security coverage.

### `mobile` — Android/iOS Application Security Testing (~10 tools)

Mobile application security testing and analysis. **Android tools** (adb for device interaction, smali/baksmali for DEX disassembly, apksigner for APK signing verification, zipalign for APK alignment, apktool for APK decompilation and recompilation), **dynamic analysis** (objection for runtime mobile exploration via Frida, scrcpy for device screen mirroring), **static analysis** (androguard for Android APK analysis and reverse engineering, apkleaks for finding URIs/endpoints/secrets in APKs), and **sandboxing** (MobSF via Docker for automated mobile app security testing). Complements the reversing module for deeper binary analysis of mobile apps.

### `blueteam` — Defensive Security, IDS/IPS, SIEM & Incident Response (~21 tools)

Blue team and SOC tools. **Intrusion detection** (Suricata for network IDS/IPS, Zeek for network security monitoring, Snort in networking module), **SIEM/log management** (Wazuh via Docker, sigma-rules with sigma-cli for detection engineering), **incident response** (TheHive + Cortex via Docker for case management, Velociraptor for endpoint visibility and live forensics, LAUREL for enriching Linux audit logs), **threat intelligence** (MISP via Docker, maltrail for malicious traffic detection), **file integrity** (AIDE for host-based integrity monitoring), **hardening** (tiger for security auditing, AppArmor, fail2ban for brute-force protection, UFW firewall), **network monitoring** (darkstat for traffic statistics, chaosreader for session reconstruction, sentrypeer for SIP honeypot), **Windows defense** (CIMSweep for PowerShell-based incident response), and **audit** (auditd for system call logging).

## Install Methods

| Method | Count | Required runtime | Used for |
| ------ | ----- | ---------------- | -------- |
| System packages (apt/dnf/pacman/zypper) | ~205 | Package manager (comes with distro) | Core tools with native packages |
| Git clone | ~260 | Git | GitHub repos with auto-setup (Python venvs), resources, wordlists |
| pipx | ~157 | Python 3.8+, pip, venv | Python tools in isolated venvs |
| Go install | ~55 | Go 1.21+ | Go-based tools (ProjectDiscovery, tomnomnom, etc.) |
| Binary release | ~21 | curl | GitHub release binaries (Trivy, ligolo-ng, etc.) |
| Build from source | ~15 | build-essential/base-devel, make, cmake | Complex tools requiring compilation (AFL++, yafu, etc.) |
| Docker | ~7 | Docker (optional, `--enable-docker`) | C2 (`--include-c2`), IR platforms, MobSF, BeEF |
| Ruby gem | 6 | Ruby 2.7+ | wpscan, evil-winrm, one_gadget, seccomp-tools, zsteg, xspear |
| Special | 3 | Java 11+ (Burp/ZAP), curl (Metasploit) | Metasploit, Burp Suite, OWASP ZAP |
| Cargo (Rust) | 4 | Rust/Cargo 1.56+ | RustScan, feroxbuster, moonwalk, pwninit |

## Scripts

| Script | Purpose |
| ------ | ------- |
| `install.sh` | Modular installer with profile/module selection, dry-run |
| `scripts/verify.sh` | Per-module verification with `--module` and `--summary` flags |
| `scripts/update.sh` | Updates all methods with `--skip-system`, `--skip-pipx`, `--skip-go`, `--skip-binary`, `--skip-docker`, etc. |
| `scripts/remove.sh` | Per-module removal with `--module`, `--remove-deps`, `--yes` flags |
| `scripts/backup.sh` | Backup/restore tool configs with AES-256-CBC encryption |

All scripts require root and support `--help`.

## Tool Locations

After installation, tools are placed in these system-wide locations:

| Method | Binary location | Data location |
| ------ | --------------- | ------------- |
| System packages | Managed by package manager | System paths |
| pipx | `/usr/local/bin/` | `/opt/pipx/` |
| Go | `/usr/local/bin/` (GOBIN) | `/opt/go/` (GOPATH) |
| Cargo | `/usr/local/bin/` (symlinked) | `~/.cargo/` |
| Git repos (Python) | `/usr/local/bin/` (symlinked from venv) | `/opt/<repo-name>/` |
| Git repos (resources) | — (reference only) | `/opt/<repo-name>/` |
| Binary releases | `/usr/local/bin/` | — |
| Ruby gems | Managed by gem | System gem path |

All binaries go to `/usr/local/bin/` which is in PATH by default on all Linux distros.

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
