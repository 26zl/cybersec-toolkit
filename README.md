# CyberSec Tools Installer

The most comprehensive automated installer for cybersecurity and penetration testing tools on Linux. Installs **364 tools** across **16 modules** using **10 install methods** with a single command. Modular, profile-based architecture with multi-distro support.

## Supported Distros

| Family | Distros |
| ------ | ------- |
| Debian/Ubuntu | Debian, Ubuntu, Kali, Parrot, Linux Mint, Pop!_OS, Elementary, Zorin, MX |
| Fedora/RHEL | Fedora, RHEL, CentOS, Rocky, Alma, Nobara |
| Arch | Arch, Manjaro, EndeavourOS, Garuda, Artix |
| openSUSE | openSUSE Leap/Tumbleweed, SLES |

## Features

- **364 tools** across 16 specialized modules
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
# Full install (all 347 tools)
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

| Module | Tools | Highlights |
| ------ | ----- | ---------- |
| `misc` | 70 | Base deps, PEASS-ng, SecLists, C2 frameworks (Sliver/Havoc/Mythic), social engineering, resources |
| `networking` | 35 | nmap, masscan, Wireshark, ettercap, mitmproxy, RustScan, ligolo-ng, bettercap |
| `recon` | 45 | subfinder, amass, nuclei, theHarvester, Shodan, reconftw, Sn1per, 23 Go OSINT tools |
| `web` | 46 | sqlmap, ffuf, gobuster, Burp Suite, ZAP, XSStrike, testssl.sh, dalfox, katana |
| `crypto` | 13 | ciphey, z3-solver, RsaCtfTool, featherduster, hash_extender, PkCrack |
| `pwn` | 27 | pwntools, Metasploit, ROPgadget, AFL++, Veil, Donut, ScareCrow, RouterSploit |
| `reversing` | 22 | radare2, Ghidra, GDB+pwndbg/GEF/peda, rizin, binwalk, Qiling |
| `forensics` | 19 | Autopsy, Sleuthkit, volatility3, foremost, bulk_extractor, chainsaw, plaso |
| `malware` | 3 | YARA, ClamAV, yara-python |
| `ad` | 14 | impacket, BloodHound, Responder, CrackMapExec/NetExec, certipy-ad, kerbrute |
| `wireless` | 15 | aircrack-ng, reaver, kismet, wifite2, fluxion, airgeddon, GNURadio, GQRX |
| `password` | 14 | john, hashcat, hydra, medusa, crunch, search-that-hash, DefaultCreds |
| `stego` | 10 | steghide, stegsolve, zsteg, stegoveritas, stegseek, outguess, openstego |
| `cloud` | 11 | Prowler, ScoutSuite, pacu, cloudfox, CloudBrute, enumerate-iam |
| `containers` | 6 | Trivy, Grype, kubeaudit, CDK, deepce, docker-bench-security |
| `blueteam` | 17 | Suricata, Zeek, Wazuh, TheHive, Velociraptor, Sigma, fail2ban, AIDE |

## Install Methods

| Method | Count | Used for |
| ------ | ----- | -------- |
| System packages (apt/dnf/pacman/zypper) | 103 | Core tools with native packages |
| Git clone | 89 | GitHub repositories, frameworks, resources |
| pipx | 66 | Python tools in isolated venvs |
| Go install | 48 | Go-based tools (ProjectDiscovery, tomnomnom, etc.) |
| Binary release | 19 | GitHub release binaries (Trivy, ligolo-ng, etc.) |
| Build from source | 11 | Complex tools requiring compilation (AFL++, yafu, etc.) |
| Docker | 5 | C2 frameworks, heavy apps (optional, requires `--enable-docker`) |
| Ruby gem | 4 | wpscan, one_gadget, seccomp-tools, zsteg |
| Special | 3 | Metasploit, Burp Suite, OWASP ZAP |
| Cargo (Rust) | 2 | RustScan, feroxbuster |

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
    misc.sh                 # Base dependencies, C2, social engineering, resources
    networking.sh            # Network scanning, tunneling, MITM
    recon.sh                 # OSINT, subdomain enum, intelligence gathering
    web.sh                   # Web app testing, fuzzing, scanning
    crypto.sh                # Cryptography analysis, cipher cracking
    pwn.sh                   # Binary exploitation, fuzzing, payloads
    reversing.sh             # Disassembly, debugging, binary analysis
    forensics.sh             # Disk/memory forensics, file carving
    malware.sh               # Malware analysis, YARA, AV
    ad.sh                    # Active Directory, Kerberos
    wireless.sh              # WiFi, Bluetooth, SDR
    password.sh              # Hash cracking, brute force, wordlists
    stego.sh                 # Steganography
    cloud.sh                 # AWS/Azure/GCP security
    containers.sh            # Docker/Kubernetes security
    blueteam.sh              # Defensive security, IDS/IPS, SIEM, IR
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
  tools_config.json          # Tool registry (364 tools, not parsed at runtime)
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
