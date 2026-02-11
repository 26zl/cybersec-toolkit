```text
   ______      __              _____
  / ____/_  __/ /_  ___  _____/ ___/___  _____
 / /   / / / / __ \/ _ \/ ___/\__ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /   ___/ /  __/ /__
\____/\__, /_.___/\___/_/   /____/\___/\___/
     /____/
              Tools Installer
```

The most comprehensive automated installer for cybersecurity tools on Linux. __730+ tools__, __17 modules__, __10 install methods__, one command.

## Quick Start

One-liner:

```bash
git clone https://github.com/26zl/cybersec-tools-installer.git && cd cybersec-tools-installer && sudo ./install.sh
```

With a profile:

```bash
git clone https://github.com/26zl/cybersec-tools-installer.git && cd cybersec-tools-installer && sudo ./install.sh --profile ctf
```

From ZIP download:

```bash
# If you downloaded the ZIP instead of using git clone:
unzip cybersec-tools-installer-main.zip && cd cybersec-tools-installer-main && sudo bash install.sh
```

## Usage

```bash
sudo ./install.sh                                    # Full install (all 730+ tools)
sudo ./install.sh --profile ctf                      # Install a profile
sudo ./install.sh --module web --module recon         # Specific modules
sudo ./install.sh --tool sqlmap --tool nmap           # Individual tools
sudo ./install.sh --enable-docker --include-c2        # Include Docker images + C2
sudo ./install.sh --profile redteam --enable-docker   # Profile with Docker
sudo ./install.sh --dry-run --profile ctf             # Preview without installing
sudo ./install.sh --skip-heavy                        # Skip large packages (sagemath, etc.)
sudo ./install.sh --upgrade-system                    # Upgrade system packages first
sudo ./install.sh --list-profiles                     # Show available profiles
sudo ./install.sh --list-modules                      # Show available modules
```

`--profile` and `--module` always auto-include the `misc` module (base dependencies and runtimes). `--tool` does not — it installs only the specified tool.

## Profiles

| Profile | Modules | Description |
| ------- | ------- | ----------- |
| `full` | All 17 modules | Complete security toolkit (add `--enable-docker` for C2/MobSF/BeEF/TheHive) |
| `ctf` | misc, crypto, pwn, reversing, stego, forensics, password, web, mobile | CTF competitions |
| `redteam` | misc, networking, recon, web, ad, pwn, mobile | Offensive security |
| `web` | misc, networking, recon, web | Web application testing |
| `malware` | misc, malware, forensics, reversing, mobile | Malware analysis |
| `osint` | misc, recon | OSINT gathering |
| `crackstation` | misc, password, crypto | Password cracking |
| `lightweight` | misc, networking, recon, web | Core tools only |
| `blueteam` | misc, blueteam, forensics, malware, containers | Defensive security / IR |

## Modules

| Module | Tools | Description |
| ------ | ----- | ----------- |
| `misc` | ~94 | Base dependencies, runtimes, post-exploitation, social engineering, wordlists, C2 (Docker) |
| `networking` | ~60 | Port scanning, packet capture, tunneling, MITM, protocol tools |
| `recon` | ~103 | Subdomain enumeration, OSINT, DNS, automated recon frameworks |
| `web` | ~79 | Vulnerability scanning, fuzzing, SQLi, XSS, CMS scanners, API testing |
| `crypto` | ~17 | RSA attacks, cipher analysis, hash attacks, constraint solving |
| `pwn` | ~54 | Exploit frameworks, binary exploitation, fuzzing, payload generation |
| `reversing` | ~31 | Disassemblers, debuggers, emulation, Java/Python reversing |
| `forensics` | ~44 | Disk/memory forensics, file carving, timeline analysis, log analysis |
| `malware` | ~5 | YARA, ClamAV, inetsim, quark-engine |
| `ad` | ~102 | Active Directory, Kerberos, credential harvesting, lateral movement, Azure AD |
| `wireless` | ~41 | WiFi cracking, Bluetooth, SDR, rogue AP |
| `password` | ~33 | Hash cracking (john, hashcat), brute force, wordlist generation |
| `stego` | ~14 | Image/audio steganography, detection |
| `cloud` | ~17 | AWS/Azure/GCP security auditing |
| `containers` | ~7 | Docker/Kubernetes security (Trivy, Grype, kubeaudit) |
| `blueteam` | ~21 | IDS/IPS, SIEM, incident response, threat intelligence, hardening |
| `mobile` | ~10 | Android/iOS app testing, APK analysis, MobSF (Docker) |

## Install Methods

| Method | Count | Used for |
| ------ | ----- | -------- |
| System packages (apt/dnf/pacman/zypper) | ~205 | Core tools |
| Git clone | ~260 | GitHub repos with auto-setup, resources, wordlists |
| pipx | ~157 | Python tools in isolated venvs |
| Go install | ~55 | Go-based tools |
| Binary release | ~21 | GitHub release binaries |
| Build from source | ~15 | Tools requiring compilation |
| Docker | ~7 | C2 (`--include-c2`), IR platforms, MobSF, BeEF |
| Ruby gem | 6 | wpscan, evil-winrm, one_gadget, seccomp-tools, zsteg, xspear |
| Special | 3 | Metasploit, Burp Suite, OWASP ZAP |
| Cargo (Rust) | 4 | RustScan, feroxbuster, moonwalk, pwninit |

## Prerequisites

The `misc` module auto-installs all runtimes (Python 3, Go, Ruby, Java, build-essential) via your package manager. Rust/Cargo is the only runtime __not__ auto-installed. When using `--tool`, the misc module does NOT run — ensure runtimes are already installed.

| Requirement | Details |
| ----------- | ------- |
| OS | Debian/Ubuntu/Kali (primary), Fedora/RHEL, Arch, openSUSE |
| Root | Must run as `sudo` |
| Disk | ~50 GB full install, ~10-20 GB per profile |

__One-liner prerequisites (Debian/Ubuntu):__

```bash
sudo apt update && sudo apt install -y \
    git curl wget python3 python3-pip python3-venv python3-dev \
    ruby ruby-dev golang-go default-jdk \
    build-essential libpcap-dev libssl-dev libffi-dev \
    zlib1g-dev libxml2-dev libxslt1-dev cmake
```

<details>
<summary>Fedora / Arch one-liners</summary>

__Fedora:__

```bash
sudo dnf install -y \
    git curl wget python3 python3-pip python3-devel \
    ruby ruby-devel golang java-17-openjdk-devel \
    @development-tools libpcap-devel openssl-devel libffi-devel \
    zlib-devel libxml2-devel libxslt-devel cmake
```

__Arch:__

```bash
sudo pacman -S --needed \
    git curl wget python python-pip \
    ruby go jdk-openjdk \
    base-devel libpcap openssl libffi zlib libxml2 libxslt cmake
```

</details>

## Docker

Docker is __optional__. Only used with `--enable-docker` for tools that need complex multi-service setups. If Docker is missing, those images are skipped — nothing else is affected.

| Image | Module | Flag | Description |
| ----- | ------ | ---- | ----------- |
| `bcsecurity/empire` | misc | `--enable-docker --include-c2` | Empire C2 |
| `spiderfoot/spiderfoot` | misc | `--enable-docker` | SpiderFoot OSINT |
| `beefproject/beef` | web | `--enable-docker` | BeEF browser exploitation |
| `opensecurity/mobile-security-framework-mobsf` | mobile | `--enable-docker` | MobSF |
| `specterops/bloodhound` | ad | `--enable-docker` | BloodHound CE |
| `strangebee/thehive:latest` | blueteam | `--enable-docker` | TheHive IR platform |
| `thehiveproject/cortex:latest` | blueteam | `--enable-docker` | Cortex analysis |

## Scripts

| Script | Purpose |
| ------ | ------- |
| `install.sh` | Modular installer with profile/module/tool selection, dry-run |
| `scripts/verify.sh` | Verify installed tools with `--module` and `--summary` |
| `scripts/update.sh` | Update all methods (`--skip-system`, `--skip-binary`, `--skip-docker`, etc.) |
| `scripts/remove.sh` | Remove by module with `--module`, `--remove-deps`, `--yes` |
| `scripts/backup.sh` | Backup/restore tool configs with AES-256-CBC encryption |

All scripts require root and support `--help`.

## Tool Locations

All binaries go to `/usr/local/bin/` (in PATH on all Linux distros).

| Method | Binary location | Data location |
| ------ | --------------- | ------------- |
| pipx | `/usr/local/bin/` | `/opt/pipx/` |
| Go | `/usr/local/bin/` | `/opt/go/` |
| Cargo | `/usr/local/bin/` (symlinked) | `~/.cargo/` |
| Git repos | `/usr/local/bin/` (symlinked) | `/opt/<repo>/` |
| Binary releases | `/usr/local/bin/` | — |

## Supply Chain Model

This installer downloads and runs code from the internet as root.

- __System packages__: GPG-signed by your distro's repos
- __pipx/Go/Cargo/Gem__: Downloads from registries (no signature verification, pipx isolated in venvs)
- __Binary releases__: SHA256 verified when checksum file available, hard-fails on mismatch
- __Git repos__: Cloned at HEAD, deps installed in isolated venvs (setup.py is NOT executed)
- __Build from source__: Runs `make` as root — review what you're building

Git repos and binaries track latest versions. The `.versions` file logs what was installed and when.

## Distro Support

__Debian/Ubuntu/Kali is the primary target__ — all 730+ tools available. Fedora/Arch/openSUSE have ~10-20 packages auto-skipped (distro-specific). pipx, Go, cargo, gem, git, and binary installs work identically across all distros.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

For educational and authorized security testing only. Only use on systems you own or have explicit written permission to test.
