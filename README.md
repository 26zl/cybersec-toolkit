[![CI](https://github.com/26zl/cybersec-tools-installer/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/cybersec-tools-installer/actions/workflows/ci.yml)
[![Integration](https://github.com/26zl/cybersec-tools-installer/actions/workflows/integration.yml/badge.svg)](https://github.com/26zl/cybersec-tools-installer/actions/workflows/integration.yml)
[![Security](https://github.com/26zl/cybersec-tools-installer/actions/workflows/security.yml/badge.svg)](https://github.com/26zl/cybersec-tools-installer/actions/workflows/security.yml)
[![Release](https://github.com/26zl/cybersec-tools-installer/actions/workflows/release.yml/badge.svg)](https://github.com/26zl/cybersec-tools-installer/actions/workflows/release.yml)

```text
   ______      __              _____
  / ____/_  __/ /_  ___  _____/ ___/___  _____
 / /   / / / / __ \/ _ \/ ___/\__ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /   ___/ /  __/ /__
\____/\__, /_.___/\___/_/   /____/\___/\___/
     /____/
              Tools Installer
```

The most comprehensive automated installer for cybersecurity tools on Linux. __665+ tools__, __17 modules__, __10 install methods__, one command.

---

## Step 1: Install Prerequisites

The installer does __not__ install runtimes for you. Install everything below __before__ running `install.sh`. The installer checks on startup and tells you exactly what is missing.

### Debian / Ubuntu / Kali

```bash
sudo apt update && sudo apt install -y \
    git curl wget python3 python3-pip python3-venv python3-dev pipx \
    ruby ruby-dev golang-go default-jdk \
    build-essential libpcap-dev libssl-dev libffi-dev \
    zlib1g-dev libxml2-dev libxslt1-dev cmake

# Rust / Cargo (not in apt — installed via rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### Fedora / RHEL

```bash
sudo dnf install -y \
    git curl wget python3 python3-pip python3-devel pipx \
    ruby ruby-devel golang java-17-openjdk-devel \
    @development-tools libpcap-devel openssl-devel libffi-devel \
    zlib-devel libxml2-devel libxslt-devel cmake

# Rust / Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### Arch

```bash
sudo pacman -S --needed \
    git curl wget python python-pip python-pipx \
    ruby go jdk-openjdk rust \
    base-devel libpcap openssl libffi zlib libxml2 libxslt cmake
```

### What each prerequisite is for

| Prerequisite | Why it is needed |
| ------------ | ---------------- |
| git, curl, wget | Cloning repos, downloading releases |
| Python 3 + pipx | ~157 Python security tools installed in isolated venvs |
| Go | ~55 Go-based tools (subfinder, nuclei, ffuf, httpx, etc.) |
| Rust / Cargo | 3 Rust tools (feroxbuster, RustScan, pwninit) |
| Ruby / gem | 6 Ruby gems (wpscan, evil-winrm, XSpear, etc.) |
| Java (JDK) | Burp Suite, ysoserial, apktool |
| build-essential / cmake | ~15 tools built from source (massdns, duplicut, etc.) |
| libpcap, libssl, libffi, zlib, libxml2, libxslt | C libraries required by Python/Go tools during compilation |
| Docker __(optional)__ | Only needed with `--enable-docker` for C2, MobSF, BeEF, TheHive |

> Only runtimes needed by your selected modules are required. For example `--profile osint` only needs Python, pipx, Go, and build tools — not Rust or Ruby.

---

## Step 2: Install

```bash
git clone https://github.com/26zl/cybersec-tools-installer.git
cd cybersec-tools-installer
sudo ./install.sh
```

That installs all 665+ tools. To install a subset, use a profile or pick specific modules:

```bash
sudo ./install.sh --profile ctf                      # CTF tools only
sudo ./install.sh --profile redteam --enable-docker   # Red team + Docker C2
sudo ./install.sh --module web --module recon          # Specific modules
sudo ./install.sh --tool sqlmap --tool nmap            # Individual tools
sudo ./install.sh --dry-run --profile ctf              # Preview without installing
```

### Try in Docker

Run the installer in a container without touching your host system:

```bash
docker build -t cybersec-installer .
docker run cybersec-installer                          # Dry-run full profile
docker run cybersec-installer --profile ctf            # Install CTF tools
docker run cybersec-installer --module web --module recon
```

Or with Docker Compose:

```bash
docker compose run installer --profile ctf
```

From a ZIP download (no git):

```bash
unzip cybersec-tools-installer-main.zip && cd cybersec-tools-installer-main && sudo bash install.sh
```

### All flags

```bash
sudo ./install.sh --help                # Full help
sudo ./install.sh --list-profiles       # Show profiles
sudo ./install.sh --list-modules        # Show modules
sudo ./install.sh --skip-heavy          # Skip large packages (sagemath, gnuradio)
sudo ./install.sh --upgrade-system      # Upgrade system packages before installing
sudo ./install.sh --enable-docker       # Pull Docker images
sudo ./install.sh --include-c2          # Include C2 frameworks (needs --enable-docker)
sudo ./install.sh -j 8                  # 8 parallel install jobs (default: 4)
sudo ./install.sh -v                    # Verbose / debug output
```

`--profile` and `--module` always auto-include the `misc` module (base dependencies). `--tool` does not — it installs only the specified tool.

---

## Profiles

| Profile | Modules | Description |
| ------- | ------- | ----------- |
| `full` | All 17 | Complete security toolkit |
| `ctf` | misc, crypto, pwn, reversing, stego, forensics, password, web, mobile | CTF competitions |
| `redteam` | misc, networking, recon, web, ad, pwn, mobile | Offensive security |
| `web` | misc, networking, recon, web | Web application testing |
| `malware` | misc, malware, forensics, reversing, mobile | Malware analysis |
| `osint` | misc, recon | OSINT gathering |
| `crackstation` | misc, password, crypto | Password cracking |
| `lightweight` | misc, networking, recon, web | Core tools, minimal footprint |
| `blueteam` | misc, blueteam, forensics, malware, containers | Defensive security / IR |

## Modules

| Module | Tools | Description |
| ------ | ----- | ----------- |
| `misc` | ~94 | Base dependencies, post-exploitation, social engineering, wordlists, C2 (Docker) |
| `networking` | ~58 | Port scanning, packet capture, tunneling, MITM, protocol tools |
| `recon` | ~103 | Subdomain enumeration, OSINT, DNS, automated recon frameworks |
| `web` | ~78 | Vulnerability scanning, fuzzing, SQLi, XSS, CMS scanners, API testing |
| `crypto` | ~17 | RSA attacks, cipher analysis, hash attacks, constraint solving |
| `pwn` | ~53 | Exploit frameworks, binary exploitation, fuzzing, payload generation |
| `reversing` | ~31 | Disassemblers, debuggers, emulation, Java/Python reversing |
| `forensics` | ~43 | Disk/memory forensics, file carving, timeline analysis, log analysis |
| `malware` | ~5 | YARA, ClamAV, inetsim, quark-engine |
| `ad` | ~102 | Active Directory, Kerberos, credential harvesting, lateral movement, Azure AD |
| `wireless` | ~41 | WiFi cracking, Bluetooth, SDR, rogue AP |
| `password` | ~32 | Hash cracking (john, hashcat), brute force, wordlist generation |
| `stego` | ~14 | Image/audio steganography, detection |
| `cloud` | ~17 | AWS/Azure/GCP security auditing |
| `containers` | ~7 | Docker/Kubernetes security (Trivy, Grype, kubeaudit) |
| `blueteam` | ~21 | IDS/IPS, SIEM, incident response, threat intelligence, hardening |
| `mobile` | ~10 | Android/iOS app testing, APK analysis, MobSF (Docker) |

## Install Methods

| Method | Count | Examples |
| ------ | ----- | ------- |
| System packages (apt/dnf/pacman/zypper) | ~199 | nmap, wireshark, john, hashcat |
| Git clone | ~260 | GitHub repos with auto-setup, resources, wordlists |
| pipx | ~157 | sqlmap, impacket, bloodhound, volatility3 |
| Go install | ~55 | nuclei, subfinder, ffuf, httpx |
| Binary release | ~21 | gitleaks, chainsaw, findomain |
| Build from source | ~15 | massdns, duplicut, yara |
| Docker | ~7 | C2, MobSF, BeEF, TheHive |
| Ruby gem | 6 | wpscan, evil-winrm, XSpear |
| Special | 3 | Metasploit, Burp Suite, OWASP ZAP |
| Cargo (Rust) | 3 | feroxbuster, RustScan, pwninit |

---

## Post-Install Scripts

All scripts require root and support `--help`.

| Script | Purpose | Example |
| ------ | ------- | ------- |
| `scripts/verify.sh` | Check which tools are installed | `sudo ./scripts/verify.sh --module web` |
| `scripts/update.sh` | Update all installed tools | `sudo ./scripts/update.sh --skip-system` |
| `scripts/remove.sh` | Remove tools by module | `sudo ./scripts/remove.sh --module ad --yes` |
| `scripts/backup.sh` | Backup/restore tool configs | `sudo ./scripts/backup.sh --encrypt` |

## Tool Locations

All binaries end up in `/usr/local/bin/` (in PATH on all Linux distros).

| Method | Binary location | Data location |
| ------ | --------------- | ------------- |
| pipx | `/usr/local/bin/` | `/opt/pipx/` |
| Go | `/usr/local/bin/` | `/opt/go/` |
| Cargo | `/usr/local/bin/` (symlinked) | `~/.cargo/` |
| Git repos | `/usr/local/bin/` (symlinked) | `/opt/<repo>/` |
| Binary releases | `/usr/local/bin/` | -- |

## Docker Images (optional)

Only used with `--enable-docker`. If Docker is not installed, these are skipped silently.

| Image | Module | Flag | Description |
| ----- | ------ | ---- | ----------- |
| `bcsecurity/empire` | misc | `--enable-docker --include-c2` | Empire C2 |
| `spiderfoot/spiderfoot` | misc | `--enable-docker` | SpiderFoot OSINT |
| `beefproject/beef` | web | `--enable-docker` | BeEF browser exploitation |
| `opensecurity/mobile-security-framework-mobsf` | mobile | `--enable-docker` | MobSF |
| `specterops/bloodhound` | ad | `--enable-docker` | BloodHound CE |
| `strangebee/thehive:latest` | blueteam | `--enable-docker` | TheHive IR platform |
| `thehiveproject/cortex:latest` | blueteam | `--enable-docker` | Cortex analysis |

## Distro Support

__Debian/Ubuntu/Kali is the primary target__ -- all 665+ tools available. Fedora/Arch/openSUSE have ~10-20 packages auto-skipped (distro-specific). pipx, Go, Cargo, gem, git, and binary installs work identically across all distros.

## Supply Chain Model

This installer downloads and runs code from the internet as root.

- __System packages__: GPG-signed by your distro's repos
- __pipx/Go/Cargo/Gem__: Downloads from registries (no signature verification, pipx isolated in venvs)
- __Binary releases__: SHA256 verified when checksum file available, hard-fails on mismatch
- __Git repos__: Cloned at HEAD, deps installed in isolated venvs (setup.py is NOT executed)
- __Build from source__: Runs `make` as root -- review what you're building

The `.versions` file logs what was installed and when.

## License

MIT License -- see [LICENSE](LICENSE) for details.

## Disclaimer

For educational and authorized security testing only. Only use on systems you own or have explicit written permission to test.
