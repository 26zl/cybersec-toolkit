<p>
  <a href="https://github.com/26zl/cybersec-tools-installer/actions/workflows/ci.yml"><img src="https://github.com/26zl/cybersec-tools-installer/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/26zl/cybersec-tools-installer/actions/workflows/integration.yml"><img src="https://github.com/26zl/cybersec-tools-installer/actions/workflows/integration.yml/badge.svg" alt="Integration"></a>
  <a href="https://github.com/26zl/cybersec-tools-installer/actions/workflows/security.yml"><img src="https://github.com/26zl/cybersec-tools-installer/actions/workflows/security.yml/badge.svg" alt="Security"></a>
  <a href="https://github.com/26zl/cybersec-tools-installer/actions/workflows/release.yml"><img src="https://github.com/26zl/cybersec-tools-installer/actions/workflows/release.yml/badge.svg" alt="Release"></a>
</p>

```text
   ______      __              _____
  / ____/_  __/ /_  ___  _____/ ___/___  _____
 / /   / / / / __ \/ _ \/ ___/\__ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /   ___/ /  __/ /__
\____/\__, /_.___/\___/_/   /____/\___/\___/
     /____/
              Tools Installer
```

The most comprehensive automated installer for cybersecurity tools on Linux. __660+ tools__, __18 modules__, __10 install methods__, one command.

---

## Step 1: Install

The installer automatically installs all required runtimes (Python, Go, Ruby, Java, Rust), dev libraries, pipx, and build tools. The only prerequisite is a supported Linux distro with a package manager.

> __Docker** is the one exception — install it manually if you want C2 frameworks, MobSF, BeEF, or TheHive (`--enable-docker`). See [Docker install docs](https://docs.docker.com/engine/install/).

### What gets installed automatically

| Runtime | How | Why |
| ------- | --- | --- |
| Python 3, pip, venv, pipx | System package + pip fallback | ~157 Python security tools |
| Go | System package | ~55 Go tools (subfinder, nuclei, ffuf, httpx, etc.) |
| Rust / Cargo | rustup (auto-downloaded) | 3 Rust tools (feroxbuster, RustScan, pwninit) |
| Ruby / gem | System package | 6 Ruby gems (wpscan, evil-winrm, XSpear, etc.) |
| Java (JDK) | System package | Burp Suite, ysoserial, apktool |
| build-essential, cmake, autotools | System package | ~15 tools built from source |
| Dev libraries | System package | libpcap, libssl, libffi, zlib, libxml2, libxslt, libglib2, libreadline, libsqlite3, libcurl, libldap, etc. |

```bash
git clone https://github.com/26zl/cybersec-tools-installer.git
cd cybersec-tools-installer
sudo ./install.sh
```

That installs all 660+ tools. To install a subset, use a profile or pick specific modules:

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

`--tool` installs only the specified tool without running the full dependency setup.

---

## Profiles

| Profile | Modules | Description |
| ------- | ------- | ----------- |
| `full` | All 18 | Complete security toolkit |
| `ctf` | misc, crypto, pwn, reversing, stego, forensics, cracking, web, mobile, blockchain | CTF competitions |
| `redteam` | misc, networking, recon, web, enterprise, pwn, mobile | Offensive security |
| `web` | misc, networking, recon, web | Web application testing |
| `malware` | misc, malware, forensics, reversing, mobile | Malware analysis |
| `osint` | misc, recon | OSINT gathering |
| `crackstation` | misc, cracking, crypto | Hash cracking |
| `lightweight` | misc, networking, recon, web | Core tools, minimal footprint |
| `blueteam` | misc, blueteam, forensics, malware, containers | Defensive security / IR |

## Modules

| Module | Tools | Description |
| ------ | ----- | ----------- |
| `misc` | ~65 | Post-exploitation, social engineering, wordlists, resources, C2 (Docker) |
| `networking` | ~58 | Port scanning, packet capture, tunneling, MITM, protocol tools |
| `recon` | ~103 | Subdomain enumeration, OSINT, DNS, automated recon frameworks |
| `web` | ~78 | Vulnerability scanning, fuzzing, SQLi, XSS, CMS scanners, API testing |
| `crypto` | ~17 | RSA attacks, cipher analysis, hash attacks, constraint solving |
| `pwn` | ~55 | Exploit frameworks, binary exploitation, fuzzing, payload generation |
| `reversing` | ~31 | Disassemblers, debuggers, emulation, Java/Python reversing |
| `forensics` | ~43 | Disk/memory forensics, file carving, timeline analysis, log analysis |
| `malware` | ~7 | YARA, ClamAV, inetsim, quark-engine, FLOSS, Capa |
| `enterprise` | ~102 | Active Directory, Kerberos, Azure AD, credential harvesting, lateral movement |
| `wireless` | ~41 | WiFi cracking, Bluetooth, SDR, rogue AP |
| `cracking` | ~32 | Hash cracking (john, hashcat), brute force, wordlist generation |
| `stego` | ~15 | Image/audio steganography, detection, StegCracker |
| `cloud` | ~18 | AWS/Azure/GCP security auditing, Checkov |
| `containers` | ~9 | Docker/Kubernetes security (Trivy, Grype, Syft, Kubescape, kubeaudit) |
| `blueteam` | ~21 | IDS/IPS, SIEM, incident response, threat intelligence, hardening |
| `mobile` | ~10 | Android/iOS app testing, APK analysis, MobSF (Docker) |
| `blockchain` | ~8 | Smart contract auditing (Slither, Mythril, Foundry), Echidna (Docker) |

## Install Methods

| Method | Count | Examples |
| ------ | ----- | ------- |
| System packages (apt/dnf/pacman/zypper) | ~199 | nmap, wireshark, john, hashcat |
| Git clone | ~260 | GitHub repos with auto-setup, resources, wordlists |
| pipx | ~157 | sqlmap, impacket, bloodhound, volatility3 |
| Go install | ~55 | nuclei, subfinder, ffuf, httpx |
| Binary release | ~26 | gitleaks, chainsaw, findomain, FLOSS, Capa, Syft, Kubescape |
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
| `scripts/remove.sh` | Remove tools by module | `sudo ./scripts/remove.sh --module enterprise --yes` |
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
| `specterops/bloodhound` | enterprise | `--enable-docker` | BloodHound CE |
| `trailofbits/echidna` | blockchain | `--enable-docker` | Echidna smart contract fuzzer |
| `strangebee/thehive:latest` | blueteam | `--enable-docker` | TheHive IR platform |
| `thehiveproject/cortex:latest` | blueteam | `--enable-docker` | Cortex analysis |

## Distro Support

__Debian/Ubuntu/Kali is the primary target__ -- all 660+ tools available. Fedora/Arch/openSUSE have ~10-20 packages auto-skipped (distro-specific). pipx, Go, Cargo, gem, git, and binary installs work identically across all distros.

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
