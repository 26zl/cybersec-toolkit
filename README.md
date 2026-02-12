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

The most comprehensive automated installer for cybersecurity tools on Linux and Termux (Android). __590+ tools__, __19 modules__, __12 install methods__, one command.

---

## Install

All required runtimes (Python, Go, Ruby, Java, Rust, Node.js), dev libraries, pipx, and build tools are installed automatically. The only prerequisite is a supported Linux distro. Windows and macOS are not supported (use WSL or Docker).

> __Docker__ is the one exception — install it manually if you want C2 frameworks, MobSF, BeEF, BloodHound, TheHive, or Cortex (`--enable-docker`). See [Docker install docs](https://docs.docker.com/engine/install/).

```bash
git clone https://github.com/26zl/cybersec-tools-installer.git
cd cybersec-tools-installer
sudo ./install.sh
```

That installs all 590+ tools. To install a subset:

```bash
sudo ./install.sh --profile ctf                      # CTF tools only
sudo ./install.sh --profile redteam --enable-docker   # Red team + Docker C2
sudo ./install.sh --module web --module recon          # Specific modules
sudo ./install.sh --tool sqlmap --tool nmap            # Individual tools
sudo ./install.sh --dry-run --profile ctf              # Preview without installing
```

### Try in Docker

```bash
docker build -t cybersec-installer .
docker run cybersec-installer --profile ctf
```

### All flags

```bash
sudo ./install.sh --help                # Full help
sudo ./install.sh --list-profiles       # Show profiles
sudo ./install.sh --list-modules        # Show modules
sudo ./install.sh --skip-heavy          # Skip large packages (sagemath, gnuradio)
sudo ./install.sh --skip-pipx           # Skip all pipx (Python) installs
sudo ./install.sh --skip-go             # Skip all Go tool installs
sudo ./install.sh --skip-cargo          # Skip all Cargo (Rust) installs
sudo ./install.sh --skip-gems           # Skip all Ruby gem installs
sudo ./install.sh --skip-git            # Skip all git clone installs
sudo ./install.sh --skip-binary         # Skip all binary release downloads
sudo ./install.sh --skip-source         # Skip build-from-source, snap, npm, and curl-pipe installs
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
| `full` | All 19 | Complete security toolkit |
| `ctf` | misc, crypto, pwn, reversing, stego, forensics, cracking, web, mobile, blockchain | CTF competitions |
| `redteam` | misc, networking, recon, web, enterprise, pwn, mobile, cracking, cloud, wireless, reversing, crypto | Offensive security |
| `web` | misc, networking, recon, web | Web application testing |
| `malware` | misc, malware, forensics, reversing, mobile | Malware analysis |
| `osint` | misc, recon | OSINT gathering |
| `crackstation` | misc, cracking, crypto | Hash cracking |
| `lightweight` | misc, networking, recon, web | Core tools, minimal footprint |
| `blueteam` | misc, blueteam, forensics, malware, containers, networking, cloud, recon | Defensive security / IR |

## Modules

| Module | Tools | Description |
| ------ | ----- | ----------- |
| `misc` | ~32 | Post-exploitation, social engineering, wordlists, resources, C2 (Docker) |
| `networking` | ~53 | Port scanning, packet capture, tunneling, MITM, protocol tools |
| `recon` | ~76 | Subdomain enumeration, OSINT, DNS, automated recon frameworks |
| `web` | ~49 | Vulnerability scanning, fuzzing, SQLi, XSS, CMS scanners, API testing |
| `crypto` | ~13 | RSA attacks, cipher analysis, hash attacks, constraint solving |
| `pwn` | ~40 | Exploit frameworks, binary exploitation, fuzzing, payload generation |
| `reversing` | ~32 | Disassemblers, debuggers, emulation, Java/Python reversing |
| `forensics` | ~43 | Disk/memory forensics, file carving, timeline analysis, log analysis |
| `malware` | ~7 | YARA, ClamAV, inetsim, quark-engine, FLOSS, Capa |
| `enterprise` | ~89 | Active Directory, Kerberos, Azure AD, credential harvesting, lateral movement |
| `wireless` | ~40 | WiFi cracking, Bluetooth, SDR, rogue AP |
| `cracking` | ~28 | Hash cracking (john, hashcat), brute force, wordlist generation |
| `stego` | ~14 | Image/audio steganography, detection, StegCracker |
| `cloud` | ~15 | AWS/Azure/GCP security auditing, Checkov |
| `containers` | ~9 | Docker/Kubernetes security (Trivy, Grype, Syft, Kubescape, kubeaudit) |
| `blueteam` | ~26 | IDS/IPS, SIEM, incident response, threat intelligence, hardening |
| `mobile` | ~12 | Android/iOS app testing, APK analysis, MobSF (Docker) |
| `blockchain` | ~5 | Smart contract auditing (Slither, Mythril, Foundry), Echidna (Docker) |
| `llm` | ~6 | LLM red teaming, prompt injection, jailbreak testing, AI vulnerability scanning |

## Install Methods

| Method | Count | Examples |
| ------ | ----- | ------- |
| Git clone | ~194 | GitHub repos with auto-setup, resources, wordlists |
| System packages (apt/dnf/pacman/zypper) | ~163 | nmap, wireshark, john, hashcat |
| pipx | ~111 | sqlmap, impacket, bloodhound, volatility3 |
| Go install | ~52 | nuclei, subfinder, ffuf, httpx |
| Binary release | ~30 | gitleaks, chainsaw, findomain, FLOSS, Capa, Syft, Kubescape |
| Build from source | ~15 | massdns, duplicut, AFLplusplus, honggfuzz |
| Docker | ~8 | Empire, MobSF, BeEF, BloodHound, TheHive, Cortex |
| Ruby gem | 6 | wpscan, evil-winrm, XSpear |
| Cargo (Rust) | 4 | feroxbuster, RustScan, pwninit, sniffnet |
| Special (curl-pipe) | 3 | Metasploit, Foundry, Steampipe |
| Snap | 2 | zaproxy, solc |
| npm | 1 | promptfoo |

---

## Post-Install Scripts

All scripts require root on Linux (`sudo`) and support `--help`. On Termux, no root is needed.

| Script | Purpose | Example |
| ------ | ------- | ------- |
| `scripts/verify.sh` | Check which tools are installed | `sudo ./scripts/verify.sh --module web` |
| `scripts/update.sh` | Update all installed tools | `sudo ./scripts/update.sh --skip-system` |
| `scripts/remove.sh` | Remove tools by module | `sudo ./scripts/remove.sh --module enterprise --yes` |
| `scripts/remove.sh --deep-clean` | Purge all caches and build artifacts | `sudo ./scripts/remove.sh --deep-clean --yes` |
| `scripts/backup.sh` | Backup/restore tool configs | `sudo ./scripts/backup.sh backup` |

`--deep-clean` removes Go module/build cache, Cargo registry, pip/pipx/npm/gem caches, orphaned pipx venvs, stale symlinks, and log files. Add `--remove-deps` to also purge Rustup toolchains.

## Tool Locations

Non-system tools (pipx, Go, Cargo, git, binary releases) are installed to `/usr/local/bin/` on Linux and `$PREFIX/bin` on Termux. System packages go to their default location (`/usr/bin/`).

| Method | Binary location (Linux) | Binary location (Termux) | Data location |
| ------ | ----------------------- | ------------------------ | ------------- |
| pipx | `/usr/local/bin/` | `$PREFIX/bin/` | `/opt/pipx/` or `~/.local/pipx/` |
| Go | `/usr/local/bin/` | `$PREFIX/bin/` | `/opt/go/` or `~/.go/` |
| Cargo | `/usr/local/bin/` (symlinked) | `$PREFIX/bin/` (symlinked) | `~/.cargo/` |
| Git repos | `/usr/local/bin/` (symlinked) | `$PREFIX/bin/` (symlinked) | `/opt/<repo>/` or `~/tools/<repo>/` |
| Binary releases | `/usr/local/bin/` | Skipped (glibc incompatible with Bionic) | -- |

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

__Debian/Ubuntu/Kali is the primary target__ -- all 590+ tools available. Fedora/Arch/openSUSE have ~10-20 packages auto-skipped (distro-specific). pipx, Go, Cargo, gem, git, and binary installs work identically across all distros. Windows and macOS are detected and blocked with a clear error message.

| Platform | Status |
| -------- | ------ |
| __WSL__ | Supported. Wireless module auto-skipped (no hardware access). Kernel-level packages filtered. |
| __ARM__ (aarch64/armv7) | Supported. x86-only binary releases and build-from-source tools skipped. |
| __Termux__ (Android) | Under development -- not fully tested on physical devices. No sudo needed. Docker/snap/binary releases/build-from-source skipped (Bionic incompatible). |
| __Windows__ (native) | Not supported. Use WSL. |
| __macOS__ | Not supported. Use Docker container. |

### Termux quick start (experimental)

> __Note:** Termux support is under development and has not been fully tested on physical Android devices. Expect rough edges.

```bash
pkg install git
git clone https://github.com/26zl/cybersec-tools-installer.git
cd cybersec-tools-installer
./install.sh --profile lightweight
```

## Supply Chain Model

This installer downloads and runs code from the internet. On Linux it runs as root (`sudo`); on Termux it runs in the app's user sandbox (no root).

- __System packages__: GPG-signed by your distro's repos (apt, dnf, pacman, zypper, pkg)
- __pipx/Go/Cargo/Gem/npm__: Downloads from registries (no signature verification, pipx isolated in venvs)
- __Binary releases__: SHA256 verified when checksum file available, hard-fails on mismatch
- __Git repos__: Cloned at HEAD, deps installed in isolated venvs (setup.py is NOT executed)
- __Build from source__: Runs `make` (as root on Linux) -- review what you're building

The `.versions` file logs what was installed and when.

## License

MIT License -- see [LICENSE](LICENSE) for details.

## Disclaimer

For educational and authorized security testing only. Only use on systems you own or have explicit written permission to test.
