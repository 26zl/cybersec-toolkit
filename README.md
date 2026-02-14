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

The most comprehensive automated installer for cybersecurity tools on Linux and Termux (Android). __570+ tools__, __18 modules__, __12 install methods__, one command.

---

## Install

All required runtimes (Python, Go, Ruby, Java, Rust, Node.js), dev libraries, pipx, and build tools are installed automatically. The only prerequisite is a supported Linux distro. Windows and macOS are not supported (use WSL or Docker).

> __Docker__ is the one exception — install it manually if you want C2 frameworks, MobSF, BeEF, BloodHound, TheHive, or Cortex (`--enable-docker`). See [Docker install docs](https://docs.docker.com/engine/install/).

```bash
git clone https://github.com/26zl/cybersec-tools-installer.git
cd cybersec-tools-installer
sudo ./install.sh
```

That installs all 570+ tools. To install a subset:

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
sudo ./install.sh --require-checksums   # Fail if binary release has no checksum file
sudo ./install.sh --upgrade-system      # Upgrade system packages before installing
sudo ./install.sh --enable-docker       # Pull Docker images
sudo ./install.sh --include-c2          # Include C2 frameworks (needs --enable-docker)
sudo ./install.sh -j 8                  # 8 parallel install jobs (default: 4)
sudo ./install.sh -v                    # Verbose / debug output
```

`--tool` installs only the specified tool without running the full dependency setup.

### Why does a full install take 15-45 minutes?

The installer orchestrates 570+ tools across 12 different install methods. The time is spent on I/O-bound operations that no scripting language can speed up:

| What takes time | Why | Typical time |
| --- | --- | --- |
| System packages (apt/dnf) | Downloading and unpacking ~150 `.deb`/`.rpm` files, resolving dependencies | ~40% |
| Cargo (Rust) crates | Compiling from source — Rust has no pre-built registry binaries | ~25% |
| Go tools | Downloading modules and compiling ~30 binaries | ~15% |
| pipx (Python) | Creating ~40 isolated venvs, downloading wheels | ~10% |
| Git clones | Cloning ~30 repositories | ~5% |
| Binary releases | Downloading ~30 pre-built binaries from GitHub | ~4% |
| Bash overhead | Array iteration, logging, progress bars | <0.1% |

The installer already parallelizes where possible (`-j 4` by default). Methods with shared locks (apt, pipx, cargo) must run sequentially. To reduce install time:

- Use `--profile lightweight` or `--module <name>` to install only what you need
- Use `--skip-cargo` to skip Rust compilation (the slowest per-tool method)
- Increase parallelism with `-j 8` for faster Go/git/binary downloads
- Set up an [apt-cacher-ng](https://wiki.debian.org/AptCacherNg) proxy for repeated installs

---

## Profiles

| Profile | Modules | Description |
| ------- | ------- | ----------- |
| `full` | All 18 | Complete security toolkit |
| `ctf` | misc, crypto, pwn, reversing, stego, forensics, cracking, web, mobile, blockchain | CTF competitions |
| `redteam` | misc, networking, recon, web, enterprise, pwn, mobile, cracking, cloud, wireless, reversing, crypto | Offensive security |
| `web` | misc, networking, recon, web | Web application testing |
| `osint` | misc, recon | OSINT gathering |
| `forensics` | misc, forensics, blueteam, reversing, stego, cracking | Digital forensics and incident response |
| `pwn` | misc, pwn, reversing, crypto | Binary exploitation and reverse engineering |
| `mobile` | misc, mobile, web, reversing | Mobile application security testing |
| `cloud` | misc, cloud, containers, networking, recon | Cloud and container security auditing |
| `blockchain` | misc, blockchain, web, crypto | Smart contract auditing and blockchain security |
| `wireless` | misc, wireless, networking | WiFi, Bluetooth, and SDR security |
| `lightweight` | misc, networking, recon, web, cracking | Hobby ethical hacking essentials (HTB, THM, bug bounty) |
| `crackstation` | misc, cracking, crypto | Hash cracking |
| `blueteam` | misc, blueteam, forensics, reversing, mobile, containers, networking, cloud, recon | Defensive security, IR, malware analysis |

## Modules

| Module | Tools | Description |
| ------ | ----- | ----------- |
| `misc` | ~30 | Post-exploitation, social engineering, wordlists, resources, C2 (Docker) |
| `networking` | ~54 | Port scanning, packet capture, tunneling, MITM, protocol tools |
| `recon` | ~76 | Subdomain enumeration, OSINT, DNS, automated recon frameworks |
| `web` | ~49 | Vulnerability scanning, fuzzing, SQLi, XSS, CMS scanners, API testing |
| `crypto` | ~13 | RSA attacks, cipher analysis, hash attacks, constraint solving |
| `pwn` | ~37 | Exploit frameworks, binary exploitation, fuzzing, payload generation |
| `reversing` | ~32 | Disassemblers, debuggers, emulation, Java/Python reversing |
| `forensics` | ~43 | Disk/memory forensics, file carving, timeline analysis, log analysis |
| `enterprise` | ~78 | Active Directory, Kerberos, Azure AD, credential harvesting, lateral movement |
| `wireless` | ~39 | WiFi cracking, Bluetooth, SDR, rogue AP |
| `cracking` | ~28 | Hash cracking (john, hashcat), brute force, wordlist generation |
| `stego` | ~14 | Image/audio steganography, detection, StegCracker |
| `cloud` | ~15 | AWS/Azure/GCP security auditing, Checkov |
| `containers` | ~9 | Docker/Kubernetes security (Trivy, Grype, Syft, Kubescape, kubeaudit) |
| `blueteam` | ~32 | IDS/IPS, SIEM, incident response, threat intelligence, hardening, malware analysis (YARA, ClamAV, FLOSS, Capa, Loki) |
| `mobile` | ~12 | Android/iOS app testing, APK analysis, MobSF (Docker) |
| `blockchain` | ~5 | Smart contract auditing (Slither, Mythril, Foundry), Echidna (Docker) |
| `llm` | ~6 | LLM red teaming, prompt injection, jailbreak testing, AI vulnerability scanning |

## Install Methods

| Method | Count | Examples |
| ------ | ----- | ------- |
| Git clone | ~175 | GitHub repos with auto-setup, resources, wordlists |
| System packages (apt/dnf/pacman/zypper) | ~163 | nmap, wireshark, john, hashcat |
| pipx | ~111 | sqlmap, impacket, bloodhound, volatility3 |
| Go install | ~52 | nuclei, subfinder, ffuf, httpx |
| Binary release | ~32 | gitleaks, chainsaw, findomain, FLOSS, Capa, Loki, Syft, Kubescape |
| Build from source | ~15 | massdns, duplicut, AFLplusplus, honggfuzz |
| Docker | ~8 | Empire, MobSF, BeEF, BloodHound, TheHive, Cortex |
| Ruby gem | 6 | wpscan, evil-winrm, brakeman |
| Cargo (Rust) | 4 | feroxbuster, RustScan, pwninit, yara-x-cli |
| Special (curl-pipe) | 3 | Metasploit, Foundry, Steampipe |
| Snap | 3 | zaproxy, solc, ngrok |
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

Only used with `--enable-docker`. If Docker is not installed and `--enable-docker` is set, the installer exits with an error asking you to install Docker first.

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

__Debian/Ubuntu/Kali is the primary target__ -- all 570+ tools available. Fedora/Arch/openSUSE have ~10-20 packages auto-skipped (distro-specific). pipx, Go, Cargo, gem, git, and binary installs work identically across all distros. Windows and macOS are detected and blocked with a clear error message.

| Platform | Status |
| -------- | ------ |
| __WSL__ | Supported. Wireless module auto-skipped (no hardware access). Kernel-level packages filtered. |
| __ARM__ (aarch64/armv7) | Supported. x86-only binary releases and build-from-source tools skipped. |
| __Termux__ (Android) | Under development -- not fully tested on physical devices. No sudo needed. Docker/snap/binary releases/build-from-source skipped (Bionic incompatible). |
| __Windows__ (native) | Not supported. Use WSL. |
| __macOS__ | Not supported. Use Docker container. |

### Termux quick start (experimental)

> __Note:__ Termux support is under development and has not been fully tested on physical Android devices. Expect rough edges.

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
- __Binary releases__: SHA256 verified when checksum file available, hard-fails on mismatch. Use `--require-checksums` to also fail when no checksum file is published
- __Go SDK__: SHA256 verified against go.dev published hashes when available; warns on API failure, hard-fails with `--require-checksums`
- __Git repos__: Cloned at HEAD, deps installed in isolated venvs (setup.py is NOT executed)
- __Build from source__: Runs `make` (as root on Linux) -- review what you're building

The `.versions` file logs what was installed and when.

## Known Limitations

Checksum verification is best-effort by default. Some upstream releases do not publish checksums or signatures, so downloads may proceed without cryptographic verification in those cases. Use `--require-checksums` to fail-closed when no checksum file is available. Go SDK downloads are SHA256-verified against go.dev when the API is reachable; use `--require-checksums` to hard-fail if it is not.

## License

MIT License -- see [LICENSE](LICENSE) for details.

## Disclaimer

For educational and authorized security testing only. Only use on systems you own or have explicit written permission to test.
