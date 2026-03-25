[![CI](https://github.com/26zl/cybersec-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/cybersec-toolkit/actions/workflows/ci.yml)
[![Integration](https://github.com/26zl/cybersec-toolkit/actions/workflows/integration.yml/badge.svg)](https://github.com/26zl/cybersec-toolkit/actions/workflows/integration.yml)
[![Security](https://github.com/26zl/cybersec-toolkit/actions/workflows/security.yml/badge.svg)](https://github.com/26zl/cybersec-toolkit/actions/workflows/security.yml)
[![uv update](https://github.com/26zl/cybersec-toolkit/actions/workflows/uv-update.yml/badge.svg)](https://github.com/26zl/cybersec-toolkit/actions/workflows/uv-update.yml)

```text
   ______      __              _____
  / ____/_  __/ /_  ___  _____/ ___/___  _____
 / /   / / / / __ \/ _ \/ ___/\__ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /   ___/ /  __/ /__
\____/\__, /_.___/\___/_/   /____/\___/\___/
     /____/                          by 26zl
              Toolkit
```

The most comprehensive modular installer and AI-integrated toolkit for cybersecurity tools on Linux and Termux (Android). __580+ tools__, __18 modules__, __14 profiles__, __12 install methods__, plus an __MCP server__ for AI-assisted hacking.

---

## Install

All required runtimes (Python, Go, Ruby, Java, Rust, Node.js), dev libraries, pipx, and build tools are installed automatically. The only prerequisite is a supported Linux distro. Windows and macOS are not supported (use WSL or Docker).

> __Docker__ is the one exception — install it manually if you want C2 frameworks, MobSF, BeEF, BloodHound, TheHive, or Cortex (`--enable-docker`). See [Docker install docs](https://docs.docker.com/engine/install/).
> __GitHub authentication__ is recommended. The installer downloads ~30 binary releases and makes ~30+ API calls to GitHub. Without auth, you're limited to __60 requests/hour__ and some downloads may fail. With auth, the limit is __5,000/hour__. The easiest way:
>
> ```bash
> # Install gh CLI and log in (one-time) — the installer auto-detects it
> sudo apt install gh && gh auth login
> ```
>
> Alternatively, export a [personal access token](https://github.com/settings/tokens) (no scopes needed):
>
> ```bash
> export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
> ```

```bash
git clone https://github.com/26zl/cybersec-toolkit.git
cd cybersec-toolkit
sudo ./install.sh
```

That installs all 580+ tools. To install a subset:

```bash
sudo ./install.sh --profile ctf                      # CTF tools only
sudo ./install.sh --profile redteam --enable-docker   # Red team + Docker C2
sudo ./install.sh --module web --module recon          # Specific modules
sudo ./install.sh --tool sqlmap --tool nmap            # Individual tools
sudo ./install.sh --dry-run --profile ctf              # Preview without installing
```

### Try in Docker

```bash
docker build -t cybersec-toolkit .
docker run cybersec-toolkit --profile ctf
```

__macOS (Apple Silicon):__ Add `--platform linux/amd64` to both commands to run via x86 emulation:

```bash
docker build --platform linux/amd64 -t cybersec-toolkit .
docker run --platform linux/amd64 cybersec-toolkit --profile ctf
```

__Termux (Android, experimental):__

> __Note:__ Termux support is under development and has not been fully tested on physical Android devices. Expect rough edges.

```bash
pkg install git
git clone https://github.com/26zl/cybersec-toolkit.git
cd cybersec-toolkit
./install.sh --profile lightweight
```

### All flags

```bash
sudo ./install.sh --help                # Full help
sudo ./install.sh --list-profiles       # Show profiles
sudo ./install.sh --list-modules        # Show modules
sudo ./install.sh --skip-heavy          # Skip large/slow packages
sudo ./install.sh --skip-pipx           # Skip all pipx (Python) installs
sudo ./install.sh --skip-go             # Skip all Go tool installs
sudo ./install.sh --skip-cargo          # Skip all Cargo (Rust) installs
sudo ./install.sh --skip-gems           # Skip all Ruby gem installs
sudo ./install.sh --skip-git            # Skip all git clone installs
sudo ./install.sh --skip-binary         # Skip all binary release downloads
sudo ./install.sh --skip-source         # Skip build-from-source, snap, npm, and curl-pipe installs
sudo ./install.sh --fast                # Skip checksum verification (see Security note below)
sudo ./install.sh --require-checksums   # Fail if binary release has no checksum file
sudo ./install.sh --upgrade-system      # Upgrade system packages before installing
sudo ./install.sh --list-sessions       # List install sessions and exit
sudo ./install.sh --rollback <id|last>  # Rollback tools installed in a session
sudo ./install.sh --version             # Show installer version and exit
sudo ./install.sh --enable-docker       # Pull Docker images
sudo ./install.sh --include-c2          # Include C2 frameworks (needs --enable-docker)
sudo ./install.sh -j 8                  # 8 parallel install jobs (default: 4)
sudo ./install.sh -v                    # Verbose / debug output
```

`--tool` installs only the specified tool without running the full dependency setup.
Dry-run time estimates count install entries across methods, so the estimate can be higher than the de-duplicated 580+ tool registry.

### Why does a full install take 15-45 minutes?

The installer orchestrates 580+ tools across 12 different install methods. The time is spent on I/O-bound operations that no scripting language can speed up:

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
| `misc` | 32 | Post-exploitation, social engineering, wordlists, resources, C2 (Docker) |
| `networking` | 54 | Port scanning, packet capture, tunneling, MITM, protocol tools |
| `recon` | 76 | Subdomain enumeration, OSINT, DNS, automated recon frameworks |
| `web` | 51 | Vulnerability scanning, fuzzing, SQLi, XSS, CMS scanners, API testing |
| `crypto` | 12 | RSA attacks, cipher analysis, hash attacks, constraint solving |
| `pwn` | 34 | Exploit frameworks, binary exploitation, fuzzing, payload generation |
| `reversing` | 31 | Disassemblers, debuggers, emulation, Java/Python reversing |
| `forensics` | 47 | Disk/memory forensics, file carving, timeline analysis, log analysis, hardware/serial |
| `enterprise` | 76 | Active Directory, Kerberos, Azure AD, credential harvesting, lateral movement |
| `wireless` | 39 | WiFi cracking, Bluetooth, SDR, rogue AP |
| `cracking` | 28 | Hash cracking (john, hashcat), brute force, wordlist generation |
| `stego` | 13 | Image/audio steganography, detection, StegCracker |
| `cloud` | 15 | AWS/Azure/GCP security auditing, Checkov |
| `containers` | 8 | Docker/Kubernetes security (Grype, Syft, Kubescape, kubeaudit) |
| `blueteam` | 31 | IDS/IPS, SIEM, incident response, threat intelligence, hardening, malware analysis (YARA, ClamAV, FLOSS, Capa, Loki) |
| `mobile` | 12 | Android/iOS app testing, APK analysis, MobSF (Docker) |
| `blockchain` | 12 | Smart contract auditing (Slither, Mythril, Foundry, Aderyn), blockchain forensics, Echidna (Docker) |
| `llm` | 9 | LLM red teaming, prompt injection, jailbreak testing, AI vulnerability scanning |

## Install Methods

| Method | Count | Examples |
| ------ | ----- | ------- |
| Git clone | ~176 | GitHub repos with auto-setup, resources, wordlists |
| System packages (apt/dnf/pacman/zypper) | ~164 | nmap, wireshark, john, hashcat |
| pipx | ~116 | sqlmap, impacket, bloodhound, volatility3 |
| Go install | ~53 | nuclei, subfinder, ffuf, httpx |
| Binary release | ~35 | gitleaks, chainsaw, findomain, FLOSS, Capa, Loki, Syft, Kubescape |
| Build from source | ~12 | massdns, duplicut, AFLplusplus, honggfuzz |
| Docker | ~9 | Empire, MobSF, BeEF, BloodHound, TheHive, Cortex, PentAGI |
| Ruby gem | 6 | wpscan, evil-winrm, brakeman |
| Cargo (Rust) | 5 | feroxbuster, RustScan, pwninit, yara-x-cli |
| Special (curl-pipe) | 3 | Metasploit, Foundry, Steampipe |
| Snap | 1 | zaproxy |
| npm | 1 | promptfoo |

---

## Post-Install Scripts

All scripts require root on Linux (`sudo`) and support `--help`. On Termux, no root is needed.

| Script | Purpose | Example |
| ------ | ------- | ------- |
| `scripts/verify.sh` | Check which tools are installed | `sudo ./scripts/verify.sh --module web --skip-heavy` |
| `scripts/update.sh` | Update all installed tools | `sudo ./scripts/update.sh --skip-system` |
| `scripts/remove.sh` | Remove tools by module | `sudo ./scripts/remove.sh --module enterprise --yes` |
| `scripts/remove.sh --deep-clean` | Purge all caches and build artifacts | `sudo ./scripts/remove.sh --deep-clean --yes` |
| `scripts/backup.sh` | Backup/restore tool configs | `sudo ./scripts/backup.sh backup` |

`--deep-clean` removes Go module/build cache, Cargo registry, pip/pipx/npm/gem caches, orphaned pipx venvs, stale symlinks, and log files. Add `--remove-deps` to also purge Rustup toolchains.

## MCP Server (AI Integration)

[MCP (Model Context Protocol)](https://modelcontextprotocol.io/) is an open standard that lets AI assistants use external tools. This project includes an MCP server that gives any MCP-capable AI (Claude Code, Claude Desktop, Cursor, etc.) full read access to the 580+ tool registry — plus the ability to check installs, recommend profiles, and execute tools. The AI becomes an interactive partner for ethical hacking: it knows every tool, which ones you have installed, and can run them for you.

### What the AI can do

| Tool | What it does |
| ---- | ------------ |
| `list_tools` | List/filter all 580+ tools by module, method, or install status (includes URLs) |
| `check_installed` | Check if a tool is installed (5 detection strategies) |
| `get_tool_info` | Full details: method, module, URL, install/update/remove commands |
| `get_module_info` | Deep-dive a module: all tools, install status, which profiles use it |
| `get_profile_tools` | See every tool a profile installs, grouped by module |
| `suggest_for_ctf` | Curated tool recommendations for 13 CTF challenge categories |
| `suggest_for_bounty` | Bug bounty tool recommendations for 6 target types with methodology and common vulns |
| `recommend_install` | Natural-language → profile/module/tool recommendation |
| `list_profiles` | All 14 profiles with tool counts and install commands |
| `run_tool` | Execute installed tools safely (sanitized args, network policy, rate limiting, audit logging). Supports remote execution via SSH |
| `run_pipeline` | Pipe tools together safely without shell (`strings binary \| grep flag`) |
| `run_script` | Write and execute Python/Bash scripts (pwntools, z3, requests, crypto). Supports per-script venv selection |
| `manage_remote_hosts` | Add, remove, list, and test SSH remote hosts for remote tool execution |

### Quick Start

Requires [uv](https://docs.astral.sh/uv/). Add to `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "uv",
      "args": ["run", "--directory", "mcp_server", "fastmcp", "run", "server.py"]
    }
  }
}
```

Restart Claude Code. The 13 tools appear in `/mcp`.

### Connect from WSL (e.g. Kali Linux)

The MCP server runs over stdio, so it works from any environment that Claude Code can spawn. To use tools installed inside WSL:

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "wsl",
      "args": [
        "-d", "kali-linux",
        "bash", "-lc",
        "cd /path/to/cybersec-toolkit/mcp_server && uv run fastmcp run server.py"
      ]
    }
  }
}
```

### Connect from Docker

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "cybersec-toolkit",
        "bash", "-c",
        "cd /opt/cybersec-toolkit/mcp_server && uv run fastmcp run server.py"
      ]
    }
  }
}
```

### Usage Examples

Once connected, just talk to the AI naturally:

- __"Which tools do I need for a web CTF?"__ -- suggests top tools with install status
- __"What does the CTF profile install?"__ -- lists all 272 tools grouped by module
- __"Tell me about the web module"__ -- 51 tools, methods breakdown, which profiles include it
- __"How do I install sqlmap?"__ -- install/update/remove commands for the right module
- __"I want to do bug bounty hunting"__ -- recommends the `web` profile
- __"Is nmap installed?"__ -- multi-strategy detection (PATH, .versions, pipx, /opt, docker)
- __"Run nmap --version"__ -- executes with output capture, network policy enforcement
- __"Run nmap on my Kali VM"__ -- remote execution via SSH with per-host tool allowlists
- __"Write a pwntools exploit for this binary"__ -- writes and runs a script with `venv="pwntools"`
- __"Extract hidden data from this PNG"__ -- pipelines `strings`, `xxd`, `binwalk` + custom scripts

### Script Execution

`run_script` lets the AI write and execute Python or Bash scripts. Requires `CYBERSEC_MCP_ALLOW_SCRIPTS=1`:

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "uv",
      "args": ["run", "--directory", "mcp_server", "fastmcp", "run", "server.py"],
      "env": {
        "CYBERSEC_MCP_ALLOW_SCRIPTS": "1",
        "CYBERSEC_MCP_ALLOW_EXTERNAL": "1"
      }
    }
  }
}
```

#### Venv Support

Some packages (e.g. pwntools) require an older Python. The `venv` parameter lets the AI choose the right interpreter per script:

```bash
# One-time setup: create a venv with pwntools
python3.12 -m venv ~/.ctf-venvs/pwntools
~/.ctf-venvs/pwntools/bin/pip install pwntools z3-solver
```

The AI then uses `run_script("from pwn import *; ...", venv="pwntools")` automatically. Scripts that only need standard libs or the server's packages (requests, pycryptodome, beautifulsoup4) run without `venv`. Set `CYBERSEC_MCP_VENVS_DIR` to override the default `~/.ctf-venvs/` location.

### Manual Scripts

The `manual_scripts/` directory stores persistent scripts — complex exploits, multi-step solvers, and reusable tools that shouldn't disappear after execution. The AI writes scripts here when they're worth keeping.

### Test the Server

```bash
cd mcp_server && uv run fastmcp dev server.py
```

This opens a web-based MCP Inspector for interactively testing each tool.

See [`mcp_server/README.md`](mcp_server/README.md) for Claude Desktop setup and full documentation.

## Development

Public contributor docs live in [`CONTRIBUTING.md`](CONTRIBUTING.md). The quick-start is:

```bash
git submodule update --init --recursive
shellcheck --severity=warning install.sh lib/*.sh modules/*.sh scripts/*.sh
bash -n install.sh lib/*.sh modules/*.sh scripts/*.sh
python3 scripts/validate_tools_config.py
python3 scripts/validate_mcp_sync.py
python3 scripts/validate_distro_compat.py
./tests/bats/bin/bats tests/*.bats
cd mcp_server && uv sync --group dev && uv run ruff check . && uv run ruff format --check . && uv run pytest tests/ -q
```

Run shell tests on Linux or WSL. Native Windows checkouts can rewrite the vendored Bats submodules with CRLF and cause `$'\r'` failures.

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
| `vxcontrol/pentagi:latest` | llm | `--enable-docker` | PentAGI autonomous pentesting |

## Distro Support

__Debian/Ubuntu/Kali is the primary target__ -- the full 580+ registry is available there, and it has the strongest test coverage. Fedora/Arch/openSUSE have ~10-20 packages auto-skipped (distro-specific) and are covered by the integration workflow. WSL and ARM are supported in practice, but they do not yet have dedicated CI jobs. Windows and macOS are detected and blocked with a clear error message.

| Platform | Status |
| -------- | ------ |
| __WSL__ | Supported for installs and MCP usage. Wireless module auto-skipped (no hardware access) and kernel-level packages filtered. Validate release-critical changes in a local WSL distro because there is no dedicated CI job yet. |
| __ARM__ (aarch64/armv7) | Supported with automatic skips for x86-only binary releases and build-from-source tools. No dedicated CI job yet. |
| __Termux__ (Android) | Experimental. Under development, not covered by CI, and not yet broadly tested on physical devices. No sudo needed. Docker/snap/binary releases/build-from-source skipped (Bionic incompatible). |
| __Windows__ (native) | Not supported. Use WSL. |
| __macOS__ | Not supported. Use Docker container. |

## Supply Chain Model

This installer downloads and runs code from the internet. On Linux it runs as root (`sudo`); on Termux it runs in the app's user sandbox (no root).

- __System packages__: GPG-signed by your distro's repos (apt, dnf, pacman, zypper, pkg)
- __pipx/Go/Cargo/Gem/npm__: Downloads from registries (no signature verification, pipx isolated in venvs)
- __Binary releases__: SHA256 verified when checksum file available, hard-fails on mismatch. Use `--require-checksums` to also fail when no checksum file is published. __Warning:__ `--fast` disables _all_ checksum verification, including for releases that do publish checksums — do not use in production or CI environments
- __Go SDK__: SHA256 verified against go.dev published hashes when available; warns on API failure, hard-fails with `--require-checksums`
- __Git repos__: Cloned at HEAD, deps installed in isolated venvs (setup.py is NOT executed)
- __Build from source__: Runs `make` (as root on Linux) -- review what you're building

The `.versions` file logs what was installed and when.

## Known Limitations

Checksum verification is best-effort by default. Some upstream releases do not publish checksums or signatures, so downloads may proceed without cryptographic verification in those cases. Use `--require-checksums` to fail-closed when no checksum file is available. Go SDK downloads are SHA256-verified against go.dev when the API is reachable; use `--require-checksums` to hard-fail if it is not.

`--fast` skips __all__ checksum verification for binary releases (both SHA256 checks and the missing-checksum warning), including releases that _do_ publish checksums. This trades integrity verification for speed. It is mutually exclusive with `--require-checksums`. Do not use `--fast` in CI pipelines or environments where supply-chain integrity matters.

## License

MIT License -- see [LICENSE](LICENSE) for details.

For contribution workflow and review expectations, see [`CONTRIBUTING.md`](CONTRIBUTING.md).
For vulnerability reporting, see [`SECURITY.md`](SECURITY.md).

## Disclaimer

For educational and authorized security testing only. Only use on systems you own or have explicit written permission to test.
