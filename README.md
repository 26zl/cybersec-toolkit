<!-- mcp-name: io.github.26zl/cybersec-toolkit -->
[![CI](https://github.com/26zl/cybersec-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/26zl/cybersec-toolkit/actions/workflows/ci.yml)
[![Integration](https://github.com/26zl/cybersec-toolkit/actions/workflows/integration.yml/badge.svg)](https://github.com/26zl/cybersec-toolkit/actions/workflows/integration.yml)
[![Security](https://github.com/26zl/cybersec-toolkit/actions/workflows/security.yml/badge.svg)](https://github.com/26zl/cybersec-toolkit/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/26zl/cybersec-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/26zl/cybersec-toolkit)
[![Last commit](https://img.shields.io/github/last-commit/26zl/cybersec-toolkit)](https://github.com/26zl/cybersec-toolkit/commits/main)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker image](https://img.shields.io/badge/ghcr.io-cybersec--toolkit-2496ED?logo=docker&logoColor=white)](https://github.com/26zl/cybersec-toolkit/pkgs/container/cybersec-toolkit)
[![Glama score](https://glama.ai/mcp/servers/26zl/cybersec-toolkit/badges/score.svg)](https://glama.ai/mcp/servers/26zl/cybersec-toolkit)

```text
    /\   /\        ______      __              _____
   (o ) ( o)      / ____/_  __/ /_  ___  _____/ ___/___  _____
    \ \_/ /      / /   / / / / __ \/ _ \/ ___/\__ \/ _ \/ ___/
  <==\   /==>   / /___/ /_/ / /_/ /  __/ /   ___/ /  __/ /__
     \ V /      \____/\__, /_.___/\___/_/   /____/\___/\___/
     /_ _\           /____/                          by 26zl
      |_|                     Toolkit
```

<p align="center"><em>&ldquo;I am a friend of virtue, not of fortune.&rdquo;</em><br>&mdash; Gjergj Kastrioti &middot; Skanderbeg (1405&ndash;1468)</p>

__A security toolkit that AI agents can drive, under rules you set.__ One command installs 670+ security tools on Linux or Termux. An [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server lets Claude Code, Codex, Gemini CLI, OpenCode, and other MCP clients discover, recommend, and run those tools through a governed execution path, inside a disposable Kata Containers VM by default. 872 Agent Skills supply the methodology for CTF, pentest, bug bounty, DFIR, and blue-team work.

| Component | What you get |
| --------- | ------------ |
| [Installer](#installer) | 670+ tools in 18 modules, 14 profiles, and 12 install methods for Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE, and Termux |
| [MCP server](#mcp-server) | 15 tools for discovery, advice, and governed execution; external targets and script execution are off by default |
| [Sandbox](#sandbox-and-host-mode) | One Kata Containers VM per session by default; `--local` runs the server on the host |
| [Agent Skills](#agent-skills) | 872 skills (31 project-authored, 841 curated), also installable as a Claude Code plugin |

> __What makes it different:__ most toolkits stop at _installing_ tools. Here an AI can also _drive_ them: infer the problem type, pick tools from every module and profile, and work through the problem with you step by step. When you explicitly authorize it, the same toolchain runs an autonomous solver loop. __Companion by default; autonomous only when you ask.__ It complements Kali, Parrot, or BlackArch rather than replacing them: it runs on the machine you already have, Termux included.

[Quick start](#quick-start) · [How it works](#how-it-works) · [Trust & safety](#trust--safety) · [Installer](#installer) · [MCP server](#mcp-server) · [Agent Skills](#agent-skills) · [Development](#development) · [License](#license)

## Quick start

__1. Install the tools__ on a supported Linux distro or on Termux:

```bash
git clone --depth 1 --branch v1.2.1 https://github.com/26zl/cybersec-toolkit.git && cd cybersec-toolkit
./install.sh --doctor             # read-only preflight: distro, prerequisites, MCP server, sandbox
sudo ./install.sh --profile ctf   # one profile; with no flags, all 18 modules
```

> v1.2.1 predates the Kata sandbox and runs the MCP server on the host. Clone `main` for the sandboxed launcher until the next release.

__2. Connect an AI client.__ The tracked configs for Claude Code (`.mcp.json`), Codex, Gemini CLI, and OpenCode start the server through `scripts/mcp-launch.sh`, with external targets and script execution disabled. Choose where the tools run:

| Mode | Tools run | Host needs | One-time setup |
| ---- | --------- | ---------- | -------------- |
| Sandbox (default) | In a disposable Kata VM, from the sandbox image | Linux with KVM, Docker 23+ with a Kata runtime, Node.js 22+ | `make sandbox-image`, then `npm --prefix sandbox ci --ignore-scripts` |
| Host (`--local`) | As your user, with the tools `install.sh` installed | [uv](https://docs.astral.sh/uv/) | Add `--local` to the launcher, or set `CYBERSEC_SANDBOX_MODE=local` in the client's `env` |

Kata needs KVM: on macOS, on Windows, and in VMs without nested virtualization, use host mode.

__3. Restart the client.__ The 15 tools appear (`/mcp` in Claude Code). Then ask for what you need, for example "triage this binary" or "map the attack surface of my lab at 10.10.0.0/24".

## How it works

Two entry points share one tool registry. An __operator__ runs the bash installer to put tools on disk: on the host, or into the sandbox image at build time. An __AI agent__ talks to the MCP server, which runs inside a Kata VM by default, to discover, recommend, and execute those tools through one governed path. `tools_config.json` is the single source of truth that the modules define and the MCP advisors read; CI validators keep the Python and bash sides in sync.

<!-- Rendered from assets/how-it-works.mmd so it displays consistently everywhere.
     Re-render with:
     npm_config_cache=/tmp/cybersec-npm-cache npx --yes \
       --package @mermaid-js/mermaid-cli@11.16.0 mmdc \
       -i assets/how-it-works.mmd -o assets/how-it-works.png -t dark -b "#0d1117" -s 3 -->
![How it works: an operator runs the bash installer to put tools on disk; an AI agent drives the MCP server, which runs in a Kata VM by default, to discover, recommend, and execute them. The installer and MCP server meet at the tools_config.json registry and the installed tools, with security.py governing tool execution and CI validators keeping the Python and bash sides in sync.](assets/how-it-works.png)

Solid arrows are runtime or installation actions; dashed arrows are validation and context relationships. Client configurations enter through the root-aware launcher, which boots the VM through a [Sandcastle](https://github.com/mattpocock/sandcastle) Kata provider (`sandbox/kata.mjs`) — or, with `--local`, starts the server on the host. `security.py` governs `run_tool` and `run_pipeline` through the allowlist, argument checks, and network policy without invoking a shell. `run_script` is a separate, disabled-by-default capability that runs arbitrary code. Agent Skills stay outside the execution path: `.claude/skills/` is canonical, and `scripts/sync-skills.sh` generates `.agents/skills/` for clients that read the portable mirror. Mermaid source: [`assets/how-it-works.mmd`](assets/how-it-works.mmd).

## Trust & safety

What runs, and what is gated:

- __Default-safe MCP.__ `CYBERSEC_MCP_ALLOW_EXTERNAL=0` rejects network targets that do not resolve to private or loopback ranges, and `CYBERSEC_MCP_ALLOW_SCRIPTS=0` disables `run_script`. External scopes and scripting are explicit opt-ins.
- __One gate for governed execution__ (`mcp_server/security.py`): registry allowlist, no shell (`create_subprocess_exec`, never `shell=True`), argument sanitization, a per-tool blocked-flag denylist (e.g. `sqlmap --os-shell`, `nmap -iL`, file-list and target-injection flags), target and network policy, rate limiting, output caps, and timeouts. The policy knows enough CLI grammar to tell a target from a header, wordlist, output path, or target-list flag. Tool output reaches the model without terminal escape sequences or LLM control markers, and lines addressed to an AI reader are flagged.
- __Tools run in a disposable VM by default.__ The launcher boots a [Kata Containers](docs/SANDBOX.md) VM with its own kernel, no host filesystem beyond an optional `CYBERSEC_SANDBOX_WORKSPACE` mount, no Docker socket, a non-root user with every capability dropped, and memory, CPU, and process limits. It is destroyed when the client disconnects. Startup fails closed instead of falling back to the host; `--local` is the explicit opt-out.
- __Know the limits.__ The VM is not a network boundary: it reaches whatever its Docker network reaches, and `CYBERSEC_MCP_ALLOW_EXTERNAL` is a preflight check on resolved addresses, not a firewall (set `CYBERSEC_SANDBOX_NETWORK=none` or use a filtered network). Inside the VM, and on your host in `--local` mode, allowed tools run with the server user's permissions, and some of them spawn child processes or load plugins.
- __Audit trail without leaks.__ Actions are logged as JSON lines to an owner-only (`0600`), rotating log under the user's state directory (`~/.local/state/cybersec-tools-mcp/audit.log` by default). Script bodies are never stored, only their SHA256 and length, and credential-shaped strings are redacted from tool arguments. A sandboxed server mirrors its records to the same host log, and records are hash-chained, so an edited or deleted entry shows up in `make audit-verify`.
- __Least privilege in the installer.__ It runs as root but drops to the invoking user (`$SUDO_USER`) for cloned-repo builds and `pip`/`cargo`/`gem` installs; binary releases are SHA256-verified when checksums are published.
- __Dual-use tooling is gated.__ C2 and phishing frameworks (Sliver, Caldera, gophish, evilginx, …) are __off by default__ and install only with `--include-c2` (the `redteam` and `full` profiles set it); the MCP layer reflects this and never auto-runs them.
- __Authorized use only.__ See [`SECURITY.md`](SECURITY.md), the [supply chain model](#supply-chain-model), and the [disclaimer](#disclaimer).

## Installer

### Requirements

A supported Linux distro (Debian/Ubuntu/Kali/Parrot, Fedora/RHEL, Arch, openSUSE) or Termux. Runtimes (Python, Go, Ruby, Java, Rust, Node.js), dev libraries, pipx, and build tools are installed automatically. The installer does not run on macOS or native Windows; use WSL or [Docker](#docker-and-podman).

- __Docker__ is needed only for `--enable-docker` (C2 frameworks, MobSF, BeEF, BloodHound, TheHive, Cortex). Install it yourself: [Docker Engine docs](https://docs.docker.com/engine/install/).
- __GitHub authentication__ is recommended. The installer downloads ~50 release binaries and makes ~50+ GitHub API calls; unauthenticated requests are limited to 60 per hour, authenticated ones to 5,000. It uses your `gh auth login` session automatically, also under `sudo`. Alternatively, pass a [personal access token](https://github.com/settings/tokens) (no scopes needed) through `sudo`, which otherwise drops it: `sudo --preserve-env=GITHUB_TOKEN ./install.sh`.

### Install

__From the latest release__ (pinned; recommended):

```bash
git clone --depth 1 --branch v1.2.1 https://github.com/26zl/cybersec-toolkit.git && cd cybersec-toolkit && sudo ./install.sh
```

__From `main`__ (newest tools and fixes, including unreleased work):

```bash
git clone https://github.com/26zl/cybersec-toolkit.git && cd cybersec-toolkit && sudo ./install.sh
```

With no flags, the installer covers the standard tools of all 18 modules. C2/phishing tools and Docker images stay opt-in; `--profile full --enable-docker` installs everything the current platform supports. To install a subset:

```bash
sudo ./install.sh --profile ctf                      # CTF tools only
sudo ./install.sh --profile redteam --enable-docker  # Red team + Docker C2
sudo ./install.sh --module web --module recon        # Specific modules
sudo ./install.sh --tool sqlmap --tool nmap          # Individual tools
sudo ./install.sh --dry-run --profile ctf            # Preview without installing
./install.sh --doctor                                # Read-only preflight; no root needed
```

<details>
<summary><strong>All flags</strong></summary>

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
sudo ./install.sh --fast                # Skip checksum verification (see Supply chain model)
sudo ./install.sh --require-checksums   # Fail if a binary release has no checksum file
sudo ./install.sh --production          # Strict checksum preset for release downloads
sudo ./install.sh --upgrade-system      # Upgrade system packages before installing
sudo ./install.sh --list-sessions       # List install sessions and exit
sudo ./install.sh --rollback <id|last>  # Roll back tools installed in a session
sudo ./install.sh --version             # Show installer version and exit
sudo ./install.sh --enable-docker       # Pull Docker images
sudo ./install.sh --include-c2          # Include C2 frameworks (needs --enable-docker)
sudo ./install.sh -j 8                  # 8 parallel install jobs (default: 4)
sudo ./install.sh -v                    # Verbose / debug output
```

`--tool` installs only the named tool, without the full dependency setup. Dry-run time estimates count install entries across methods, so they can exceed the de-duplicated 670+ tool registry.

</details>

<details>
<summary><strong>Why a full install takes 15-45 minutes</strong></summary>

The time goes to I/O-bound work that no scripting language can speed up:

| What takes time | Why |
| --- | --- |
| System packages (apt/dnf) | Downloading and unpacking `.deb`/`.rpm` packages and resolving dependencies |
| Go tools | Downloading modules and compiling each binary |
| pipx (Python) | Creating one isolated venv per tool and downloading wheels |
| Cargo (Rust) crates | Compiling from source |
| Git clones | Cloning each repository |
| Binary releases | Downloading pre-built binaries from GitHub |

`./install.sh --dry-run` prints the live per-method breakdown. pipx, Go, git, and binary installs run in parallel (`-j 4` by default); the system package manager and Cargo run sequentially. To go faster: install a profile or `--module` instead of everything, `--skip-cargo` to avoid Rust compilation, `-j 8` for more parallel jobs, and an [apt-cacher-ng](https://wiki.debian.org/AptCacherNg) proxy for repeated installs.

</details>

### Docker and Podman

The prebuilt image is the installer on Ubuntu, not a sandbox. Its default command is a dry run of the `full` profile:

```bash
docker run --rm ghcr.io/26zl/cybersec-toolkit                                  # preview only
docker run -it --name cybersec --entrypoint bash ghcr.io/26zl/cybersec-toolkit  # keep a container
sudo ./install.sh --profile ctf                                                # inside it; reattach with: docker start -ai cybersec
```

Build it yourself with `docker build -t cybersec-toolkit .`, or run a throwaway install through the bundled Compose file with `docker compose run --rm installer --profile ctf`. On Apple silicon, add `--platform linux/amd64` to `docker build` and `docker run`. Podman works as a drop-in replacement (`podman compose` needs a compose provider). The image grants the `toolkit` user passwordless sudo so the installer can manage packages; treat code inside it as root-capable.

### Termux (Android)

```bash
pkg install git
git clone https://github.com/26zl/cybersec-toolkit.git && cd cybersec-toolkit
./install.sh --profile lightweight
```

### Profiles

| Profile | Modules | Description |
| ------- | ------- | ----------- |
| `full` | All 18 | Complete security toolkit |
| `ctf` | misc, crypto, pwn, reversing, stego, forensics, cracking, web, mobile, blockchain | CTF competitions |
| `redteam` | misc, networking, recon, web, enterprise, pwn, mobile, cracking, cloud, wireless, reversing, crypto | Offensive security |
| `web` | misc, networking, recon, web, llm | Web application testing |
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

### Modules

| Module | Tools | Description |
| ------ | ----- | ----------- |
| `misc` | 40 | Post-exploitation, social engineering, wordlists, resources, C2 (Docker + Loki) |
| `networking` | 57 | Port scanning, packet capture, tunneling, MITM, protocol tools |
| `recon` | 82 | Subdomain enumeration, OSINT, DNS, automated recon frameworks |
| `web` | 60 | Vulnerability scanning, fuzzing, SQLi, XSS, CMS scanners, API testing |
| `crypto` | 15 | RSA attacks, cipher analysis, hash attacks, constraint solving |
| `pwn` | 36 | Exploit frameworks, binary exploitation, fuzzing, payload generation |
| `reversing` | 33 | Disassemblers, debuggers, emulation, Java/Python reversing |
| `forensics` | 57 | Disk/memory forensics, file carving, timeline analysis, log analysis, hardware/serial |
| `enterprise` | 80 | Active Directory, Kerberos, Azure AD, credential harvesting, lateral movement |
| `wireless` | 41 | WiFi cracking, Bluetooth, SDR, rogue AP |
| `cracking` | 34 | Hash cracking (john, hashcat), brute force, wordlist generation |
| `stego` | 15 | Image/audio steganography, detection, StegCracker |
| `cloud` | 22 | AWS/Azure/GCP security auditing, Checkov |
| `containers` | 15 | Docker/Kubernetes security (Grype, Syft, Kubescape, kubeaudit) |
| `blueteam` | 36 | IDS/IPS, SIEM, incident response, threat intelligence, hardening, malware analysis (YARA, ClamAV, FLOSS, Capa, Loki) |
| `mobile` | 18 | Android/iOS app testing, APK analysis, MobSF (Docker) |
| `blockchain` | 15 | Smart contract auditing (Slither, Mythril, Foundry, Aderyn), blockchain forensics, Echidna (Docker) |
| `llm` | 14 | LLM red teaming, prompt injection, jailbreak testing, AI vulnerability scanning |

<details>
<summary><strong>Install methods</strong> — preferred order: apt &gt; pipx &gt; go &gt; cargo &gt; binary &gt; gem &gt; Docker &gt; git clone &gt; source</summary>

| Method | Count | Examples |
| ------ | ----- | ------- |
| Git clone | 193 | GitHub repos with auto-setup, resources, wordlists |
| System packages (apt/dnf/pacman/zypper) | 166 | nmap, wireshark, john, hashcat |
| pipx | 137 | sqlmap, impacket, bloodhound, volatility3 |
| Go install | 62 | nuclei, subfinder, ffuf, httpx |
| Binary release | 51 | gitleaks, chainsaw, findomain, FLOSS, Capa, Loki, Syft, Kubescape |
| Build from source | 23 | massdns, duplicut, AFLplusplus, honggfuzz |
| Docker | 13 | Empire, MobSF, BeEF, BloodHound, TheHive, Cortex, PentAGI |
| Cargo (Rust) | 8 | feroxbuster, RustScan, pwninit, yara-x-cli |
| Ruby gem | 6 | wpscan, evil-winrm, brakeman |
| npm | 5 | promptfoo, apk-mitm, surya, solgraph |
| Special | 5 | Metasploit, Foundry, Steampipe, patator (curl-pipe installers), crypto venv bootstrap |
| Snap | 1 | zaproxy |

</details>

### Post-install scripts

All scripts support `--help` and need root on Linux (`sudo`); Termux needs no root.

| Script | Purpose | Example |
| ------ | ------- | ------- |
| `scripts/verify.sh` | Check which tools are installed | `sudo ./scripts/verify.sh --module web --skip-heavy` |
| `scripts/update.sh` | Update all installed tools | `sudo ./scripts/update.sh --skip-system` |
| `scripts/remove.sh` | Remove tools by module | `sudo ./scripts/remove.sh --module enterprise --yes` |
| `scripts/remove.sh --deep-clean` | Purge caches and build artifacts | `sudo ./scripts/remove.sh --deep-clean --yes` |
| `scripts/backup.sh` | Back up and restore tool configs | `sudo ./scripts/backup.sh backup` |

`--deep-clean` removes the Go module/build cache, the Cargo registry, pip/pipx/npm/gem caches, orphaned pipx venvs, stale symlinks, and log files. Add `--remove-deps` to also purge Rustup toolchains.

<details>
<summary><strong>Tool locations</strong></summary>

Non-system tools land in `/usr/local/bin/` on Linux and `$PREFIX/bin` on Termux; system packages use their default location (`/usr/bin/`).

| Method | Binary location (Linux) | Binary location (Termux) | Data location |
| ------ | ----------------------- | ------------------------ | ------------- |
| pipx | `/usr/local/bin/` | `$PREFIX/bin/` | `/opt/pipx/` or `~/.local/pipx/` |
| Go | `/usr/local/bin/` | `$PREFIX/bin/` | `/opt/go/` or `~/.go/` |
| Cargo | `/usr/local/bin/` (symlinked) | `$PREFIX/bin/` (symlinked) | `~/.cargo/` |
| Git repos | `/usr/local/bin/` (symlinked) | `$PREFIX/bin/` (symlinked) | `/opt/<repo>/` or `~/tools/<repo>/` |
| Binary releases | `/usr/local/bin/` | Skipped (glibc incompatible with Bionic) | -- |

The `.versions` file records what was installed, how, and when.

</details>

<details>
<summary><strong>Optional Docker images</strong> (<code>--enable-docker</code>)</summary>

If `--enable-docker` is set and Docker is missing, the installer stops and asks you to install Docker first.

| Image | Module | Flag | Description |
| ----- | ------ | ---- | ----------- |
| `bcsecurity/empire` | misc | `--enable-docker --include-c2` | Empire C2 |
| `spiderfoot/spiderfoot` | misc | `--enable-docker` | SpiderFoot OSINT |
| `beefproject/beef` | web | `--enable-docker` | BeEF browser exploitation |
| `opensecurity/mobile-security-framework-mobsf` | mobile | `--enable-docker` | MobSF |
| `specterops/bloodhound` | enterprise | `--enable-docker` | BloodHound CE |
| `trailofbits/echidna` | blockchain | `--enable-docker` | Echidna smart contract fuzzer |
| `checkmarx/kics:latest` | cloud | `--enable-docker` | KICS infrastructure-as-code scanner |
| `sagemath/sagemath:latest` | crypto | `--enable-docker` | SageMath (Coppersmith, Groebner bases, curve arithmetic) |
| `strangebee/thehive:latest` | blueteam | `--enable-docker` | TheHive IR platform |
| `thehiveproject/cortex:latest` | blueteam | `--enable-docker` | Cortex analysis |
| `zeek/zeek:latest` | blueteam | `--enable-docker` | Zeek network analysis |
| `wagga40/zircolite:latest` | blueteam | `--enable-docker` | Zircolite EVTX detection |
| `vxcontrol/pentagi:latest` | llm | `--enable-docker` | PentAGI autonomous pentesting |

</details>

### Distro support

__Debian/Ubuntu/Kali is the primary target__: the full 670+ registry is available there, and it has the strongest test coverage. Fedora, Arch, and openSUSE auto-skip ~10-20 distro-specific packages and run in the integration workflow.

| Platform | Status |
| -------- | ------ |
| __WSL__ | Supported for installs and MCP use; the wireless module and kernel-level packages are skipped. No dedicated CI job, so validate release-critical changes in a local WSL distro. See [Windows Defender false positives](#windows-defender-false-positives) if the repo lives on a Windows-mounted path. |
| __ARM__ (aarch64/armv7) | Supported, with automatic skips for x86-only binary releases and build-from-source tools. No dedicated CI job. |
| __Termux__ (Android) | Supported without sudo. Docker, snap, binary releases, and build-from-source are skipped (Bionic incompatible). No dedicated CI job. |
| __Windows__ (native) | Not supported. Use WSL. |
| __macOS__ | The installer is not supported; use the Docker image. The MCP server runs on macOS in host mode (`--local`). |
| __Other Linux distros__ | Distros without `apt`/`dnf`/`pacman`/`zypper` (NixOS, Gentoo, Void, Alpine, Slackware, …) are detected and blocked with a clear error. Use the [Docker image](#docker-and-podman). |

### Supply chain model

The installer downloads and runs code from the internet. On Linux it runs as root (`sudo`); on Termux it runs in the app's user sandbox.

- __System packages__: signed by your distro's repositories (apt, dnf, pacman, zypper, pkg).
- __pipx/Go/Cargo/Gem/npm__: fetched from their registries without signature verification; pipx tools are isolated in venvs.
- __Binary releases__: SHA256-verified when the release publishes a checksum file, with a hard failure on mismatch. About half of the upstream releases publish none; `--require-checksums` or the `--production` preset fails those tools instead of installing them unverified. `--fast` disables all checksum verification, including for releases that publish checksums, and cannot be combined with the strict flags; keep it out of CI and production.
- __Runtime bootstraps__: the rustup, uv, and cargo-binstall installers and NodeSource's setup script (run as root) are fetched over HTTPS and sanity-checked before they run, but not signature-verified. cargo-binstall then downloads prebuilt Rust binaries where available; `--skip-source` skips its installer on a fresh host, so Rust tools compile from crates.io.
- __Go SDK__: SHA256-verified against go.dev when the API is reachable; strict mode fails if it is not.
- __Git repos__: cloned at HEAD; dependencies go into isolated venvs, and `setup.py` is not executed.
- __Build from source__: runs `make`, as root on Linux. Review what you build.
- __MCP Python dependencies__: resolved by `uv` with a 3-day `exclude-newer` window, and Dependabot waits the same 3 days. This does not apply to the security tools themselves, which follow their upstream release channels.
- __Toolkit Docker images__: Ubuntu and uv are digest-pinned; apt packages resolve from the current signed Ubuntu repositories, so rebuilds are not bit-for-bit reproducible.
- __Optional tool images__: pulled by mutable tags, several of them `latest`. `--production` does not pin or verify them.

`--production` does not pin Git clones, language-package registries, or build-from-source tools; those track their upstream release channels.

### Windows Defender false positives

On a Windows-mounted path (e.g. `C:\Users\<you>\...`, or any folder visible from Windows while you work in WSL), Microsoft Defender and other AV products may quarantine individual files. IOC tables, sample obfuscated PowerShell, malware-analysis snippets, and exploit strings in `.claude/skills/`, `writeups/`, and parts of `mcp_server/` contain the same byte patterns real attackers use. Common verdicts include `Trojan:Script/Wacatac.B!ml`, `HackTool:*`, and generic `Heur.*`. These are false positives for a security toolkit.

<details>
<summary><strong>Workarounds</strong></summary>

1. __Exclude the repo folder__ (recommended on a personal dev box), from an elevated PowerShell:

   ```powershell
   Add-MpPreference -ExclusionPath "C:\path\to\cybersec-toolkit"
   ```

2. __Restore files from quarantine__ via Windows Security → Virus & threat protection → Protection history → "Allow on device". This is per file and does not prevent re-detection.
3. __Keep the repo inside the WSL filesystem__ (e.g. `~/cybersec-toolkit`). Defender does not scan WSL2's virtual disk by default. `scripts/sync-wsl.sh` does this for the MCP server.

Files removed by Defender show up as `D` in `git status`; restore them with `git checkout -- <path>` once the exclusion is in place.

</details>

## MCP server

The server gives MCP-capable clients read access to the 670+ tool registry, install status and recommendations, and governed execution of installed tools. The agent knows every tool, which ones are available, and how to chain them.

### Supported clients

| Client | Integration | Status |
| ------ | ----------- | ------ |
| Claude Code | `.mcp.json` (tracked) + `.claude/skills/` | Native configuration included |
| Claude Desktop | `claude_desktop_config.json` | Configuration example documented |
| OpenCode | `opencode.jsonc` (tracked) + `.agents/skills/` | Live tested |
| Codex | `.codex/config.toml` (tracked) | Native configuration included |
| Gemini CLI | `GEMINI.md` + `.gemini/settings.json` (tracked) | Native configuration included |
| GitHub Copilot | `.mcp.json` (CLI) + `.github/copilot-instructions.md` | CLI live tested; VS Code documented |
| Hermes Agent | User `~/.hermes/config.yaml` | Live tested |
| OpenClaw | User `~/.openclaw/openclaw.json` + `.agents/skills/` | Live tested |
| DeepSeek Harness (dsh) | `$DSH_HOME/settings.yaml` + `.agents/skills/` | Configuration example documented |
| Cursor / Cline / Goose | Client MCP settings + Agent Skills | Compatible through MCP; skills supported |
| Continue | Client MCP settings; rules/prompts for context | Compatible through MCP |
| LM Studio (>=0.3.17) | `mcp.json`; manual or MCP-provided context | Compatible through MCP |
| Ollama | MCP host in front of it | Compatible through an MCP host |
| Open WebUI | MCP-to-OpenAPI bridge | Compatible through an MCP host or bridge |

Per-client setup is in [`docs/AI_CLIENTS.md`](docs/AI_CLIENTS.md); coordinating several agents across any MCP client is in [`docs/ORCHESTRATION.md`](docs/ORCHESTRATION.md).

The server is published to the [official MCP Registry](https://registry.modelcontextprotocol.io/) as `io.github.26zl/cybersec-toolkit` and listed on Glama:

<a href="https://glama.ai/mcp/servers/26zl/cybersec-toolkit"><img width="380" height="200" src="https://glama.ai/mcp/servers/26zl/cybersec-toolkit/badge" alt="Cybersec Toolkit MCP server on Glama" /></a>

### What the AI can do

| Tool | What it does |
| ---- | ------------ |
| `list_tools` | List/filter all 670+ tools by module, method, or install status (includes URLs) |
| `check_installed` | Check if a tool is installed (6 detection strategies) |
| `get_tool_info` | Full details: method, module, URL, install/update/remove commands |
| `get_module_info` | Deep-dive a module: all tools, install status, which profiles use it |
| `get_profile_tools` | See every tool a profile installs, grouped by module |
| `suggest_for_ctf` | Curated tool recommendations for 14 CTF challenge categories |
| `suggest_for_bounty` | Bug bounty tool recommendations for 7 target types with methodology and common vulns |
| `guided_assessment` | Companion-first solve assistant for an authorized target: classifies the target/finding, returns triage gates, recommends skills, picks tools from all modules/profiles, and guides step by step; opt-in `autonomous` starts an auto-solver loop over `run_tool`, `run_pipeline`, and the separately gated `run_script` |
| `get_cve_info` | Map a CVE id or nickname (e.g. `log4shell`) to curated skills, registry tools, modules, and live NVD/KEV/EPSS lookup commands |
| `recommend_install` | Natural-language → profile/module/tool recommendation |
| `list_profiles` | All 14 profiles with tool counts and install commands |
| `run_tool` | Execute installed tools safely (sanitized args, network policy, rate limiting, audit logging); supports remote execution over SSH |
| `run_pipeline` | Pipe tools together without a shell (`strings binary \| grep flag`) |
| `run_script` | Explicit opt-in Python/Bash execution, with per-script venv selection |
| `manage_remote_hosts` | Add, remove, list, and test SSH remote hosts for remote tool execution |

<details>
<summary><strong>Usage examples — full workflows, offense to defense</strong></summary>

The agent can query every tool and its install state, chain governed tool calls, parse the output, and pivot on what it finds. Script execution requires a separate opt-in.

#### External recon → attack surface (needs `CYBERSEC_MCP_ALLOW_EXTERNAL=1`, authorized scope only)

- __"Enumerate the attack surface for target.com and flag anything exploitable"__ — fans out `amass` / `subfinder` → resolves and probes with `httpx` → fingerprints with `whatweb` → runs `nuclei` templates → content discovery with `ffuf`, then ranks hosts by exposure and proposes next steps
- __"Found an open redirect on `/go?url=` — weaponize it"__ — verifies with `curl`, then builds an SSRF / OAuth-token-theft PoC and probes for an exploitable callback

#### Web exploitation

- __"Confirm and exploit the SQLi on the login endpoint"__ — `sqlmap` to confirm and dump (destructive `--os-shell`/`--os-cmd` are policy-blocked), then `run_script` to automate the auth bypass and pull just enough for a PoC
- __"GraphQL introspection is on — map it and hunt IDOR"__ — pulls the schema, generates queries, fuzzes object IDs, and diffs authenticated vs unauthenticated responses

#### Active Directory / internal

- __"Low-priv creds on 10.10.0.0/24 — find a path to Domain Admin"__ — collects with `bloodhound`, kerberoasts with `impacket` (`GetUserSPNs.py`), cracks the TGS in `hashcat`, then validates lateral movement with `netexec`, all on a Kali box over SSH (`manage_remote_hosts`, host mode)
- __"Check for DCSync rights and dump if the path exists"__ — enumerates replication ACLs, then runs `secretsdump.py` against the DC

#### Binary exploitation & reversing

- __"Build a ret2libc exploit for this 64-bit binary"__ — triages with `checksec` / `readelf`, finds gadgets with `ROPgadget`, leaks libc via a `puts@plt` call, then writes the full `pwntools` chain in `venv="pwntools"` and pops a shell locally
- __"Recover the algorithm from this stripped binary"__ — `objdump` / `radare2` disassembly piped into targeted analysis, then a `run_script` reimplementation to verify behavior

#### Crypto

- __"Break this RSA — small `e`, several ciphertexts"__ — detects the attack (Håstad / common modulus / Wiener) and solves it with `pycryptodome` + `sympy` in a venv, returning plaintext
- __"This JWT is HS256 with a weak key"__ — cracks the signing secret and forges an admin token

#### Blue team · detection engineering

- __"Write a Sigma rule for this technique and convert it to my SIEM"__ — authors the rule and renders it for the target backend (Splunk / Elastic) via `sigma-cli`
- __"Hunt these Windows event logs for lateral movement"__ — runs `chainsaw` over the EVTX with Sigma rules, then summarizes hits by host and timeline
- __"Build YARA rules from these samples and scan the tree"__ — generates `yara` signatures and runs them recursively

#### DFIR · malware triage

- __"Timeline this memory dump"__ — sweeps `volatility3` plugins (`pslist`, `netscan`, `malfind`) and chains them into one narrative
- __"Hunt for C2 beaconing in this pcap"__ — `tshark` / `tcpdump` extraction → `suricata` rules → flags periodic callbacks
- __"Statically triage this suspicious file"__ — `file` → `strings` → `capa` / `yara`, then extracts IOCs for enrichment

#### Cloud · containers · ops

- __"Audit this AWS account for public S3 and risky IAM"__ — runs `prowler` / `scoutsuite` and surfaces only the high-severity findings
- __"Scan this image and k8s manifests before deploy"__ — `grype` image scan plus `kubescape` config checks
- __"What's my redteam coverage — and fix the gaps"__ — diffs `get_profile_tools("redteam")` against install status and emits the exact install commands

#### Mobile · wireless · blockchain

- __"Static-analyze this APK for secrets and insecure storage"__ — `apktool` / `jadx` decompile → MobSF-style checks, then greps for keys and endpoints
- __"Audit this Wi-Fi capture"__ — parses the handshake and runs `aircrack-ng` / `hashcat` against it
- __"Review this Solidity contract for reentrancy"__ — runs `slither` / `mythril` and explains the findings

`run_tool` and `run_pipeline` are argument-sanitized, network-policed, rate-limited, and audit-logged, and destructive flags (`--os-shell`, `-rf`, `--exploit`, …) are blocked. `run_script` is off by default: enabling it runs arbitrary code with the server user's filesystem and network permissions (inside the VM by default, on your host with `--local`), and the external-target policy does not constrain it. Use only against systems you are authorized to test.

</details>

### Sandbox and host mode

`scripts/mcp-launch.sh` starts the server inside a Kata Containers VM unless you pass `--local` or set `CYBERSEC_SANDBOX_MODE=local`. The VM is created by a [Sandcastle](https://github.com/mattpocock/sandcastle) isolated-sandbox provider (`sandbox/kata.mjs`) that pins the Kata runtime; the same provider can also back a Sandcastle agent-orchestration loop instead of an MCP client. Startup fails closed: a missing runtime, sandbox image, KVM device, Node.js, or launcher dependency stops the server with the reason instead of falling back to the host. `./install.sh --doctor` reports sandbox readiness. Setup, tuning, and the threat model are in [`docs/SANDBOX.md`](docs/SANDBOX.md).

- __The VM has its own tool set.__ The sandbox image ships the MCP server plus `file`, `git`, `binutils`, `nmap`, `curl`, and Python. Tools installed on the host are not visible inside it, and `check_installed` and the advisors report the guest's tools. Bake a profile into the image instead, and rebuild after pulling server changes, because the image carries its own copy of the server:

  ```bash
  docker build -f sandbox/Dockerfile --build-arg TOOLKIT_PROFILE=ctf -t cybersec-toolkit-sandbox:latest .
  ```

- __Files__: the VM sees no host path unless `CYBERSEC_SANDBOX_WORKSPACE` names an absolute directory, which appears as `/workspace` (read-only with `CYBERSEC_SANDBOX_WORKSPACE_RO=1`). Pass guest paths to `run_tool`.
- __Network__: the VM uses Docker's default bridge. Set `CYBERSEC_SANDBOX_NETWORK=none` for offline analysis, or a filtered Docker network to scope egress.
- __Privileges__: uid 10001, all capabilities dropped, `no-new-privileges`, and 2 GB / 2 vCPUs / 512 processes by default. Raw-socket scans (`nmap -sS`, `-sU`, OS detection) need `CYBERSEC_SANDBOX_CAP_ADD=NET_RAW`.
- __Host mode only__: remote execution over SSH (`manage_remote_hosts`) and venvs under `~/.ctf-venvs/` that you created on the host.
- __Audit__: records leave the VM on a stderr side channel and are appended to the host log, so the trail outlives the VM.

### Client setup

Claude Code reads the tracked `.mcp.json`:

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "bash",
      "args": [
        "-lc",
        "cd \"$(git rev-parse --show-toplevel)\" && exec bash scripts/mcp-launch.sh"
      ],
      "env": {
        "CYBERSEC_MCP_ALLOW_EXTERNAL": "0",
        "CYBERSEC_MCP_ALLOW_SCRIPTS": "0"
      }
    }
  }
}
```

The login shell (`bash -lc`) picks up `node` and `uv` from your profile, so profile scripts must not print to stdout, which carries the MCP protocol. Other clients use the same launcher; from any directory:

```bash
bash /path/to/cybersec-toolkit/scripts/mcp-launch.sh           # Kata VM (default)
bash /path/to/cybersec-toolkit/scripts/mcp-launch.sh --local   # host, no VM boundary
```

- __Codex__: the project `.codex/config.toml` resolves the Git root first, so it works from any subdirectory. If Codex ignores project config, copy the `[mcp_servers.cybersec-tools]` block into `~/.codex/config.toml`.
- __Cursor / Continue / Cline / Goose__: add the launch command in the client's MCP settings, with an absolute path if the client's working directory is not the repo root.
- __LM Studio (≥0.3.17)__: an MCP host itself. Add the server to its `mcp.json` (same `mcpServers` shape as `.mcp.json`) with an absolute path. MCP over LM Studio's API needs ≥0.4.0 and an MCP-capable endpoint such as `/api/v1/chat` or `/v1/responses`.
- __Ollama and other local models__: a model runtime does not speak MCP. Put an MCP-capable host in front of it (OpenCode, Hermes, OpenClaw, [Kit](https://github.com/mark3labs/kit), LM Studio, Cline, Continue, Goose, or Open WebUI through an MCP→OpenAPI bridge such as `mcpo`) and point that host at the launcher.

Start with this one server and keep scripts and external targets off unless you have an authorized scope; prefer hosts with human-in-the-loop tool approval. Vendor-neutral repository instructions live in [`AGENTS.md`](AGENTS.md); Claude Code reads [`CLAUDE.md`](CLAUDE.md), Gemini CLI reads [`GEMINI.md`](GEMINI.md).

<details>
<summary><strong>Connect from WSL (e.g. Kali Linux)</strong></summary>

The server speaks stdio, so a Windows client can launch it inside WSL. This runs it directly in WSL, without the Kata VM (the equivalent of `--local`):

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "wsl",
      "args": [
        "-d", "kali-linux",
        "bash", "-lc",
        "cd ~/cybersec-toolkit/mcp_server && uv run fastmcp run server.py --transport stdio --no-banner"
      ]
    }
  }
}
```

Use a clone inside the WSL filesystem, or run `scripts/sync-wsl.sh` from a Windows checkout to copy the server to `~/cybersec-toolkit` in WSL (uv cannot create a venv on NTFS). Passing `CYBERSEC_MCP_*` variables from Windows needs `WSLENV`; see [`mcp_server/README.md`](mcp_server/README.md).

</details>

<details>
<summary><strong>Connect from Docker</strong></summary>

Runs the server in the installer image. This is an ordinary container, not the Kata VM, and its user has passwordless sudo:

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "CYBERSEC_MCP_ALLOW_EXTERNAL=0", "-e", "CYBERSEC_MCP_ALLOW_SCRIPTS=0",
        "--entrypoint", "bash", "cybersec-toolkit",
        "-c",
        "cd /opt/cybersec-toolkit/mcp_server && uv run fastmcp run server.py --transport stdio --no-banner"
      ]
    }
  }
}
```

</details>

### Script execution

`run_script` lets the agent write and run Python or Bash. Enable it with `"CYBERSEC_MCP_ALLOW_SCRIPTS": "1"` in the client's `env` block. Scripts get the server process's filesystem and network permissions (the VM by default, your user in `--local` mode), and `CYBERSEC_MCP_ALLOW_EXTERNAL` does not constrain them. Review generated code and scope before opting in.

Python libraries without console scripts live in named venvs under `~/.ctf-venvs/` (override with `CYBERSEC_MCP_VENVS_DIR`), selected per script with the `venv` parameter. `./install.sh --module crypto` creates `~/.ctf-venvs/crypto` with `pycryptodome`, `sympy`, `gmpy2`, `numpy`, `z3`, `fpylll` (+ `cysignals`, which fpylll needs at import time but does not declare), and `cypari2`, so the agent can call `run_script(code, venv="crypto")`. In the sandbox, venvs are guest paths: build the image with `TOOLKIT_PROFILE=ctf` to get `crypto`. Some packages need an older Python, for example pwntools:

```bash
python3.12 -m venv ~/.ctf-venvs/pwntools
~/.ctf-venvs/pwntools/bin/pip install pwntools z3-solver
```

Without a named venv, scripts see FastMCP and the standard library; `cd mcp_server && uv sync --extra ctf-core` adds `requests`, `pycryptodome`, `beautifulsoup4`, Pillow, and NumPy.

Reusable helpers the agent writes for you (exploits, multi-step solvers, parsers, protocol helpers) are saved under `manual_scripts/`. In companion mode the agent proposes a script and runs it only after you approve; in `autonomous` mode it writes and runs scoped helpers when tools and pipelines stop making progress. Plain recon and HTTP requests stay `run_tool` calls.

### Test the server

```bash
cd mcp_server && uv run fastmcp dev server.py
```

This opens the MCP Inspector for exercising each tool interactively. [`mcp_server/README.md`](mcp_server/README.md) covers Claude Desktop setup and the full server reference.

## Agent Skills

872 Agent Skills live in `.claude/skills/`, the canonical tree that Claude Code discovers directly. Skills load on demand for the task at hand instead of occupying context permanently. 31 are project-authored and 841 are curated from open-source projects, each attributed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md):

- 10 project developer skills (`add-tool`, `validate-all`, `module-scaffold`, `writeup-template`, `mcp-sync-check`, `security-wordlists`, `security-payloads`, `guided-assessment`, `skill-dependency-audit`, `skill-curation-router`)
- 4 cross-skill coordinators (`finding-triage`, `security-comms`, `authorization-gate`, `evidence-hygiene`) that route findings, communication, authorization checks, and evidence sanitization
- 7 coverage-gap anchors (GRC/privacy, AI/LLM security, IoT/embedded/hardware, mainframe, telecom/5G, SAP/ERP, supply-chain/product security)
- 6 CTF methodology skills (`ctf-crypto`, `ctf-pwn`, `ctf-web`, `ctf-rev`, `ctf-forensics`, `ctf-stego`) and 4 bug bounty methodology skills (`bounty-recon`, `bounty-web`, `bounty-api`, `bounty-mobile`)
- 754 operational how-tos from [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (Apache 2.0)
- 58 offensive methodology skills from [SnailSploit Claude-Red](https://github.com/SnailSploit/Claude-Red) (MIT)
- 14 code audit skills from [Trail of Bits](https://github.com/trailofbits/skills) (CC-BY-SA 4.0)
- 10 bug bounty workflow skills from [BugHunter (claude-bug-bounty)](https://github.com/shuvonsec/claude-bug-bounty) (MIT)
- 4 high-level workflows from [Transilience](https://github.com/transilienceai/communitytools) (MIT)
- 1 coding-agent workflow skill from [multica-ai/andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills) (MIT)

Source and category index: [`.claude/skills/SKILLS.md`](.claude/skills/SKILLS.md). Ranking and curation: `.claude/skills/CURATION.md` and `curation.json`, regenerated with `python3 scripts/curate_claude_skills.py --write`.

__As a Claude Code plugin.__ The repo doubles as a [plugin marketplace](https://docs.claude.com/en/docs/claude-code/plugins), so any project can pull in the skill library without cloning:

```text
/plugin marketplace add 26zl/cybersec-toolkit
/plugin install cybersec-toolkit@cybersec-toolkit
```

The plugin carries the skills only; the MCP server is configured separately (see [MCP server](#mcp-server)).

__In other clients.__ OpenCode, Codex, Gemini CLI, GitHub Copilot, Cursor, Cline, Goose, Hermes, and OpenClaw support Agent Skills through their own paths. `scripts/sync-skills.sh` mirrors `.claude/skills/` into the git-ignored `.agents/skills/` for clients that read that location (`--check` reports drift; `make setup` runs it). Continue and LM Studio do not document automatic skill discovery; give them selected skill content as rules or context instead. Details: [`docs/AI_CLIENTS.md`](docs/AI_CLIENTS.md).

__Helper-script dependencies.__ Some vendored skills include helper scripts with optional Python imports, declared in [`.claude/skills/requirements.txt`](.claude/skills/requirements.txt) and generated from the import inventory. `scripts/validate_claude_skills.py` checks skill metadata, index counts, curation freshness, and helper-script syntax.

```bash
python3 scripts/audit_skill_dependencies.py --check-declared   # verify declarations
python3 -m pip install -r .claude/skills/requirements.txt      # optional, ideally in a venv
```

## Development

Contributions are welcome: testing installs on different distros, adding missing tools, fixing package mappings, improving MCP workflows, writing example use cases, and reporting rough edges from real CTF, lab, bug bounty, pentest, DFIR, or defensive work. Open an issue for bigger changes or send a focused PR for small fixes; [`CONTRIBUTING.md`](CONTRIBUTING.md) has the validation checklist.

```bash
git clone https://github.com/26zl/cybersec-toolkit.git && cd cybersec-toolkit
make setup    # submodules, MCP deps, sandbox deps, skill mirror
make check    # lint, validators, bats, pytest, sandbox tests
```

`make help` lists every target; the raw commands are in [`AGENTS.md`](AGENTS.md). The MCP Python project resolves dependencies with `uv` and `exclude-newer = "3 days"`, so fresh releases are ignored for 72 hours to limit the blast radius of a compromised upload; Dependabot and the weekly uv update workflow use the same cooldown. Run the shell tests on Linux, macOS, or WSL: native Windows checkouts can rewrite the Bats submodules with CRLF and fail with `$'\r'`.

## Star History

<a href="https://www.star-history.com/?repos=26zl%2Fcybersec-toolkit&type=date&legend=top-left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=26zl/cybersec-toolkit&type=date&theme=dark&legend=top-left" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=26zl/cybersec-toolkit&type=date&legend=top-left" />
    <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=26zl/cybersec-toolkit&type=date&legend=top-left" />
  </picture>
</a>

## License

MIT License. See [LICENSE](LICENSE).

The repository also redistributes third-party components under their own terms, including some under CC-BY-SA-4.0 (ShareAlike, not relicensable to MIT). If you redistribute or adapt bundled content, follow those terms; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

Contribution workflow: [`CONTRIBUTING.md`](CONTRIBUTING.md). Community expectations: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Vulnerability reporting: [`SECURITY.md`](SECURITY.md).

## Disclaimer

This project is provided for educational, defensive, and explicitly authorized
security testing only. Use it only on systems you own or have written permission
to assess, and follow all applicable laws, rules of engagement, third-party tool
licenses, and service terms.

The toolkit includes dual-use offensive and defensive tools. Some commands can
scan networks, execute exploits, modify systems, or trigger security alerts.
MCP/AI integrations are guarded by safety policies, but users remain responsible
for reviewing scope, prompts, commands, and outputs before running actions.

This repository does not redistribute the security tools themselves; it installs
publicly available, open-source projects from their official upstream sources at
install time. It is intended for lawful, authorized use only.

The project is provided "as is", without warranty. Maintainers are not
responsible for misuse, damage, data loss, service disruption, or legal
consequences from using this toolkit.

Third-party content is bundled under its original license — see
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
