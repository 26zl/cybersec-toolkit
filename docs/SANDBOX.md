# Sandboxed Execution

The MCP server runs inside a Kata Containers VM by default. Security tools
therefore execute behind a hardware-virtualized boundary instead of as the host
user, which is what makes the toolkit usable on machines that also hold data
unrelated to the engagement.

```text
Sandcastle            agent orchestration (optional layer)
  └─ Kata Container   strong execution isolation (own kernel, own VM)
       └─ cybersec-toolkit MCP
            └─ nmap / nuclei / semgrep / binwalk / ...
```

`scripts/mcp-launch.sh` is the entry point for every client. It starts
`sandbox/mcp.mjs`, which creates the VM through the Kata sandbox provider in
`sandbox/kata.mjs` and wires the client's stdio to the MCP server inside it.
The VM is destroyed when the client disconnects.

## Threat model

What the boundary is for:

- A tool that parses a hostile sample (PCAP, firmware, APK, PDF) gets its own
  kernel. A parser bug or an exploit in the sample lands in a disposable VM.
- `run_script`, when enabled, executes inside the VM rather than against the
  operator's filesystem, SSH keys, cloud credentials, and browser profiles.
- Nothing from the host is visible unless it is mounted explicitly
  (`CYBERSEC_SANDBOX_WORKSPACE`). There is no Docker socket and no home
  directory inside the VM.

What it is not:

- Not a network boundary. `CYBERSEC_MCP_ALLOW_EXTERNAL=0` stays a preflight
  check on resolved addresses, not a firewall; the VM still reaches whatever
  its Docker network reaches. Set `CYBERSEC_SANDBOX_NETWORK=none` for offline
  analysis work.
- Not an authorization control. Scope and permission to test a target remain
  the operator's responsibility.
- Not a guarantee against every hypervisor escape — it raises the cost of one,
  which namespace containers do not.

## Host prerequisites

| Requirement | Notes |
| ----------- | ----- |
| Linux host | Kata needs KVM. macOS and Windows hosts cannot run it directly; use a Linux host, a VM with nested virtualization, or `--local`. |
| Hardware virtualization | `/dev/kvm` present. In a cloud VM this requires nested virtualization. |
| Docker Engine or Podman | The provider drives whichever CLI is on PATH; set `CYBERSEC_SANDBOX_ENGINE` to pin one. |
| Kata Containers 4.x (runtime-rs) | Registered as a Docker runtime (see below). The 3.x Go runtime still works with the older `path`-based registration. |
| Node.js 22+ | Runs the launcher and the sandbox provider. |

On a Linux host with native KVM this is the intended path. Nested virtualization
works for Linux-on-Linux (a cloud VM with nesting enabled), but on **Apple silicon
under Virtualization.framework** a nested Linux VM boots the Kata guest kernel yet
does not complete a sandbox: the QEMU runtime's host→guest `AF_VSOCK` handshake to
the agent times out, and the dragonball runtime hits a `virtio-mmio` region conflict.
These are limitations of that nesting layer, not of Kata. On macOS, prefer `--local`
(no VM boundary) or a remote Linux host.

## Setup

1. Install Kata Containers (a `kata-static` release tarball unpacks under
   `/opt/kata`) and confirm the host supports KVM:

   ```bash
   ls -l /dev/kvm
   kata-ctl check all   # if the kata-tools package is installed
   ```

2. Register Kata as a Docker runtime in `/etc/docker/daemon.json`. Since 4.0
   the default is `runtime-rs`, a containerd shim v2 — register it with
   `runtimeType` (the shim binary) and select a `runtime-rs` config with
   `ConfigPath`, not the `path` field the deprecated Go runtime used:

   ```json
   {
     "runtimes": {
       "kata": {
         "runtimeType": "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2",
         "options": {
           "ConfigPath": "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml"
         }
       }
     }
   }
   ```

   Then restart Docker, confirm the runtime is registered, and prove it boots a
   VM — the guest kernel must differ from the host's:

   ```bash
   sudo systemctl restart docker
   docker info --format '{{json .Runtimes}}'
   uname -r                                              # host kernel
   docker run --runtime kata --rm ubuntu:24.04 uname -r  # guest kernel
   ```

   Under Podman the runtime comes from `[engine.runtimes]` in
   `containers.conf`, and Podman does not list it back, so name it explicitly
   with `CYBERSEC_SANDBOX_RUNTIME=kata`. Rootless Podman additionally needs the
   image's uid (10001) to fall inside your `/etc/subuid` range.

3. Build the sandbox image from the repository root:

   ```bash
   make sandbox-image
   ```

   The image carries the MCP server plus a minimal tool set. To bake in a full
   profile, pass it as a build argument:

   ```bash
   docker build -f sandbox/Dockerfile --build-arg TOOLKIT_PROFILE=ctf \
       -t cybersec-toolkit-sandbox:latest .
   ```

4. Install the launcher's Node dependencies:

   ```bash
   npm --prefix sandbox ci --ignore-scripts
   ```

## Running

The tracked client configurations (`.mcp.json`, `.codex/config.toml`,
`.gemini/settings.json`, `opencode.jsonc`) all invoke the launcher, so the
sandbox is the default everywhere:

```bash
bash scripts/mcp-launch.sh
```

Startup fails closed. A missing runtime, a missing image, or an unreachable
Docker daemon stops the server with the reason instead of silently running
tools on the host. Pinning a non-Kata runtime is refused for the same reason —
`runc` would be a namespace container sharing the host kernel, which is the
thing this layer exists to avoid. `CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME=1`
accepts that deliberately, for a smoke test on a host without KVM, and every
such session prints a warning.

Host execution is an explicit opt-out — appropriate for developing the toolkit
itself, and for macOS where Kata cannot run:

```bash
bash scripts/mcp-launch.sh --local     # or CYBERSEC_SANDBOX_MODE=local
```

Because the launcher runs under a login shell, exporting
`CYBERSEC_SANDBOX_MODE=local` from a shell profile opts one developer's machine
out without editing any tracked client configuration.

## Configuration

All variables are read by `sandbox/kata.mjs` and may also be passed as options
to `kata()`.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `CYBERSEC_SANDBOX_MODE` | `kata` | `kata` or `local`. Read by the launcher. |
| `CYBERSEC_SANDBOX_IMAGE` | `cybersec-toolkit-sandbox:latest` | Image to boot. |
| `CYBERSEC_SANDBOX_ENGINE` | first of docker, podman on PATH | `docker` or `podman`. |
| `CYBERSEC_SANDBOX_RUNTIME` | auto-detected (docker) | Pin a runtime name. Required under Podman, which does not advertise its configured runtimes. |
| `CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME` | `0` | `1` accepts a non-Kata runtime. Startup refuses one otherwise, and warns loudly when accepted: there is no VM boundary. |
| `CYBERSEC_SANDBOX_NETWORK` | Docker default bridge | `none` for an offline VM, or a named Docker network. |
| `CYBERSEC_SANDBOX_WORKSPACE` | unset | Absolute host directory to mount at `/workspace`. The only host path the VM can see. |
| `CYBERSEC_SANDBOX_WORKSPACE_RO` | `0` | `1` mounts the workspace read-only. |
| `CYBERSEC_SANDBOX_MEMORY` | `2g` | Guest memory. |
| `CYBERSEC_SANDBOX_CPUS` | `2` | Guest vCPUs. |
| `CYBERSEC_SANDBOX_PIDS_LIMIT` | `512` | Process limit inside the guest. |
| `CYBERSEC_SANDBOX_USER` | `10001:10001` | Guest uid:gid; must match the image. |
| `CYBERSEC_SANDBOX_CAP_ADD` | none | Comma-separated capabilities, e.g. `NET_RAW` for `nmap -sS`. |

`CYBERSEC_MCP_ALLOW_EXTERNAL` and `CYBERSEC_MCP_ALLOW_SCRIPTS` are forwarded
into the VM. Host-specific paths such as `CYBERSEC_MCP_AUDIT_LOG` and
`CYBERSEC_MCP_VENVS_DIR` are not: they are baked into the image and must keep
pointing at guest paths. `CYBERSEC_MCP_AUDIT_LOG` still applies on the host, where
it names the file the mirrored records are appended to.

## Working with files

Paths passed to `run_tool` are resolved inside the VM, not on the host. Point
the sandbox at the engagement directory and use guest paths:

```bash
export CYBERSEC_SANDBOX_WORKSPACE=/home/analyst/cases/acme
# a host file at /home/analyst/cases/acme/capture.pcap is /workspace/capture.pcap
```

The mounted directory keeps its host ownership, and the guest process is
uid 10001. Make the directory writable for it — group-write plus a matching
gid, or `CYBERSEC_SANDBOX_USER` set to the owner's uid:gid — or mount it
read-only with `CYBERSEC_SANDBOX_WORKSPACE_RO=1` when the tools only need to
read.

Without a workspace the VM starts with no host filesystem access at all, which
is the right default for reviewing an untrusted sample that the sandbox pulls
in itself. To hand a single file to a running sandbox without mounting
anything, copy it in by label:

```bash
docker cp ./sample.pcap \
    "$(docker ps -q --filter label=cybersec-toolkit.sandbox=kata)":/workspace/
```

The provider exposes the same thing programmatically as `copyIn()` and
`copyFileOut()` on the sandbox handle, which is what Sandcastle's orchestration
path uses.

## Network scope

The VM's reach is the reach of its Docker network, so scope belongs here rather
than in the MCP policy, which only preflights resolved addresses.

```bash
# Fully offline: no interface at all.
CYBERSEC_SANDBOX_NETWORK=none

# No route off the host, but containers on the same network stay reachable.
docker network create --internal cybersec-offline
CYBERSEC_SANDBOX_NETWORK=cybersec-offline

# Scoped egress: give the sandbox its own subnet and filter it on the host.
docker network create --subnet 10.77.0.0/24 cybersec-scope
sudo iptables -I DOCKER-USER -s 10.77.0.0/24 ! -d 203.0.113.0/24 -j DROP
CYBERSEC_SANDBOX_NETWORK=cybersec-scope
```

`DOCKER-USER` is the chain Docker leaves for operator rules, so entries there
survive daemon restarts and container churn. Keep `CYBERSEC_MCP_ALLOW_EXTERNAL=0`
as well: the two controls answer different questions, and only the firewall
actually stops a redirect.

## What the VM contains

The tracked image ships the MCP server plus a minimal tool set (`file`, `git`,
`binutils`, `nmap`, `curl`, Python). Everything else has to be baked in at build
time with `TOOLKIT_PROFILE`, because the guest has no package manager privileges
at runtime:

- `check_installed`, `list_tools`, and the advisors' `missing_tools` block report
  the guest's tool set, not the host's. A tool installed on the host is not
  available to the sandboxed server.
- `run_script` venvs are guest paths. `~/.ctf-venvs/crypto` exists only if the
  image was built with a profile that populates it, so
  `run_script(venv="crypto")` needs `--build-arg TOOLKIT_PROFILE=ctf` or a
  derived image.
- Audit records leave the VM automatically; see [Audit trail](#audit-trail).

## Audit trail

The server's own log lives at `/var/log/cybersec/audit.log` inside the VM and is
destroyed with it, so the guest also mirrors every record to stderr behind the
`@cybersec-audit@` sentinel (`CYBERSEC_MCP_AUDIT_STREAM=1`, set in the image).
`sandbox/mcp.mjs` picks those lines out of the stderr stream and appends them to
the host log — `~/.local/state/cybersec-tools-mcp/audit.log` by default, or
`CYBERSEC_MCP_AUDIT_LOG` — with the same 0600/0700 permissions and 5 MB
rotation the in-VM handler uses. Nothing else crosses the boundary: stdin and
stdout stay on direct file descriptors, and no host path is mounted for this.

Two things depend on that host copy:

- The operator's durable trail. It is the compliance artifact, and it must
  outlive the VM.
- `scripts/agent-guard.sh`, which clears a session only after it sees a real
  `guided_assessment` / `suggest_for_ctf` / `suggest_for_bounty` record in that
  log. Without the mirror the guard either finds nothing and stops enforcing, or
  finds a stale log and blocks every governed tool for the rest of the session.

Set `CYBERSEC_MCP_AUDIT_REQUIRED=1` on the host to refuse to start when the host
log cannot be written, rather than continuing with a warning.

### Tamper evidence

Every record carries `chain` (one id per server process), `seq`, and `prev` —
the SHA256 of the previous record in that chain. Editing or dropping a record
breaks every link after it:

```bash
make audit-verify                                   # default host log
python3 scripts/verify_audit_chain.py path/to.log   # or a specific one
```

The chain survives the trip out of the VM because the host appends the guest's
lines verbatim. Two limits are inherent and worth stating: records written
before this existed are reported as unchained rather than flagged, and because
the chain is unkeyed, someone who can read the log can still append a
well-formed record. It detects modification and deletion, not forgery by a
reader.

## Hardening applied to each VM

`--cap-drop ALL`, `--security-opt no-new-privileges`, a non-root guest user
(`10001:10001`), `--pids-limit`, and memory/CPU caps. The image drops setuid
and setgid bits and ships no `sudo`. The container is created with `--rm` and
labelled `cybersec-toolkit.sandbox=kata`.

Two consequences worth knowing:

- Raw-socket scans (`nmap -sS`, `-sU`, OS detection) need
  `CYBERSEC_SANDBOX_CAP_ADD=NET_RAW`. Without it, connect scans still work.
- The guest filesystem is discarded on teardown. Anything worth keeping must be
  written to `/workspace` or copied out before the client disconnects.

If a launcher is killed with `SIGKILL`, its VM can survive. Sweep by label:

```bash
docker rm --force $(docker ps -aq --filter label=cybersec-toolkit.sandbox=kata)
```

## Sandcastle orchestration

`sandbox/kata.mjs` exports a standard Sandcastle isolated sandbox provider, so
the same VM boundary can back an agent loop instead of an MCP client:

```javascript
import { run } from '@ai-hero/sandcastle';
import { kata } from './sandbox/kata.mjs';

await run({ agent: /* agent provider */, sandbox: kata() });
```

This requires an image that also contains the agent CLI; the tracked
`sandbox/Dockerfile` builds the MCP/tool layer only. It does ship
`sandbox/guest-mcp.json`, the MCP client configuration such an agent would use
to reach the server from inside the VM.

## What the MCP registry publishes

The OCI package in [`server.json`](../server.json) points at
`ghcr.io/26zl/cybersec-toolkit`, the installer image. That image grants its
`toolkit` user passwordless sudo so `install.sh` can manage packages, and it
carries no Kata runtime — a client that launches it from the registry gets a
root-capable container, not the boundary described here. Treat the registry
package as the convenience path, and this document as the isolated one.

## Troubleshooting

| Message | Cause |
| ------- | ----- |
| `No Kata runtime is registered with Docker` | Kata is not installed, or not in `/etc/docker/daemon.json`. Check `docker info --format '{{json .Runtimes}}'`. |
| `Sandbox image '...' not found` | Run `make sandbox-image`. |
| `docker CLI not found on PATH` | Docker Engine is not installed, or the launcher runs with a stripped `PATH`. |
| `failed to connect to the docker API` | The daemon is not running, or the user is not in the `docker` group. |
| `Kata sandbox requires Node.js 22+` | Install Node.js 22 or newer. |
| `Install sandbox dependencies` | Run `npm --prefix sandbox ci --ignore-scripts`. |

Report host readiness at any time with:

```bash
./install.sh --doctor
```
