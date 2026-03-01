# MCP Server for Cybersec Toolkit

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that exposes the 580+ cybersecurity registry to AI assistants. Query installed tools, get CTF recommendations, get profile/install advice, and execute tools — all from Claude Code, Claude Desktop, or any MCP-capable client.

## Tools Provided

| Tool | Description |
| ---- | ----------- |
| `list_tools` | List/filter tools by module, method, or install status (includes URLs) |
| `check_installed` | Check if a specific tool is installed (multi-strategy detection) |
| `get_tool_info` | Detailed info: method, module, URL, install status, install/update/remove commands |
| `get_module_info` | Full module details: all tools, install status, management commands, which profiles use it |
| `get_profile_tools` | List every tool a profile installs, grouped by module with install status |
| `suggest_for_ctf` | Tool suggestions for 13 CTF challenge categories with descriptions |
| `suggest_for_bounty` | Tool suggestions for 6 bug bounty target types with methodology and common vulns |
| `recommend_install` | Recommend a profile, modules, or individual tools based on what you need |
| `list_profiles` | List all 14 installation profiles with tool counts and details |
| `run_tool` | Execute an installed tool safely (argument sanitization + network policy). Supports remote execution via `host` parameter |
| `run_pipeline` | Pipe tools together safely without shell (e.g. `strings binary \| grep flag`). Max 10 steps |
| `run_script` | Write and execute Python/Bash scripts (pwntools, z3, requests, crypto). Optional `venv` parameter for per-script interpreter selection |
| `manage_remote_hosts` | Add, remove, list, and test SSH remote hosts for remote tool execution |

## Setup

### Prerequisites

Install [uv](https://docs.astral.sh/uv/getting-started/installation/):

```bash
# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Claude Code

Add to `.mcp.json` in the project root:

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

Then restart Claude Code. The tools will appear in the `/mcp` command.

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/cybersec-toolkit/mcp_server", "fastmcp", "run", "server.py"]
    }
  }
}
```

Replace `/path/to/cybersec-toolkit` with the actual path.

### Docker

The Dockerfile pre-installs `uv` and resolves MCP dependencies at build time. To connect Claude Code/Desktop to the MCP server inside a container, run the container with stdio passthrough:

```bash
# Build the image
docker build -t cybersec-toolkit .

# Run MCP server inside container (stdio transport)
docker run -i --rm --entrypoint bash cybersec-toolkit \
  -c 'export PATH="$HOME/.local/bin:$PATH" && cd /opt/cybersec-toolkit/mcp_server && uv run fastmcp run server.py'
```

Then point your `.mcp.json` or `claude_desktop_config.json` at the Docker command:

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--entrypoint", "bash", "cybersec-toolkit",
        "-c",
        "export PATH=\"$HOME/.local/bin:$PATH\" && cd /opt/cybersec-toolkit/mcp_server && uv run fastmcp run server.py"
      ]
    }
  }
}
```

This gives the MCP server access to all tools installed in the container. The `check_installed` and `run_tool` endpoints will detect and execute tools from the container's PATH.

### WSL (Windows → Linux)

When running from Windows, the MCP server runs inside WSL. A WSL-local copy is needed because `uv` can't create `.venv` on NTFS.

**First-time setup:**

```bash
# 1. Install uv in WSL
wsl.exe bash -lc "curl -LsSf https://astral.sh/uv/install.sh | sh"

# 2. Clone or sync the repo into WSL
./scripts/sync-wsl.sh              # from Git Bash

# 3. Build the venv
wsl.exe bash -lc "cd ~/cybersec-toolkit/mcp_server && ~/.local/bin/uv sync"

# 4. (Optional) Create pwntools venv for run_script
wsl.exe bash -lc "mkdir -p ~/.ctf-venvs && python3 -m venv ~/.ctf-venvs/pwntools && ~/.ctf-venvs/pwntools/bin/pip install pwntools z3-solver"
```

**MCP config (`.mcp.json` / `claude_desktop_config.json`):**

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "wsl.exe",
      "args": [
        "bash", "-lc",
        "export CYBERSEC_MCP_ALLOW_SCRIPTS=1 CYBERSEC_MCP_ALLOW_EXTERNAL=0 && cd ~/cybersec-toolkit/mcp_server && ~/.local/bin/uv run fastmcp run server.py"
      ],
      "env": {
        "CYBERSEC_MCP_ALLOW_SCRIPTS": "1",
        "CYBERSEC_MCP_ALLOW_EXTERNAL": "0",
        "WSLENV": "CYBERSEC_MCP_ALLOW_SCRIPTS/u:CYBERSEC_MCP_ALLOW_EXTERNAL/u"
      }
    }
  }
}
```

**Key details:**

- Env vars must be set in **both** the `bash -lc` command (`export`) AND the `env` block with `WSLENV` — Windows env vars don't propagate into WSL automatically
- Add `-d <distro>` before `bash` in `args` to target a specific WSL distro (default: user's default)
- Run `./scripts/sync-wsl.sh` after code changes to update the WSL copy
- Pwntools venv must be created directly in WSL (full network access), not through `run_script` (subject to MCP network policy)

**Claude Code vs Claude Desktop:**

| Capability | Claude Code | Claude Desktop |
| --- | --- | --- |
| Read/write files on Windows | Yes (direct filesystem access) | Yes (via MCP: `run_tool`, `run_script`) |
| Run shell commands on Windows | Yes (`Bash` tool) | No (but can run tools via MCP in WSL) |
| Browse/discover files | Yes | Yes (via MCP: `run_tool("ls", "-la /path/")`) |
| Run tools in WSL via MCP | Yes (`run_tool`, `run_pipeline`, `run_script`) | Yes (same MCP tools) |
| Analyze files | Yes (MCP + direct read) | Yes (via MCP — user provides path or Claude uses `ls` to find files) |
| Edit project code | Yes | No |

**IMPORTANT: Claude Desktop HAS filesystem access via MCP tools.** It should NEVER ask users to "upload" or "attach" files. The MCP server runs locally in WSL and can access both WSL files and Windows files (at `/mnt/c/...`).

**Working with files in Claude Desktop (CTF/bug bounty workflow):**

```bash
# User tells Claude Desktop: "analyze /home/user/challenge.pcap"
# Or for Windows files: "analyze /mnt/c/Users/<username>/Downloads/challenge.pcap"

# Claude Desktop can then run:
run_tool("file", "/home/user/challenge.pcap")              # identify file type
run_tool("tshark", "-r /home/user/challenge.pcap -Y http")  # analyze pcap
run_tool("strings", "/home/user/binary")                    # extract strings
run_pipeline([                                               # chain tools
  {"tool": "strings", "args": "/home/user/binary"},
  {"tool": "grep", "args": "-i flag"}
])
run_script("with open('/home/user/data.bin','rb') as f: print(f.read().hex())")
run_tool("ls", "-la /mnt/c/Users/<username>/Downloads/")     # browse Windows files from WSL
```

**Tip:** Create a working directory for challenges (e.g. `~/ctf/`) and tell Claude Desktop the path. It can then use `ls` to discover files and MCP tools to analyze them.

### Custom Project Root

If running from a different directory, set the environment variable:

```bash
export CYBERSEC_INSTALLER_ROOT=/path/to/cybersec-toolkit
```

## Testing

### MCP Inspector

```bash
cd mcp_server
uv run fastmcp dev server.py
```

This opens a web-based inspector for interactively testing each tool.

### Quick Verification

```bash
# Start the server via the CLI entrypoint
cd mcp_server
uv run cybersec-mcp

# Or via fastmcp directly
uv run fastmcp run server.py
```

### Example Queries

Once connected via an MCP client:

- **List all tools**: `list_tools()` — returns 580+ tools with URLs
- **Filter by module**: `list_tools(module="web")` — 51 web app testing tools
- **Filter by method**: `list_tools(method="pipx")` — Python tools installed via pipx
- **Check installed only**: `list_tools(installed_only=true)` — with version info
- **Check a tool**: `check_installed("nmap")` — detailed install status
- **Tool details**: `get_tool_info("sqlmap")` — method, module, URL, install/update/remove commands
- **Full module view**: `get_module_info("web")` — all 51 tools, install status, which profiles include it
- **Profile contents**: `get_profile_tools("ctf")` — all 272 tools grouped by module
- **CTF suggestions**: `suggest_for_ctf("web")` — curated tools with descriptions and install status
- **Bug bounty suggestions**: `suggest_for_bounty("web_app")` — tools, methodology, common vulns, scope warning
- **What to install**: `recommend_install("I want to do CTF competitions")` — recommends ctf profile
- **Just a few tools**: `recommend_install("I need nmap and sqlmap")` — recommends individual modules
- **List profiles**: `list_profiles()` — all 14 profiles with tool counts
- **Run a tool**: `run_tool("nmap", "--version")` — execute with network policy enforcement
- **Run a pipeline**: `run_pipeline([{"tool": "strings", "args": "./binary"}, {"tool": "grep", "args": "flag"}])` — pipe tools together
- **Run a script**: `run_script("from pwn import *; print(cyclic(20))", venv="pwntools")` — write and execute scripts
- **Run remotely**: `run_tool("nmap", "-sV 10.0.0.1", host="kali-vm")` — execute on a remote host via SSH
- **Manage remotes**: `manage_remote_hosts("add", name="kali-vm", hostname="192.168.1.50")` — configure SSH hosts

## Architecture

```text
mcp_server/
  __init__.py          # Package marker
  server.py            # FastMCP server — 13 tool registrations + entry point
  tools_db.py          # ToolsDatabase — loads tools_config.json, checks installs (TTL-cached)
  ctf_advisor.py       # CTF challenge-type → tool mapping with suggestions
  bounty_advisor.py    # Bug bounty target-type → tool mapping with methodology and common vulns
  profiles.py          # Profile recommendation engine — 14 profiles, keyword matching
  security.py          # Execution validation, argument sanitization, network policy, rate limiting,
                       #   script execution with venv support, pipeline execution
  sanitize.py          # Output sanitization — strips LLM markers, XML injection, Unicode evasion
  audit.py             # JSON audit logging with rotation for executions and blocked attempts
  remote.py            # Remote SSH execution — host config, connection testing, input validation
  pyproject.toml       # UV dependency config (fastmcp>=3.0.0,<4.0.0) + CLI entrypoint
  README.md            # This file
manual_scripts/        # Persistent scripts — exploits, solvers, reusable tools
```

## Security

The `run_tool`, `run_pipeline`, and `run_script` endpoints enforce multiple safety measures:

- **Registry check**: Only tools listed in `tools_config.json` (plus ~120 system utilities) can be executed
- **Install check**: Tool must be installed and in PATH
- **Argument sanitization**: Shell injection patterns (`;`, `&`, `|`, `` ` ``, `$(`, `${`) are blocked. `$`, `>`, `<` alone are allowed — no shell is used, and tools need them for regex/awk/XML
- **Destructive flag blocking**: `--delete`, `-rf`, `--exploit` and similar universal flags are rejected
- **Tool-specific flag blocking**: Dangerous per-tool options are blocked — sqlmap `--os-shell`/`--os-cmd`/`--os-pwn`/`--priv-esc`/`--file-read`/`--file-write`/`--file-dest`, nmap `-iL`/`-iR`, masscan `--includefile`, sed `-i` (in-place modification)
- **Network policy**: Network tools can only target private/loopback IPs by default (including single-label hostnames like `google`). Set `CYBERSEC_MCP_ALLOW_EXTERNAL=1` to allow external targets
- **Script execution gate**: `run_script` is disabled by default. Set `CYBERSEC_MCP_ALLOW_SCRIPTS=1` to enable
- **Venv isolation**: `run_script` supports a `venv` parameter to select a specific Python interpreter from `~/.ctf-venvs/` (configurable via `CYBERSEC_MCP_VENVS_DIR`). Invalid venv names return a structured error without executing
- **Pipeline validation**: `run_pipeline` validates all steps (allowlist, args, policy) before executing any. Max 10 steps per pipeline
- **Rate limiting**: Max 10 concurrent executions and 60 per minute (sliding window)
- **Output sanitization**: Strips LLM prompt markers (OpenAI, Llama), Anthropic tool protocol tags, XML injection tags, and known injection prefixes. Unicode NFKC normalization prevents full-width character evasion
- **Audit logging**: All executions (tools, scripts, blocked attempts) are logged to `audit.log` (JSON lines, 5 MB rotation). Script content is logged before execution. Crash-safe — logging failures never interrupt execution
- **Remote host input validation**: Hostname and username fields are validated against safe character patterns to prevent SSH option injection
- **No shell execution**: Uses `asyncio.create_subprocess_exec()` (no `shell=True`)
- **Async DNS**: Network target validation runs in a thread pool to avoid blocking the event loop
- **Timeout**: Configurable 1-300s, process killed on timeout
- **Output limits**: Truncated at 200KB to prevent memory issues

## Environment Variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `CYBERSEC_MCP_ALLOW_SCRIPTS` | `""` (disabled) | Set to `1` to enable `run_script` |
| `CYBERSEC_MCP_ALLOW_EXTERNAL` | `""` (disabled) | Set to `1` to allow network tools to target external IPs |
| `CYBERSEC_MCP_SCRIPT_PYTHON` | `""` (sys.executable) | Static override for Python interpreter used by `run_script` (when no `venv` is set) |
| `CYBERSEC_MCP_VENVS_DIR` | `~/.ctf-venvs` | Directory containing named Python venvs for the `venv` parameter |
| `CYBERSEC_INSTALLER_ROOT` | Auto-detected | Override the project root path |
