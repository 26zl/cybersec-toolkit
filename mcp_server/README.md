# MCP Server for Cybersec Toolkit

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that exposes the 570-tool cybersecurity registry to AI assistants. Query installed tools, get CTF recommendations, get profile/install advice, and execute tools — all from Claude Code, Claude Desktop, or any MCP-capable client.

## Tools Provided

| Tool | Description |
| ---- | ----------- |
| `list_tools` | List/filter tools by module, method, or install status (includes URLs) |
| `check_installed` | Check if a specific tool is installed (multi-strategy detection) |
| `get_tool_info` | Detailed info: method, module, URL, install status, install/update/remove commands |
| `get_module_info` | Full module details: all tools, install status, management commands, which profiles use it |
| `get_profile_tools` | List every tool a profile installs, grouped by module with install status |
| `suggest_for_ctf` | Tool suggestions for 13 CTF challenge categories with descriptions |
| `recommend_install` | Recommend a profile, modules, or individual tools based on what you need |
| `list_profiles` | List all 14 installation profiles with tool counts and details |
| `run_tool` | Execute an installed tool safely (argument sanitization + network policy) |

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
docker run -i --rm cybersec-toolkit \
  bash -c 'export PATH="$HOME/.local/bin:$PATH" && cd /opt/cybersec-toolkit/mcp_server && uv run fastmcp run server.py'
```

Then point your `.mcp.json` or `claude_desktop_config.json` at the Docker command:

```json
{
  "mcpServers": {
    "cybersec-tools": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "cybersec-toolkit",
        "bash", "-c",
        "export PATH=\"$HOME/.local/bin:$PATH\" && cd /opt/cybersec-toolkit/mcp_server && uv run fastmcp run server.py"
      ]
    }
  }
}
```

This gives the MCP server access to all tools installed in the container. The `check_installed` and `run_tool` endpoints will detect and execute tools from the container's PATH.

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

- **List all tools**: `list_tools()` — returns 570 tools with URLs
- **Filter by module**: `list_tools(module="web")` — 49 web app testing tools
- **Filter by method**: `list_tools(method="pipx")` — Python tools installed via pipx
- **Check installed only**: `list_tools(installed_only=true)` — with version info
- **Check a tool**: `check_installed("nmap")` — detailed install status
- **Tool details**: `get_tool_info("sqlmap")` — method, module, URL, install/update/remove commands
- **Full module view**: `get_module_info("web")` — all 49 tools, install status, which profiles include it
- **Profile contents**: `get_profile_tools("ctf")` — all 264 tools grouped by module
- **CTF suggestions**: `suggest_for_ctf("web")` — curated tools with descriptions and install status
- **What to install**: `recommend_install("I want to do CTF competitions")` — recommends ctf profile
- **Just a few tools**: `recommend_install("I need nmap and sqlmap")` — recommends individual modules
- **List profiles**: `list_profiles()` — all 14 profiles with tool counts
- **Run a tool**: `run_tool("nmap", "--version")` — execute with network policy enforcement

## Architecture

```text
mcp_server/
  __init__.py          # Package marker
  server.py            # FastMCP server — 9 tool registrations + entry point
  tools_db.py          # ToolsDatabase — loads tools_config.json, checks installs (TTL-cached)
  ctf_advisor.py       # CTF challenge-type → tool mapping with suggestions
  profiles.py          # Profile recommendation engine — 14 profiles, keyword matching
  security.py          # Execution validation, argument sanitization, network policy
  pyproject.toml       # UV dependency config (fastmcp>=3.0.0,<4.0.0) + CLI entrypoint
  README.md            # This file
```

## Security

The `run_tool` endpoint enforces multiple safety measures:

- **Registry check**: Only tools listed in `tools_config.json` can be executed
- **Install check**: Tool must be installed and in PATH
- **Argument sanitization**: Shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`) are blocked
- **Destructive flag blocking**: `--delete`, `-rf`, `--exploit` and similar flags are rejected
- **Network policy**: Network tools (nmap, sqlmap, etc.) can only target private/loopback IPs by default. Set `CYBERSEC_MCP_ALLOW_EXTERNAL=1` to allow external targets
- **No shell execution**: Uses `asyncio.create_subprocess_exec()` (no `shell=True`)
- **Timeout**: Configurable 1-300s, process killed on timeout
- **Output limits**: Truncated at 50KB to prevent memory issues
