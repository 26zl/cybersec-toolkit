"""Main FastMCP server — 13 MCP tool registrations + entry point."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP

# Ensure the parent directory is on sys.path so both `python -m mcp_server.server`
# (relative imports) and `fastmcp dev inspector server.py` (direct imports) work.
_parent = str(Path(__file__).resolve().parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from mcp_server.bounty_advisor import suggest_for_bounty as _suggest_for_bounty  # noqa: E402, I001
from mcp_server.ctf_advisor import suggest_for_ctf as _suggest_for_ctf  # noqa: E402
from mcp_server.profiles import PROFILES  # noqa: E402
from mcp_server.profiles import list_profiles as _list_profiles  # noqa: E402
from mcp_server.profiles import recommend_install as _recommend_install  # noqa: E402
from mcp_server.remote import RemoteHostConfig, check_ssh_connection  # noqa: E402
from mcp_server.security import execute_pipeline as _execute_pipeline  # noqa: E402
from mcp_server.security import execute_script as _execute_script  # noqa: E402
from mcp_server.security import execute_tool as _execute_tool  # noqa: E402
from mcp_server.security import execute_tool_remote as _execute_tool_remote  # noqa: E402
from mcp_server.tools_db import MODULE_DESCRIPTIONS, ToolsDatabase  # noqa: E402

mcp = FastMCP(
    "Cybersec Toolkit",
    instructions="""\
You are an expert offensive security AI — CTF solver, exploit developer, and bug bounty hunter.

## Capabilities
- **run_tool**: Run 570+ security tools and ~120 system utilities directly
- **run_pipeline**: Pipe tools together (strings | grep, xxd | grep, etc.)
- **run_script**: Write and run Python/Bash scripts (pwntools, z3, requests, crypto, struct, etc.)
- **suggest_for_ctf**: Get tool recommendations + methodology + quick wins per CTF category
- **suggest_for_bounty**: Get tool recommendations + methodology + common vulns per bug bounty target type

## Attack methodology
1. **Recon** — Gather information with nmap, amass, subfinder, whatweb, curl, dig
2. **Analyze** — Examine findings with strings, file, xxd, readelf, objdump, binwalk
3. **Exploit** — Write and run exploits with run_script (pwntools, requests, z3, crypto)
4. **Adapt** — Iterate based on results, try alternative attack paths

## Decision tree for unknown files
1. Run `file` to identify file type
2. Run `strings | grep -i flag` (CTF) or `strings | grep -i password\\|secret\\|key` (bounty) for quick wins
3. Run `xxd | head` for hex inspection
4. Based on type: ELF→pwn/reversing, PCAP→networking, PNG/JPG→stego, ZIP→forensics, \
APK→mobile, text→crypto/misc, cloud config→cloud
5. Use `suggest_for_ctf` (CTF) or `suggest_for_bounty` (bug bounty) for target-specific methodology

## CTF workflow per category
- **Web**: curl/httpx recon → ffuf/gobuster fuzzing → sqlmap SQLi → run_script for custom exploits
- **Crypto**: run_script with PyCryptodome, z3, gmpy2 for RSA, custom implementations
- **Pwn**: checksec → readelf/objdump → find offset → run_script with pwntools (ROP, shellcode, fmt str)
- **Reversing**: strings → file → objdump/readelf → strace/ltrace → run_script for decoding
- **Forensics**: binwalk -e → volatility3 → foremost → exiftool → run_script for custom parsers
- **Stego**: exiftool → steghide → zsteg → stegsolve → run_script for LSB extraction
- **Networking**: nmap/masscan service discovery → tshark/tcpdump traffic analysis → \
isolate interesting streams/services → run_script for protocol decoding, covert channels, replay

## Efficiency tips
- **Combine operations**: Run multiple analyses in a single run_script call instead of separate run_tool calls
- **Metadata first**: Before deep analysis, run lightweight metadata tools (file, exiftool, capinfos, \
readelf -h) — they reveal structure, format, and hidden info in seconds even on huge files
- **Split large inputs**: For large files, filter or extract the relevant subset first, then analyze: \
PCAPs (tshark -Y "filter" -w /tmp/subset.pcap), binaries (dd/binwalk -e), logs (grep/awk)
- **Glob patterns don't expand** in run_tool (no shell). To find files, use \
`run_script("import glob; print(glob.glob('/path/*.ext'))")` instead of `run_tool("ls", "*.ext")`
- **Use working_dir**: Set `working_dir="/tmp"` in run_script to keep temp files accessible between calls

## Automation patterns
- **run_pipeline** for quick filtering: `strings file | grep keyword`, `xxd dump | grep MAGIC`
- **run_script** for complex logic: pwntools exploits, z3 constraint solving, requests for API testing, \
custom payload generation, race conditions
- **Combine**: Use run_tool for recon, run_pipeline for filtering, run_script for exploitation or automation

## Error handling
- If a tool fails, try an alternative (nmap→masscan, gobuster→ffuf, steghide→zsteg, sqlmap→run_script)
- Check exit_code and stderr for diagnostics
- On timeout: reduce scope, split input, or use faster tools
- On missing tool: check check_installed, suggest installation or use run_script as fallback

## Bug bounty methodology
1. **Scope**: Always verify targets are in scope before testing
2. **Recon**: amass, subfinder, httpx, waybackurls for asset discovery
3. **Scanning**: nuclei, nikto, nmap for vulnerability scanning
4. **Manual testing**: run_script for custom payload generation, race conditions, business logic flaws
5. **Reporting**: Document findings with reproducible steps
6. Use `suggest_for_bounty` for target-specific tools, methodology, and common vulns \
(supports: web_app, api, mobile_app, cloud, network, iot)

## Manual scripts
- The project has a `manual_scripts/` directory for persistent scripts (exploits, solvers, custom tools)
- When a script is more than a one-off (complex exploit, reusable tool, multi-step solver), \
write it to `manual_scripts/`
- Naming convention: `solve_<challenge>.py`, `exploit_<target>.py`, `recon_<scope>.py`, `tool_<function>.py`
- Combine: write the script to `manual_scripts/`, run it via run_script with working_dir pointing to the project root

## Multi-step solving
- Don't stop after the first finding — escalate, pivot, combine findings
- Use output from one tool as input to the next (pipeline thinking)
- Document each step for reproducibility

## Use your tools
- **Use run_tool for tool execution** — do NOT reimplement tools via run_script. \
Use `run_tool("curl", "-s http://target")` not `run_script("subprocess.run(['curl', ...])")`
- **Use run_pipeline for chaining** — do NOT write shell pipes in run_script. \
Use `run_pipeline([{"tool": "strings", "args": "file"}, {"tool": "grep", "args": "key"}])`
- **Use suggest_for_ctf / suggest_for_bounty** — before diving in, call these to get \
curated tool lists and methodology for your challenge type
- **Use check_installed before assuming** — verify a tool exists before trying to use it
- **Reserve run_script for actual programming** — custom exploits, crypto solvers, parsers, \
data processing. Not for wrapping tools you could call directly

## Ground truth — avoid hallucination
- **NEVER assume — verify**: Do not assume how a tool, instruction, or API works. \
Run it and observe the actual output before building on it
- **Do not fabricate output**: If you haven't run a tool, do not claim to know what it returns. \
Run it first, then analyze the real output
- **Test one variable at a time**: When exploring unknown behavior, change ONE thing per test \
so you know exactly what caused the difference
- **State uncertainty explicitly**: Say "I think X based on Y" not "X does Y". \
If you're guessing, say so — then test it
- **Re-read actual output**: Before drawing conclusions, re-read the exact tool output. \
Don't paraphrase it in a way that adds assumptions
- **Verify before chaining**: Before building a multi-step exploit, verify each step independently. \
Do not chain 5 unverified assumptions into one payload

## Avoiding dead ends
- **Follow anomalies immediately**: If output is unexpected (e.g. hex input producing ASCII chars, \
unusual error messages, different behavior than expected), investigate that anomaly FIRST — \
it is likely the intended attack vector
- **Pivot after 2-3 failures**: If the same approach fails 2-3 times with minor variations, \
STOP and switch to a completely different technique. Do not keep trying variations of a broken approach
- **Test at every layer**: For web challenges, test the web layer (SSTI, parameter injection, \
different endpoints) AND the application layer (instruction set, object model), not just one
- **Explore syntax systematically**: When probing an unknown API/instruction set, test ALL \
argument combinations (e.g. `CALL A`, `CALL A B`, `CALL A B C`) instead of assuming syntax
- **Keep a mental scoreboard**: Track which approaches yielded interesting results vs. dead ends. \
Prioritize the promising leads over exhausting dead-end variations

## Solution writeup
- After solving a challenge or confirming a finding, ALWAYS provide a summary/writeup
- Include: what was found, tools/techniques used, key steps, and the final result (flag, vuln, PoC)
- For CTFs: flag, category, difficulty, solve path, alternative approaches if relevant
- For bug bounty: vulnerability type, affected endpoint, impact, reproduction steps, remediation
- REDACT sensitive data in writeups — mask credentials (****), anonymize PII, use minimal PoC

## Venv support for run_script
- Default: uses the MCP server's Python (has requests, pycryptodome, beautifulsoup4)
- `venv="pwntools"`: uses ~/.ctf-venvs/pwntools/ — for pwntools, z3 (Python 3.12)
- Use the venv parameter when the script needs packages not in the default Python
- CYBERSEC_MCP_VENVS_DIR can be overridden for custom location

## CRITICAL: File access via MCP tools
- You HAVE full filesystem access through your MCP tools (run_tool, run_pipeline, run_script)
- The MCP server runs on the user's LOCAL machine in WSL — NOT in a cloud sandbox
- NEVER ask the user to "upload", "drag and drop", or "attach" files — you can read them directly
- NEVER say you don't have filesystem access — you DO, via MCP tools
- Windows files are at `/mnt/c/Users/<username>/...` (e.g. `/mnt/c/Users/lenti/Downloads/`)
- WSL files are at their normal paths (e.g. `/home/user/...`)
- When a user mentions a file or path, IMMEDIATELY use run_tool to access it:
  1. `run_tool("ls", "-la /mnt/c/Users/lenti/Downloads/")` — browse directories
  2. `run_tool("file", "/path/to/file")` — identify file type
  3. `run_tool("strings", "/path/to/file")` — extract strings
  4. `run_script("with open('/path/file','rb') as f: ...")` — read binary data
- If the user says a file is in "Downloads", try `/mnt/c/Users/lenti/Downloads/` directly
- If a path doesn't work, use `run_tool("ls", ...)` to find the correct path

## Sensitive data handling
- When credentials, API keys, tokens, or PII are discovered: flag them clearly but do NOT spread them \
across multiple outputs unnecessarily
- Do NOT exfiltrate discovered data beyond what is needed for a minimal PoC
- Clean up temporary files containing secrets after use (run_script to delete)
- In bug bounty: report the existence and access method, not the credentials themselves

## Guidelines
- Be direct and technical — avoid generic disclaimers, but DO warn about specific risks \
(rate limiting detected, destructive action, permissions issue, target appears down)
- Always suggest next steps based on results
- Use run_script actively for anything requiring programming logic
- Combine tools creatively to solve complex challenges
- Security is handled by env flags (CYBERSEC_MCP_ALLOW_SCRIPTS, CYBERSEC_MCP_ALLOW_EXTERNAL), \
not by instructions
""",
)

# Shared database instance (loaded once on server start).
_db = ToolsDatabase()

# Remote host configuration (loaded once on server start).
_remote = RemoteHostConfig()

# Termux runs without sudo; Linux requires it.
_SUDO = "" if os.environ.get("TERMUX_VERSION") else "sudo "


def _cmd(script: str, args: str = "") -> str:
    """Build a shell command string, prefixing sudo when not on Termux."""
    return f"{_SUDO}{script}{' ' + args if args else ''}"


@mcp.tool
def list_tools(
    module: Optional[str] = None,
    method: Optional[str] = None,
    installed_only: bool = False,
) -> dict:
    """List and filter tools from the 570-tool cybersecurity registry.

    Args:
        module: Filter by module (e.g. "web", "pwn", "forensics"). 18 modules available.
        method: Filter by install method (apt, pipx, go, cargo, gem, git, binary, docker, snap, special, source, npm).
        installed_only: If true, only return tools that are currently installed.

    Returns:
        Tool list with count, available filters, and tool entries (name, method, module, url).
    """
    tools = _db.list_tools(module=module, method=method, installed_only=installed_only)

    tool_entries = []
    for t in tools:
        entry: dict = {
            "name": t["name"],
            "method": t["method"],
            "module": t["module"],
            "url": t.get("url", ""),
        }
        if installed_only and "install_status" in t:
            entry["install_status"] = t["install_status"]
        tool_entries.append(entry)

    result: dict = {
        "count": len(tool_entries),
        "total_in_registry": _db.total_tools,
        "tools": tool_entries,
    }

    # Add filter info when no filters applied
    if not module and not method:
        result["available_modules"] = _db.modules
        result["available_methods"] = _db.methods

    return result


@mcp.tool
async def check_installed(tool_name: str, host: Optional[str] = None) -> dict:
    """Check if a specific cybersecurity tool is installed on the system.

    Uses multiple detection strategies: .versions tracking, PATH lookup,
    pipx binary name fallback, /opt directory check, and docker image check.

    When host is provided, checks installation on the remote host via SSH
    using 'which <binary>'.

    Args:
        tool_name: Name of the tool to check (as listed in tools_config.json).
        host: Optional remote host name (as configured via manage_remote_hosts).

    Returns:
        Installation status with detection method and details.
    """
    tool = _db.tools_by_name.get(tool_name)

    # System utility — not in registry but allowed
    if not tool:
        from mcp_server.security import SYSTEM_UTILITIES

        if tool_name in SYSTEM_UTILITIES:
            if host:
                from mcp_server.remote import execute_remote_command

                try:
                    ssh_args = _remote.get_ssh_base_args(host)
                except ValueError as e:
                    return {"tool": tool_name, "in_registry": False, "system_utility": True, "error": str(e)}
                result = await execute_remote_command(ssh_args, ["which", tool_name], timeout=15)
                installed = result["exit_code"] == 0
                path = result["stdout"].strip() if installed else ""
                return {
                    "tool": tool_name,
                    "in_registry": False,
                    "system_utility": True,
                    "installed": installed,
                    "details": f"found at {path} on {host}" if installed else f"not found on {host}",
                    "remote": True,
                    "host": host,
                }
            import shutil

            path = shutil.which(tool_name)
            return {
                "tool": tool_name,
                "in_registry": False,
                "system_utility": True,
                "installed": path is not None,
                "details": f"found at {path}" if path else "not installed or not in PATH",
            }

        # Not in registry and not a system utility
        return {
            "tool": tool_name,
            "in_registry": False,
            "error": f"Tool '{tool_name}' not found in registry and not a recognized system utility.",
        }

    if host:
        # Remote installation check via SSH 'which'
        from mcp_server.remote import execute_remote_command
        from mcp_server.tools_db import PIPX_BIN_NAMES

        try:
            ssh_args = _remote.get_ssh_base_args(host)
        except ValueError as e:
            return {"tool": tool_name, "in_registry": True, "error": str(e)}

        binary = PIPX_BIN_NAMES.get(tool_name, tool_name)
        result = await execute_remote_command(ssh_args, ["which", binary], timeout=15)
        installed = result["exit_code"] == 0
        path = result["stdout"].strip() if installed else ""
        return {
            "tool": tool_name,
            "in_registry": True,
            "module": tool["module"],
            "method": tool["method"],
            "url": tool.get("url", ""),
            "installed": installed,
            "details": f"found at {path} on {host}" if installed else f"not found on {host}",
            "remote": True,
            "host": host,
        }

    status = _db.check_installed(tool_name)
    return {
        "tool": tool_name,
        "in_registry": True,
        "module": tool["module"],
        "method": tool["method"],
        "url": tool.get("url", ""),
        **status,
    }


@mcp.tool
def get_tool_info(tool_name: str) -> dict:
    """Get detailed information about a cybersecurity tool.

    Returns the tool's install method, module, URL, installation status,
    module description, and management commands (install, update, remove).

    Args:
        tool_name: Name of the tool to look up.

    Returns:
        Full tool details including install/update/remove commands.
    """
    tool = _db.tools_by_name.get(tool_name)
    if not tool:
        return {
            "error": f"Tool '{tool_name}' not found in registry. Use list_tools() to see available tools.",
        }

    status = _db.check_installed(tool_name)
    module = tool["module"]
    module_desc = MODULE_DESCRIPTIONS.get(module, "")

    return {
        "name": tool["name"],
        "method": tool["method"],
        "module": module,
        "module_description": module_desc,
        "url": tool.get("url", ""),
        "installed": status["installed"],
        "install_details": status["details"],
        "commands": {
            "install": _cmd("./install.sh", f"--module {module}"),
            "update": _cmd("./scripts/update.sh", f"--module {module}"),
            "remove": _cmd("./scripts/remove.sh", f"--module {module}"),
            "verify": _cmd("./scripts/verify.sh", f"--module {module}"),
        },
    }


@mcp.tool
def suggest_for_ctf(challenge_type: str) -> dict:
    """Suggest cybersecurity tools for a CTF challenge category.

    Provides curated tool recommendations with installation status for
    13 challenge types: web, crypto, pwn, reversing, forensics, stego,
    misc, networking, wireless, osint, cloud, mobile, blockchain.

    Also accepts aliases: re/rev (reversing), binary/exploitation (pwn),
    steganography (stego), network (networking), recon (osint), etc.

    Args:
        challenge_type: Type of CTF challenge (e.g. "web", "crypto", "pwn").

    Returns:
        Suggested tools with descriptions and install status, plus relevant modules.
    """
    return _suggest_for_ctf(challenge_type, _db)


@mcp.tool
def suggest_for_bounty(target_type: str) -> dict:
    """Suggest cybersecurity tools for a bug bounty target type.

    Provides curated tool recommendations with installation status,
    methodology steps (starting with scope verification), common
    vulnerabilities, and quick wins for 6 target types: web_app, api,
    mobile_app, cloud, network, iot.

    Also accepts aliases: web/webapp (web_app), rest/graphql (api),
    android/ios/mobile (mobile_app), aws/azure/gcp/k8s (cloud),
    infra/infrastructure (network), firmware/embedded (iot).

    Args:
        target_type: Type of bug bounty target (e.g. "web_app", "api", "cloud").

    Returns:
        Suggested tools with install status, methodology, common vulns, and scope warning.
    """
    return _suggest_for_bounty(target_type, _db)


@mcp.tool
def recommend_install(task: str) -> dict:
    """Recommend which profile, modules, or individual tools to install.

    Analyzes a natural-language description of what the user wants to do and
    recommends the best installation approach — from a full profile down to
    just a few individual tools. Avoids installing everything when only a
    subset is needed.

    Examples:
        "I want to do CTF competitions" → ctf profile
        "web application pentesting" → web profile
        "I just need nmap and burpsuite" → individual modules networking + web
        "crack some password hashes" → crackstation profile
        "forensics and incident response" → forensics profile
        "everything" → full profile
        "quick minimal setup" → lightweight profile

    Args:
        task: Natural-language description of what the user wants to do.

    Returns:
        Recommendation with install commands, module details, and alternatives.
    """
    return _recommend_install(task, _db)


@mcp.tool
def list_profiles() -> dict:
    """List all 14 available installation profiles with details.

    Each profile is a curated set of modules targeting a specific use case.
    Shows module count, tool count, and install command for each profile.
    Profiles range from 'osint' (2 modules, ~80 tools) to 'full' (18 modules, 570 tools).

    Returns:
        All profiles with descriptions, module lists, tool counts, and install commands.
    """
    return _list_profiles(_db)


@mcp.tool
def get_profile_tools(profile: str) -> dict:
    """List every tool that a specific profile would install.

    Given a profile name, returns the complete list of tools grouped by
    module, with install status for each. This lets you see exactly what
    you get before running the install command.

    Args:
        profile: Profile name (e.g. "ctf", "redteam", "web", "full").

    Returns:
        All tools in the profile grouped by module, with install status and counts.
    """
    profile_lower = profile.lower().strip()
    if profile_lower not in PROFILES:
        return {
            "error": f"Unknown profile '{profile}'. Available: {', '.join(sorted(PROFILES))}",
        }

    profile_data = PROFILES[profile_lower]
    modules = profile_data["modules"]

    by_module: list[dict] = []
    total = 0
    installed = 0

    for mod in modules:
        mod_tools = [t for t in _db._tools if t["module"] == mod]
        tool_entries = []
        for t in mod_tools:
            status = _db.check_installed(t["name"])
            tool_entries.append(
                {
                    "name": t["name"],
                    "method": t["method"],
                    "url": t.get("url", ""),
                    "installed": status["installed"],
                }
            )
            total += 1
            if status["installed"]:
                installed += 1

        by_module.append(
            {
                "module": mod,
                "description": MODULE_DESCRIPTIONS.get(mod, ""),
                "tool_count": len(tool_entries),
                "tools": tool_entries,
            }
        )

    return {
        "profile": profile_lower,
        "description": profile_data["description"],
        "total_tools": total,
        "installed_tools": installed,
        "install_command": _cmd("./install.sh", f"--profile {profile_lower}"),
        "modules": by_module,
    }


@mcp.tool
def get_module_info(module: str) -> dict:
    """Get full details about a module: description, all tools, and management commands.

    Args:
        module: Module name (e.g. "web", "pwn", "forensics").

    Returns:
        Module description, tool list with install status, and install/update/remove commands.
    """
    module_lower = module.lower().strip()
    if module_lower not in MODULE_DESCRIPTIONS:
        return {
            "error": f"Unknown module '{module}'. Available: {', '.join(sorted(MODULE_DESCRIPTIONS))}",
        }

    mod_tools = [t for t in _db._tools if t["module"] == module_lower]
    installed_count = 0
    tool_entries = []

    for t in mod_tools:
        status = _db.check_installed(t["name"])
        tool_entries.append(
            {
                "name": t["name"],
                "method": t["method"],
                "url": t.get("url", ""),
                "installed": status["installed"],
                "details": status["details"],
            }
        )
        if status["installed"]:
            installed_count += 1

    # Group tools by method for overview
    by_method: dict[str, int] = {}
    for t in mod_tools:
        by_method[t["method"]] = by_method.get(t["method"], 0) + 1

    # Which profiles include this module
    in_profiles = [name for name, p in PROFILES.items() if module_lower in p["modules"]]

    return {
        "module": module_lower,
        "description": MODULE_DESCRIPTIONS[module_lower],
        "total_tools": len(mod_tools),
        "installed_tools": installed_count,
        "tools_by_method": by_method,
        "tools": tool_entries,
        "in_profiles": in_profiles,
        "commands": {
            "install": _cmd("./install.sh", f"--module {module_lower}"),
            "update": _cmd("./scripts/update.sh", f"--module {module_lower}"),
            "remove": _cmd("./scripts/remove.sh", f"--module {module_lower}"),
            "verify": _cmd("./scripts/verify.sh", f"--module {module_lower}"),
        },
    }


@mcp.tool
async def run_tool(
    tool_name: str,
    args: str = "",
    timeout: int = 120,
    host: Optional[str] = None,
) -> dict:
    """Execute an installed cybersecurity tool or system utility and return its output.

    Runs tools from the 570-tool registry as well as ~120 standard system
    utilities (strings, file, curl, grep, base64, xxd, jq, python3, etc.)
    that are allowed without being in the registry. Arguments are sanitized
    to prevent shell injection. Timeout is clamped to 1-300s. Output is
    truncated at 200KB.

    Network tools (including curl, wget, ping, etc.) are restricted to
    local/private targets by default. Set CYBERSEC_MCP_ALLOW_EXTERNAL=1
    to allow external targets.

    When host is provided, the tool is executed on the remote host via SSH.
    The tool does not need to be installed locally — only on the remote host.

    Args:
        tool_name: Name of the tool to run (registry tool or system utility).
        args: Command-line arguments as a string (e.g. "--version" or "-sV 10.0.0.1").
        timeout: Maximum execution time in seconds (default 120, max 300).
        host: Optional remote host name (as configured via manage_remote_hosts).

    Returns:
        Execution result with exit_code, stdout, stderr, and the command that was run.
    """
    if host:
        return await _execute_tool_remote(tool_name, args, _db, _remote, host, timeout=timeout)
    return await _execute_tool(tool_name, args, _db, timeout=timeout)


@mcp.tool
async def run_pipeline(
    steps: list[dict],
    timeout: int = 120,
    host: Optional[str] = None,
) -> dict:
    """Execute a pipeline of tools, piping stdout from each step into stdin of the next.

    Replaces shell piping (e.g. `strings binary | grep flag`) with a safe,
    no-shell alternative. Each step is validated individually (allowlist,
    argument sanitization, policy checks) before any process starts.

    Only intermediate output is NOT truncated — this allows large intermediate
    results (e.g. strings output) to be filtered down by later steps (e.g. grep).
    The final output is truncated at 200KB.

    Examples:
        run_pipeline([{"tool": "strings", "args": "./binary"}, {"tool": "grep", "args": "flag"}])
        run_pipeline([{"tool": "cat", "args": "data.b64"}, {"tool": "base64", "args": "-d"}])
        run_pipeline([{"tool": "xxd", "args": "firmware.bin"}, {"tool": "grep", "args": "MAGIC"}])

    Args:
        steps: List of dicts, each with 'tool' (required) and 'args' (optional) keys.
               Max 10 steps per pipeline.
        timeout: Global timeout for entire pipeline in seconds (default 120, max 300).
        host: Reserved for future use. Currently only local execution is supported.

    Returns:
        Execution result with exit_code, stdout, stderr, truncated, commands, step_count.
    """
    if host:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "Remote pipeline execution is not yet supported.",
            "truncated": False,
            "commands": [],
            "step_count": 0,
        }
    return await _execute_pipeline(steps, _db, timeout=timeout)


@mcp.tool
async def run_script(
    code: str,
    language: str = "python",
    timeout: int = 120,
    working_dir: Optional[str] = None,
    venv: Optional[str] = None,
) -> dict:
    """Write and execute a Python or Bash script, returning its output.

    Writes the code to a temporary file, executes it via python3/bash,
    and returns stdout/stderr. The temp file is deleted after execution.
    Requires CYBERSEC_MCP_ALLOW_SCRIPTS=1 environment variable.

    Use cases:
        - Pwntools exploits: buffer overflows, ROP chains, format strings
        - Z3 constraint solving: reverse engineering, crypto challenges
        - Crypto attacks: RSA factoring, padding oracles, custom ciphers
        - Web scripting: requests, JWT manipulation, race conditions
        - Binary parsing: struct.unpack, custom file format parsers
        - Bash automation: port scanning loops, enumeration scripts

    Examples:
        run_script("from pwn import *; print(cyclic(20))", venv="pwntools")
        run_script("from z3 import *; x = Int('x'); s = Solver(); s.add(x * 7 == 42); s.check(); print(s.model())")
        run_script("import requests; r = requests.get('http://10.0.0.1/api'); print(r.json())")
        run_script("import struct; print(struct.pack('<I', 0xdeadbeef).hex())")
        run_script("for p in $(seq 1 1024); do (echo >/dev/tcp/10.0.0.1/$p) 2>/dev/null && echo $p; done",
            language="bash")

    Args:
        code: The script source code to execute.
        language: "python" (default) or "bash".
        timeout: Maximum execution time in seconds (default 120, max 300).
        working_dir: Working directory for the script (default: system temp dir).
        venv: Optional Python venv name from ~/.ctf-venvs/ (e.g. "pwntools").
              Allows using a different Python with specific packages installed.
              Ignored for language="bash". If not set, uses the MCP server's Python.

    Returns:
        Execution result with exit_code, stdout, stderr, truncated, language,
        script_file, and working_dir.
    """
    return await _execute_script(
        code=code,
        language=language,
        timeout=timeout,
        working_dir=working_dir,
        venv=venv,
    )


@mcp.tool
async def manage_remote_hosts(
    action: str,
    name: Optional[str] = None,
    hostname: Optional[str] = None,
    user: str = "kali",
    port: int = 22,
    ssh_key: Optional[str] = None,
    description: str = "",
    tool_allowlist: Optional[str] = None,
) -> dict:
    """Manage SSH remote hosts for running tools on remote Kali/Linux boxes.

    Actions:
        list  — List all configured remote hosts.
        add   — Add or update a remote host (requires name and hostname).
        remove — Remove a remote host by name.
        test  — Test SSH connectivity to a remote host.

    Args:
        action: One of "list", "add", "remove", "test".
        name: Host name (required for add/remove/test).
        hostname: IP address or hostname of the remote machine (required for add).
        user: SSH username (default "kali").
        port: SSH port (default 22).
        ssh_key: Path to SSH private key (e.g. "~/.ssh/id_kali").
        description: Human-readable description of the host.
        tool_allowlist: Comma-separated list of allowed tool names
            (e.g. "nmap,gobuster,sqlmap"). None means all tools allowed.

    Returns:
        Action result with host details or error message.
    """
    action = action.lower().strip()

    if action == "list":
        hosts = _remote.list_hosts()
        return {"action": "list", "hosts": hosts, "count": len(hosts)}

    if not name:
        return {"error": f"Action '{action}' requires a 'name' parameter."}

    if action == "add":
        if not hostname:
            return {"error": "Action 'add' requires a 'hostname' parameter."}
        parsed_allowlist: list[str] | None = None
        if tool_allowlist is not None:
            parsed_allowlist = [t.strip() for t in tool_allowlist.split(",") if t.strip()]
        try:
            entry = _remote.add_host(
                name=name,
                hostname=hostname,
                user=user,
                port=port,
                ssh_key=ssh_key,
                description=description,
                tool_allowlist=parsed_allowlist,
            )
            return {"action": "add", "name": name, "host": entry}
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    if action == "remove":
        try:
            removed = _remote.remove_host(name)
        except OSError as e:
            return {"error": f"Failed to save config: {e}"}
        if removed:
            return {"action": "remove", "name": name, "removed": True}
        return {"error": f"Host '{name}' not found."}

    if action == "test":
        try:
            ssh_args = _remote.get_ssh_base_args(name)
        except ValueError as e:
            return {"error": str(e)}
        result = await check_ssh_connection(ssh_args)
        return {"action": "test", "name": name, **result}

    return {"error": f"Unknown action '{action}'. Use: list, add, remove, test."}


def main() -> None:
    """Entry point for the ``cybersec-mcp`` console script."""
    mcp.run()


if __name__ == "__main__":
    main()
