# AI Client Compatibility

This document describes how to connect the Cybersec Toolkit MCP server to
various AI coding clients, MCP hosts, and model runtimes.

## Quick reference

| Client | MCP host? | Project config | Skills | Label |
| ------ | --------- | -------------- | ------ | ----- |
| Claude Code | Yes | `.mcp.json` (tracked) | `.claude/skills/` (native) | Native configuration included |
| Claude Desktop | Yes | `claude_desktop_config.json` | — | Configuration example documented |
| OpenCode | Yes | `opencode.jsonc` (tracked) | `.agents/skills/` (discovery) | Live tested |
| Codex | Yes | `.codex/config.toml` (tracked) | `.agents/skills/` (native) | Configuration validated |
| Gemini CLI | Yes | `.gemini/settings.json` (tracked) + `GEMINI.md` | `.agents/skills/` (native) | Configuration validated |
| GitHub Copilot | Varies by surface | `.mcp.json` (CLI) + `.github/copilot-instructions.md` | `.claude/skills/` or `.agents/skills/` (native) | CLI live tested; VS Code documented |
| Hermes Agent | Yes | User `~/.hermes/config.yaml` | External skill directory (configured) | Live tested |
| OpenClaw | Yes | User `~/.openclaw/openclaw.json` | `.agents/skills/` (discovery) | Live tested |
| Cursor | Yes | Client MCP settings UI | `.agents/skills/` (native) | Compatible through MCP |
| Continue | Yes | Client MCP settings | Rules/prompts; no native repository skill discovery documented | Compatible through MCP |
| Cline | Yes | Client MCP settings | `.claude/skills/` (native; feature flag) | Compatible through MCP |
| Goose | Yes | Client MCP settings | `.agents/skills/` (native) | Compatible through MCP |
| LM Studio (>=0.3.17) | Yes | `mcp.json` (Cursor notation) | Manual or MCP-provided context | Compatible through MCP |
| Aider | No (agent) | — | — | Not applicable |
| Ollama | No (model runtime) | — | — | Compatible through an MCP host |
| Open WebUI | No (needs bridge) | — | — | Compatible through MCP host or bridge |

## Canonical MCP launch command

All clients use the same MCP server. The canonical launcher is
`scripts/mcp-launch.sh`. It determines the repository root from its own
location and starts the FastMCP server over stdio via `uv`.

**From the repository root:**

```bash
bash scripts/mcp-launch.sh
```

**From a repository subdirectory** (e.g. `mcp_server/`), the tracked Codex,
OpenCode, and Gemini configurations resolve the Git root automatically. A
direct shell invocation must use a path that is valid from the current
directory (for example, `bash ../scripts/mcp-launch.sh` from `mcp_server/`) or
the absolute launcher path shown below.

**From an unrelated directory**, use the launcher's absolute path:

```bash
bash /absolute/path/to/cybersec-toolkit/scripts/mcp-launch.sh
```

Safe defaults are applied automatically:

- `CYBERSEC_MCP_ALLOW_EXTERNAL=0` (network tools restricted to private/loopback)
- `CYBERSEC_MCP_ALLOW_SCRIPTS=0` (unsandboxed script execution disabled)

To enable external targets or scripts, set the corresponding environment
variable to `1` in the client's MCP configuration and restart the client.

## Model provider vs model runtime vs MCP client

These are distinct layers:

1. **Model provider** — the API or service that hosts the LLM (Anthropic,
   OpenAI, DeepSeek, Ollama Cloud, local Ollama, etc.).
2. **Model runtime** — the software that loads and runs a model (Ollama,
   LM Studio, llama.cpp, vLLM). A runtime is not an MCP host.
3. **AI/MCP client** — the agent or coding interface that calls MCP tools
   (Claude Code, OpenCode, Hermes, OpenClaw, Cursor, Goose, etc.).
4. **MCP server** — the tool provider (this project's `mcp_server/`).
5. **Skills/instructions** — methodology context the AI loads on demand.

A bare Ollama model does not speak MCP. An MCP-capable client must sit in
front of it. For example:

```text
Ollama (model runtime) → OpenCode (MCP client) → cybersec-tools (MCP server)
```

Choose any provider and model supported by your client. The MCP integration
is independent of that choice.

## OpenCode

### Configuration

The tracked `opencode.jsonc` defines the local MCP server with safe defaults.
OpenCode discovers it automatically from the project root. The configuration
contains only the MCP server definition — no model, provider, or API key.

### Model selection

Users select models through OpenCode's `/models` command or the `model` key
in their own `opencode.json`. The repository does not select a model on the
user's behalf.

Users cycle supported reasoning variants with `Ctrl+T` in the OpenCode TUI.
The repository does not force a reasoning level.

### Optional provider examples

These are examples only. The user chooses their own provider and model.

**Ollama Cloud:**

```bash
ollama launch opencode --model deepseek-v4-pro:cloud
```

- Ollama supplies the model; OpenCode is the MCP-capable agent.
- A bare Ollama model is not itself the MCP host.
- Model selection and MCP configuration are separate.
- Provider credentials remain in the user's credential store or environment.

**Local Ollama:**

```bash
ollama launch opencode
```

Choose the local model in Ollama's launcher. Ollama injects the provider
configuration for that session without overwriting the user's OpenCode
configuration. For a manual provider definition, follow Ollama's current
OpenCode integration guide and choose the model name and context size locally.

**Direct DeepSeek API:**

```text
/connect
/models
```

Select DeepSeek in `/connect`, enter the user's own API key, and then choose
the desired DeepSeek model with `/models`. Credentials remain in OpenCode's
user credential store rather than the repository configuration.

**Other OpenAI-compatible providers:**

```jsonc
{
  "provider": {
    "openai-compatible": {
      "options": {
        "apiKey": "{env:MY_API_KEY}",
        "baseURL": "https://api.example.com/v1"
      }
    }
  },
  "model": "openai-compatible/model-name"
}
```

### Skills

OpenCode discovers skills from `.agents/skills/` (generated mirror of
`.claude/skills/`). Run `scripts/sync-skills.sh` after cloning to generate
the mirror. OpenCode also reads `.claude/skills/` directly.

## Hermes Agent

Hermes Agent has native MCP client support through `mcp_servers` in the
user's Hermes configuration at `~/.hermes/config.yaml`.

### Example configuration

Add to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  cybersec-tools:
    command: "bash"
    args:
      - "/absolute/path/to/cybersec-toolkit/scripts/mcp-launch.sh"
    env:
      CYBERSEC_MCP_ALLOW_EXTERNAL: "0"
      CYBERSEC_MCP_ALLOW_SCRIPTS: "0"
```

Replace `/absolute/path/to/cybersec-toolkit` with the actual repository path.

### Verifying MCP tools

```bash
hermes mcp list
hermes mcp test cybersec-tools
```

### Tool filtering

Hermes supports per-server tool filtering. To restrict which tools are
exposed, add a `tools.include` list. Omit `tools.include` to expose all
MCP tools governed by the server's own policy:

```yaml
mcp_servers:
  cybersec-tools:
    command: "bash"
    args:
      - "/path/to/cybersec-toolkit/scripts/mcp-launch.sh"
    env:
      CYBERSEC_MCP_ALLOW_EXTERNAL: "0"
      CYBERSEC_MCP_ALLOW_SCRIPTS: "0"
    tools:
      include:
        - list_tools
        - check_installed
        - get_tool_info
```

The specific tools above are examples. The user chooses which tools to
include.

### Blocked execution

When `run_tool` is blocked by policy (e.g. external targets disabled), the
MCP server returns a structured error with the policy reason and the
configuration change needed. Hermes surfaces this to the user.

### Hermes curated MCP catalog

A future entry in Hermes' curated MCP catalog would require:

- **Packaging**: The MCP server must be installable as a standalone package
  (e.g. `pip install cybersec-tools-mcp`). Currently it requires the full
  repository checkout for `tools_config.json`.
- **Manifest**: Catalog entries live under `optional-mcps/<name>/manifest.yaml`
  in the Hermes Agent repository.
- **Source/provenance**: Clear upstream URL, license, and version.
- **Current status**: The server is not yet packaged for standalone
  installation. A `pyproject.toml` exists but the package depends on the
  repository root for data files.

This integration was live tested with an isolated temporary home directory.
`hermes mcp list` showed the server as enabled, and
`hermes mcp test cybersec-tools` started the server, completed the MCP
handshake, and discovered all currently registered tools. The test did not
modify the user's global Hermes configuration or exercise catalog publishing.

## OpenClaw

OpenClaw supports both native MCP configuration and project Agent Skills.

### MCP integration

Add to `~/.openclaw/openclaw.json` (JSON5 format):

```json5
{
  mcp: {
    servers: {
      "cybersec-tools": {
        command: "bash",
        args: ["/absolute/path/to/cybersec-toolkit/scripts/mcp-launch.sh"],
        env: {
          CYBERSEC_MCP_ALLOW_EXTERNAL: "0",
          CYBERSEC_MCP_ALLOW_SCRIPTS: "0"
        }
      }
    }
  }
}
```

Replace the path with the actual repository location. This is a user-edited
example — do not copy the placeholder path into a tracked runtime
configuration.

### Listing and inspecting

```bash
openclaw mcp list
openclaw mcp show cybersec-tools
openclaw mcp status --verbose
openclaw mcp doctor cybersec-tools --probe
openclaw mcp probe cybersec-tools
```

### Skills integration

OpenClaw discovers skills from `<workspace>/.agents/skills/`. After cloning
the repository:

```bash
scripts/sync-skills.sh            # generate .agents/skills/ from .claude/skills/
scripts/sync-skills.sh --check    # verify the mirror is up to date
```

`.claude/skills/` remains the single source of truth. `.agents/skills/` is a
generated mirror (git-ignored). OpenClaw discovers skills from the workspace
root automatically.

### OpenClaw ecosystem (future)

OpenClaw supports several integration types:

1. **ClawHub skill** — a `SKILL.md` file published to ClawHub.
2. **OpenClaw bundle plugin** — packages an MCP server definition and
   optional integration skill.
3. **OpenClaw code plugin** — in-process code extending OpenClaw runtime.
4. **Normal MCP server definition** — the approach documented above.

A bundle-style plugin is the most natural fit for this toolkit. Requirements
for future publication include packaging, provenance, validation, and
security review. Not yet published.

This integration was live tested with an isolated temporary home directory.
`openclaw mcp status --verbose`, `openclaw mcp doctor cybersec-tools --probe`,
and `openclaw mcp probe cybersec-tools` all completed without diagnostics and
discovered all currently registered tools. `openclaw config validate` also
accepted the JSON5 configuration without warnings. The test did not modify the
user's global OpenClaw configuration or exercise ClawHub/plugin publishing.

## GitHub Copilot

GitHub Copilot has multiple surfaces with different MCP support:

- **GitHub Copilot Chat in VS Code** — supports MCP via `.vscode/mcp.json`.
  Adding a tracked `.vscode/mcp.json` would duplicate the existing server
  definition without enough user value; documentation is the more
  maintainable choice.
- **GitHub Copilot CLI** — reads the tracked repository-level `.mcp.json`.
- **`.github/copilot-instructions.md`** — provides repository-level
  instructions for Copilot's coding agent. The tracked file gives concise
  architecture and validation guidance without duplicating `AGENTS.md`.

Verify that Copilot CLI discovers the workspace server without invoking a
model:

```bash
copilot mcp list
copilot mcp get cybersec-tools
```

For a non-interactive prompt (`copilot -p`), workspace MCP loading is disabled
by default. Enable it explicitly and allow only the tool needed for the test:

```bash
GITHUB_COPILOT_PROMPT_MODE_WORKSPACE_MCP=true copilot -p \
  "Call the cybersec-tools list_profiles MCP tool exactly once." \
  --disable-builtin-mcps \
  --allow-tool='cybersec-tools(list_profiles)'
```

This prompt-mode opt-in is documented in the
[Copilot CLI command reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference).
A local end-to-end test loaded `cybersec-tools` from the workspace, invoked
`list_profiles`, and completed successfully. This validates Copilot CLI only;
the VS Code surface was not live tested.

## Gemini CLI

Gemini CLI reads `GEMINI.md` for project instructions and `.gemini/settings.json`
for project-level settings.

### MCP configuration

The tracked `.gemini/settings.json` defines the local MCP server with safe
defaults. Gemini CLI discovers it from the project root.

## Other clients

### Cursor, Continue, Cline, Goose

These clients support MCP through their respective settings UI or config
files. Use the canonical launch command with an absolute path:

```bash
bash /absolute/path/to/cybersec-toolkit/scripts/mcp-launch.sh
```

Set environment variables in the client's MCP configuration:

- `CYBERSEC_MCP_ALLOW_EXTERNAL=0`
- `CYBERSEC_MCP_ALLOW_SCRIPTS=0`

Cursor, Cline, and Goose support Agent Skills, with client-specific discovery paths.
Continue supports MCP plus its own rules and prompts, but does not currently document
automatic discovery of this repository's `SKILL.md` directories. Adding a standalone
`SKILLS.md` file would provide an index only; it would not create on-demand activation.

### LM Studio (>=0.3.17)

LM Studio is an MCP host. Add the server to its `mcp.json` (Cursor notation)
using an absolute path to `scripts/mcp-launch.sh`. Using MCP via LM Studio's
API requires >=0.4.0 and an MCP-capable endpoint.

LM Studio does not currently document native repository `SKILL.md` discovery. Provide
selected skill content as chat/system context, or expose reusable guidance through an
MCP server or LM Studio plugin. This limitation is separate from MCP tool support.

### Aider

Aider is an AI coding agent but not an MCP host. It cannot directly use MCP
tools. Use Aider for code editing and a separate MCP-capable client for
cybersecurity tool execution.

### Ollama

Ollama is a model runtime, not an MCP host. Use an MCP-capable client
(OpenCode, Hermes, OpenClaw, Cursor, Goose, etc.) in front of Ollama and
point that client at the MCP server.

### Open WebUI

Open WebUI can connect to MCP servers through an MCP-to-OpenAPI bridge such
as `mcpo`. Configure the bridge to expose the cybersec-tools MCP server, then
add the resulting OpenAPI endpoint to Open WebUI as a tool.

## Troubleshooting

### `uv` not found

Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Wrong working directory

From the repository root, use `bash scripts/mcp-launch.sh`. From another
directory, use the launcher's absolute path. The launcher determines the
repository root from its own location.

### MCP server not discovered

- Verify the client's MCP configuration points to the correct path.
- Restart the client after changing MCP configuration.
- Check the client's logs for MCP connection errors.

### Environment changes requiring a client restart

MCP server environment variables are set at launch time. After changing
`CYBERSEC_MCP_ALLOW_EXTERNAL` or `CYBERSEC_MCP_ALLOW_SCRIPTS`, restart the
client.

### External target blocked

Set `CYBERSEC_MCP_ALLOW_EXTERNAL=1` in the client's MCP configuration and
restart. Ensure you have explicit authorization for the target scope.

### Scripts disabled

Set `CYBERSEC_MCP_ALLOW_SCRIPTS=1` in the client's MCP configuration and
restart. This is an unsandboxed code-execution opt-in.

### Generated `.agents/skills` missing

Run `scripts/sync-skills.sh` to generate the mirror from `.claude/skills/`.

### Local model lacks sufficient tool-calling capability

Smaller local models may not reliably call MCP tools. Use a model with
proven tool-calling ability or a cloud provider model.
