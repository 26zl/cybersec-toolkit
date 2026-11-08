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
| DeepSeek Harness (dsh) | Yes | User `$DSH_HOME/settings.yaml` | `.agents/skills/` (native) | Configuration example documented |
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
location and starts the FastMCP server over stdio inside a Kata Containers
VM, so tools execute behind a hardware-virtualized boundary rather than as
the host user. See [`SANDBOX.md`](SANDBOX.md) for host prerequisites.

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

- `CYBERSEC_SANDBOX_MODE=kata` (the server runs inside a disposable VM)
- `CYBERSEC_MCP_ALLOW_EXTERNAL=0` (network tools restricted to private/loopback)
- `CYBERSEC_MCP_ALLOW_SCRIPTS=0` (script execution disabled)

To enable external targets or scripts, set the corresponding environment
variable to `1` in the client's MCP configuration and restart the client.

**Host execution** is an explicit opt-out, for developing the toolkit itself
and for hosts without KVM:

```bash
bash scripts/mcp-launch.sh --local
```

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

### Where target data goes

Every tool result the server returns — scan output, page content, and any
credential or personal data a tool finds on a target — becomes part of the
client's conversation and is sent to the model provider. The server strips
terminal escapes and flags injection attempts in that output, but by default it
does not redact secrets from it; only the local audit log is redacted. Set
`CYBERSEC_MCP_REDACT_OUTPUT=1` to redact credential-shaped strings from returned
output as well (pattern matching, so not a guarantee). When an
engagement's rules of engagement or a client contract forbid sharing target
data with a third party, run the model locally (for example Ollama or LM Studio
behind an MCP-capable client) so the output never leaves the host.

## Cyber model provider (OrcaRouter Cyber Inference)

The toolkit itself ships no model client — the MCP client on the other end of
stdio chooses the model. For deliberate security work, [OrcaRouter](https://www.orcarouter.ai)
is a named, OpenAI-compatible provider preset that lets a security team that has
completed business verification reach cyber-tier models and gateway controls on
one endpoint: **Cyber models for your red team, gateway controls for your blue
team.** It admits authorized, scoped security-reasoning requests that general
gateways often refuse or silently downgrade.

| | Value |
| --- | --- |
| Provider ID | `orcarouter` (**OrcaRouter Cyber Inference**) |
| Inference base (OpenAI wire format) | `https://api.orcarouter.ai/v1` |
| Model catalog | `GET https://api.orcarouter.ai/v1/models` |
| Auth (one click) | OAuth 2.0 + PKCE, key issued at `https://www.orcarouter.ai/api/v1/auth/keys` |
| Auth (existing key) | `ORCAROUTER_API_KEY`, an `sk-orca-…` key |
| Provider page | <https://www.orcarouter.ai/cyber> |
| Cyber-tier catalog | <https://www.orcarouter.ai/models?tier=cyber> |

### Choose a model

| Tier | Model ID | Use |
| --- | --- | --- |
| Default | `orcarouter/auto` | Automatic routing; works with any key; the provider default |
| Cyber (business-verified teams) | `orca/orcacyber-ultra-1.0` | Security code scanning and multi-step reasoning over large codebases |
| Cyber (business-verified teams) | `orca/orcacyber-zero-1.5` (also `orca/orcacyber-zero-1.0`) | OrcaCyber harness |
| General fallback | `orcarouter/fusion` | General-purpose fallback |

The Cyber IDs are the catalog form (`orca/<id>`, namespaced like every other vendor),
and that is what a client must send in `model`. Cyber-tier models serve
authenticated catalog listings only and are gated on business verification; select
a cyber model only on a key whose owner completed that step.

### Where the catalog is filtered

The preset in your client's config drives the model picker, so the picker must
follow the catalog rather than a hardcoded list. A chat-only client, or a client
that lets a user choose the tier, should list the catalog filtered to chat.
Filtering is a static, offline decision over the catalog metadata (endpoint types,
input modalities), so it works whether the catalog came from the live `GET /models`
call or from the fallback seed:

- Read `GET /models`; it needs no key, and with the user's `sk-orca-…` key it returns
  only what their workspace can call. Keep every `vendor/model` ID exactly as returned.
- Chat: keep models whose `supported_endpoint_types` include one of `openai`,
  `anthropic`, `gemini`, `openai-response`; drop anything that offers only
  non-chat endpoints such as an image generation endpoint.
- Image or file input: keep only chat models whose `architecture.input_modalities`
  explicitly lists `image` (or `file`). A model that omits the field is left out, and an
  attachment the selected model does not declare clears the selection instead of
  being sent.
- Scheduled evaluation: `scripts/evaluate_orcarouter_catalog.py` applies these rules
  (`scripts/orcarouter_model_filter.py` holds the rule set), prints the text and
  multimodal pickers, and exits non-zero if a picker would keep a model without a
  chat endpoint. A fetch failure falls back to a small, checked-in seed and says so.

```bash
python3 scripts/evaluate_orcarouter_catalog.py --show-config   # provider block for Codex
python3 scripts/evaluate_orcarouter_catalog.py --json          # live catalog + pickers
```

### 1. Paste an existing API key

Either tier works, and nothing is written to the repository:

```bash
export ORCAROUTER_API_KEY=sk-orca-…   # keep it out of shell history
```

Copy it from the OrcaRouter console and treat it like any other credential — never
put it in tracked config ([`.mcp.json`](../.mcp.json) is committed and must stay
free of tokens; the same rule applies to your provider config).

### 2. Connect with OrcaRouter (OAuth 2.0 + PKCE)

No client secret, no pre-registered redirect URI. The user authorizes in the browser
and the client receives a normal `sk-orca-…` key, billed to the user's account,
listed in their console, and revocable at
<https://www.orcarouter.ai/console/authorized-apps>.

- OpenCode: run `/connect` and pick OrcaRouter.
- Codex: run `codex login` if your version lists OrcaRouter.
- Clients without a built-in OrcaRouter login: the helper script implements both
  flows. `--connect` opens the consent page on a loopback callback and checks the
  returned `state`; `--code`/`--verifier` accepts an out-of-band code:

  ```bash
  python3 scripts/evaluate_orcarouter_catalog.py --connect
  python3 scripts/evaluate_orcarouter_catalog.py --code <code> --verifier <verifier>
  ```

  The script prints the consent URL for `--connect`; the verifier for `--code` comes
  from the client that started that flow. Always send `code_challenge_method=S256`
  (the `plain` method is rejected with `400`), the consent `scope` is `api`, and
  `app_name` is `Cybersec Toolkit`. The exchange goes to the auth origin only —
  `https://api.orcarouter.ai/v1/auth/keys` is a 404.

A `200` returns the key (the script verifies the `sk-orca-` prefix and that the
scope reads back as `api`, and never prints the key). Persistence follows the
client's own rule: a PKCE-issued key is a durable API key, not a refresh token, so
store it once in the client's credential store and reuse it (a user may issue at
most 10 per 24 hours) — never re-authorize on every launch. A `401` from the relay
means revoked: mark that account for reauthentication rather than retrying or
inventing a refresh grant.

### Provider evidence

- Inference and model list: [`GET https://api.orcarouter.ai/v1/models`](https://api.orcarouter.ai/v1/models),
  OpenAI-compatible `/chat/completions` on the same base.
- Authorization, exchange, revocation: <https://www.orcarouter.ai/auth>,
  <https://www.orcarouter.ai/api/v1/auth/keys>, revoke every app-issued key at
  <https://www.orcarouter.ai/console/authorized-apps>.
- Product: <https://www.orcarouter.ai>, <https://www.orcarouter.ai/cyber>,
  <https://www.orcarouter.ai/models?tier=cyber>.
- Terms and routing: <https://www.orcarouter.ai/terms>, <https://www.orcarouter.ai/legal>.
- Maintenance owner: OrcaRouter team; verified against the live catalog on 2026-11-08.

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

**Other providers:** use the client's own provider preset for any named vendor.
For an endpoint without a preset, define a custom `openai-compatible` provider that
points at that vendor's base URL.

**OrcaRouter Cyber Inference** — a named provider preset, not a custom
`openai-compatible` endpoint. [OrcaRouter](https://www.orcarouter.ai) is an
OpenAI-compatible AI gateway that routes many providers behind one endpoint:

```jsonc
{
  "provider": {
    "orcarouter": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "OrcaRouter Cyber Inference",
      "options": {
        "baseURL": "https://api.orcarouter.ai/v1",
        "apiKey": "{env:ORCAROUTER_API_KEY}"
      },
      "models": {
        "orcarouter/auto": {},
        "orcarouter/fusion": {}
      }
    }
  },
  "model": "orcarouter/orcarouter/auto"
}
```

- `ORCAROUTER_API_KEY` is an `sk-orca-…` key from the user's own OrcaRouter account;
  or drop the `options.apiKey` line and run OpenCode's `/connect` OAuth login
  (browser authorization, no client secret), which stores the same kind of key.
- Agent Firewall and Guardrails on the gateway screen prompts and tool calls
  before they reach the model. See
  [Cyber model provider](#cyber-model-provider-orcarouter-cyber-inference) below for the tier list,
  catalog filtering and the OAuth 2.0 + PKCE connect flow.
- Model IDs come from `GET https://api.orcarouter.ai/v1/models`; keep the
  `vendor/model` namespace as returned.

### Skills

OpenCode discovers skills from `.agents/skills/` (generated mirror of
`.claude/skills/`). Run `scripts/sync-skills.sh` after cloning to generate
the mirror. OpenCode also reads `.claude/skills/` directly.

### Non-interactive runs

`opencode run` reads the rest of its message from stdin when stdin is not a
terminal and waits for EOF, so a scripted call with an open stdin hangs before
it contacts the model. Close stdin explicitly:

```bash
opencode run -m <provider>/<model> "Call the cybersec-tools list_profiles tool once." < /dev/null
```

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

## DeepSeek Harness (dsh)

DeepSeek Harness is DeepSeek's open-source agent harness, built on an
everything-is-a-plugin architecture. MCP servers attach through the
`@deepseek-ai/dsh-mcp-client` plugin. The project is in developer preview and
documents compatibility-breaking changes between releases; review its
`SAFETY.md` before running it.

### dsh MCP configuration

Add one plugin entry per server to `$DSH_HOME/settings.yaml`:

```yaml
- id: mcp-cybersec
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: cybersec
    transport: stdio
    command: bash
    args: ['/absolute/path/to/cybersec-toolkit/scripts/mcp-launch.sh']
    env:
      CYBERSEC_MCP_ALLOW_EXTERNAL: '0'
      CYBERSEC_MCP_ALLOW_SCRIPTS: '0'
```

Replace the path with the actual repository location. This is a user-edited
example — do not copy the placeholder path into a tracked runtime
configuration.

Tools appear to the model as `mcp__cybersec__<tool>`, for example
`mcp__cybersec__guided_assessment`. Only tools are bridged; MCP resources and
prompts are not supported. Set `failOnStartupError: true` to abort the harness
when the server fails to connect instead of starting without its tools.

### No project-local configuration

Unlike OpenCode and Codex, dsh has no tracked project-config layer. The tree
composes each bundle's patch, then the profile's `cordis.patch.yml`, then the
home-level `$DSH_HOME/cordis.patch.yml`, then `--patch` overlays. Repository
configuration is therefore documented here rather than shipped as a tracked
file. Inspect the composed tree with `dsh --dump-config`.

### dsh skills discovery

The `skill-filesystem` provider scans `<projectRoot>/.agents/skills` by
default, where the project root is the nearest ancestor containing `.git`. The
generated mirror is discovered without extra configuration:

```bash
scripts/sync-skills.sh            # generate .agents/skills/ from .claude/skills/
scripts/sync-skills.sh --check    # verify the mirror is up to date
```

### Verification status

The MCP launch command and 15-tool inventory were verified directly over
stdio. The configuration above is derived from the upstream
`dsh-mcp-client` and `skill-filesystem` package references; it has not been
executed against a running harness here, so it is documented at the
configuration-example tier rather than as live tested.

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
restart. This is a code-execution opt-in; the code runs inside the sandbox
VM by default, and as the host user in `--local` mode.

### Sandbox will not start

The launcher reports the reason — no Kata runtime registered, missing image,
unreachable Docker daemon, or Node.js older than 22. See
[`SANDBOX.md`](SANDBOX.md#troubleshooting), or use `--local` to run on the
host without the VM boundary.

### Generated `.agents/skills` missing

Run `scripts/sync-skills.sh` to generate the mirror from `.claude/skills/`.

### Local model lacks sufficient tool-calling capability

Smaller local models may not reliably call MCP tools. Use a model with
proven tool-calling ability or a cloud provider model.

### Local model context window too small for the tool surface

Every client sends its own system prompt plus the schemas of all 15 tools on
every turn, and the tool descriptions are deliberately detailed so the model
picks the right tool and arguments. That preamble is large before the user's
first message: measured at about 16K tokens (OpenCode with Ollama), 44K
(Codex), and 136K (OpenCode with a custom `openai-compatible` provider, which
it does not compact). A model served with a 32K window rejects the request
(`context_length_exceeded`) or, on runtimes that truncate silently, drops the
start of the prompt and loses the tool definitions.

- Raise the runtime's context window first. Many Ollama models default to
  4K-8K; create a tag with a larger window instead of editing the service:

  ```bash
  printf 'FROM <model>\nPARAMETER num_ctx 32768\n' > Modelfile
  ollama create <model>:32k -f Modelfile
  ```

  Other local servers expose the same setting as a flag (for example
  `--max-context`).
- Restrict the exposed tools in the client when the window cannot grow (see
  the Hermes `tools.include` example above).
- Shortening the server's tool descriptions is a trade-off, not a fix: they
  are detailed on purpose, and small-context models are not a target of the
  server design.
