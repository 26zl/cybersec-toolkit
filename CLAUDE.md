# Claude Code Project Context

@AGENTS.md

## Claude Code-specific guidance

The imported `AGENTS.md` is the shared contract. Keep architecture, security,
testing, MCP tool order, approval gates, image validation, writeups, and tool
contribution rules there. This file contains only Claude Code-specific behavior.

### MCP

- Project MCP configuration: `.mcp.json`.
- Verify the server and tools with `/mcp` inside Claude Code.
- The tracked configuration launches the same governed FastMCP server described
  in `AGENTS.md`; do not bypass its policy layer.
- For Windows/WSL, use the WSL launch form documented in
  `mcp_server/README.md` and run `scripts/sync-wsl.sh` after server changes.

### Agent Skills and plugin marketplace

- `.claude/skills/` is the repository source of truth for Agent Skills and is
  discovered directly by Claude Code.
- After editing skills, run `scripts/sync-skills.sh` so clients using
  `.agents/skills/` receive the generated mirror.
- The repository is a Claude Code plugin marketplace. Its plugin manifest points
  to `.claude/skills/`; installation is available through
  `/plugin marketplace add 26zl/cybersec-toolkit`.
- Skill discovery does not replace the MCP server: skills provide methodology and
  context, while MCP provides governed discovery and execution.

### Claude Code verification

1. Run `/mcp` and confirm `cybersec-tools` is connected.
2. Confirm a relevant skill can be discovered from `.claude/skills/`.
3. Run `make check` after the final repository edits.
