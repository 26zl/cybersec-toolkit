# Gemini CLI Project Context

@./AGENTS.md

## Gemini CLI-specific guidance

The imported `AGENTS.md` is the shared contract. It supplies the mandatory MCP
tool order, tool-first rules, approval gate for new tools, writeup requirement,
image-validation rule, security-variable semantics, testing workflow, and Agent
Skills behavior. Do not duplicate those rules here.

- Project MCP configuration: `.gemini/settings.json`.
- The project configuration uses the root-aware `scripts/mcp-launch.sh`; it does
  not select a model, provider, reasoning level, paid service, or API key.
- Run `scripts/sync-skills.sh` to generate `.agents/skills/` from the canonical
  `.claude/skills/` tree.
- Agent Skills discovery and activation are Gemini CLI behavior, independent of
  MCP compatibility. Keep `.claude/skills/` as the repository source and never
  edit the generated `.agents/skills/` mirror directly.
- Verify the imported project context with `/memory show`.
- Verify MCP connectivity with `/mcp list` and inspect the `cybersec-tools`
  server before relying on it for a workflow.
