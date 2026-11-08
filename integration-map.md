# Integration map — 26zl/cybersec-toolkit

- Repository: https://github.com/26zl/cybersec-toolkit
- Default branch / PR base: `main`
- Base SHA: `f38b965cea487ae5ac8e1d534ef8a59c0d203c44`
- Working branch: `feat/orcarouter-provider` (local only)
- Cyber scope (cyber-classifier): `both` (red-team and blue-team tooling)
- Integration tier (feasibility-classifier + manual review): `docs`
  - confidence 0.72, scope `none` for code-level client; the repo ships no model
    client, no provider registry, no UI. The only provider surface is
    `docs/AI_CLIENTS.md` "Optional provider examples" (OpenCode jsonc) and the
    Codex `.codex/config.toml` snippet pattern.
  - `has_oauth_seam`: false. `serve_hint`: none.

## Where a provider fits

| Surface | File | Current state |
| --- | --- | --- |
| Provider docs (OpenCode) | `docs/AI_CLIENTS.md` | generic `openai-compatible` example, no named OrcaRouter provider |
| Client configs | `.mcp.json`, `opencode.jsonc`, `.codex/config.toml`, `.gemini/settings.json` | MCP server only; no model/provider keys |
| Model client code | none | — |
| Catalog / capability filtering | none | — |
| Auth | none | — |

## Plan (docs tier + supporting helper)

1. `docs/AI_CLIENTS.md`: replace the generic `openai-compatible` example with the
   named **OrcaRouter Cyber Inference** provider (`orcarouter`, base
   `https://api.orcarouter.ai/v1`, `{env:ORCAROUTER_API_KEY}`), and add a
   "Cyber model provider (OrcaRouter Cyber Inference)" section with the tier table,
   catalog filtering rules, API-key path, OAuth 2.0 + PKCE connect path and
   provider evidence links.
2. `scripts/orcarouter_model_filter.py`: the catalog filter rule set (chat endpoint
   types, media input modalities, fail closed).
3. `scripts/evaluate_orcarouter_catalog.py`: provider block, live catalog fetch with
   checked-in fallback seed, pickers, PKCE helper (loopback + out-of-band), live
   chat check.
4. `mcp_server/tests/test_orcarouter_catalog.py`: 24 tests covering catalog bounds,
   pickers, seed fallback, HTTPS enforcement, both credential adapters, PKCE
   (S256, state check), terminal 401 handling, CLI.

No secrets, personal data or attack content are added. All live checks use
credentials from environment variables only.
