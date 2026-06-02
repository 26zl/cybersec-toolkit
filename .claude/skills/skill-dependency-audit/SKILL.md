---
name: skill-dependency-audit
description: Use when auditing optional Python dependencies for vendored Claude skill helper scripts, checking missing imports, deciding whether dependencies belong in MCP runtime, or troubleshooting a skill script that fails with ModuleNotFoundError.
---

# Skill helper dependency audit

Use this skill when a vendored `.claude/skills/*/scripts/*.py` helper fails to import, or when deciding whether optional skill dependencies should be installed.

## Workflow

1. Run the dependency auditor:

```bash
python3 scripts/audit_skill_dependencies.py
```

1. For JSON output:

```bash
python3 scripts/audit_skill_dependencies.py --json
```

1. For CI-like behavior:

```bash
python3 scripts/audit_skill_dependencies.py --fail-on-missing
```

## Policy

- Do not add every vendored helper dependency to `mcp_server/pyproject.toml`.
- Keep MCP runtime minimal unless the MCP server imports the dependency directly.
- Treat vendored skill helper dependencies as optional, task-specific extras.
- If a helper becomes a supported project feature, add tests and promote only its required dependencies.

## Output interpretation

- `third_party_imports`: import names found in skill helper scripts.
- `missing`: imports not available in the active Python environment.
- `examples`: representative scripts that import that module.
