---
name: skill-curation-router
description: Use when choosing, ranking, curating, pruning, or de-duplicating Claude cybersecurity skills; when a broad cybersecurity task could match many skills; or when deciding which skill should be loaded first.
---

# Skill curation router

Use this skill to reduce noise when a task could activate too many cybersecurity skills.

## Routing workflow

1. Check `.claude/skills/CURATION.md` for tier and domain anchors.
1. For fuzzy prompts, run:

```bash
python3 scripts/curate_claude_skills.py --query "<user task>" --top 10
```

1. Start with one T0/T1 anchor skill, then add one specialist skill only when the target platform, tool, or technique is clear.
1. Prefer coverage anchor skills for GRC, AI/LLM, IoT/embedded, mainframe, telecom/5G, SAP/ERP, and supply-chain/product-security tasks.
1. Treat T3 skills as exact-match playbooks. Do not load several near-duplicate T3 skills just because their descriptions overlap.

## Selection policy

- Broad program question: use a T1 coverage anchor or project workflow skill.
- Specific tool/vendor/task: use the highest-ranked exact specialist from the query helper.
- Offensive/simulation task: confirm authorization and use the least invasive workflow first.
- Current regulation, standard, or product behavior: verify against current official sources before making a definitive claim.
