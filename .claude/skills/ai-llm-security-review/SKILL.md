---
name: ai-llm-security-review
description: Use for AI/LLM security assessments, prompt injection, RAG security, agent/tool permissioning, model supply chain, LLM red teaming, AI governance, eval design, data leakage, jailbreak testing, and secure AI application review.
---

# AI and LLM security review

Use this skill for AI applications, agents, RAG systems, model gateways, prompt chains, evals, and LLM governance.

## Review workflow

1. Inventory the AI system: model/provider, prompts, tools, RAG sources, memory, logs, user roles, secrets, data classes, and downstream actions.
2. Threat model trust boundaries:
   - user input to prompt
   - retrieved content to model
   - model output to tools
   - tool output to user
   - logs/traces to operators
3. Test high-risk paths:
   - direct and indirect prompt injection
   - data exfiltration from RAG or memory
   - insecure tool invocation
   - overbroad agent permissions
   - jailbreaks that change policy or role
   - model/provider key leakage
   - training/eval data contamination
4. Recommend controls:
   - least-privilege tool scopes
   - allowlisted tool schemas and argument validation
   - retrieval filtering and source attribution
   - secret redaction before prompts/logs
   - output validation before side effects
   - human approval for destructive or external actions
   - continuous evals and regression prompts

## Deliverables

Return findings as:

| Risk | Attack path | Impact | Evidence | Control | Test to keep fixed |
| --- | --- | --- | --- | --- | --- |

When the task involves current AI regulation or sector obligations, verify against current official sources before making definitive claims.
