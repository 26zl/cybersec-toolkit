---
name: guided-assessment
description: Pick and run the right MCP tools for an authorized security task. Default companion mode auto-detects the workflow/problem type, classifies target/finding input, returns triage gates, recommended skills, reporting next steps, selects from all modules/profiles, recommends the next command, and guides step-by-step; opt-in autonomous starts an auto-solver loop over the full MCP toolchain via run_tool/run_pipeline/run_script, including AI-created scoped helper scripts when tools/pipelines are not enough, under policy. Use for "what tools for this", "classify this finding", "triage this report", "run the right tools for me", "assess/triage this authorized target", or - when explicitly asked - "autonomously solve this". Clears authorization-gate once, then stays strictly in scope and never bypasses MCP policy.
---

# Guided assessment

Helps choose and run the right tools for an **authorized** task (CTF/lab/owned host, or a
written-permission bounty/pentest scope) via the `guided_assessment` MCP tool. It does
**not** bypass the policy layer: every executed command goes through the same `run_tool`
engine — registry allowlist, argument sanitizer, blocked flags, target-scope/external
policy, timeouts, and audit logging.

The default is **companion mode**, not autonomous: it figures out the workflow/problem
type + toolset from the full registry/modules/profiles, then helps the user solve
step-by-step through MCP tools. Full autonomy is an explicit opt-in
(`mode="autonomous"`).

## Pre-flight (authorization floor)

For any network target, run **`authorization-gate`** first and confirm: the target is a
CTF/lab/owned asset or covered by written authorization; the exact in-scope hosts/apps/
files; and, for public targets, that `CYBERSEC_MCP_ALLOW_EXTERNAL=1` is intentional. If
authorization/scope is unclear, stay in default `mode="companion"` and ask for the
missing scope before running network commands.

## Default: let MCP pick the tools

```text
guided_assessment(target="<url-host-ip-or-file>")   # mode/workflow/target_type default to companion/auto/auto
```

With `workflow="auto"` + `target_type="auto"` (the defaults) the tool infers the problem
type from the target (file → CTF category by extension; URL → web_app/api; host/IP →
network) and returns the recommended methodology, the right tools with install status,
ready commands, a companion directive, and `recommended_next_command`. It also returns
`classification`, `triage_gate`, `recommended_skills`, and `reporting_next_steps` so the
agent can route URL/finding input through classify -> triage -> report without a separate
CLI. The agent should say what it recommends running and why, then continue by using
`run_tool`, `run_pipeline`, and `run_script` as the user approves. Read `auto_detected`
to see what it picked; pass an explicit `workflow`/`target_type` to override.

If the user already has a finding summary, pass it as `finding="..."`. The MCP response
classifies it but does not echo the raw finding text.

## Modes

- `companion` (default): auto-select tools from the full registry/modules/profiles and
  help the user solve step-by-step through MCP tool calls. It recommends the next command
  and waits for user approval or a clear "continue" before running it.
- `autonomous` (opt-in — only when the user explicitly wants it): start the auto-solver
  loop over the full MCP toolchain. This call runs the selected bootstrap steps, then
  the client agent keeps solving with `run_tool`, `run_pipeline`, `run_script`, registry
  lookup, advisors, and relevant skills under MCP policy. If normal tools and pipelines
  do not make progress and programming logic is the smallest reliable path, the AI/client
  agent creates, saves, and runs scoped helper scripts for the user; reusable multi-step
  helpers go under `manual_scripts/`. Simple recon/HTTP commands such as `curl` remain
  normal `run_tool` calls.

## Autonomous mode (opt-in)

Trigger only when the user explicitly asks to auto-solve. After authorization clears, call
`guided_assessment(target=..., mode="autonomous", authorization_confirmed=true)`. Treat the
returned `autonomous` block as the solver contract: the MCP server provides target
classification, recommended tools, install status, bootstrap output, and the list of MCP
tools the agent should use next. Continue the user-approved loop under MCP policy, pausing
if scope, impact, or risk changes:

1. **Discover/enumerate** — start from the bootstrap output, widen with the full MCP
   toolchain; pull methodology from `suggest_for_ctf`/`suggest_for_bounty`, `list_tools`,
   `check_installed`, `get_tool_info`, and the relevant `ctf-*`/`bounty-*`/`offensive-*`/
   `web2-vuln-classes`/`web3-audit` skills.
2. **Hypothesize** — name the most promising lead from real output.
3. **Exploit** — use the right tool, and `run_script` for real logic (pwntools/ROP, z3/RSA,
   custom HTTP chains, deserialization, smart-contract PoCs). Build incrementally. If
   repeated tool attempts do not progress and custom logic is required, create a focused
   helper for the user, persist it in `manual_scripts/` when it should be kept, and run it
   via `run_script`.
4. **Iterate/pivot** — read actual results, change one variable at a time, pivot after 2–3
   failures.
5. **Extract** — flag (CTF) or minimal PoC (bounty/pentest); don't over-exfiltrate.
6. **Triage/report** — read `triage_gate`, run `triage-validation`, then
   `evidence-hygiene`, then `report-writing` only if every gate passes.
7. **Writeup** — finish with `writeup-template`; route findings via `finding-triage` then
   `security-comms` when needed.

The scaffold the tool returns is a starting point, not the limit. The solver can choose
from the whole registry/toolchain, but every follow-up command must still stay inside
authorization and MCP policy.

## Scope discipline (all modes)

- Touch only in-scope assets; if a lead points out of scope, stop and report it.
- C2/phishing/DoS/credential-stuffing/destructive actions are never run.
- External targets blocked → set `CYBERSEC_MCP_ALLOW_EXTERNAL=1` for the authorized scope
  and restart, then resume. If `run_tool` is blocked by policy, fix config/scope — don't
  work around it.
- Before sharing reports, writeups, screenshots, HAR files, or PoC output, use
  `evidence-hygiene` to redact cookies, tokens, PII, secrets, and unrelated data.
