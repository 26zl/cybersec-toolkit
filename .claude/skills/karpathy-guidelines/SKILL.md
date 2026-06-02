---
name: karpathy-guidelines
description: Behavioral coding-agent guidelines to reduce common LLM coding mistakes. Use when writing, reviewing, or refactoring code to avoid overcomplication, make surgical changes, surface assumptions, and define verifiable success criteria.
license: MIT
source: https://github.com/multica-ai/andrej-karpathy-skills
source_commit: 2c606141936f1eeef17fa3043a72095b4765b9c2
---

# Karpathy Guidelines

Behavioral guidelines to reduce common coding-agent mistakes, derived from Andrej Karpathy's observations on LLM coding pitfalls.

Tradeoff: these guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

Do not assume. Do not hide confusion. Surface tradeoffs.

Before implementing:

- State assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them instead of silently choosing one.
- If a simpler approach exists, say so.
- If something is unclear, stop, name the confusion, and ask.

## 2. Simplicity First

Minimum code that solves the problem. Nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No flexibility or configurability that was not requested.
- No error handling for impossible scenarios.
- If 200 lines could be 50, simplify.

Ask: would a senior engineer call this overcomplicated? If yes, simplify.

## 3. Surgical Changes

Touch only what is needed. Clean up only the mess introduced by the current change.

When editing existing code:

- Do not improve adjacent code, comments, or formatting as a side quest.
- Do not refactor things that are not part of the request.
- Match the existing style, even when a different style is tempting.
- If unrelated dead code appears, mention it instead of deleting it.

When the current change creates orphans:

- Remove imports, variables, functions, and tests made unused by this change.
- Do not remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

Define success criteria and loop until verified.

Transform vague implementation requests into verifiable goals:

- "Add validation" becomes "Write tests for invalid inputs, then make them pass."
- "Fix the bug" becomes "Write a test that reproduces it, then make it pass."
- "Refactor X" becomes "Ensure tests pass before and after."

For multi-step tasks, state a brief plan with verification for each step:

```text
1. [Step] -> verify: [check]
2. [Step] -> verify: [check]
3. [Step] -> verify: [check]
```

Strong success criteria let the agent loop independently. Weak criteria such as "make it work" require constant clarification.
