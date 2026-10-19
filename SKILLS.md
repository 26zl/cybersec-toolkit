#!/usr/bin/env bash
# shellcheck shell=bash
#
# update-skills.sh
# =============================================================================
# Pin management and drift detection for vendored, third-party skill sources.
#
# Vendored skills are copied into this repository and *pinned* to an exact
# upstream commit.  A pin is recorded in four places which MUST agree:
#
#   1. SKILLS.md                  (human-readable registry table)
#   2. THIRD_PARTY_NOTICES.md     (license / provenance notice)
#   3. scripts/update-skills.sh   (SOURCE_PINS below — this file)
#   4. <skill>/SKILL.md           (YAML frontmatter: upstream_commit)
#
# Governance (see AGENTS.md, "Skills (portable via sync)"):
#
#   * Re-vendoring is manual and reviewed.  This script NEVER rewrites pins.
#   * A pin may only be bumped once the upstream HEAD is at least COOLDOWN_DAYS
#     old — a defence against adopting a malicious / force-pushed commit.
#
# Usage
#   scripts/update-skills.sh [OPTIONS]
#
# Options
#   --check-pins        Offline only: verify the four pin locations agree.
#   --check-upstream    Network only: compare pins to upstream HEAD + cooldown.
#   --all               Both (default).
#   --json              Emit a machine-readable report on stdout.
#   --quiet             Errors only.
#   --verbose           Include DEBUG diagnostics.
#   --timeout SECS      Network timeout per git invocation (default: 45).
#   --cooldown DAYS     Minimum upstream commit age (default: 3).
#   --no-color          Disable ANSI colours (also honoured: NO_COLOR).
#   -h | --help         This text.
#
# Exit codes
#   0  success, no drift
#   1  usage error
#   2  environment / precondition failure (missing tool, unreadable file)
#   3  pin-validation failure (malformed pin, inconsistent registry)
#   4  network / remote failure
#   5  drift detected (bump required)
#
# Requirements: bash >= 4.3, git >= 2.20, standard POSIX userland.
# =============================================================================