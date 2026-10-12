#!/usr/bin/env bash
# Deterministic hash of the sources baked into the sandbox image. The Makefile
# stamps it onto the image as a label at build time; `install.sh --doctor` reads
# the label back and compares, so a sandbox image built before a server/policy
# change is reported stale instead of silently running old code.
#
# Content only (no names/mtimes beyond sha256sum's own output), stable ordering.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The files COPYed into sandbox/Dockerfile that determine the server's behaviour.
mapfile -t files < <(
    printf '%s\n' \
        mcp_server/*.py \
        mcp_server/pyproject.toml \
        mcp_server/uv.lock \
        tools_config.json \
        sandbox/Dockerfile \
        sandbox/guest-mcp.json \
        | LC_ALL=C sort -u
)

LC_ALL=C sha256sum "${files[@]}" | sha256sum | cut -c1-64
