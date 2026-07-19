FROM ubuntu:26.04@sha256:53958ec7b67c2c9355df922dd08dbf0360611f8c3cdb656875e81873db9ffdba

LABEL maintainer="26zl" \
      description="Cybersec Toolkit — 580+ security tools, one command"

ENV DEBIAN_FRONTEND=noninteractive

# Minimal bootstrap — just enough to run install.sh.
# install.sh → install_shared_deps() handles all runtimes, compilers,
# and dev libraries automatically via SHARED_BASE_PACKAGES.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        git curl wget sudo ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

# Passwordless sudo — install.sh needs broad root throughout, so this image is a
# build/install convenience, not a hardened sandbox (code in it is effectively root).
RUN useradd -m -s /bin/bash toolkit \
    && echo "toolkit ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/toolkit

WORKDIR /opt/cybersec-toolkit
COPY --chown=toolkit:toolkit . .
RUN chmod +x install.sh scripts/*.sh

# MCP server: install uv + resolve dependencies so `uv run` works offline.
# uv is pulled from the official Astral image, pinned by SHA256 digest
# (corresponds to uv v0.11.25). Replaces a curl-pipe install to satisfy
# Scorecard's PinnedDependencies check.
COPY --from=ghcr.io/astral-sh/uv:0.11.25@sha256:1e3808aa9023d0980e7c15b1fa7c1ac16ff35925780cf5c459858b2d693f01a9 /uv /uvx /usr/local/bin/
RUN cd mcp_server && uv sync

# uv sync ran as root; hand the resulting venv to toolkit. The rest of the tree
# is already toolkit-owned via COPY --chown, so no full-tree re-chown is needed.
RUN chown -R toolkit:toolkit mcp_server

USER toolkit

ENTRYPOINT ["sudo", "./install.sh"]
CMD ["--dry-run", "--profile", "full"]
