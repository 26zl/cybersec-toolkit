FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

LABEL maintainer="26zl" \
      description="Cybersec Toolkit — 670+ security tools, one command" \
      io.modelcontextprotocol.server.name="io.github.26zl/cybersec-toolkit"

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
# (corresponds to uv v0.12.4) to avoid an unpinned remote installer.
COPY --from=ghcr.io/astral-sh/uv:0.12.4@sha256:d0a6eca6c669dc7e9c51218707b8438a3d30402733d739dcc00adb3e213e8f5c /uv /usr/local/bin/uv
RUN cd mcp_server && uv sync --no-dev --frozen

# uv sync ran as root; hand the resulting venv to toolkit. The rest of the tree
# is already toolkit-owned via COPY --chown, so no full-tree re-chown is needed.
RUN chown -R toolkit:toolkit mcp_server

# Keep runtime `uv run` commands on the prebuilt, locked environment.
ENV UV_NO_SYNC=1

USER toolkit

ENTRYPOINT ["sudo", "./install.sh"]
CMD ["--dry-run", "--profile", "full"]
