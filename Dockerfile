FROM ubuntu:24.04@sha256:c4a8d5503dfb2a3eb8ab5f807da5bc69a85730fb49b5cfca2330194ebcc41c7b

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

# Create non-root user with sudo access (install.sh requires root for apt).
RUN useradd -m -s /bin/bash toolkit \
    && echo "toolkit ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/toolkit

WORKDIR /opt/cybersec-toolkit
COPY . .
RUN chmod +x install.sh scripts/*.sh

# MCP server: install uv + resolve dependencies so `uv run` works offline.
# uv is pulled from the official Astral image, pinned by SHA256 digest
# (corresponds to uv v0.11.7). Replaces a curl-pipe install to satisfy
# Scorecard's PinnedDependencies check.
COPY --from=ghcr.io/astral-sh/uv:0.11.7@sha256:240fb85ab0f263ef12f492d8476aa3a2e4e1e333f7d67fbdd923d00a506a516a /uv /uvx /usr/local/bin/
RUN cd mcp_server && uv sync

# Give toolkit user ownership of the working directory.
RUN chown -R toolkit:toolkit /opt/cybersec-toolkit

USER toolkit

ENTRYPOINT ["sudo", "./install.sh"]
CMD ["--dry-run", "--profile", "full"]
