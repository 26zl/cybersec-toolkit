FROM ubuntu:26.04@sha256:f3d28607ddd78734bb7f71f117f3c6706c666b8b76cbff7c9ff6e5718d46ff64

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
# (corresponds to uv v0.11.21). Replaces a curl-pipe install to satisfy
# Scorecard's PinnedDependencies check.
COPY --from=ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 /uv /uvx /usr/local/bin/
RUN cd mcp_server && uv sync

# Give toolkit user ownership of the working directory.
RUN chown -R toolkit:toolkit /opt/cybersec-toolkit

USER toolkit

ENTRYPOINT ["sudo", "./install.sh"]
CMD ["--dry-run", "--profile", "full"]
