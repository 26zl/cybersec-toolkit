FROM ubuntu:24.04

LABEL maintainer="26zl" \
      description="Cybersec Toolkit — 568 security tools, one command"

ENV DEBIAN_FRONTEND=noninteractive

# Minimal bootstrap — just enough to run install.sh.
# install.sh → install_shared_deps() handles all runtimes, compilers,
# and dev libraries automatically via SHARED_BASE_PACKAGES.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        git curl wget sudo ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cybersec-toolkit
COPY . .
RUN chmod +x install.sh scripts/*.sh

# MCP server: install uv + resolve dependencies so `uv run` works offline.
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"
RUN cd mcp_server && uv sync

ENTRYPOINT ["./install.sh"]
CMD ["--dry-run", "--profile", "full"]
