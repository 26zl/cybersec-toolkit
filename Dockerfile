FROM ubuntu:24.04

LABEL maintainer="26zl" \
      description="Cybersec Toolkit — 570 security tools, one command"

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
# Install uv as root, then move binary so it's available to all users.
RUN curl -LsSf https://astral.sh/uv/0.6.6/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv \
    && mv /root/.local/bin/uvx /usr/local/bin/uvx
RUN cd mcp_server && uv sync

# Give toolkit user ownership of the working directory.
RUN chown -R toolkit:toolkit /opt/cybersec-toolkit

USER toolkit

ENTRYPOINT ["sudo", "./install.sh"]
CMD ["--dry-run", "--profile", "full"]
