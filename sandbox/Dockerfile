FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl file git binutils nmap python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.12.4@sha256:d0a6eca6c669dc7e9c51218707b8438a3d30402733d739dcc00adb3e213e8f5c /uv /usr/local/bin/uv

WORKDIR /opt/cybersec-toolkit
# Copy only runtime and installer sources; local credentials never enter layers.
COPY mcp_server/*.py mcp_server/pyproject.toml mcp_server/uv.lock mcp_server/README.md ./mcp_server/
COPY tools_config.json install.sh ./
COPY lib/ ./lib/
COPY modules/ ./modules/
COPY profiles/ ./profiles/
COPY scripts/ ./scripts/
COPY sandbox/guest-mcp.json ./sandbox/guest-mcp.json
RUN uv sync --directory mcp_server --frozen --no-dev --no-editable

# Additional tool profiles are installed at build time, before dropping privilege.
ARG TOOLKIT_PROFILE=""
RUN if [ -n "$TOOLKIT_PROFILE" ]; then \
        bash install.sh --profile "$TOOLKIT_PROFILE" --production --yes; \
    fi

RUN groupadd --gid 10001 toolkit \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash toolkit \
    && install -d -o 10001 -g 10001 /workspace /var/log/cybersec \
    && rm -f /etc/sudoers.d/toolkit \
    && find /usr /opt -xdev -type f -perm /6000 -exec chmod a-s {} +

ENV HOME=/home/toolkit \
    UV_NO_SYNC=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CYBERSEC_INSTALLER_ROOT=/opt/cybersec-toolkit \
    CYBERSEC_MCP_ALLOW_EXTERNAL=0 \
    CYBERSEC_MCP_ALLOW_SCRIPTS=0 \
    CYBERSEC_MCP_AUDIT_REQUIRED=1 \
    CYBERSEC_MCP_AUDIT_STREAM=1 \
    CYBERSEC_MCP_AUDIT_LOG=/var/log/cybersec/audit.log
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/opt/cybersec-toolkit/mcp_server/.venv/bin/python", "-m", "mcp_server.server"]
