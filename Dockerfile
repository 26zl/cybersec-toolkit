# A named stage (not COPY --from=<image>) so Dependabot tracks the uv image.
FROM ghcr.io/astral-sh/uv:0.13.1@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 AS uv

FROM ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944

LABEL maintainer="26zl" \
      description="Cybersec Toolkit — 670+ security tools, one command" \
      io.modelcontextprotocol.server.name="io.github.26zl/cybersec-toolkit"

ENV DEBIAN_FRONTEND=noninteractive

# Minimal bootstrap — just enough to run install.sh.
# install.sh → install_shared_deps() handles all runtimes, compilers,
# and dev libraries automatically via SHARED_BASE_PACKAGES.
# The base image ships an unpackaged pebble Go binary (known HIGH CVEs) that
# this project never uses; drop it so image scanners stay clean.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        git curl wget sudo ca-certificates python3 \
    && rm -rf /usr/bin/pebble /var/lib/pebble \
    && rm -rf /var/lib/apt/lists/*

# Passwordless sudo — install.sh needs broad root throughout, so this image is a
# build/install convenience, not a hardened sandbox (code in it is effectively root).
RUN useradd -m -s /bin/bash toolkit \
    && echo "toolkit ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/toolkit

WORKDIR /opt/cybersec-toolkit
COPY --chown=toolkit:toolkit . .
RUN chmod +x install.sh scripts/*.sh

# MCP server: uv from the digest-pinned stage above; deps resolved now so `uv run` works offline.
COPY --from=uv /uv /usr/local/bin/uv
RUN cd mcp_server && uv sync --no-dev --frozen

# uv sync ran as root; hand the resulting venv to toolkit. The rest of the tree
# is already toolkit-owned via COPY --chown, so no full-tree re-chown is needed.
RUN chown -R toolkit:toolkit mcp_server

# Keep runtime `uv run` commands on the prebuilt, locked environment.
ENV UV_NO_SYNC=1

USER toolkit

ENTRYPOINT ["sudo", "./install.sh"]
CMD ["--dry-run", "--profile", "full"]
