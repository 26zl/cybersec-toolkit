FROM ubuntu:24.04

LABEL maintainer="26zl" \
      description="Cybersec Tools Installer — 660+ security tools, one command"

ENV DEBIAN_FRONTEND=noninteractive

# Minimal bootstrap — just enough to run install.sh.
# install.sh → install_shared_deps() handles all runtimes, compilers,
# and dev libraries automatically via SHARED_BASE_PACKAGES.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl wget sudo ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cybersec-tools-installer
COPY . .
RUN chmod +x install.sh scripts/*.sh

ENTRYPOINT ["./install.sh"]
CMD ["--dry-run", "--profile", "full"]
