FROM ubuntu:24.04

LABEL maintainer="26zl" \
      description="Cybersec Tools Installer — 665+ security tools, one command"

ENV DEBIAN_FRONTEND=noninteractive

# Prerequisites (mirrors README "Debian / Ubuntu / Kali" section)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl wget sudo \
        python3 python3-pip python3-venv python3-dev pipx \
        ruby ruby-dev golang-go default-jdk \
        build-essential libpcap-dev libssl-dev libffi-dev \
        zlib1g-dev libxml2-dev libxslt1-dev cmake \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Rust / Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /opt/cybersec-tools-installer
COPY . .
RUN chmod +x install.sh scripts/*.sh

ENTRYPOINT ["./install.sh"]
CMD ["--dry-run", "--profile", "full"]
