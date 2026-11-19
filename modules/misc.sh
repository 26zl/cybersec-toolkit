#!/usr/bin/env bash
# shellcheck disable=SC2034  # Arrays are consumed by scripts that source this module
# Module: Misc / Dependencies / Cross-domain tools
# Build deps, runtimes, utilities, C2 frameworks, social engineering,
# post-exploitation, mobile, resources

MISC_PACKAGES=()

MISC_PIPX=(arsenal-cli sploitscan faraday-cli)

MISC_GO=(
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
)

MISC_GIT=(
    # Resources
    "SecLists=https://github.com/danielmiessler/SecLists.git"
    "PayloadsAllTheThings=https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    "InternalAllTheThings=https://github.com/swisskyrepo/InternalAllTheThings.git"
    # Enumeration
    "PEASS-ng=https://github.com/peass-ng/PEASS-ng.git"
    "linux-smart-enumeration=https://github.com/diego-treitos/linux-smart-enumeration.git"
    "SUDO_KILLER=https://github.com/TH3xACE/SUDO_KILLER.git"
    # General
    "CyberChef=https://github.com/gchq/CyberChef.git"
)

# Tools gated by INCLUDE_C2. Loki-C2 is cloned as a resource and requires manual setup.
MISC_C2_GIT=(
    # Social engineering / phishing
    "SET=https://github.com/trustedsec/social-engineer-toolkit.git"
    "Zphisher=https://github.com/htr-tech/zphisher.git"
    "EvilGoPhish=https://github.com/fin3ss3g0d/evilgophish.git"
    "SquarePhish=https://github.com/secureworks/squarephish.git"
    "CredMaster=https://github.com/knavesec/CredMaster.git"
    "Modlishka=https://github.com/drk1wi/Modlishka.git"
    # C2 / adversary emulation
    "Caldera=https://github.com/apache/caldera.git"
    "Loki-C2=https://github.com/boku7/Loki.git"
    # Gated post-exploitation tools
    "LaZagne=https://github.com/AlessandroZ/LaZagne.git"
    "mimipenguin=https://github.com/huntergregal/mimipenguin.git"
    "PyExfil=https://github.com/ytisf/PyExfil.git"
    "usbkill=https://github.com/hephaest0s/usbkill.git"
    # C2 frameworks (heavy; each has its own build/compose — cloned here)
    "Mythic=https://github.com/its-a-feature/Mythic.git"
    "Havoc=https://github.com/HavocFramework/Havoc.git"
    "PoshC2=https://github.com/nettitude/PoshC2.git"
    "merlin=https://github.com/Ne0nd0g/merlin.git"
)

# Git repo names for verify/remove (general). remove.sh removes both sets; verify.sh
# checks MISC_C2_GIT_NAMES only when INCLUDE_C2=true.
MISC_GIT_NAMES=(
    SecLists PayloadsAllTheThings InternalAllTheThings
    PEASS-ng linux-smart-enumeration SUDO_KILLER
    CyberChef
)
MISC_C2_GIT_NAMES=(
    SET Zphisher EvilGoPhish SquarePhish CredMaster Modlishka
    Caldera Loki-C2
    LaZagne mimipenguin PyExfil usbkill
    Mythic Havoc PoshC2 merlin
)
MISC_GO_BINS=(gf anew qsreplace notify pdtm)

# SecLists ships rockyou only as a tarball; unpack it so wordlist flags can use the .txt.
extract_seclists_rockyou() {
    local dir="${GITHUB_TOOL_DIR:-}/SecLists/Passwords/Leaked-Databases"
    local archive="$dir/rockyou.txt.tar.gz"
    [[ -f "$archive" && ! -e "$dir/rockyou.txt" && ! -L "$dir/rockyou.txt" ]] || return 0
    if ! _validate_release_archive "$archive" tar >> "$LOG_FILE" 2>&1 \
        || ! python3 - "$archive" "$dir" >> "$LOG_FILE" 2>&1 <<'PY'
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile

temporary = None
try:
    with tarfile.open(sys.argv[1], "r:gz") as archive:
        members = [member for member in archive.getmembers() if PurePosixPath(member.name) == PurePosixPath("rockyou.txt")]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError("Expected exactly one regular rockyou.txt member")
        with archive.extractfile(members[0]) as source:
            with tempfile.NamedTemporaryFile(prefix=".rockyou.", dir=sys.argv[2], delete=False) as output:
                temporary = output.name
                shutil.copyfileobj(source, output)
                os.fchmod(output.fileno(), 0o644)
        os.link(temporary, Path(sys.argv[2], "rockyou.txt"))
finally:
    if temporary is not None:
        os.unlink(temporary)
PY
    then
        log_warn "Could not safely extract $archive"
        TOTAL_TOOL_FAILURES=$((TOTAL_TOOL_FAILURES + 1))
        return 1
    fi
}

install_module_misc() {
    [[ ${#MISC_PACKAGES[@]} -gt 0 ]] && install_apt_batch "Misc - Packages" "${MISC_PACKAGES[@]}"

    install_pipx_batch "Misc - Python" "${MISC_PIPX[@]}"

    install_go_batch "Misc - Go" "${MISC_GO[@]}"

    # Git repos (resources, post-exploitation, CTF)
    install_git_batch "Misc - Git" "${MISC_GIT[@]}"
    extract_seclists_rockyou

    # Binary releases (skipped on Termux — Linux/glibc binaries)
    install_binary_releases "${BINARY_RELEASES_MISC[@]}"

    # C2 + credential-phishing/social-engineering frameworks — only with INCLUDE_C2.
    if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
        log_info "Installing C2 / phishing frameworks (INCLUDE_C2 enabled)..."
        [[ ${#MISC_C2_GIT[@]} -gt 0 ]] && install_git_batch "Misc - C2/Phishing (Git)" "${MISC_C2_GIT[@]}"
        [[ ${#BINARY_RELEASES_MISC_C2[@]} -gt 0 ]] && install_binary_releases "${BINARY_RELEASES_MISC_C2[@]}"
    else
        log_info "Skipping C2 / phishing frameworks (INCLUDE_C2 disabled — use --include-c2 or the redteam/full profile)"
    fi

    # Docker: OSINT + C2 frameworks that need multi-service orchestration.
    if [[ "${ENABLE_DOCKER:-false}" == "true" ]]; then
        if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
            log_info "Installing C2 frameworks via Docker..."
            docker_pull "bcsecurity/empire" "Empire" || true
        fi
    else
        if [[ "${INCLUDE_C2:-false}" == "true" ]]; then
            log_warn "Docker-based C2 frameworks (Empire) require --enable-docker. Skipping."
        fi
    fi
}
