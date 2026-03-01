"""Tools database — loads tools_config.json, .versions, checks install status."""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

# Project root: CYBERSEC_INSTALLER_ROOT env var, or parent of mcp_server/
PROJECT_ROOT = Path(os.environ.get("CYBERSEC_INSTALLER_ROOT", Path(__file__).parent.parent))

# Pipx package name → binary name mapping (from scripts/verify.sh:130-155).
# Most pipx packages install a binary with the same name — these are the exceptions.
PIPX_BIN_NAMES: dict[str, str] = {
    "arsenal-cli": "arsenal",
    "sherlock-project": "sherlock",
    "osrframework": "usufy",
    "raccoon-scanner": "raccoon",
    "factordb-python": "factordb",
    "z3-solver": "z3",
    "pwntools": "pwn",
    "boofuzz": "boo",
    "frida-tools": "frida",
    "volatility3": "vol",
    "oletools": "olevba",
    "mvt": "mvt-android",
    "hachoir": "hachoir-metadata",
    "peepdf-3": "peepdf",
    "impacket": "impacket-secretsdump",
    "certipy-ad": "certipy",
    "bloodhound": "bloodhound-python",
    "ldapsearchad": "ldapsearch-ad.py",
    "sipvicious": "sipvicious_svmap",
    "scoutsuite": "scout",
    "sigma-cli": "sigma",
    "quark-engine": "quark",
    "slither-analyzer": "slither",
    "mythril": "myth",
    "eth-ape": "ape",
    "vcdvcd": "vcdcat",
    "lascar": "lascarctl",
}

# Module descriptions (from lib/common.sh:1212-1231).
MODULE_DESCRIPTIONS: dict[str, str] = {
    "misc": "Security tools, utilities, resources, C2, social engineering",
    "networking": "Port scanning, packet capture, tunneling, MITM",
    "recon": "Subdomain enum, OSINT, intelligence gathering",
    "web": "Web app testing, fuzzing, scanning",
    "crypto": "Cryptography analysis, cipher cracking",
    "pwn": "Binary exploitation, shellcode, fuzzers",
    "reversing": "Disassembly, debugging, binary analysis",
    "forensics": "Disk/memory forensics, file carving",
    "enterprise": "AD, Kerberos, LDAP, Azure AD, lateral movement",
    "wireless": "WiFi, Bluetooth, SDR",
    "cracking": "Hash cracking, brute force, wordlists",
    "stego": "Steganography tools",
    "cloud": "AWS/Azure/GCP security",
    "containers": "Docker/Kubernetes security",
    "blueteam": "Defensive security, IDS/IPS, SIEM, IR, malware analysis",
    "mobile": "Android/iOS app testing, APK analysis",
    "blockchain": "Smart contract auditing, analysis, reversing",
    "llm": "LLM red teaming, prompt injection, AI security",
}

# Docker image registry (from lib/installers.sh:1611-1621).
# Maps tool label → docker image.
DOCKER_IMAGES: dict[str, str] = {
    "BeEF": "beefproject/beef",
    "Empire": "bcsecurity/empire",
    "MobSF": "opensecurity/mobile-security-framework-mobsf",
    "SpiderFoot": "spiderfoot/spiderfoot",
    "BloodHound CE": "specterops/bloodhound",
    "TheHive": "strangebee/thehive:latest",
    "Cortex": "thehiveproject/cortex:latest",
    "Echidna": "trailofbits/echidna",
    "PentAGI": "vxcontrol/pentagi:latest",
}


class ToolsDatabase:
    """Loads and queries the cybersec tools registry."""

    def __init__(self, project_root: Optional[Path] = None):
        self.root = Path(project_root) if project_root else PROJECT_ROOT
        self._tools: list[dict] = []
        self.tools_by_name: dict[str, dict] = {}
        self._versions: dict[str, dict] = {}
        self._versions_ts: float = 0.0  # last reload timestamp
        self._load_tools()

    def _load_tools(self) -> None:
        config_path = self.root / "tools_config.json"
        with open(config_path, "r", encoding="utf-8") as f:
            self._tools = json.load(f)
        self.tools_by_name = {t["name"]: t for t in self._tools}

    def reload_versions(self, ttl: float = 2.0) -> dict[str, dict]:
        """Parse .versions file (tool|method|version|timestamp format).

        Results are cached for *ttl* seconds (default 2s) to avoid re-reading
        the file on every check_installed() call during a batch operation like
        list_tools(installed_only=True).
        """
        now = time.monotonic()
        if self._versions_ts > 0 and (now - self._versions_ts) < ttl:
            return self._versions

        self._versions = {}
        versions_path = self.root / ".versions"
        if not versions_path.exists():
            self._versions_ts = now
            return self._versions
        try:
            with open(versions_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) >= 4:
                        self._versions[parts[0]] = {
                            "method": parts[1],
                            "version": parts[2],
                            "timestamp": parts[3],
                        }
        except PermissionError:
            pass  # Degrade gracefully — fall through to PATH/pipx/docker checks
        self._versions_ts = now
        return self._versions

    def check_installed(self, tool_name: str) -> dict:
        """Multi-strategy install check for a tool.

        Returns dict with: installed (bool), method (str), details (str).
        """
        tool = self.tools_by_name.get(tool_name)
        if not tool:
            return {
                "installed": False,
                "method": "unknown",
                "details": f"Tool '{tool_name}' not found in registry",
            }

        # 1. Check .versions tracking
        self.reload_versions()
        if tool_name in self._versions:
            v = self._versions[tool_name]
            return {
                "installed": True,
                "method": "versions_tracked",
                "details": f"Tracked: {v['version']} ({v['method']}, {v['timestamp']})",
            }

        # 2. PATH check via shutil.which
        if shutil.which(tool_name):
            return {
                "installed": True,
                "method": "path",
                "details": f"Found in PATH: {shutil.which(tool_name)}",
            }

        # 3. Pipx binary name fallback
        if tool["method"] == "pipx" and tool_name in PIPX_BIN_NAMES:
            bin_name = PIPX_BIN_NAMES[tool_name]
            if shutil.which(bin_name):
                return {
                    "installed": True,
                    "method": "pipx_binary",
                    "details": f"Pipx binary '{bin_name}' found in PATH",
                }

        # 4. Git clone directory check (Termux: ~/tools, Linux: /opt)
        if tool["method"] == "git":
            custom_dir = os.environ.get("GITHUB_TOOL_DIR")
            git_dirs = [Path(custom_dir or "/opt") / tool_name]
            if os.environ.get("TERMUX_VERSION"):
                git_dirs.insert(0, Path.home() / "tools" / tool_name)
            for git_path in git_dirs:
                if git_path.is_dir():
                    return {
                        "installed": True,
                        "method": "git_directory",
                        "details": f"Git clone found at {git_path}",
                    }

        # 5. Docker image check
        if tool["method"] == "docker":
            image = self._find_docker_image(tool_name)
            if image and self._docker_image_exists(image):
                return {
                    "installed": True,
                    "method": "docker",
                    "details": f"Docker image '{image}' found locally",
                }

        return {
            "installed": False,
            "method": tool["method"],
            "details": "Not found via any detection method",
        }

    def _find_docker_image(self, tool_name: str) -> Optional[str]:
        """Find the docker image for a tool name."""
        name_lower = tool_name.lower()
        # Exact match on label (case-insensitive)
        for label, image in DOCKER_IMAGES.items():
            if name_lower == label.lower():
                return image
        # Exact match on image name (last component, strip tag, e.g. "empire" from "bcsecurity/empire")
        for label, image in DOCKER_IMAGES.items():
            image_name = image.rsplit("/", 1)[-1].split(":")[0].lower()
            if name_lower == image_name:
                return image
        return None

    def _docker_image_exists(self, image: str) -> bool:
        """Check if a docker image exists locally."""
        try:
            result = subprocess.run(
                ["docker", "images", "-q", image],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return bool(result.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def list_tools(
        self,
        module: Optional[str] = None,
        method: Optional[str] = None,
        installed_only: bool = False,
    ) -> list[dict]:
        """Filter and return tools from the registry."""
        results = self._tools

        if module:
            results = [t for t in results if t["module"] == module]
        if method:
            results = [t for t in results if t["method"] == method]

        if installed_only:
            filtered = []
            for t in results:
                status = self.check_installed(t["name"])
                if status["installed"]:
                    t_copy = dict(t)
                    t_copy["install_status"] = status
                    filtered.append(t_copy)
            results = filtered

        return results

    @property
    def total_tools(self) -> int:
        return len(self._tools)

    @property
    def modules(self) -> list[str]:
        return sorted(set(t["module"] for t in self._tools))

    @property
    def methods(self) -> list[str]:
        return sorted(set(t["method"] for t in self._tools))
