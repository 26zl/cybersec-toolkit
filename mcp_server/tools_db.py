"""Tools database — loads tools_config.json, .versions, checks install status."""

import json
import os
import shutil
import subprocess
import time
import warnings
from pathlib import Path
from typing import Optional


def _resolve_registry_path(root: Path) -> Path:
    """Resolve the fixed tools registry path under a validated project root.

    Supports symlinks where ``tools_config.json`` itself is a link out of the
    project tree — e.g. WSL setups where the registry symlinks to a
    Windows-mounted path under ``/mnt/c/...``. The path is *constructed* under
    ``root``, so the "directly under root" guarantee comes from construction;
    we do not need to additionally constrain where the symlink target lives.
    """
    resolved_root = root.resolve(strict=True)
    config_path = resolved_root / "tools_config.json"
    if not config_path.is_file():
        raise FileNotFoundError(f"tools_config.json not found directly under {resolved_root}")
    return config_path


def _discover_project_root() -> Path:
    """Locate the installer root that contains tools_config.json.

    Resolution order:
    0. CYBERSEC_INSTALLER_ROOT env var (explicit override)
    1. Current working directory and its parents
    2. The source tree relative to this file
    """
    override = os.environ.get("CYBERSEC_INSTALLER_ROOT")
    if override:
        # Honor the override unconditionally so a misconfigured path fails loudly
        # at registry load (FileNotFoundError) instead of silently resolving a
        # different repo's tools_config.json via cwd discovery.
        return Path(override).expanduser()

    module_path = Path(__file__).resolve()
    search_roots = [Path.cwd().resolve(), module_path.parent, module_path.parent.parent]
    seen: set[Path] = set()

    for start in search_roots:
        for candidate in (start, *start.parents):
            if candidate in seen:
                continue
            seen.add(candidate)
            if (candidate / "tools_config.json").exists():
                return candidate

    return module_path.parent.parent


PROJECT_ROOT = _discover_project_root()

# Pipx package name → binary name mapping (from _PIPX_BIN_NAMES in scripts/verify.sh).
# Most pipx packages install a binary with the same name — these are the exceptions.
PIPX_BIN_NAMES: dict[str, str] = {
    "netexec": "nxc",
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
    "plaso": "log2timeline",
    "pyrit": "pyrit_scan",
    "cisco-ai-mcp-scanner": "mcp-scanner",
    "cisco-ai-skill-scanner": "skill-scanner",
    "knock-subdomains": "knockpy",
    "principalmapper": "pmapper",
    "dissect.target": "target-query",
    "python-evtx": "evtx_dump",
    "man-spider": "manspider",
}

# apt package name -> primary executable name, for packages whose binary differs
# from the Debian package name. Used by check_installed's binary fallback so an
# apt tool already on PATH is not reported missing when .versions is absent.
# NOT sync-pinned (unlike PIPX_BIN_NAMES, which validate_mcp_sync.py mirrors to
# scripts/verify.sh) — keep this list local to the MCP layer.
APT_BIN_NAMES: dict[str, str] = {
    "snmp": "snmpwalk",
    "wireless-tools": "iwconfig",
    "bluez": "bluetoothctl",
    "auditd": "ausearch",
    "poppler-utils": "pdftotext",
    "zbar-tools": "zbarimg",
    "ewf-tools": "ewfinfo",
    "binutils": "readelf",
    "qemu-user-static": "qemu-x86_64-static",
    "qemu-system-x86": "qemu-system-x86_64",
    "hcxtools": "hcxpcapngtool",
    "dns2tcp": "dns2tcpc",
    "clamav": "clamscan",
    "ettercap-text-only": "ettercap",
    "apparmor-utils": "aa-unconfined",
    "libimage-exiftool-perl": "exiftool",
    "libhivex-bin": "hivexml",
    "pst-utils": "readpst",
    "mdbtools": "mdb-tables",
    "netcat-openbsd": "nc",
    "wireshark-common": "tshark",
    "upx-ucl": "upx",
    "dnsutils": "dig",
    "openscap-scanner": "oscap",
    "sleuthkit": "fls",
}

# "special"-method tool name -> primary executable name, for tools installed via
# bespoke installers whose binary differs from the registry name. Lets
# check_installed find system/Kali/manual installs that have no .versions row
# (e.g. metasploit shipping msfconsole). steampipe's binary == its name, so it is
# already covered by the plain PATH check and intentionally omitted here.
SPECIAL_BIN_NAMES: dict[str, str] = {
    "metasploit": "msfconsole",
    "foundry": "forge",
}

# Source-build names follow the artifacts and PATH links declared by module BUILD_BINS.
SOURCE_BIN_NAMES: dict[str, str] = {
    "massdns": "massdns",
    "hash_extender": "hash_extender",
    "PkCrack": "pkcrack",
    "yafu": "yafu",
    "fastcoll": "fastcoll",
    "pemcrack": "pemcrack",
    "Donut": "donut",
    "ScareCrow": "ScareCrow",
    "Freeze": "Freeze",
    "QueenSono": "QueenSono",
    "Ivy": "Ivy",
    "AFLplusplus": "afl-fuzz",
    "honggfuzz": "honggfuzz",
    "radamsa": "radamsa",
    "ELFkickers": "sstrip",
    "rappel": "rappel",
    "azurehound": "azurehound",
    "rusthound": "rusthound",
    "rusthound-ce": "rusthound-ce",
    "GoExec": "GoExec",
    "GoMapEnum": "GoMapEnum",
    "gosecretsdump": "gosecretsdump",
    "duplicut": "duplicut",
    "kernel-hardening-checker": "kernel-hardening-checker",
    "pycdc": "pycdc",
}
# Release labels can differ from the executable selected in BINARY_RELEASES_*.
BINARY_BIN_NAMES: dict[str, str] = {
    "dex2jar": "d2j-dex2jar",
    "osquery": "osqueryi",
    "heimdall-rs": "heimdall",
}
PRIMARY_NATIVE_BINARIES: dict[str, tuple[str, ...]] = {"netexec": ("netexec", "NetExec")}
NON_CLI_TOOLS: dict[str, tuple[str, str, str]] = {
    "forensics-extra": (
        "metapackage",
        "Installs other forensic packages; it has no executable of its own.",
        'Use list_tools(module="forensics") to find the individual CLI packages it provides.',
    ),
    "libnfc-dev": (
        "library",
        "Development headers and library files; it has no standalone CLI.",
        "Use the library from a program or use a registered NFC CLI such as mfoc.",
    ),
}


# Git is an installation transport, not an execution capability. Names below
# match the installer's PATH launchers; the executable must still exist at runtime.
GIT_BIN_NAMES: dict[str, str] = {
    "libc-database": "libc-database",
    "dnscat2": "dnscat2",
    "firmware-mod-kit": "firmware-mod-kit",
    "pkinittools": "pkinittools",
    "libnfc-crypto1-crack": "libnfc-crypto1-crack",
    "USB-HID-decoders": "usb-hid-decoders",
    "Qiling": "qiling",
    "Krakatau": "krakatau",
    "PurplePanda": "purplepanda",
    "cloudmapper": "cloudmapper",
    "dvcs-ripper": "dvcs-ripper",
    "linux-smart-enumeration": "linux-smart-enumeration",
    "SUDO_KILLER": "sudo_killer",
    "LaZagne": "lazagne",
    "mimipenguin": "mimipenguin",
    "usbkill": "usbkill",
    "SET": "set",
    "Zphisher": "zphisher",
    "SquarePhish": "squarephish",
    "CredMaster": "credmaster",
    "Modlishka": "modlishka",
    "spiderfoot": "spiderfoot",
    "bettercap": "bettercap",
    "nipe": "nipe",
    "PRET": "pret",
    "pwnat": "pwnat",
    "recon-ng": "recon-ng",
    "reconftw": "reconftw",
    "nmapAutomator": "nmapautomator",
    "Sn1per": "sn1per",
    "blackbird": "blackbird",
    "GooFuzz": "goofuzz",
    "Telepathy": "telepathy",
    "certSniff": "certsniff",
    "linkedin2username": "linkedin2username",
    "EyeWitness": "eyewitness",
    "osmedeus": "osmedeus",
    "nikto": "nikto",
    "commix": "commix",
    "XSStrike": "xsstrike",
    "jwt_tool": "jwt_tool",
    "smuggler": "smuggler",
    "testssl.sh": "testssl.sh",
    "CMSmap": "cmsmap",
    "PhpSploit": "phpsploit",
    "phpggc": "phpggc",
    "PadBuster": "padbuster",
    "h2csmuggler": "h2csmuggler",
    "pp-finder": "pp-finder",
    "tomcatwardeployer": "tomcatwardeployer",
    "XXEinjector": "xxeinjector",
    "paramspider": "paramspider",
    "RsaCtfTool": "rsactftool",
    "rsatool": "rsatool",
    "exploitdb": "searchsploit",
    "RouterSploit": "routersploit",
    "Penelope": "penelope",
    "ShellNoob": "shellnoob",
    "unicorn": "unicorn",
    "nanodump": "nanodump",
    "eviltree": "eviltree",
    "Hoaxshell": "hoaxshell",
    "DNSExfiltrator": "dnsexfiltrator",
    "Egress-Assess": "egress-assess",
    "pyinstxtractor": "pyinstxtractor",
    "RegRipper": "regripper",
    "Depix": "depix",
    "firefox_decrypt": "firefox_decrypt",
    "Responder": "responder",
    "enum4linux-ng": "enum4linux-ng",
    "linWinPwn": "linwinpwn",
    "PCredz": "pcredz",
    "krbrelayx": "krbrelayx",
    "spraykatz": "spraykatz",
    "dfscoerce": "dfscoerce",
    "petitpotam": "petitpotam",
    "shadowcoerce": "shadowcoerce",
    "noPac": "nopac",
    "zerologon": "zerologon",
    "ntlm_theft": "ntlm_theft",
    "ntlmv1-multi": "ntlmv1-multi",
    "PassTheCert": "passthecert",
    "privexchange": "privexchange",
    "GPOddity": "gpoddity",
    "gmsadumper": "gmsadumper",
    "ExtractBitlockerKeys": "extractbitlockerkeys",
    "PXEThief": "pxethief",
    "sccmsecrets": "sccmsecrets",
    "sccmwtf": "sccmwtf",
    "cmloot": "cmloot",
    "pywsus": "pywsus",
    "RemoteMonologue": "remotemonologue",
    "roastinthemiddle": "roastinthemiddle",
    "lnkup": "lnkup",
    "ruler": "ruler",
    "bqm": "bqm",
    "cypheroth": "cypheroth",
    "abuseACL": "abuseacl",
    "asrepcatcher": "asrepcatcher",
    "conpass": "conpass",
    "freeipscanner": "freeipscanner",
    "goldencopy": "goldencopy",
    "keytabextract": "keytabextract",
    "ldaprelayscan": "ldaprelayscan",
    "LDAPWordlistHarvester": "ldapwordlistharvester",
    "wifite2": "wifite2",
    "fluxion": "fluxion",
    "airgeddon": "airgeddon",
    "hostapd-mana": "hostapd-mana",
    "wifiphisher": "wifiphisher",
    "PSKracker": "pskracker",
    "eaphammer": "eaphammer",
    "wifipumpkin3": "wifipumpkin3",
    "proxmark3": "proxmark3",
    "mfdread": "mfdread",
    "DefaultCreds-cheat-sheet": "defaultcreds-cheat-sheet",
    "pipal": "pipal",
    "username-anarchy": "username-anarchy",
    "gpp-decrypt": "gpp-decrypt",
    "openstego": "openstego",
    "stegextract": "stegextract",
    "stegosaurus": "stegosaurus",
    "CloudBrute": "cloudbrute",
    "enumerate-iam": "enumerate-iam",
    "GCPBucketBrute": "gcpbucketbrute",
    "cloud_enum": "cloud_enum",
    "deepce": "deepce",
    "docker-bench-security": "docker-bench-security",
    "peirates": "peirates",
    "theHarvester": "theHarvester",
    "Villain": "villain",
    "Corsy": "corsy",
    "NoSQLMap": "nosqlmap",
    "Gopherus": "gopherus",
    "dnschef": "dnschef",
    "yersinia": "yersinia",
    "stringcheese": "stringcheese",
    "FuzzyAI": "fuzzyai",
    "ctf-usb-keyboard-parser": "ctf-usb-keyboard-parser",
    "LinkFinder": "linkfinder",
    "SecretFinder": "secretfinder",
    "FavFreak": "favfreak",
    "Photon": "photon",
    "ghauri": "ghauri",
    "tplmap": "tplmap",
    "SSRFmap": "ssrfmap",
    "graphw00f": "graphw00f",
    "Oralyzer": "oralyzer",
    "ropium": "ropium",
    "featherduster": "featherduster",
    "targetedKerberoast": "targetedkerberoast",
    "cupp": "cupp",
    "changeme": "changeme",
    "crowbar": "crowbar",
    "kwprocessor": "kwprocessor",
    "medusa-frida": "medusa-frida",
}
GIT_NATIVE_BINARIES: dict[str, tuple[str, ...]] = {
    "usbkill": ("usbkill.py",),
    "nipe": ("nipe.pl",),
    "SET": ("setoolkit",),
    "wifite2": ("wifite",),
    "RegRipper": ("rip", "rip.pl"),
    "nikto": ("nikto.pl",),
    "PCredz": ("Pcredz",),
    "RsaCtfTool": ("RsaCtfTool", "rsacrack"),
    "asrepcatcher": ("ASRepCatcher",),
    "Qiling": ("qltool",),
    "Krakatau": ("krak2",),
    "theHarvester": ("theharvester",),
}
HOST_CONTROL_OPT_INS: dict[str, str] = {
    "usbkill": "CYBERSEC_MCP_ALLOW_USBKILL",
    "nipe": "CYBERSEC_MCP_ALLOW_NIPE",
}
EXECUTABLE_GIT: frozenset[str] = frozenset(GIT_BIN_NAMES)
_GIT_NETWORK_REGISTRY: frozenset[str] = frozenset(
    [
        "dnscat2",
        "pkinittools",
        "libnfc-crypto1-crack",
        "RsaCtfTool",
        "PurplePanda",
        "cloudmapper",
        "dvcs-ripper",
        "DNSExfiltrator",
        "PCredz",
        "CMSmap",
        "CloudBrute",
        "Corsy",
        "CredMaster",
        "DefaultCreds-cheat-sheet",
        "Egress-Assess",
        "EyeWitness",
        "FavFreak",
        "FuzzyAI",
        "GCPBucketBrute",
        "GPOddity",
        "GooFuzz",
        "Hoaxshell",
        "LDAPWordlistHarvester",
        "LinkFinder",
        "Modlishka",
        "NoSQLMap",
        "Oralyzer",
        "PRET",
        "PXEThief",
        "PadBuster",
        "PassTheCert",
        "Penelope",
        "Photon",
        "PhpSploit",
        "Responder",
        "RouterSploit",
        "SET",
        "SSRFmap",
        "SecretFinder",
        "Sn1per",
        "SquarePhish",
        "Telepathy",
        "Villain",
        "XSStrike",
        "XXEinjector",
        "Zphisher",
        "abuseACL",
        "airgeddon",
        "asrepcatcher",
        "bettercap",
        "blackbird",
        "bqm",
        "certSniff",
        "changeme",
        "cloud_enum",
        "cmloot",
        "commix",
        "conpass",
        "crowbar",
        "cypheroth",
        "dfscoerce",
        "dnschef",
        "eaphammer",
        "enum4linux-ng",
        "enumerate-iam",
        "fluxion",
        "freeipscanner",
        "ghauri",
        "gmsadumper",
        "goldencopy",
        "graphw00f",
        "h2csmuggler",
        "hostapd-mana",
        "jwt_tool",
        "krbrelayx",
        "ldaprelayscan",
        "linWinPwn",
        "linkedin2username",
        "lnkup",
        "medusa-frida",
        "nikto",
        "nipe",
        "nmapAutomator",
        "noPac",
        "osmedeus",
        "paramspider",
        "peirates",
        "petitpotam",
        "pp-finder",
        "privexchange",
        "pwnat",
        "pywsus",
        "recon-ng",
        "reconftw",
        "roastinthemiddle",
        "ruler",
        "sccmsecrets",
        "sccmwtf",
        "shadowcoerce",
        "smuggler",
        "spiderfoot",
        "spraykatz",
        "targetedKerberoast",
        "testssl.sh",
        "theHarvester",
        "tomcatwardeployer",
        "tplmap",
        "wifiphisher",
        "wifipumpkin3",
        "wifite2",
        "yersinia",
        "zerologon",
    ]
)
GIT_NETWORK_TOOLS: frozenset[str] = _GIT_NETWORK_REGISTRY | frozenset(
    GIT_BIN_NAMES[name] for name in _GIT_NETWORK_REGISTRY
)
GIT_NON_EXECUTABLE: dict[str, str] = {
    "robin": "service",
    "pallms": "resource",
    "SecLists": "resource",
    "PayloadsAllTheThings": "resource",
    "InternalAllTheThings": "resource",
    "PEASS-ng": "resource",
    "PyExfil": "framework",
    "Vigil": "framework",
    "EvilGoPhish": "framework",
    "CyberChef": "framework",
    "Caldera": "framework",
    "Loki-C2": "framework",
    "axiom": "framework",
    "iKy": "framework",
    "symfony-exploits": "suite",
    "vulscan": "resource",
    "pwndbg": "framework",
    "GEF": "framework",
    "peda": "framework",
    "decomp2dbg": "framework",
    "mousejack": "framework",
    "Hob0Rules": "resource",
    "Pantagrule": "resource",
    "OneRuleToRuleThemStill": "resource",
    "stegsolve": "gui",
    "sigma-rules": "resource",
    "maltrail": "framework",
    "MISP-docker": "framework",
    "wazuh-docker": "framework",
    "shannon": "framework",
    "pentagi": "framework",
    "preeny": "framework",
    "atomic-red-team": "resource",
    "Mythic": "framework",
    "Havoc": "framework",
    "PoshC2": "framework",
    "merlin": "framework",
    "PurpleLlama": "framework",
}


# Registry tool -> further executables its package installs. run_tool accepts these names and
# applies the owning tool's install check, e.g. sleuthkit ships fls, mmls and icat.
PACKAGE_EXTRA_BINARIES: dict[str, frozenset[str]] = {
    "ELFkickers": frozenset({"elfls", "objres", "rebind", "elftoc", "ebfc", "infect"}),
    "pycdc": frozenset({"pycdas"}),
    "binutils": frozenset({"readelf", "objdump", "nm", "strings"}),
    "sleuthkit": frozenset(
        {"fls", "mmls", "icat", "fsstat", "istat", "ils", "blkls", "tsk_recover", "mactime"},
    ),
}
_EXTRA_BINARY_OWNER: dict[str, str] = {
    binary: package for package, binaries in PACKAGE_EXTRA_BINARIES.items() for binary in binaries
}


def package_for_extra_binary(binary: str) -> str | None:
    """The registry tool whose package installs *binary* besides its primary executable."""
    owner = _EXTRA_BINARY_OWNER.get(binary)
    if owner:
        return owner
    mappings = (
        PIPX_BIN_NAMES,
        APT_BIN_NAMES,
        SPECIAL_BIN_NAMES,
        NPM_BIN_NAMES,
        CARGO_BIN_NAMES,
        GIT_BIN_NAMES,
        SOURCE_BIN_NAMES,
        BINARY_BIN_NAMES,
    )
    owners = {name for mapping in mappings for name, alias in mapping.items() if alias == binary and alias != name}
    owners.update(name for name, aliases in GIT_NATIVE_BINARIES.items() if binary in aliases and binary != name)
    owners.update(name for name, aliases in PRIMARY_NATIVE_BINARIES.items() if binary in aliases and binary != name)
    return next(iter(owners)) if len(owners) == 1 else None


# npm / cargo package name -> installed binary name, for the packages where they
# differ. Sync-pinned: validate_mcp_sync.py mirrors these to _NPM_BIN_NAMES and
# _CARGO_BIN_NAMES in lib/installers.sh, which verify.sh/update.sh/remove.sh share.
NPM_BIN_NAMES: dict[str, str] = {
    "rms-runtime-mobile-security": "rms",
    "rea-agents": "rea",
}
CARGO_BIN_NAMES: dict[str, str] = {
    "yara-x-cli": "yr",
}


def resolve_binary_name(method: str, tool_name: str) -> str:
    """Map a registry tool name to its installed executable name, by install method.

    Single source of truth for the package-name != executable-name mapping so the
    local PATH check and the remote SSH ``which`` check resolve the same binary
    (otherwise apt-renamed/special-method tools always report "not installed" on
    remote hosts). Returns *tool_name* unchanged when no mapping applies.
    """
    if method == "source":
        return SOURCE_BIN_NAMES.get(tool_name, tool_name)
    if method == "binary":
        return BINARY_BIN_NAMES.get(tool_name, tool_name)
    if method == "git":
        return GIT_BIN_NAMES.get(tool_name, tool_name)
    if method == "pipx":
        return PIPX_BIN_NAMES.get(tool_name, tool_name)
    if method == "apt":
        return APT_BIN_NAMES.get(tool_name, tool_name)
    if method == "special":
        return SPECIAL_BIN_NAMES.get(tool_name, tool_name)
    if method == "npm":
        return NPM_BIN_NAMES.get(tool_name, tool_name)
    if method == "cargo":
        return CARGO_BIN_NAMES.get(tool_name, tool_name)
    return tool_name


def binary_candidates(method: str, tool_name: str) -> tuple[str, ...]:
    """Known installer and native launchers, ordered by the toolkit's canonical name."""
    canonical = resolve_binary_name(method, tool_name)
    if method != "git" or tool_name not in GIT_BIN_NAMES:
        return tuple(dict.fromkeys((canonical, *PRIMARY_NATIVE_BINARIES.get(tool_name, ()))))
    return tuple(dict.fromkeys((canonical, *GIT_NATIVE_BINARIES.get(tool_name, ()), tool_name)))


def resolve_installed_binary(method: str, tool_name: str) -> str:
    """Select a known launcher present in PATH, or return the canonical missing name."""
    candidates = binary_candidates(method, tool_name)
    return next((candidate for candidate in candidates if shutil.which(candidate)), candidates[0])


def execution_metadata(tool: dict) -> dict:
    """Describe supported invocation separately from installation state."""
    name, method = tool["name"], tool["method"]
    # Imported lazily because the policy engine consumes this metadata too.
    from mcp_server.security import _NETWORK_TOOLS

    binary = resolve_binary_name(method, name)
    kind, executable = "cli", True
    reason = (
        "CLI executable; installation and argument/network policies are checked before launch. "
        "Operator authorization for the target remains required."
    )
    access = f'Use run_tool(tool_name="{name}", args="...").'
    if name in NON_CLI_TOOLS:
        kind, reason, access = NON_CLI_TOOLS[name]
        executable, binary = False, None
    elif method == "git":
        executable = name in GIT_BIN_NAMES
        kind = "cli" if executable else GIT_NON_EXECUTABLE.get(name, "unreviewed")
        if not executable:
            binary = None
            if kind == "resource":
                reason = "Repository of data, rules, payloads or supporting scripts; no single CLI launcher."
                access = (
                    "Use run_tool with file/ls/cat/grep on the installed resource files, or pass their paths to a CLI."
                )
            elif kind == "gui":
                reason = "Desktop application; no reviewed non-interactive CLI launcher."
                access = "Open the installed application through its desktop interface."
            elif kind == "suite":
                reason = "Repository contains multiple independent entry points; no single project-named CLI."
                access = "Inspect the upstream entry points and install a named CLI before calling run_tool."
            elif kind == "service":
                reason = "Web application or MCP service; no standalone project-named CLI launcher."
                access = "Use the documented service API or MCP client after operator-approved setup."
            elif kind == "framework":
                reason = (
                    "Framework, service, plugin or library requiring its own runtime/setup; no reviewed CLI launcher."
                )
                access = "Use the upstream setup/client instructions; the repository remains discoverable here."
            else:
                reason = "Git project has no reviewed executable metadata; review its launcher and policies first."
                access = "Use get_tool_info to inspect its upstream URL and installation module."
    elif method == "docker":
        executable, binary, kind = False, None, "container"
        reason = "Installed as a container image; no host CLI wrapper is registered."
        access = "Use its documented container command or service client after operator-approved setup."
    elif name == "ctf-crypto-venv":
        executable, binary, kind = False, None, "environment"
        reason = "Python environment for script execution; not a standalone executable."
        access = 'Use run_script(venv="crypto") only after scripts are explicitly enabled.'
    result = {
        "executable": executable,
        "binary": binary,
        "kind": kind,
        "network": name in GIT_NETWORK_TOOLS
        or binary in GIT_NETWORK_TOOLS
        or name in _NETWORK_TOOLS
        or binary in _NETWORK_TOOLS,
        "reason": reason,
        "access": access,
    }
    if method == "docker":
        label = DOCKER_TOOL_LABELS.get(name, name)
        result["image"] = next(
            (image for key, image in DOCKER_IMAGES.items() if key.casefold() == label.casefold()), None
        )
    if executable and method == "git":
        result["binary_candidates"] = list(binary_candidates(method, name))
        if name in {"NoSQLMap", "Gopherus", "DNSExfiltrator", "featherduster"}:
            result["runtime_requirements"] = (
                "Legacy Python 2 CLI; requires a compatible Python 2 interpreter and dependencies."
            )
        elif name == "nanodump":
            result["runtime_requirements"] = (
                "Windows native CLI; requires a compatible Windows build and execution host."
            )
        elif name == "RemoteMonologue":
            result["runtime_requirements"] = (
                "Python front end with Windows target components and their runtime requirements."
            )
        elif name in {
            "proxmark3",
            "hostapd-mana",
            "wifite2",
            "fluxion",
            "airgeddon",
            "wifiphisher",
            "eaphammer",
            "wifipumpkin3",
        }:
            result["runtime_requirements"] = (
                "Requires supported hardware/drivers and, for active operations, appropriate host privileges."
            )
        elif name in {"usbkill", "nipe"}:
            opt_in = HOST_CONTROL_OPT_INS[name]
            result["activation"] = {
                "environment_variable": opt_in,
                "enabled": os.environ.get(opt_in, "").strip() == "1",
                "requires_external_for": ["install", "start", "restart", "status"] if name == "nipe" else [],
            }
            if name == "usbkill":
                result["runtime_requirements"] = (
                    f"Full host-control functionality requires {opt_in}=1 and appropriate host permissions; "
                    "configured actions can shut down the system or wipe files, RAM and swap."
                )
            else:
                result["runtime_requirements"] = (
                    f"Requires Perl/CPAN dependencies, appropriate network privileges and {opt_in}=1. "
                    "Network operations also require CYBERSEC_MCP_ALLOW_EXTERNAL=1; stop remains local."
                )
    aliases = set(binary_candidates(method, name)) | set(PACKAGE_EXTRA_BINARIES.get(name, ()))
    aliases.discard(name)
    if executable and aliases:
        result["aliases"] = sorted(aliases)
    return result


def execution_summary(tool: dict) -> dict:
    """Keep large discovery lists compact; detailed guidance lives in get_tool_info."""
    metadata = execution_metadata(tool)
    fields = ("kind", "executable", "binary", "network", "runtime_requirements", "activation")
    return {key: metadata[key] for key in fields if key in metadata}


# Registry tools installed ONLY when INCLUDE_C2=true (the redteam/full profiles, or
# --include-c2). The installer gates these in modules/misc.sh and modules/pwn.sh;
# mirror that here so MCP tool/profile output reflects the gating. Synced from bash
# by validate_mcp_sync.py:
#   git    -> modules/misc.sh MISC_C2_GIT_NAMES + modules/pwn.sh PWN_C2_GIT_NAMES
#   binary -> lib/installers.sh BINARY_RELEASES_MISC_C2 (2nd |-field)
#   docker -> empire (bcsecurity/empire), gated in install_module_misc
C2_TOOLS: frozenset[str] = frozenset(
    {
        # Pwn-module C2 / reverse-shell frameworks (PWN_C2_GIT_NAMES)
        "Hoaxshell",
        "Villain",
        "SET",
        "Zphisher",
        "EvilGoPhish",
        "SquarePhish",
        "CredMaster",
        "Modlishka",
        "Caldera",
        "Loki-C2",
        "gophish",
        "sliver-server",
        "sliver-client",
        "evilginx",
        "empire",
        # INCLUDE_C2-gated post-exploitation tools
        "LaZagne",
        "mimipenguin",
        "PyExfil",
        "usbkill",
        # C2 frameworks (git-cloned, INCLUDE_C2-gated)
        "Mythic",
        "Havoc",
        "PoshC2",
        "merlin",
        # Rogue-AP credential-phishing frameworks (WIRELESS_C2_GIT_NAMES)
        "fluxion",
        "wifiphisher",
        "eaphammer",
        "wifipumpkin3",
        # Browser hooking framework (Docker, gated in install_module_web)
        "beef",
    }
)

# Module descriptions (from MODULE_DESCRIPTIONS in lib/common.sh).
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

# Docker image registry (from ALL_DOCKER_IMAGES in lib/installers.sh).
# Maps tool label → docker image.
DOCKER_IMAGES: dict[str, str] = {
    "BeEF": "beefproject/beef",
    "Empire": "bcsecurity/empire",
    "MobSF": "opensecurity/mobile-security-framework-mobsf",
    "BloodHound CE": "specterops/bloodhound",
    "TheHive": "strangebee/thehive:latest",
    "Cortex": "thehiveproject/cortex:latest",
    "Echidna": "trailofbits/echidna",
    "PentAGI": "vxcontrol/pentagi:latest",
    "Zeek": "zeek/zeek:latest",
    "Zircolite": "wagga40/zircolite:latest",
    "KICS": "checkmarx/kics:latest",
    "SageMath": "sagemath/sagemath:latest",
}

# Registry names whose DOCKER_IMAGES label (also the .versions key docker_pull writes) differs.
DOCKER_TOOL_LABELS: dict[str, str] = {
    "bloodhound-ce": "BloodHound CE",
    "pentagi-docker": "PentAGI",
}


class ToolsDatabase:
    """Loads and queries the cybersec tools registry."""

    def __init__(self, project_root: Optional[Path] = None):
        self.root = Path(project_root) if project_root else PROJECT_ROOT
        self._tools: list[dict] = []
        self.tools_by_name: dict[str, dict] = {}
        self._versions: dict[str, dict] = {}
        self._versions_ts: float = 0.0  # last reload timestamp
        self._versions_unreadable_warned = False
        self._docker_refs: set[str] = set()
        self._docker_refs_ts: float = 0.0
        self._load_tools()

    def _load_tools(self) -> None:
        config_path = _resolve_registry_path(self.root)
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                tools = json.load(f)
            if not isinstance(tools, list):
                raise ValueError("top level must be a list of tool objects")
            names: set[str] = set()
            for index, entry in enumerate(tools):
                if not isinstance(entry, dict):
                    raise ValueError(f"entry {index} is not an object")
                for key in ("name", "method", "module"):
                    if not isinstance(entry.get(key), str):
                        raise ValueError(f"entry {index} lacks a string '{key}'")
                if entry["name"] in names:
                    raise ValueError(f"duplicate tool name: {entry['name']}")
                names.add(entry["name"])
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"{config_path}: invalid registry ({exc})") from exc
        self._tools = tools
        self.tools_by_name = {t["name"]: t for t in self._tools}

    def get_tool(self, tool_name: str) -> dict | None:
        """Resolve registry names and unambiguous installed executable aliases."""
        tool = self.tools_by_name.get(tool_name)
        if tool is not None:
            return tool
        owner = package_for_extra_binary(tool_name)
        return self.tools_by_name.get(owner) if owner else None

    def execution_candidates(self, tool_name: str) -> tuple[str, ...]:
        """Keep explicit executable aliases distinct from the package's primary CLI."""
        tool = self.get_tool(tool_name)
        if tool is None:
            return ()
        if tool_name != tool["name"]:
            return (tool_name,)
        return binary_candidates(tool["method"], tool["name"])

    def execution_status(self, tool_name: str) -> dict:
        """Report launch readiness without treating a clone or version record as a CLI."""
        tool = self.get_tool(tool_name)
        if tool is None:
            return {"executable": False, "ready": False, "reason": "Tool not found in registry"}
        result = execution_metadata(tool)
        candidates = self.execution_candidates(tool_name) if result["executable"] else ()
        selected = next(
            (candidate for candidate in candidates if shutil.which(candidate)), candidates[0] if candidates else None
        )
        binary_path = shutil.which(selected) if selected else None
        if selected:
            result["binary"] = selected
        if tool_name != tool["name"]:
            result["access"] = f'Use run_tool(tool_name="{tool_name}", args="...").'
        result["ready"] = binary_path is not None
        if binary_path:
            result["path"] = binary_path
        elif result["executable"]:
            result["readiness_reason"] = "CLI launcher is not in PATH; a clone or version record alone is insufficient."
        if tool["method"] == "git":
            custom_dir = os.environ.get("GITHUB_TOOL_DIR")
            roots = [Path(custom_dir or "/opt")]
            if os.environ.get("TERMUX_VERSION"):
                roots.insert(0, Path.home() / "tools")
            result["location_candidates"] = [str(root / tool["name"]) for root in roots]
        return result

    def reload_versions(self, ttl: float = 2.0) -> dict[str, dict]:
        """Parse .versions file (tool|method|version|timestamp format).

        Results are cached for *ttl* seconds (default 2s) to avoid re-reading
        the file on every check_installed() call during a batch operation like
        list_tools(installed_only=True).
        """
        now = time.monotonic()
        if self._versions_ts > 0 and (now - self._versions_ts) < ttl:
            return self._versions

        # Built aside and swapped in whole: sync tools run in a threadpool, and a
        # reader must never see a half-filled dict.
        versions: dict[str, dict] = {}
        versions_path = self.root / ".versions"
        try:
            with open(versions_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) >= 4:
                        versions[parts[0]] = {
                            "method": parts[1],
                            "version": parts[2],
                            "timestamp": parts[3],
                        }
        except (OSError, ValueError) as exc:
            # Missing, unreadable, corrupt or non-UTF-8 .versions: fall through to
            # the PATH/pipx/docker checks. A present-but-unreadable file silently
            # degrades install detection (e.g. root-owned 0600 .versions under a
            # non-root server), so surface that case once.
            versions = {}
            if not self._versions_unreadable_warned and isinstance(exc, OSError) and versions_path.exists():
                self._versions_unreadable_warned = True
                warnings.warn(
                    f".versions exists at {versions_path} but is not readable ({exc}); "
                    "install detection falls back to PATH only. Make it readable by the "
                    "server user (e.g. chmod 644).",
                    RuntimeWarning,
                    stacklevel=2,
                )
        self._versions = versions
        self._versions_ts = now
        return versions

    def check_installed(self, tool_name: str) -> dict:
        """Multi-strategy install check for a tool.

        Returns dict with: installed (bool), method (str), details (str).
        """
        tool = self.get_tool(tool_name)
        if not tool:
            return {
                "installed": False,
                "method": "unknown",
                "details": f"Tool '{tool_name}' not found in registry",
            }

        if tool_name != tool["name"]:
            path = shutil.which(tool_name)
            return {
                "installed": path is not None,
                "method": "path",
                "details": f"Found in PATH: {path}"
                if path
                else f"Binary '{tool_name}' is not installed or not in PATH",
            }

        tool_name = tool["name"]

        # 1. Check .versions tracking
        versions = self.reload_versions()
        tracked_key = tool_name
        if tool_name not in versions and tool["method"] == "docker":
            tracked_key = DOCKER_TOOL_LABELS.get(tool_name, tool_name)
        elif tool_name not in versions and resolve_binary_name(tool["method"], tool_name) in versions:
            tracked_key = resolve_binary_name(tool["method"], tool_name)
        if tracked_key in versions:
            v = versions[tracked_key]
            return {
                "installed": True,
                "method": "versions_tracked",
                "details": f"Tracked: {v['version']} ({v['method']}, {v['timestamp']})",
            }

        # 2. PATH check via shutil.which
        found = shutil.which(tool_name)
        if found:
            return {
                "installed": True,
                "method": "path",
                "details": f"Found in PATH: {found}",
            }

        # 3. Binary name fallback (package name != executable name)
        resolved = resolve_installed_binary(tool["method"], tool_name)
        bin_name = resolved if resolved != tool_name else None
        if bin_name and shutil.which(bin_name):
            return {
                "installed": True,
                "method": f"{tool['method']}_binary",
                "details": f"Binary '{bin_name}' found in PATH",
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

        # 5. run_script venv check: "ctf-<name>-venv" is the venv the server hands
        # to run_script(venv="<name>"), so its interpreter is the install proof.
        # Checked directly rather than through .versions so a manually created
        # venv — the documented fallback — also reports honestly.
        if tool["method"] == "special" and tool_name.startswith("ctf-") and tool_name.endswith("-venv"):
            venvs_dir = os.environ.get("CYBERSEC_MCP_VENVS_DIR", "").strip()
            venv_root = Path(venvs_dir) if venvs_dir else Path.home() / ".ctf-venvs"
            venv_python = venv_root / tool_name[len("ctf-") : -len("-venv")] / "bin" / "python"
            if venv_python.is_file():
                return {
                    "installed": True,
                    "method": "venv",
                    "details": f"Venv interpreter: {venv_python}",
                }

        # 6. Docker image check
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
        name_lower = DOCKER_TOOL_LABELS.get(tool_name, tool_name).lower()
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

    def _docker_refs_cached(self, ttl: float = 2.0) -> set[str]:
        """Local image refs as ``repo:tag``, cached briefly.

        A registry-wide scan checks every docker tool; one ``docker images`` call
        per scan replaces one per tool, and a hung daemon costs one timeout
        instead of one per image.
        """
        now = time.monotonic()
        if self._docker_refs_ts > 0 and (now - self._docker_refs_ts) < ttl:
            return self._docker_refs
        try:
            result = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            refs = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            refs = set()
        self._docker_refs = refs
        self._docker_refs_ts = now
        return refs

    def _docker_image_exists(self, image: str) -> bool:
        """Check if a docker image exists locally (any tag when *image* names none)."""
        repo, sep, tag = image.rpartition(":")
        if not sep or "/" in tag:
            # No tag, or the colon belonged to a registry port ("host:5000/repo").
            repo, tag = image, ""
        refs = self._docker_refs_cached()
        if tag:
            return f"{repo}:{tag}" in refs
        return any(ref.rsplit(":", 1)[0] == repo for ref in refs)

    def list_tools(
        self,
        module: Optional[str] = None,
        method: Optional[str] = None,
        installed_only: bool = False,
        query: Optional[str] = None,
        executable_only: bool = False,
    ) -> list[dict]:
        """Filter and return tools from the registry."""
        results = self._tools

        if module:
            results = [t for t in results if t["module"] == module]
        if method:
            results = [t for t in results if t["method"] == method]

        if query:
            terms = query.casefold().split()
            results = [
                t
                for t in results
                if all(
                    term
                    in " ".join(
                        (
                            t["name"],
                            *binary_candidates(t["method"], t["name"]),
                            *PACKAGE_EXTRA_BINARIES.get(t["name"], ()),
                            t["module"],
                            t.get("url", ""),
                        )
                    ).casefold()
                    for term in terms
                )
            ]
        if executable_only:
            results = [t for t in results if execution_metadata(t)["executable"]]

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
