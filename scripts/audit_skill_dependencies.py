#!/usr/bin/env python3
"""Audit optional Python imports used by vendored Claude skill helper scripts."""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import re
import sys
import sysconfig
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / ".claude" / "skills"
DEFAULT_REQUIREMENTS = SKILLS_DIR / "requirements.txt"

STDLIB = set(getattr(sys, "stdlib_module_names", ()))
# Fallback for Python < 3.10 (no sys.stdlib_module_names): match a module's file
# origin against the interpreter's stdlib directories so pure-Python stdlib
# modules (json/re/...) are not misclassified as third-party.
_STDLIB_DIRS = tuple(
    p for p in {sysconfig.get_paths().get("stdlib"), sysconfig.get_paths().get("platstdlib")} if p
)
LOCAL_IMPORTS = {"mcp_server"}

NON_PIP_IMPORTS = {
    "rekall": "Legacy Rekall framework; install/use a Rekall runtime separately or prefer volatility3 on modern Python.",
}

# Top-level import name -> installable PyPI distribution(s). Keep this explicit:
# namespace packages such as azure/google/sigma need several distributions, while
# many security libraries use import names that differ from their package names.
IMPORT_TO_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "Evtx": ("python-evtx",),
    "Levenshtein": ("python-Levenshtein",),
    "LnkParse3": ("LnkParse3",),
    "OpenSSL": ("pyOpenSSL",),
    "PIL": ("Pillow",),
    "Registry": ("python-registry",),
    "androguard": ("androguard",),
    "anyrun": ("anyrun-sdk",),
    "atomic_operator": ("atomic-operator",),
    "attackcti": ("attackcti",),
    "azure": (
        "azure-identity",
        "azure-mgmt-resource",
        "azure-mgmt-security",
        "azure-mgmt-securityinsight",
        "azure-mgmt-storage",
        "azure-monitor-query",
    ),
    "bleak": ("bleak",),
    "boto3": ("boto3",),
    "botocore": ("botocore",),
    "bs4": ("beautifulsoup4",),
    "cbor2": ("cbor2",),
    "censys": ("censys",),
    "cryptography": ("cryptography",),
    "defusedxml": ("defusedxml",),
    "dissect": ("dissect.cobaltstrike",),
    "dns": ("dnspython",),
    "dnstwist": ("dnstwist",),
    "docker": ("docker",),
    "dpkt": ("dpkt",),
    "elasticsearch": ("elasticsearch",),
    "elftools": ("pyelftools",),
    "evtx": ("evtx",),
    "falconpy": ("crowdstrike-falconpy",),
    "fido2": ("fido2",),
    "flask": ("Flask",),
    "fluent": ("fluent-logger",),
    "frida": ("frida",),
    "geoip2": ("geoip2",),
    "google": (
        "google-api-core",
        "google-auth",
        "google-cloud-asset",
        "google-cloud-compute",
        "google-cloud-dlp",
        "google-cloud-iam",
        "google-cloud-iap",
        "google-cloud-resource-manager",
        "google-cloud-securitycenter",
        "google-cloud-storage",
    ),
    "googleapiclient": ("google-api-python-client",),
    "gophish": ("gophish",),
    "grpc": ("grpcio",),
    "gvm": ("python-gvm",),
    "hvac": ("hvac",),
    "impacket": ("impacket",),
    "jinja2": ("Jinja2",),
    "joblib": ("joblib",),
    "jsbeautifier": ("jsbeautifier",),
    "jsonschema": ("jsonschema",),
    "jwt": ("PyJWT",),
    "kubernetes": ("kubernetes",),
    "ldap3": ("ldap3",),
    "librosa": ("librosa",),
    "lxml": ("lxml",),
    "mitreattack": ("mitreattack-python",),
    "mlkem": ("mlkem",),
    "msal": ("msal",),
    "msgpack": ("msgpack",),
    "mysql": ("mysql-connector-python",),
    "napalm": ("napalm",),
    "neo4j": ("neo4j",),
    "netflow": ("netflow",),
    "netmiko": ("netmiko",),
    "networkx": ("networkx",),
    "nmap": ("python-nmap",),
    "numpy": ("numpy",),
    "okta": ("okta",),
    "oletools": ("oletools",),
    "packaging": ("packaging",),
    "paho": ("paho-mqtt",),
    "pandas": ("pandas",),
    "paramiko": ("paramiko",),
    "pefile": ("pefile",),
    "pkcs11": ("python-pkcs11",),
    "psutil": ("psutil",),
    "psycopg2": ("psycopg2-binary",),
    "pwn": ("pwntools",),
    "pycrtsh": ("pycrtsh",),
    "pycti": ("pycti",),
    "pymisp": ("pymisp",),
    "pymodbus": ("pymodbus",),
    "pypff": ("pypff",),
    "pyrad": ("pyrad",),
    "pyshark": ("pyshark",),
    "pysnmp": ("pysnmp",),
    "pytsk3": ("pytsk3",),
    "pyzbar": ("pyzbar",),
    "r2pipe": ("r2pipe",),
    "regipy": ("regipy",),
    "requests": ("requests",),
    "rich": ("rich",),
    "scapy": ("scapy",),
    "shodan": ("shodan",),
    "sigma": ("pysigma", "pysigma-backend-splunk"),
    "sklearn": ("scikit-learn",),
    "spacy": ("spacy",),
    "splunklib": ("splunk-sdk",),
    "sqlalchemy": ("SQLAlchemy",),
    "sslyze": ("sslyze",),
    "stix2": ("stix2",),
    "taxii2client": ("taxii2-client",),
    "tldextract": ("tldextract",),
    "transformers": ("transformers",),
    "urllib3": ("urllib3",),
    "watchdog": ("watchdog",),
    "websockets": ("websockets",),
    "whois": ("python-whois",),
    "windowsprefetch": ("windowsprefetch",),
    "winrm": ("pywinrm",),
    "yaml": ("PyYAML",),
    "yara": ("yara-python",),
    "yara_x": ("yara-x",),
    "zat": ("zat",),
}


def normalize_package_name(name: str) -> str:
    """PEP 503-normalize a distribution name for stable comparisons."""
    return re.sub(r"[-_.]+", "-", name).lower()


def iter_python_scripts() -> list[Path]:
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(SKILLS_DIR.glob("**/scripts/**/*.py"))


def top_level_imports(script: Path) -> set[str]:
    source = script.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source, filename=str(script))
    imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imports.add(node.module.split(".", 1)[0])

    return imports


def is_local_import(script: Path, module: str) -> bool:
    if module in LOCAL_IMPORTS:
        return True
    return (script.parent / f"{module}.py").exists() or (script.parent / module / "__init__.py").exists()


def is_stdlib(module: str) -> bool:
    if module in STDLIB:
        return True
    if module.startswith("_"):
        return True
    # find_spec can raise (ModuleNotFoundError on a broken parent package,
    # ValueError on a malformed name) — treat any failure as "not stdlib"
    # rather than aborting the whole audit.
    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, ValueError):
        return False
    if spec is None:
        return False
    if spec.origin in {"built-in", "frozen"}:
        return True
    # Pure-Python stdlib module with a file origin (covers Python < 3.10 where
    # STDLIB is empty). Anything under site-packages is third-party, not stdlib.
    origin = spec.origin or ""
    return bool(_STDLIB_DIRS) and origin.startswith(_STDLIB_DIRS) and "site-packages" not in origin


def is_installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def packages_for_import(module: str) -> tuple[str, ...]:
    return IMPORT_TO_REQUIREMENTS.get(module, ())


def external_runtime_for_import(module: str) -> str:
    return NON_PIP_IMPORTS.get(module, "")


def expected_requirements(modules: list[dict]) -> list[str]:
    packages = {
        package
        for item in modules
        for package in item["packages"]
    }
    return sorted(packages, key=lambda value: normalize_package_name(value))


def parse_requirements(path: Path) -> list[str]:
    """Parse package names from a simple requirements.txt-style file."""
    if not path.is_file():
        return []

    packages: list[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "--", "-c")):
            continue
        match = re.match(r"([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
        if match:
            packages.append(match.group(1))
    return packages


def render_requirements(packages: list[str]) -> str:
    lines = [
        "# Optional Python dependencies for .claude/skills/**/scripts/*.py.",
        "# Generated by scripts/audit_skill_dependencies.py --write-requirements.",
        "# Keep this in sync with helper-script imports by running:",
        "#   python3 scripts/audit_skill_dependencies.py --write-requirements",
        "#",
        "# Full bootstrap for local helper-script execution:",
        "#   python3 -m pip install -r .claude/skills/requirements.txt",
        "#",
    ]
    lines.extend(packages)
    return "\n".join(lines) + "\n"


def write_requirements(path: Path, packages: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_requirements(packages), encoding="utf-8")


def diff_requirements(expected: list[str], declared: list[str]) -> tuple[list[str], list[str]]:
    expected_by_name = {normalize_package_name(package): package for package in expected}
    declared_by_name = {normalize_package_name(package): package for package in declared}
    missing = [
        expected_by_name[name]
        for name in sorted(set(expected_by_name) - set(declared_by_name))
    ]
    extra = [
        declared_by_name[name]
        for name in sorted(set(declared_by_name) - set(expected_by_name))
    ]
    return missing, extra


def _display_path(path: Path) -> str:
    """Path relative to the repo root when possible, else the absolute path.

    A ``--requirements-file`` outside the repo (e.g. /tmp/req.txt) must not crash
    the audit with a ValueError from ``Path.relative_to``.
    """
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def audit(requirements_file: Path = DEFAULT_REQUIREMENTS) -> dict:
    scripts = iter_python_scripts()
    by_module: dict[str, list[str]] = defaultdict(list)
    syntax_errors: list[dict[str, str | int]] = []

    for script in scripts:
        try:
            imports = top_level_imports(script)
        except SyntaxError as exc:
            syntax_errors.append({
                "file": str(script.relative_to(ROOT)),
                "line": exc.lineno or 0,
                "message": exc.msg,
            })
            continue

        for module in sorted(imports):
            if is_local_import(script, module) or is_stdlib(module):
                continue
            by_module[module].append(str(script.relative_to(ROOT)))

    modules = []
    for module, files in sorted(by_module.items()):
        installed = is_installed(module)
        packages = list(packages_for_import(module))
        external_runtime = external_runtime_for_import(module)
        modules.append({
            "module": module,
            "packages": packages,
            "external_runtime": external_runtime,
            "installed": installed,
            "script_count": len(files),
            "examples": files[:5],
        })

    expected = expected_requirements(modules)
    declared = parse_requirements(requirements_file)
    missing_declared, extra_declared = diff_requirements(expected, declared)
    unmapped = [item["module"] for item in modules if not item["packages"] and not item["external_runtime"]]
    external_runtime_imports = [
        {
            "module": item["module"],
            "runtime": item["external_runtime"],
            "script_count": item["script_count"],
            "examples": item["examples"],
        }
        for item in modules
        if item["external_runtime"]
    ]

    return {
        "scripts_checked": len(scripts),
        "third_party_imports": len(modules),
        "expected_package_count": len(expected),
        "expected_packages": expected,
        "requirements_file": _display_path(requirements_file),
        "requirements_exists": requirements_file.is_file(),
        "declared_package_count": len(declared),
        "declared_packages": declared,
        "unmapped_modules": unmapped,
        "external_runtime_imports": external_runtime_imports,
        "missing_declared_packages": missing_declared,
        "extra_declared_packages": extra_declared,
        "missing_count": sum(1 for item in modules if not item["installed"]),
        "syntax_errors": syntax_errors,
        "modules": modules,
    }


def print_text(report: dict, *, show_missing_env_details: bool = True) -> None:
    print(f"Skill Python scripts checked: {report['scripts_checked']}")
    print(f"Third-party import names:    {report['third_party_imports']}")
    print(f"Expected optional packages:  {report['expected_package_count']}")
    if report["requirements_exists"]:
        print(f"Declared optional packages:  {report['declared_package_count']} ({report['requirements_file']})")
    else:
        print(f"Declared optional packages:  missing ({report['requirements_file']})")
    print(f"Unmapped import names:       {len(report['unmapped_modules'])}")
    print(f"External runtime imports:    {len(report['external_runtime_imports'])}")
    print(f"Undeclared package names:    {len(report['missing_declared_packages'])}")
    print(f"Extra declared packages:     {len(report['extra_declared_packages'])}")
    print(f"Missing in this Python env:  {report['missing_count']}")
    if report["syntax_errors"]:
        print(f"Syntax errors:               {len(report['syntax_errors'])}")

    if report["unmapped_modules"]:
        print("\nUnmapped import names:")
        for module in report["unmapped_modules"]:
            print(f"  - {module}")

    if report["missing_declared_packages"]:
        print("\nMissing from declared requirements:")
        for package in report["missing_declared_packages"]:
            print(f"  - {package}")

    if report["extra_declared_packages"]:
        print("\nExtra packages in declared requirements:")
        for package in report["extra_declared_packages"]:
            print(f"  - {package}")

    if report["external_runtime_imports"]:
        print("\nExternal runtime imports:")
        for item in report["external_runtime_imports"]:
            examples = ", ".join(item["examples"][:2])
            print(f"  - {item['module']}: {item['runtime']}; e.g. {examples}")

    missing = [item for item in report["modules"] if not item["installed"]]
    if not missing or not show_missing_env_details:
        return

    print("\nMissing optional imports in this Python environment:")
    for item in missing:
        examples = ", ".join(item["examples"][:2])
        if item["packages"]:
            packages = ", ".join(item["packages"])
        elif item["external_runtime"]:
            packages = f"external runtime: {item['external_runtime']}"
        else:
            packages = "UNMAPPED"
        print(f"  - {item['module']} ({packages}): {item['script_count']} script(s); e.g. {examples}")
    print(f"\nInstall declared optional packages with: python3 -m pip install -r {report['requirements_file']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--fail-on-missing", action="store_true", help="Exit non-zero if imports are missing")
    parser.add_argument(
        "--check-declared",
        action="store_true",
        help="Exit non-zero if helper-script imports are unmapped or requirements.txt is stale",
    )
    parser.add_argument(
        "--write-requirements",
        action="store_true",
        help=f"Regenerate {DEFAULT_REQUIREMENTS.relative_to(ROOT)} from helper-script imports",
    )
    parser.add_argument(
        "--requirements-file",
        type=Path,
        default=DEFAULT_REQUIREMENTS,
        help=f"Requirements file to check or write (default: {DEFAULT_REQUIREMENTS.relative_to(ROOT)})",
    )
    args = parser.parse_args()

    requirements_file = args.requirements_file
    if not requirements_file.is_absolute():
        requirements_file = ROOT / requirements_file

    report = audit(requirements_file=requirements_file)
    if args.write_requirements:
        if report["syntax_errors"] or report["unmapped_modules"]:
            if not args.json:
                print_text(report)
            return 2
        write_requirements(requirements_file, report["expected_packages"])
        report = audit(requirements_file=requirements_file)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text(report, show_missing_env_details=(not args.check_declared or args.fail_on_missing))

    if report["syntax_errors"]:
        return 2
    declaration_errors = (
        (not report["requirements_exists"])
        or bool(report["unmapped_modules"])
        or bool(report["missing_declared_packages"])
        or bool(report["extra_declared_packages"])
    )
    if args.check_declared and declaration_errors:
        return 1
    if args.fail_on_missing and report["missing_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
