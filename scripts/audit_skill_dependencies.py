#!/usr/bin/env python3
"""Audit optional Python imports used by vendored Claude skill helper scripts."""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / ".claude" / "skills"

STDLIB = set(getattr(sys, "stdlib_module_names", ()))
LOCAL_IMPORTS = {"mcp_server"}
PACKAGE_HINTS = {
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "Crypto": "pycryptodome",
    "dateutil": "python-dateutil",
    "dns": "dnspython",
    "dotenv": "python-dotenv",
    "magic": "python-magic",
    "OpenSSL": "pyOpenSSL",
    "PIL": "Pillow",
    "sklearn": "scikit-learn",
    "win32api": "pywin32",
    "win32con": "pywin32",
    "win32evtlog": "pywin32",
    "yaml": "PyYAML",
    "yara": "yara-python",
}


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
    spec = importlib.util.find_spec(module)
    return spec is not None and spec.origin in {"built-in", "frozen"}


def is_installed(module: str) -> bool:
    return importlib.util.find_spec(module) is not None


def audit() -> dict:
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
        modules.append({
            "module": module,
            "package_hint": PACKAGE_HINTS.get(module, module),
            "installed": installed,
            "script_count": len(files),
            "examples": files[:5],
        })

    return {
        "scripts_checked": len(scripts),
        "third_party_imports": len(modules),
        "missing_count": sum(1 for item in modules if not item["installed"]),
        "syntax_errors": syntax_errors,
        "modules": modules,
    }


def print_text(report: dict) -> None:
    print(f"Skill Python scripts checked: {report['scripts_checked']}")
    print(f"Third-party import names:    {report['third_party_imports']}")
    print(f"Missing in this Python env:  {report['missing_count']}")
    if report["syntax_errors"]:
        print(f"Syntax errors:               {len(report['syntax_errors'])}")

    missing = [item for item in report["modules"] if not item["installed"]]
    if not missing:
        return

    print("\nMissing optional imports:")
    for item in missing:
        examples = ", ".join(item["examples"][:2])
        print(f"  - {item['module']} ({item['package_hint']}): {item['script_count']} script(s); e.g. {examples}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--fail-on-missing", action="store_true", help="Exit non-zero if imports are missing")
    args = parser.parse_args()

    report = audit()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text(report)

    if report["syntax_errors"]:
        return 2
    if args.fail_on_missing and report["missing_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
