#!/usr/bin/env python3
"""Assert the tracked client MCP configs launch the same default-safe server.

Checks .mcp.json, opencode.jsonc, .codex/config.toml and .gemini/settings.json:
every file must carry the shared launch command (no ``--local``) and exactly the
two default-safe environment variables. Offline and stdlib-only; needs Python 3.11+.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parent.parent
LAUNCH = ["bash", "-lc", 'cd "$(git rev-parse --show-toplevel)" && exec bash scripts/mcp-launch.sh']
SAFE_ENV = {"CYBERSEC_MCP_ALLOW_EXTERNAL": "0", "CYBERSEC_MCP_ALLOW_SCRIPTS": "0"}
SERVER = "cybersec-tools"
FILES = (".mcp.json", "opencode.jsonc", ".codex/config.toml", ".gemini/settings.json")
USAGE = "usage: validate_client_configs.py [--selftest]"


def strip_jsonc(text: str) -> str:
    """Drop // and /* */ comments and trailing commas outside string literals."""
    out: list[str] = []
    i = 0
    in_str = False
    while i < len(text):
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise ValueError("unterminated /* comment")
            i = end + 2
            continue
        else:
            out.append(c)
        i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    out: list[str] = []
    in_str = False
    for i, c in enumerate(text):
        if in_str:
            out.append(c)
            if c == '"' and not _escaped(text, i):
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif c == "," and re.match(r"\s*[}\]]", text[i + 1 :]):
            continue
        else:
            out.append(c)
    return "".join(out)


def _escaped(text: str, i: int) -> bool:
    n = 0
    while i - 1 - n >= 0 and text[i - 1 - n] == "\\":
        n += 1
    return n % 2 == 1


def extract(name: str, text: str) -> tuple[list[str], dict]:
    if name == ".codex/config.toml":
        s = tomllib.loads(text)["mcp_servers"][SERVER]
        return [s["command"], *s["args"]], s.get("env", {})
    if name == "opencode.jsonc":
        s = json.loads(strip_jsonc(text))["mcp"][SERVER]
        return s["command"], s.get("environment", {})
    s = json.loads(text)["mcpServers"][SERVER]
    return [s["command"], *s["args"]], s.get("env", {})


def check(name: str, text: str) -> list[str]:
    try:
        command, env = extract(name, text)
    except (KeyError, ValueError, TypeError, IndexError) as exc:
        return [f"{name}: cannot read the {SERVER} entry ({exc!r})"]
    errors = []
    if command != LAUNCH:
        errors.append(f"{name}: launch command differs from the shared launcher")
    if any("--local" in str(part) for part in command):
        errors.append(f"{name}: must not pass --local")
    if env != SAFE_ENV:
        errors.append(f"{name}: env must contain only CYBERSEC_MCP_ALLOW_EXTERNAL=0 and CYBERSEC_MCP_ALLOW_SCRIPTS=0")
    return errors


def selftest() -> int:
    texts = {n: (ROOT / n).read_text(encoding="utf-8") for n in FILES}
    for name, text in texts.items():
        assert check(name, text) == [], f"selftest: {name} should be valid"

    for name, text in texts.items():
        scripts_on = text.replace('"CYBERSEC_MCP_ALLOW_SCRIPTS": "0"', '"CYBERSEC_MCP_ALLOW_SCRIPTS": "1"')
        scripts_on = scripts_on.replace('CYBERSEC_MCP_ALLOW_SCRIPTS = "0"', 'CYBERSEC_MCP_ALLOW_SCRIPTS = "1"')
        assert scripts_on != text and check(name, scripts_on), f"selftest: {name} ALLOW_SCRIPTS=1 must fail"
        local = text.replace("mcp-launch.sh", "mcp-launch.sh --local")
        assert local != text and check(name, local), f"selftest: {name} --local must fail"
        no_env = re.sub(r'"?CYBERSEC_MCP_ALLOW_EXTERNAL"?\s*[:=]\s*"0",?', "", text)
        assert no_env != text and check(name, no_env), f"selftest: {name} missing env must fail"

    assert check(".mcp.json", '{"mcpServers": {}}'), "selftest: missing entry must fail"
    assert check(".mcp.json", "{"), "selftest: invalid JSON must fail"
    assert check(".codex/config.toml", "[mcp_servers]"), "selftest: missing TOML entry must fail"
    assert json.loads(strip_jsonc('{"a": "//x", /* c */ "b": "q\\\\", // t\n"c": ",}",}')) == {
        "a": "//x",
        "b": "q\\",
        "c": ",}",
    }
    print("selftest OK")
    return 0


def main() -> int:
    from _cli import check_args

    check_args({"--selftest"}, USAGE)
    if "--selftest" in sys.argv[1:]:
        return selftest()
    errors: list[str] = []
    for name in FILES:
        try:
            text = (ROOT / name).read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{name}: cannot read ({exc})")
            continue
        errors.extend(check(name, text))
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if not errors:
        print(f"client configs OK ({len(FILES)} files)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
