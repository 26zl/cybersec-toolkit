#!/usr/bin/env python3
"""Launch a configured release bundle with caller-relative file arguments."""

from __future__ import annotations

import json
import os
import re
import signal
import sys
from pathlib import Path


def cli_style(value: str) -> str:
    return value[:1] + re.sub(r"[-_]", "", value[1:]).lower()


def resolve_name(value: str, names) -> str | None:
    normalized = cli_style(value)
    exact = [name for name in names if cli_style(name) == normalized]
    if exact:
        return exact[0]
    matches = [name for name in names if cli_style(name).startswith(normalized)]
    return matches[0] if len(matches) == 1 else None


def option_schema(fields: str):
    options = {}
    shorts = {}
    for field in fields.split():
        name, short, kind = field.split(":")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", name) or kind not in {"p", "b", "v"}:
            raise ValueError("Invalid command option schema")
        if short != "-" and (len(short) != 1 or short in shorts):
            raise ValueError("Invalid short option schema")
        if name in options:
            raise ValueError("Duplicate command option")
        options[name] = kind
        if short != "-":
            shorts[short] = name
    return options, shorts


def split_value(tail: str):
    if not tail:
        return "=", None
    if tail[0] in "=:":
        return "=", tail[1:]
    if len(tail) > 1 and tail[1] == "=":
        return tail[:2], tail[2:]
    return "=", tail


def update_path(previous: str, operator: str, value: str) -> str:
    if operator == "=":
        return value
    if operator in {"+=", "&="}:
        return previous + value
    if operator == "^=":
        return value + previous
    if len(operator) == 2 and operator[1] == "=" and operator[0] not in ",+-":
        old, separator, new = value.partition(operator[0])
        if separator:
            return previous.replace(old, new)
    raise ValueError("Unsupported path update; use an explicit path assignment")


def translate_arguments(arguments: list[str], caller: str, config: dict) -> list[str]:
    if not arguments or config.get("argument_style", "none") == "none":
        return arguments
    command = resolve_name(arguments[0], config.get("commands", {}))
    if command is None:
        return arguments
    options, shorts = option_schema(config["commands"][command])
    paths = dict(config.get("default_outputs", {}).get(command, {}))
    explicit_paths = set()
    result = [arguments[0]]
    trailing = []
    informational = False
    booleans = {}
    index = 1

    def handle(name, operator, value):
        nonlocal informational
        if options[name] == "p":
            paths[name] = update_path(paths.get(name, ""), operator, value)
            explicit_paths.add(name)
        if options[name] == "b":
            booleans[name] = value is None or value.lower() in {"true", "on", "yes", "t", "y", "1"}
        if name in config.get("informational_options", []):
            informational = informational or options[name] != "b" or booleans[name]

    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            trailing = arguments[index:]
            break
        match = re.match(r"^--([A-Za-z][A-Za-z0-9_-]*)(.*)$", token)
        if match:
            raw_name, tail = match.groups()
            name = resolve_name(raw_name, options)
            if name is None:
                result.append(token)
            else:
                operator, value = split_value(tail)
                if raw_name.endswith("-") and tail.startswith("="):
                    operator = "-="
                if options[name] != "b" and value is None:
                    if index + 1 >= len(arguments):
                        raise ValueError(f"Missing value for --{name}")
                    index += 1
                    value = arguments[index]
                handle(name, operator, value)
                if options[name] != "p":
                    result.append(token)
                    if not tail and value is not None and options[name] != "b":
                        result.append(value)
        elif token.startswith("-") and token != "-":
            offset = 1
            while offset < len(token):
                letter = token[offset]
                name = shorts.get(letter)
                if name is None:
                    result.append("-" + token[offset:])
                    break
                tail = token[offset + 1 :]
                if options[name] == "b" and not tail.startswith(("=", ":")):
                    handle(name, "=", None)
                    result.append("-" + letter)
                    offset += 1
                    continue
                operator, value = split_value(tail)
                if value is None:
                    if index + 1 >= len(arguments):
                        raise ValueError(f"Missing value for -{letter}")
                    index += 1
                    value = arguments[index]
                handle(name, operator, value)
                if options[name] != "p":
                    result.append("-" + letter + tail)
                    if not tail:
                        result.append(value)
                break
        else:
            result.append(token)
        index += 1

    conditional_default = config.get("conditional_defaults", {}).get(command)
    if not informational and conditional_default:
        name = conditional_default["option"]
        if not paths.get(name):
            alternate = booleans.get(conditional_default["boolean_option"], False)
            paths[name] = conditional_default["alternate" if alternate else "default"]
    if informational:
        paths = {name: value for name, value in paths.items() if name in explicit_paths}
    # Joining without normalization preserves symlink/.. semantics and empty stdout paths.
    result.extend(
        f"--{name}={value if not value or os.path.isabs(value) else os.path.join(caller, value)}"
        for name, value in paths.items()
    )
    return result + trailing


def bundle_path(directory: Path, value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Invalid bundle path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Bundle paths must stay within the release directory")
    path = directory / relative
    for part in [path, *path.parents]:
        if part == directory:
            break
        if part.is_symlink():
            raise ValueError("Bundle paths must not use symlinks")
    return path


def load_configuration(directory: Path) -> dict:
    manifest = bundle_path(directory, ".runtime-launcher.json")
    config = json.loads(manifest.read_text())
    if not isinstance(config, dict):
        raise ValueError("Invalid runtime launcher configuration")
    if config.get("argument_style", "none") not in {"none", "cligen"}:
        raise ValueError("Unsupported runtime argument style")
    commands = config.get("commands", {})
    if not isinstance(commands, dict):
        raise ValueError("Invalid command schemas")
    for command, schema in commands.items():
        if not isinstance(command, str) or not command or not isinstance(schema, str):
            raise ValueError("Invalid command schema")
        option_schema(schema)
    for command, defaults in config.get("default_outputs", {}).items():
        if command not in commands or not isinstance(defaults, dict):
            raise ValueError("Invalid default output configuration")
        options, _ = option_schema(commands[command])
        for name, value in defaults.items():
            if options.get(name) != "p" or not isinstance(value, str):
                raise ValueError("Invalid default output option")
    for command, default in config.get("conditional_defaults", {}).items():
        if command not in commands or not isinstance(default, dict):
            raise ValueError("Invalid conditional path default")
        options, _ = option_schema(commands[command])
        if options.get(default.get("option")) != "p" or options.get(default.get("boolean_option")) != "b":
            raise ValueError("Invalid conditional path options")
        if not all(isinstance(default.get(key), str) for key in ("default", "alternate")):
            raise ValueError("Invalid conditional path values")
    for key in ("informational_options", "library_directories", "required_files"):
        values = config.get(key, [])
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError(f"Invalid {key} configuration")
    return config


def main() -> None:
    launcher = Path(__file__).resolve()
    directory = launcher.parent
    config = load_configuration(directory)
    executable = bundle_path(directory, config.get("executable"))
    if executable == launcher or not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("Bundle executable is missing or not executable")
    working_directory = bundle_path(directory, config["working_directory"]) if "working_directory" in config else None
    if working_directory is not None and not working_directory.is_dir():
        raise ValueError("Bundle working directory is missing")
    libraries = [bundle_path(directory, value) for value in config.get("library_directories", [])]
    if not all(path.is_dir() for path in libraries):
        raise ValueError("Bundle library directory is missing")
    for value in config.get("required_files", []):
        if not bundle_path(directory, value).is_file():
            raise ValueError("Required bundle runtime file is missing")
    arguments = translate_arguments(sys.argv[1:], os.getcwd(), config)
    environment = os.environ.copy()
    inherited = environment.get("LD_LIBRARY_PATH", "")
    if libraries:
        environment["LD_LIBRARY_PATH"] = ":".join(str(path) for path in libraries) + (
            ":" + inherited if inherited else ""
        )
    if working_directory is not None:
        os.chdir(working_directory)
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    os.execve(executable, [str(executable), *arguments], environment)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(f"Runtime launcher: {error}", file=sys.stderr)
        sys.exit(1)
