"""Cybersec Toolkit MCP Server — query 580+ tools, get recommendations, execute safely."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote, urlparse


def _editable_project_root() -> Path | None:
    """Return the flat source tree for editable installs, when available.

    This project keeps the package modules directly in ``mcp_server/`` rather
    than in ``mcp_server/mcp_server/``. Hatchling's editable install therefore
    exposes a generated package under site-packages. Without extending
    ``__path__`` back to the source tree, ``uv run cybersec-mcp`` can import a
    stale copied module after local edits.
    """
    package_file = Path(__file__).resolve()
    for parent in package_file.parents:
        for direct_url in parent.glob("cybersec_tools_mcp-*.dist-info/direct_url.json"):
            try:
                data = json.loads(direct_url.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not data.get("dir_info", {}).get("editable"):
                continue
            parsed = urlparse(data.get("url", ""))
            if parsed.scheme != "file":
                continue
            candidate = Path(unquote(parsed.path))
            if (candidate / "pyproject.toml").is_file() and (candidate / "server.py").is_file():
                return candidate
    return None


_source_root = _editable_project_root()
if _source_root is not None:
    _source_root_str = str(_source_root)
    if _source_root_str not in __path__:
        __path__.insert(0, _source_root_str)
