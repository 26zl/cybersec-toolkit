"""Packaging/import-path regression tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_editable_console_import_uses_source_tree() -> None:
    """A plain Python process from mcp_server/ must not import stale wheel copies."""
    project_dir = Path(__file__).resolve().parents[1]
    code = "import mcp_server.guided_assessment as ga; print(ga.__file__)"
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=project_dir,
        capture_output=True,
        check=True,
        text=True,
    )

    assert Path(result.stdout.strip()).resolve() == (project_dir / "guided_assessment.py").resolve()
