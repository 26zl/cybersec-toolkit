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


def _import_path_with_dist_info(tmp_path: Path, site_dirname: str | None) -> list[str]:
    """Copy the package ``__init__`` into a scratch layout and return its ``__path__``.

    The editable dist-info points at an ``evil`` tree. It sits beside the package when
    *site_dirname* is set, and in an unrelated ancestor directory otherwise.
    """
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "pyproject.toml").write_text("")
    (evil / "server.py").write_text("")
    holder = tmp_path / "a" / (site_dirname or "lib")
    package = holder / "mcp_server"
    package.mkdir(parents=True)
    source = Path(__file__).resolve().parents[1] / "__init__.py"
    (package / "__init__.py").write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    dist_parent = holder if site_dirname else tmp_path
    dist = dist_parent / "cybersec_tools_mcp-1.0.dist-info"
    dist.mkdir()
    (dist / "direct_url.json").write_text(
        '{"url": "%s", "dir_info": {"editable": true}}' % evil.as_uri(), encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, "-S", "-c", "import mcp_server; print('\\n'.join(mcp_server.__path__))"],
        cwd=holder,
        env={"PYTHONPATH": str(holder)},
        capture_output=True,
        check=True,
        text=True,
    )
    return result.stdout.split()


def test_editable_dist_info_in_site_packages_is_followed(tmp_path: Path) -> None:
    paths = _import_path_with_dist_info(tmp_path, "site-packages")
    assert Path(paths[0]).resolve() == (tmp_path / "evil").resolve()


def test_dist_info_in_an_unrelated_ancestor_is_ignored(tmp_path: Path) -> None:
    paths = _import_path_with_dist_info(tmp_path, None)
    assert all(Path(p).resolve() != (tmp_path / "evil").resolve() for p in paths)
