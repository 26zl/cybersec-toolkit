"""The zip write guard checked against the real zip: every path zip writes or deletes is a target."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess

import pytest

from mcp_server.security import _zip_write_targets

pytestmark = pytest.mark.skipif(shutil.which("zip") is None, reason="needs Info-ZIP zip")

VECTORS = [
    "out.zip f.txt",
    "-qr out.zip d",
    "-x '*.o' -r out.zip d",
    "-rx '*.o' extra.zip -q out.zip d",
    "-x*.o extra.zip -r out.zip d",
    "--excl '*.o' -r out.zip d",
    "-r out.zip d -x '*.o' more.zip",
    "-b . out.zip f.txt",
    "-b. out.zip f.txt",
    "--temp-path=. out.zip f.txt",
    "base.zip -O new.zip f.txt",
    "-qrO new.zip base.zip f.txt",
    "-qOnew.zip base.zip f.txt",
    "--out new.zip base.zip f.txt",
    "-qlf log.txt out.zip f.txt",
    "-qlflog.txt out.zip f.txt",
    "-qdb out.zip f.txt",
    "-qPsecret out.zip f.txt",
    "-Pm out.zip f.txt",
    "-qm out.zip f.txt",
    "-rmq out.zip d",
    "--mov out.zip f.txt",
    "-q -m -x '*.o' -r out.zip d",
    "-qtt 01012030 out.zip f.txt",
    "-d base.zip f.txt",
    "-X-lf log.txt out.zip f.txt",
    "-X-m out.zip f.txt",
    "-X-rm out.zip d",
    "-X-Onew.zip base.zip f.txt",
    "-la-lflog.txt out.zip f.txt",
    "-n= out.zip f.txt",
    "-ds= out.zip f.txt",
    "-X-b . out.zip f.txt",
]


def _state(root: str) -> dict[str, tuple[int, int, int]]:
    state = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            state[os.path.relpath(path, root)] = (st.st_mtime_ns, st.st_size, st.st_ino)
    return state


@pytest.mark.parametrize("vector", VECTORS)
def test_every_path_zip_touches_is_a_target(vector, tmp_path):
    (tmp_path / "d").mkdir()
    for rel, body in {"f.txt": "f", "d/a.txt": "a", "d/b.o": "b"}.items():
        (tmp_path / rel).write_text(body)
    subprocess.run(["zip", "-q", "base.zip", "f.txt"], cwd=tmp_path, check=True)
    argv = shlex.split(vector)
    before = _state(str(tmp_path))
    subprocess.run(["zip", *argv], cwd=tmp_path, capture_output=True, check=False)
    after = _state(str(tmp_path))
    touched = [p for p in after if before.get(p) != after[p] and not (tmp_path / p).is_dir()]
    touched += [p for p in before if p not in after]
    targets = {os.path.normpath(t) for t in _zip_write_targets(argv)}
    for path in touched:
        parts = path.split(os.sep)
        assert any(os.sep.join(parts[: n + 1]) in targets for n in range(len(parts))), (path, targets)
