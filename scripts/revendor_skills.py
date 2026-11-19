#!/usr/bin/env python3
"""Merge upstream changes into the vendored skills of one source.

For each vendored skill the source also ships, three trees are merged: the
upstream version the local copy was taken from, the local copy, and the upstream
version at the target commit. Local edits survive the merge.

The merge base is found by content rather than read from the recorded pin: a pin
can be newer than the files under it, and upstream history can be rewritten.
A local file identical to any earlier upstream version of itself counts as
unmodified and is replaced by the target version. A file that upstream ships and
the local copy lacks counts as deliberately removed and stays removed.

SKILL.md frontmatter is merged key by key, so provenance keys added locally do
not collide with an upstream edit on the neighbouring line. When both sides
introduce the same key, the upstream value wins.

A source moves as a whole. If any of its skills conflicts, nothing is written and
the conflicts are reported, so the recorded pin never describes a mixed state.
To resolve by hand: run with --mark-conflicts, edit the conflict markers, then
run with --finalize.

Only files are copied. Nothing from the upstream repository is executed, and a
skill containing a symlink or submodule is refused. Invisible characters in an
incoming file (Unicode tag characters, zero-width spaces, bidi controls) are
written as visible <U+XXXX> escapes and listed in the report.

Usage:
    revendor_skills.py --clone DIR --pin SHA --target SHA [--skills-dir DIR]
                       [--name LABEL] [--prune] [--list-local-edits]
                       [--mark-conflicts | --finalize] [--dry-run]

Exit status: 0 when every skill is at the target, 3 when some need manual work,
1 on error.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _skill_text import FRONTMATTER_FENCE, FRONTMATTER_KEY, drop_tool_grant, has_unparsed_grant, show_invisible  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SKILLS_DIR = REPO_ROOT / ".claude" / "skills"

SKILL_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
CONFLICT_LINE = re.compile(r"(\d{6}) ([0-9a-f]{40,64}) ([123])\t(.+)", re.DOTALL)
CONFLICT_MARKER = re.compile(rb"(?m)^(<{7}|>{7}|\|{7})( |$)")
REGULAR_MODES = {"100644", "100755"}
LOCAL_JUNK_DIRS = {"__pycache__", ".pytest_cache", ".ruff_cache"}
LOCAL_JUNK_SUFFIXES = (".pyc", ".pyo")
HISTORY_LIMIT = 300
MIN_GIT = (2, 45)

Entries = dict[str, tuple[str, str]]
Blocks = list[tuple[str, str]]


class UnsafeSkill(Exception):
    """The skill holds something other than regular files."""


class Git:
    def __init__(self, clone: Path) -> None:
        located = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "--absolute-git-dir"], capture_output=True, text=True, check=True
        )
        self._env = {**os.environ, "GIT_DIR": located.stdout.strip(), "LC_ALL": "C"}

    def run(self, *args: str, stdin: bytes | None = None, ok: tuple[int, ...] = (0,), env: dict | None = None) -> bytes:
        proc = subprocess.run(["git", *args], input=stdin, capture_output=True, env={**self._env, **(env or {})})
        if proc.returncode not in ok:
            raise RuntimeError(f"git {' '.join(args[:3])} failed: {proc.stderr.decode(errors='replace').strip()}")
        return proc.stdout

    def text(self, *args: str) -> str:
        return self.run(*args).decode("utf-8", errors="surrogateescape")

    def exists(self, obj: str) -> bool:
        return subprocess.run(["git", "cat-file", "-e", obj], capture_output=True, env=self._env).returncode == 0

    def entries(self, treeish: str) -> Entries:
        found: Entries = {}
        for record in self.run("ls-tree", "-r", "-z", treeish).split(b"\0"):
            if not record:
                continue
            meta, path = record.split(b"\t", 1)
            mode, _kind, oid = meta.decode().split()
            found[path.decode("utf-8", errors="surrogateescape")] = (mode, oid)
        return found

    def write_tree(self, entries: Entries) -> str:
        with tempfile.TemporaryDirectory() as scratch:
            env = {"GIT_INDEX_FILE": str(Path(scratch) / "index")}
            listing = b"".join(
                f"{mode} {oid}\t{path}".encode() + b"\0" for path, (mode, oid) in sorted(entries.items())
            )
            self.run("update-index", "-z", "--index-info", stdin=listing, env=env)
            return self.run("write-tree", env=env).decode().strip()

    def blob(self, oid: str) -> bytes:
        return self.run("cat-file", "blob", oid)

    def store(self, content: bytes) -> str:
        return self.run("hash-object", "-w", "--no-filters", "--stdin", stdin=content).decode().strip()

    def merge_text(self, base: bytes, ours: bytes, theirs: bytes) -> tuple[bytes, bool]:
        """Three-way merge of one file; the flag is False when conflict markers were left in the result."""
        with tempfile.TemporaryDirectory() as scratch:
            names = []
            for label, content in (("ours", ours), ("base", base), ("theirs", theirs)):
                path = Path(scratch) / label
                path.write_bytes(content)
                names.append(str(path))
            labels = ["-L", "local", "-L", "base", "-L", "upstream"]
            proc = subprocess.run(["git", "merge-file", "-p", "--diff3", *labels, *names], capture_output=True)
        if proc.returncode < 0 or proc.returncode > 127:
            raise RuntimeError(f"git merge-file failed: {proc.stderr.decode(errors='replace').strip()}")
        return proc.stdout, proc.returncode == 0


def require_git() -> None:
    out = subprocess.run(["git", "--version"], capture_output=True, text=True, check=True).stdout
    found = re.search(r"(\d+)\.(\d+)", out)
    if not found or (int(found.group(1)), int(found.group(2))) < MIN_GIT:
        raise RuntimeError(f"git {MIN_GIT[0]}.{MIN_GIT[1]}+ is required for tree merges, found: {out.strip()}")


def skill_paths(git: Git, commit: str) -> dict[str, list[str]]:
    """Map each skill name to the upstream directories that hold a SKILL.md for it."""
    found: dict[str, list[str]] = {}
    for path in git.text("ls-tree", "-r", "--name-only", "-z", commit).split("\0"):
        if path.endswith("/SKILL.md"):
            directory = path[: -len("/SKILL.md")]
            found.setdefault(directory.rsplit("/", 1)[-1], []).append(directory)
    return found


def local_files(skill_dir: Path) -> list[tuple[str, Path]]:
    paths: list[tuple[str, Path]] = []
    for root, dirs, files in os.walk(skill_dir):
        dirs[:] = sorted(d for d in dirs if d not in LOCAL_JUNK_DIRS)
        for directory in dirs:
            if (Path(root) / directory).is_symlink():
                raise UnsafeSkill(f"local symlink {directory}")
        for name in sorted(files):
            full = Path(root) / name
            if full.is_symlink():
                raise UnsafeSkill(f"local symlink {full.relative_to(skill_dir)}")
            if name.endswith(LOCAL_JUNK_SUFFIXES) or name == ".DS_Store":
                continue
            if "\n" in str(full):
                raise UnsafeSkill("newline in a local file name")
            paths.append((full.relative_to(skill_dir).as_posix(), full))
    return paths


def local_entries(git: Git, skill_dir: Path) -> Entries:
    paths = local_files(skill_dir)
    if not paths:
        return {}
    listing = "".join(f"{full}\n" for _, full in paths).encode()
    oids = git.run("hash-object", "-w", "--no-filters", "--stdin-paths", stdin=listing).decode().split()
    return {rel: ("100755" if os.access(full, os.X_OK) else "100644", oid) for (rel, full), oid in zip(paths, oids)}


def similarity(left: bytes, right: bytes) -> float:
    a = left.decode(errors="replace").splitlines()
    b = right.decode(errors="replace").splitlines()
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def pick_base(git: Git, pin: str, path_at_pin: str, ours: Entries, theirs: Entries) -> tuple[Entries, bool, list[str]]:
    """Rebuild the upstream tree the local copy came from.

    Also returns whether the copy predates the pin, and the files that match no upstream version.
    """
    commits = git.text("rev-list", f"--max-count={HISTORY_LIMIT}", pin, "--", path_at_pin).split()
    versions: list[Entries] = [git.entries(f"{pin}:{path_at_pin}")]
    for commit in commits:
        if commit == pin:
            continue
        try:
            versions.append(git.entries(f"{commit}:{path_at_pin}"))
        except RuntimeError:
            continue  # the commit that removed or first moved the directory has no tree for it

    def score(candidate: Entries) -> int:
        return sum(1 for rel, entry in ours.items() if candidate.get(rel, ("", ""))[1] == entry[1])

    # Ties go to the newest version, so an unmodified copy is assumed to be at the pin.
    best = max(range(len(versions)), key=lambda i: (score(versions[i]), -i))
    base = dict(versions[best])
    predates_pin = best != 0
    edited: list[str] = []
    for rel, (mode, oid) in ours.items():
        if base.get(rel, ("", ""))[1] == oid:
            continue
        if theirs.get(rel, ("", ""))[1] == oid:
            base[rel] = (mode, oid)  # already at the target version
            continue
        earlier = [v[rel] for v in versions if rel in v]
        if not earlier:
            continue
        if any(old_oid == oid for _, old_oid in earlier):
            base[rel] = (mode, oid)
            predates_pin = True
            continue
        local = git.blob(oid)
        closest = max(dict.fromkeys(old_oid for _, old_oid in earlier), key=lambda o: similarity(git.blob(o), local))
        base[rel] = (base.get(rel, (mode, ""))[0], closest)
        edited.append(rel)
    return base, predates_pin, edited


def merge_trees(git: Git, base: str, ours: str, theirs: str) -> tuple[str, dict[str, dict[int, str]]]:
    """Return the merged tree and, per conflicted path, the blob at each stage (1 base, 2 ours, 3 theirs)."""
    out = git.run("merge-tree", "--write-tree", "-z", f"--merge-base={base}", ours, theirs, ok=(0, 1))
    fields = out.decode(errors="replace").split("\0")
    conflicts: dict[str, dict[int, str]] = {}
    for field in fields[1:]:
        if not field:
            break
        parsed = CONFLICT_LINE.fullmatch(field)
        if parsed:
            conflicts.setdefault(parsed.group(4), {})[int(parsed.group(3))] = parsed.group(2)
    return fields[0], conflicts


def split_frontmatter(text: str) -> tuple[Blocks, str] | None:
    """Split a document into ordered (key, block) frontmatter pairs and the body; None when it cannot be keyed."""
    fences = list(FRONTMATTER_FENCE.finditer(text))
    if not text.startswith("---") or len(fences) < 2 or fences[0].start() != 0:
        return [], text
    inner = text[fences[0].end() + 1 : fences[1].start()]
    body = text[fences[1].end() :]
    blocks: Blocks = []
    for line in inner.splitlines(keepends=True):
        key = FRONTMATTER_KEY.match(line)
        if key:
            blocks.append((key.group(1), line))
        elif blocks:
            blocks[-1] = (blocks[-1][0], blocks[-1][1] + line)
        elif line.strip():
            return None
    if len({key for key, _ in blocks}) != len(blocks):
        return None
    return blocks, body.removeprefix("\n")


def merge_frontmatter(base: Blocks, ours: Blocks, theirs: Blocks) -> Blocks | None:
    b, o, t = dict(base), dict(ours), dict(theirs)
    merged: dict[str, str] = {}
    for key in dict.fromkeys([k for k, _ in theirs] + [k for k, _ in ours]):
        before, local, upstream = b.get(key), o.get(key), t.get(key)
        if local == upstream or upstream == before:
            value = local
        elif local == before or before is None:
            value = upstream
        else:
            return None
        if value is not None:
            merged[key] = value if value.endswith("\n") else value + "\n"
    order = [k for k, _ in theirs if k in merged]
    for index, (key, _) in enumerate(ours):
        if key in merged and key not in order:
            previous = next((p for p, _ in reversed(ours[:index]) if p in order), None)
            order.insert(order.index(previous) + 1 if previous is not None else 0, key)
    return [(key, merged[key]) for key in order]


def merge_skill_md(git: Git, base: bytes, ours: bytes, theirs: bytes) -> tuple[bytes, bool] | None:
    """Merge frontmatter by key and the body by line; None when the frontmatter itself conflicts."""
    parts = [split_frontmatter(blob.decode(errors="surrogateescape")) for blob in (base, ours, theirs)]
    if any(part is None for part in parts):
        return None
    (base_fm, base_body), (ours_fm, ours_body), (theirs_fm, theirs_body) = parts
    frontmatter = merge_frontmatter(base_fm, ours_fm, theirs_fm)
    if frontmatter is None:
        return None
    bodies = [text.encode(errors="surrogateescape") for text in (base_body, ours_body, theirs_body)]
    body, clean = git.merge_text(*bodies)
    head = "---\n" + "".join(block for _, block in frontmatter) + "---\n" if frontmatter else ""
    return head.encode(errors="surrogateescape") + body, clean


def top_dirs(entries: Entries) -> set[str]:
    return {rel.split("/", 1)[0] for rel in entries if "/" in rel}


def merge_skill(
    git: Git, pin: str, path_at_pin: str, theirs_ref: str, ours: Entries
) -> tuple[Entries, list[str], bool, list[str], list[str]]:
    """Merge one skill.

    Returns the merged entries, the paths in conflict, whether the copy predated the
    pin, the files with local edits, and the incoming files whose invisible characters
    were made visible.
    """
    theirs = git.entries(theirs_ref)
    shown: list[str] = []
    for rel, (mode, oid) in list(theirs.items()):
        if mode not in REGULAR_MODES:
            raise UnsafeSkill(f"upstream {rel} has mode {mode}")
        if ours.get(rel, ("", ""))[1] == oid:
            continue
        blob = git.blob(oid)
        if b"\0" in blob and rel != "SKILL.md":
            continue  # binary; rewriting bytes that merely look like escapes would corrupt it
        text = blob.decode("utf-8", errors="surrogateescape")
        visible = show_invisible(text)
        # An upstream skill does not get to pre-approve tools for itself.
        incoming = drop_tool_grant(visible) if rel == "SKILL.md" else visible
        if rel == "SKILL.md" and has_unparsed_grant(incoming):
            raise UnsafeSkill("SKILL.md names allowed-tools in a form that cannot be removed")
        if incoming != text:
            theirs[rel] = (mode, git.store(incoming.encode("utf-8", errors="surrogateescape")))
        if visible != text:
            shown.append(rel)
    base, predates_pin, edited = pick_base(git, pin, path_at_pin, ours, theirs)
    merged_tree, conflicts = merge_trees(git, git.write_tree(base), git.write_tree(ours), git.write_tree(theirs))
    merged = git.entries(merged_tree)

    # A helper directory removed from the local copy stays removed, including files upstream adds to it later.
    trimmed = top_dirs(base) - top_dirs(ours)
    unresolved = []
    for rel, stages in conflicts.items():
        if 2 not in stages or rel.split("/", 1)[0] in trimmed:
            merged.pop(rel, None)
            continue
        if rel == "SKILL.md" and 3 in stages:
            before = git.blob(stages[1]) if 1 in stages else b""
            keyed = merge_skill_md(git, before, git.blob(stages[2]), git.blob(stages[3]))
            if keyed is not None:
                merged[rel] = (ours[rel][0], git.store(keyed[0]))
                if keyed[1]:
                    continue
        unresolved.append(rel)
    merged = {rel: entry for rel, entry in merged.items() if "/" not in rel or rel.split("/", 1)[0] not in trimmed}
    return merged, sorted(unresolved), predates_pin, edited, shown


def write_skill(git: Git, entries: Entries, dest: Path) -> None:
    staging = dest.with_name(f".revendor-new-{dest.name}")
    retired = dest.with_name(f".revendor-old-{dest.name}")
    for leftover in (staging, retired):
        if leftover.exists():
            shutil.rmtree(leftover)
    for rel, (mode, oid) in entries.items():
        target = staging / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git.blob(oid))
        target.chmod(0o755 if mode == "100755" else 0o644)
    dest.rename(retired)
    staging.rename(dest)
    shutil.rmtree(retired)


def marked_files(skill_dir: Path) -> list[str]:
    return [rel for rel, full in local_files(skill_dir) if CONFLICT_MARKER.search(full.read_bytes())]


def bump_frontmatter_pin(skill_md: Path, old: str, new: str) -> bool:
    text = skill_md.read_text(encoding="utf-8", errors="surrogateescape")
    fences = list(FRONTMATTER_FENCE.finditer(text))
    if len(fences) < 2 or fences[0].start() != 0:
        return False
    end = fences[1].start()
    head = re.sub(rf"(?m)^(upstream_commit:\s*){re.escape(old)}[ \t]*$", rf"\g<1>{new}", text[:end])
    if head == text[:end]:
        return False
    skill_md.write_text(head + text[end:], encoding="utf-8", errors="surrogateescape")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--clone", required=True, type=Path, help="local clone of the upstream repository")
    parser.add_argument("--pin", required=True, help="commit the vendored copies are recorded at")
    parser.add_argument("--target", required=True, help="upstream commit to move to")
    parser.add_argument("--skills-dir", type=Path, default=DEFAULT_SKILLS_DIR)
    parser.add_argument("--name", default="source", help="label used in the report")
    parser.add_argument("--prune", action="store_true", help="delete vendored skills that upstream removed")
    parser.add_argument("--list-local-edits", action="store_true", help="list files that match no upstream version")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--mark-conflicts", action="store_true", help="write the merge with conflict markers to edit")
    mode.add_argument("--finalize", action="store_true", help="accept hand-resolved skills; merge nothing")
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    args = parser.parse_args(argv)

    try:
        require_git()
        git = Git(args.clone)
        for commit in (args.pin, args.target):
            if not git.exists(f"{commit}^{{commit}}"):
                raise RuntimeError(f"commit {commit} is not in {args.clone}")
        at_pin, at_target = skill_paths(git, args.pin), skill_paths(git, args.target)
    except (RuntimeError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    ours = sorted(p.parent.name for p in args.skills_dir.glob("*/SKILL.md"))
    claimed = [name for name in ours if name in at_pin]
    planned: dict[str, Entries] = {}
    unchanged, predated, removed, local_edits, made_visible = [], [], [], [], []
    blocked: dict[str, str] = {}

    for name in claimed:
        skill_dir = args.skills_dir / name
        if not SKILL_NAME.fullmatch(name):
            blocked[name] = "unexpected directory name"
            continue
        if len(at_pin[name]) > 1 or len(at_target.get(name, [])) > 1:
            blocked[name] = "several upstream directories share this skill name"
            continue
        if name not in at_target:
            removed.append(name)
            continue
        try:
            if args.finalize:
                marked = marked_files(skill_dir)
                if marked:
                    blocked[name] = "conflict markers left in " + ", ".join(marked)
                continue
            local = local_entries(git, skill_dir)
            merged, unresolved, predates_pin, edited, shown = merge_skill(
                git, args.pin, at_pin[name][0], f"{args.target}:{at_target[name][0]}", local
            )
        except UnsafeSkill as exc:
            blocked[name] = f"refused: {exc}"
            continue
        except RuntimeError as exc:
            print(f"error: {name}: {exc}", file=sys.stderr)
            return 1
        if "SKILL.md" not in merged:
            blocked[name] = "merge result has no SKILL.md"
            continue
        if predates_pin:
            predated.append(name)
        local_edits.extend(f"{name}/{rel}" for rel in edited)
        made_visible.extend(f"{name}/{rel}" for rel in shown)
        if unresolved:
            blocked[name] = "conflict in " + ", ".join(unresolved)
            if args.mark_conflicts:
                planned[name] = merged
        elif merged == local:
            unchanged.append(name)
        else:
            planned[name] = merged

    pin_advances = not blocked
    writes = not args.dry_run and (pin_advances or args.mark_conflicts)
    if writes:
        for name, entries in planned.items():
            write_skill(git, entries, args.skills_dir / name)
        if args.prune:
            for name in removed:
                shutil.rmtree(args.skills_dir / name)
    if pin_advances and not args.dry_run and args.pin != args.target:
        for name in claimed:
            skill_md = args.skills_dir / name / "SKILL.md"
            if skill_md.is_file():
                bump_frontmatter_pin(skill_md, args.pin, args.target)

    updated = sorted(name for name in planned if name not in blocked)
    held = bool(planned) and not writes and not args.dry_run
    # Upstream directory names end up in a pull request body, so only well-formed ones are printed.
    candidates = set(at_target) - set(at_pin) - set(ours)
    new_upstream = sorted(name for name in candidates if SKILL_NAME.fullmatch(name))
    odd_names = len(candidates) - len(new_upstream)
    print(f"== {args.name}: {args.pin[:12]} -> {args.target[:12]}{' (dry run)' if args.dry_run else ''}")
    print(
        f"  vendored: {len(claimed)}  {'mergeable' if held else 'updated'}: {len(updated)}  "
        f"unchanged: {len(unchanged)}  blocked: {len(blocked)}  removed upstream: {len(removed)}"
    )
    if predated:
        print(f"  {len(predated)} local copies predated the recorded pin")
    if local_edits:
        print(f"  {len(local_edits)} files carry local edits (kept){':' if args.list_local_edits else ''}")
        if args.list_local_edits:
            for path in local_edits:
                print(f"  LOCAL-EDIT: {path}")
    if updated:
        print(f"  {'MERGEABLE' if held else 'UPDATED'}: {' '.join(updated)}")
    for path in made_visible:
        print(f"  INVISIBLE-TEXT: {path} (written as <U+XXXX> escapes; review what it spelled)")
    for name, reason in blocked.items():
        print(f"  BLOCKED: {name}: {reason}")
    for name in removed:
        print(f"  {'PRUNED' if args.prune and writes else 'REMOVED-UPSTREAM'}: {name}")
    if new_upstream:
        print(f"  NEW-UPSTREAM: {' '.join(new_upstream)}")
    if odd_names:
        print(f"  NEW-UPSTREAM: {odd_names} more with names outside the skill naming rule")
    if pin_advances:
        print("  PIN: advance")
    elif args.mark_conflicts:
        print("  PIN: hold (resolve the conflict markers, then run with --finalize)")
    else:
        print("  PIN: hold (nothing written; run with --mark-conflicts to resolve by hand)")
    return 0 if pin_advances else 3


if __name__ == "__main__":
    sys.exit(main())
