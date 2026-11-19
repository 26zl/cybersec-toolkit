#!/usr/bin/env python3
"""Check external links in the repository's Markdown for rot.

markdownlint validates structure, not reachability. This walks tracked *.md
(skipping the same vendored paths the Makefile excludes), extracts http(s) URLs,
and reports links that are confirmed dead — DNS failure, connection refused, or a
404/410. Ambiguous responses (timeouts, 401/403/405/429, other 5xx) are reported
as "unverified" and do NOT fail the run, because external hosts routinely block
bots or rate-limit rather than being gone.

--internal checks relative file links and #anchors instead, offline and fast.

Usage:
    python3 scripts/check_doc_links.py [--timeout N] [--path DIR]...
    python3 scripts/check_doc_links.py --internal    # relative links + anchors; offline
    python3 scripts/check_doc_links.py --self-test   # offline; no network
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Mirror Makefile MD_EXCLUDE: vendored/generated trees we do not own.
EXCLUDE_PREFIXES = (
    "tests/bats/",
    "tests/test_helper/",
    "mcp_server/.venv/",
    ".claude/skills/",
    ".agents/skills/",
)

# Trailing characters Markdown/prose commonly glues onto a URL.
_URL_RE = re.compile(r"https?://[^\s\)\]\}<>\"'`|]+")
_TRAILING = ".,;:!?"

# Hosts/patterns that are illustrative, not real endpoints.
_PLACEHOLDER = re.compile(
    r"(^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])"
    r"|example\.(com|org|net)"
    r"|your-|<[a-z]|\{|\bTARGET\b|placeholder|xxxx)",
    re.IGNORECASE,
)

# Statuses that prove the link is alive even when the body is not returned.
_ALIVE_STATUS = {200, 201, 203, 204, 206, 301, 302, 303, 307, 308}
# Statuses that prove the resource is gone.
_DEAD_STATUS = {404, 410}


def extract_urls(text: str) -> set[str]:
    """Pull http(s) URLs from Markdown, trimming glued trailing punctuation."""
    out: set[str] = set()
    for raw in _URL_RE.findall(text):
        url = raw
        while url and url[-1] in _TRAILING:
            url = url[:-1]
        # Drop an unbalanced trailing ')' left by a Markdown link wrapper.
        if url.endswith(")") and url.count("(") < url.count(")"):
            url = url[:-1]
        if url:
            out.add(url)
    return out


def is_checkable(url: str) -> bool:
    """False for placeholder/example URLs that are never meant to resolve."""
    return _PLACEHOLDER.search(url) is None


def classify(status: int | None, *, network_error: bool = False) -> str:
    """Map an HTTP status (or a hard network error) to alive/dead/unverified."""
    if network_error:
        return "dead"
    if status in _DEAD_STATUS:
        return "dead"
    if status in _ALIVE_STATUS:
        return "alive"
    # Blocked or limited (401/403/429/5xx...): cannot confirm rot either way.
    return "unverified"


_FENCE_RE = re.compile(r"(?ms)^[ ]{0,3}(`{3,}|~{3,}).*?^[ ]{0,3}\1[`~]*[ \t]*$|^[ ]{0,3}(`{3,}|~{3,}).*\Z")
_INLINE_CODE_RE = re.compile(r"(`+)(?:(?!\1).)+?\1", re.DOTALL)
_LINK_RE = re.compile(
    r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*(<[^>\n]*>|[^)\s]*(?:\([^)\s]*\)[^)\s]*)*)(?:\s+[\"'][^\n]*?[\"'])?\s*\)"
)
_HEADING_RE = re.compile(r"(?m)^ {0,3}#{1,6}[ \t]+(.+?)[ \t]*#*[ \t]*$")
_HTML_ANCHOR_RE = re.compile(r"""<a\s[^>]*\b(?:name|id)=["']([^"']+)["']""", re.IGNORECASE)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def strip_code(text: str) -> str:
    """Blank out fenced and inline code so example links inside it are not checked."""
    text = _FENCE_RE.sub("", text)
    return _INLINE_CODE_RE.sub("", text)


def slugify(heading: str) -> str:
    """GitHub's heading-to-anchor rule: strip markup, lowercase, drop punctuation, spaces to hyphens."""
    heading = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    heading = re.sub(r"[`*_~]|<[^>]+>", "", heading).strip().lower()
    heading = re.sub(r"[^\w\- ]", "", heading)
    return heading.replace(" ", "-")


def anchors_of(text: str) -> set[str]:
    """Anchors a Markdown file exposes: heading slugs (with GitHub's -N duplicate suffix) and HTML ids."""
    seen: dict[str, int] = {}
    out: set[str] = set(_HTML_ANCHOR_RE.findall(text))
    for heading in _HEADING_RE.findall(strip_fences(text)):
        slug = slugify(heading)
        n = seen.get(slug, 0)
        out.add(slug if n == 0 else f"{slug}-{n}")
        seen[slug] = n + 1
    return out


def strip_fences(text: str) -> str:
    return _FENCE_RE.sub("", text)


def internal_problems(rel: str, text: str, root: Path, anchor_cache: dict[Path, set[str]]) -> list[str]:
    """Broken relative file links and #anchors in one Markdown file."""
    problems: list[str] = []
    base = (root / rel).parent
    for raw in _LINK_RE.findall(strip_code(text)):
        target = raw.strip("<>")
        if not target or _SCHEME_RE.match(target) or target.startswith(("//", "{", "$")):
            continue
        path_part, _, anchor = target.partition("#")
        path_part = path_part.partition("?")[0]
        dest = (
            (root / rel)
            if not path_part
            else (root / path_part.lstrip("/") if path_part.startswith("/") else base / path_part)
        )
        dest = Path(*dest.parts) if dest.is_absolute() else dest
        try:
            dest = dest.resolve()
            dest.relative_to(root.resolve())
        except (OSError, ValueError):
            problems.append(f"{rel}: link leaves the repository: {target}")
            continue
        if not dest.exists():
            problems.append(f"{rel}: missing file: {target}")
            continue
        if anchor and dest.suffix == ".md" and dest.is_file():
            if dest not in anchor_cache:
                anchor_cache[dest] = anchors_of(dest.read_text(encoding="utf-8", errors="replace"))
            if anchor.lower() not in anchor_cache[dest]:
                problems.append(f"{rel}: missing anchor: {target}")
    return problems


def check_internal(paths: list[str]) -> int:
    cache: dict[Path, set[str]] = {}
    problems: list[str] = []
    files = _tracked_markdown(paths)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        problems += internal_problems(str(f.relative_to(ROOT)), text, ROOT, cache)
    for problem in problems:
        print(f"  ✗ {problem}")
    print(
        f"{len(problems)} broken internal link(s) in {len(files)} Markdown files"
        if problems
        else f"OK: internal links in {len(files)} Markdown files"
    )
    return 1 if problems else 0


def _tracked_markdown(paths: list[str]) -> list[Path]:
    try:
        listing = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "*.md"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        listing = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.md")]

    files: list[Path] = []
    for rel in listing:
        if rel.startswith(EXCLUDE_PREFIXES):
            continue
        if paths and not any(rel.startswith(p) for p in paths):
            continue
        files.append(ROOT / rel)
    return files


def _probe(url: str, timeout: float) -> tuple[str, str]:
    """Return (verdict, detail) for one URL."""
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "cybersec-toolkit-linkcheck/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (http(s) only, from our own docs)
            return classify(resp.status), str(resp.status)
    except urllib.error.HTTPError as e:
        return classify(e.code), str(e.code)
    except Exception as e:  # noqa: BLE001 - one odd server response must not abort the run
        return _classify_error(e)


def _classify_error(exc: BaseException) -> tuple[str, str]:
    """Only a name that does not resolve or a refused connection is proof of rot."""
    reason = getattr(exc, "reason", exc)
    detail = f"{type(exc).__name__}: {reason}"
    if isinstance(reason, socket.gaierror):
        # EAI_AGAIN and friends mean the resolver was unreachable, not that the name is gone.
        return ("dead", detail) if reason.errno == socket.EAI_NONAME else ("unverified", detail)
    if isinstance(reason, ConnectionRefusedError):
        return "dead", detail
    return "unverified", detail


def run_self_test() -> int:
    """Offline check of the pure functions — no network."""
    fails = 0

    def check(name: str, got, want) -> None:
        nonlocal fails
        if got == want:
            print(f"  PASS {name}")
        else:
            print(f"  FAIL {name}: got {got!r} want {want!r}")
            fails += 1

    urls = extract_urls(
        "See [x](https://a.example/path). Also https://b.test/y), and `https://c.test/z`. Bare: https://d.test/w."
    )
    check("extract trims markdown paren", "https://a.example/path" in urls, True)
    check("extract trims trailing dot", "https://d.test/w" in urls, True)
    check("extract keeps backtick-wrapped url", "https://c.test/z" in urls, True)

    check("placeholder localhost skipped", is_checkable("http://localhost:8080/x"), False)
    check("placeholder example.com skipped", is_checkable("https://example.com/y"), False)
    check("placeholder <var> skipped", is_checkable("https://<host>/api"), False)
    check("real url checkable", is_checkable("https://github.com/26zl/cybersec-toolkit"), True)

    check("404 -> dead", classify(404), "dead")
    check("410 -> dead", classify(410), "dead")
    check("200 -> alive", classify(200), "alive")
    check("301 -> alive", classify(301), "alive")
    check("403 -> unverified", classify(403), "unverified")
    check("dns error -> dead", classify(None, network_error=True), "dead")

    unresolved = urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, "Name or service not known"))
    check("unresolvable name -> dead", _classify_error(unresolved)[0], "dead")
    check("refused -> dead", _classify_error(urllib.error.URLError(ConnectionRefusedError(61, "refused")))[0], "dead")
    resolver_down = urllib.error.URLError(socket.gaierror(-3, "again"))
    check("resolver down -> unverified", _classify_error(resolver_down)[0], "unverified")
    check("reset -> unverified", _classify_error(ConnectionResetError(104, "reset"))[0], "unverified")
    check("remote disconnect -> unverified", _classify_error(http.client.RemoteDisconnected("closed"))[0], "unverified")
    check("bad status line -> unverified", _classify_error(http.client.BadStatusLine("x"))[0], "unverified")
    check("tls error -> unverified", _classify_error(ssl.SSLError("handshake"))[0], "unverified")
    check("timeout -> unverified", _classify_error(TimeoutError("timed out"))[0], "unverified")

    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "a.md").write_text('# Top\n\n## Sub Heading!\n\n## Sub Heading!\n<a id="hand"></a>\n', encoding="utf-8")
        (root / "d").mkdir()
        body = (
            "[ok](a.md) [anchor](a.md#sub-heading) [dup](a.md#sub-heading-1) [html](a.md#hand) [self](#here)\n"
            "[dir](d) [ext](https://x.test/y) [mail](mailto:a@b.c)\n"
            "```\n[fenced](nope.md)\n```\n`[inline](nope.md)`\n## Here\n"
        )
        (root / "b.md").write_text(body, encoding="utf-8")
        cache: dict[Path, set[str]] = {}
        check("valid internal links pass", internal_problems("b.md", body, root, cache), [])
        bad = internal_problems("b.md", "[m](nope.md) [a](a.md#nope) [s](#nowhere) [o](../../etc/passwd)", root, cache)
        check("broken internal links are all reported", len(bad), 4)

    print()
    print("self-test: OK" if fails == 0 else f"self-test: {fails} FAILED")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--path", action="append", default=[], help="Limit to repo-relative path prefixes")
    ap.add_argument("--self-test", action="store_true", help="Run offline logic checks and exit")
    ap.add_argument("--internal", action="store_true", help="Check relative file links and #anchors (offline)")
    args = ap.parse_args()

    if args.internal:
        return check_internal(args.path)

    if args.self_test:
        return 1 if run_self_test() else 0

    files = _tracked_markdown(args.path)
    urls: set[str] = set()
    for f in files:
        try:
            urls |= extract_urls(f.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    checkable = sorted(u for u in urls if is_checkable(u))
    print(f"Checking {len(checkable)} external links from {len(files)} Markdown files...\n")

    dead: list[tuple[str, str]] = []
    unverified: list[tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_probe, u, args.timeout): u for u in checkable}
        for fut in concurrent.futures.as_completed(futures):
            url = futures[fut]
            verdict, detail = fut.result()
            if verdict == "dead":
                dead.append((url, detail))
            elif verdict == "unverified":
                unverified.append((url, detail))

    if unverified:
        print(f"Unverified ({len(unverified)}) — blocked/limited/timeout, not counted as rot:")
        for url, detail in sorted(unverified):
            print(f"  ? {url}  ({detail})")
        print()
    if dead:
        print(f"DEAD ({len(dead)}):")
        for url, detail in sorted(dead):
            print(f"  ✗ {url}  ({detail})")
        print()
        print(f"{len(dead)} dead link(s) found")
        return 1
    print("OK: no dead links")
    return 0


if __name__ == "__main__":
    sys.exit(main())
