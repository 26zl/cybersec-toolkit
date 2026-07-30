#!/usr/bin/env python3
"""Check external links in the repository's Markdown for rot.

markdownlint validates structure, not reachability. This walks tracked *.md
(skipping the same vendored paths the Makefile excludes), extracts http(s) URLs,
and reports links that are confirmed dead — DNS failure, connection refused, or a
404/410. Ambiguous responses (timeouts, 401/403/405/429, other 5xx) are reported
as "unverified" and do NOT fail the run, because external hosts routinely block
bots or rate-limit rather than being gone.

Usage:
    python3 scripts/check_doc_links.py [--timeout N] [--path DIR]...
    python3 scripts/check_doc_links.py --self-test   # offline; no network
"""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import subprocess
import sys
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
# Statuses that mean "exists but blocked/limited" — cannot confirm rot either way.
_AMBIGUOUS_STATUS = {401, 403, 405, 406, 408, 429, 500, 502, 503, 504}
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
    return "unverified"


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
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        reason = getattr(e, "reason", e)
        # A DNS failure / refused connection is real rot; a timeout is ambiguous.
        text = str(reason).lower()
        if "timed out" in text or "timeout" in text:
            return "unverified", f"timeout: {reason}"
        return "dead", f"{type(e).__name__}: {reason}"


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
        "See [x](https://a.example/path). Also https://b.test/y), and "
        "`https://c.test/z`. Bare: https://d.test/w."
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

    print()
    print("self-test: OK" if fails == 0 else f"self-test: {fails} FAILED")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--path", action="append", default=[], help="Limit to repo-relative path prefixes")
    ap.add_argument("--self-test", action="store_true", help="Run offline logic checks and exit")
    args = ap.parse_args()

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
