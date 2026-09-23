# Publishing

Maintainer steps for the two external distribution channels. Both are optional
and independent of normal repository work.

## Cutting a release

1. `make bump VERSION=x.y.z` — updates every version surface at once (VERSION,
   pyproject, plugin.json, marketplace.json, CITATION.cff, server.json's
   version + image tag, and the README's pinned `--branch` tag), refreshes
   `mcp_server/uv.lock`, and runs the version validator.
2. Commit, push, tag, and publish notes:

   ```bash
   git commit -am "release: x.y.z" && git push
   gh release create vx.y.z --generate-notes
   ```

   The push rebuilds `latest`; the `vx.y.z` tag that the release creates builds
   the `x.y.z` image (below) and fails if the tag does not match `VERSION`. Wait
   for that tag build to finish, then publish to the MCP registry (below): the
   registry inspects the `x.y.z` image, so it has to exist first.

## Container image (GHCR) — automated

`.github/workflows/publish-image.yml` builds the image, scans it with Trivy
(fails on fixable HIGH/CRITICAL CVEs), and pushes it to
`ghcr.io/26zl/cybersec-toolkit` on pushes to `main` and `v*.*.*` tags. Doc-,
writeup-, and CI-only commits are skipped via `paths-ignore`. A push to `main`
produces `latest` and `sha-<short>`; the numeric version tag (e.g. `1.2.1`) comes
only from the `v*.*.*` tag build, so a later main push cannot re-point a released
version tag, and a tag build never moves `latest`.

Merges that the `uv-update` workflow auto-merges are pushed with `GITHUB_TOKEN`,
which does not trigger other workflows, so they are not published until the next
push to `main`. To ship a dependency fix sooner, run **Publish image** manually
from `main` (Actions → Publish image → Run workflow).

The image must carry `LABEL io.modelcontextprotocol.server.name=` (set in the
`Dockerfile`) — the registry checks this annotation before accepting the OCI
package.

One-time: the first push creates a **private** package. Make it public so
`docker run ghcr.io/26zl/cybersec-toolkit` and the MCP-registry reference resolve
for everyone: Repo → Packages → `cybersec-toolkit` → Package settings → Change
visibility → Public.

### Rolling back a bad image

Tags are mutable, so a rollback re-points them at the last good digest (listed
under the package's versions, or in that build's workflow log) without a rebuild:

```bash
docker buildx imagetools create \
    -t ghcr.io/26zl/cybersec-toolkit:latest \
    -t ghcr.io/26zl/cybersec-toolkit:x.y.z \
    ghcr.io/26zl/cybersec-toolkit@sha256:<good-digest>
```

## MCP Registry — one manual publish per release

`server.json` is the manifest. It points at the GHCR image and overrides the
container entrypoint so it runs the MCP server over stdio. Two rules the registry
enforces (already satisfied here): the OCI package must **not** carry a `version`
field (the version lives in the image tag inside `identifier`), and the image
must carry the `io.modelcontextprotocol.server.name` label.

The publisher ships as a binary in the registry repo's releases — pick your
platform asset:

```bash
d=$(mktemp -d)
gh release download -R modelcontextprotocol/registry \
  -p 'mcp-publisher_darwin_arm64.tar.gz' -D "$d"   # or *_darwin_amd64 / *_linux_amd64 / *_linux_arm64
tar -xzf "$d"/mcp-publisher_*.tar.gz -C "$d"

"$d"/mcp-publisher validate server.json   # pre-check against the live schema
"$d"/mcp-publisher login github           # OAuth as 26zl (authorize the device code)
"$d"/mcp-publisher publish server.json    # run right after login — the token is short-lived
```

The registry token expires quickly, so run `login` and `publish` back-to-back.
Verify:

```bash
curl -s 'https://registry.modelcontextprotocol.io/v0/servers?search=cybersec-toolkit' | jq '.servers[]'
```

Optionally confirm the OCI launch works before publishing (image must be public).
Test the `x.y.z` tag that `server.json` references, not `latest`:

```bash
docker run -i --rm --entrypoint uv ghcr.io/26zl/cybersec-toolkit:x.y.z \
  run --directory mcp_server fastmcp run server.py --transport stdio --no-banner
```

The `mcp-name` marker in `README.md` ties this repository to the registry entry.

## awesome-mcp-servers

Listed via a PR to <https://github.com/punkpeye/awesome-mcp-servers> (Security
section). Entry format:

```markdown
- [26zl/cybersec-toolkit](https://github.com/26zl/cybersec-toolkit) 🐍 🏠 🐧 - One command installs 670+ security tools; an authorization-gated MCP server lets AI clients discover and run them for CTF, pentest, bug bounty, and DFIR.
```
