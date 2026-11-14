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
`ghcr.io/26zl/cybersec-toolkit` on pushes to `main` and `v*.*.*` tags. Nothing
is built until the CI and Security runs of the same commit are green: a failed
run fails the publish, and a commit whose runs were cancelled by a newer push is
skipped with a warning. A tag therefore has to sit on a commit that CI has run
on. For a commit that was merged with `GITHUB_TOKEN` and so has no runs of its
own, the runs on the head of its pull request count instead. Commits
that touch only documentation, writeups, CI, skills or tests are skipped via
`paths-ignore`, since none of those reach the image. A push to `main`
produces `latest` and `sha-<short>`; the numeric version tag (e.g. `1.2.1`) comes
only from the `v*.*.*` tag build, so a later main push cannot re-point a released
version tag, and a tag build never moves `latest`.

Every Wednesday the workflow also rebuilds `latest` from `main`, which picks up
distro package fixes that arrive without a commit here, and scans the released
`x.y.z` image. That tag is built once and is what `server.json` points the MCP
Registry at, so it only gets a fix through a new release: fixable HIGH/CRITICAL
findings open an issue labelled `image-scan`, which the scan closes again once
the released image is clean.

Merges that the `uv-update` workflow auto-merges are pushed with `GITHUB_TOKEN`,
which does not trigger other workflows, so they are not published until the next
push to `main` or the weekly rebuild. To ship a dependency fix sooner, run
**Publish image** manually from `main` (Actions → Publish image → Run workflow).

The image must carry `LABEL io.modelcontextprotocol.server.name=` (set in the
`Dockerfile`) — the registry checks this annotation before accepting the OCI
package.

One-time: the first push creates a **private** package. Make it public so
`docker run ghcr.io/26zl/cybersec-toolkit` and the MCP-registry reference resolve
for everyone: Repo → Packages → `cybersec-toolkit` → Package settings → Change
visibility → Public.

## Repository settings the workflows depend on

These live in the GitHub UI, not in the repository, so a changed setting fails
silently until a workflow needs it:

- **Settings → Actions → General → Workflow permissions → "Allow GitHub Actions
  to create and approve pull requests"** must be on, or the weekly `uv-update`
  workflow resolves the upgrade but fails at "Create pull request"
  (`GitHub Actions is not permitted to create or approve pull requests`) and
  routine Python updates stop. Dependabot security updates are unaffected.
- **Settings → Rules → "Protect main"** holds the required status checks, each
  bound to the GitHub Actions app, so a commit status posted under the same
  name by anything else does not satisfy them. A job that is renamed, or moved
  to another CI system, has to be updated there. The path-filtered Integration
  workflow, including its sandbox and installer image Trivy scans, is not among
  them, so its failures do not block a merge.
- **Settings → Rules → "Release tags are immutable"** forbids deleting or moving
  a `v*` tag and has no bypass list; "Protect release tags" limits who may
  create one. A tag pushed by mistake therefore stays until that ruleset is
  disabled by hand, the tag removed, and the ruleset enabled again. Check
  `VERSION` before tagging: a tag that does not match it fails the image build
  and cannot simply be moved.
- The weekly jobs report through issues they open and close themselves, labelled
  `image-scan` (released image), `integration-failure` (weekly Integration run)
  and `skills-update` (vendored skills).
- **Packages → `cybersec-toolkit`** visibility must stay public (above).

Verify a published image's provenance with
`gh attestation verify oci://ghcr.io/26zl/cybersec-toolkit:<version> --repo 26zl/cybersec-toolkit`.

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
- [26zl/cybersec-toolkit](https://github.com/26zl/cybersec-toolkit) 🐍 🏠 🐧 - One command installs 670+ security tools; an MCP server lets AI clients look them up and run the installed ones under a scope policy and an audit log, for CTF, pentest, bug bounty, and DFIR.
```
