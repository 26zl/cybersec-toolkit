# Publishing

Maintainer steps for the two external distribution channels. Both are optional
and independent of normal repository work.

## Container image (GHCR) — automated

`.github/workflows/publish-image.yml` builds the image, scans it with Trivy
(fails on fixable HIGH/CRITICAL CVEs), and pushes it to
`ghcr.io/26zl/cybersec-toolkit` on every push to `main` and on `v*.*.*` tags.
Tags produced: `latest`, the `VERSION` value (for example `1.1.0`), and
`sha-<short>`.

One-time: the first push creates a **private** package. Make it public so
`docker run ghcr.io/26zl/cybersec-toolkit` and the MCP-registry OCI reference
resolve for everyone: Repo → Packages → `cybersec-toolkit` → Package settings →
Change visibility → Public.

## MCP Registry — one manual publish per release

`server.json` is the manifest. It points at the GHCR image and overrides the
container entrypoint so it runs the MCP server over stdio.

1. Verify the OCI launch command works (the image must be public first):

   ```bash
   docker run -i --rm --entrypoint uv ghcr.io/26zl/cybersec-toolkit:1.1.0 \
     run --directory mcp_server fastmcp run server.py --transport stdio --no-banner
   ```

   It should start and wait on stdin (Ctrl-C to exit).

2. Install the publisher and publish. This authenticates the `io.github.26zl`
   namespace via GitHub OAuth as `26zl`:

   ```bash
   brew install mcp-publisher   # or grab a binary from modelcontextprotocol/registry releases
   mcp-publisher login github
   mcp-publisher publish
   ```

On each release: bump `version` and the image tag in `server.json` to match
`VERSION`, then re-run `mcp-publisher publish`. The `mcp-name` marker in
`README.md` ties this repository to the registry entry.

## awesome-mcp-servers

Entry for the Security section of
<https://github.com/punkpeye/awesome-mcp-servers>:

```markdown
- [26zl/cybersec-toolkit](https://github.com/26zl/cybersec-toolkit) 🐍 🏠 🐧 - One command installs 670+ security tools; an authorization-gated MCP server lets AI clients discover and run them for CTF, pentest, bug bounty, and DFIR.
```

Submit: fork the list, add the line alphabetically in the Security section, run
their `awesome-lint` if present, and open a PR.
