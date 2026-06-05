# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately using GitHub Security Advisories:

**<https://github.com/26zl/cybersec-toolkit/security/advisories/new>**

Include:

- A description of the issue and its impact
- Steps to reproduce
- Affected file(s) and line number(s) if known
- A suggested fix, if you have one

Expect an initial response within 7 days. Credit is given in the release notes unless you request otherwise.

**Do not** open public issues or pull requests with proof-of-concept exploits, and do not post details to social media or mailing lists before a fix is released.

## Scope

**In scope:**

- Code execution, privilege escalation, or sandbox escape in the installer (`install.sh`, `lib/`, `modules/`, `scripts/`)
- Command injection, path traversal, or argument-sanitization bypass in the MCP server (`mcp_server/`)
- Supply-chain weaknesses in project bootstrap/runtime or installer logic: unverified downloads, checksum bypasses, dependency update weaknesses, or fetching the wrong upstream artifact through our scripts
- Secrets leakage in version-controlled files (`.versions`, audit logs, config samples)
- CI/CD pipeline weaknesses: unpinned actions, missing egress controls, unauthenticated artifact uploads

**Out of scope:**

- Vulnerabilities in the third-party tools this project installs — report those to the respective upstream projects
- Issues that require a malicious user to already have `sudo` / root on the target machine
- Known limitations documented in the README's "Known Limitations" and "Supply Chain Model" sections (e.g., `--fast` skipping checksums by design — this is documented behavior, not a vulnerability)
- Attacks against authorized targets (this is a tool for offensive security — misuse by an operator against unauthorized targets is a policy issue, not a vulnerability)

## Supported versions

Only the latest `main` branch is supported. This project does not maintain backports.

## Supply-chain hardening (existing protections)

For context when evaluating a report:

- **System packages** — GPG-signed via the distro's repos (apt, dnf, pacman, zypper, pkg)
- **Binary releases** — SHA256-verified against published checksums when available. `--require-checksums` turns missing checksums into a hard failure
- **Go SDK** — SHA256-verified against `go.dev/dl/?mode=json` when reachable
- **MCP Python dependencies** — resolved by `uv` with a 3-day `exclude-newer` release-age window for project runtime dependencies
- **GitHub Actions** — all SHA-pinned with version comments; `step-security/harden-runner` enforces egress audit in every job
- **MCP execution engine** — tool allowlisting, argument sanitization (blocks `;`, `&`, `|`, backtick, `$(`, `${`), per-tool blocked flags, network target allowlisting (private/loopback only by default — `CYBERSEC_MCP_ALLOW_EXTERNAL=1` opts in), rate limiting, and audit logging
- **MCP script execution** — off by default; requires `CYBERSEC_MCP_ALLOW_SCRIPTS=1`

## Automated security checks

These run on every push and PR via `.github/workflows/security.yml`:

- **gitleaks** — secret detection
- **custom-security-scan** — hardcoded IPs, secrets, non-HTTPS URLs, unsafe eval, curl-pipe patterns, `chmod 777`
- **pip-audit** — audits MCP server Python dependencies for known vulnerabilities
- **pin-check** — enforces SHA-pinned GitHub Actions
- **scorecard** — OSSF Scorecard (public-repo pushes to main)

## Disclosure

Once a fix is released, the advisory is made public with credit to the reporter (unless they requested otherwise). Embargo periods can be arranged by email before the advisory is opened.
