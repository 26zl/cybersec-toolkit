# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release notes for every version also live in
[GitHub Releases](https://github.com/26zl/cybersec-toolkit/releases); versions
before 1.4.0 are summarised there rather than duplicated here.

## [Unreleased]

### Changed

- Security workflow: scoped the `pull-requests: read` token permission down to the
  Gitleaks job so the workflow's top-level permissions stay at `contents: read`
  (least privilege; other jobs no longer receive the scope).

### Added

- This changelog.

### Fixed

- MCP server: `resolve_binary_name()` now honours the npm/cargo binary-name maps the
  installer already uses, so `rea-agents` (`rea`), `rms-runtime-mobile-security`
  (`rms`) and `yara-x-cli` (`yr`) are detected as installed and runnable instead of
  being reported missing. `validate_mcp_sync.py` mirrors these maps against
  `lib/installers.sh` (and now parses `declare -gA`) so the two sides cannot drift.

## [1.4.0] - 2026-10-15

### Added

- Sandbox image can bake in a toolkit profile and stamp the source hash
  (`make sandbox-image TOOLKIT_PROFILE=ctf`); the launcher warns when the running
  image was built from different server sources.

### Changed

- Sandbox VM runs with a read-only root filesystem; the only writable paths are
  size-capped tmpfs mounts (`CYBERSEC_SANDBOX_SCRATCH_SIZE`, default `1g`), so an
  unpacked sample cannot exhaust host Docker storage.
- Invalid `install.sh` arguments now exit 2 (previously 1), as `--help` documents.
- Dependency refresh via `uv lock --upgrade` (fastmcp 3.4.8, pydantic 2.14,
  ruff 0.17, others), npm transitive updates, harden-runner v2.22.1,
  setup-uv v10.3.0; CI now also tests Python 3.14.

### Security

- Strict mode (`--production` / `--require-checksums`) skips the unsigned rustup,
  uv, cargo-binstall and Foundry bootstraps when they would run as root.
- Package removal is refused when it would also remove dependent packages
  (apt simulation, `rpm -e --test` on dnf/zypper).
- Audit log: credentials in compound names (`DB_PASSWORD=`, `?access_token=`) are
  redacted, free-form fields are capped with a SHA256 retained so every record
  reaches the host log, and `make audit-verify` flags records inserted into a chain.
- The GitHub-token netrc file is always cleaned up, including after parallel installs.
- Root no longer writes through symlinks planted at the log or lock paths.
- Sandbox workspace rejects Kata/Docker state and runtime sockets and honours
  `workspaceReadonly: true`; the opt-in unsafe runtime always warns, and CI checks
  that a runc runtime registered under a Kata name is refused.

### Fixed

- `update.sh` no longer rebuilds Go, cargo, gem or npm tools the toolkit did not
  install (they used to shadow distro packages in `/usr/local/bin`).
- Rollback accuracy: NetExec, Metasploit, crates with a differing binary name
  (`yr`), release directories and `.deb` releases are actually removed; pre-existing
  Docker images and clones are left alone; survivors keep their `.versions` row and
  the run exits 1.
- `remove.sh`: `--module` drops the `.versions` rows it removed, failed special-tool
  removals are counted, and `--deep-clean` deletes user caches as the user.
- `backup.sh`: restores `*.enc` and legacy per-file archives, fails when a restore
  finds nothing, honours `BACKUP_KEEP=N`, and no longer backs up tool clones.
- `verify.sh --installed-only` checks packages whose command name differs and
  tracked C2 tools.
- MCP server: remote runs stop the local ssh client on client cancel, audit records
  survive filesystems without `flock`, concurrent sessions no longer overwrite each
  other's `remote_hosts.json`, and `run_script` reports `sandboxed: true` only inside
  a verified Kata VM.
- Agent guard catches `timeout`, `nice`, `xargs` and `bash -c` wrappers and keeps
  clearance across compaction.
- Skill index reads multi-line descriptions; docs corrected (FastMCP 3.x Inspector
  command, README counts, client support, supply-chain wording, sandbox raw-socket note).

[Unreleased]: https://github.com/26zl/cybersec-toolkit/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/26zl/cybersec-toolkit/releases/tag/v1.4.0
