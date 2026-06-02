---
name: supply-chain-prodsec-hardening
description: Use for software supply chain, product security, SBOM, SLSA, provenance, Sigstore/cosign, dependency pinning, CI/CD hardening, artifact signing, build isolation, release security, vendor risk, and secure SDLC work.
---

# Supply-chain and product-security hardening

Use this skill for SDLC, build/release pipelines, dependency trust, artifact provenance, product security, and supply-chain risk reduction.

## Workflow

1. Map the product delivery path:
   - source repositories
   - developer identities
   - CI runners
   - dependency sources
   - build steps
   - artifact registries
   - deployment targets
2. Identify trust decisions:
   - who can merge
   - who can release
   - what dependencies are allowed
   - where secrets live
   - which artifacts are trusted
3. Add controls in priority order:
   - branch protection and required reviews
   - pinned dependencies and lockfiles
   - dependency update policy
   - SBOM generation and retention
   - vulnerability and license gates
   - provenance attestation
   - artifact signing and verification
   - isolated, ephemeral build runners
   - least-privilege CI tokens
   - secret scanning and rotation
4. Validate with a release rehearsal: can an untrusted change, dependency, runner, or artifact reach production?

## Output pattern

| Stage | Weakness | Attack path | Control | Evidence | Owner | Priority |
| --- | --- | --- | --- | --- | --- | --- |

Prefer controls that are enforceable in CI/CD or registry policy over wiki-only process.
