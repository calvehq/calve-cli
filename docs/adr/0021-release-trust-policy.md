# ADR 0021: Release trust policy

Status: Proposed (M5).

## Context
Users and calve-extensions must be able to verify what they install.

## Decision
- Normalized, reproducible archives; per-target SBOM; combined `SHA256SUMS`; build attestations; cosign keyless signature on the sums.
- Catalog signing keys: ed25519, sha256 target hashes (tough's supported set, FG2c); keys never in a repository; keygen refuses paths inside a git worktree.

## Consequences
Push, tag, release and publish require explicit authorization.

## Tests / evidence
M5: reproducible double build, clean-install verification, attestation verification.

## Residuals
None.
