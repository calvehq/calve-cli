# ADR 0021: Release trust policy

Status: Proposed (M5).

## Context
Users and calve-extensions must be able to verify what they install.

## Decision
- Normalized, reproducible archives; per-target SBOM; combined `SHA256SUMS`; build attestations; cosign keyless signature on the sums.
- Catalog signing keys: ed25519 only; every declared key id equals sha256 of the canonical `{keytype, scheme, keyval}`; no key material under two ids; no non-standard key fields; consistent snapshots; every target carries a sha256 hash. Enforced by Calve on top of TUF for root and every loaded delegation (G1-TUF `tests/policy.rs`). Keys never in a repository; keygen refuses paths inside a git worktree.

## Consequences
Push, tag, release and publish require explicit authorization.

## Tests / evidence
M5: reproducible double build, clean-install verification, attestation verification.

## Residuals
None.
