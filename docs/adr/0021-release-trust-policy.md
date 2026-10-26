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

## M2 production implementation (2026-10-15)
- The catalog key/hash policy part of this ADR is implemented in M2 (`catalog::tuf` policy, `catalog_policy` tests). Release signing, provenance and the remaining release policy stay M5.

## M2 closeout (2026-10-15): first-party publisher role — outstanding, release-blocking
The first-party catalog produced by calve-extensions' `xtask publish` is signed by the top-level `targets` role; there is no delegated first-party publisher role and no `id-policy.json` for it. Plan §9.1 lets M2 use top-level targets only (the mandatory delegation gate is client conformance, 119/119), so this is **not** an M2 deliverable, but per the M2 review it is recorded as an **outstanding requirement that blocks release**: before v0.1.0 the first-party catalog must sign packages through a delegated publisher role (paths `<id>/**` per first-party id, a separate offline-capable key, `id-policy.json` naming its id prefix) and the installer must record that role as the publisher. Calve's installer already enforces delegated roles, id policy and publisher pins (`install::publisher_identity_id_policy_and_path_authorization`); the missing part is the publisher side (`xtask keygen`/`publish`).

## M5: first-party publisher role (2026-10-26)
- calve-extensions `xtask keygen|publish|rotate` (c51a741) sign packages through the delegated role `calve` (3 keys, threshold 2 by default; terminating; explicit `<id>/*` paths per first-party id; `id-policy.json` → `org.calve.`). Top-level `targets` signs only `index.json`, `id-policy.json` and the delegation. Publisher and top-level key rotation (root N+1 cross-signed by the old root key) are supported. See calve-extensions `docs/publishing.md`.
- End-to-end with the calve client (`~/calve-scripts/delegation.sh`, 21/21, evidence `evidence/m5/delegation-run2.log`): installs record `publisher: calve`; 1-of-3 refused, 2-of-3 accepted; an out-of-path target is not trusted; a foreign id is refused at publish; existing and fresh clients follow publisher and root rotations; retired publisher keys refused. The run found a client bug (stale delegated role after refresh → recovery_required), fixed in ef1c906.
- Gate status: publisher workflow implemented and verified locally (L1). Release signing, attestations, cosign and clean-install verification remain open (M5 F).
