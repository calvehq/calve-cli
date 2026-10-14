# ADR 0007: TUF adapter, client library and the delegation gate

Status: Accepted with an open blocker (G1 delegation BLOCKED).

## Context
The catalog must be a real TUF repository with delegations (publisher namespaces). `tough` 0.24's documentation claims no delegation support (F11); rust-tuf 0.3.0-beta14 claims it (F12).

## Decision
- A narrow `TrustClient` adapter in `calve-app/src/catalog/tuf.rs`; the library is replaceable behind it.
- **M0 evidence reversed the documentation:** rust-tuf's client cannot resolve delegated targets at all (FG2); tough 0.24's code does load delegations with snapshot hash/length enforcement and glob path patterns. **tough 0.24 is adopted** (user decision 2026-10-13), with `default-features = false` and Calve's own transport (ureq), so no hyper/reqwest.
- The adapter records the raw bytes the client fetched; tough's datastore is re-serialized and cannot be re-imported offline (FG15).
- Delegation conformance is a **mandatory G1 release gate** (user decision).

## Consequences
- tuf-conformance (pinned commit `8729aa18`): 83/119 pass. Delegation behaviour fails 21 cases (eager loading of all delegated roles; one out-of-path target in any delegate fails the whole load; unusual role names); the consistent-snapshot target URL for paths with directories is wrong; a same-version timestamp with changed content is adopted. **G1 is BLOCKED** until a conformant client passes: options are an upstream tough fix (needs authorization to contribute), a Calve-maintained fork behind `TrustClient`, or another library. M2 may proceed on infrastructure only.
- Calve must stop reading a target stream at the first error (tough's stream never terminates after a violation; FG2c) and treat "system time stepped backward" as retryable (FG15).
- Catalog policy: ed25519 keys and sha256 hashes only (tough lacks RSA-PSS-384/512, ECDSA P-384, ML-DSA, sha512-only targets).

## Tests / evidence
FG2 (FG2a/2b PASS, FG2c per-case results), FG15; M2 adversarial TUF suite (§9.4).

## Residuals
aws-lc-rs (C, through rustls) enters the tree with tough; vetted in `docs/audit/dependency-vetting.md`.
