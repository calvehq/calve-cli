# ADR 0007: TUF adapter, client library and the delegation gate

Status: Accepted. G1 TUF-delegation blocker resolved by local evidence (G1-TUF phase, 2026-10-14); G1 PENDING real CI runners.

## Context
The catalog must be a real TUF repository with delegations (publisher namespaces). `tough` 0.24's documentation claims no delegation support (F11); rust-tuf 0.3.0-beta14 claims it (F12).

## Decision
- A narrow `TrustClient` adapter in `calve-app/src/catalog/tuf.rs`; the library is replaceable behind it.
- M0: rust-tuf's client cannot resolve delegated targets (FG2); tough 0.24 was adopted (user decision 2026-10-13) but fails tuf-conformance delegation (FG2c, 83/119; 86/119 with faketime).
- **G1-TUF (M0 review Decision 1, bounded check first):** tough has no upstream fix (no commits after 0.24.0). **`sigstore-tuf` 0.15.0** (sigstore/sigstore-rust `f950b1b683560aadf7737539f8d7eaa656a9f0c0`, Apache-2.0) passes the pinned suite **119/119**, including over Calve's own transport (three consecutive runs). It replaces tough behind `TrustClient`; **no fork**.
- Dependency form: `sigstore-tuf = "=0.15.0"`, `default-features = false`, `features = ["aws-lc-rs"]` (no reqwest/hyper). Any version bump re-runs conformance ×3, the regression suite and dependency checks before adoption.
- Calve transport (ureq): per-fetch byte cap from the verifier's `max_length` enforced while reading, connect + whole-request deadlines, no redirects, no idle-connection reuse, mirror-relative path validation.
- Calve catalog policy is applied on top of the verifier (ADR 0021): ed25519 only, computed key ids, unique key material, no non-standard key fields, consistent snapshots, sha256 target hashes.
- Delegation conformance is a **mandatory G1 release gate** (user decision).

## Consequences
- Lazy pre-order delegation search with terminating/path pruning, per-segment globs, percent-encoded role file names, consistent-snapshot target paths `dir/<hash>.name`, same-version timestamps ignored.
- The verifier treats declared key ids as authoritative and counts distinct ids toward a threshold; Calve policy closes the duplicate-key gap.
- A target is fetched once, bounded by its pinned length and verified; the M0 "infinite error stream" cannot occur.
- Targets are buffered in memory up to `target_max_length` (configured per catalog in M2).

## Tests / evidence
FG2 (M0), G1-TUF report (`docs/audit/milestones/G1-TUF.md`): conformance 119/119 ×3; 13 delegation regression, 7 malicious-mirror, 5 policy tests; FG2a 5/5 and FG15 8/8 reruns on Linux and natively on Windows.

## Residuals
aws-lc-rs/aws-lc-sys (C) in the trust path (vetted; reproducible build checked; no FIPS claim). Pre-1.0 dependency with frequent releases (exact pin). Conformance on Windows/macOS/aarch64 PENDING CI / BLOCKED.

## M2 production implementation (2026-10-15)
- Production adapter `catalog::tuf` (Mirror over ureq with caps/deadlines/no redirects, `TrustClient` exposing only Calve types; an xtask rule allows `sigstore_tuf` only in `catalog/{tuf,state}.rs`). Root and delegated-role policy (computed key ids, unique key material, ed25519/sha256 only) is enforced before acceptance, and re-checked in `resolve()`.
- Production PASS (Linux): tuf-conformance 119/119 in runs 1–3 (`examples/tuf-conformance-client`, logs `evidence/m2/logs/tuf-conformance-prod-run{1,2,3}*`); catalog_delegation 13, catalog_mirror 8, catalog_policy 5, catalog_fg2a 5, catalog_fg15 9 — also PASS natively on Windows (gnu). The G1-TUF spike results remain historical evidence; G1 stays PENDING CI.
