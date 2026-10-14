# Catalog trust

Status: M0 design proven (FG2a, FG2b, FG15); delegation conformance **BLOCKED** (FG2c). Decision records: ADR 0007, ADR 0008.

- The catalog is a TUF repository; Calve's client is tough 0.24 behind the `TrustClient` adapter, with Calve's own HTTP transport (no hyper/reqwest).
- Bootstrap pins the root by SHA-256 (`repo_id`), written to `REPO_ID`; every generation must match it.
- Each accepted refresh becomes a generation `gen-N/` holding the client's datastore, the **raw bytes** it fetched (`raw/`) and `state.json`; floors only ever increase; `CURRENT` names the activated generation.
- Recovery never re-validates from bootstrap, never activates on checksums alone and never falls back to the parent of a damaged activated generation; anything inconsistent is `RecoveryRequired(trust_state)` until a fresh accepted refresh or an audited reset (`calve extension catalog reset <name> --root-digest <sha256>`).
- Package states: Fresh, Stale (≤ / > `revocation_max_age`, default 7 days), Expired, Revoked; install/update only when Fresh.
- Policy: ed25519 keys, sha256 target hashes, consistent snapshots, target paths `<extension-id>/<version>/<file>` authorized by delegation paths and the catalog's `custom.calve.id_policy`; cross-catalog id pinning.
- Known client issues (FG2c): eager loading of all delegated roles; one out-of-path target in any delegate fails the whole load; wrong consistent-snapshot URL for targets in subdirectories; target streams must be abandoned at the first error; "system time stepped backward" is retryable.
