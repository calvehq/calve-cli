# ADR 0003: OpenAEVC source identity

Status: Accepted (M0, FG1 PASS).

## Context
Calve consumed seven `openaevc-*` crates from `main` over SSH. Upstream #17 merged them into one crate, `openaevc`, with feature-gated modules (`store`, `runtime`, `transport`, `full`), and tagged `v0.1.0` (tag object `d4bee88b`, peeled `5720d3ec15bee6c49630b2cec5a21afd357dedf8`) on a publicly readable HTTPS remote. `openaevc-sdk` is `publish = false`, so it exists only in git; mixing a crates.io `openaevc` with the git SDK yields two incompatible packages.

## Decision
- Both `openaevc` and `openaevc-sdk` come from `git = "https://github.com/calvehq/openaevc.git", tag = "v0.1.0", version = "=0.1.0", default-features = false`.
- Only `calve-app` enables `runtime` (and gets `transport` through the SDK). Every other crate uses default features (none).
- `OPENAEVC_TAG = "v0.1.0"` and `OPENAEVC_REVISION = "5720d3ec…"` are compiled in and shown by `calve version` and doctor.
- OpenAEVC v0.1.0 is never modified from Calve; gaps become Calve-owned contracts (ADR 0004) or `docs/proposals/openaevc-*.md`.

## Consequences
- CI no longer needs an SSH deploy key.
- `xtask check-architecture` asserts one `openaevc` package id/source/rev and rejects crates.io or `branch = "main"` sources (negative fixtures).
- Each non-app crate is built in an isolated scratch workspace to prove no `store`/`runtime`/`transport` feature leaks in through unification.

## Tests / evidence
FG1 (`docs/audit/spikes/FG01.md`): lock source, single package id, isolated minimal builds, feature tree. M1 §5.2 gates 1–7.

## Residuals
None known. An upstream re-tag would change the peeled commit; the lockfile pins the commit and the xtask compares it to `OPENAEVC_REVISION`.
