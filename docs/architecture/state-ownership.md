# State ownership

Every fact has one owner, and nothing else may change it.

| State | Owner | Where |
|---|---|---|
| Packs, candidates, effects, evidence, verifications, policy decisions, promoted packs, Baselines | OpenAEVC | `.calve/openaevc/` |
| Executions, leases, provenance, receipts, journal | OpenAEVC | `.calve/openaevc/` |
| Principals, grants, revocations | OpenAEVC | `.calve/openaevc/` |
| Intents, Tasks, reviews as product records, inbox, aliases, active Baseline pointer, extension grants | Calve | `.calve/product.sqlite3` |
| Read models and projections | Calve, derived | `.calve/product.sqlite3`; rebuildable |
| Operation journals | Calve | `.calve/run/` |
| Workspaces and registrations | Calve | `<data>/calve/workspace.sqlite3` |
| Extension packages and catalog trust state | Calve | `<data>/calve/` |
| What a file or resource kind means | Extensions | signed metadata and CIC modules |

Three rules follow, each enforced by `xtask check-architecture` with a negative test:

1. **Calve does not reach into OpenAEVC's store.** Mutations are commands through the SDK or runtime API; reads are its query API. There is one documented exception: `maintenance gc --dry-run` counts collectable objects with a read-only query, because OpenAEVC v0.1.0 has no API for it. See [ADR 0022](../adr/0022-gc-dry-run-read.md).
2. **Calve copies no protocol state as truth.** A projection can always be dropped and rebuilt, and when it disagrees with OpenAEVC, OpenAEVC wins.
3. **The host has no domain knowledge.** Calve's code names no first-party domain (INV-022).

Calve and OpenAEVC data are written in separate transactions, so an operation that touches both has no joint atomicity. Calve makes this safe by ordering and journaling, not by claiming a transaction. Projection updates read from OpenAEVC first and then write in one short product transaction, which never spans an await.

Decision records: [ADR 0002](../adr/0002-product-state-ownership.md), [ADR 0009](../adr/0009-product-state-ownership.md), [ADR 0010](../adr/0010-cross-store-identity.md).
