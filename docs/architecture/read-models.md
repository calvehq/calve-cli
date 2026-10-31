# Read models

A read model answers one screen or command, such as `status`, `view overview` or `inbox list`. Each is derived from OpenAEVC plus product state, is never authoritative, and can be rebuilt with `maintenance rebuild-projections`.

**Pattern.** A projection reads from OpenAEVC first, then writes in one short product transaction. No transaction spans an await, so a read model never blocks a writer. Reads use keyset pages and batched OpenAEVC reads, so cost follows the page size and not the history size.

**Consistency.** Projections advance against OpenAEVC's journal sequence. A read model that is behind catches up on read. Refreshes that overlap converge on the same authoritative state, which `projection_concurrency.rs` tests.

**Equivalence.** Indexed paths are tested against the full-scan definition they replace, because an index that silently drops rows is the failure that matters here.

**Measured at 10,000 packs** (release build, Linux, this host; 500 packs with review evidence):

| Read model | Time | Target |
|---|---|---|
| `status` | 42 ms | < 150 ms |
| `view overview` | 93 ms | < 100 ms |
| `view packs` | 23–44 ms | < 100 ms |
| `view pack` | 74 ms | < 100 ms |
| `inbox` | 52 ms | < 100 ms |
| `activity --pack` | 2.4 ms | < 100 ms |
| `view evidence` | 101 ms | **missed** (< 100 ms) |

The first read after a large import builds the projections once: `status` took 5.4 s and receipts 8.4 s at this size. Later updates cost only the change.

**Known limit.** OpenAEVC v0.1.0 cannot resolve a receipt by request id, so the receipt projection lists digests when a requested receipt is missing. See [OpenAEVC compatibility](../compatibility/openaevc.md).

Stable shapes: [JSON API](../reference/json-api.md).
