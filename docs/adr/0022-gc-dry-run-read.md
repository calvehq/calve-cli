# ADR 0022: GC dry run reads the runtime database

Status: Withdrawn. Replaced before approval; nothing depends on it.

## Context
`maintenance gc --dry-run` must report a count and estimated bytes per class. OpenAEVC v0.1.0's `collect_garbage` deletes, and its `Store` API cannot list what it would delete. This ADR proposed one read-only SQL query on the runtime database as an exception to the rule against touching `.calve/openaevc/`. The project owner did not approve it.

## Replacement
The dry run copies the store's database into a disposable directory, hard-links its objects, and runs the public `SqliteStore::collect_garbage` on that view, so the numbers come from OpenAEVC's own collector and no Calve code reads OpenAEVC's schema. It holds the store open while copying, so no runtime writes underneath. While the store is in use, this class reports no count and says so.

`check-architecture` has no exception: all SQL on OpenAEVC's tables fails it.

## Consequences
The dry run costs a copy of the runtime database. Hard links keep object bytes shared; on a filesystem without them, objects are copied too. Objects stored inline are counted, but their bytes are not in the estimate.
