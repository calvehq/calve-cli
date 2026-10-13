# Maintenance and recovery

| Command | What it does |
|---|---|
| `maintenance check` | Product database integrity and foreign keys, OpenAEVC store verification, and pending recovery actions |
| `maintenance verify-store` | OpenAEVC journal and object verification |
| `maintenance gc [--dry-run] [--grace-secs N]` | OpenAEVC garbage collection: removes unindexed objects and orphan files older than the grace period; indexed (accepted) history is never removed |
| `maintenance compact` | WAL checkpoint and `VACUUM` of the product database |
| `maintenance rebuild-projections` | Rebuilds derived projections (the inbox) from their sources |
| `recover inspect` | Whether the Project opens, and how many disposable leftovers exist |
| `recover plan` | The exact actions recovery would take |
| `recover apply --yes` | Performs those actions |

Recovery only ever acts on provably disposable or restorable state:

- `.calve-init-*` staging from an interrupted `init`;
- a staged `.calveignore` edit;
- extension install staging in the shared cache;
- an interrupted `project adopt-copy`: if the new state does not open, the copy's original `.calve` is restored; if it does, the leftover source state is removed.

Staging younger than ten minutes is left alone so a running operation is never disturbed. Recovery never edits OpenAEVC data or the product database. Store verification and GC need exclusive access to the OpenAEVC data directory, so the daemon releases its cached runtime for them.
