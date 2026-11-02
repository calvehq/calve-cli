# Maintenance and recovery

| Command | What it does |
|---|---|
| `maintenance check` | Product database integrity and foreign keys, OpenAEVC store verification, and pending recovery actions |
| `maintenance verify-store` | OpenAEVC journal and object verification |
| `maintenance gc [--dry-run] [--grace-secs N] [--conflicts --older-than-secs N]` | One plan, per class with owner, count, estimated bytes and reason: OpenAEVC-unreachable objects (`OPENAEVC_RUNTIME`; indexed history is never removed), resolved Inbox rows past 30 days (`CALVE_PRODUCT`), temporary files, logs past 14 days, finished capture sessions, supersede sagas and materializations past 30 days (`FILESYSTEM_CACHE`; a removed materialization can no longer be rolled back). Conflict artifacts only with `--conflicts`, only for resolved operations |
| `maintenance compact` | WAL checkpoint and `VACUUM` of the product database |
| `maintenance rebuild-projections` | Rebuilds derived projections (the inbox) from their sources |
| `recover inspect` | Read-only (no runtime, no migration): product DB and store status, identity and continuity, backups with integrity and SHA-256 check, unfinished operations, leftovers |
| `recover plan` | The exact actions recovery would take |
| `recover apply --yes` | Performs those actions |
| `recover apply --rebuild-product --yes` | When the product database is lost and no backup exists: creates an empty one and rebuilds what derives from OpenAEVC. Accepted history is intact; Intents, Tasks and other product records are gone. Refused while a database exists |
| `recover apply --restore-backup <file> --yes` | Replaces the product database with a backup (verified by SHA-256 and integrity check; the current one is kept as `pre-restore`), then reconciles it against OpenAEVC |

Recovery only ever acts on provably disposable or restorable state:

- `.calve-init-*` staging from an interrupted `init`;
- a staged ignore-file edit;
- interrupted package installs or retirements (journaled; staging is removed or the install completes);
- an interrupted `project adopt-copy`: unless the adoption wrote its completion marker, the copy's original `.calve` is restored; after it, the leftover source state is removed.

Staging younger than ten minutes is left alone so a running operation is never disturbed. Recovery never edits OpenAEVC data. Store verification and GC need exclusive access to the OpenAEVC data directory, so the daemon releases its cached runtime for them.
