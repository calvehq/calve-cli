# Materialization guarantees

## Guaranteed

- **Work you never captured is not destroyed.** A path that differs from what Calve recorded blocks the operation, unless you pass `--discard` for that path.
- **Originals are kept while the operation can be rolled back.** Each is copied from the same no-follow handle that was hashed, to a verified backup, before it is replaced. `maintenance gc` removes finished operations after 30 days.
- **No partial content is written.** Blobs are verified chunk by chunk and as a whole first.
- **A crash is recoverable.** The write-ahead log lets `materialize resume` settle each step from what is on disk.
- **Detected concurrent writes are kept.** Anything unexpected stops the operation as Conflicted, and `.calve/conflicts/<op>/` holds the displaced bytes. Conflict artifacts are never removed automatically.
- **Rollback is checked.** Each step is reversed only after confirming the current content is what the step wrote.

## Not guaranteed

- **No lost-update freedom, on any platform.** These are check-then-act steps, not compare-and-swap. A concurrent writer is detected after the fact, never prevented. Do not edit files during a materialization.
- **Weak filesystems are refused, not made safe.** Without an atomic exchange or no-replace rename, replacing existing files is refused with `MATERIALIZE_CONFLICT(unsafe_fs)`. `--allow-unsafe-fs` proceeds with plain renames and records that choice: a write in the final window before the rename can be lost.
- **Same-user tampering** with journals or backups is not detected reliably. Their checks catch accidents.

The algorithm is in [materialization](../reference/materialization.md).
