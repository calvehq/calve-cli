# Materialization

Materialization writes accepted file content into the working tree without destroying work that was never captured (§14, ADR 0013).

```sh
calve baseline materialize <baseline-or-alias>                   # plan only
calve baseline materialize <baseline> --apply [--activate]
calve baseline materialize <baseline> --apply --discard path/to/file
calve resource materialize <path> --from <pack> [--apply] [--discard]
calve materialize list
calve materialize resume <op>
calve materialize resolve <op> --keep ours|theirs
calve materialize rollback <op> --yes
```

1. The Baseline is validated through OpenAEVC and its members' file effects are composed; chunked content is read from its blobs and verified chunk by chunk and as a whole (`CONTENT_CORRUPT`, or `MATERIALIZE_CONFLICT(content_unavailable)` when a blob is absent; nothing partial is written).
2. Each path is classified: `create`, `unchanged`, `update` (the local file matches a snapshot Calve recorded), `delete`, or `blocked_uncaptured_changes`. Without `--apply`, or when anything is blocked, Calve returns the plan and stops; `--discard <path>` is an explicit per-path decision to overwrite.
3. Applying runs a write-ahead log, `.calve/run/materialize/<op>/journal`, one step per path: intent → the original is copied from the same no-follow handle that was hashed into `<step>.backup` and verified → Calve's bytes go to a synced temp file in the same directory → `renameat2(RENAME_EXCHANGE)` (replace) or `RENAME_NOREPLACE` (create, and delete-to-trash) → the destination must be Calve's inode with the expected digest → the displaced original must equal what was preserved → done.
4. Anything unexpected stops the operation as **Conflicted** and nothing is reversed: `.calve/conflicts/<op>/<step>/` keeps `displaced` (the concurrent writer's bytes), `ours`, and `meta.json` (owner-only, never removed automatically). `materialize resolve --keep theirs` puts the displaced bytes back, `--keep ours` keeps Calve's; both go through the same WAL and the operation then continues.
5. A crash leaves an intent without `done`; `materialize resume` settles it from what is on disk (path, temp, trash, verified backup) and continues. A new materialization is refused while one is unfinished.
6. `materialize rollback` reverses completed steps newest first, each only after re-checking the parent directories (no symlinks), that the current content is what the step wrote, and that the backup is intact; otherwise that step becomes a conflict with the current bytes kept.
7. Writes require the write action on each resource. Provenance is one OpenAEVC execution per operation on a dedicated, afterwards abandoned, pack (`<extension>.materialized` observations). `--activate` moves the active Baseline only once the operation is Completed.

These are check-then-act steps, not compare-and-swap: a concurrent writer is detected after the fact, never prevented, and no lost-update freedom is claimed on any platform.

**Filesystems without exchange/no-replace** (macOS and Windows until M5, and weak Linux filesystems): replacing or deleting existing files is refused with `MATERIALIZE_CONFLICT(unsafe_fs)`; new files are still created without replacing. `--allow-unsafe-fs` applies anyway with plain renames, records the choice in the journal and warns: the original is still backed up, but a write in the final window before the rename is lost.
