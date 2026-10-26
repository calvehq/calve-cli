# ADR 0013: Materialization WAL and per-platform guarantees

Status: Accepted; weak-FS limitation approved with conditions.

## Context
Writing a Baseline into a working tree must never lose content the user had, even under crashes and concurrent writers it cannot control.

## Decision
- JSONL WAL per operation: intent → preserve the verified original (hash through the same handle) → mutate with the strongest platform primitive → post-mutation identity check → post-verify displaced content → done. Check-then-rename is never called compare-and-swap; there is no automatic swap-back.
- Primitives: Linux `renameat2` EXCHANGE/NOREPLACE (FG11 PASS on ext4/tmpfs/overlayfs); Windows `ReplaceFileW` with backup, `MoveFileExW` without replace, hard-link create (FG11 Windows run); macOS `renamex_np` (BLOCKED, no Mac).
- Four separate properties per platform: original preserved, conflict detected (after the fact), atomic visibility, displaced content preserved. No lost-update-freedom and no conflict-free concurrency are claimed.

## Consequences
- **User decision (2026-10-13):** materialization on filesystems lacking the primitives stays **refused by default** (`MATERIALIZE_CONFLICT(unsafe_fs)`); `--allow-unsafe-fs` requires an explicit **per-operation** acknowledgment and records provenance in the journal; default recovery guarantees are never weakened.
- Conflict artifacts (`.calve/conflicts/<op>/<seq>/`) are never auto-deleted.

## Tests / evidence
FG11 (Linux; Windows axis); M4 crash at every record boundary × op kind, concurrent-writer injection, rollback revalidation, ENOSPC.

## Residuals
Lost updates by writers outside Calve's control (e.g. a writer that overwrites Calve's new file later) are possible on every platform (honesty register).

## M4 implementation (2026-10-17)
- `wal.rs` implements the WAL on Linux with `renameat2` EXCHANGE/NOREPLACE (probed in `.calve/tmp`), the post-mutation inode/digest check and displaced-content verification; conflicts keep `displaced`, `ours`, `current` and `meta.json` (0600 in 0700) and are never removed automatically (`maintenance gc --conflicts` only for resolved operations).
- `calve materialize list|resume|resolve --keep ours|theirs|rollback --yes`; rollback revalidates the parent chain (nofollow), current content and backup per step.
- Provenance: one OpenAEVC execution per operation (`p.intent`/`p.ack`, interrupted attempts found by `changepack.created` discovery and acked or abandoned).
- **Platform status:** macOS and Windows use the fallback primitives until M5 (`renamex_np`, `ReplaceFileW`/`MoveFileExW` are not wired yet), so on those platforms replace and delete are **refused by default** and need `--allow-unsafe-fs`. This is a behaviour change from M3 (plain rename) on Windows.
- **Not yet covered:** ENOSPC injection; symlink, chmod, mkdir and rmdir steps (file domains produce file writes and deletes only; parents are created on demand).
- Evidence: `wal::tests` (4), `materialize_wal.rs` (14 crash points, concurrent writer before the swap and through the old inode, weak-FS refusal and opt-in residual, exact rollback), §57 D (B0→B1 touches only the necessary paths).

## M5 implementation (2026-10-26)
- **Primitives trait:** `replace(dir, temp, name, spare)` returns where the displaced original is. Linux keeps `renameat2` EXCHANGE (displaced at `temp`). The default — used on Windows — is **displace-then-place**: two no-replace renames (`name → spare`, then `temp → name`). Nothing is overwritten and the original is moved, never copied; readers can briefly see the path absent (not atomic visibility); a file created in that gap fails the second rename and all three copies are kept (`created_concurrently`). A crash between the two renames is finished by reconciliation only when the trash holds the verified original, the temp holds Calve's bytes and the backup verifies; any other state is a conflict.
- **Windows:** `windows-handle-rename` — `calve_win_sec::rename_by_handle` (NtSetInformationFile FileRenameInformation with the directory handle as RootDirectory, no replace). Found natively: the Win32 `SetFileInformationByHandle` rejects a RootDirectory (error 87) and resolves a bare target name against the **process working directory**, so it is not used. The source is opened nofollow with DELETE and full sharing; a holder without `FILE_SHARE_DELETE` makes the step fail with a sharing violation and the file untouched (resume completes it). Directory entries are flushed through a handle-relative `NtCreateFile` + `FlushFileBuffers` (ReOpenFile on a directory handle is refused). The primitives are probed per project (`.calve/tmp`): no-replace must refuse an existing target; otherwise the fallback (refused by default) applies. `ReplaceFileW` and `MoveFileExW` are not used (path-based).
- **macOS:** not wired; uses the fallback (replace/delete refused by default). `renameatx_np` swap/excl is the intended primitive. PENDING (no Mac host).
- **Modes:** a replacement keeps the displaced file's rwx bits (setuid/setgid/sticky dropped) on Unix and the read-only flag on Windows; Calve's own displaced/trash copies that are read-only are made writable before removal on Windows.
- **ENOSPC / write errors:** a failed temp write removes the partial temp; the tree is untouched and resume restarts the step. Debug injection: `CALVE_TEST_ENOSPC=<step>.temp|<step>.backup`.
- **Directories:** parents are created on demand and are not journaled; rollback removes files only, so directories it created stay (documented limitation, not a guarantee). A file in the parent chain, or a directory at a file path, is never replaced. Symlinks at the target or in the parent chain are never followed.
- **Evidence:** `wal::tests` (create/replace/delete/reverse, conflicts, rollback refusals, modes, read-only, symlinked target, directories; Windows: sharing violation + reconcile) natively on Windows and on Linux; `materialize_wal.rs` crash-at-every-boundary and concurrent-writer runs for both exchange and displace-then-place (`CALVE_FS_PRIMITIVES=displace`, including a crash between the two renames), ENOSPC on temp and backup, two concurrent materializations.
