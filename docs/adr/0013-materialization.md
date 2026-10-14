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
