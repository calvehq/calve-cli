# ADR 0022: GC dry run reads the runtime database

Status: Proposed (M7); needs the project owner's approval as an exception to the architecture rule.

## Context
Plan §44.3 requires `maintenance gc --dry-run` to report a count and estimated bytes per class. Plan §49 rule 7 fails CI if Calve opens `.calve/openaevc/` directly. OpenAEVC v0.1.0's `collect_garbage` is the only way to learn the collectable set, and it deletes. The `Store` API cannot enumerate objects, and v0.1.0 is not modified from Calve.

## Decision
`crates/calve-app/src/gc.rs` keeps one read-only query, with OpenAEVC's own criteria, opened with `SQLITE_OPEN_READ_ONLY`. `xtask check-architecture` names this file and the read forms it may use. Any other file, and any write form in this file, fails the check. Deletion always goes through `collect_garbage`.

## Consequences
A runtime schema change breaks the count. The pin is exact, and the maintenance tests exercise the query, so a bump finds it. The count can differ from what is later removed, because objects may be indexed in between; that is inherent to a dry run.

## Upgrade
Remove the exception when OpenAEVC offers a GC plan.
