# ADR 0009: Product state ownership, internal backups, no export/import

Status: Accepted (extends ADR 0002).

## Context
The product DB mixes durable Calve data with rebuildable indexes of OpenAEVC state. The user decided there are no user-facing export/import commands.

## Decision
- Classification per table (§10): durable product data (intents, tasks, dependencies, links, metadata, preferences, grants, adoptions) is backed up; OpenAEVC-derived indexes (baselines, pack summaries, reviews index) are rebuilt; reviews are always published to OpenAEVC as `org.calve.review` evidence.
- Internal SQLite online backups before every migration and daily on idle (`.calve/backups/product-<UTC>-v<schema>.db`), `PRAGMA integrity_check` after writing, retention 7 daily + pre-migration 30 days.
- Recovery via `recover inspect` / `recover apply --restore-backup <file>` followed by reconciliation (ADR 0010).

## Consequences
Operational journals (capture, supersede, materialize, install, catalog generations, spawn) live outside the product DB and must survive its loss.

## Tests / evidence
M4: DB deleted → restore + rebuild equality; old backup → indexes reflect current OpenAEVC; migration crash → restore; integrity failure detected.

## Residuals
None beyond ADR 0010's scope statement.
