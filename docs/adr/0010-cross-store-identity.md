# ADR 0010: Cross-store identity and reconciliation

Status: Accepted (M0: FG10 PASS; fallback identity NOT approved by the user).

## Context
Calve state spans the OpenAEVC store, the product DB, operational journals, extension registrations, catalog generations and the workspace.

## Decision
- Journal identity = `(NamespaceId, genesis_hash)`; every Calve record carries `{project_id, namespace_id, genesis_hash}`.
- Continuity: the product checkpoint `{sequence, hash}` is extended by verifying SDK-fetched events with OpenAEVC's own `verify_chain` (FG10 proved events and hashes are retrievable through the SDK).
- Outcomes: binding mismatch → `RecoveryRequired(identity_mismatch)`; chain failure/gap → `RecoveryRequired(continuity)`; head below checkpoint → `RecoveryRequired(openaevc_behind)`. Calve never writes OpenAEVC to fix projections.
- Reconciliation order: bindings → OpenAEVC recovery → catalog → install journals ↔ registry → capture/supersede ↔ executions → materialization ↔ filesystem → projections → inbox.

## Consequences
- **User decision (2026-10-13):** because FG10 passed, the fallback store identity (random store id) is **not approved** and must not be used.

## Tests / evidence
FG10; M4 identity/continuity tests incl. dry-run writes nothing.

## Residuals
The hash chain proves extension of the checkpointed journal. FG10 showed `GetJournalCheckpoint` returns signed checkpoints once the checkpoint interval is reached, so Calve pins the latest signed checkpoint digest (M4) and the claim is upgraded to full-chain-rewrite detection back to that checkpoint; before the first checkpoint only extension is proven. `runtime_instance` changes on every reopen and is informational only.

## M4 implementation (2026-10-17)
- `store_binding` (product DB v14) holds `{project_id, namespace_id, genesis_hash, checkpoint}`; `continuity.rs` verifies the chain from the pinned signed checkpoint with OpenAEVC's `verify_chain` and returns `RECOVERY_REQUIRED` with reason `identity_mismatch`, `continuity` or `openaevc_behind`.
- `recover inspect` uses the store API only (no runtime, no migration, no write); `recover plan` actions name their owner.
- Reconciliation from OpenAEVC: pack index (titles from `org.calve.title`, Intent links from `pack.intent`, added in H after a crash test found a stale link), Baselines (labels in metadata), adoption leftovers (explicit completion marker, after a crash test found that a crash mid-import discarded the source).
- Every OpenAEVC command Calve sends has a crash point right after it (`openaevc.<Command>`); `crash_boundaries.rs` exercises 25 of the 34 commands, the rest through the capture, supersede and materialization journals.
