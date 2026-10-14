# ADR 0011: Capture: canonical per-path ops, sessions, supersede/compensate

Status: Accepted (M0: FG7, FG8, FG9 PASS).

## Context
OpenAEVC appends each submitted effect immediately and never removes candidate effects (F5); a candidate digest covers the full ordered effect list (F6); seal is refused while an execution is active (F7).

## Decision
- Plan before mutate: a CIC capture session runs to `Finished` (spool + `I`, `O`, relations) before any OpenAEVC command.
- Capture execution lifecycle per F19 (Planned → Submitting(k) → Submitted | Interrupted | Cancelled | FailedSubmit), resume on a new execution with `idempotency_key = <capture-id>:<attempt>`.
- Two equivalence checks: resource-state (RSE) and candidate-content (CCE); the candidate digest is never claimed equal after rollback.
- `--rollback=supersede` (default) is a journaled cross-store saga S0–S9 with fallible compensation C1–C3, a versioned active-pack commitment (compare-and-swap) and P abandoned last; `--rollback=compensate` appends compensating effects (RSE holds, CCE does not, reported).

## Consequences
Request-level idempotency (F22) covers identical-envelope retries within the replay window (FG8: identical receipts for Create/Submit/Complete/Abandon). Outside it, discovery: v0.1.0 has no pack-listing query, so P' is found by scanning `ListEvents{kinds:[changepack.created], after: <head sequence journaled before S2>}` + `GetChangePack` metadata `calve.supersede_id`; effects by CCE; executions by `idempotency_key` (same key → same execution id). `AbandonChangePack` succeeds while an execution is RUNNING and leaves it RUNNING until lease expiry (FG9), so S1 (cancel first) is mandatory.

## Tests / evidence
M4: crash after every S/C step inside and outside the replay window; divergence and conflict injection; compensation conflict → RecoveryRequired.

## Residuals
No atomicity across OpenAEVC commands. Raw OpenAEVC clients can seal a pack Calve considers incomplete (asserted residual).
