# ADR 0008: Trust-state persistence: crash consistency, not local tamper resistance

Status: Accepted (M0: FG15 PASS).

## Context
Catalog trust state must survive crashes and accidental damage without ever lowering rollback floors. Processes of the same OS user are trusted (user decision), so local tampering is out of scope.

## Decision
- Generations `gen-N/` = the client's accepted datastore + `raw/` (exact fetched bytes) + `state.json{repo_id, parent_gen, parent_state_digest, state_digest, client_accepted, phase, versions}`; `floors.json`/`floors.prev.json`; `CURRENT{gen, state_sha256}`; `REPO_ID` pinned at bootstrap.
- Commit protocol: copy the activated state to `gen-N.tmp` → the client accepts a transition there → state.json → rename (Prepared) → Calve policy (floors, repo id; Verified) → floors → CURRENT → prune (keep activated + previous).
- Recovery: delete `*.tmp`; the activated generation must be intact and re-importable by the client from its raw bytes; **roll forward** exactly one client-accepted, parent-linked child; **then** compare floors (ahead of the state → `RecoveryRequired(trust_state)`); missing floors are rewritten from the activated state; anything else is quarantined. Never a fallback to the parent of a corrupt activated generation; never activation on checksums alone.

## Consequences
- M0 deltas: raw-byte storage is required for tough as well; floors comparison follows roll-forward; `REPO_ID` file filters candidate generations even when CURRENT is lost.
- The privileged reset (`calve extension catalog reset <name> --root-digest`) archives the old state and logs it; never automatic.

## Tests / evidence
FG15 6/6 (crash at all nine commit steps × three refreshes; floors lost/ahead; corrupt/orphan/foreign generations; interrupted root rotation; delegation removal; root pin; reset).

## Residuals
**User-approved limitation:** no tamper resistance against the same OS user. Rollback resistance is claimed against network/mirror attackers only.
