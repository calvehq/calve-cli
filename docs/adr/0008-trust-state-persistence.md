# ADR 0008: Trust-state persistence: crash consistency, not local tamper resistance

Status: Accepted (M0: FG15 PASS; G1-TUF rerun on sigstore-tuf 0.15.0: 8/8 Linux + Windows).

## Context
Catalog trust state must survive crashes and accidental damage without ever lowering rollback floors. Processes of the same OS user are trusted (user decision), so local tampering is out of scope.

## Decision
- Generations `gen-N/` = the exact verified bytes the client wrote through its metadata store (top-level roles, lazily loaded delegated roles, `root_history/N.root.json`) + `state.json{repo_id, parent_gen, parent_state_digest, state_digest, client_accepted, phase, versions, accepted_at}`; `floors.json`/`floors.prev.json` (with `accepted_at`); `CURRENT{gen, state_sha256}`; `REPO_ID` and `bootstrap-root.json` (sha256 = `REPO_ID`) pinned at bootstrap. Delegation floors come from the snapshot pins.
- Commit protocol: copy the activated state to `gen-N.tmp` → the client accepts a transition there → state.json → rename (Prepared) → Calve policy (floors, repo id; Verified) → floors → CURRENT → prune (keep activated + previous).
- Recovery: delete `*.tmp`; the activated generation must be intact and **replay** through the verifier from the bootstrap root as of its `accepted_at` (every stored role, delegated roles through their delegators; any error → `RecoveryRequired`); **roll forward** exactly one client-accepted, parent-linked child; **then** compare floors (ahead of the state → `RecoveryRequired(trust_state)`); missing floors are rewritten from the activated state; anything else is quarantined. Never a fallback to the parent of a corrupt activated generation; never activation on checksums alone.

## Consequences
- M0 deltas: raw-byte storage is required for tough as well; floors comparison follows roll-forward; `REPO_ID` file filters candidate generations even when CURRENT is lost.
- G1-TUF deltas: no separate `raw/` copy (sigstore-tuf stores fetched bytes verbatim); the verifier clock is `max(system clock, last accepted_at)`, so a stepped-back clock cannot revive expired metadata; resolving a target is itself a transition, so lazily loaded delegated roles land in the new generation. Windows: files are synced through a writable handle; directory fsync is Unix-only and rename durability uses `MoveFileExW(MOVEFILE_WRITE_THROUGH)` (M2/M4).
- The privileged reset (`calve extension catalog reset <name> --root-digest`) archives the old state and logs it; never automatic.

## Tests / evidence
FG15 6/6 on tough (M0); G1-TUF rerun 8/8 on sigstore-tuf, Linux and Windows (adds delegated-role replay with repaired digests → RecoveryRequired, and the stepped-back clock case).

## Residuals
**User-approved limitation:** no tamper resistance against the same OS user. Rollback resistance is claimed against network/mirror attackers only.
