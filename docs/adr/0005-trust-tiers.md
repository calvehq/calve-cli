# ADR 0005: Trust tiers T1/T2/T3

Status: Accepted; T2 limitation user-approved (2026-10-13); M2 implemented.

## Context
Three kinds of extension code run on a user's machine: CIC wasm (planning), native OpenAEVC-contract binaries spawned by the frozen OpenAEVC runtime (F4: it spawns `rec.program` directly, clears env except PATH, re-hashes the artifact per spawn), and workers/checks.

## Decision
- **T1** `cic.wasm` in the supervised sandbox: isolation by construction (no imports) plus memory, fuel and hard wall-clock limits.
- **T2** native OpenAEVC binaries: **elevated trust, not OS-confined.** Enforced only: TUF-verified package, per-spawn re-hash, cleared env, capability ceilings and grants for host-mediated calls. Installing or enabling T2 requires an explicit, recorded acknowledgment ("runs as native code with your user permissions").
- **T3** workers/checks: runner limits and process containment (ADR 0017); Linux additionally self-applies Landlock through `calve __exec-confined`.
- Logical purity, observed determinism and enforced isolation are reported separately (docs, `calve extension show`, console).

## Consequences
- A versioned launcher-hook proposal (`docs/proposals/openaevc-spawn-policy.md`) is kept for a future OpenAEVC release; Calve does not patch OpenAEVC.

## Tests / evidence
Residual tests: `fixture_t2_escape` writes outside its directory and the write **succeeds** (asserted residual); a T1 module with an import is rejected (FG4); T3 Linux write outside scratch → EACCES (FG12 Landlock); macOS/Windows T3 writes succeed (PENDING native).

## Residuals
**User-approved limitation:** T2 native extensions are not OS-confined. Self-applied Landlock in first-party T2 binaries is author self-restriction, not host enforcement.

## M2 production implementation (2026-10-15)
- T2 acknowledgment: `extension install|enable|update --acknowledge-native`, recorded per Project as the grant marker `calve:t2-acknowledged` on that artifact digest.
- T3 check plans produced by a T1 module run with the user's permissions, so they need a recorded per-artifact approval of the exact plan digest (`pack check --approve-plan <digest>`), may name only a bare program resolved on absolute PATH entries, and run on a candidate copy made without following symlinks (security-review fixes 66c3d8b, abaeae0 and the digest-bound approval).
