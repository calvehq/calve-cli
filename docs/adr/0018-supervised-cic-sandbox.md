# ADR 0018: Supervised CIC sandbox and hard deadlines

Status: Accepted (M0: FG3 PASS; M2 production PASS on Linux).

## Context
wasmi has no epoch interruption (F13); fuel alone cannot bound wall time for every instruction mix.

## Decision
- Soft deadline on the calling thread: `call_resumable` with fuel slices; between slices the host checks wall time and the per-call fuel budget.
- Hard deadline: every CIC session runs in a child (`calve __cic-sandbox`) speaking framed messages over stdio; the parent kills it at the wall-clock deadline (process group / Job Object).
- Resource caps: guest memory 64 MiB (StoreLimits, growth denial tracked → `OUT_OF_MEMORY`), module ≤ 8 MiB, tables ≤ 10 000, 1 instance/memory/table.

## Consequences
- **M0 deltas:** compile **eagerly** (`CompilationMode::Eager`: lazy translation charges fuel and its out-of-fuel is not resumable); each resume grants `max(slice, required_fuel)` (bulk-memory instructions can need more than a slice); **never** give wasmi a per-package `opt-level` override (a mixed profile overflows the host stack on a tight loop — `tests/fg04_wasmi_profile.rs`).

## Tests / evidence
FG3: release soft-deadline overshoot 50 µs (slice 1e5) / 15.6 ms (1e7); bulk ops are fuel-metered per byte; supervised hard kill 1.012 s for a 1 s deadline.

## Residuals
wasmi interpreter bugs (tracked by cargo-deny advisories).

## M2 production implementation (2026-10-15)
- `calve __cic-sandbox` serves every production CIC session (`domains::open_session`); Linux applies Landlock deny-all in the child. The production host is the one exercised by calve-extensions conformance.

## Current status
On Linux the child applies Landlock deny-all. Where confinement is required, a module does not run if the kernel enforces none; `doctor` reports `cic_landlock` and the policy. macOS and Windows have no such second wall: there the boundary is wasm alone, with the parent killing the child at the deadline. No Job Object is used for this child, whatever earlier text says.
