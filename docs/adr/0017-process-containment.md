# ADR 0017: Process containment

Status: Accepted; Unix/macOS gaps user-approved (M0: FG12 PASS Linux).

## Context
Cancelling or crashing must not leave worker trees running.

## Decision
- Windows: a parent-owned, non-inheritable Job Object with `KILL_ON_JOB_CLOSE`, assignment at creation (`PROC_THREAD_ATTRIBUTE_JOB_LIST`, suspended-assign fallback), explicit `TerminateJobObject` on cancel; refuse to start workers if nesting fails unless explicitly allowed.
- Unix: `calve __exec-confined` helper leads one process group; PDEATHSIG + post-registration `getppid()` race check; signal handler kills the group; result reported and acked before the final group kill, with a pre-opened CLOEXEC fd fallback that works under Landlock; restart reaping by start-time match.

## Consequences
FG12 (Linux) proved group kill incl. double-forked grandchildren, the PDEATHSIG race, result-before-kill ordering, RLIMIT_AS, pidfd reaping, and the fallback fd under Landlock. Delta: the helper's Landlock read allowance is limited to system paths (/usr, /bin, /lib, /lib64, /etc, /proc, /dev, /sys) plus read-write scratch, so workers cannot open the spawn/result directory.

## Tests / evidence
FG12; M5 native Windows/macOS tests.

## Residuals
**User-approved limitations:** descendants that leave the group (`setsid`/`setpgid`) escape cancellation; a SIGKILLed helper does not propagate (reaped at restart); macOS has no parent-death signal (restart reaping only). Cgroup containment is a non-goal for 0.1.0.

## M5 implementation (2026-10-26)
- **Unix** (`calve_app::supervise`): the `__exec-confined` helper as decided; spawn journals in `<runtime dir>/spawn` (0700; `$XDG_RUNTIME_DIR/calve/<digest>` or the data root) record `spawned`/`result`/`helper_exit`/`cancel_intent`/`cancelled`/`lost`. The result socket accepts only the helper (`SO_PEERCRED` pid = group id). Reaping (daemon start and before each spawn) touches a record only if its journal id is 32 hex equal to the file name, the recorded parent is dead, and the helper's start time matches or the group is orphaned; a group id is never killed while a reused pid could lead it. A helper that dies (SIGKILL) is recorded `lost` and its orphaned group is killed at once. Landlock read-write roots fail closed (no `/` fallback; empty, relative and `/` roots dropped) and the achieved level (`full`/`partial`/`none`) is in the result.
- **Windows** (`calve_win_sec::Job`): non-inheritable `KILL_ON_JOB_CLOSE` job with optional memory and active-process limits; **deviation:** assignment uses the suspended path only (`CREATE_SUSPENDED` → `AssignProcessToJobObject` → resume every thread via a Toolhelp32 snapshot); `PROC_THREAD_ATTRIBUTE_JOB_LIST` is not implemented (std's `Command` exposes no attribute list without more FFI). Cancel = `TerminateJobObject` and wait for `ActiveProcesses == 0`. `allow_uncontained` is not implemented: a job failure always refuses the worker.
- **macOS:** restart reaping compiles with the Unix code; not executed (PENDING, no host).
- Evidence: `apps/calve/tests/supervise.rs` (Linux, 8: normal exit ordering, cancellation incl. double-forked grandchild, parent death, PDEATHSIG race, Landlock fallback file, lost helper, setsid escape asserted, reaping checks); `calve-win-sec` native Windows (job terminate, close, active-process limit, killed parent takes the tree).
- Not wired: RLIMIT / job limits from provider configuration (the primitives exist; defaults unlimited).
