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
