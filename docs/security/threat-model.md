# Threat model


This document states what Calve defends, what it deliberately does not, and where each claim is tested. A claim without a passing test or recorded result is not made; anything that cannot be run locally is marked **PENDING** with its release gate.

## 1. Assets

- The user's working tree and the content Calve captures from it or writes into it.
- The OpenAEVC store of a Project (authoritative history, candidates, receipts, journals).
- Calve's product database and operational journals (capture, supersede, materialization, install, catalog generations, spawn).
- Catalog trust state (TUF generations, floors, the pinned repository identity).
- Secrets handed to workers.
- Installed extension artifacts.

## 2. Trust boundaries

| Boundary | Trusted side | Untrusted side | Mechanism | Evidence |
|---|---|---|---|---|
| **Same OS user** | every process of the user running Calve | — | none: same-user processes are **trusted** (user decision; like ssh-agent/gpg-agent) | asserted by tests (ADR 0016) |
| Other local users | the user | other accounts | Unix: 0700/0600 permissions; Windows: owner-only DACLs, pipe DACL, impersonation SID check | M5 (Windows PENDING native) |
| Network / catalog mirrors | the pinned root of trust | mirrors, CDNs, the network | TUF (sigstore-tuf 0.15.0) + Calve catalog policy, bounded transport, floors and a pinned repository identity | FG2a, FG15 reruns; G1-TUF conformance 119/119 ×3, malicious-mirror tests; G1 PENDING CI |
| Extension planning code (T1) | the host | `cic.wasm` | wasm without imports, memory/fuel caps, supervised child (`calve __cic-sandbox`, Linux Landlock deny-all) with a hard wall-clock kill; every response validated (cardinality, order, paths, canonical JSON) | FG3, FG4, FG13; M2 `cic_host`, `cic_sessions`, `cic_fixture`, calve-extensions conformance |
| Check plans (T1 output run as T3) | the user's approval | a package's `check_plan` | runs only after the user approves a digest covering the plan, the package (id, version, target, file digests) and the resolved executable (path + sha256), re-checked before each spawn; bare program on absolute `PATH` entries only; candidate copied without following symlinks; credential/loader environment names refused (defence in depth) | M2 `checks` unit tests, `domains` e2e incl. `check_plan_approval_is_bound_to_the_resolved_executable` |
| Native extensions (T2) | — | — | **not confined** (OpenAEVC spawns them directly, F4); TUF-verified package, per-spawn re-hash, cleared env, grants for host-mediated calls, explicit user acknowledgment (`--acknowledge-native`, recorded per artifact) | ADR 0005; `t2_native_code_is_not_confined_residual` (M2) |
| Workers and checks (T3) | the host | the worker | process group / Job Object; on Linux a user and mount namespace hides `.calve/` and Calve's private directories, including the daemon socket, then Landlock. A worker that cannot be confined is refused by default on Linux | `apps/calve/tests/confinement.rs` |

## 3. In scope (defended)

- **Catalog compromise below the root of trust:** forged, expired, rolled-back, frozen or mix-and-match metadata from a mirror; targets substituted on the mirror; a delegate signing outside its paths. The verifier checks TUF; Calve adds a catalog key/hash policy (computed key ids, unique key material), byte caps and deadlines on every fetch, floors that never decrease, a verifier clock that never goes below the last accepted time, a pinned `REPO_ID`, and refuses to activate anything the client did not accept as a transition from the activated state. Slow-retrieval and endless-data mirrors end in one bounded error.
- **Crashes and accidental damage** of every Calve-owned store: hash-chained journals with intent-before-mutation and ack-after-mutation (FG17), catalog generation recovery (FG15), materialization WAL (M4), product DB backups (M4).
- **Path escapes** from the Project root through symlinks or `..` (cap-std component walk with nofollow; FG5).
- **Untrusted planning code:** a CIC guest cannot reach the host (no imports), cannot exhaust memory or run unboundedly (caps, fuel, hard kill), and cannot make the host accept malformed, non-canonical, partial or mis-ordered output (exact validation; 25 adversarial modules + 11 adversarial relate guests).
- **Other local users** reaching the daemon or Calve's files (M5).

## 4. Out of scope (explicitly not defended)

- Anything running as the same OS user: it can read and modify Calve's state, trust state, installed extensions and journals, connect to the daemon and impersonate clients. Integrity checks (OpenAEVC per-spawn re-hash, journal hash chains, catalog checksums) **detect accidents**, not same-user tampering.
- A compromised root key or a malicious first-party publisher.
- Malicious T2 native extensions acting with the user's permissions.
- Kernel, hypervisor or hardware attacks; side channels.

## 5. Honesty register (non-guarantees; each has an asserting test or a recorded result)

| Area | Not guaranteed | Where asserted |
|---|---|---|
| T2 native extensions | not OS-confined; self-applied Landlock in first-party binaries is author self-restriction | `apps/calve/tests/extensions.rs::t2_native_code_is_not_confined_residual` (M2, Linux): the write outside the install dir succeeds |
| Check plans | approval binds the plan, package and executable, not what the program then does: an approved `sh -c …` runs with the user's permissions, under the worker supervisor and, on Linux, Landlock; an executable replaced between the pre-spawn hash and exec is not detected | M2 `checks` tests (refusal, digest binding) |
| Package publishers | a catalog's delegated publisher may publish any id its delegation paths and `id-policy.json` allow; the first-party catalog uses the delegated `calve` role, limited to `org.calve.` | M2 `install` tests (publisher chain, id policy) |
| Secret redaction | best effort per stream; misses cross-stream splits, transformations, base64 edge bytes, channels outside Calve's sinks | M3 residual tests |
| Process containment | Unix descendants that `setsid`/`setpgid` escape; a SIGKILLed helper does not propagate until restart reaping; macOS has no parent-death signal; Windows out-of-job processes started by other services | FG12 (Linux), M5 |
| Filesystem concurrency | no conflict-free concurrency; atomic exchange/replace prevents partial reads and preserves displaced content but does not prevent every lost update; weak filesystems refused by default | FG11 (Linux, Windows), M4 |
| Local trust state | no tamper resistance against the same OS user; rollback resistance only against network/mirror attackers | FG15, FG2a |
| Store history | the hash chain proves extension of the checkpointed journal; full-chain rewrite detection only back to a pinned signed checkpoint | FG10, M4 |
| Capture | no atomicity across OpenAEVC commands; the candidate digest is never equal after a rollback; a raw OpenAEVC client can seal a pack Calve considers incomplete | FG7, M4 |
| Catalog delegation conformance | shown on Linux (119/119 ×3) and by regression tests on Linux + Windows; not yet on CI runners, macOS or aarch64 | G1-TUF report — G1 PENDING CI; macOS/aarch64 BLOCKED |
| Catalog verifier dependency | sigstore-tuf is pre-1.0 with frequent releases and counts distinct key ids toward thresholds; target bytes are buffered up to the configured cap | exact pin + re-run on bump; policy tests (duplicate key material); `target_max_length` per catalog (M2) |

## 6. Platform status

| Platform | Status |
|---|---|
| Linux x86_64 | Tested locally: full suites on WSL2 kernel 6.6, ext4 and tmpfs |
| Windows x86_64 (gnu) | Tested natively from cross-compiled binaries. Other-user, squatting and remote checks are not tested; see [Windows boundary](windows-boundary.md) |
| Windows MSVC | Not built yet |
| macOS, aarch64 | Not built or tested yet |
