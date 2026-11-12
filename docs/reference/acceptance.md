# Acceptance scenarios

`cargo run -p xtask -- acceptance --scenario <A..P|all|local> [--report out.json]` runs scenarios from this checkout, one complete test each, and records an environment fingerprint (OS, kernel, toolchain, commit, Cargo.lock hash, OpenAEVC revision, `calve` binary digest). A and B need the first-party catalog in `CALVE_CATALOG_ADD` (arguments of `calve extension catalog add`, one per line); without it they are reported `not-run`, never passed, and `all` fails. `local` runs only the scenarios that need no catalog (CI). The report separates `pass` from `pass-with-deviation`: a scenario with a deviation below is not a full pass even when its test is green.

| Scenario | Test | Status | Notes |
|---|---|---|---|
| A — Fresh installation and generic Project | `examples::scenario_a` | Pass (Linux) | Step 9 is OpenAEVC's policy evaluation (general-project declares no verifier or evaluator); step 14 restarts a real daemon. |
| B — Software project without Git | `examples::scenario_b` | Pass (Linux) | First-party software and Rust extensions. Step 8 runs the harness in its own pack over the same working tree (an execution on the candidate would make it unpromotable, and Calve refuses it) and the candidate's checks through `pack check`. Step 11 copies the Project, relocates the registration to the copy, removes its working files and materializes. |
| C — Pre-promotion reopen | `examples::scenario_c` | **Approved deviation** (pass-with-deviation) | Effect-bearing generations refuse the reopen and continue through an explicit replacement. See below. |
| D — Independent Baselines | `examples::scenario_d` | Pass (Linux) | B0→B1 touches only file2/file3; shared files keep their inodes. |
| E — Revision | `examples::scenario_e` | Pass (Linux) | |
| F — Parallel agent work | `examples::scenario_f` | Pass (Linux) | Each worker finishes only after it has seen the other running, so the two really overlap. The console engine reads a real daemon for step 5. |
| G — Capability denial | `acceptance::scenario_g_capability_denial` | Pass (Linux) | A fixture extension's real `process.execute` host call; OpenAEVC denies it and Calve reports `CAPABILITY_DENIED` with the grant command. |
| H — Extension permission widening | `extensions::scenario_h_permission_widening` | Pass (Linux) | |
| I — Project relocation | `examples::scenario_i` | Pass (Linux) | |
| J — Copied Project | `examples::scenario_j` | Pass (Linux) | The active execution is left RUNNING by killing its daemon before the copy. Imported objects are inert history: they verify, and appear in no Baseline list. |
| K — Crash during execution | `examples::scenario_k` | Pass (Linux) | A real daemon killed with SIGKILL. |
| L — Crash during extension install | `extensions::scenario_l_crash_during_extension_install` | Pass (Linux) | The crash is the debug-build fault point after the first durable install record. |
| M — Unsafe Baseline materialization | `examples::scenario_m` | Pass (Linux) | |
| N — Third-party extension | `extensions::scenario_n_third_party_extension` | Pass (Linux) | No Calve metadata and no Calve code: the extension's resources come from its signed manifest, and its evidence and resources are created, promoted and viewed generically. |
| O — Console reconnect | `examples::scenario_o` | Pass (Linux) | The console engine against a real calved, without a terminal. |
| P — Version incompatibility | `acceptance::scenario_p_version_incompatibility`, `acceptance::scenario_p_simulated_runtime_ranges`, `extensions::scenario_p_a_package_is_judged_on_its_protocol_range` | **Approved substitution** (pass-with-deviation) | Real packages; the runtime side is simulated. See below. |

## Scenario C: approved v0.1.0 deviation

The original text stands in the acceptance definition. The owner approved a narrow deviation for generations that carry effects.

**Why:** OpenAEVC v0.1.0 keeps a pack's effects on reopen (`handlers/packs.rs::reopen`), only ever appends to them (`handlers/execution.rs:590`), and promotes only when every effect's `provenance.generation` equals the current generation (`handlers/promotion.rs:95-104`). No command removes an effect, so a pack with effects could never be promoted after a reopen.

**What Calve does:** `pack reopen` on such a pack is refused with `REOPEN_UNSAFE` before anything changes, naming the way on. Nothing supersedes on its own. `supersede start` is the explicit operation: it works from OPEN, SEALED or QUALIFIED, and the original is abandoned last, only when the saga's checks pass. This is **not an unqualified pass**.

**Tested:** the literal eight steps on one pack when generation 1 has no effects (`examples::scenario_c`); safe refusal then explicit replacement through promotion (`an_effect_bearing_pack_refuses_reopen_and_is_replaced_explicitly`); crashes, conflict, cancellation and lost attempts (`replacing_a_sealed_pack_converges_after_a_crash_at_every_step`, `a_conflict_while_replacing_a_sealed_pack_keeps_the_original`, `a_cancelled_or_lost_replay_keeps_a_sealed_original`).

## Scenario P: approved substitution (pass-with-deviation)

| Step | Expected | Actual |
|---|---|---|
| 1. Run against an unsupported package or protocol | Refused | **Real:** signed packages advertising lower, higher and malformed ranges pass every other check and are refused with `EXTENSION_INCOMPATIBLE`. Ranges touching the supported version are accepted. **Simulated:** runtime ranges come from a debug-only report, because only one OpenAEVC can be linked. This is not a second implementation |
| 2. Writes blocked before mutation | No change | Asserted for each case |
| 3. Doctor reports the mismatch and range | Exact report | `doctor` fails with `OPENAEVC_INCOMPATIBLE` naming the reported and supported ranges |

Release builds contain no override: `xtask dist` refuses a binary that names a test hook.

Windows, macOS and aarch64 runs of these scenarios are pending; they need a shell, daemon lifecycle and the catalog on those hosts. Scenarios that use adopt-copy or Baseline transfer depend on FG16 (PASS).

