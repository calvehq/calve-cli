# Acceptance scenarios

`cargo run -p xtask -- acceptance --scenario <A..P|all> [--report out.json]` runs scenarios from this checkout, one complete test each, and records an environment fingerprint (OS, kernel, toolchain, commit, Cargo.lock hash, OpenAEVC revision, `calve` binary digest). A and B need the first-party catalog in `CALVE_CATALOG_ADD` (arguments of `calve extension catalog add`, one per line); without it they are reported `not-run`, never passed. The report separates `pass` from `pass-with-deviation`: a scenario with a deviation below is not a full pass even when its test is green.

| Scenario | Test | Status | Notes |
|---|---|---|---|
| A — Fresh installation and generic Project | `examples::scenario_a` | Pass (Linux) | Step 9 is OpenAEVC's policy evaluation (general-project declares no verifier or evaluator); step 14 restarts a real daemon. |
| B — Software project without Git | `examples::scenario_b` | Pass (Linux) | First-party software and Rust extensions. Step 8 runs the harness in its own pack over the same working tree (an execution on the candidate would make it unpromotable, and Calve refuses it) and the candidate's checks through `pack check`. Step 11 copies the Project, relocates the registration to the copy, removes its working files and materializes. |
| C — Pre-promotion reopen | `examples::scenario_c` | **Blocked by OpenAEVC v0.1.0; decision requested** | The literal lifecycle passes on one pack when generation 1 has no effects. With effects, steps 5–7 cannot pass: see below. |
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
| P — Version incompatibility | `acceptance::scenario_p_version_incompatibility`, `extensions::scenario_p_an_extension_of_an_unsupported_protocol_is_refused` | **Needs review** | See below. |

## Scenario C: decision request

**Steps:** 1. create, seal, verify, approve generation 1. 2. Reopen. 3. Generation 2. 4. Prior verification and review stale. 5. Modify the candidate. 6. Rerun qualification and review. 7. Promote generation 2. 8. Generation 1 evidence inspectable.

**Counterexample, frozen OpenAEVC v0.1.0.** `handlers/packs.rs::reopen` keeps `candidate_effects`. `handlers/execution.rs:590` only ever appends to it. `handlers/promotion.rs:95-104` refuses unless every candidate effect has `provenance.generation == generation`. No command removes an effect. So a pack holding any effect at reopen can never be promoted: `pack promote` returns `candidate contains effects without complete provenance for this generation`.

**Affected invariant:** OpenAEVC's single authority on promotion. Calve cannot change this without modifying v0.1.0.

**What passes:** steps 1–4 and 8 with effects; all eight steps on one pack when generation 1 has no effects; steps 5–7 with effects through `supersede start`, where the work continues in a replacement pack. `pack reopen` warns about this.

**Alternatives:** (a) accept the replacement-pack path for packs with effects, stating that the pack id changes; (b) make `pack reopen` supersede automatically, so the product's reopen always continues, with a new pack id underneath; (c) require an OpenAEVC release that lets a reopened pack drop or re-attribute effects.

**Decision needed:** which of these, scoped to packs with effects at reopen.

## Scenario P: steps and results

| Step | Expected | Actual |
|---|---|---|
| 1. Run against an unsupported package or protocol | Refused | A real extension package declaring protocol 9 is refused at install, naming both ranges. For the runtime itself only one OpenAEVC can be linked, so a debug-only report override (`CALVE_TEST_RUNTIME_PROTOCOL`) feeds the real check |
| 2. Writes blocked before mutation | No change | Asserted by event count and pack list |
| 3. Doctor reports the mismatch and range | Exact report | `doctor` fails with `OPENAEVC_INCOMPATIBLE` naming the runtime range and the supported range |

**Proposed:** treat the package fixture as the real test of step 1. The runtime case cannot be run against a real older OpenAEVC until one exists.

Windows, macOS and aarch64 runs of these scenarios are pending; they need a shell, daemon lifecycle and the catalog on those hosts. Scenarios that use adopt-copy or Baseline transfer depend on FG16 (PASS).

