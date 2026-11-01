# Acceptance scenarios

`cargo run -p xtask -- acceptance --scenario <A..P|all> [--report out.json]` runs scenarios from this checkout, one complete test each, and records an environment fingerprint (OS, kernel, toolchain, commit, Cargo.lock hash, OpenAEVC revision, `calve` binary digest). A and B need the first-party catalog in `CALVE_CATALOG_ADD` (arguments of `calve extension catalog add`, one per line); without it they are reported `not-run`, never passed. The report separates `pass` from `pass-with-deviation`: a scenario with a deviation below is not a full pass even when its test is green.

| Scenario | Test | Status | Notes |
|---|---|---|---|
| A — Fresh installation and generic Project | `examples::scenario_a` | Pass (Linux) | Step 9 is OpenAEVC's policy evaluation (general-project declares no verifier or evaluator); step 14 restarts a real daemon. |
| B — Software project without Git | `examples::scenario_b` | Pass (Linux) | First-party software and Rust extensions. Step 8 runs the harness in its own pack over the same working tree (an execution on the candidate would make it unpromotable, and Calve refuses it) and the candidate's checks through `pack check`. Step 11 copies the Project, relocates the registration to the copy, removes its working files and materializes. |
| C — Pre-promotion reopen | `examples::scenario_c` | **Deviation** | Steps 1–4 and 8 hold. Steps 5–7 cannot run on the same pack: OpenAEVC v0.1.0 keeps a pack's effects on reopen and promotes only effects of the current generation, so a pack with effects cannot be promoted after a reopen. The script asserts that refusal, then runs 5–7 on a superseding pack. |
| D — Independent Baselines | `examples::scenario_d` | Pass (Linux) | B0→B1 touches only file2/file3; shared files keep their inodes. |
| E — Revision | `examples::scenario_e` | Pass (Linux) | |
| F — Parallel agent work | `examples::scenario_f` | **Deviation** | The console engine reads a real daemon for step 5. The two executions do not overlap: a run holds the Project writer lock until it ends, so the second meets the retryable `PROJECT_LOCKED` and runs afterwards. |
| G — Capability denial | `acceptance::scenario_g_capability_denial` | Pass (Linux) | A fixture extension's real `process.execute` host call; OpenAEVC denies it and Calve reports `CAPABILITY_DENIED` with the grant command. |
| H — Extension permission widening | `extensions::scenario_h_permission_widening` | Pass (Linux) | |
| I — Project relocation | `examples::scenario_i` | Pass (Linux) | |
| J — Copied Project | `examples::scenario_j` | Pass (Linux) | The active execution is left RUNNING by killing its daemon before the copy. Imported objects are inert history: they verify, and appear in no Baseline list. |
| K — Crash during execution | `examples::scenario_k` | Pass (Linux) | A real daemon killed with SIGKILL. |
| L — Crash during extension install | `extensions::scenario_l_crash_during_extension_install` | Pass (Linux) | The crash is the debug-build fault point after the first durable install record. |
| M — Unsafe Baseline materialization | `examples::scenario_m` | Pass (Linux) | |
| N — Third-party extension | `extensions::scenario_n_third_party_extension` | **Deviation** | An openaevc-only extension enables and its evidence is created and read generically. Creating resource instances needs integration metadata (`resource set` refuses kinds no metadata declares), so step 3 covers evidence only. |
| O — Console reconnect | `examples::scenario_o` | Pass (Linux) | The console engine against a real calved, without a terminal. |
| P — Version incompatibility | `acceptance::scenario_p_version_incompatibility` | **Deviation** | Only one OpenAEVC exists to link, so the unsupported runtime is a debug-only report override; the real check runs on it. Doctor reports the mismatch as a structured error, because every command refuses at open. |

Windows, macOS and aarch64 runs of these scenarios are pending; they need a shell, daemon lifecycle and the catalog on those hosts. Scenarios that use adopt-copy or Baseline transfer depend on FG16 (PASS).

