# Acceptance scenarios (§57 A–P)

Status: map created at M0; test ids are assigned when each scenario is implemented. `xtask acceptance --scenario <A..P> [--report out.json]` (M7) runs a scenario from a clean checkout and records an environment fingerprint (OS, toolchain, lock hashes, OpenAEVC rev, contract rev, `CALVE_BIN` digest).

| Scenario | Repository | Test ids (current) | Status (2026-10-15) | Missing steps / owner |
|---|---|---|---|---|
| A — Fresh installation and generic Project | calve-cli + calve-extensions e2e | `examples::general_project`, `workflow::project_pack_baseline_survives_restart`; with real extensions via calve-extensions `scripts/bump-contract.sh` | Partial | 9 verify/evaluate, 13 receipt/activity, 14 a real daemon restart (only the embedded runtime restarts) — M4/M7 |
| B — Software project without Git | calve-extensions e2e | `examples::software_project` (fixture and first-party catalog) | Partial | 5 `status` shows uncaptured change, 7 diff, 8 tests through a provider/harness (uses `pack check`), 9 review, 11–12 materialize into a clean copied directory (the example restores into the same tree) — M4/M7 |
| C — Pre-promotion reopen | calve-cli | `workflow::stale_generation_cannot_seal_after_reopen`, `workflow::review_policy_gates_promotion_and_old_decisions_do_not_cross_candidates` | Partial | no single test of steps 1–8; 4 stale display, 8 generation-1 history inspectable — M4 |
| D — Independent Baselines | calve-extensions e2e | `examples::multi_baseline` | Partial | B0 then B1 with only the necessary reconciliation — M4 |
| E — Revision | calve-extensions e2e | `examples::revision`, `workflow::revision_targets_promoted_pack_and_composes_in_a_new_baseline` | Partial | 6 compare B0/B1 (materializing each, step 7, is done) — M4 |
| F — Parallel agent work | calve-cli | `examples::parallel_intents`, `workflow::cross_intent_task_dependencies_block_completion_and_reject_cycles` | Partial | 5 dependency-aware UI (console) — M6 |
| G — Capability denial | calve-cli | — (`extensions::catalog_install_grant_update_rollback_and_uninstall` covers grants at activation only) | Missing | the deny → grant → retry → revoke → deny run with `process.execute` — G2 gate |
| H — Extension permission widening | calve-cli | `extensions::catalog_install_grant_update_rollback_and_uninstall` | Exercised, not yet run as a scenario | 7 the grant's binding to the new digest is not asserted — M7 |
| I — Project relocation | calve-cli | `cli::cli_project_rename_and_health_cover_copies_and_moves` | Partial | 2 stop the daemon, 5 NamespaceId unchanged, 6 protocol state valid — M4 |
| J — Copied Project | calve-cli | `adopt::copied_project_is_adopted_with_new_identity`, `registry::copied_identity_is_blocked_until_original_is_relocated` | Partial | 8 active executions not cloned as live; depends on FG16 — M4 |
| K — Crash during execution | calve-cli | `recovery::crash_during_execution_is_reported_lost` | Exercised, not yet run as a scenario | 6 "no duplicate successful execution" not asserted — M4 |
| L — Crash during extension install | calve-cli | `recovery::interrupted_extension_install_is_recoverable`, `install::a_crash_at_every_install_step_converges` | Partial | 3 a previous valid version stays active (no prior version in the e2e) — M4 |
| M — Unsafe Baseline materialization | calve-cli | `materialize::baseline_materialization_protects_uncaptured_work` | Exercised, not yet run as a scenario | 4 the explanation offering capture/reconcile choices is not asserted — M4 |
| N — Third-party OpenAEVC extension without Calve-specific renderer | calve-cli | `extensions::catalog_install_grant_update_rollback_and_uninstall` (`openaevc-only` package) | Partial | 3–4 create/view its resources/evidence through the generic renderer — M6 |
| O — Console reconnect | calve-cli | — | Missing | all — M6 |
| P — Version incompatibility | calve-cli | — (`app::application_envelope_correlates_success_and_version_error` is the API version, not OpenAEVC) | Missing | all — M4 (P15) |

No scenario passes yet: a scenario passes only when one test (or the M7 `xtask acceptance` run) performs every step. Scenarios that use adopt-copy or Baseline transfer depend on FG16 (PASS).

Source (2026-10-15, M2 closeout): the scenario titles and steps are the original product plan's §57 (`tmp/PLAN.md` L4255–4431, untracked); the gaps above re-check the 2026-10-13 core audit against the current tests. An earlier M2 note said the definitions were missing from the repository; they were recovered from that file.
