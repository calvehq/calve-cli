# Acceptance scenarios (§57 A–P)

Status: map created at M0; test ids are assigned when each scenario is implemented. `xtask acceptance --scenario <A..P> [--report out.json]` (M7) runs a scenario from a clean checkout and records an environment fingerprint (OS, toolchain, lock hashes, OpenAEVC rev, contract rev, `CALVE_BIN` digest).

| Scenario | Repository | Test id | Status |
|---|---|---|---|
| A | calve-cli (fixtures) + calve-extensions e2e (real extensions) | candidate evidence (M2): `apps/calve/tests/examples.rs` (6 scripts) against the fixture catalog, and with `--include-ignored` + `CALVE_CATALOG_ADD` against a published first-party catalog (run by calve-extensions `scripts/bump-contract.sh`) | open: scenario text needed to map |
| B | calve-extensions e2e | — | open |
| C | calve-cli | — | open |
| D | calve-extensions e2e | — | open |
| E | calve-extensions e2e | — | open |
| F–P | calve-cli | — | open |

Scenarios that use adopt-copy or Baseline transfer depend on FG16 (PASS).

M2 note (2026-10-15): the §57 scenario definitions are not in the repository (as with the C1–C44 console titles), so no scenario is marked passing. The M2 cross-repo e2e that exists — six example workflows (software checks + materialization, general resources + review, parallel intents, multiple Baselines, revisions, a local agent) against a catalog published by calve-extensions' xtask and verified by Calve's production TUF client — is recorded above as candidate evidence; B, D and E stay open until the scenario text is restored.
