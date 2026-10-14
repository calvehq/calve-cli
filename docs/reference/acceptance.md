# Acceptance scenarios (§57 A–P)

Status: map created at M0; test ids are assigned when each scenario is implemented. `xtask acceptance --scenario <A..P> [--report out.json]` (M7) runs a scenario from a clean checkout and records an environment fingerprint (OS, toolchain, lock hashes, OpenAEVC rev, contract rev, `CALVE_BIN` digest).

| Scenario | Repository | Test id | Status |
|---|---|---|---|
| A | calve-cli (fixtures) + calve-extensions e2e (real extensions) | — | open |
| B | calve-extensions e2e | — | open |
| C | calve-cli | — | open |
| D | calve-extensions e2e | — | open |
| E | calve-extensions e2e | — | open |
| F–P | calve-cli | — | open |

Scenarios that use adopt-copy or Baseline transfer depend on FG16 (PASS).
