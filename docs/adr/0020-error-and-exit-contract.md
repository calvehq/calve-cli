# ADR 0020: Error and exit-code contract (§41)

Status: Accepted (M3, 2026-10-15).

## Context
The CLI must have stable, documented exit codes, error codes and a versioned `--json` envelope.

## Decision
- `calve-api` owns `ErrorCode`, the exit table and the `--json` envelope `{"api_version":"1", …}` with per-command JSON Schemas in `docs/reference/json/v1/`.
- Within v1 only additive optional fields; a breaking change introduces v2 schemas and `--json-api 1|2`.
- New host codes from CIC (`ABI_VIOLATION`, `INCOMPATIBLE_CIC`, `TRAPPED`, `OUT_OF_FUEL`, `DEADLINE_EXCEEDED`, `OUT_OF_MEMORY`, `RELATION_FAILED`, `RELATION_REFUSED`) and catalog/materialization codes are added to the table.

## Consequences
Approved contract corrections are listed in the CHANGELOG (exit codes, envelope, error codes, `--yes`/`--force`).

## Tests / evidence
M3: schema snapshot tests fail on any non-additive change; exit-code tests per command.

## Residuals
None.

## M3 implementation (2026-10-15)
- `calve_api::errors::CODES` holds every code with its exit status (§41's 25 first); `split_code` reads the `CODE: message` convention product errors use; `openaevc_code` maps OpenAEVC codes, whose structured error stays in `detail.openaevc`.
- The CLI exits with the code's status (clap usage errors 2), prints `calve: CODE: message` plus the OpenAEVC cause, and under `--json` writes the error envelope to stderr.
- `--json` is declared per command by its schema (`calve_api::json`); output is `{"api_version":"1","command","data"}`. Schemas are recorded from the end-to-end suites and enforced by `cargo xtask json-schemas` (additive-only).
- Human output: tables for lists (per-command column preferences), aligned records with nested values indented, never raw JSON; terminal control and bidi characters escaped.
- Destructive commands (`pack abandon`, `maintenance gc` without `--dry-run`, `workspace delete`, `project unregister`, `extension uninstall`, `extension catalog remove`, `authority revoke`, `authority identity-remove`, `provider remove`, `inbox clear-resolved`) refuse without `--yes` (`CONFIRMATION_REQUIRED`); on a terminal the CLI asks and resends acknowledged, a refusal is `USER_CANCELLED` (130). `workspace delete` of a Workspace that still lists Projects also needs `--force`. The console's confirmation dialog is the acknowledgment.

