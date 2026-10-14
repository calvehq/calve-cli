# ADR 0020: Error and exit-code contract (§41)

Status: Proposed (M3).

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
