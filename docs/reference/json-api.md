# JSON API v1

Status: **implemented (M3, ADR 0020).**

`--json` is accepted only by commands that declare it, i.e. the commands with a schema in [`json/v1/`](json/v1/) (`calve_api::json::COMMANDS`); any other command refuses it with exit 2. Human output is the default (§17.1).

- Success, on stdout: `{"api_version":"1","command":"<command>","data":<value>}`. `data` validates against `json/v1/<command with dots>.json`.
- Error, on stderr: `{"api_version":"1","command":"<command>","error":{"code","message","retryable","detail","exit_code"}}`; the exit status is `exit_code` ([exit codes](exit-codes.md)).

Within v1 only additive optional fields appear. `cargo xtask json-schemas` runs the CLI end-to-end suites with `CALVE_JSON_RECORD` set, validates every recorded output against the committed schemas and fails on a non-additive change (a removed required field or a changed type) or on a command without a schema; `--write` adds schemas for new commands and new optional fields. A breaking change ships v2 schemas and `--json-api 1|2`, with the default on the oldest supported version until a documented deprecation.

Inter-process wire types (daemon IPC, unchanged): `Response{api_version: 1, request_id, correlation_id?, outcome}` with `outcome` = `{"status":"ok","value":…}` or `{"status":"error","error":{…}}`. `CALVE_CORRELATION_ID` sets the request's correlation id; a confirmed resend of a destructive command is correlated with the first request.

Commands without a JSON mode: `console`, `daemon serve`, `daemon restart`, `daemon logs` (interactive, lifecycle or plain-text output). Commands whose JSON mode waits for an end-to-end test to record its schema (refused until then; tracked for M7 P28/P30): `execution cancel`, `task link-execution`, `extension catalog reset`, `extension switch-publisher`.

Schemas are inferred from the recorded outputs, so they are as precise as the tests: a field that every recorded output carried is `required`.
