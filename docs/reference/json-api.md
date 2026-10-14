# JSON API v1

`--json` output is a versioned envelope. Current wire types (`calve-api`): `Response{api_version: 1, request_id, correlation_id?, outcome}` with `outcome` = `{"status":"ok","value":…}` or `{"status":"error","error":{"code","message","retryable","detail?"}}`.

Rules (ADR 0020, implemented in M3): per-command JSON Schemas in `docs/reference/json/v1/`; within v1 only additive optional fields; a breaking change ships v2 schemas and `--json-api 1|2`, with the default staying on the oldest supported version until a documented deprecation; schema snapshot tests fail on any non-additive change.
