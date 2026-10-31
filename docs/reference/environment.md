# Environment variables

## For users

| Variable | Effect |
|---|---|
| `XDG_CONFIG_HOME` | Base of the config directory (`$HOME/.config` if unset) |
| `XDG_DATA_HOME` | Base of the data directory (`$HOME/.local/share` if unset) |
| `XDG_RUNTIME_DIR` | Runtime base used for private files |
| `CALVE_DISCOVERY_CEILING` | Directories where Project discovery stops (absolute paths, `PATH`-style) |
| `CALVE_CORRELATION_ID` | Correlation id for the request, to tie related requests together |
| `CALVE_EXECUTION_LEASE_MS` | Execution lease, 5 s to 1 h; default two minutes |
| `CALVE_REPLAY_WINDOW_MS` | Replay window of signed envelopes |
| `CALVE_KEYRING_COMMAND` | Program run as `<command> <name>` to resolve `keyring:` secrets |
| `SOURCE_DATE_EPOCH` | Timestamp used by `xtask dist` |

## Set by Calve for workers

`CALVE_PROJECT_ROOT`, `CALVE_PACK`, `CALVE_GENERATION`, `CALVE_EXECUTION`, `CALVE_HARNESS`, `CALVE_TASK`. A worker's environment is otherwise empty except for the provider's allowlist and resolved secrets.

## Internal

These exist for the build and tests. They are not a supported interface. `CALVE_HOST_TARGET` is set at build time. `CALVE_JSON_RECORD` records JSON output for schema checks. `CALVE_SANDBOX_PROGRAM` and `CALVE_JOB_PARENT` are used by internal process launch.

Test hooks act only in debug builds, and release builds ignore them: `CALVE_FAULT`, `CALVE_FS_PRIMITIVES`, `CALVE_KEEP_SPAWN_RECORDS`, `CALVE_TEST_*`, and the runtime protocol override `CALVE_TEST_RUNTIME_PROTOCOL`.
