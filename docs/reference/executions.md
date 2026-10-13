# Executions

OpenAEVC owns execution identity, admission, leases and state. Calve starts executions for configured harnesses, supervises the worker process, and presents the result.

```text
calve execution start <pack-id> --harness <harness> --generation <n> [--task <task-id>]
calve execution list [--pack <pack-id>] [--state running]
calve execution show <execution-id>
calve execution logs <execution-id>
calve execution wait <execution-id> --timeout-ms 30000
calve execution cancel <execution-id> --reason "No longer needed"
calve execution retry <execution-id>
```

`start` runs a harness (see [providers and harnesses](providers-and-harnesses.md)) as an OpenAEVC execution on an OPEN pack. The worker's output becomes observations, and in `change` mode the files it changes inside the harness scope become snapshot effects with provenance. Changes outside the scope fail the execution and are not recorded. Supervised commands (`start`, `retry`) run under `calved` so the worker survives the CLI exiting; Calve starts the daemon automatically unless `--no-daemon-start` is given, and otherwise runs in-process.

`logs` returns the journal events for an execution. `view`-level detail, including resolved output lines, observations and produced effects, is shown on the console's Execution screen.

`cancel` sends OpenAEVC's cancellation command; the running worker notices within half a second and its process group is terminated. `retry` asks OpenAEVC for the successor attempt of a `FAILED`, `LOST` or `CANCELLED` execution on the same work unit; the failed record is never rewritten, and the retry budget is OpenAEVC's (`max_attempts`, 3 for Calve harnesses and captures).

`wait` polls until `SUCCEEDED`, `FAILED`, `CANCELLED` or `LOST` and returns that record; the timeout must be between 1 ms and 24 hours.

Workers renew their lease while they run. The lease defaults to two minutes, so if `calved` crashes, OpenAEVC reports the interrupted execution as `LOST` shortly after restart and it appears in the Inbox. `CALVE_EXECUTION_LEASE_MS` (5 s to 1 h) tunes the lease for tests or unusual hosts.
