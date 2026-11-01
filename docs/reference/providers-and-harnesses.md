# Providers and harnesses

A **provider profile** says how to launch a worker. A **harness** says what one run does: its command, whether it may change files, and which paths it may touch. OpenAEVC owns the execution record, lease and provenance; Calve launches and supervises the process.

## Provider profiles

```sh
calve provider add shell --kind local-process --executable sh
calve provider add agent --kind stdio-agent --executable /opt/my-agent \
  --secret API_TOKEN=env:MY_AGENT_TOKEN --env LANG --timeout-ms 600000
calve provider edit agent --allow-project <project-id>
calve provider test agent          # executable, secrets and references, without running
calve provider disable agent
```

Profiles live in configuration (`[providers.<id>]`, global scope by default; `--scope workspace|project` on `add`). Fields: `kind`, `executable`, `args`, `env` (variables inherited from Calve's environment, everything else is cleared), `secrets` (child variable → `env:NAME` reference, resolved at launch and never stored), `default_harness`, `timeout_ms`, `max_output_bytes`, `projects` (allowed Project IDs; empty allows all), and `limits`.

`[providers.<id>.limits]` (or `provider add|edit --memory-limit-bytes N --cpu-limit-seconds N --process-limit N`) are enforced by the operating system for every worker the provider runs:

| Limit | Unix | Windows |
|---|---|---|
| `memory_bytes` (≥ 16 MiB) | `RLIMIT_AS` (address space), hard and soft | Job Object memory limit |
| `cpu_seconds` | `RLIMIT_CPU`; past it the kernel stops the worker | refused (`CONTAINMENT_UNAVAILABLE`) |
| `processes` | refused: `RLIMIT_NPROC` counts every process of the user | Job Object active-process limit |

A limit the platform cannot enforce is refused when the provider is configured or launched, never ignored. On Unix the limits are applied by `calve __exec-limited`, which sets them on itself and then `exec`s the worker under the same supervision and Landlock rules; a worker that cannot start within its limits fails instead of running unlimited.

Two adapters ship:

- **local-process** runs the executable; exit status 0 means success.
- **stdio-agent** speaks a JSON-lines contract. Calve writes one context frame, `{"type":"context","version":1,"project_id",...,"pack","generation","execution","harness","mode","paths","task","intent","active_baseline"}`; the agent writes `{"type":"log","text":...}`, `{"type":"propose","path":...,"content_base64":...}` and finally `{"type":"done","status":"succeeded"|"failed","reason":...}`. Any other line fails the execution.

## Harnesses

Harnesses are declared in configuration and validated on load:

```toml
format_version = 1
[harnesses.fmt]
provider = "shell"
mode = "change"          # or "check": observations only, no effects
paths = ["src"]          # Project-relative scope; empty means the whole Project
command = ["-c", "cargo fmt"]
timeout_ms = 600000
```

`calve harness list|show|test` inspect them; the `capture` harness is built in (its protocol ids derive from the enabled file package). Run one with `calve execution start <pack> --harness fmt --generation <n> [--task <id>]`.

## What a run guarantees

- The argument vector is passed without a shell; the executable path is resolved before launch.
- The environment is cleared except for the allowlist, resolved secrets and `CALVE_PROJECT_ROOT`, `CALVE_PACK`, `CALVE_GENERATION`, `CALVE_EXECUTION`, `CALVE_HARNESS` and `CALVE_TASK`.
- Output is captured up to `max_output_bytes` and recorded as `org.calve.harness.log` observations.
- The worker runs in its own process group; timeout and cancellation kill the whole group.
- The lease is renewed while the worker runs.
- In `change` mode, a `local-process` worker's files changed inside `paths` become snapshot effects. A stdio agent's effects come only from its `propose` frames. Any change outside the scope, or any change in `check` mode, fails the execution and nothing is recorded.
- A pack takes one effect-producing execution, because OpenAEVC promotes only effects whose provenance matches the current generation.
