# Process model

| Process | Role |
|---|---|
| `calve` | The CLI and terminal console. Serves requests in-process, or sends them to a daemon. |
| `calved` | The optional local daemon. Holds one open runtime per Project and supervises workers. |
| `calve __cic-sandbox` | A short-lived supervised child running one extension's wasm module. |
| `calve __exec-limited` | A Unix trampoline that applies resource limits to itself and then `exec`s the worker. |
| Workers and checks | Launched and supervised by Calve. |
| Native extensions | Spawned directly by OpenAEVC, and not confined by Calve (T2). |

**One code path.** Every request is a typed `Request` run by `calve_app::app::execute`, either in the CLI process (embedded) or in `calved`. Both take the same Project writer lock, so choosing a mode changes where code runs, never what it does.

The CLI uses a running daemon when there is one. `execution start`, `execution retry` and the console start it automatically, because a supervised worker must outlive the CLI. `--direct` and `--no-daemon-start` opt out.

**Writers and readers.** Commands hold the Project writer lock for short sections. A run holds it only to admit itself and to record its result. While the worker runs, a durable claim names its pack, mode and paths, and commands proceed unless they collide with that claim (`PROJECT_LOCKED`, retryable). OpenAEVC remains the authority on packs and generations; claims only keep Calve's working-tree steps apart. A claim whose execution has ended is dropped on sight, and the daemon ticks the runtime so a dead run's lease expires. Reads are not blocked by a long execution in the daemon.

**Crash behaviour.** Every multi-step Calve operation (capture, materialization, supersede, install) has a journal that records intent before mutating and completion after. A crash leaves a state that `recover plan` can name; see the [recovery guide](../guides/recovery.md). A worker is in its own process group on Unix and a Job Object on Windows, so cancellation and timeouts reach all of it, with the limits listed in the [threat model](../security/threat-model.md).

Transport details are in [IPC](../reference/ipc.md) and the [daemon reference](../reference/daemon.md).
