# Configure providers

A provider profile says how to launch a worker. Profiles are configuration, global by default, and `--scope workspace|project` narrows one.

```sh
calve provider add shell --kind local-process --executable sh --env PATH --env HOME
calve provider add agent --kind stdio-agent --executable /opt/my-agent \
  --secret API_TOKEN=env:MY_AGENT_TOKEN --env PATH --env HOME
calve provider edit agent --allow-project <project-id>
calve provider test agent
```

`provider test` checks the executable, secrets and references without running anything.

**Environment.** Workers get an empty environment plus what you list, so `PATH` is unset unless you pass it. `--env` passes a variable through. With a daemon, `--env` and `env:` secrets read the daemon's environment, so export them before it starts. Calve adds `CALVE_PROJECT_ROOT`, `CALVE_PACK`, `CALVE_GENERATION`, `CALVE_EXECUTION`, `CALVE_HARNESS` and `CALVE_TASK`.

**Secrets.** A secret is a reference, `env:NAME` or `keyring:NAME`. It is resolved at launch, passed only in the worker's environment, and redacted from output as well as Calve can. Redaction is a safety net with known gaps, so only give a secret to a worker you trust. See [secrets](../security/secrets.md).

**Limits.** The operating system enforces these:

```sh
calve provider edit agent --memory-limit-bytes 2147483648 --cpu-limit-seconds 600
```

A limit the platform cannot enforce is refused, never ignored. `--process-limit` works on Windows only, and `--cpu-limit-seconds` on Unix only.

**Harnesses** bind a provider to a job:

```toml
format_version = 1
[harnesses.fmt]
provider = "shell"
mode = "change"          # or "check": observations only
paths = ["src"]          # empty means the whole Project
command = ["-c", "cargo fmt"]
timeout_ms = 600000
```

Harnesses in a Project's `config.toml` count only after `calve config approve`. Inspect them with `calve harness list|show|test`.

Reference: [providers and harnesses](../reference/providers-and-harnesses.md).
