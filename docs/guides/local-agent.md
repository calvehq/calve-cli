# Run a local agent

A worker is any program. Calve starts no model itself; you tell it how to launch yours and what a run may touch. The [`local-agent`](../../examples/local-agent) example is the tested version.

A worker that changes files needs a Project with a file domain:

```sh
clv init agents && cd agents
clv extension enable org.calve.software --acknowledge-native
```

Then set up the [provider and harness](provider-configuration.md). Use an absolute path for the executable, because `calved` has its own working directory:

```sh
clv provider add agent --kind stdio-agent --executable /opt/my-agent \
  --secret API_TOKEN=env:MY_AGENT_TOKEN --timeout-ms 600000
clv provider test agent
```

```toml
# .calve/config.toml
format_version = 1
[harnesses.changelog]
provider = "agent"
mode = "change"
paths = ["CHANGELOG.md"]
```

```sh
clv config approve        # harnesses in a Project file count only once approved
```

Run it on an open pack with no effects:

```sh
clv pack create "Agent changelog"
clv execution start <pack> --harness changelog --generation 1
clv execution list --pack <pack>
clv execution logs <execution>
clv execution wait <execution> --timeout-ms 600000
```

The worker's output is recorded as it arrives, with secrets redacted, so `execution logs` shows it during the run. A stdio agent's effects come only from its `propose` frames; files it writes itself are not recorded. For a `local-process` worker, files changed inside `paths` become effects. A change outside `paths` fails the run and records nothing.

Review what it did as you would any other change: `clv pack diff <pack>`, then seal and promote. Nothing an agent produces is accepted until it passes the same gates as a human's change.

If a run fails or is lost, `clv execution retry <execution>` creates a successor attempt on the same work unit. `clv execution cancel <execution> --reason <why>` stops a running worker.

Running workers concurrently means separate packs with separate paths, under `calved`. They overlap, and a real collision gets a retryable `PROJECT_LOCKED`. The [`parallel-intents`](../../examples/parallel-intents) example shows two.
