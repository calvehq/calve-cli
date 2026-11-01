# Execution

An execution is one recorded run of a worker against a pack. OpenAEVC owns its identity, admission, lease and final state; Calve launches and supervises the process.

```text
RUNNING ──> SUCCEEDED | FAILED | CANCELLED | LOST
```

A **provider** says how to launch a worker. A **harness** says what one run does: its command, whether it may change files (`change`) or only observe (`check`), and which paths it may touch.

The worker's output becomes observations. In `change` mode, a local process's changed files inside the harness scope become effects with provenance, and a stdio agent proposes its effects explicitly. A change outside the scope fails the execution and nothing is recorded.

Workers renew a lease while they run. If `calved` dies, the lease expires and OpenAEVC reports the execution as `LOST`. A retry creates a successor attempt; the failed record is never rewritten.

In one Project, writes are serialized. Parallel work means parallel packs whose executions take turns, not simultaneous writers. A second concurrent writer gets the retryable `PROJECT_LOCKED`.

More: [executions](../reference/executions.md), [providers and harnesses](../reference/providers-and-harnesses.md).
