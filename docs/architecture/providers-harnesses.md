# Providers and harnesses

The split keeps launching separate from intent. A **provider** is configuration about a program. A **harness** is a declaration about one kind of run. OpenAEVC never sees either as a concept; to it, a run is an execution with provenance.

A run goes through these steps:

1. Calve checks the pack, then resolves the provider, harness and secrets. Secrets are resolved at launch and are never stored.
2. It asks OpenAEVC to admit an execution, which yields an id and a lease.
3. It spawns the worker through the OS supervisor: argument vector with no shell, cleared environment plus an allowlist, own process group or Job Object, resource limits, and Landlock on Linux.
4. While the worker runs, the supervisor renews the lease, and redacted output becomes observations.
5. In `change` mode, Calve compares the tree inside the harness scope and submits snapshot effects for a local process, and submits a stdio agent's proposals. Anything outside the scope fails the run with nothing recorded.
6. Calve reports the final state to OpenAEVC.

A limit the platform cannot enforce is refused (`CONTAINMENT_UNAVAILABLE`), never silently dropped.

Two adapters exist: `local-process` (exit status decides) and `stdio-agent` (a JSON-lines contract). The built-in `capture` harness runs captures as executions too, so captures carry the same provenance.

Calve starts no model and calls no AI service. An agent is a program a provider launches.

More: [providers and harnesses](../reference/providers-and-harnesses.md), [secrets](../security/secrets.md), [ADR 0017](../adr/0017-process-containment.md).
