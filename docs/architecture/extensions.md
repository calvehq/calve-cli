# Extensions

Calve's host contains no domain knowledge. Everything it knows about files, languages and resources comes from packages enabled in a Project.

A package has up to three parts, signed together in a TUF catalog:

| Part | Runs | Confinement | Purpose |
|---|---|---|---|
| `calve-integration.json` | not code | n/a | Declares kinds: `files`, `resources`, `checks`, `relations` |
| `cic.wasm` | in Calve's sandbox | T1: no imports, memory and fuel caps, supervised child | Planning: detection, check plans, ignore decisions, capture, diffs |
| Native artifact | spawned by OpenAEVC | T2: **none** | Validates and applies effects, judges candidates |

Two kinds exist. **cic-capable** packages ship all three. **openaevc-only** packages ship the native artifact, optionally with `calve-ui.json`.

**The contract boundary.** `calve-integration-contract` is the only crate extensions share with Calve. calve-extensions pins it by commit and tests against it in its own repository; it never depends on Calve's daemon or application crates.

**Getting from a catalog to running code** passes three separate gates: trust, compatibility and permission. See [extensions](../reference/extensions.md).

**Check plans** are the sharp edge. A wasm module proposes a command, and that command then runs with your permissions. So a plan runs only after you approve a digest covering the plan, the package and the resolved executable, and that digest is re-checked before each spawn.

More: [trust tiers](../security/trust-tiers.md), [the contract](../reference/integration-contract.md), [catalog trust](../reference/catalog-trust.md), and the [authoring guide](https://github.com/calvehq/calve-extensions/blob/main/docs/authoring.md).
