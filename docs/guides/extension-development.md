# Develop an extension

Extensions live outside this repository. Calve has no built-in domain, so a third-party extension uses exactly the path first-party ones use.

| Task | Where |
|---|---|
| Write a package (metadata, wasm module, native artifact) | [authoring guide](https://github.com/calvehq/calve-extensions/blob/main/docs/authoring.md) |
| Sign and publish a catalog | [publishing guide](https://github.com/calvehq/calve-extensions/blob/main/docs/publishing.md) |
| The contract itself | [Calve Integration Contract](../reference/integration-contract.md) |
| Run a local catalog | [catalog operations](catalog-operations.md) |

Start with the smallest thing that works. An **openaevc-only** package is a native OpenAEVC extension and nothing else. Its signed manifest is enough: each effect kind it declares works with `calve resource set <effect-kind>:<name>=JSON`, and its evidence reads generically, with no Calve code.

Add [`calve-integration.json`](../reference/metadata-schema.md) and a CIC module when you want short names, files, checks or diffs.

Before you publish, know what you are asking users for:

- A native artifact is T2: it runs **unconfined**, with the user's permissions. Users must pass `--acknowledge-native`.
- Host capabilities are denied until granted. `network.connect` is not supported by OpenAEVC v0.1.0.
- An update that requests a new capability stops at `permission_widening` until the user grants it.
