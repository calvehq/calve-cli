# Architecture

Calve is a product layer over OpenAEVC. OpenAEVC owns change identity, the signed command path, execution leases and provenance, evidence, policy decisions, promotion and Baselines. Calve owns Projects and Workspaces, Intents and Tasks, reviews, provider profiles, extension catalogs, read models and the terminal experience. Calve changes OpenAEVC state only through its commands, and reads through its APIs. The one exception is a read-only count in `maintenance gc --dry-run` ([ADR 0022](../adr/0022-gc-dry-run-read.md)). See [state ownership](state-ownership.md).

## Crates

```text
apps/calve ──────────┐                 (binaries: calve, calved)
                     ├──> calve-client ──> calve-ipc ──> calve-api
calve-console ───────┘         │
                               └──────────> calve-app ──> calve-api, calve-integration-contract
                                                 │
                                   OpenAEVC SDK, runtime, store
calve-extensions (separate repository) ──> calve-integration-contract, by pinned commit
```

| Crate | Owns |
|---|---|
| `calve-api` | Versioned request/response envelopes and the typed `Action` grammar shared by CLI, daemon and console |
| `calve-app` | Every use case: Projects, the product database and migrations, workspaces, config, work, reviews, providers and the process runner, extension manager, domains, read models, maintenance and recovery |
| `calve-ipc` | Local framing, peer checks, handshake, replay protection; it takes the request handler as a parameter |
| `calve-client` | One client with daemon and embedded backends, daemon lifecycle |
| `calve-console` | Terminal state, rendering, input; reads models through `calve-client` only |
| `calve-integration-contract` | The versioned contract shared with extensions |
| `calve-win-sec` | Windows security FFI, the single crate allowed `unsafe` |
| `calve-testkit` | Shared integration-test helpers |
| `xtask` | Architecture enforcement, CLI reference and JSON schemas, release archives and attestations, acceptance runs |

`cargo run -p xtask -- check-architecture` fails CI on a forbidden dependency edge (for example the console depending on `calve-app`), a terminal crate outside the console, SQL or runtime crates outside `calve-app`, OpenAEVC path dependencies, or direct access to OpenAEVC storage. calve-extensions enforces its own dependency allowlist, which excludes Calve's private crates.

## Processes

Every request is a typed `Request` executed by `calve_app::app::execute`, either in the CLI process (embedded) or in `calved`. Both paths run identical code and take the same Project writer lock. The daemon keeps one runtime per Project so queries proceed during long executions; see [daemon](../reference/daemon.md).

## State

```text
<project>/.calve/
  project.toml        immutable identity (ProjectId, NamespaceId, creator)
  keys.toml           Project keys (mode 0600)
  product.sqlite3     Calve product metadata (versioned migrations)
  openaevc/           OpenAEVC runtime state (never edited by Calve)
  extensions/         artifacts pinned by older Projects
<data dir>/calve/
  workspace.sqlite3   Workspaces and Project registrations
  packages/           content-addressed package cache
  catalogs/<name>/    trusted catalogs, pinned root, rollback floors
  logs/daemon.log
<config dir>/calve/config.toml, workspaces/<id>.toml
```
