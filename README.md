<!--
  Calve CLI README

  Repo-ready assets expected under ./assets:
-->

<h1 align="center">Calve</h1>

<p align="center">
  <strong>See the whole change. Decide what becomes real.</strong><br/>
  <em>A local-first control layer for capturing, verifying, authorizing, promoting and recovering changes made by humans or machines.</em>
</p>

Calve is a Rust CLI, local daemon and terminal console built on [OpenAEVC](docs/compatibility/openaevc.md). OpenAEVC owns the authoritative change lifecycle: signed commands, executions and provenance, evidence, policy decisions, promotion and Baselines. Calve organizes work around it (Projects, Workspaces, Intents, Tasks, reviews, workers and extensions) and makes the state understandable without reading raw protocol objects. Git is never required.

```text
Intent → Task → ChangePack → capture / agent run → seal → verify & review → promote → Baseline
```

## Build

```sh
cargo build --workspace --locked      # Rust 1.95+; builds calve and calved
```

Calve currently tracks the `main` branch of OpenAEVC over SSH until a release tag exists; see [compatibility](docs/compatibility/openaevc.md).

## A first change

```sh
calve init my-project && cd my-project
calve extension catalog add first-party <url> --root root.json --root-digest <sha256>
calve extension enable org.calve.software --acknowledge-native   # from the signed catalog
calve intent create "Say hello"
calve pack create "Add README" --intent <intent> --require-review
echo hello > README.md
calve pack capture <pack> README.md --generation 1
calve pack seal <pack> --generation <n>
calve pack approve <pack> --generation <n> --reason "Looks right"
calve pack qualify <pack> --generation <n>
calve pack promote <pack> --generation <n>
calve baseline create v1 <promoted-digest> && calve baseline activate v1
calve console
```

The [getting-started guide](docs/guides/getting-started.md) explains each step, and [`examples/`](examples) holds six CI-validated end-to-end scripts: general (non-software) Projects, software with language checks and materialization, parallel Intents, multiple Baselines, revisions, and a local agent.

## What is in the box

| Area | Highlights | Reference |
|---|---|---|
| Projects & Workspaces | Registration, relocation, copy detection, `adopt-copy` through OpenAEVC object exchange | [workspaces](docs/reference/workspaces.md) |
| Work | Intents, Tasks, cross-Intent dependencies, reconciliation with OpenAEVC state | [tasks and packs](docs/reference/tasks-and-packs.md) |
| Change workflow | Capture, seal, verify, evaluate, language checks, review, qualify, promote, revisions | [software resources](docs/reference/software-resources.md), [review policy](docs/reference/review-policy.md), [revisions](docs/reference/revisions.md) |
| Workers | Provider profiles, declarative harnesses, supervised local-process and stdio-agent runs, retry | [providers and harnesses](docs/reference/providers-and-harnesses.md), [executions](docs/reference/executions.md) |
| Extensions | Content-addressed cache, signed catalogs with rollback protection, capability grants, widening detection | [extensions](docs/reference/extensions.md) |
| Domains | `general-project`, `software-project`, and Rust, Go, Python, JS/TS, Java, C/C++, Shell and HCL checks | [domains](docs/reference/domains.md) |
| Composition | Independent Baselines, aliases, comparison, safe materialization | [materialization](docs/reference/materialization.md) |
| Operations | Inbox, activity, receipts, authority, doctor, maintenance, GC, recovery, daemon | [inbox](docs/reference/inbox.md), [authority](docs/reference/authority.md), [maintenance and recovery](docs/reference/maintenance-and-recovery.md), [daemon](docs/reference/daemon.md) |
| Console | Responsive three-pane terminal UI, palette, command mode, explain mode, diff and graph views | [console](docs/reference/console.md) |

Every command is listed in the generated [CLI reference](docs/reference/cli.md). Use `--json` for structured output, and `--project <path-or-id>` outside a Project directory.

## Design

[Architecture](docs/architecture/overview.md) describes the crate boundaries (enforced in CI by `cargo run -p xtask -- check-architecture`), the daemon and embedded execution modes, and the on-disk layout. [Vocabulary](docs/concepts/vocabulary.md) defines the terms, and the [ADRs](docs/adr) record the OpenAEVC boundary and product-state ownership.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md) and [SECURITY.md](SECURITY.md). Calve is licensed under Apache-2.0.
