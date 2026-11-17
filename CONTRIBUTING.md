# Contributing to Calve

Calve owns product workflows and presentation. OpenAEVC owns protocol authority, execution admission, verification qualification, promotion, immutable objects, and Baseline validity. Changes to those semantics belong upstream; Calve must call the public OpenAEVC API.

Before opening a pull request, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p xtask -- check-architecture
cargo run -p xtask -- cli-reference --check   # regenerate with: cargo run -p xtask -- cli-reference
```

After changing a console read model, regenerate the console fixtures and review the snapshot diffs:

```sh
crates/calve-console/tests/fixtures/generate.sh
CALVE_UPDATE_SNAPSHOTS=1 cargo test -p calve-console
```

OpenAEVC is pinned to its public `v0.1.0` release tag and fetched over HTTPS (`https://github.com/calvehq/openaevc.git`); no SSH access or Cargo git configuration is needed. Both `openaevc` and `openaevc-sdk` come from that tag, and `cargo run -p xtask -- check-architecture` and `check-isolation` verify the pin and feature isolation (see [the compatibility document](docs/compatibility/openaevc.md)). Do not commit a path dependency or OpenAEVC implementation internals into Calve.

Keep user-visible commands documented, include tests for state-changing workflows, and explain any migration or compatibility change. Preserve structured OpenAEVC errors and avoid inventing Calve-side authorization rules. A Project's `.calve/` directory contains local operational state and private keys; never add it to an example fixture or bug report.
