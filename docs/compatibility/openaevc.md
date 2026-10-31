# OpenAEVC compatibility

Calve 0.1.0 is built against the **OpenAEVC `v0.1.0` release** (ADR 0003):

| | |
|---|---|
| Source | `https://github.com/calvehq/openaevc.git` (public HTTPS; no SSH key needed) |
| Tag | `v0.1.0` (tag object `d4bee88b`) |
| Commit | `5720d3ec15bee6c49630b2cec5a21afd357dedf8` |
| Packages | `openaevc` (feature-gated modules) and `openaevc-sdk` (git-only, `publish = false`), both from the same tag |

Both packages are declared with `default-features = false`. Only `calve-app` enables `openaevc/runtime` (the SDK adds `transport`); every other crate compiles the protocol, crypto, core and extension-contract modules only. Mixing a crates.io `openaevc` with the git SDK would produce two incompatible packages and is rejected by `xtask check-architecture`, which also asserts that `Cargo.lock` resolves both packages to exactly the tag and commit above and that this matches the compiled-in `OPENAEVC_TAG`/`OPENAEVC_REVISION`.

`calve version` shows the build pin (`openaevc_tag`, `openaevc_revision`, `openaevc_crate_version`, protocol). `calve doctor` shows the pin and the protocol and extension-contract versions negotiated with the running OpenAEVC runtime; Calve stops before Project mutations if either range has no overlap. Calve uses the SDK's signed request envelopes and the runtime admission path and never reads or writes OpenAEVC tables.

OpenAEVC `v0.1.0` is never modified from Calve. Anything it cannot express is a Calve-owned, versioned contract (the Calve Integration Contract, ADR 0004) or an OpenAEVC proposal under `docs/proposals/`.

## Known limits of v0.1.0

Calve works within these and does not hide them.

| Limit | Effect in Calve |
|---|---|
| A pack's effects survive a reopen, and only effects of the current generation can be promoted | A reopened pack with effects cannot be promoted; `supersede start` continues the work in a new pack (Scenario C). |
| Any execution advances the pack's generation | Calve refuses to start an execution on a pack with effects. Run harnesses in a separate pack, or use `pack check` on the sealed candidate. |
| No query from a request id to its receipt | The receipt projection lists receipt digests when a receipt is missing. It costs seconds on the first build at 10,000 packs. |
| No plan or dry run for `collect_garbage` | `maintenance gc --dry-run` counts with one read-only query on the runtime's database (`crates/calve-app/src/gc.rs`). It is the only direct access to `.calve/openaevc/`, named in `check-architecture`; deletion always goes through OpenAEVC. |
| `network.connect` is not a supported host capability | Extensions cannot be granted network access through the host. |
| Objects imported by adopt-copy are inert history | They verify, and appear in no Baseline list. |
| Writes to one Project are serialized | A concurrent writer gets the retryable `PROJECT_LOCKED`. |

Previous pin: `main` at `288b804fc2b7d178de9dd2de20d13e615aed02c8` over SSH (the M1 rollback point).
