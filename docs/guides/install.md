# Install

Calve ships two binaries, `calve` and `calved`, and no extensions. Extensions come from a signed catalog.

> No version has been released yet. Until one is, [build from source](#from-source).

## From a release archive

Each release has an archive per platform: `calve-<version>-<target>`, with its SBOM (`.cdx.json`), `SHA256SUMS`, attestations and a Sigstore bundle. Targets built by the release workflow are `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin` and `x86_64-pc-windows-msvc`.

1. Download the archive for your platform with `SHA256SUMS` and `SHA256SUMS.sigstore.json`.
2. [Verify them](verify-a-release.md). Do this before you run anything.
3. Unpack, and put `calve` and `calved` in the same directory on your `PATH`. On Windows the client checks that the daemon is the `calved.exe` beside it, so keep them together.
4. Run `calve version` and `calve doctor`.

## From source

```sh
cargo build --workspace --locked --release     # Rust 1.95; toolchain pinned in rust-toolchain.toml
export PATH="$PWD/target/release:$PATH"
```

OpenAEVC v0.1.0 comes from its public tag over HTTPS, so no key or token is needed.

## Add a catalog

Get the catalog URL, its root file and the root's SHA-256 from the publisher through a channel you trust. The digest is what anchors your trust, so do not take it from the same place as the catalog.

```sh
calve extension catalog add first-party <https-url-or-dir> --root root.json --root-digest <sha256>
```

Next: [getting started](getting-started.md).
