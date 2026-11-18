# Install

Calve ships two binaries, `clv` (the command-line interface) and `calved` (the daemon), and no extensions. Extensions come from a signed catalog.

> Releases: <https://github.com/calvehq/calve-cli/releases>. The latest is v0.1.0.

## From a release archive

Each release has an archive per platform: `calve-<version>-<target>`, with its SBOM (`.cdx.json`), `SHA256SUMS`, attestations and a Sigstore bundle. Targets built by the release workflow are `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin` and `x86_64-pc-windows-msvc`. On macOS, materialization can create files but refuses to replace or delete them unless you pass `--allow-unsafe-fs`.

1. Download every file of the release into one directory. Verification checks them all, and needs the `.intoto.json` attestations.
2. [Verify them](verify-a-release.md). Do this before you run anything.
3. Unpack, and put `clv` and `calved` in the same directory on your `PATH`. On Windows the client checks that the daemon is the `calved.exe` beside it, so keep them together.

   **Windows PowerShell:** PowerShell (5.1 and 7) has a built-in alias `clv` for `Clear-Variable`, which takes precedence over `clv.exe`. Type `clv.exe`, or free the name for every session by adding this line to your PowerShell profile (`notepad $PROFILE`):

   ```powershell
   Remove-Item Alias:clv -Force -ErrorAction SilentlyContinue
   ```

   Command Prompt, Git Bash and WSL are not affected.
4. Run `clv version`, then `clv doctor` inside a Project.

## From source

```sh
cargo build --workspace --locked --release     # Rust 1.95; toolchain pinned in rust-toolchain.toml
export PATH="$PWD/target/release:$PATH"
```

OpenAEVC v0.1.0 comes from its public tag over HTTPS, so no key or token is needed.

## Add a catalog

Get the catalog URL, its root file and the root's SHA-256 from the publisher through a channel you trust. The digest is what anchors your trust, so do not take it from the same place as the catalog.

The first-party catalog (the extensions from [calve-extensions](https://github.com/calvehq/calve-extensions)) is served at `https://calvehq.github.io/calve-extensions/`. Its root SHA-256 is:

```
35eb235e04e8c5417a762193ed137cb83d0ffcd96a2773378298b220e4f96fe7
```

```sh
curl -fsSLO https://calvehq.github.io/calve-extensions/metadata/1.root.json
clv extension catalog add first-party https://calvehq.github.io/calve-extensions/ --root 1.root.json --root-digest 35eb235e04e8c5417a762193ed137cb83d0ffcd96a2773378298b220e4f96fe7
```

Any other catalog works the same way: `clv extension catalog add <name> <https-url-or-dir> --root root.json --root-digest <sha256>`.

Next: [getting started](getting-started.md).
