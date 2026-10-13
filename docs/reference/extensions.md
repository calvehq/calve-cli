# Extensions and catalogs

OpenAEVC defines the extension contract, handshake and runtime authorization. Calve manages where extension artifacts come from, which versions a Project uses, and which host capabilities they are granted.

## Package cache

Installed artifacts live in a content-addressed cache in the Calve data directory (`extensions/<sha256>/`), with a `package.json` recording id, version, digest, manifest and source. Installation stages into a temporary directory and renames it into place, so an interrupted install never leaves a half-installed package (leftovers older than ten minutes are listed by `calve recover plan`). Projects reference packages by digest, and OpenAEVC loads them from the cache.

## Sources

- **bundled**: extensions shipped beside the `calve` executable (`calve_ext_*`), trusted as part of the installation.
- **signed catalogs**: a directory holding `catalog.json`, trusted explicitly:

```sh
calve extension catalog-trust example /path/to/catalog --key ed25519:... [--key ...] [--threshold 2]
calve extension catalogs
calve extension catalog-untrust example
```

`catalog.json` is `{"signed": {...}, "signatures": [...]}`. `signed` holds `name`, `version`, `expires` (Unix seconds) and `packages` (`id`, `version`, relative `artifact` path, `digest`, `summary`). Signatures are Ed25519 over `calve.catalog.v1\n` followed by the sorted-key JSON of `signed`. Calve requires `threshold` valid signatures from pinned keys, refuses expired metadata, and refuses a version older than the last one it accepted (rollback protection). Artifact bytes must match the listed digest, and the handshake must report the same id and version. Publishers use `cargo run -p xtask -- catalog-keygen <seed-file>` and `catalog-sign <dir> <seed-file>...`.

## Commands

| Command | Scope | Effect |
|---|---|---|
| `extension search [query]` | machine | Packages in bundled and trusted catalogs |
| `extension install <id> [--version v]` | machine | Verify and cache a package |
| `extension list --installed` | machine | Cached packages and the Projects using them |
| `extension uninstall <id> [--version v]` | machine | Refused while any Project has it enabled; metadata is kept so history stays explainable |
| `extension enable [<id or path>] [--grant cap]` | Project | Install if needed and register with OpenAEVC |
| `extension list` / `info <id>` / `health` | Project | Registered extensions, manifests, health |
| `extension permissions <id>` | Project | Requested versus granted host capabilities |
| `extension grant <id> <cap>...` / `revoke` | Project | Change granted capabilities (only requested ones can be granted) |
| `extension update <id> [--grant cap]` | Project | Install the newest version; switch only if no capability widens beyond current grants |
| `extension disable <id>` | Project | Unregister from this Project |

Enabling grants nothing by default. Grants are recorded per extension id, version and artifact digest. When an update requests a capability the current version did not, the update installs the new package but keeps the Project on the old one, and reports `permission_widening` until you rerun with `--grant` for each new capability.
