# Changelog

All notable changes to Calve are documented here. Observable behaviour changes are limited to the
approved contract corrections (rev 10 §1); each is listed with its reason.

## Unreleased

### Changed (approved contract corrections)

- **Bundled extensions removed.** Calve ships only `calve` and `calved`. Extensions come from signed
  catalogs (`calve extension catalog add …`, `calve extension install …`); the first-party ones live
  in calve-extensions.
- **Catalogs are TUF repositories.** `extension catalog-trust`/`catalog-untrust`/`catalogs` are
  replaced by `extension catalog add|list|refresh|reset|remove`; the root is pinned by SHA-256 and
  verified with delegations, rollback and freeze protection (sigstore-tuf behind Calve's
  `TrustClient`). `extension enable` takes an extension id (no local artifact paths).
- **Native extensions need an explicit acknowledgment.** `--acknowledge-native` on install and per
  Project on enable/update records that the extension runs with the user's permissions and is not
  confined.
- **The Calve Integration Contract (CIC) is introduced.** Ignore decisions, capture decisions,
  diffs, language detection and check plans come from the enabled packages' CIC modules, run in a
  supervised wasm sandbox (`calve __cic-sandbox`). A rename is captured as a delete plus an add with
  a derived relation recorded as an observation (no rename effects are emitted; recorded ones are
  still read).
- **Capture refuses over-limit files** with `FILE_TOO_LARGE` (inline content limit 1 MiB until
  chunked content).
- `ignore list` shows Calve's hard rule and the lines of the package's ignore file; the package's
  built-in defaults are reported by `ignore check`.
- The built-in capture harness is listed as `capture`.
