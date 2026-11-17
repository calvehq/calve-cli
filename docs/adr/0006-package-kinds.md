# ADR 0006: Package kinds and metadata identity

Status: Accepted (M0: FG14 PASS; M2 production PASS locally).

## Context
Not every extension needs Calve planning operations; some are plain OpenAEVC extensions with optional UI metadata.

## Decision
- `openaevc-only` packages: native artifact (+ optional `calve-ui.json`, presentation only).
- `cic-capable` packages: native artifact + `cic.wasm` + **required** `calve-integration.json` (schema `calve.integration/1`: extension_id, version, abi, cic ranges, capabilities{required, optional}, display_name, detect.markers, ops, relations[{kind, required, schema}], optional_relations policy). Unknown keys within the schema major are preserved and ignored.
- Every file is a TUF target; its target hash is its identity, recorded in `PackageRecord`. `describe` must equal the signed metadata by canonical value.
- Three independent gates: trust (TUF), compatibility (protocol/contract, CIC range, platform, schema major), permission (grants + T2 acknowledgment).
- Install path `<extension_dir>/<id>/<artifact-sha256>/` inside the runtime's `extension_dirs`, then `RegisterExtension{entrypoint: "<id>/<sha>/<bin>", artifact_digest}` (FG14 proved nested entrypoints and the registry query).

## Consequences
- **Upgrade guard (F21, confirmed by FG14):** OpenAEVC resolves the extension at each effect submission, so a re-registration changes behaviour for in-flight work. Upgrading X is refused (`EXTENSION_IN_USE`) while dependent executions or Calve sessions are active or resumable. No per-execution pinning is claimed.
- Relation kinds must be prefixed with the extension id; a required relation kind implies required capability `relate.v1` (checked at install by `Metadata::validate`).

## Tests / evidence
FG14; contract tests `metadata_rules_and_forward_compat`; M2 install-journal crash tests.

## Residuals
Same-user modification of an installed directory is detected by OpenAEVC's per-spawn re-hash, not prevented (trusted boundary).

## M2 production implementation (2026-10-15)
- Schema 1 gained optional `files`, `resources` and `checks` declarations (validated by `Metadata::validate`: kinds prefixed by the extension id, required capabilities, plain ignore-file names). The host derives every domain kind from them (INV-022; `xtask` refuses first-party domain literals in calve-cli).
- Installer: I0–I4 journal, read-only `<id>/<native-sha>/`, `recover()`, `retire()`, pins and id-policy keyed by the percent-encoded delegation chain, upgrade guard `EXTENSION_IN_USE`.

## M2 closeout (2026-10-15): native artifact identity
- Native builds are keyed by the **exact Rust target triple** (`calve_integration_contract::catalog::HOST_TARGET`, e.g. `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-gnu` are different builds) with the executable's sha256, at `<id>/<version>/<triple>/<file>`. Two platforms never share a target path, even with equal file names (previously one file name per version, so Linux and macOS builds would have collided).
- The installer selects only its own triple and requires three digests to be equal: the TUF target hash, the `package.json` native digest and the handshake's `artifact_digest`. The record stores `target`; a record for another triple is refused at activation (`EXTENSION_INCOMPATIBLE`).
- After `RegisterExtension`, the manifest OpenAEVC recorded (it re-runs the handshake) must equal the installed manifest field for field; otherwise the registration is removed and activation fails with `EXTENSION_IDENTITY_MISMATCH` (a failed removal is reported, never ignored).
- The layout types (`PackageIndex`, `VersionEntry`, `NativeBuild`, `Kind`) live in the contract crate, shared by the installer and calve-extensions' `xtask publish`.
- Tests: `install::native_builds_are_selected_by_exact_target_triple_and_digest`, `install::the_registered_manifest_must_be_exactly_the_installed_one`, contract `catalog` tests.
