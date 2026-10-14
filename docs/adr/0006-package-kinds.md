# ADR 0006: Package kinds and metadata identity

Status: Accepted (M0: FG14 PASS).

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
