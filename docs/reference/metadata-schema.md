# Integration metadata schema

`calve-integration.json` is the signed file a cic-capable package uses to declare itself to Calve. Schema: `calve.integration/1`. Types: `calve_integration_contract::metadata`. A package without this file is openaevc-only: Calve then reads its effect kinds from the signed OpenAEVC manifest, and each effect kind is usable with `calve resource set <effect-kind>:<name>=JSON`.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schema` | string | yes | `calve.integration/1`; an unknown major is refused |
| `extension_id` | string | yes | Must equal the package id and the native manifest's id |
| `version` | string | yes | Must equal the package version |
| `display_name` | string | yes | Shown to users |
| `abi` | integer | yes | Wasm ABI, `1` |
| `cic` | array | yes | Supported ranges: `{major, min_minor, max_minor}` |
| `capabilities` | object | yes | `required` and `optional`: `op.vN` strings, equal to what `hello/0` advertises |
| `ops` | array | no | Operations the module implements |
| `files` | object | no | The Project's file domain |
| `resources` | array | no | Non-file kinds for `calve resource set` |
| `checks` | object | no | `{verifier}`, judging Calve's check evidence |
| `relations` | array | no | Derived relation kinds and their payload schemas |
| `optional_relations` | boolean | no | Whether a failed `relate` drops relations or fails the capture |

Unknown optional keys inside a known schema are kept and ignored.

**`files`:** `resource_kind`; `put` and `delete` effect kinds; optional `put_chunked`; `history`, kinds valid only in recorded history; `write_action`; optional `verifier` and `evaluator`; `ignore_files`, plain file names whose text is passed to `classify`.

**`resources[]`:** `short`, the name users type; `kind`; `set` and `remove` effect kinds; `write_action`.

**Rules:** every kind must start with the extension id. `files` needs `capture.v1` and `classify.v1`; `checks` needs `detect.v1` and `check_plan.v1`. Harness and provider ids derive from the id: `<id>.capture`, `.materialize`, `.edit`, `.local`.

The authoritative validator is `metadata::validate` in the contract crate, shared with `cargo xtask check-architecture` in calve-extensions. The wire contract is in the [integration contract](integration-contract.md).
