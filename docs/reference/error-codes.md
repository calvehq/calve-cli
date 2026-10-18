# Error codes

Status: **implemented (M3, ADR 0020; M4 outcomes 2026-10-17).** Every error is a `Fault{code, message, retryable, detail?}`; the code fixes the exit status ([exit codes](exit-codes.md)). Product messages carry their code as a `CODE: message` prefix inside Calve, split into `code` and `message` at the API.

## §41 taxonomy
`PROJECT_NOT_FOUND`, `PROJECT_IDENTITY_CONFLICT`, `PROJECT_LOCKED`, `WORKSPACE_NOT_FOUND`, `INVALID_CONFIGURATION`, `OPENAEVC_INCOMPATIBLE`, `OPENAEVC_OPERATION_REJECTED`, `CAPABILITY_DENIED`, `STALE_VIEW`, `REVIEW_STALE`, `EXTENSION_NOT_INSTALLED`, `EXTENSION_INCOMPATIBLE`, `EXTENSION_PERMISSION_REQUIRED`, `PROVIDER_UNAVAILABLE`, `HARNESS_UNAVAILABLE`, `SECRET_UNAVAILABLE`, `RESOURCE_DIVERGED`, `UNSAFE_MATERIALIZATION`, `DAEMON_UNAVAILABLE`, `DAEMON_INCOMPATIBLE`, `MIGRATION_REQUIRED`, `RECOVERY_REQUIRED`, `CORRUPT_PRODUCT_STATE`, `UNSUPPORTED_PLATFORM_FEATURE`, `USER_CANCELLED`.

## Further codes
`PRODUCT_ERROR`, `IO_ERROR`, `INTERNAL`, `INVALID_ARGUMENT`, `NOT_FOUND`, `ALREADY_EXISTS`, `CONFIRMATION_REQUIRED`, `UNSUPPORTED_API_VERSION`, `UNSUPPORTED_PAYLOAD_VERSION`, `INVALID_OPERATION_KIND`, `CATALOG_STALE`, `CATALOG_UNTRUSTED`, `CATALOG_POLICY`, `EXTENSION_REVOKED`, `EXTENSION_IN_USE`, `EXTENSION_IDENTITY_MISMATCH`, `PUBLISHER_NOT_AUTHORIZED`, `PACKAGE_INVALID`, `PACKAGE_TAMPERED`, `T2_ACKNOWLEDGMENT_REQUIRED`, `CHECK_PLAN_UNAPPROVED`, `CHECK_PLAN_CHANGED`, `INCOMPATIBLE_CIC`, `ABI_VIOLATION`, `TRAPPED`, `OUT_OF_FUEL`, `DEADLINE_EXCEEDED`, `OUT_OF_MEMORY`, `RELATION_FAILED`, `RELATION_REFUSED`, `RELATION_SCHEMA_INVALID`, `CAPTURE_DIVERGED`, `CAPTURE_REFUSED`, `CAPTURE_INCOMPLETE`, `UNSTABLE_FILE`, `FILE_TOO_LARGE`, `LIMIT_EXCEEDED`, `SUPERSEDE_CONFLICT`, `SUPERSEDE_DIVERGED`, `MATERIALIZE_CONFLICT`, `CONTENT_CORRUPT`, `CONTENT_NOT_PORTABLE`, `CLOSURE_UNCLASSIFIED`, `CONTAINMENT_UNAVAILABLE`.

## M4 outcomes

| Code | Exit | When | `detail` |
|---|---|---|---|
| `CAPTURE_INCOMPLETE` | 9 | seal/promote while a capture session of the pack is unfinished; a session out of attempts | `{session}` |
| `CAPTURE_DIVERGED` | 3 | the pack changed under a capture session (effects it did not produce) | `{session, pack, paths}` |
| `CAPTURE_REFUSED` | 9 | the extension rejected a captured change | `{session, path}` |
| `CONFIRMATION_REQUIRED` | 5 | capture-tree would record deletions without `--accept-deletions`; destructive commands without `--yes` | `{deletions}` |
| `FILE_TOO_LARGE` | 9 | a file over the domain's capture limit (1 MiB inline, 256 MiB chunked) | `{path, limit}` |
| `LIMIT_EXCEEDED` | 9 | more than 10 000 files or 512 MiB in one capture-tree batch | `{limit, scope}` (files) |
| `SUPERSEDE_CONFLICT` | 3 | a pending supersession of the pack; a concurrent product or candidate change (compare-and-swap) | `{saga, state}` or `{pack}` |
| `SUPERSEDE_DIVERGED` | 3 | the replay did not reproduce the kept effects | `{saga, …}` |
| `MATERIALIZE_CONFLICT` | 3 | `unsafe_fs`, `unfinished_operation`, `content_unavailable`, `source_changed`, a WAL step conflict (`changed_before_mutation`, `created_concurrently`, `displaced_changed`, `post_mutation_identity`, `evidence_missing`, `unexpected_*`), `rollback` | `{reason, op?, step?, path?, artifacts?}` |
| `CONTENT_CORRUPT` | 7 | a chunk or file digest mismatch, or OpenAEVC's integrity check failed | `{path, blob?}` |
| `CONTENT_NOT_PORTABLE` | 9 | a transfer closure references an object that is not present | `{missing}` |
| `CLOSURE_UNCLASSIFIED` | 9 | an effect kind or pointer the refs document does not classify; refs document missing | — |
| `RECOVERY_REQUIRED` | 7 | identity/continuity failure; a damaged operational journal | `{reason?}` |
| `MIGRATION_REQUIRED` | 7 | a read on an older product schema | — |
| `STALE_VIEW` | 3 | a pack command at a generation that moved | `{expected, current}` |

`apps/calve/tests/errors.rs` produces each of these (except `SUPERSEDE_DIVERGED`, covered by `capture_saga.rs`) and checks the JSON envelope (code, `exit_code` equal to the process exit status, detail) and the human line `calve: CODE: message`.

## OpenAEVC errors
OpenAEVC's structured error stays in `detail.openaevc` (code, message, retryable, object). Its code maps onto Calve's:

| OpenAEVC | Calve |
|---|---|
| `UNAUTHORIZED`, `FORBIDDEN`, `CAPABILITY_EXPIRED`, `CAPABILITY_REVOKED` | `CAPABILITY_DENIED` |
| `STALE_GENERATION`, `CONFLICT` | `STALE_VIEW` |
| `PROTOCOL_VERSION_UNSUPPORTED` | `OPENAEVC_INCOMPATIBLE` |
| `EXTENSION_INCOMPATIBLE` | `EXTENSION_INCOMPATIBLE` |
| `RECOVERY_REQUIRED`, `STORAGE_INTEGRITY_ERROR` | `RECOVERY_REQUIRED` |
| `NOT_FOUND`, `ALREADY_EXISTS`, `INVALID_ARGUMENT`, `INTERNAL` | same name |
| anything else | `OPENAEVC_OPERATION_REJECTED` |

Messages and details are redacted against the secrets in use ([secrets](../security/secrets.md)). `PRODUCT_ERROR` remains for messages not yet classified (exit 1).

Not yet emitted (reserved for later milestones): `REVIEW_STALE`, `RESOURCE_DIVERGED`, `UNSAFE_MATERIALIZATION` (materialization reports `blocked` paths instead), `UNSUPPORTED_PLATFORM_FEATURE`, `EXTENSION_PERMISSION_REQUIRED`, `CAPABILITY_DENIED` from Calve itself (OpenAEVC's denials map to it), `CONTAINMENT_UNAVAILABLE`, `CATALOG_STALE`.
