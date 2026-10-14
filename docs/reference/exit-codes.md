# Exit codes

Status: **current** — `0` success, `1` any error (`calve: <CODE>: <message>` on stderr). **Target** (M3, ADR 0020; an approved contract correction recorded in the CHANGELOG):

| Code | Meaning | Error codes |
|---|---|---|
| 0 | success | — |
| 1 | general failure | `PRODUCT_ERROR`, `IO_ERROR`, `INTERNAL` |
| 2 | usage / invalid input | clap errors, `INVALID_CONFIGURATION` |
| 3 | conflict or stale state; retry after refreshing | `STALE_VIEW`, `REVIEW_STALE`, `RESOURCE_DIVERGED`, `SUPERSEDE_CONFLICT`, `MATERIALIZE_CONFLICT`, `EXTENSION_IN_USE`, `PROJECT_LOCKED` |
| 4 | not found | `PROJECT_NOT_FOUND`, `WORKSPACE_NOT_FOUND`, `EXTENSION_NOT_INSTALLED` |
| 5 | permission / authority denied | `CAPABILITY_DENIED`, `EXTENSION_PERMISSION_REQUIRED`, `PUBLISHER_NOT_AUTHORIZED` |
| 6 | incompatible | `OPENAEVC_INCOMPATIBLE`, `EXTENSION_INCOMPATIBLE`, `INCOMPATIBLE_CIC`, `DAEMON_INCOMPATIBLE`, `UNSUPPORTED_PLATFORM_FEATURE` |
| 7 | recovery or migration required | `RECOVERY_REQUIRED`, `MIGRATION_REQUIRED`, `CORRUPT_PRODUCT_STATE` |
| 8 | unavailable | `DAEMON_UNAVAILABLE`, `PROVIDER_UNAVAILABLE`, `HARNESS_UNAVAILABLE`, `SECRET_UNAVAILABLE`, `CATALOG_STALE` |
| 9 | rejected by OpenAEVC or by policy | `OPENAEVC_OPERATION_REJECTED`, `EXTENSION_REVOKED` |
| 130 | cancelled by the user | `USER_CANCELLED` |
