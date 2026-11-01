# Project format

```text
<project>/.calve/
  project.toml        immutable identity
  keys.toml           Project signing keys (owner-only)
  config.toml         Project configuration (optional)
  product.sqlite3     Calve product database
  openaevc/           OpenAEVC runtime state; only OpenAEVC writes here
  backups/            product database backups, owner-only, with SHA-256 sidecars
  cache/              rebuildable
  run/                operation journals and staging (capture, materialize)
  logs/               local logs, and the output of cancelled executions
  tmp/                temporary files
  conflicts/<op>/     materialization conflicts, never removed automatically
```

| File | Format | Rule |
|---|---|---|
| `project.toml` | TOML | Holds ProjectId, NamespaceId and creator. Never rewritten; the display name is in the product database. |
| `product.sqlite3` | SQLite | Versioned by `schema_migrations`. Migrations run on open, and a newer schema refuses to start. |
| `openaevc/` | OpenAEVC's own | Versioned and verified by OpenAEVC. |
| `config.toml` | TOML | Starts with `format_version = 1`; see [configuration](config.md). |

When the Project root is a Git checkout, Calve adds `/.calve/` to `.git/info/exclude`, which is local to that clone. Add it to your own `.gitignore` too if others share the repository. Everything under `.calve/` is private state: do not commit it, and do not edit it by hand.

Moving the directory is safe when followed by `project relocate`. Copying it requires `project adopt-copy`. See [relocation and copies](../guides/relocation-and-copies.md).

Machine-level state is in the [architecture overview](../architecture/overview.md#state).
