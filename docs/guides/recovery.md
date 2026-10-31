# Recovery

Start here when a command says recovery is needed, or after a crash or disk-full error. `recover inspect` changes nothing, so it is always safe to run.

## 1. Look

```sh
calve recover inspect
```

This reads the Project without a runtime or migration. It reports the product database and store status, identity and continuity, backups, unfinished operations and leftovers. It works even when the Project will not open.

`calve doctor` gives the wider view, and `calve doctor --bundle <file>` writes a redacted diagnostics bundle.

## 2. See the plan

```sh
calve recover plan
```

This lists the exact actions. Recovery acts only on state that is provably disposable or restorable, and it never edits OpenAEVC data.

## 3. Apply it

```sh
calve recover apply --yes
```

## Unfinished operations

| Operation | Commands |
|---|---|
| Materialization | `materialize list`, `materialize resume <op>`, `materialize resolve <op> --keep ours\|theirs`, `materialize rollback <op> --yes` |
| Capture | `capture list`, `capture resume <session>`, `capture rollback <session> --yes` |
| Supersede | `supersede list`, `supersede resume <saga>` |
| Extension install | `recover apply`, which finishes or removes it |
| Adopt-copy | `recover apply`, which finishes or restores it |

A conflicted materialization keeps both versions under `.calve/conflicts/<op>/`, and those are never removed automatically.

## Lost product database

```sh
calve recover apply --restore-backup <file> --yes
```

The backup is verified by SHA-256 and an integrity check, and the current database is kept as `pre-restore`. Calve then reconciles against OpenAEVC, which is still the authority. Product state written after the backup was taken, such as Tasks, is lost. Accepted history is not, because it lives in OpenAEVC.

## Check the store

```sh
calve maintenance check
calve maintenance verify-store
```

These need exclusive access, so the daemon releases its runtime for them.

## Catalog trust

`RecoveryRequired(trust_state)` means Calve no longer trusts the local catalog state. A successful `extension catalog refresh` clears it. If that is not possible, reset it with a root you trust. See [catalog operations](catalog-operations.md).

Reference: [maintenance and recovery](../reference/maintenance-and-recovery.md).
