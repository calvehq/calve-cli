# Materialization

Materialization writes accepted file content into the working tree without destroying work that was never captured.

```sh
calve baseline materialize <baseline-or-alias>                   # plan only
calve baseline materialize <baseline> --apply [--activate]
calve baseline materialize <baseline> --apply --discard path/to/file
calve resource materialize <path> --from <pack> [--apply] [--discard]
```

1. The Baseline is validated through OpenAEVC and its members' snapshots are resolved; later promotions of the same path win.
2. Each path is classified: `create` (missing locally), `unchanged`, `update` (the local file matches some snapshot Calve has recorded, so nothing uncaptured is lost), or `blocked_uncaptured_changes` (local content matches no recorded snapshot).
3. Without `--apply`, or when anything is blocked, Calve returns the plan and stops. There is no force flag; `--discard <path>` is an explicit, per-path decision to overwrite, and the previous content is first copied to `.calve/cache/discarded/<sha256>`.
4. Writes require the principal to be authorized for the file package's declared write action on each resource. They run inside an OpenAEVC execution on a dedicated, afterwards abandoned, pack: every written file is recorded as a `<extension>.materialized` observation, with receipts and provenance.
5. Files are written through a temporary file and rename, never through symlinked directories, and every desired digest is re-checked afterwards. `--activate` moves Calve's active Baseline pointer only after a successful apply.
