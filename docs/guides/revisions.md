# Revisions and reversal

Promoted packs never change. To amend or undo one, add a RevisionPack and compose a new Baseline. The [`revision`](../../examples/revision) example is the tested version.

```sh
calve revision create "Amend the config" --of <promoted-digest> --relation amends
calve revision capture <revision> config.txt --generation 1
calve revision seal <revision> --generation <n>
calve pack qualify <revision> --generation <n>
calve revision promote <revision> --generation <n>
```

Use `--relation reverts` to undo, and `supersedes` to replace. `--of` takes several digests. `--require-review` works here as well.

Nothing changes until a Baseline includes the revision:

```sh
calve baseline create "without" <original>
calve baseline create "with" <original> <revision-digest>
```

Both Baselines stay valid, so you can materialize either one. To return to the earlier state, go back to the Baseline without the revision; nothing has to be deleted.
