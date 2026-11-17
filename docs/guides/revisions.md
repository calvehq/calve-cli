# Revisions and reversal

Promoted packs never change. To amend or undo one, add a RevisionPack and compose a new Baseline. The [`revision`](../../examples/revision) example is the tested version.

```sh
clv revision create "Amend the config" --of <promoted-digest> --relation amends
clv revision capture <revision> config.txt --generation 1
clv revision seal <revision> --generation <n>
clv pack qualify <revision> --generation <n>
clv revision promote <revision> --generation <n>
```

Use `--relation reverts` to undo, and `supersedes` to replace. `--of` takes several digests. `--require-review` works here as well.

Nothing changes until a Baseline includes the revision:

```sh
clv baseline create "without" <original>
clv baseline create "with" <original> <revision-digest>
```

Both Baselines stay valid, so you can materialize either one. To return to the earlier state, go back to the Baseline without the revision; nothing has to be deleted.
