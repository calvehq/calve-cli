# RevisionPack

A promoted pack is immutable. To change what it did, you create a RevisionPack: a pack that `amends`, `supersedes` or `reverts` one or more promoted packs. The targets stay as they are, and OpenAEVC records the relation in the protocol graph.

A RevisionPack is otherwise an ordinary pack, with the same capture, seal, review, qualify and promote steps.

A revision does not change any Baseline by itself. Earlier Baselines keep their exact members. To adopt a revision, create a new Baseline that includes it next to the original.

Do not confuse this with `supersede start`, which replaces a pack that was never promoted.

More: [revisions](../reference/revisions.md), the [revision guide](../guides/revisions.md).
