# RevisionPacks

A RevisionPack proposes a new change relative to one or more immutable promoted packs. It does not edit or delete its targets. Use the promoted-pack digest returned by `calve pack promote`:

```text
calve revision create "Amend accepted behavior" --of <promoted-pack-digest> --relation amends
calve revision list
calve revision show <revision-id>
```

Relations are `amends`, `supersedes`, or `reverts`. Repeat values after `--of` to target more than one promoted pack. OpenAEVC validates that each target is a PromotedPack object and records the revision relation in the protocol graph.

Add `--require-review` to require a candidate-bound approval before qualification and promotion. The regular `calve review approve` and `review reject` commands apply to RevisionPacks as well; see [review policy](review-policy.md).

The returned revision ID is a pack ID. Use the existing `calve pack capture`, `capture-tree`, `seal`, `verify`, `qualify`, and `promote` commands with that ID and its current generation. Add the promoted revision digest to a new Baseline alongside the relevant original members. Earlier Baselines remain immutable.

`calve revision capture|diff|seal|verify|evaluate|check|review|approve|reject|promote` run the same lifecycle as the pack commands and additionally confirm the target is a RevisionPack. See `examples/revision` for a Baseline with and without a revision.

## Rollback results

Rolling back a capture reports two separate things. `rse_holds` says the resources are in the state they were before; `cce_holds` says the candidate's content effects match that state too. On the default path, a superseding pack, a Done saga reports both as true. In `compensate` mode the pack keeps the capture and its compensation, so `rse_holds` is true and `cce_holds` is false. The candidate digest is never equal to the earlier one in either mode, because the effects are new.
