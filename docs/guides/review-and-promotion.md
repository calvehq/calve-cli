# Review and promotion

Promotion is the point where a proposal becomes accepted history, and it cannot be undone. Everything before it exists so you can decide with the whole change in view.

## Require a review

```sh
calve pack create "Reviewed change" --require-review --forbid-self-review
calve authority identity-add reviewer
```

## Look at it

```sh
calve pack seal <pack> --generation <n>
calve pack show <pack>
calve pack diff <pack>
calve evidence list <pack> --current
```

Or use `calve console`, which shows the pack, its diff, evidence and blockers on one screen.

## Decide

```sh
calve --as reviewer pack approve <pack> --generation <n> --reason "Checked"
# or
calve --as reviewer pack reject <pack> --generation <n> --reason "Breaks the pilot list"
```

A decision binds to this exact candidate. After a rejection, change the work and review the new candidate; a later approval of the same candidate does not clear the rejection.

## Change after sealing

`pack reopen` is possible, but with OpenAEVC v0.1.0 a pack with effects cannot then be promoted, because reopening keeps old effects and only effects of the current generation can be promoted. To carry on with the work, supersede it:

```sh
calve pack reopen <pack> --generation <n>
calve supersede start <pack> --keep <keep> --yes
```

`supersede start` replaces the OPEN pack with a new one, which you then capture into, seal and review. See [Scenario C](../reference/acceptance.md).

## Promote

```sh
calve pack qualify <pack> --generation <n>
calve pack promote <pack> --generation <n>
```

`qualify` asks OpenAEVC whether policy allows the candidate. `promote` prints the promoted digest, the permanent id of this change. Add it to a Baseline. To change it later, use a [revision](revisions.md).
