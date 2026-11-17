# Review and promotion

Promotion is the point where a proposal becomes accepted history, and it cannot be undone. Everything before it exists so you can decide with the whole change in view.

## Require a review

```sh
clv pack create "Reviewed change" --require-review --forbid-self-review
clv authority identity-add reviewer
```

## Look at it

```sh
clv pack seal <pack> --generation <n>
clv pack show <pack>
clv pack diff <pack>
clv evidence list <pack> --current
```

Or use `clv console`, which shows the pack, its diff, evidence and blockers on one screen.

## Decide

```sh
clv --as reviewer pack approve <pack> --generation <n> --reason "Checked"
# or
clv --as reviewer pack reject <pack> --generation <n> --reason "Breaks the pilot list"
```

A decision binds to this exact candidate. After a rejection, change the work and review the new candidate; a later approval of the same candidate does not clear the rejection.

## Change after sealing

A pack with no effects can reopen. A pack with effects cannot on OpenAEVC v0.1.0: `pack reopen` is refused with `REOPEN_UNSAFE`, and nothing changes, because such a pack could never be promoted afterwards. Replace it explicitly:

```sh
clv supersede start <pack> --keep <keep> --yes
```

The replacement holds the first `<keep>` effects, and you capture into it, seal and review it. The original is abandoned last, and stays in history. See [Scenario C](../reference/acceptance.md).

## Promote

```sh
clv pack qualify <pack> --generation <n>
clv pack promote <pack> --generation <n>
```

`qualify` asks OpenAEVC whether policy allows the candidate. `promote` prints the promoted digest, the permanent id of this change. Add it to a Baseline. To change it later, use a [revision](revisions.md).
