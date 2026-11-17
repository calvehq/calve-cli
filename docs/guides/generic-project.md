# A generic Project

Calve works on anything, not only source code. This guide runs a launch checklist through the whole workflow. The [`general-project`](../../examples/general-project) example is this guide as a tested script.

```sh
clv init launch && cd launch        # needs a catalog; see the install guide
clv extension enable org.calve.general --acknowledge-native
```

Say why, and plan the work:

```sh
clv intent create "Launch plan" --description "Agree the launch checklist"
clv task create <intent> "Draft the checklist" --assignee alex
clv pack create "Launch checklist" --intent <intent> --require-review
```

Records are resources, not files. Each `--set` is `kind:name=JSON`:

```sh
clv resource set <pack> --generation 1 \
  --set 'note:launch/summary={"text":"Ship to the pilot group first."}' \
  --set 'checklist:launch/steps={"items":[{"text":"Docs reviewed","done":true}]}'
clv task link-pack <task> <pack>
```

Take the current generation from `pack show`, then seal, approve and promote:

```sh
clv pack seal <pack> --generation <n>
clv pack approve <pack> --generation <n> --reason "Matches the plan"
clv pack qualify <pack> --generation <n>
clv pack promote <pack> --generation <n>       # prints promoted_digest
clv task complete <task>
clv baseline create pilot <promoted-digest>
clv baseline activate <baseline>
```

The Baseline is now the accepted state of the plan. Later changes go in new packs. See [review and promotion](review-and-promotion.md).
