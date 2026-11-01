# A generic Project

Calve works on anything, not only source code. This guide runs a launch checklist through the whole workflow. The [`general-project`](../../examples/general-project) example is this guide as a tested script.

```sh
calve init launch && cd launch        # needs a catalog; see the install guide
calve extension enable org.calve.general --acknowledge-native
```

Say why, and plan the work:

```sh
calve intent create "Launch plan" --description "Agree the launch checklist"
calve task create <intent> "Draft the checklist" --assignee alex
calve pack create "Launch checklist" --intent <intent> --require-review
```

Records are resources, not files. Each `--set` is `kind:name=JSON`:

```sh
calve resource set <pack> --generation 1 \
  --set 'note:launch/summary={"text":"Ship to the pilot group first."}' \
  --set 'checklist:launch/steps={"items":[{"text":"Docs reviewed","done":true}]}'
calve task link-pack <task> <pack>
```

Take the current generation from `pack show`, then seal, approve and promote:

```sh
calve pack seal <pack> --generation <n>
calve pack approve <pack> --generation <n> --reason "Matches the plan"
calve pack qualify <pack> --generation <n>
calve pack promote <pack> --generation <n>       # prints promoted_digest
calve task complete <task>
calve baseline create pilot <promoted-digest>
calve baseline activate <baseline>
```

The Baseline is now the accepted state of the plan. Later changes go in new packs. See [review and promotion](review-and-promotion.md).
