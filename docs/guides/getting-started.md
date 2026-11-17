# Getting started

```sh
cargo build --workspace --locked          # builds clv and calved
export PATH="$PWD/target/debug:$PATH"
```

Create a Project and enable the software extension:

```sh
mkdir hello && cd hello
clv init                     # prints recommended extensions and next actions
clv extension catalog add first-party <url> --root root.json --root-digest <sha256>
clv extension enable org.calve.software --acknowledge-native
echo "hello" > README.md
```

Plan work and capture a change:

```sh
clv intent create "Say hello"
clv pack create "Add README" --intent <intent-id> --require-review
clv pack capture <pack-id> README.md --generation 1
clv pack show <pack-id>      # note the generation
clv pack seal <pack-id> --generation <n>
```

Review, qualify and promote:

```sh
clv pack approve <pack-id> --generation <n> --reason "Looks right"
clv pack qualify <pack-id> --generation <n>
clv pack promote <pack-id> --generation <n>        # prints the promoted digest
clv baseline create v1 <promoted-digest>
clv baseline activate <baseline-id>   # printed by baseline create
```

`clv status` summarizes the Project, and `clv console` shows the same Project interactively (`?` lists keys). The scripts in [`examples/`](../../examples) walk through non-software Projects, language checks, parallel Intents, multiple Baselines, revisions and a local agent end to end.
