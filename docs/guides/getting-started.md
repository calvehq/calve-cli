# Getting started

```sh
cargo build --workspace --locked          # builds calve, calved and the calve_ext_* extensions
export PATH="$PWD/target/debug:$PATH"
```

Create a Project and enable the software extension:

```sh
mkdir hello && cd hello
calve init                     # prints recommended extensions and next actions
calve extension enable         # bundled software extension
echo "hello" > README.md
```

Plan work and capture a change:

```sh
calve intent create "Say hello"
calve pack create "Add README" --intent <intent-id> --require-review
calve pack capture <pack-id> README.md --generation 1
calve pack show <pack-id>      # note the generation
calve pack seal <pack-id> --generation <n>
```

Review, qualify and promote:

```sh
calve pack approve <pack-id> --generation <n> --reason "Looks right"
calve pack qualify <pack-id> --generation <n>
calve pack promote <pack-id> --generation <n>        # prints the promoted digest
calve baseline create v1 <promoted-digest>
calve baseline activate v1
```

`calve status` summarizes the Project, and `calve console` shows the same Project interactively (`?` lists keys). The scripts in [`examples/`](../../examples) walk through non-software Projects, language checks, parallel Intents, multiple Baselines, revisions and a local agent end to end.
