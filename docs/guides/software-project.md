# A software Project

This guide captures source files, runs language checks and writes accepted files back. The [`software-project`](../../examples/software-project) example is the tested version.

```sh
calve init hello && cd hello
calve extension enable org.calve.software --acknowledge-native
calve extension enable org.calve.rust --acknowledge-native
```

Calve needs no Git. It captures exact snapshots of files, and the software extension decides what is ignored.

```sh
calve pack create "Greeting" --require-check rust
calve pack capture-tree <pack> . --generation 1
calve pack diff <pack>
calve pack seal <pack> --generation <n>
```

`capture-tree` accepts at most 64 files and 16 MiB of inline content; a larger file is refused with `FILE_TOO_LARGE`. A deletion needs `--accept-deletions`.

## Check

```sh
calve pack check <pack> --generation <n>
```

The check runs on a copy of the working tree with the candidate overlaid. The first run stops with `CHECK_PLAN_UNAPPROVED` and prints the exact command, because a package chose it and it will run with your permissions. Read it, then approve its digest with `--approve-plan`.

To change a command, configure it for the Project:

```toml
format_version = 1
[integrations."org.calve.rust".checks]
test = ["cargo", "test", "--locked"]
```

Do not run a harness on this pack. An execution starts a new generation, and OpenAEVC only promotes effects from the current one, so Calve refuses. Use a separate pack for test runs.

## Promote and materialize

```sh
calve pack qualify <pack> --generation <n>
calve pack promote <pack> --generation <n>
calve baseline create v1 <promoted-digest>
calve baseline materialize <baseline>              # plan only
calve baseline materialize <baseline> --apply
```

If you have uncaptured work in a path the Baseline would change, materialization blocks that path. Capture it, or discard it explicitly with `--discard <path>`. See [materialization](../reference/materialization.md).
