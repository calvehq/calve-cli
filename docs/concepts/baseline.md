# Baseline

A Baseline is an independent composition of promoted packs. It is not a branch, and it is not a version of another Baseline: `B0 = P0, P1, P3` and `B1 = P0, P1, P2` are two separate compositions that happen to share members.

Because members are referenced by digest, Baselines share immutable objects and creating one duplicates none of them.

Calve adds two conveniences that OpenAEVC does not know about, both local to the Project:

- **Aliases**, such as `staging`, are mutable names for a Baseline.
- **The active Baseline** is a pointer saying which Baseline this Project is working from.

`baseline materialize` writes a Baseline's files into the working tree. It never destroys work that was not captured: it shows a plan, and blocks on uncaptured changes unless you decide per path. See [materialization](../reference/materialization.md).

More: the [multiple Baselines guide](../guides/multiple-baselines.md).
