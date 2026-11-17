# Vocabulary

**Workspace.** A local grouping of Projects on one machine. A Project can belong to several; Workspaces hold no change state.

**Project.** A directory with a `.calve/` folder: one ProjectId bound to one OpenAEVC Namespace. Moving a Project keeps its identity (`project relocate`); a copy must be adopted as a new Project (`project adopt-copy`).

**Namespace.** The OpenAEVC authority and history boundary behind a Project.

**Intent.** Why changes are being made. It is Calve workflow state; closing it never alters accepted history.

**Task.** A unit of work under an Intent, with cross-Intent dependencies. Tasks link to packs, executions and work units, and Calve reports when a Task's state disagrees with OpenAEVC.

**ChangePack.** A proposed change owned by OpenAEVC. It moves through OPEN (effects accumulate) → SEALED (candidate fixed) → QUALIFIED (policy allows it) → PROMOTED (immutable), or is quarantined or abandoned. Every structural change advances its generation, and commands name the generation they expect.

**RevisionPack.** A pack that amends, supersedes or reverts promoted packs without editing them.

**Evidence, verification, evaluation.** Immutable objects bound to one sealed candidate. Policies (`--require-review`, `--require-check`, `--require-snapshot-verification`) are OpenAEVC rules over them.

**Review.** A Calve decision recorded as candidate-bound evidence. Reopening makes old reviews stale.

**Baseline.** An independent composition of promoted packs, not a branch or a version of another Baseline. Calve's active Baseline is only a local pointer; `materialize` writes a Baseline's files into the working tree.

**Provider and harness.** How to launch a worker, and what one run does. See [providers and harnesses](../reference/providers-and-harnesses.md).

**Extension.** An OpenAEVC extension binary defining resource and effect kinds, verifiers or evaluators. Calve installs, pins and grants them.

**Receipt.** OpenAEVC's signed record of a command, verifiable with `receipt verify`.
