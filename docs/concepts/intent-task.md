# Intent and Task

An **Intent** says why changes are being made. A **Task** is a unit of work under an Intent. Both are Calve workflow state, kept in the product database. Neither is part of accepted history, so closing or cancelling one never alters a promoted pack or a Baseline.

Tasks depend on other Tasks, including across Intents. Calve rejects cycles, refuses to start a Task before its prerequisites are complete, and refuses to complete it while one is open.

A Task can link to packs, executions and work units. Calve stores only their ids and fetches their state from OpenAEVC when you look. If the two disagree, for example a completed Task linked to a work unit that is still open, Calve reports the inconsistency in the Inbox instead of changing either side.

More: [tasks and packs](../reference/tasks-and-packs.md), the [`parallel-intents`](../../examples/parallel-intents) example.
