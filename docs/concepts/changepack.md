# ChangePack

A ChangePack is a proposed change. It is owned by [OpenAEVC](../compatibility/openaevc.md); Calve creates and drives packs but never edits their records.

```text
OPEN ──seal──> SEALED ──qualify──> QUALIFIED ──promote──> PROMOTED
  ^              │
  └────reopen────┘            quarantined or abandoned from most states
```

- **OPEN:** effects accumulate, from a capture, `resource set` or a worker run.
- **SEALED:** the candidate is fixed and has a digest. Evidence, verification and review bind to that digest.
- **QUALIFIED:** OpenAEVC's policy allows the candidate.
- **PROMOTED:** immutable accepted history, identified by its promoted digest.

**Generations.** Structural changes advance a pack's generation, and commands name the generation they expect. A stale generation is rejected, so a command cannot act on a pack that changed underneath it.

**Two limits of OpenAEVC v0.1.0 shape how you use packs:**

- Only effects of the current generation can be promoted, and a reopen keeps a pack's effects. A pack with effects therefore cannot be promoted after a reopen. Use `supersede start` to continue the work in a new pack.
- Any execution advances the generation. Calve refuses an execution on a pack that has effects, so run harnesses in a separate pack, or use `pack check` on the sealed candidate.

The product guide is the [review and promotion guide](../guides/review-and-promotion.md); normative semantics are OpenAEVC's.
