# Review policy

Create a pack with `--require-review` to attach an immutable OpenAEVC policy requiring candidate-bound Calve approval evidence and no candidate-bound rejection evidence. The option is available on both `clv pack create` and `clv revision create`. It can be combined with `--require-snapshot-verification` on a ChangePack.

```text
clv pack create "Reviewed change" --require-review
clv pack seal <pack-id> --generation 1
clv review approve <pack-id> --generation 1 --reason "Checked"
clv pack qualify <pack-id> --generation 1
clv pack promote <pack-id> --generation 1
```

Calve stores the human decision in Project metadata and submits a namespaced review evidence object through OpenAEVC. The evidence payload identifies the review, pack, generation, candidate digest, reviewer principal, decision, reason, and timestamp. OpenAEVC evaluates the policy at qualification and promotion. An approval for an older candidate cannot satisfy the current candidate's gate.

`clv review list <pack-id>` includes `evidence_digest` for a policy-relevant approval or rejection. `clv evidence show <digest>` retrieves that immutable OpenAEVC object. Reviews on packs without the review policy remain product records and have a null evidence digest.

`clv review reject` records rejection evidence. Once a candidate has any rejection, later approval of that same candidate does not clear the policy block. A pack with effects cannot reopen on OpenAEVC v0.1.0, so continue with `supersede start` and review the replacement. `review comment` remains a product record and does not affect the policy.

The gate relies on OpenAEVC principal and evidence permissions. Create a separate reviewer with `clv authority identity-add <name>` and pass `--as <name>` when recording a decision. Packs created with `--forbid-self-review` reject an approval from the pack creator; Calve checks this rule when recording a review. OpenAEVC's review evidence policy does not encode principal separation, so another client holding equivalent namespace authority can submit protocol evidence directly. Calve reserves the `org.calve.review.*` kinds in its generic `evidence add` path.
