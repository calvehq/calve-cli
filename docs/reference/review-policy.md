# Review policy

Create a pack with `--require-review` to attach an immutable OpenAEVC policy requiring candidate-bound Calve approval evidence and no candidate-bound rejection evidence. The option is available on both `calve pack create` and `calve revision create`. It can be combined with `--require-snapshot-verification` on a ChangePack.

```text
calve pack create "Reviewed change" --require-review
calve pack seal <pack-id> --generation 1
calve review approve <pack-id> --generation 1 --reason "Checked"
calve pack qualify <pack-id> --generation 1
calve pack promote <pack-id> --generation 1
```

Calve stores the human decision in Project metadata and submits a namespaced review evidence object through OpenAEVC. The evidence payload identifies the review, pack, generation, candidate digest, reviewer principal, decision, reason, and timestamp. OpenAEVC evaluates the policy at qualification and promotion. An approval for an older candidate cannot satisfy the current candidate's gate.

`calve review list <pack-id>` includes `evidence_digest` for a policy-relevant approval or rejection. `calve evidence show <digest>` retrieves that immutable OpenAEVC object. Reviews on packs without the review policy remain product records and have a null evidence digest.

`calve review reject` records rejection evidence. Once a candidate has any rejection, later approval of that same candidate does not clear the policy block. Reopen the pack, make or confirm the intended change, seal the new generation, and review that candidate again. `review comment` remains a product record and does not affect the policy.

The gate relies on OpenAEVC principal and evidence permissions. Create a separate reviewer with `calve authority identity-add <name>` and pass `--as <name>` when recording a decision. Packs created with `--forbid-self-review` reject an approval from the pack creator; Calve checks this rule when recording a review. OpenAEVC's review evidence policy does not encode principal separation, so another client holding equivalent namespace authority can submit protocol evidence directly. Calve reserves the `org.calve.review.*` kinds in its generic `evidence add` path.
