# Review

A review is a human decision on one sealed candidate. Calve stores the decision in product metadata and, on a pack with `--require-review`, also submits candidate-bound evidence to OpenAEVC, whose policy gates qualification and promotion.

The binding is what makes it safe. An approval is for one candidate digest. If the pack is reopened and sealed again, old reviews are stale and cannot satisfy the gate.

A rejection is sticky for its candidate: a later approval of the same candidate does not clear it. Change the pack and review the new candidate.

Comments are product records and do not affect the policy.

`--forbid-self-review` is checked by Calve when a review is recorded. OpenAEVC's policy does not encode who may review, so another client holding equivalent authority is not stopped by it.

More: [review policy](../reference/review-policy.md), the [review and promotion guide](../guides/review-and-promotion.md).
