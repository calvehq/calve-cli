# ADR 0001: OpenAEVC is the sole protocol authority

Status: Accepted for the initial implementation.

Calve depends on pinned public OpenAEVC packages and invokes its signed SDK command and query path. Calve may construct an embedded runtime through public APIs but does not read or write OpenAEVC tables or infer authorization from local product metadata. The CLI and console may present eligibility and explanations, but authoritative lifecycle and promotion decisions remain in OpenAEVC.

This boundary permits Calve to evolve its product workflow without forking protocol semantics. It also makes an unavailable or incompatible OpenAEVC dependency a build or startup error rather than a reason to silently substitute local rules.
