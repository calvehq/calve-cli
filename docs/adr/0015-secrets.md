# ADR 0015: Secrets

Status: Accepted; redaction residuals user-approved.

## Context
Secrets reach workers through the environment and may surface in many sinks (logs, errors, journals, bundles).

## Decision
- Env only; never argv, config dumps, `WorkerContext` (names only), errors or metric labels; `Zeroizing` buffers; never given to CIC.
- Per-stream redactor (Aho-Corasick over raw, base64 std/URL-safe at offsets 0/1/2, percent, JSON-escaped, hex lower/upper), window = longest pattern − 1, applied to all 15 inventoried sinks.

## Consequences
The real boundary is not giving secrets to untrusted workers.

## Tests / evidence
M3: per-sink tests, every encoding/offset, 1-byte writes, an exhaustive grep over all artifacts.

## Residuals
**User-approved limitation:** splits across stdout/stderr, arbitrary transformations, base64 edge bytes and channels outside Calve's sinks are not redacted (tests assert the residuals).
