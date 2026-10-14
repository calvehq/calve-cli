# ADR 0012: Durable file content: inline and chunked

Status: Accepted (M0: FG6 PASS → chunking enabled, contingent on FG16 closure).

## Context
The software extension stores content inline (≤ 1 MiB, F10). Observation blobs are immutable, content-addressed and ≤ 8 MiB (F9, F17).

## Decision
- Inline ≤ 1 MiB; chunked content as ≤ 4 MiB Blob observations up to `max_file_size` (default 256 MiB), referenced from `org.calve.software.snapshot-chunked` effects.
- Fail closed: an effect is accepted only if its content is retained, reachable, integrity-verifiable and portable (transitive closure + Calve supplemental edges, FG16). Without portability, chunking is disabled entirely (`FILE_TOO_LARGE`).

## Consequences
FG6 proved immutability, retention after every terminal state (GC), SDK reachability, integrity on read, and exchange carry; FG16 proved the supplemental closure. **FG16 correction:** `manifest.schemas["calve.refs/1"]` is the **content hash** (SHA-256 of the refs document bytes), not a Blob object digest (object digests are namespace-specific); refs documents live in Calve's content-addressed refs store, filled at install from the signed package, travel in the transfer bundle keyed by content hash and are hash-verified at the destination. Store GC needs exclusive access to the data root (runtime closed, daemon-coordinated).

## Tests / evidence
FG6, FG16; M4 boundary/corruption/missing-blob/adopt-copy tests.

## Residuals
None beyond the user-approved fallback (`FILE_TOO_LARGE` if a later regression disables chunking).
