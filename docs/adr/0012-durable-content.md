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

## M4 implementation (2026-10-17)
- Contract `content`: INLINE_MAX 1 MiB, CHUNK_MAX 4 MiB, FILE_MAX 256 MiB, payload `{digest, size, chunks:[{blob_digest, digest, size}]}`; file domains declare `files.put_chunked` (`org.calve.software.snapshot-chunked`).
- Capture uploads chunks as journaled Blob observations (`capture.chunk.<i>.<k>`), reads each back and verifies before the effect is proposed.
- Reads verify every chunk and the whole file: a digest or store-integrity mismatch (including bytes removed from an indexed object) is `CONTENT_CORRUPT`; an object absent from the Namespace is `MATERIALIZE_CONFLICT(content_unavailable)`; nothing partial is written.
- Closure (`closure.rs`): exhaustive ObjectKind classification, supplemental refs edges; `CLOSURE_UNCLASSIFIED` / `CONTENT_NOT_PORTABLE` fail closed. Adopt-copy carries the refs documents and re-walks at the destination with only those; `Project::historical_file` reconstructs accepted bytes from immutable objects alone.
- Evidence: `content.rs` (inline boundary ±1, 9 MiB round trip, clean-destination reconstruction with the extension binary and refs store retired, missing refs fail closed, corruption, absence), calve-extensions 5851707 (software `snapshot-chunked`, refs documents for software and general).
