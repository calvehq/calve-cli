# Calve Integration Contract (CIC) v1

Status: contract crate `calve-integration-contract` 1.0.0-alpha.1 (committed); wire major 1, minor 0; wasm ABI 1. Decision record: ADR 0004. Evidence: FG4, FG13.

## Packages
A **cic-capable** package ships, as separate TUF targets: the native OpenAEVC artifact, `cic.wasm`, and `calve-integration.json`. An **openaevc-only** package ships the native artifact and optionally `calve-ui.json` (ADR 0006).

## Version axes (each negotiated or checked separately)
| Axis | Form | Rule |
|---|---|---|
| Wasm ABI | integer (`cic_abi_version()` = 1) | exact match against the host set `{1}`, else `INCOMPATIBLE_CIC(abi)` |
| CIC wire | per-major ranges `[{major, min_minor, max_minor}]` | highest major present on both sides; minor = `min(host.max, guest.max)` if ≥ `max(host.min, guest.min)`; else `INCOMPATIBLE_CIC(wire)` |
| Capabilities | `op.vN` | declared (signed metadata) = advertised (`hello/0`) exactly, else `ABI_VIOLATION`; negotiated = host ∩ advertised; every required capability must be negotiated |
| Metadata schema | `calve.integration/N` | host supports a set of N; unknown → `PACKAGE_INVALID(schema)`; unknown optional keys inside N are kept and ignored |

## `hello/0` (frozen forever)
Request (`cic_init`): `{"hello":0,"host":{"abi":[1],"cic":[…],"capabilities":[…],"schemas":[1]}}`.
Reply: `{"hello":0,"guest":{"abi":1,"cic":[…],"capabilities":{"required":[…],"optional":[…]},"schema":1,"extension_id":…,"version":…}}`.
Both reject unknown fields except a reserved, ignored `"x"` object.

## Wasm ABI 1
Exports: `memory`, `cic_abi_version() -> i32`, `cic_alloc(len) -> ptr`, `cic_free(ptr, len)`, `cic_init(ptr, len) -> i64`, `cic_call(ptr, len) -> i64`. **No imports, no start section, exactly one memory.** Immutable global exports (e.g. rustc's `__data_end`, `__heap_base`) are allowed and ignored; a mutable global export is rejected.
- `i32` values are read as `u32`; the `i64` result is `ptr << 32 | len`; bounds are checked with u64 arithmetic against the memory size **after** the call.
- The request buffer belongs to the guest from call entry. The response stays valid until the host calls `cic_free` exactly once, before the next call; `2 ≤ len ≤ max_response`; result 0 → `INTERNAL`; the response must not overlap the request.
- A fresh instance per session; never reused after an error. Encoding: UTF-8 JSON in RFC 8785 canonical form, integers only (|n| ≤ 2⁵³−1).

## Messages
Request `{"v":"1.0","seq":n,"op":…,"body":…}` (`seq` from 1, +1 each); response `{"seq":n,"ok":…}` or `{"seq":n,"err":{"code","message","retryable"}}`.
Guest codes: `INVALID_INPUT`, `LIMIT_EXCEEDED`, `UNSUPPORTED_OP`, `BAD_STATE`, `INTERNAL`. Host codes: `TRAPPED`, `ABI_VIOLATION`, `OUT_OF_FUEL`, `DEADLINE_EXCEEDED`, `OUT_OF_MEMORY`, `CANCELLED`, `INCOMPATIBLE_CIC`.

## Operations
Stateless: `describe`, `detect{markers}`, `check_plan`, `diff`, `classify`. Streaming (`capture.begin/chunk/finish`, `materialize_plan`) over host-merge-joined tuples `{path, base?, work?}` in byte-wise path order; exactly one op per tuple (`add | modify | delete | unchanged | refuse{reason}`), byte-equal paths, shape-checked op kinds; output digest `O = SHA-256(Σ JCS(op) ‖ 0x0A)` recomputed by the host. Aggregate: `relate.begin/groups/finish` (capability `relate.v1`) over host-grouped ops with a `groups_commitment`, acked cumulative counts and running digest, per-kind outcomes `complete | {"refused": reason}`, relations digest `R`; any session failure discards all relations; fatality per the package's `relations[].required` and `optional_relations` policy.

## Limits (defaults)
Guest memory 64 MiB; module 8 MiB; tables 10 000; request/response 4 MiB; chunk 2 048 tuples; `max_group` 64; fuel slice 1e7, per call 5e8; soft deadline 5 s; hard deadline 15 s (supervised child).

## Conformance
Golden transcripts `evidence/m0/fixtures/cic/goldens/v1/session.jsonl` (local evidence) must be byte-identical for every guest × host pair; the reference guests are cic-ref-rust and the independent `no_std` cic-ref-min.
