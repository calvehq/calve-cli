# ADR 0004: Calve Integration Contract (CIC) v1 and wasm ABI 1

Status: Accepted (M0: FG4, FG13 PASS; deltas recorded).

## Context
OpenAEVC v0.1.0's extension operations are closed (validate_effect, apply_effect, verify, evaluate, compose; F3). Calve needs domain-specific *planning* operations — detection, classification, capture, materialization planning, diffs, relations — without putting software semantics in the host (INV-022). Extensions are distributed only through the signed catalog and must be runnable without trusting native code.

## Decision
- A versioned, Calve-owned contract crate `calve-integration-contract` (own SemVer, starts `1.0.0-alpha.1`; depends only on serde, serde_json, sha2) defines: the frozen `hello/0` exchange; four independent version axes (wasm ABI integer, CIC wire per-major ranges, capabilities `op.vN`, metadata schema `calve.integration/N`); the declared/advertised/negotiated capability sets; request/response envelopes; streaming session bodies (capture, relate); manifest/tuple/op digests (`M`, `I`, `O`, `R`); the metadata schema; a payload-schema subset; the relate fatality policy; host-side verifiers.
- Guests are `cic.wasm` modules with **no imports, no start section, one memory** and the exports `memory, cic_abi_version, cic_alloc, cic_free, cic_init, cic_call`. JSON in RFC 8785 canonical form, integers only (|n| ≤ 2⁵³−1).
- Path-local operations (classify, capture, materialize_plan) are validated exactly per input item; aggregate semantics (relate) run in a separate session over host-grouped input with commitments and acked counts.

## Consequences
- **M0 deltas (evidence-driven):**
  - Immutable **global** exports are allowed and ignored (rustc always exports `__data_end`/`__heap_base` for wasm32 cdylibs); function/memory exports stay exact; a mutable global export is rejected (FG4).
  - The canonical-JSON check is part of the host contract (a non-canonical, float-bearing or unsorted response is `ABI_VIOLATION`) (FG4).
- Two independent guests (cic-ref-rust on the contract crate; cic-ref-min, `no_std`, zero dependencies) and two independent hosts (Calve host, `mini_host`) produce byte-identical transcripts (golden `fixtures/cic/goldens/v1/session.jsonl`).
- The wasm guest ABI glue necessarily uses `unsafe` (raw guest pointers). The §4.1 rule "`forbid(unsafe_code)` everywhere except calve-win-sec" applies to calve-cli crates; calve-extensions `cic` crates and testkit wasm fixtures need a scoped exemption for their ABI glue (to be confirmed at M0 review).

## Tests / evidence
FG4 (2×2 goldens, 25 adversarial modules on both hosts, determinism across fuel slices, debug/release and in-process/supervised), FG13 (relate), contract tests (`crates/calve-integration-contract/tests/{contract,session}.rs`).

## Residuals
Cross-OS determinism (macOS, Windows) is PENDING native runs; the Windows axis is run in M0 where possible (FG4 Windows). A12: cic-ref-rust contains 64 float instructions (serde_json number formatting), cic-ref-min none; integer-only JSON avoids float divergence in the protocol, but guest-internal float paths are not proven deterministic across architectures (aarch64 BLOCKED).
