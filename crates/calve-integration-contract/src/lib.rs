//! Calve Integration Contract (CIC) v1 — the Calve-owned contract between the domain-neutral
//! host and extension semantics that OpenAEVC v0.1.0's closed extension operations cannot
//! express (rev 10 §6, ADR 0004).
//!
//! This crate is deliberately small and independently versioned: wire types, the wasm ABI
//! constants, `hello/0`, version/capability negotiation, the canonical JSON form, and the
//! streaming digests. It depends on nothing in Calve.
#![forbid(unsafe_code)]

pub mod abi;
pub mod digest;
pub mod hello;
pub mod jcs;
pub mod metadata;
pub mod session;
pub mod wire;

pub use hello::{CicRange, Hello, HostHello, Negotiated, negotiate};
