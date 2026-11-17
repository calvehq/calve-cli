//! Streaming digests over canonical JSON lines (rev 10 §6.5, §6.5b):
//! `H = SHA-256( Σ JCS(item) ‖ 0x0A )` in order — manifests (`M`), tuple streams (`T`),
//! op streams (`O`), group streams and relation streams (`R`).

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::jcs;

#[derive(Debug, Clone, Default)]
pub struct LineHasher {
    h: Sha256,
    count: u64,
}

impl LineHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, item: &Value) -> Result<(), jcs::FloatNotAllowed> {
        self.h.update(jcs::to_vec(item)?);
        self.h.update([0x0A]);
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Hex of the running digest (does not consume the hasher).
    pub fn peek(&self) -> String {
        hex(&self.h.clone().finalize())
    }

    pub fn finish(self) -> String {
        hex(&self.h.finalize())
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Session input digest `I = SHA-256(JCS({v, op, params, base, work, tuples}))`.
pub fn input_digest(
    v: &str,
    op: &str,
    params: &Value,
    base: &str,
    work: &str,
    tuples: &str,
) -> String {
    let doc = serde_json::json!({"v": v, "op": op, "params": params, "base": base, "work": work, "tuples": tuples});
    sha256_hex(&jcs::to_vec(&doc).expect("integer-only"))
}
