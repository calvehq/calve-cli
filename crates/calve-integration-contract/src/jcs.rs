//! Canonical JSON for CIC (RFC 8785 restricted to the CIC value domain: integers only).
//!
//! Keys are sorted by UTF-16 code units (RFC 8785 §3.2.3), output is compact, strings use the
//! minimal JSON escaping of `serde_json` (which matches RFC 8785 for the escapes it emits).
//! Floats are rejected: the CIC schemas contain none, which also removes the main source of
//! cross-platform numeric divergence.

use serde_json::Value;

/// Rejected number: a float, or an integer outside ±(2^53−1).
#[derive(Debug, PartialEq, Eq)]
pub struct FloatNotAllowed;

pub const MAX_SAFE: u64 = (1 << 53) - 1;

pub fn to_vec(v: &Value) -> Result<Vec<u8>, FloatNotAllowed> {
    let mut out = Vec::new();
    write(v, &mut out)?;
    Ok(out)
}

fn write(v: &Value, out: &mut Vec<u8>) -> Result<(), FloatNotAllowed> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => {
            // Integers only, within the I-JSON safe range |n| ≤ 2^53−1 (§6.2 Encoding).
            let safe = n.as_i64().is_some_and(|i| i.unsigned_abs() <= MAX_SAFE)
                || n.as_u64().is_some_and(|u| u <= MAX_SAFE);
            if !safe {
                return Err(FloatNotAllowed);
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => {
            out.extend_from_slice(serde_json::to_string(s).expect("string").as_bytes())
        }
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(x, out)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(serde_json::to_string(k).expect("key").as_bytes());
                out.push(b':');
                write(&m[*k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// True when `bytes` are exactly the canonical form of the JSON they encode.
pub fn is_canonical(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| to_vec(&v).ok())
        .is_some_and(|c| c == bytes)
}
