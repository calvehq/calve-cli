//! Durable file content limits and the chunked payload (rev 10 §13, ADR 0012). Hosts emit and
//! extensions validate with this one definition.
//!
//! Inline payload `{digest, size, content}` (content ≤ [`INLINE_MAX`]); chunked payload
//! `{digest, size, chunks: [{blob_digest, digest, size}]}` with every chunk ≤ [`CHUNK_MAX`], the
//! sizes summing to `size` ≤ [`FILE_MAX`]. The extension checks structure and limits; the host
//! checks that the blobs exist and hash to the declared digests (an extension cannot read them).
use serde_json::Value;

pub const INLINE_MAX: u64 = 1024 * 1024;
pub const CHUNK_MAX: u64 = 4 * 1024 * 1024;
pub const FILE_MAX: u64 = 256 * 1024 * 1024;
pub const MAX_CHUNKS: u64 = FILE_MAX / CHUNK_MAX;

fn digest(v: &Value, what: &str) -> Result<String, String> {
    let s = v
        .as_str()
        .ok_or_else(|| format!("{what} must be a digest string"))?;
    let hex = s
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("{what} must be sha256:<hex>"))?;
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("{what} is not a sha256 digest"));
    }
    Ok(s.to_owned())
}

/// Validates a chunked payload's structure and limits; returns `(digest, size)`.
pub fn validate_chunked(p: &Value) -> Result<(String, u64), String> {
    let o = p.as_object().ok_or("payload must be an object")?;
    if o.len() != 3 {
        return Err("a chunked payload is {digest, size, chunks}".into());
    }
    let d = digest(&p["digest"], "digest")?;
    let size = p["size"].as_u64().ok_or("size")?;
    if size <= INLINE_MAX || size > FILE_MAX {
        return Err(format!(
            "chunked files are {INLINE_MAX} < size ≤ {FILE_MAX} bytes"
        ));
    }
    let chunks = p["chunks"].as_array().ok_or("chunks")?;
    if chunks.is_empty() || chunks.len() as u64 > MAX_CHUNKS {
        return Err(format!("1 to {MAX_CHUNKS} chunks"));
    }
    let mut sum = 0u64;
    for c in chunks {
        if c.as_object().is_none_or(|o| o.len() != 3) {
            return Err("a chunk is {blob_digest, digest, size}".into());
        }
        digest(&c["blob_digest"], "blob_digest")?;
        digest(&c["digest"], "chunk digest")?;
        let n = c["size"].as_u64().ok_or("chunk size")?;
        if n == 0 || n > CHUNK_MAX {
            return Err(format!("chunks are 1 to {CHUNK_MAX} bytes"));
        }
        sum += n;
    }
    if sum != size {
        return Err("chunk sizes do not add up to size".into());
    }
    Ok((d, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chunked_payloads_are_bounded_and_consistent() {
        let h = |c: char| format!("sha256:{}", c.to_string().repeat(64));
        let ok = json!({"digest": h('a'), "size": CHUNK_MAX + 10,
            "chunks": [{"blob_digest": h('b'), "digest": h('c'), "size": CHUNK_MAX},
                       {"blob_digest": h('d'), "digest": h('e'), "size": 10}]});
        assert_eq!(validate_chunked(&ok).unwrap().1, CHUNK_MAX + 10);
        let mut bad = ok.clone();
        bad["size"] = json!(CHUNK_MAX + 11);
        assert!(validate_chunked(&bad).is_err(), "sum");
        let mut bad = ok.clone();
        bad["chunks"][0]["size"] = json!(CHUNK_MAX + 1);
        assert!(validate_chunked(&bad).is_err(), "chunk limit");
        let mut bad = ok.clone();
        bad["size"] = json!(100);
        assert!(validate_chunked(&bad).is_err(), "small files are inline");
        let mut bad = ok;
        bad["chunks"][1]["blob_digest"] = json!("nope");
        assert!(validate_chunked(&bad).is_err(), "digest form");
    }
}
