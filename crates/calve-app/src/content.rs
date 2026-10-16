//! Durable file content on read (rev 10 §13 property 4): inline bytes or chunk Blobs, every
//! chunk and the whole file verified before any use. A missing blob is
//! `MATERIALIZE_CONFLICT(content_unavailable)`; a digest or storage-integrity mismatch is
//! `CONTENT_CORRUPT`. Nothing partial is ever returned.
use openaevc::protocol::{Blob, Candidate, Digest, ErrorCode, ObjectEnvelope, PromotedPack, Query};
use openaevc_sdk::OpenAevcClient;
use serde_json::json;

use crate::resources::Content;
use crate::{Project, Result};

impl Project {
    /// The bytes of `path` as accepted in the promoted pack `promoted`, read from immutable
    /// objects alone (imported history included): no extension and no refs store is consulted.
    pub async fn historical_file(&self, promoted: Digest, path: &str) -> Result<Vec<u8>> {
        let object = |d: Digest| async move {
            let v = self.client.query(Query::GetObject { digest: d }).await?;
            Ok::<_, crate::Error>(
                serde_json::from_value::<ObjectEnvelope>(v["envelope"].clone())?.body,
            )
        };
        let pack: PromotedPack = serde_json::from_value(object(promoted).await?)?;
        let candidate: Candidate = serde_json::from_value(object(pack.candidate).await?)?;
        let effect = candidate
            .effects
            .iter()
            .rev()
            .find(|e| e.target.locator == path)
            .ok_or_else(|| {
                crate::coded("NOT_FOUND", format!("{promoted} does not change {path}"))
            })?;
        if effect.payload.get("chunks").is_some() {
            return self.chunked_bytes(path, &effect.payload).await;
        }
        crate::resources::effect_content(effect).ok_or_else(|| {
            crate::coded(
                "CONTENT_CORRUPT",
                format!("{path}: no verified content in {promoted}"),
            )
        })
    }

    pub(crate) async fn content_bytes(&self, path: &str, c: &Content) -> Result<Vec<u8>> {
        match c {
            Content::Inline(b) => Ok(b.clone()),
            Content::Chunked(p) => self.chunked_bytes(path, p).await,
        }
    }

    /// The bytes of a chunked-file payload, every chunk and the whole file verified.
    pub(crate) async fn chunked_bytes(
        &self,
        path: &str,
        payload: &serde_json::Value,
    ) -> Result<Vec<u8>> {
        let (digest, size) = calve_integration_contract::content::validate_chunked(payload)
            .map_err(|m| crate::coded("CONTENT_CORRUPT", format!("{path}: {m}")))?;
        let mut out = Vec::with_capacity(size as usize);
        for (k, chunk) in payload["chunks"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let blob: Digest = chunk["blob_digest"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    crate::coded("CONTENT_CORRUPT", format!("{path}: chunk {k} digest"))
                })?;
            let v = match self.client.query(Query::GetObject { digest: blob }).await {
                Ok(v) => v,
                Err(err) if err.code == ErrorCode::NotFound => {
                    return Err(crate::detailed(
                        "MATERIALIZE_CONFLICT",
                        format!("{path}: chunk {k} ({blob}) is not available"),
                        json!({"reason": "content_unavailable", "path": path, "blob": blob}),
                    ));
                }
                Err(err) if err.code == ErrorCode::StorageIntegrityError => {
                    return Err(crate::detailed(
                        "CONTENT_CORRUPT",
                        format!("{path}: chunk {k} fails OpenAEVC's integrity check"),
                        json!({"path": path, "blob": blob, "openaevc": err}),
                    ));
                }
                Err(err) => return Err(err.into()),
            };
            let env: ObjectEnvelope = serde_json::from_value(v["envelope"].clone())?;
            let data = serde_json::from_value::<Blob>(env.body)?.data;
            if openaevc::crypto::sha256(&data).to_string()
                != chunk["digest"].as_str().unwrap_or_default()
                || chunk["size"].as_u64() != Some(data.len() as u64)
            {
                return Err(crate::detailed(
                    "CONTENT_CORRUPT",
                    format!("{path}: chunk {k} does not match its digest"),
                    json!({"path": path, "blob": blob}),
                ));
            }
            out.extend_from_slice(&data);
        }
        if openaevc::crypto::sha256(&out).to_string() != digest {
            return Err(crate::detailed(
                "CONTENT_CORRUPT",
                format!("{path}: the assembled file does not match its digest"),
                json!({"path": path}),
            ));
        }
        Ok(out)
    }
}
