//! Typed transfer closure (rev 10 §13 property 5; FG16, F24).
//!
//! `closure = native GetObjectClosure(roots) ∪ supplemental`, where supplemental follows, for
//! every effect of every candidate, the effect's `ExtensionRef.manifest_digest` → the manifest's
//! `schemas["calve.refs/1"]` content hash → the refs document (Calve's content-addressed refs
//! store, filled at install) → the payload pointers typed `ObjectRef` (e.g. chunk blobs). No
//! extension code runs, so history stays portable after the binary is retired. Every object kind
//! of OpenAEVC v0.1.0 is classified by an exhaustive match (a new kind is a compile error);
//! an effect kind the refs document does not declare, an unknown refs schema, a pointer that does
//! not resolve or a bound exceeded is `CLOSURE_UNCLASSIFIED`; a referenced object that is absent
//! is `CONTENT_NOT_PORTABLE`. Both fail closed.
use std::collections::BTreeSet;

use openaevc::protocol::{Digest, ErrorCode, ObjectKind, Query};
use openaevc_sdk::OpenAevcClient;
use serde_json::Value;

use calve_integration_contract::refs::{self, Edge};

use crate::{Project, Result};

/// How complete OpenAEVC's own reference edges are for each object kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeEdges {
    Complete,
    /// Calve adds supplemental edges (manifest schemas, effect payload pointers).
    Supplemental,
}

pub fn classify(kind: ObjectKind) -> NativeEdges {
    match kind {
        ObjectKind::ExtensionManifest | ObjectKind::Candidate => NativeEdges::Supplemental,
        ObjectKind::Blob
        | ObjectKind::CapabilityGrant
        | ObjectKind::Revocation
        | ObjectKind::PolicyDocument
        | ObjectKind::PolicyDecision
        | ObjectKind::Observation
        | ObjectKind::Evidence
        | ObjectKind::VerificationResult
        | ObjectKind::EvaluationResult
        | ObjectKind::PromotedPack
        | ObjectKind::PromotionRecord
        | ObjectKind::Receipt
        | ObjectKind::Baseline
        | ObjectKind::JournalCheckpoint => NativeEdges::Complete,
    }
}

fn unclassified(m: impl Into<String>) -> crate::Error {
    crate::coded("CLOSURE_UNCLASSIFIED", m)
}

impl Project {
    async fn object_or_none(&self, digest: Digest) -> Result<Option<Value>> {
        match self.client.query(Query::GetObject { digest }).await {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.code == ErrorCode::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The transfer closure of `roots` and the refs documents (content hashes) it used.
    /// `refs_doc` resolves a content hash to the document bytes.
    pub async fn transfer_closure(
        &self,
        roots: &[Digest],
        refs_doc: &dyn Fn(&str) -> Result<Option<Vec<u8>>>,
    ) -> Result<(BTreeSet<Digest>, BTreeSet<String>)> {
        let mut objects = BTreeSet::new();
        let mut used = BTreeSet::new();
        let mut queue: Vec<Digest> = roots.to_vec();
        while let Some(d) = queue.pop() {
            if !objects.insert(d) {
                continue;
            }
            let native = self
                .client
                .query(Query::GetObjectClosure { digest: d })
                .await?;
            let missing: Vec<Digest> =
                serde_json::from_value(native["missing"].clone()).unwrap_or_default();
            if !missing.is_empty() {
                return Err(crate::detailed(
                    "CONTENT_NOT_PORTABLE",
                    format!("{d} references objects that are not present"),
                    serde_json::json!({"missing": missing}),
                ));
            }
            for n in
                serde_json::from_value::<Vec<Digest>>(native["objects"].clone()).unwrap_or_default()
            {
                if !objects.contains(&n) {
                    queue.push(n);
                }
            }
            let Some(o) = self.object_or_none(d).await? else {
                return Err(crate::detailed(
                    "CONTENT_NOT_PORTABLE",
                    format!("{d} is not present"),
                    serde_json::json!({"missing": [d]}),
                ));
            };
            let env = &o["envelope"];
            let kind: ObjectKind = serde_json::from_value(env["kind"].clone())
                .map_err(|e| unclassified(format!("{d}: {e}")))?;
            if classify(kind) == NativeEdges::Complete || kind == ObjectKind::ExtensionManifest {
                continue;
            }
            for effect in env["body"]["effects"].as_array().into_iter().flatten() {
                let ext = &effect["provenance"]["extension"];
                if ext.is_null() {
                    continue;
                }
                let manifest: Digest = ext["manifest_digest"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| unclassified("effect without a manifest digest"))?;
                let m = self.object_or_none(manifest).await?.ok_or_else(|| {
                    crate::detailed(
                        "CONTENT_NOT_PORTABLE",
                        format!("manifest {manifest} is not present"),
                        serde_json::json!({"missing": [manifest]}),
                    )
                })?;
                let ekind = effect["kind"].as_str().unwrap_or_default();
                let Some(h) = m["envelope"]["body"]["schemas"]
                    .get(refs::SCHEMA)
                    .and_then(Value::as_str)
                else {
                    return Err(unclassified(format!(
                        "{ekind}: its extension declares no {}",
                        refs::SCHEMA
                    )));
                };
                let bytes = refs_doc(h)?
                    .ok_or_else(|| unclassified(format!("refs document {h} is not available")))?;
                if format!("sha256:{}", crate::journal::sha256_hex(&bytes)) != h {
                    return Err(unclassified(format!("refs document {h} fails its hash")));
                }
                used.insert(h.to_owned());
                let parsed = refs::parse(&serde_json::from_slice(&bytes)?).map_err(unclassified)?;
                let Some(pointers) = parsed.get(ekind) else {
                    return Err(unclassified(format!("{ekind} is not declared in {h}")));
                };
                for (ptr, edge) in pointers {
                    if *edge != Edge::ObjectRef {
                        continue;
                    }
                    for v in refs::resolve(&effect["payload"], ptr).map_err(unclassified)? {
                        let d: Digest =
                            v.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                                unclassified(format!("{ekind} {ptr} is not a digest"))
                            })?;
                        queue.push(d);
                    }
                }
            }
        }
        Ok((objects, used))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_object_kind_is_classified() {
        for k in openaevc::protocol::ObjectKind::ALL {
            let _ = super::classify(*k);
        }
    }
}
