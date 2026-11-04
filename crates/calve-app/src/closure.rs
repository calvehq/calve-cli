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
                let parsed = parse_refs(&serde_json::from_slice(&bytes)?).map_err(unclassified)?;
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

/// `refs::parse` plus Calve's own rule: a `calve.refs/1` document has exactly the fields the
/// schema defines. An unknown field could carry meaning this Calve ignores, so it fails closed.
pub fn parse_refs(doc: &Value) -> std::result::Result<refs::Refs, String> {
    let only = |v: &Value, allowed: &[&str], at: &str| -> std::result::Result<(), String> {
        let o = v
            .as_object()
            .ok_or(format!("refs: {at} must be an object"))?;
        match o.keys().find(|k| !allowed.contains(&k.as_str())) {
            Some(k) => Err(format!("refs: unknown field `{k}` in {at}")),
            None => Ok(()),
        }
    };
    only(doc, &["schema", "kinds"], "the document")?;
    let parsed = refs::parse(doc)?;
    for (kind, list) in doc["kinds"].as_object().into_iter().flatten() {
        for p in list.as_array().into_iter().flatten() {
            only(p, &["pointer", "edge"], kind)?;
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::parse_refs;
    use calve_integration_contract::refs::{self, MAX_DEPTH, MAX_MATCHES, MAX_POINTERS};
    use serde_json::{Value, json};

    fn doc(kinds: Value) -> Value {
        json!({"schema": refs::SCHEMA, "kinds": kinds})
    }

    fn ptr(p: &str) -> Value {
        json!({"pointer": p, "edge": "ObjectRef"})
    }

    /// N77: pointers are bounded in count, depth and matches; the version must be exactly
    /// calve.refs/1; malformed and unknown fields fail closed.
    #[test]
    fn reference_pointers_are_bounded_versioned_and_strict() {
        let toy: Value = serde_json::from_str(calve_testkit_refs()).unwrap();
        assert!(parse_refs(&toy).is_ok());
        let bad = |d: Value, why: &str| assert!(parse_refs(&d).is_err(), "{why}: {d}");
        // Versions.
        bad(
            json!({"schema": "calve.refs/2", "kinds": {}}),
            "a later version",
        );
        bad(json!({"kinds": {}}), "no version");
        bad(
            json!({"schema": 1, "kinds": {}}),
            "a version that is not a string",
        );
        // Malformed and unknown fields.
        bad(
            json!({"schema": refs::SCHEMA, "kinds": {}, "extra": 1}),
            "unknown top-level field",
        );
        bad(
            doc(json!({"k": [{"pointer": "/a", "edge": "ObjectRef", "optional": true}]})),
            "unknown entry field",
        );
        bad(doc(json!({"k": ["/a"]})), "an entry that is not an object");
        bad(doc(json!([])), "kinds that are not an object");
        bad(doc(json!({"k": {}})), "a list that is not an array");
        bad(doc(json!({"k": [{"pointer": "/a"}]})), "no edge");
        bad(doc(json!({"k": [{"edge": "ObjectRef"}]})), "no pointer");
        bad(doc(json!({"k": [ptr("a")]})), "a relative pointer");
        // Count and depth bounds, at and past the limit.
        assert!(parse_refs(&doc(json!({"k": vec![ptr("/a"); MAX_POINTERS]}))).is_ok());
        bad(
            doc(json!({"k": vec![ptr("/a"); MAX_POINTERS + 1]})),
            "too many pointers",
        );
        let deep = |n: usize| format!("/{}", vec!["a"; n].join("/"));
        assert!(parse_refs(&doc(json!({"k": [ptr(&deep(MAX_DEPTH))]}))).is_ok());
        bad(doc(json!({"k": [ptr(&deep(MAX_DEPTH + 1))]})), "too deep");
        // Match bounds when resolving, and a pointer that resolves to nothing.
        let many = |n: usize| json!({"xs": vec![json!({"d": "x"}); n]});
        assert_eq!(
            refs::resolve(&many(MAX_MATCHES), "/xs/*/d").unwrap().len(),
            MAX_MATCHES
        );
        assert!(refs::resolve(&many(MAX_MATCHES + 1), "/xs/*/d").is_err());
        assert!(refs::resolve(&many(1), "/xs/*/missing").is_err());
    }

    fn calve_testkit_refs() -> &'static str {
        r#"{"kinds":{"org.example.toy.put":[{"edge":"ContentHash","pointer":"/digest"}]},"schema":"calve.refs/1"}"#
    }

    #[test]
    fn every_object_kind_is_classified() {
        for k in openaevc::protocol::ObjectKind::ALL {
            let _ = super::classify(*k);
        }
    }
}
