//! Baselines read from OpenAEVC (rev 10 §27; P6–P8). Calve's product tables are indexes and
//! labels only: listing, validation, aliases, comparison and materialization all start from the
//! Baseline objects in the Namespace, so Baselines that were adopted, transferred or created
//! while the product database was missing behave like any other.
//!
//! Composition order is OpenAEVC's: `topo_order` over the Baseline's edges (a member applies
//! after every member it requires, orders after or revises), ties broken by digest. Two members
//! that write the same path with no edge between them are reported as `unordered_overlaps`; the
//! deterministic tie-break is never presented as a decision.
use std::collections::{BTreeMap, BTreeSet};

use openaevc::protocol::{
    AppliedEffect, Baseline, Candidate, CompositionEdge, CompositionEdgeKind, Digest, Metadata,
    ObjectEnvelope, ObjectKind, PromotedPack, Query, RevisionRelation,
};
use openaevc_sdk::OpenAevcClient;
use serde_json::{Value, json};

use crate::{Error, Project, Result};

fn invalid(m: impl Into<String>) -> Error {
    Error::Message(m.into())
}

/// One composed member with the effects of its promoted candidate.
pub struct Member {
    pub digest: Digest,
    pub promoted: PromotedPack,
    pub effects: Vec<AppliedEffect>,
}

/// Accepted file state of a composition, by digest; the effect that produced each file is kept
/// so its content can be resolved (inline or chunked) when needed.
#[derive(Default)]
pub struct ComposedFiles {
    pub files: BTreeMap<String, (String, AppliedEffect)>,
    pub removed: BTreeSet<String>,
    /// Paths written by members with no ordering edge between them.
    pub unordered_overlaps: BTreeMap<String, Vec<Digest>>,
}

/// Baseline label metadata Calve sets at creation (rebuildable after product DB loss).
pub(crate) fn baseline_metadata(label: &str, derived_from: Option<Digest>) -> Metadata {
    let mut m = Metadata::new();
    m.insert("org.calve.label".into(), json!(label));
    if let Some(d) = derived_from {
        m.insert("org.calve.derived_from".into(), json!(d));
    }
    m
}

fn parse_envelope(v: &Value, kind: ObjectKind) -> Result<(Digest, ObjectEnvelope)> {
    let digest: Digest = serde_json::from_value(v["digest"].clone())?;
    let env: ObjectEnvelope = serde_json::from_value(v["envelope"].clone())?;
    if env.kind != kind {
        return Err(invalid(format!("{digest} is not a {kind:?}")));
    }
    Ok((digest, env))
}

impl Project {
    /// Every Baseline object in the Namespace with its digest, oldest first by creation event.
    pub async fn protocol_baselines(&self) -> Result<Vec<(Digest, Baseline)>> {
        let mut out = vec![];
        let mut after = None;
        loop {
            let page = self
                .client
                .query(Query::ListObjectDigests {
                    kind: Some(ObjectKind::Baseline),
                    after,
                    limit: None,
                })
                .await?;
            for o in page["objects"].as_array().into_iter().flatten() {
                let digest: Digest = serde_json::from_value(o["digest"].clone())?;
                let v = self.client.query(Query::GetObject { digest }).await?;
                let (_, env) = parse_envelope(&v, ObjectKind::Baseline)?;
                if env.namespace == self.identity.namespace_id {
                    out.push((digest, serde_json::from_value(env.body)?));
                }
            }
            match serde_json::from_value::<Option<Digest>>(page["next"].clone())? {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Ok(out)
    }

    /// A Baseline by id or alias, with its object digest.
    pub async fn baseline_object(&self, id_or_alias: &str) -> Result<(Digest, Baseline)> {
        let id = self.resolve_baseline_id(id_or_alias)?;
        let v = self
            .client
            .query(Query::GetBaseline { baseline: id })
            .await?;
        let (digest, env) = parse_envelope(&v, ObjectKind::Baseline)?;
        if env.namespace != self.identity.namespace_id {
            return Err(invalid("unexpected Baseline object"));
        }
        let b: Baseline = serde_json::from_value(env.body)?;
        if b.id != id {
            return Err(crate::coded(
                "CORRUPT_PRODUCT_STATE",
                "Baseline identity mismatch",
            ));
        }
        Ok((digest, b))
    }

    /// The label: the product index, else the label recorded in the object.
    pub(crate) fn baseline_label(&self, b: &Baseline) -> Option<String> {
        self.db
            .query_row(
                "SELECT label FROM baseline_metadata WHERE id=?1",
                [b.id.to_string()],
                |r| r.get(0),
            )
            .ok()
            .or_else(|| {
                b.metadata
                    .get("org.calve.label")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
    }

    pub async fn promoted_pack(&self, digest: Digest) -> Result<PromotedPack> {
        let v = self
            .client
            .query(Query::GetPromotedPack {
                pack: None,
                digest: Some(digest),
            })
            .await?;
        let env: ObjectEnvelope = serde_json::from_value(v["envelope"].clone())?;
        Ok(serde_json::from_value(env.body)?)
    }

    async fn candidate(&self, digest: Digest) -> Result<Candidate> {
        let v = self.client.query(Query::GetObject { digest }).await?;
        let (_, env) = parse_envelope(&v, ObjectKind::Candidate)?;
        Ok(serde_json::from_value(env.body)?)
    }

    /// Members in composition order.
    pub async fn composed_members(&self, b: &Baseline) -> Result<Vec<Member>> {
        let pairs: Vec<(Digest, Digest)> = b.edges.iter().map(|e| (e.from, e.to)).collect();
        let order = openaevc::core::graph::topo_order(&b.members, &pairs)
            .map_err(|_| crate::coded("CORRUPT_PRODUCT_STATE", "Baseline graph has a cycle"))?;
        let mut out = vec![];
        for digest in order {
            let promoted = self.promoted_pack(digest).await?;
            let effects = self.candidate(promoted.candidate).await?.effects;
            out.push(Member {
                digest,
                promoted,
                effects,
            });
        }
        Ok(out)
    }

    /// File state of a Baseline (file domain effects in composition order).
    pub async fn composed_files(&self, b: &Baseline) -> Result<ComposedFiles> {
        let mut out = ComposedFiles::default();
        let Ok(d) = self.file_domain().await else {
            return Ok(out);
        };
        let ordered: BTreeSet<(Digest, Digest)> = b
            .edges
            .iter()
            .flat_map(|e| [(e.from, e.to), (e.to, e.from)])
            .collect();
        let mut writer: BTreeMap<String, Digest> = BTreeMap::new();
        for m in self.composed_members(b).await? {
            for e in m.effects.iter().filter(|e| d.is_file_effect(e)) {
                let path = e.target.locator.clone();
                crate::validate_locator(&path)?;
                if let Some(prev) = writer.insert(path.clone(), m.digest)
                    && prev != m.digest
                    && !ordered.contains(&(prev, m.digest))
                {
                    let o = out.unordered_overlaps.entry(path.clone()).or_default();
                    for x in [prev, m.digest] {
                        if !o.contains(&x) {
                            o.push(x);
                        }
                    }
                }
                match d.op(&e.kind) {
                    Some(crate::domains::FileOp::Put) => {
                        out.removed.remove(&path);
                        let digest = e.payload["digest"].as_str().unwrap_or_default().to_owned();
                        out.files.insert(path, (digest, e.clone()));
                    }
                    Some(crate::domains::FileOp::Delete) => {
                        out.files.remove(&path);
                        out.removed.insert(path);
                    }
                    Some(crate::domains::FileOp::Move) => {
                        let from = e.payload["from"].as_str().unwrap_or_default().to_owned();
                        out.files.remove(&from);
                        out.removed.insert(from);
                        out.removed.remove(&path);
                        let digest = e.payload["digest"].as_str().unwrap_or_default().to_owned();
                        out.files.insert(path, (digest, e.clone()));
                    }
                    None => {}
                }
            }
        }
        Ok(out)
    }

    /// Revision relations inside a Baseline: `(revision member, relation, target, target present)`.
    pub async fn baseline_revisions(&self, b: &Baseline) -> Result<Vec<Value>> {
        let mut out = vec![];
        for m in &b.members {
            if let Some(rev) = self.promoted_pack(*m).await?.revision {
                for t in rev.targets {
                    out.push(json!({"revision": m, "relation": rev.relation, "target": t,
                        "target_present": b.members.contains(&t)}));
                }
            }
        }
        Ok(out)
    }

    /// Members and caller edges of a derived Baseline (§27.2): `base` plus `add`, minus `remove`;
    /// `replace` adds RevisionPacks and, for `supersedes`, removes their targets (a reversal or
    /// amendment keeps its targets, which OpenAEVC requires). Revision edges are recomputed by
    /// OpenAEVC; only REQUIRES/ORDERS_AFTER caller edges carry over.
    pub async fn derived_composition(
        &self,
        base: &Baseline,
        add: &[Digest],
        remove: &[Digest],
        replace: &[Digest],
        edges: &[CompositionEdge],
    ) -> Result<(Vec<Digest>, Vec<CompositionEdge>)> {
        let mut members: BTreeSet<Digest> = base.members.iter().copied().collect();
        members.extend(add.iter().copied());
        for r in replace {
            let p = self.promoted_pack(*r).await?;
            let rev = p.revision.ok_or_else(|| {
                crate::coded(
                    "INVALID_ARGUMENT",
                    format!("{r} is not a promoted RevisionPack"),
                )
            })?;
            members.insert(*r);
            if rev.relation == RevisionRelation::Supersedes {
                for t in rev.targets {
                    members.remove(&t);
                }
            }
        }
        for r in remove {
            if !members.remove(r) {
                return Err(crate::coded(
                    "INVALID_ARGUMENT",
                    format!("{r} is not a member of the base Baseline"),
                ));
            }
        }
        let mut out: BTreeSet<CompositionEdge> = base
            .edges
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    CompositionEdgeKind::Requires | CompositionEdgeKind::OrdersAfter
                ) && e.relation.is_none()
                    && members.contains(&e.from)
                    && members.contains(&e.to)
            })
            .cloned()
            .collect();
        out.extend(edges.iter().cloned());
        Ok((members.into_iter().collect(), out.into_iter().collect()))
    }
}
