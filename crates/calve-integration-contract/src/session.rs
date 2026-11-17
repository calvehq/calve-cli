//! Streaming session bodies (rev 10 §6.5, §6.5b): `capture` and `relate` as deterministic state
//! machines, and the host-side validation of each guest response.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::digest::LineHasher;
use crate::metadata::{Metadata, validate_payload};
use crate::wire::{KindStatus, Tuple};

/// Op names on the wire.
pub mod op {
    pub const DESCRIBE: &str = "describe";
    pub const DETECT: &str = "detect";
    pub const CAPTURE_BEGIN: &str = "capture.begin";
    pub const CAPTURE_CHUNK: &str = "capture.chunk";
    pub const CAPTURE_FINISH: &str = "capture.finish";
    pub const RELATE_BEGIN: &str = "relate.begin";
    pub const RELATE_GROUPS: &str = "relate.groups";
    pub const RELATE_FINISH: &str = "relate.finish";
}

/// Session states shared by every streaming op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    New,
    Ready,
    Open,
    Finished,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBegin {
    pub base_digest: String,
    pub expected_tuples: u64,
    pub params: Value,
    pub work_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureChunk {
    pub index: u64,
    pub tuples: Vec<Tuple>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureChunkOk {
    pub ops: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFinish {
    pub total_tuples: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFinishOk {
    pub output_digest: String,
    pub total_ops: u64,
}

/// One op as delivered to `relate`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub op: Value,
    pub op_index: u64,
    pub path: String,
}

/// A group by opaque `group_key`: members, or `overflow: true` with only the count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub count: u64,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<Member>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overflow: Option<bool>,
}

impl Group {
    pub fn delivered_members(&self) -> u64 {
        self.members.as_ref().map_or(0, |m| m.len() as u64)
    }

    pub fn is_well_formed(&self) -> bool {
        match (&self.members, self.overflow) {
            (Some(m), None) => !m.is_empty() && m.len() as u64 == self.count,
            (None, Some(true)) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelateBegin {
    pub groups_commitment: String,
    pub max_group: u64,
    pub params: Value,
    pub source_o: String,
    pub total_groups: u64,
    pub total_members: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelateGroups {
    pub groups: Vec<Group>,
    pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub groups_received: u64,
    pub index: u64,
    pub members_received: u64,
    pub running_groups_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relation {
    pub kind: String,
    pub members: Vec<u64>,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelateChunkOk {
    pub ack: Ack,
    pub relations: Vec<Relation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelateFinish {
    pub total_groups: u64,
    pub total_members: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindOutcome {
    pub kind: String,
    pub status: KindStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelateFinishOk {
    pub groups_digest_seen: String,
    pub kinds: Vec<KindOutcome>,
    pub relations_digest: String,
    pub total_groups_seen: u64,
    pub total_members_seen: u64,
    pub total_relations: u64,
}

/// Host-side tracker of one relate session (§6.5b). Every guest response goes through it;
/// any error means `ABI_VIOLATION` and the whole session's relations are discarded.
#[derive(Debug)]
pub struct RelateVerifier<'m> {
    meta: &'m Metadata,
    begin: RelateBegin,
    next_index: u64,
    groups: u64,
    members: u64,
    groups_hash: LineHasher,
    relations_hash: LineHasher,
    relations: Vec<Relation>,
    kinds_emitted: BTreeSet<String>,
}

impl<'m> RelateVerifier<'m> {
    pub fn new(meta: &'m Metadata, begin: RelateBegin) -> Self {
        RelateVerifier {
            meta,
            begin,
            next_index: 0,
            groups: 0,
            members: 0,
            groups_hash: LineHasher::new(),
            relations_hash: LineHasher::new(),
            relations: Vec::new(),
            kinds_emitted: BTreeSet::new(),
        }
    }

    /// Validates one `relate.groups` response against the chunk the host sent.
    pub fn chunk(&mut self, sent: &RelateGroups, got: RelateChunkOk) -> Result<(), String> {
        if sent.index != self.next_index {
            return Err(format!("host sent chunk {} out of order", sent.index));
        }
        let mut in_chunk = BTreeSet::new();
        for g in &sent.groups {
            self.groups_hash
                .push(&serde_json::to_value(g).expect("group"))
                .map_err(|_| "float in group")?;
            self.groups += 1;
            self.members += g.delivered_members();
            in_chunk.extend(g.members.iter().flatten().map(|m| m.op_index));
        }
        self.next_index += 1;
        let want = Ack {
            groups_received: self.groups,
            index: sent.index,
            members_received: self.members,
            running_groups_digest: self.groups_hash.peek(),
        };
        if got.ack != want {
            return Err(format!("ack mismatch: got {:?}, want {want:?}", got.ack));
        }
        let mut prev: Option<(&str, u64)> = None;
        for r in &got.relations {
            let decl = self
                .meta
                .relations
                .iter()
                .find(|d| d.kind == r.kind)
                .ok_or_else(|| format!("undeclared relation kind {}", r.kind))?;
            if !r.kind.starts_with(&format!("{}.", self.meta.extension_id)) {
                return Err(format!(
                    "kind {} not prefixed with the extension id",
                    r.kind
                ));
            }
            let first = *r.members.first().ok_or("relation without members")?;
            let unique: BTreeSet<_> = r.members.iter().collect();
            if unique.len() != r.members.len() {
                return Err("duplicate relation member".into());
            }
            if let Some(m) = r.members.iter().find(|m| !in_chunk.contains(m)) {
                return Err(format!("member {m} is not an op of this chunk's groups"));
            }
            validate_payload(&decl.schema, &r.payload).map_err(|e| format!("payload: {e}"))?;
            if prev.is_some_and(|p| p > (r.kind.as_str(), first)) {
                return Err("relations not sorted by (kind, first member)".into());
            }
            prev = Some((&r.kind, first));
        }
        for r in got.relations {
            self.relations_hash
                .push(&serde_json::to_value(&r).expect("relation"))
                .map_err(|_| "float in relation")?;
            self.kinds_emitted.insert(r.kind.clone());
            self.relations.push(r);
        }
        Ok(())
    }

    /// Validates the `relate.finish` response; returns the accepted relations and outcomes.
    pub fn finish(
        self,
        got: RelateFinishOk,
    ) -> Result<(Vec<Relation>, Vec<KindOutcome>, String), String> {
        let commitment = self.groups_hash.peek();
        if self.groups != self.begin.total_groups
            || self.members != self.begin.total_members
            || commitment != self.begin.groups_commitment
        {
            return Err("host stream differs from its own commitment".into());
        }
        if got.total_groups_seen != self.groups
            || got.total_members_seen != self.members
            || got.groups_digest_seen != commitment
        {
            return Err("guest did not process exactly the committed input".into());
        }
        let r = self.relations_hash.finish();
        if got.relations_digest != r || got.total_relations != self.relations.len() as u64 {
            return Err("relations digest/count mismatch".into());
        }
        let declared: Vec<&str> = self
            .meta
            .relations
            .iter()
            .map(|d| d.kind.as_str())
            .collect();
        let mut reported: Vec<&str> = got.kinds.iter().map(|k| k.kind.as_str()).collect();
        reported.sort();
        let mut want = declared.clone();
        want.sort();
        if reported != want {
            return Err(format!("kinds {reported:?} != declared {want:?}"));
        }
        for k in &got.kinds {
            if matches!(k.status, KindStatus::Refused(_)) && self.kinds_emitted.contains(&k.kind) {
                return Err(format!("refused kind {} emitted relations", k.kind));
            }
        }
        Ok((self.relations, got.kinds, r))
    }
}

/// Merge join of two path-sorted, path-unique manifests into tuples in byte-wise path order.
pub fn merge_join(base: &[crate::wire::Entry], work: &[crate::wire::Entry]) -> Vec<Tuple> {
    let (mut i, mut j, mut out) = (0, 0, Vec::with_capacity(base.len().max(work.len())));
    while i < base.len() || j < work.len() {
        let ord = match (base.get(i), work.get(j)) {
            (Some(b), Some(w)) => b.path.as_bytes().cmp(w.path.as_bytes()),
            (Some(_), None) => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Greater,
        };
        let (b, w) = match ord {
            std::cmp::Ordering::Less => (base.get(i).cloned(), None),
            std::cmp::Ordering::Greater => (None, work.get(j).cloned()),
            std::cmp::Ordering::Equal => (base.get(i).cloned(), work.get(j).cloned()),
        };
        i += usize::from(b.is_some());
        j += usize::from(w.is_some());
        let path = b.as_ref().or(w.as_ref()).expect("one side").path.clone();
        out.push(Tuple {
            path,
            base: b,
            work: w,
        });
    }
    out
}

/// Generic, domain-agnostic grouping of ops by their opaque `group_key` (§6.5): sorted by
/// `(key, path, op_index)`; groups larger than `max_group` are delivered as overflow.
// ponytail: in-memory sort; M2 replaces it with the bounded on-disk external sort (§6.6).
pub fn group_ops(ops: &[Value], max_group: u64) -> Vec<Group> {
    let mut keyed: Vec<(&str, &str, u64, &Value)> = ops
        .iter()
        .enumerate()
        .filter_map(|(i, op)| {
            Some((
                op.get("group_key")?.as_str()?,
                op.get("path")?.as_str()?,
                i as u64,
                op,
            ))
        })
        .collect();
    keyed.sort_by(|a, b| {
        (a.0.as_bytes(), a.1.as_bytes(), a.2).cmp(&(b.0.as_bytes(), b.1.as_bytes(), b.2))
    });
    let mut groups = Vec::new();
    for run in keyed.chunk_by(|a, b| a.0 == b.0) {
        let count = run.len() as u64;
        let key = run[0].0.to_owned();
        groups.push(if count > max_group {
            Group {
                count,
                key,
                members: None,
                overflow: Some(true),
            }
        } else {
            let members = run
                .iter()
                .map(|(_, p, i, op)| Member {
                    op: (*op).clone(),
                    op_index: *i,
                    path: (*p).to_owned(),
                })
                .collect();
            Group {
                count,
                key,
                members: Some(members),
                overflow: None,
            }
        });
    }
    groups
}

/// The `relate.begin` commitment over a full grouped stream.
pub fn commitment(groups: &[Group]) -> (u64, u64, String) {
    let mut h = LineHasher::new();
    let mut members = 0;
    for g in groups {
        h.push(&serde_json::to_value(g).expect("group"))
            .expect("integer-only");
        members += g.delivered_members();
    }
    (groups.len() as u64, members, h.finish())
}

/// Host-side tracker of one capture session: chunk order, strictly increasing paths across
/// chunks, exact per-tuple validation, and the independently computed output digest `O`.
#[derive(Debug, Default)]
pub struct CaptureVerifier {
    next_index: u64,
    last_path: Option<String>,
    tuples: u64,
    ops: LineHasher,
}

impl CaptureVerifier {
    pub fn chunk(&mut self, sent: &CaptureChunk, got: &CaptureChunkOk) -> Result<(), String> {
        if sent.index != self.next_index {
            return Err("chunk out of order".into());
        }
        for t in &sent.tuples {
            if self
                .last_path
                .as_deref()
                .is_some_and(|p| p.as_bytes() >= t.path.as_bytes())
            {
                return Err(format!("host tuple {} not strictly increasing", t.path));
            }
            self.last_path = Some(t.path.clone());
        }
        let typed: Vec<crate::wire::CaptureOp> = got
            .ops
            .iter()
            .map(|o| serde_json::from_value(o.clone()).map_err(|e| format!("op schema: {e}")))
            .collect::<Result<_, _>>()?;
        crate::wire::validate_capture_chunk(&sent.tuples, &typed)?;
        for o in &got.ops {
            self.ops.push(o).map_err(|_| "float in op")?;
        }
        self.next_index += 1;
        self.tuples += sent.tuples.len() as u64;
        Ok(())
    }

    /// Checks `finish` and returns the host-computed `O`.
    pub fn finish(self, got: &CaptureFinishOk) -> Result<String, String> {
        let o = self.ops.finish();
        if got.total_ops != self.tuples || got.output_digest != o {
            return Err(format!(
                "finish mismatch: guest O {} / host O {o}",
                got.output_digest
            ));
        }
        Ok(o)
    }
}
