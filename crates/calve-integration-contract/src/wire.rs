//! CIC wire v1 message model and the path-local / streaming shapes (rev 10 §6.3–§6.5b).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request envelope: `{"v":"1.k","seq":n,"op":…,"body":…}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: String,
    pub seq: u64,
    pub op: String,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

/// Response envelope: exactly one of `ok` / `err`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<WireError>,
}

/// One manifest entry (§6.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Symlink,
    Dir,
}

/// Merge-joined tuple delivered to path-local streaming ops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tuple {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work: Option<Entry>,
}

/// Capture op per tuple (exactly one per input tuple, same order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureOp {
    Add {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_key: Option<String>,
    },
    Modify {
        path: String,
    },
    Delete {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_key: Option<String>,
    },
    Unchanged {
        path: String,
    },
    Refuse {
        path: String,
        reason: String,
    },
}

impl CaptureOp {
    pub fn path(&self) -> &str {
        match self {
            CaptureOp::Add { path, .. }
            | CaptureOp::Modify { path }
            | CaptureOp::Delete { path, .. }
            | CaptureOp::Unchanged { path }
            | CaptureOp::Refuse { path, .. } => path,
        }
    }
}

/// Validation of one path-local capture chunk response (§6.4): exact cardinality, same order,
/// byte-equal paths, op kind allowed for the tuple shape.
pub fn validate_capture_chunk(tuples: &[Tuple], ops: &[CaptureOp]) -> Result<(), String> {
    if tuples.len() != ops.len() {
        return Err(format!(
            "cardinality: {} tuples, {} ops",
            tuples.len(),
            ops.len()
        ));
    }
    for (t, op) in tuples.iter().zip(ops) {
        if op.path() != t.path {
            return Err(format!("path mismatch: {} vs {}", op.path(), t.path));
        }
        let ok = match op {
            CaptureOp::Add { .. } => t.base.is_none() && t.work.is_some(),
            CaptureOp::Delete { .. } => t.base.is_some() && t.work.is_none(),
            CaptureOp::Modify { .. } => matches!((&t.base, &t.work), (Some(b), Some(w)) if b != w),
            CaptureOp::Unchanged { .. } => {
                matches!((&t.base, &t.work), (Some(b), Some(w)) if b == w)
            }
            CaptureOp::Refuse { .. } => true,
        };
        if !ok {
            return Err(format!("op {op:?} not allowed for tuple {}", t.path));
        }
    }
    Ok(())
}

/// Per-kind relation outcome at relate `finish` (§6.5b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KindStatus {
    Complete,
    Refused(String),
}

/// `detect` (§6.4): the names present at the Project root and the file extensions seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectIn {
    pub markers: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectOut {
    pub languages: Vec<String>,
}

/// `check_plan` (§6.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckPlanIn {
    pub languages: Vec<String>,
    pub markers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedCheck {
    pub language: String,
    pub name: String,
    pub argv: Vec<String>,
    /// The tool takes the language's source files as trailing arguments.
    #[serde(default)]
    pub takes_files: bool,
    /// Environment variables passed through; everything else is cleared.
    #[serde(default)]
    pub env: Vec<String>,
    /// File extensions (without dot) of the language's sources.
    #[serde(default)]
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckPlanOut {
    pub checks: Vec<PlannedCheck>,
}

/// `classify` (§6.4): exactly one decision per entry, same order and paths. Each batch carries
/// every ignore source applicable to its paths (ancestor directories), so batches are
/// independent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifyEntry {
    pub path: String,
    pub kind: EntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifyIn {
    pub entries: Vec<ClassifyEntry>,
    /// Ignore-source path (e.g. `src/.calveignore`) → its text.
    pub ignore_sources: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub path: String,
    pub ignored: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifyOut {
    pub decisions: Vec<Decision>,
}

/// Exact validation of a `classify` response: one decision per entry, same order, byte-equal
/// paths.
pub fn validate_classify(sent: &[ClassifyEntry], got: &[Decision]) -> Result<(), String> {
    if sent.len() != got.len() {
        return Err(format!(
            "cardinality: {} entries, {} decisions",
            sent.len(),
            got.len()
        ));
    }
    match sent.iter().zip(got).find(|(e, d)| e.path != d.path) {
        Some((e, d)) => Err(format!("path mismatch: {} vs {}", d.path, e.path)),
        None => Ok(()),
    }
}

/// `diff` (§6.4): content inline (base64), at most 1 MiB per side; larger never sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffIn {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    pub context: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hunk {
    pub old_start: u64,
    pub old_lines: u64,
    pub new_start: u64,
    pub new_lines: u64,
    /// Lines prefixed with ' ', '-' or '+'.
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiffOut {
    Binary,
    TooLarge,
    Hunks { hunks: Vec<Hunk> },
}

/// Diff content limit per side.
pub const MAX_DIFF_SIDE: u64 = 1024 * 1024;
