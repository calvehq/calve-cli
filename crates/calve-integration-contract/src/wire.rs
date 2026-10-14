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
