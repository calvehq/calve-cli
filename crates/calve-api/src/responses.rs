//! Typed `--json` responses (ADR 0020, M4 requirement 1). For these commands the response type
//! is the contract: Calve builds the output from it, the published v1 schema is generated from
//! it (optional fields, nullability and every enum variant come from the type, not from what a
//! test happened to print), and every recorded output must deserialize into it with no unknown
//! field. Other commands still carry schemas inferred from recorded output.
use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// State of a materialization operation (§14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum MaterializeState {
    /// Steps remain, or provenance is not recorded yet: `calve materialize resume`.
    Interrupted,
    /// A step found unexpected content: `calve materialize resolve`.
    Conflicted,
    Completed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepRef {
    pub step: String,
    pub path: String,
}

/// `calve materialize list` item.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterializeOperation {
    pub op: String,
    /// Absent only for a journal interrupted before its plan was recorded.
    pub label: Option<String>,
    pub state: MaterializeState,
    /// Unresolved conflicts.
    pub conflicts: Vec<StepRef>,
}

/// `calve materialize resume` / `resolve`: the operation driven to `Completed`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterializeCompleted {
    pub op: String,
    pub state: MaterializeState,
    /// The OpenAEVC execution holding the provenance observations.
    pub execution: String,
    pub provenance_pack: String,
    /// Paths of the planned steps.
    pub written: Vec<String>,
    /// `linux-renameat2` or `fallback`.
    pub primitives: String,
    /// `resolve` only: paths whose conflict was resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<Vec<String>>,
}

/// `calve materialize rollback`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterializeRolledBack {
    pub op: String,
    pub state: MaterializeState,
    pub reverted: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxCounts {
    /// Unresolved, unacknowledged, unsnoozed items.
    pub attention: u64,
    pub danger: u64,
    /// Last refresh of that Project's Inbox (Unix seconds); null when it has no items.
    pub as_of: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxSummaryProject {
    pub project_id: String,
    pub name: String,
    pub path: String,
    /// Absent when the Project's database could not be read (then `error` says why).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox: Option<InboxCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `calve inbox summary`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxSummary {
    pub projects: Vec<InboxSummaryProject>,
}

/// Who removes a GC class (§44.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GcOwner {
    OpenaevcRuntime,
    CalveProduct,
    FilesystemCache,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GcClass {
    pub class: String,
    pub owner: GcOwner,
    pub count: u64,
    pub estimated_bytes: u64,
    pub reason: String,
    /// Up to 20 Project-relative paths.
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GcRemoved {
    pub class: String,
    pub owner: GcOwner,
    pub removed: u64,
    /// OpenAEVC's collector only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned: Option<u64>,
}

/// `calve maintenance gc`: with `--dry-run`, `classes`; otherwise `planned` and `removed`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GcReport {
    pub dry_run: bool,
    pub grace_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classes: Option<Vec<GcClass>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planned: Option<Vec<GcClass>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<GcRemoved>>,
}

/// State of a capture session (§12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CaptureState {
    Planned,
    Submitting,
    Submitted,
    FailedSubmit,
    /// The candidate changed under the session; roll it back and capture again.
    Diverged,
    /// An attempt ended without success after applying effects; roll it back.
    Lost,
    Done,
    Superseded,
    Compensated,
    Abandoned,
}

/// `calve capture list` item.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureSession {
    pub session: String,
    pub pack: String,
    pub state: CaptureState,
    pub attempts: u64,
    /// The step of an intent without an outcome (resume settles it).
    pub pending_intent: Option<String>,
}

/// State of a supersede saga (§12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SupersedeState {
    Planned,
    CaptureClosed,
    ReplacementCreated,
    ReplayStarted,
    ReplayCompleted,
    Verified,
    Revalidated,
    ProductRelinked,
    OriginalAbandoned,
    Done,
    Diverged,
    Conflict,
    Conflicted,
    RecoveryRequired,
}

/// `calve supersede list` item.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupersedeSaga {
    pub saga: String,
    pub pack: String,
    pub state: SupersedeState,
    pub replacement: Option<String>,
    /// `superseded` once done.
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActiveBaseline {
    pub id: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusPack {
    pub id: String,
    pub title: String,
    pub generation: u64,
    /// A pending supersession of this pack (§12).
    pub superseding: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusPacks {
    pub open: u64,
    pub sealed: u64,
    pub qualified: u64,
    /// By lowercase state (`open`, `sealed`, `qualified`).
    pub items: BTreeMap<String, Vec<StatusPack>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusTasks {
    pub total: u64,
    pub blocked: u64,
    /// Blocked or inconsistent tasks, as `task list` shows them.
    pub attention: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionRef {
    pub kind: String,
    /// The pack or operation the item is about.
    pub pack: String,
    pub summary: String,
    pub source_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusBlockers {
    pub verification: Vec<AttentionRef>,
    pub review: Vec<AttentionRef>,
}

/// `calve status` (§17.5): a derived read model, never a second authority.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// Project identity (`project_id`, `namespace_id`, …) and `name`.
    pub project: Value,
    pub active_baseline: Option<ActiveBaseline>,
    pub packs: StatusPacks,
    pub tasks: StatusTasks,
    /// OpenAEVC executions that are PENDING, ADMITTED, STARTING or RUNNING.
    pub active_executions: Vec<Value>,
    /// A count, or `{"error"}` when no file domain is enabled.
    pub uncaptured_changes: Value,
    pub blockers: StatusBlockers,
    pub recovery: Vec<AttentionRef>,
    pub attention_items: u64,
    pub extension_problems: Vec<Value>,
    pub provider_problems: Vec<Value>,
}

fn strict<T: serde::de::DeserializeOwned>(v: &Value) -> Result<(), String> {
    serde_json::from_value::<T>(v.clone())
        .map(drop)
        .map_err(|e| e.to_string())
}

fn schema<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).unwrap_or(Value::Null)
}

/// Strict check of a recorded output against its response type.
pub type Check = fn(&Value) -> Result<(), String>;

/// The typed commands: `(command, schema of data, check)`.
pub fn typed() -> Vec<(&'static str, Value, Check)> {
    vec![
        (
            "capture list",
            schema::<Vec<CaptureSession>>(),
            strict::<Vec<CaptureSession>>,
        ),
        (
            "inbox summary",
            schema::<InboxSummary>(),
            strict::<InboxSummary>,
        ),
        ("maintenance gc", schema::<GcReport>(), strict::<GcReport>),
        (
            "materialize list",
            schema::<Vec<MaterializeOperation>>(),
            strict::<Vec<MaterializeOperation>>,
        ),
        (
            "materialize resolve",
            schema::<MaterializeCompleted>(),
            strict::<MaterializeCompleted>,
        ),
        (
            "materialize resume",
            schema::<MaterializeCompleted>(),
            strict::<MaterializeCompleted>,
        ),
        (
            "materialize rollback",
            schema::<MaterializeRolledBack>(),
            strict::<MaterializeRolledBack>,
        ),
        ("status", schema::<Status>(), strict::<Status>),
        (
            "supersede list",
            schema::<Vec<SupersedeSaga>>(),
            strict::<Vec<SupersedeSaga>>,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_carry_nullability_and_variants() {
        let s = schema::<Vec<MaterializeOperation>>().to_string();
        for v in [
            "Interrupted",
            "Conflicted",
            "Completed",
            "RolledBack",
            "null",
        ] {
            assert!(s.contains(v), "{v}: {s}");
        }
        assert!(
            strict::<MaterializeOperation>(
                &serde_json::json!({"op":"x","label":null,"state":"Completed","conflicts":[]})
            )
            .is_ok()
        );
        assert!(
            strict::<MaterializeOperation>(
                &serde_json::json!({"op":"x","label":null,"state":"Done","conflicts":[]})
            )
            .is_err()
        );
        assert!(strict::<MaterializeOperation>(&serde_json::json!({"op":"x","label":"l","state":"Completed","conflicts":[],"extra":1})).is_err());
    }
}
