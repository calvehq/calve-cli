//! Calve application layer: Projects, the product store, and every use case behind the API.
#![forbid(unsafe_code)]

pub use calve_api::{ActivityFilter, GrantOptions};
pub use calve_domain::{general, language as domain};

pub mod adopt;
pub mod app;
pub mod checks;
pub mod compatibility;
pub mod config;
pub mod extensions;
pub mod extsort;
pub mod general_ops;
pub mod identities;
pub mod ignore;
pub mod integration;
pub mod manifests;
pub mod materialize;
pub mod observe;
pub mod ops;
pub mod providers;
pub mod registry;
pub mod resources;
pub mod sandbox;
pub mod views;
pub mod workspace_io;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use openaevc::core::{IdGeneratorExt, SystemClock, UuidV7Ids};
use openaevc::crypto::{Signer, SigningKey, sha256};
use openaevc::protocol::{
    Baseline, BaselineId, Blob, ChangePack, Command, Digest, EffectProposal, ErrorCode, Event,
    EvidenceCondition, ExecutionId, ExecutionRequest, ExecutionState, Expr, GrantBody, GrantId,
    Metadata, NamespaceId, NewPrincipal, NodeRef, ObjectEnvelope, ObjectKind, PackId, PackSpec,
    PackState, PolicyDocument, PolicyRule, PrincipalId, PrincipalKind, ProviderDescriptor, Query,
    ResourceRef, ResourceSelector, RevisionRelation, Timestamp, VerificationStatus,
    VerifierCondition, WorkUnitId, WorkerInfo,
};
use openaevc::runtime::{Admin, Runtime, RuntimeConfig, RuntimeDeps};
use openaevc::store::{SqliteOptions, SqliteStore};
use openaevc_sdk::{EmbeddedClient, OpenAevcClient, Session, TypedClient};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("project writer is busy: {0}")]
    Busy(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Protocol(Box<openaevc::protocol::ProtocolError>),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    TomlRead(#[from] toml::de::Error),
    #[error(transparent)]
    TomlWrite(#[from] toml::ser::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<openaevc::protocol::ProtocolError> for Error {
    fn from(error: openaevc::protocol::ProtocolError) -> Self {
        Self::Protocol(Box::new(error))
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

const SOFTWARE_EXTENSION: &str = "org.calve.software";
const SOFTWARE_RESOURCE: &str = "org.calve.software.file";
const SOFTWARE_EFFECT: &str = "org.calve.software.snapshot";
const SOFTWARE_VERIFIER: &str = "org.calve.software.snapshot.verify";
const SOFTWARE_EVALUATOR: &str = "org.calve.software.change-size";
const SOFTWARE_PROVIDER: &str = "org.calve.software.local";
const SOFTWARE_HARNESS: &str = "org.calve.software.capture";
const REVIEW_POLICY_NAME: &str = "org.calve.review.required/v1";
const REVIEW_APPROVAL_KIND: &str = "org.calve.review.approval/v1";
const REVIEW_REJECTION_KIND: &str = "org.calve.review.rejection/v1";
const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;
const CHECKPOINT_INTERVAL: u64 = 1000;
const CAPTURE_MAX_ATTEMPTS: u32 = 3;

/// Matching rules for the API's activity filter.
pub(crate) trait ActivityRules {
    fn time_bounds(&self) -> Result<(Option<i128>, Option<i128>)>;
    fn needs_full_scan(&self) -> bool;
    fn matches(&self, row: &Value, nanos: i128, bounds: (Option<i128>, Option<i128>)) -> bool;
}

impl ActivityRules for ActivityFilter {
    fn time_bounds(&self) -> Result<(Option<i128>, Option<i128>)> {
        let parse = |value: &Option<String>| -> Result<Option<i128>> {
            value
                .as_ref()
                .map(|s| {
                    s.parse::<Timestamp>()
                        .map(|t| t.unix_nanos())
                        .map_err(|e| invalid(e.to_string()))
                })
                .transpose()
        };
        let (since, until) = (parse(&self.since)?, parse(&self.until)?);
        if since.zip(until).is_some_and(|(start, end)| start > end) {
            return Err(invalid("activity --since must be before --until"));
        }
        if self
            .source
            .as_deref()
            .is_some_and(|source| source != "calve" && source != "openaevc")
        {
            return Err(invalid("activity --source must be calve or openaevc"));
        }
        Ok((since, until))
    }

    fn needs_full_scan(&self) -> bool {
        self.actor.is_some()
            || self.object_kind.is_some()
            || self.pack.is_some()
            || self.task.is_some()
            || self.execution.is_some()
            || self.since.is_some()
            || self.until.is_some()
            || self.severity.is_some()
            || self.event_type.is_some()
    }

    fn matches(&self, row: &Value, nanos: i128, bounds: (Option<i128>, Option<i128>)) -> bool {
        if bounds.0.is_some_and(|since| nanos < since)
            || bounds.1.is_some_and(|until| nanos > until)
        {
            return false;
        }
        let equal = |field: &str, expected: &Option<String>| {
            expected
                .as_deref()
                .is_none_or(|value| row[field].as_str() == Some(value))
        };
        if !equal("source", &self.source)
            || !equal("actor", &self.actor)
            || !equal("kind", &self.event_type)
        {
            return false;
        }
        if let Some(kind) = &self.object_kind {
            let event_kind = row["kind"].as_str().unwrap_or("");
            if event_kind.split('.').next() != Some(kind.as_str()) {
                return false;
            }
        }
        if let Some(severity) = &self.severity
            && row["severity"]
                .as_str()
                .or_else(|| row["body"]["severity"].as_str())
                != Some(severity.as_str())
        {
            return false;
        }
        [&self.pack, &self.task, &self.execution]
            .into_iter()
            .flatten()
            .all(|reference| {
                row["subjects"]
                    .as_array()
                    .is_some_and(|subjects| subjects.iter().any(|subject| subject == reference))
                    || row["detail"].as_str() == Some(reference)
                    || value_contains_exact(&row["body"], reference)
            })
    }
}

/// Cuts text at a char boundary so untrusted output cannot split a UTF-8 sequence.
pub(crate) fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Project-relative file locator rules shared by capture and worker proposals.
pub(crate) fn validate_locator(locator: &str) -> Result<()> {
    use std::path::Component;
    let path = Path::new(locator);
    if locator.contains('\\')
        || path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || path
            .components()
            .next()
            .is_some_and(|part| part.as_os_str() == ".calve")
    {
        return Err(invalid(format!(
            "{locator:?} must be a relative file path outside .calve"
        )));
    }
    Ok(())
}

fn value_contains_exact(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(s) => s == needle,
        Value::Array(items) => items.iter().any(|item| value_contains_exact(item, needle)),
        Value::Object(fields) => fields
            .values()
            .any(|item| value_contains_exact(item, needle)),
        _ => false,
    }
}

type ActivityRow = (i128, &'static str, u64, Value);

fn sort_activity_rows(rows: &mut [ActivityRow]) {
    rows.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| {
                if a.1 == b.1 {
                    b.2.cmp(&a.2)
                } else {
                    a.1.cmp(b.1)
                }
            })
            .then_with(|| a.3["id"].as_str().cmp(&b.3["id"].as_str()))
    });
}

fn push_activity_row(
    rows: &mut Vec<ActivityRow>,
    candidate: ActivityRow,
    limit: u16,
    filter: &ActivityFilter,
    bounds: (Option<i128>, Option<i128>),
) {
    if filter.matches(&candidate.3, candidate.0, bounds) {
        rows.push(candidate);
        if rows.len() >= usize::from(limit) * 2 {
            sort_activity_rows(rows);
            rows.truncate(usize::from(limit));
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectIdentity {
    pub format_version: u32,
    pub project_id: String,
    pub namespace_id: NamespaceId,
    pub created_at: u64,
    pub created_by: PrincipalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Keys {
    admin_id: PrincipalId,
    admin_seed: Vec<u8>,
    root_seed: Vec<u8>,
    runtime_principal: PrincipalId,
    runtime_seed: Vec<u8>,
}

fn signing_key(bytes: &[u8]) -> Result<Arc<SigningKey>> {
    let seed: [u8; 32] = bytes.try_into().map_err(|_| invalid("invalid key seed"))?;
    Ok(Arc::new(SigningKey::from_seed(seed)))
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system time before Unix epoch"))?
        .as_secs())
}

fn normalized_optional(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn validate_task_metadata(
    description: Option<&str>,
    priority: &str,
    assignee: Option<&str>,
) -> Result<()> {
    if !matches!(priority, "low" | "normal" | "high" | "urgent") {
        return Err(invalid(
            "task priority must be low, normal, high, or urgent",
        ));
    }
    if description.is_some_and(|value| value.len() > 4096) {
        return Err(invalid("task description exceeds 4096 bytes"));
    }
    if assignee.is_some_and(|value| value.len() > 128) {
        return Err(invalid("task assignee exceeds 128 bytes"));
    }
    Ok(())
}

fn validate_intent_tags(tags: &[String]) -> Result<Vec<String>> {
    if tags.len() > 16 {
        return Err(invalid("intent accepts at most 16 tags"));
    }
    let mut result = Vec::new();
    for tag in tags {
        let tag = tag.trim();
        if tag.is_empty() || tag.len() > 64 {
            return Err(invalid("intent tag must be 1–64 bytes"));
        }
        if !result.iter().any(|existing| existing == tag) {
            result.push(tag.to_owned());
        }
    }
    Ok(result)
}

/// Execution lease length. Short enough that a crashed daemon's executions are reported LOST
/// soon after restart; workers renew it while they run. `CALVE_EXECUTION_LEASE_MS` tunes it.
fn lease_ms() -> u64 {
    std::env::var("CALVE_EXECUTION_LEASE_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map_or(120_000, |ms: u64| ms.clamp(5_000, 3_600_000))
}

fn make_runtime(state: &Path, keys: &Keys, create: bool) -> Result<Arc<Runtime>> {
    let store = SqliteStore::open(
        &state.join("openaevc"),
        if create {
            SqliteOptions::create()
        } else {
            SqliteOptions::default()
        },
    )?;
    let clock = Arc::new(SystemClock);
    let ids = Arc::new(UuidV7Ids::new(clock.clone()));
    let admin = signing_key(&keys.admin_seed)?;
    let config = RuntimeConfig {
        admins: vec![Admin {
            id: keys.admin_id,
            public_key: admin.public_key(),
        }],
        // Project-pinned artifacts (older Projects) first, then the shared package cache.
        extension_dirs: [Some(state.join("extensions")), extensions::cache_dir()]
            .into_iter()
            .flatten()
            .collect(),
        extension_deadline_ms: 60_000,
        checkpoint_interval: CHECKPOINT_INTERVAL,
        lease_ms: lease_ms(),
        heartbeat_interval_ms: lease_ms() / 4,
        ..RuntimeConfig::default()
    };
    Ok(Arc::new(Runtime::open(
        RuntimeDeps {
            store: Arc::new(store),
            clock,
            ids,
            signer: signing_key(&keys.runtime_seed)?,
            runtime_principal: keys.runtime_principal,
        },
        config,
    )?))
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(content.as_bytes())?;
    Ok(())
}

const PROJECT_SCHEMA: &str = "
         CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
         INSERT INTO schema_migrations VALUES (1);
         CREATE TABLE intents (
           id TEXT PRIMARY KEY, title TEXT NOT NULL, closed INTEGER NOT NULL DEFAULT 0,
           created_at INTEGER NOT NULL, description TEXT, tags TEXT NOT NULL DEFAULT '[]',
           state TEXT NOT NULL DEFAULT 'OPEN', updated_at INTEGER NOT NULL,
           actors TEXT NOT NULL DEFAULT '[]', graph_node TEXT
         );
         CREATE TABLE tasks (
           id TEXT PRIMARY KEY, intent_id TEXT NOT NULL REFERENCES intents(id),
           title TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'OPEN', created_at INTEGER NOT NULL,
           description TEXT, priority TEXT NOT NULL DEFAULT 'normal', assignee TEXT,
           updated_at INTEGER NOT NULL
         );
         CREATE TABLE task_dependencies (
           task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
           depends_on_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
           PRIMARY KEY(task_id,depends_on_id), CHECK(task_id != depends_on_id)
         );
         CREATE INDEX task_dependencies_blocker ON task_dependencies(depends_on_id);
         CREATE TABLE task_links (
           task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
           kind TEXT NOT NULL CHECK(kind IN ('pack','execution')),
           object_id TEXT NOT NULL, created_at INTEGER NOT NULL,
           PRIMARY KEY(task_id,kind,object_id)
         );
         CREATE INDEX task_links_object ON task_links(kind,object_id);
         CREATE TABLE task_work_units (
           task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
           work_unit_id TEXT NOT NULL, created_at INTEGER NOT NULL,
           PRIMARY KEY(task_id,work_unit_id)
         );
         CREATE INDEX task_work_units_object ON task_work_units(work_unit_id);
         ALTER TABLE tasks ADD COLUMN blocked_reason TEXT;
         INSERT INTO schema_migrations VALUES (2);
         CREATE TABLE pack_metadata (
           id TEXT PRIMARY KEY, title TEXT NOT NULL, intent_id TEXT REFERENCES intents(id),
           created_at INTEGER NOT NULL
         );
         CREATE TABLE baseline_metadata (
           id TEXT PRIMARY KEY, digest TEXT NOT NULL, label TEXT NOT NULL,
           created_at INTEGER NOT NULL
         );
         CREATE TABLE reviews (
           id TEXT PRIMARY KEY, pack_id TEXT NOT NULL, generation INTEGER NOT NULL,
           candidate_digest TEXT NOT NULL, reviewer TEXT NOT NULL,
           decision TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL,
           evidence_digest TEXT
         );
         INSERT INTO schema_migrations VALUES (3);
         INSERT INTO schema_migrations VALUES (4);
         CREATE TABLE inbox_items (
           source_key TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL,
           summary TEXT NOT NULL, severity TEXT NOT NULL,
           first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
           read_at INTEGER, acknowledged_at INTEGER, snoozed_until INTEGER, resolved_at INTEGER
         );
         INSERT INTO schema_migrations VALUES (5);
         INSERT INTO schema_migrations VALUES (6);
         INSERT INTO schema_migrations VALUES (7);
         CREATE TABLE preferences (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE product_events (
           seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
           subject TEXT NOT NULL, detail TEXT NOT NULL, created_at INTEGER NOT NULL,
           created_at_ns INTEGER NOT NULL
         );
         INSERT INTO schema_migrations VALUES (8);
         INSERT INTO schema_migrations VALUES (9);
         INSERT INTO schema_migrations VALUES (10);
         CREATE TABLE extension_grants (
           extension_id TEXT NOT NULL, version TEXT NOT NULL, artifact_digest TEXT NOT NULL,
           capability TEXT NOT NULL, granted_at INTEGER NOT NULL,
           PRIMARY KEY(extension_id,artifact_digest,capability)
         );
         CREATE TABLE adoptions (
           source_project_id TEXT NOT NULL, source_namespace_id TEXT NOT NULL,
           source_path TEXT NOT NULL, adopted_at INTEGER NOT NULL, detail TEXT NOT NULL
         );
         INSERT INTO schema_migrations VALUES (11);
         CREATE TABLE pack_summaries (
           id TEXT PRIMARY KEY, state TEXT NOT NULL, generation INTEGER NOT NULL,
           created_at TEXT NOT NULL, updated_at TEXT NOT NULL, changed INTEGER NOT NULL,
           candidate_digest TEXT, promoted_digest TEXT, revision INTEGER NOT NULL
         );
         CREATE TABLE projection_checkpoints (name TEXT PRIMARY KEY, sequence INTEGER NOT NULL);
         INSERT INTO schema_migrations VALUES (12);
         CREATE TABLE pack_files (
           pack TEXT NOT NULL, position INTEGER NOT NULL, path TEXT NOT NULL,
           change TEXT NOT NULL, digest TEXT, from_path TEXT,
           PRIMARY KEY(pack, position)
         );
         CREATE INDEX pack_files_path ON pack_files(path);
         DELETE FROM projection_checkpoints WHERE name='packs';
         INSERT INTO schema_migrations VALUES (13);";

fn init_db(path: &Path, create: bool) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | if create {
            OpenFlags::SQLITE_OPEN_CREATE
        } else {
            OpenFlags::empty()
        };
    let mut db = Connection::open_with_flags(path, flags)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;")?;
    let version: u32 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    match (version, create) {
        (0, true) => {
            let tx = db.transaction()?;
            tx.execute_batch(PROJECT_SCHEMA)?;
            tx.execute_batch("PRAGMA user_version=13")?;
            tx.commit()?;
        }
        (0, false) => {
            // The first Calve slice recorded schema_migrations but not SQLite user_version.
            let legacy: Option<u32> = db
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|_| invalid("unrecognized project database schema"))?
                .flatten();
            if legacy != Some(1) {
                return Err(invalid("unrecognized project database schema"));
            }
            migrate_task_dependencies(&mut db)?;
            migrate_review_evidence(&mut db)?;
            migrate_task_metadata(&mut db)?;
            migrate_inbox(&mut db)?;
            migrate_intents(&mut db)?;
            migrate_task_links(&mut db)?;
            migrate_activity_time(&mut db)?;
            migrate_intent_references(&mut db)?;
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (1, false) => {
            migrate_task_dependencies(&mut db)?;
            migrate_review_evidence(&mut db)?;
            migrate_task_metadata(&mut db)?;
            migrate_inbox(&mut db)?;
            migrate_intents(&mut db)?;
            migrate_task_links(&mut db)?;
            migrate_activity_time(&mut db)?;
            migrate_intent_references(&mut db)?;
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (2, false) => {
            migrate_review_evidence(&mut db)?;
            migrate_task_metadata(&mut db)?;
            migrate_inbox(&mut db)?;
            migrate_intents(&mut db)?;
            migrate_task_links(&mut db)?;
            migrate_activity_time(&mut db)?;
            migrate_intent_references(&mut db)?;
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (3, false) => {
            migrate_task_metadata(&mut db)?;
            migrate_inbox(&mut db)?;
            migrate_intents(&mut db)?;
            migrate_task_links(&mut db)?;
            migrate_activity_time(&mut db)?;
            migrate_intent_references(&mut db)?;
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (4, false) => {
            migrate_inbox(&mut db)?;
            migrate_intents(&mut db)?;
            migrate_task_links(&mut db)?;
            migrate_activity_time(&mut db)?;
            migrate_intent_references(&mut db)?;
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (5, false) => {
            migrate_intents(&mut db)?;
            migrate_task_links(&mut db)?;
            migrate_activity_time(&mut db)?;
            migrate_intent_references(&mut db)?;
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (6, false) => {
            migrate_task_links(&mut db)?;
            migrate_activity_time(&mut db)?;
            migrate_intent_references(&mut db)?;
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (7, false) => {
            migrate_activity_time(&mut db)?;
            migrate_intent_references(&mut db)?;
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (8, false) => {
            migrate_intent_references(&mut db)?;
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (9, false) => {
            migrate_task_work_units(&mut db)?;
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (10, false) => {
            migrate_extension_grants(&mut db)?;
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (11, false) => {
            migrate_pack_index(&mut db)?;
            migrate_pack_files(&mut db)?;
        }
        (12, false) => migrate_pack_files(&mut db)?,
        (13, false) => {}
        (1..=13, true) => return Err(invalid("project database already exists")),
        (other, _) => {
            return Err(invalid(format!(
                "unsupported project database schema version {other}"
            )));
        }
    }
    Ok(db)
}

fn migrate_task_dependencies(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "CREATE TABLE task_dependencies (
           task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
           depends_on_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
           PRIMARY KEY(task_id,depends_on_id), CHECK(task_id != depends_on_id)
         );
         CREATE INDEX task_dependencies_blocker ON task_dependencies(depends_on_id);
         INSERT INTO schema_migrations VALUES (2);
         PRAGMA user_version=2;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_review_evidence(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "ALTER TABLE reviews ADD COLUMN evidence_digest TEXT;
         INSERT INTO schema_migrations VALUES (3);
         PRAGMA user_version=3;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_task_metadata(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "ALTER TABLE tasks ADD COLUMN description TEXT;
         ALTER TABLE tasks ADD COLUMN priority TEXT NOT NULL DEFAULT 'normal';
         ALTER TABLE tasks ADD COLUMN assignee TEXT;
         ALTER TABLE tasks ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
         UPDATE tasks SET updated_at=created_at;
         INSERT INTO schema_migrations VALUES (4);
         PRAGMA user_version=4;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_inbox(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "CREATE TABLE inbox_items (
           source_key TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL,
           summary TEXT NOT NULL, severity TEXT NOT NULL,
           first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
           read_at INTEGER, acknowledged_at INTEGER, snoozed_until INTEGER, resolved_at INTEGER
         );
         INSERT INTO schema_migrations VALUES (5);
         PRAGMA user_version=5;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_intents(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "ALTER TABLE intents ADD COLUMN description TEXT;
         ALTER TABLE intents ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
         ALTER TABLE intents ADD COLUMN state TEXT NOT NULL DEFAULT 'OPEN';
         ALTER TABLE intents ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
         UPDATE intents SET state=CASE WHEN closed=1 THEN 'COMPLETED' ELSE 'OPEN' END,
                            updated_at=created_at;
         INSERT INTO schema_migrations VALUES (6);
         PRAGMA user_version=6;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_task_links(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "ALTER TABLE tasks ADD COLUMN blocked_reason TEXT;
         CREATE TABLE task_links (
           task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
           kind TEXT NOT NULL CHECK(kind IN ('pack','execution')),
           object_id TEXT NOT NULL, created_at INTEGER NOT NULL,
           PRIMARY KEY(task_id,kind,object_id)
         );
         CREATE INDEX task_links_object ON task_links(kind,object_id);
         INSERT INTO schema_migrations VALUES (7);
         PRAGMA user_version=7;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_activity_time(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "ALTER TABLE product_events ADD COLUMN created_at_ns INTEGER NOT NULL DEFAULT 0;
         UPDATE product_events SET created_at_ns=created_at*1000000000;
         INSERT INTO schema_migrations VALUES (8);
         PRAGMA user_version=8;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_intent_references(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "ALTER TABLE intents ADD COLUMN actors TEXT NOT NULL DEFAULT '[]';
         ALTER TABLE intents ADD COLUMN graph_node TEXT;
         INSERT INTO schema_migrations VALUES (9);
         PRAGMA user_version=9;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_task_work_units(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "CREATE TABLE task_work_units (
           task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
           work_unit_id TEXT NOT NULL, created_at INTEGER NOT NULL,
           PRIMARY KEY(task_id,work_unit_id)
         );
         CREATE INDEX task_work_units_object ON task_work_units(work_unit_id);
         INSERT INTO schema_migrations VALUES (10);
         PRAGMA user_version=10;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_extension_grants(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "CREATE TABLE extension_grants (
           extension_id TEXT NOT NULL, version TEXT NOT NULL, artifact_digest TEXT NOT NULL,
           capability TEXT NOT NULL, granted_at INTEGER NOT NULL,
           PRIMARY KEY(extension_id,artifact_digest,capability)
         );
         CREATE TABLE adoptions (
           source_project_id TEXT NOT NULL, source_namespace_id TEXT NOT NULL,
           source_path TEXT NOT NULL, adopted_at INTEGER NOT NULL, detail TEXT NOT NULL
         );
         INSERT INTO schema_migrations VALUES (11);
         PRAGMA user_version=11;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_pack_index(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "CREATE TABLE pack_summaries (
           id TEXT PRIMARY KEY, state TEXT NOT NULL, generation INTEGER NOT NULL,
           created_at TEXT NOT NULL, updated_at TEXT NOT NULL, changed INTEGER NOT NULL,
           candidate_digest TEXT, promoted_digest TEXT, revision INTEGER NOT NULL
         );
         CREATE TABLE projection_checkpoints (name TEXT PRIMARY KEY, sequence INTEGER NOT NULL);
         INSERT INTO schema_migrations VALUES (12);
         PRAGMA user_version=12;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_pack_files(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(
        "CREATE TABLE pack_files (
           pack TEXT NOT NULL, position INTEGER NOT NULL, path TEXT NOT NULL,
           change TEXT NOT NULL, digest TEXT, from_path TEXT,
           PRIMARY KEY(pack, position)
         );
         CREATE INDEX pack_files_path ON pack_files(path);
         DELETE FROM projection_checkpoints WHERE name='packs';
         INSERT INTO schema_migrations VALUES (13);
         PRAGMA user_version=13;",
    )?;
    tx.commit()?;
    Ok(())
}

fn event(db: &Connection, kind: &str, subject: &str, detail: &str) -> Result<()> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system time before Unix epoch"))?;
    let nanos = i64::try_from(time.as_nanos())
        .map_err(|_| invalid("product activity timestamp exceeds SQLite range"))?;
    db.execute(
        "INSERT INTO product_events(kind,subject,detail,created_at,created_at_ns) VALUES (?1,?2,?3,?4,?5)",
        params![kind, subject, detail, time.as_secs(), nanos],
    )?;
    Ok(())
}

/// One file change recorded by a capture execution.
#[derive(Debug, Clone)]
pub(crate) enum FileChange {
    Snapshot(String, Vec<u8>),
    Delete {
        path: String,
        previous: Digest,
    },
    Rename {
        from: String,
        to: String,
        content: Vec<u8>,
    },
}

impl FileChange {
    fn path(&self) -> &str {
        match self {
            Self::Snapshot(path, _) | Self::Delete { path, .. } => path,
            Self::Rename { to, .. } => to,
        }
    }

    fn touched(&self) -> Vec<&str> {
        match self {
            Self::Rename { from, to, .. } => vec![from, to],
            other => vec![other.path()],
        }
    }

    fn digest(&self) -> Option<Digest> {
        match self {
            Self::Snapshot(_, content) | Self::Rename { content, .. } => Some(sha256(content)),
            Self::Delete { .. } => None,
        }
    }

    fn effect(&self) -> EffectProposal {
        let (kind, payload) = match self {
            Self::Snapshot(_, content) => (
                SOFTWARE_EFFECT,
                json!({"digest":sha256(content),"size":content.len(),"content":openaevc::protocol::b64::encode(content)}),
            ),
            Self::Delete { previous, .. } => (
                "org.calve.software.delete",
                json!({"previous_digest":previous}),
            ),
            Self::Rename { from, content, .. } => (
                "org.calve.software.rename",
                json!({"from":from,"digest":sha256(content),"size":content.len(),"content":openaevc::protocol::b64::encode(content)}),
            ),
        };
        EffectProposal {
            kind: kind.into(),
            target: ResourceRef {
                kind: SOFTWARE_RESOURCE.into(),
                locator: self.path().to_owned(),
                version: None,
                extension: SOFTWARE_EXTENSION.into(),
            },
            payload,
            preconditions: vec![],
            outputs: vec![],
        }
    }

    fn summary(&self) -> Value {
        match self {
            Self::Snapshot(path, content) => {
                json!({"path":path,"change":"snapshot","digest":sha256(content)})
            }
            Self::Delete { path, previous } => {
                json!({"path":path,"change":"delete","previous_digest":previous})
            }
            Self::Rename { from, to, content } => {
                json!({"path":to,"from":from,"change":"rename","digest":sha256(content)})
            }
        }
    }
}

/// Identity and name of a Project, read without starting its OpenAEVC runtime.
#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub root: PathBuf,
    pub identity: ProjectIdentity,
    pub display_name: String,
}

pub struct Project {
    pub root: PathBuf,
    pub identity: ProjectIdentity,
    pub display_name: String,
    pub client: EmbeddedClient,
    db: Connection,
    /// Shared runtime, so other identities can get their own session on it.
    runtime: Arc<Runtime>,
    /// Promoted and abandoned packs never change; they are fetched once per process.
    immutable_packs: std::cell::RefCell<BTreeMap<String, ChangePack>>,
}

impl Project {
    pub async fn init(path: &Path, name: Option<&str>) -> Result<Self> {
        Self::init_with(path, name, false).await
    }

    /// `nested` allows a Project inside another Project's tree; the outer Project's scanners
    /// still see the inner files unless its ignore rules exclude them.
    pub async fn init_with(path: &Path, name: Option<&str>, nested: bool) -> Result<Self> {
        fs::create_dir_all(path)?;
        let root = fs::canonicalize(path)?;
        if !nested && Self::discover(root.parent().unwrap_or(&root)).is_ok() {
            return Err(invalid(
                "a parent directory is already a Calve project; pass --nested to create one inside it",
            ));
        }
        let state = root.join(".calve");
        if state.exists() {
            return Err(invalid("project is already initialized"));
        }
        let staging = root.join(format!(".calve-init-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&staging)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
        }
        fs::create_dir(staging.join("extensions"))?;
        let result = async {
            let ids = UuidV7Ids::new(Arc::new(SystemClock));
            let admin = SigningKey::generate();
            let root_key = SigningKey::generate();
            let runtime_key = SigningKey::generate();
            let keys = Keys {
                admin_id: ids.next(),
                admin_seed: admin.seed().to_vec(),
                root_seed: root_key.seed().to_vec(),
                runtime_principal: ids.next(),
                runtime_seed: runtime_key.seed().to_vec(),
            };
            let runtime = make_runtime(&staging, &keys, true)?;
            let admin_client = EmbeddedClient::new(
                runtime.clone(),
                Session::new(Arc::new(admin), keys.admin_id, None),
            );
            let principal = NewPrincipal {
                kind: PrincipalKind::Key,
                public_key: Some(root_key.public_key()),
                linked_to: None,
                attributes: BTreeMap::new(),
            };
            let (namespace_id, roots) = admin_client.create_namespace(vec![principal]).await?;
            let display_name = name.map(str::to_owned).unwrap_or_else(|| {
                root.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
            let display_name = display_name.trim().to_owned();
            if display_name.trim().is_empty()
                || display_name.len() > 100
                || display_name.chars().any(char::is_control)
            {
                return Err(invalid("project name must be 1–100 printable characters"));
            }
            let identity = ProjectIdentity {
                format_version: 2,
                project_id: format!("prj_{}", uuid::Uuid::now_v7()),
                namespace_id,
                created_at: now()?,
                created_by: roots[0],
                name: None,
            };
            write_private(&staging.join("keys.toml"), &toml::to_string(&keys)?)?;
            fs::write(staging.join("project.toml"), toml::to_string(&identity)?)?;
            let db = init_db(&staging.join("product.sqlite3"), true)?;
            db.execute(
                "INSERT INTO preferences(key,value) VALUES ('project.display_name',?1)",
                [&display_name],
            )?;
            event(&db, "project.created", &identity.project_id, &display_name)?;
            drop(db);
            drop(admin_client);
            drop(runtime);
            fs::rename(&staging, &state)?;
            Ok::<(), Error>(())
        }
        .await;
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
        Self::open(&root)
    }

    pub fn discover(start: &Path) -> Result<PathBuf> {
        let mut current = fs::canonicalize(start)?;
        if current.is_file() {
            current.pop();
        }
        loop {
            if current.join(".calve/project.toml").is_file() {
                return Ok(current);
            }
            if !current.pop() {
                return Err(invalid("no Calve project found"));
            }
        }
    }

    /// Reads identity and display name only; safe while another handle holds the runtime.
    pub fn peek(path: &Path) -> Result<ProjectInfo> {
        let root = Self::discover(path)?;
        let state = root.join(".calve");
        if fs::symlink_metadata(&state)?.file_type().is_symlink() {
            return Err(invalid(".calve must be a real project directory"));
        }
        let identity: ProjectIdentity =
            toml::from_str(&fs::read_to_string(state.join("project.toml"))?)?;
        if !matches!(identity.format_version, 1 | 2) {
            return Err(invalid("unsupported project format"));
        }
        let stored: Option<String> = Connection::open_with_flags(
            state.join("product.sqlite3"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .ok()
        .and_then(|db| {
            db.query_row(
                "SELECT value FROM preferences WHERE key='project.display_name'",
                [],
                |row| row.get(0),
            )
            .ok()
        });
        let display_name = stored
            .or_else(|| identity.name.clone())
            .ok_or_else(|| invalid("project display name is missing"))?;
        Ok(ProjectInfo {
            root,
            identity,
            display_name,
        })
    }

    pub fn info(&self) -> ProjectInfo {
        ProjectInfo {
            root: self.root.clone(),
            identity: self.identity.clone(),
            display_name: self.display_name.clone(),
        }
    }

    pub fn open(path: &Path) -> Result<Self> {
        let root = Self::discover(path)?;
        let state = root.join(".calve");
        if fs::symlink_metadata(&state)?.file_type().is_symlink() {
            return Err(invalid(".calve must be a real project directory"));
        }
        let identity: ProjectIdentity =
            toml::from_str(&fs::read_to_string(state.join("project.toml"))?)?;
        if !matches!(identity.format_version, 1 | 2) {
            return Err(invalid("unsupported project format"));
        }
        let key_path = state.join("keys.toml");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&key_path)?.permissions().mode() & 0o077 != 0 {
                return Err(invalid(
                    "keys.toml permissions must exclude group and others",
                ));
            }
        }
        let keys: Keys = toml::from_str(&fs::read_to_string(key_path)?)?;
        let runtime = make_runtime(&state, &keys, false)?;
        let client = EmbeddedClient::new(
            runtime.clone(),
            Session::new(
                signing_key(&keys.root_seed)?,
                identity.created_by,
                Some(identity.namespace_id),
            ),
        );
        let db_path = state.join("product.sqlite3");
        if !db_path.is_file() {
            return Err(invalid("project product database is missing"));
        }
        let db = init_db(&db_path, false)?;
        let stored_name: Option<String> = db
            .query_row(
                "SELECT value FROM preferences WHERE key='project.display_name'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let display_name = stored_name
            .or_else(|| identity.name.clone())
            .ok_or_else(|| invalid("project display name is missing"))?;
        Ok(Self {
            root,
            identity,
            display_name,
            client,
            db,
            runtime,
            immutable_packs: Default::default(),
        })
    }

    pub fn create_intent(&self, title: &str) -> Result<String> {
        self.create_intent_with_metadata(title, None, &[])
    }

    pub fn rename(&mut self, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
            return Err(invalid("project name must be 1–100 printable characters"));
        }
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO preferences(key,value) VALUES ('project.display_name',?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [name],
        )?;
        event(&tx, "project.renamed", &self.identity.project_id, name)?;
        tx.commit()?;
        self.display_name = name.to_owned();
        Ok(())
    }

    pub fn create_intent_with_metadata(
        &self,
        title: &str,
        description: Option<&str>,
        tags: &[String],
    ) -> Result<String> {
        self.create_intent_record(title, description, tags, &[], None)
    }

    pub async fn create_intent_with_references(
        &self,
        title: &str,
        description: Option<&str>,
        tags: &[String],
        actors: &[String],
        graph_node: Option<&str>,
    ) -> Result<String> {
        let actors = self.validate_intent_actors(actors).await?;
        let graph_node = match graph_node {
            Some(node) => Some(self.validate_intent_graph_node(node).await?),
            None => None,
        };
        self.create_intent_record(title, description, tags, &actors, graph_node.as_deref())
    }

    async fn validate_intent_actors(&self, actors: &[String]) -> Result<Vec<String>> {
        if actors.len() > 16 {
            return Err(invalid("Intent supports at most 16 actor references"));
        }
        let mut unique = BTreeSet::new();
        for actor in actors {
            let id: PrincipalId = actor
                .parse()
                .map_err(|_| invalid(format!("invalid actor principal ID {actor}")))?;
            self.client
                .query(Query::GetPrincipal { principal: id })
                .await?;
            unique.insert(id.to_string());
        }
        Ok(unique.into_iter().collect())
    }

    async fn validate_intent_graph_node(&self, node: &str) -> Result<String> {
        let node: NodeRef = node.parse().map_err(invalid)?;
        let result = self
            .client
            .query(Query::GetNode { node: node.clone() })
            .await?;
        if !matches!(result["type"].as_str(), Some("pack" | "work_unit")) {
            return Err(invalid("Intent graph node must be a pack or work unit"));
        }
        Ok(node.to_string())
    }

    fn create_intent_record(
        &self,
        title: &str,
        description: Option<&str>,
        tags: &[String],
        actors: &[String],
        graph_node: Option<&str>,
    ) -> Result<String> {
        if title.trim().is_empty() {
            return Err(invalid("intent title cannot be empty"));
        }
        if title.len() > 256 || description.is_some_and(|v| v.len() > 4096) {
            return Err(invalid("intent title or description is too long"));
        }
        let tags = validate_intent_tags(tags)?;
        let id = format!("int_{}", uuid::Uuid::now_v7());
        let timestamp = now()?;
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO intents(id,title,closed,created_at,description,tags,state,updated_at,actors,graph_node)
             VALUES (?1,?2,0,?3,?4,?5,'OPEN',?3,?6,?7)",
            params![
                id,
                title.trim(),
                timestamp,
                normalized_optional(description),
                serde_json::to_string(&tags)?,
                serde_json::to_string(actors)?,
                graph_node
            ],
        )?;
        event(&tx, "intent.created", &id, title)?;
        tx.commit()?;
        Ok(id)
    }

    pub fn list_intents(&self) -> Result<Vec<Value>> {
        let mut stmt = self
            .db
            .prepare("SELECT id,title,description,tags,state,created_at,updated_at,actors,graph_node FROM intents ORDER BY created_at,id")?;
        let rows = stmt.query_map([], |r| {
            let tags: String = r.get(3)?;
            let tags: Vec<String> = serde_json::from_str(&tags).map_err(|error| rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error)))?;
            let actors: String = r.get(7)?;
            let actors: Vec<String> = serde_json::from_str(&actors).map_err(|error| rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error)))?;
            let state: String = r.get(4)?;
            Ok(json!({"id":r.get::<_,String>(0)?,"title":r.get::<_,String>(1)?,
                "description":r.get::<_,Option<String>>(2)?,"tags":tags,"state":state,"actors":actors,
                "graph_node":r.get::<_,Option<String>>(8)?,
                "closed":state != "OPEN","created_at":r.get::<_,u64>(5)?,"updated_at":r.get::<_,u64>(6)?}))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn intent(&self, id: &str) -> Result<Value> {
        self.list_intents()?
            .into_iter()
            .find(|intent| intent["id"] == id)
            .ok_or_else(|| invalid(format!("unknown intent {id}")))
    }

    pub async fn intent_with_packs(&self, id: &str) -> Result<Value> {
        let mut intent = self.intent(id)?;
        let ids = {
            let mut stmt = self
                .db
                .prepare("SELECT id FROM pack_metadata ORDER BY created_at,id")?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut linked = Vec::new();
        for pack_id in ids {
            let pack = self.pack(&pack_id).await?;
            if pack
                .intent
                .as_ref()
                .and_then(|value| value["org.calve.intent"].as_str())
                == Some(id)
            {
                linked.push(json!({
                    "id":pack_id,"generation":pack.generation,"state":pack.state.as_str()
                }));
            }
        }
        intent["linked_packs"] = json!(linked);
        Ok(intent)
    }

    pub fn update_intent(
        &self,
        id: &str,
        title: Option<&str>,
        description: Option<&str>,
        tags: Option<&[String]>,
    ) -> Result<()> {
        self.update_intent_record(id, title, description, tags, None, None)
    }

    pub async fn update_intent_with_references(
        &self,
        id: &str,
        title: Option<&str>,
        description: Option<&str>,
        tags: Option<&[String]>,
        actors: Option<&[String]>,
        graph_node: Option<Option<&str>>,
    ) -> Result<()> {
        let actors = match actors {
            Some(value) => Some(self.validate_intent_actors(value).await?),
            None => None,
        };
        let graph_node = match graph_node {
            Some(Some(node)) => Some(Some(self.validate_intent_graph_node(node).await?)),
            Some(None) => Some(None),
            None => None,
        };
        self.update_intent_record(
            id,
            title,
            description,
            tags,
            actors.as_deref(),
            graph_node.as_ref().map(Option::as_deref),
        )
    }

    fn update_intent_record(
        &self,
        id: &str,
        title: Option<&str>,
        description: Option<&str>,
        tags: Option<&[String]>,
        actors: Option<&[String]>,
        graph_node: Option<Option<&str>>,
    ) -> Result<()> {
        if title.is_none()
            && description.is_none()
            && tags.is_none()
            && actors.is_none()
            && graph_node.is_none()
        {
            return Err(invalid("intent edit needs at least one field"));
        }
        if title.is_some_and(|v| v.trim().is_empty() || v.len() > 256)
            || description.is_some_and(|v| v.len() > 4096)
        {
            return Err(invalid("intent title or description is invalid"));
        }
        let tags = tags.map(validate_intent_tags).transpose()?;
        let tx = self.db.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE intents SET title=COALESCE(?2,title),
             description=CASE WHEN ?3 THEN ?4 ELSE description END,
             tags=COALESCE(?5,tags),actors=COALESCE(?6,actors),
             graph_node=CASE WHEN ?7 THEN ?8 ELSE graph_node END,
             updated_at=?9 WHERE id=?1",
            params![
                id,
                title.map(str::trim),
                description.is_some(),
                normalized_optional(description),
                tags.map(|value| serde_json::to_string(&value))
                    .transpose()?,
                actors.map(serde_json::to_string).transpose()?,
                graph_node.is_some(),
                graph_node.flatten(),
                now()?
            ],
        )?;
        if changed == 0 {
            return Err(invalid(format!("unknown intent {id}")));
        }
        event(&tx, "intent.updated", id, "")?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_intent_state(&self, id: &str, state: &str) -> Result<()> {
        if !matches!(state, "OPEN" | "COMPLETED" | "CANCELLED") {
            return Err(invalid("invalid intent state"));
        }
        let current: String = self
            .db
            .query_row("SELECT state FROM intents WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or_else(|| invalid(format!("unknown intent {id}")))?;
        if current == state {
            return Err(invalid(format!("intent is already {state}")));
        }
        if state != "OPEN" && current != "OPEN" {
            return Err(invalid("reopen the intent before changing its closure"));
        }
        self.db.execute(
            "UPDATE intents SET state=?2,closed=?3,updated_at=?4 WHERE id=?1",
            params![id, state, state != "OPEN", now()?],
        )?;
        event(&self.db, "intent.state.changed", id, state)
    }

    pub fn create_task(&self, intent: &str, title: &str) -> Result<String> {
        self.create_task_with_metadata(intent, title, None, "normal", None)
    }

    pub fn create_task_with_metadata(
        &self,
        intent: &str,
        title: &str,
        description: Option<&str>,
        priority: &str,
        assignee: Option<&str>,
    ) -> Result<String> {
        if title.trim().is_empty() {
            return Err(invalid("task title cannot be empty"));
        }
        validate_task_metadata(description, priority, assignee)?;
        let state: String = self
            .db
            .query_row("SELECT state FROM intents WHERE id=?1", [intent], |row| {
                row.get(0)
            })
            .optional()?
            .ok_or_else(|| invalid(format!("unknown intent {intent}")))?;
        if state != "OPEN" {
            return Err(invalid("cannot create a task in a closed intent"));
        }
        let id = format!("tsk_{}", uuid::Uuid::now_v7());
        let timestamp = now()?;
        self.db.execute(
            "INSERT INTO tasks(id,intent_id,title,state,created_at,description,priority,assignee,updated_at)
             VALUES (?1,?2,?3,'OPEN',?4,?5,?6,?7,?4)",
            params![id, intent, title.trim(), timestamp, normalized_optional(description), priority, normalized_optional(assignee)],
        )?;
        event(&self.db, "task.created", &id, title)?;
        Ok(id)
    }

    pub fn update_task(
        &self,
        id: &str,
        title: Option<&str>,
        description: Option<&str>,
        priority: Option<&str>,
        assignee: Option<&str>,
    ) -> Result<()> {
        if title.is_none() && description.is_none() && priority.is_none() && assignee.is_none() {
            return Err(invalid("task update needs at least one field"));
        }
        if title.is_some_and(|value| value.trim().is_empty()) {
            return Err(invalid("task title cannot be empty"));
        }
        validate_task_metadata(description, priority.unwrap_or("normal"), assignee)?;
        let changed = self.db.execute(
            "UPDATE tasks SET title=COALESCE(?2,title),
             description=CASE WHEN ?3 THEN ?4 ELSE description END,
             priority=COALESCE(?5,priority),
             assignee=CASE WHEN ?6 THEN ?7 ELSE assignee END,
             updated_at=?8 WHERE id=?1",
            params![
                id,
                title.map(str::trim),
                description.is_some(),
                normalized_optional(description),
                priority,
                assignee.is_some(),
                normalized_optional(assignee),
                now()?
            ],
        )?;
        if changed == 0 {
            return Err(invalid(format!("unknown task {id}")));
        }
        event(&self.db, "task.updated", id, "")
    }

    pub fn list_tasks(&self) -> Result<Vec<Value>> {
        let mut deps = self.db.prepare(
            "SELECT d.task_id,d.depends_on_id,t.state FROM task_dependencies d
             JOIN tasks t ON t.id=d.depends_on_id ORDER BY d.task_id,d.depends_on_id",
        )?;
        let mut dependency_map: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for row in deps.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })? {
            let (task_id, depends_on, state) = row?;
            dependency_map
                .entry(task_id)
                .or_default()
                .push((depends_on, state));
        }
        let mut links = self.db.prepare(
            "SELECT task_id,kind,object_id FROM task_links ORDER BY task_id,kind,created_at,object_id",
        )?;
        let mut link_map: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for row in links.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })? {
            let (task_id, kind, object_id) = row?;
            link_map.entry(task_id).or_default().push((kind, object_id));
        }
        let mut work_links = self.db.prepare(
            "SELECT task_id,work_unit_id FROM task_work_units ORDER BY task_id,created_at,work_unit_id",
        )?;
        let mut work_link_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for row in
            work_links.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        {
            let (task_id, work_unit_id) = row?;
            work_link_map.entry(task_id).or_default().push(work_unit_id);
        }
        let mut stmt = self
            .db
            .prepare("SELECT id,intent_id,title,state,description,priority,assignee,created_at,updated_at,blocked_reason FROM tasks ORDER BY created_at,id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, u64>(7)?,
                r.get::<_, u64>(8)?,
                r.get::<_, Option<String>>(9)?,
            ))
        })?;
        let mut tasks = Vec::new();
        for row in rows {
            let (
                id,
                intent_id,
                title,
                state,
                description,
                priority,
                assignee,
                created_at,
                updated_at,
                blocked_reason,
            ) = row?;
            let pairs = dependency_map.remove(&id).unwrap_or_default();
            let depends_on: Vec<&str> = pairs.iter().map(|(id, _)| id.as_str()).collect();
            let blocked_by: Vec<&str> = pairs
                .iter()
                .filter(|(_, state)| state != "COMPLETE")
                .map(|(id, _)| id.as_str())
                .collect();
            let links = link_map.remove(&id).unwrap_or_default();
            let linked_packs: Vec<&str> = links
                .iter()
                .filter(|(kind, _)| kind == "pack")
                .map(|(_, id)| id.as_str())
                .collect();
            let linked_executions: Vec<&str> = links
                .iter()
                .filter(|(kind, _)| kind == "execution")
                .map(|(_, id)| id.as_str())
                .collect();
            let linked_work_units = work_link_map.remove(&id).unwrap_or_default();
            tasks.push(json!({"id":id,"intent_id":intent_id,"title":title,"description":description,"priority":priority,"assignee":assignee,"state":state,"blocked_reason":blocked_reason,"created_at":created_at,"updated_at":updated_at,"depends_on":depends_on,"blocked_by":blocked_by,"linked_packs":linked_packs,"linked_executions":linked_executions,"linked_work_units":linked_work_units}));
        }
        Ok(tasks)
    }

    pub fn task(&self, id: &str) -> Result<Value> {
        self.list_tasks()?
            .into_iter()
            .find(|task| task["id"] == id)
            .ok_or_else(|| invalid(format!("unknown task {id}")))
    }

    pub async fn link_task_pack(&self, task_id: &str, pack_id: &str) -> Result<()> {
        let task = self.task(task_id)?;
        let pack = self.pack(pack_id).await?;
        if let Some(intent_id) = pack
            .intent
            .as_ref()
            .and_then(|intent| intent["org.calve.intent"].as_str())
            && task["intent_id"] != intent_id
        {
            return Err(invalid("pack belongs to another Intent"));
        }
        let inserted = self.db.execute(
            "INSERT OR IGNORE INTO task_links(task_id,kind,object_id,created_at)
             VALUES (?1,'pack',?2,?3)",
            params![task_id, pack_id, now()?],
        )?;
        if inserted != 0 {
            event(&self.db, "task.pack.linked", task_id, pack_id)?;
        }
        Ok(())
    }

    pub async fn link_task_work_unit(&self, task_id: &str, work_unit_id: &str) -> Result<()> {
        let task = self.task(task_id)?;
        let work_unit: WorkUnitId = work_unit_id
            .parse()
            .map_err(|_| invalid(format!("invalid work unit ID {work_unit_id}")))?;
        let node = self
            .client
            .query(Query::GetNode {
                node: NodeRef::from(work_unit),
            })
            .await?;
        if node["type"] != "work_unit" || node["node"] != work_unit.to_string() {
            return Err(invalid("OpenAEVC did not return the requested work unit"));
        }
        let pack_id = node["pack"]
            .as_str()
            .ok_or_else(|| invalid("work unit has no owning pack"))?;
        let pack = self.pack(pack_id).await?;
        if let Some(intent_id) = pack
            .intent
            .as_ref()
            .and_then(|intent| intent["org.calve.intent"].as_str())
            && task["intent_id"] != intent_id
        {
            return Err(invalid("work unit pack belongs to another Intent"));
        }
        let tx = self.db.unchecked_transaction()?;
        let timestamp = now()?;
        tx.execute(
            "INSERT OR IGNORE INTO task_links(task_id,kind,object_id,created_at)
             VALUES (?1,'pack',?2,?3)",
            params![task_id, pack_id, timestamp],
        )?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO task_work_units(task_id,work_unit_id,created_at)
             VALUES (?1,?2,?3)",
            params![task_id, work_unit_id, timestamp],
        )?;
        if inserted != 0 {
            event(&tx, "task.work_unit.linked", task_id, work_unit_id)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub async fn link_task_execution(&self, task_id: &str, execution_id: &str) -> Result<()> {
        let task = self.task(task_id)?;
        let execution: openaevc::protocol::Execution =
            serde_json::from_value(self.execution(execution_id).await?)?;
        let pack_id = execution.pack.to_string();
        let pack = self.pack(&pack_id).await?;
        if let Some(intent_id) = pack
            .intent
            .as_ref()
            .and_then(|intent| intent["org.calve.intent"].as_str())
            && task["intent_id"] != intent_id
        {
            return Err(invalid("execution pack belongs to another Intent"));
        }
        let tx = self.db.unchecked_transaction()?;
        let timestamp = now()?;
        tx.execute(
            "INSERT OR IGNORE INTO task_links(task_id,kind,object_id,created_at)
                    VALUES (?1,'pack',?2,?3)",
            params![task_id, pack_id, timestamp],
        )?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO task_links(task_id,kind,object_id,created_at)
                    VALUES (?1,'execution',?2,?3)",
            params![task_id, execution_id, timestamp],
        )?;
        tx.commit()?;
        if inserted != 0 {
            event(&self.db, "task.execution.linked", task_id, execution_id)?;
        }
        Ok(())
    }

    pub async fn tasks_with_protocol(&self) -> Result<Vec<Value>> {
        let mut tasks = self.list_tasks()?;
        self.enrich_tasks_with_protocol(&mut tasks).await?;
        Ok(tasks)
    }

    pub async fn task_with_protocol(&self, id: &str) -> Result<Value> {
        let mut task = self.task(id)?;
        self.enrich_tasks_with_protocol(std::slice::from_mut(&mut task))
            .await?;
        Ok(task)
    }

    async fn enrich_tasks_with_protocol(&self, tasks: &mut [Value]) -> Result<()> {
        let mut execution_cache = BTreeMap::<String, openaevc::protocol::Execution>::new();
        let mut work_unit_cache = BTreeMap::<String, Value>::new();
        let mut pack_cache = BTreeMap::<String, (PackState, Option<Value>)>::new();
        for task in tasks {
            let mut issues = Vec::new();
            let mut work_unit_states = Vec::new();
            for id in task["linked_work_units"].as_array().into_iter().flatten() {
                let id = id
                    .as_str()
                    .ok_or_else(|| invalid("invalid linked work unit ID"))?;
                let node = if let Some(cached) = work_unit_cache.get(id) {
                    cached.clone()
                } else {
                    let work_unit: WorkUnitId = id
                        .parse()
                        .map_err(|_| invalid("invalid linked work unit ID"))?;
                    let fetched = self
                        .client
                        .query(Query::GetNode {
                            node: NodeRef::from(work_unit),
                        })
                        .await?;
                    if fetched["type"] != "work_unit" || fetched["node"] != id {
                        return Err(invalid("linked work unit query returned another node"));
                    }
                    work_unit_cache.insert(id.to_owned(), fetched.clone());
                    fetched
                };
                let state = node["state"]
                    .as_str()
                    .ok_or_else(|| invalid("work unit has no state"))?;
                work_unit_states.push(json!({
                    "id":id,"pack":node["pack"],"state":state,"kind":node["kind"]
                }));
                if task["state"] == "COMPLETE" && state != "COMPLETED" {
                    issues.push(format!(
                        "completed with {} work unit {id}",
                        state.to_lowercase()
                    ));
                }
            }
            let mut latest = BTreeMap::<String, openaevc::protocol::Execution>::new();
            let mut execution_states = Vec::new();
            for id in task["linked_executions"].as_array().into_iter().flatten() {
                let id = id
                    .as_str()
                    .ok_or_else(|| invalid("invalid linked execution ID"))?;
                let execution = if let Some(cached) = execution_cache.get(id) {
                    cached.clone()
                } else {
                    let fetched: openaevc::protocol::Execution =
                        serde_json::from_value(self.execution(id).await?)?;
                    execution_cache.insert(id.to_owned(), fetched.clone());
                    fetched
                };
                execution_states.push(json!({"id":id,"state":execution.state.as_str(),"work_unit":execution.work_unit}));
                let key = execution.work_unit.to_string();
                let replace = latest.get(&key).is_none_or(|previous| {
                    (execution.created_at, execution.id.to_string())
                        > (previous.created_at, previous.id.to_string())
                });
                if replace {
                    latest.insert(key, execution);
                }
            }
            for execution in latest.values() {
                if task["state"] == "COMPLETE" && execution.state != ExecutionState::Succeeded {
                    issues.push(format!(
                        "completed with {} execution {}",
                        execution.state.as_str().to_lowercase(),
                        execution.id
                    ));
                }
            }
            let mut pack_states = Vec::new();
            for id in task["linked_packs"].as_array().into_iter().flatten() {
                let id = id
                    .as_str()
                    .ok_or_else(|| invalid("invalid linked pack ID"))?;
                let (state, intent) = if let Some(cached) = pack_cache.get(id) {
                    cached.clone()
                } else {
                    let pack = self.pack(id).await?;
                    let current = (pack.state, pack.intent);
                    pack_cache.insert(id.to_owned(), current.clone());
                    current
                };
                pack_states.push(json!({"id":id,"state":state.as_str()}));
                if task["state"] == "COMPLETE"
                    && matches!(state, PackState::Quarantined | PackState::Abandoned)
                {
                    issues.push(format!(
                        "completed with {} pack {id}",
                        state.as_str().to_lowercase()
                    ));
                }
                if let Some(intent_id) = intent
                    .as_ref()
                    .and_then(|value| value["org.calve.intent"].as_str())
                    && task["intent_id"] != intent_id
                {
                    issues.push(format!("linked pack {id} now belongs to another Intent"));
                }
            }
            task["execution_states"] = json!(execution_states);
            task["work_unit_states"] = json!(work_unit_states);
            task["pack_states"] = json!(pack_states);
            task["inconsistencies"] = json!(issues);
        }
        Ok(())
    }

    pub fn add_task_dependency(&self, task: &str, depends_on: &str) -> Result<()> {
        if task == depends_on {
            return Err(invalid("a task cannot depend on itself"));
        }
        let states = [task, depends_on]
            .into_iter()
            .map(|id| {
                self.db
                    .query_row("SELECT state FROM tasks WHERE id=?1", [id], |r| {
                        r.get::<_, String>(0)
                    })
                    .optional()?
                    .ok_or_else(|| invalid(format!("unknown task {id}")))
            })
            .collect::<Result<Vec<_>>>()?;
        if states[0] == "COMPLETE" && states[1] != "COMPLETE" {
            return Err(invalid(
                "a completed task cannot gain an incomplete prerequisite",
            ));
        }
        let cycle: bool = self.db.query_row(
            "WITH RECURSIVE deps(id) AS (
               SELECT ?1 UNION SELECT d.depends_on_id FROM task_dependencies d JOIN deps ON d.task_id=deps.id
             ) SELECT EXISTS(SELECT 1 FROM deps WHERE id=?2)",
            params![depends_on, task],
            |r| r.get(0),
        )?;
        if cycle {
            return Err(invalid("task dependency would create a cycle"));
        }
        let inserted = self.db.execute(
            "INSERT OR IGNORE INTO task_dependencies(task_id,depends_on_id) VALUES (?1,?2)",
            params![task, depends_on],
        )?;
        if inserted != 0 {
            event(&self.db, "task.dependency.added", task, depends_on)?;
        }
        Ok(())
    }

    pub fn remove_task_dependency(&self, task: &str, depends_on: &str) -> Result<()> {
        let count = self.db.execute(
            "DELETE FROM task_dependencies WHERE task_id=?1 AND depends_on_id=?2",
            params![task, depends_on],
        )?;
        if count == 0 {
            return Err(invalid("task dependency does not exist"));
        }
        event(&self.db, "task.dependency.removed", task, depends_on)
    }

    pub fn complete_task(&self, id: &str) -> Result<()> {
        let blocked: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM task_dependencies d JOIN tasks t ON t.id=d.depends_on_id
             WHERE d.task_id=?1 AND t.state!='COMPLETE'",
            [id],
            |r| r.get(0),
        )?;
        if blocked != 0 {
            return Err(invalid(format!(
                "task {id} has {blocked} incomplete dependencies"
            )));
        }
        let n = self.db.execute(
            "UPDATE tasks SET state='COMPLETE',blocked_reason=NULL,updated_at=?2
             WHERE id=?1 AND state IN ('OPEN','IN_PROGRESS')",
            params![id, now()?],
        )?;
        if n == 0 {
            return Err(invalid(format!("task {id} is not open or in progress")));
        }
        event(&self.db, "task.completed", id, "")
    }

    pub fn start_task(&self, id: &str) -> Result<()> {
        let blocked: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM task_dependencies d JOIN tasks t ON t.id=d.depends_on_id
             WHERE d.task_id=?1 AND t.state!='COMPLETE'",
            [id],
            |r| r.get(0),
        )?;
        if blocked != 0 {
            return Err(invalid(format!(
                "task {id} has {blocked} incomplete dependencies"
            )));
        }
        let changed = self.db.execute(
            "UPDATE tasks SET state='IN_PROGRESS',updated_at=?2 WHERE id=?1 AND state='OPEN'",
            params![id, now()?],
        )?;
        if changed == 0 {
            return Err(invalid(format!("task {id} is not open")));
        }
        event(&self.db, "task.started", id, "")
    }

    pub fn block_task(&self, id: &str, reason: &str) -> Result<()> {
        let reason = reason.trim();
        if reason.is_empty() || reason.len() > 1024 {
            return Err(invalid("block reason must be 1–1024 bytes"));
        }
        let changed = self.db.execute(
            "UPDATE tasks SET state='BLOCKED',blocked_reason=?2,updated_at=?3
             WHERE id=?1 AND state IN ('OPEN','IN_PROGRESS')",
            params![id, reason, now()?],
        )?;
        if changed == 0 {
            return Err(invalid(format!("task {id} is not open or in progress")));
        }
        event(&self.db, "task.blocked", id, reason)
    }

    pub fn unblock_task(&self, id: &str) -> Result<()> {
        let changed = self.db.execute(
            "UPDATE tasks SET state='OPEN',blocked_reason=NULL,updated_at=?2
             WHERE id=?1 AND state='BLOCKED'",
            params![id, now()?],
        )?;
        if changed == 0 {
            return Err(invalid(format!("task {id} is not blocked")));
        }
        event(&self.db, "task.unblocked", id, "")
    }

    pub fn reopen_task(&self, id: &str) -> Result<()> {
        let dependents: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM task_dependencies d JOIN tasks t ON t.id=d.task_id
             WHERE d.depends_on_id=?1 AND t.state='COMPLETE'",
            [id],
            |r| r.get(0),
        )?;
        if dependents != 0 {
            return Err(invalid(format!(
                "task {id} has {dependents} completed dependents; reopen them first"
            )));
        }
        let changed = self.db.execute(
            "UPDATE tasks SET state='OPEN',updated_at=?2 WHERE id=?1 AND state='COMPLETE'",
            params![id, now()?],
        )?;
        if changed == 0 {
            return Err(invalid(format!("task {id} is not complete")));
        }
        event(&self.db, "task.reopened", id, "")
    }

    pub async fn create_pack(&self, title: &str, intent: Option<&str>) -> Result<PackId> {
        self.create_pack_with_verification(title, intent, false)
            .await
    }

    /// Creates a pack with an optional OpenAEVC policy requiring a passing software verification.
    pub async fn create_pack_with_verification(
        &self,
        title: &str,
        intent: Option<&str>,
        require_snapshot_verification: bool,
    ) -> Result<PackId> {
        self.create_pack_with_requirements(title, intent, require_snapshot_verification, false)
            .await
    }

    async fn register_pack_policies(
        &self,
        require_snapshot_verification: bool,
        require_review: bool,
    ) -> Result<Vec<Digest>> {
        self.register_pack_policies_with_checks(require_snapshot_verification, require_review, &[])
            .await
    }

    async fn register_pack_policies_with_checks(
        &self,
        require_snapshot_verification: bool,
        require_review: bool,
        required_checks: &[String],
    ) -> Result<Vec<Digest>> {
        let mut policies = Vec::new();
        for key in required_checks {
            let language =
                domain::language(key).ok_or_else(|| invalid(format!("unknown language {key}")))?;
            policies.push(PolicyDocument {
                name: format!("{}.checks-required", language.extension_id()),
                description: Some(format!(
                    "Require passing {} checks on the candidate",
                    language.display
                )),
                rules: vec![PolicyRule {
                    id: "checks-pass".into(),
                    expr: Expr::Verifier(VerifierCondition {
                        kind: language.verifier(),
                        status: VerificationStatus::Pass,
                    }),
                }],
            });
        }
        if require_snapshot_verification {
            policies.push(PolicyDocument {
                name: "org.calve.software.snapshot-required".into(),
                description: Some(
                    "Require a passing verification of the sealed file snapshots".into(),
                ),
                rules: vec![PolicyRule {
                    id: "snapshot-pass".into(),
                    expr: Expr::Verifier(VerifierCondition {
                        kind: SOFTWARE_VERIFIER.into(),
                        status: VerificationStatus::Pass,
                    }),
                }],
            });
        }
        if require_review {
            policies.push(PolicyDocument {
                name: REVIEW_POLICY_NAME.into(),
                description: Some(
                    "Require a candidate-bound Calve approval without a rejection".into(),
                ),
                rules: vec![PolicyRule {
                    id: "approved-not-rejected".into(),
                    expr: Expr::All(vec![
                        Expr::Evidence(EvidenceCondition {
                            kind: REVIEW_APPROVAL_KIND.into(),
                        }),
                        Expr::Not(Box::new(Expr::Evidence(EvidenceCondition {
                            kind: REVIEW_REJECTION_KIND.into(),
                        }))),
                    ]),
                }],
            });
        }
        let mut digests = Vec::new();
        for document in policies {
            let receipt = self
                .client
                .command(Command::RegisterPolicy {
                    document,
                    mandatory: false,
                })
                .await?;
            digests.push(
                receipt
                    .result
                    .digest
                    .ok_or_else(|| invalid("policy registration did not return a digest"))?,
            );
        }
        Ok(digests)
    }

    /// Creates a pack with OpenAEVC-enforced verification and/or review requirements.
    pub async fn create_pack_with_requirements(
        &self,
        title: &str,
        intent: Option<&str>,
        require_snapshot_verification: bool,
        require_review: bool,
    ) -> Result<PackId> {
        self.create_pack_with_policies(
            title,
            intent,
            require_snapshot_verification,
            require_review,
            &[],
        )
        .await
    }

    /// `required_checks` are language keys whose verifier must pass before promotion.
    pub async fn create_pack_with_policies(
        &self,
        title: &str,
        intent: Option<&str>,
        require_snapshot_verification: bool,
        require_review: bool,
        required_checks: &[String],
    ) -> Result<PackId> {
        if title.trim().is_empty() {
            return Err(invalid("pack title cannot be empty"));
        }
        if let Some(id) = intent {
            let count: i64 =
                self.db
                    .query_row("SELECT COUNT(*) FROM intents WHERE id=?1", [id], |r| {
                        r.get(0)
                    })?;
            if count == 0 {
                return Err(invalid(format!("unknown intent {id}")));
            }
        }
        let required_policies = self
            .register_pack_policies_with_checks(
                require_snapshot_verification,
                require_review,
                required_checks,
            )
            .await?;
        let spec = PackSpec {
            intent: intent.map(|id| json!({"org.calve.intent": id})),
            required_policies,
            metadata: Metadata::new(),
            ..PackSpec::default()
        };
        let id = self.client.create_change_pack(spec).await?;
        self.db.execute(
            "INSERT INTO pack_metadata VALUES (?1,?2,?3,?4)",
            params![id.to_string(), title, intent, now()?],
        )?;
        event(&self.db, "pack.created", &id.to_string(), title)?;
        Ok(id)
    }

    pub async fn pack(&self, id: &str) -> Result<ChangePack> {
        if let Some(pack) = self.immutable_packs.borrow().get(id) {
            return Ok(pack.clone());
        }
        let parsed: PackId = id.parse().map_err(|_| invalid("invalid pack ID"))?;
        let pack = self.client.get_change_pack(parsed).await?;
        if matches!(pack.state, PackState::Promoted | PackState::Abandoned) {
            self.immutable_packs
                .borrow_mut()
                .insert(id.to_owned(), pack.clone());
        }
        Ok(pack)
    }

    /// Brings the pack index up to date: only packs mentioned by journal events after the
    /// checkpoint (or missing from the index) are fetched again (PLAN §19.3).
    pub(crate) async fn refresh_pack_index(&self) -> Result<()> {
        let checkpoint: u64 = self
            .db
            .query_row(
                "SELECT sequence FROM projection_checkpoints WHERE name='packs'",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let mut dirty = BTreeSet::new();
        let mut head = checkpoint;
        self.scan_protocol_events(checkpoint, |event| {
            head = event.sequence;
            dirty.extend(
                event
                    .subjects
                    .iter()
                    .filter(|s| s.starts_with("cpk_"))
                    .cloned(),
            );
            Ok(())
        })
        .await?;
        let mut missing = self.db.prepare(
            "SELECT m.id FROM pack_metadata m LEFT JOIN pack_summaries s ON s.id=m.id WHERE s.id IS NULL",
        )?;
        dirty.extend(
            missing
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?,
        );
        drop(missing);
        let known: BTreeSet<String> = {
            let mut stmt = self.db.prepare("SELECT id FROM pack_metadata")?;
            stmt.query_map([], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        let tx = self.db.unchecked_transaction()?;
        for id in dirty.into_iter().filter(|id| known.contains(id)) {
            let pack = self.pack(&id).await?;
            let changed: BTreeSet<&str> = pack
                .candidate_effects
                .iter()
                .map(|e| e.target.locator.as_str())
                .collect();
            tx.execute(
                "INSERT INTO pack_summaries VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                 ON CONFLICT(id) DO UPDATE SET state=excluded.state, generation=excluded.generation,
                 updated_at=excluded.updated_at, changed=excluded.changed,
                 candidate_digest=excluded.candidate_digest, promoted_digest=excluded.promoted_digest,
                 revision=excluded.revision",
                params![
                    id,
                    pack.state.as_str(),
                    pack.generation,
                    pack.created_at.to_string(),
                    pack.updated_at.to_string(),
                    changed.len() as i64,
                    pack.sealed.as_ref().map(|s| s.candidate.to_string()),
                    pack.promotion.as_ref().map(|p| p.promoted_pack.to_string()),
                    pack.revision.is_some(),
                ],
            )?;
            tx.execute("DELETE FROM pack_files WHERE pack=?1", [&id])?;
            for (position, effect) in pack
                .candidate_effects
                .iter()
                .filter(|e| resources::is_file_effect(&e.kind))
                .enumerate()
            {
                let change = effect.kind.rsplit('.').next().unwrap_or("snapshot");
                tx.execute(
                    "INSERT INTO pack_files VALUES (?1,?2,?3,?4,?5,?6)",
                    params![
                        id,
                        position as i64,
                        effect.target.locator,
                        change,
                        effect.payload["digest"].as_str(),
                        effect.payload["from"].as_str()
                    ],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO projection_checkpoints VALUES ('packs',?1) ON CONFLICT(name) DO UPDATE SET sequence=excluded.sequence",
            [head],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Clears derived projections so the next read rebuilds them from OpenAEVC.
    pub(crate) fn reset_pack_index(&self) -> Result<()> {
        self.db.execute_batch(
            "DELETE FROM pack_summaries; DELETE FROM pack_files; DELETE FROM projection_checkpoints WHERE name='packs';",
        )?;
        Ok(())
    }

    /// Registers immutable evidence against the exact sealed candidate.
    pub async fn register_evidence(
        &self,
        id: &str,
        generation: u64,
        kind: &str,
        media_type: &str,
        data: Vec<u8>,
    ) -> Result<Digest> {
        if kind.trim().is_empty() || media_type.trim().is_empty() {
            return Err(invalid("evidence kind and media type are required"));
        }
        if kind.starts_with("org.calve.review.") {
            return Err(invalid(
                "Calve review evidence is reserved for review commands",
            ));
        }
        if data.len() > 1024 * 1024 {
            return Err(invalid("evidence payload exceeds 1 MiB"));
        }
        let pack = self.pack(id).await?;
        if pack.generation != generation {
            return Err(invalid(format!(
                "generation conflict: current is {}",
                pack.generation
            )));
        }
        if !matches!(pack.state, PackState::Sealed | PackState::Qualified) {
            return Err(invalid("evidence requires a sealed or qualified pack"));
        }
        let candidate = pack
            .sealed
            .as_ref()
            .ok_or_else(|| invalid("evidence requires a sealed candidate"))?
            .candidate;
        let receipt = self
            .client
            .command(Command::RegisterEvidence {
                pack: pack.id,
                generation,
                candidate,
                kind: kind.into(),
                payload: Blob {
                    media_type: media_type.into(),
                    data,
                },
                schema: None,
                sources: vec![],
                extension: None,
            })
            .await?;
        receipt
            .result
            .digest
            .ok_or_else(|| invalid("evidence receipt has no digest"))
    }

    pub async fn evidence(&self, digest: Digest) -> Result<Value> {
        Ok(self.client.query(Query::GetEvidence { digest }).await?)
    }

    pub async fn receipt(&self, digest: Digest) -> Result<Value> {
        let object = self.client.query(Query::GetObject { digest }).await?;
        if object["envelope"]["kind"] != "receipt" {
            return Err(invalid("object is not an OpenAEVC receipt"));
        }
        Ok(object)
    }

    pub async fn list_receipts(&self, after: Option<Digest>, limit: u32) -> Result<Value> {
        if !(1..=100).contains(&limit) {
            return Err(invalid("receipt page limit must be 1–100"));
        }
        let page = self
            .client
            .query(Query::ListObjectDigests {
                kind: Some(ObjectKind::Receipt),
                after,
                limit: Some(limit),
            })
            .await?;
        let entries = page["objects"]
            .as_array()
            .ok_or_else(|| invalid("invalid receipt index response"))?;
        let mut items = Vec::new();
        for entry in entries {
            let digest: Digest = serde_json::from_value(entry["digest"].clone())?;
            let object = self.receipt(digest).await?;
            items.push(json!({"digest":digest,"receipt":object["envelope"]["body"]}));
        }
        Ok(json!({"items":items,"next":page["next"]}))
    }

    pub async fn list_executions(
        &self,
        pack: Option<&str>,
        state: Option<ExecutionState>,
    ) -> Result<Value> {
        let pack = pack
            .map(|value| {
                value
                    .parse::<PackId>()
                    .map_err(|_| invalid("invalid pack ID"))
            })
            .transpose()?;
        Ok(self
            .client
            .query(Query::ListExecutions { pack, state })
            .await?)
    }

    pub async fn execution(&self, id: &str) -> Result<Value> {
        let execution = id
            .parse::<ExecutionId>()
            .map_err(|_| invalid("invalid execution ID"))?;
        Ok(self.client.query(Query::GetExecution { execution }).await?)
    }

    pub async fn wait_execution(&self, id: &str, timeout_ms: u64) -> Result<Value> {
        if timeout_ms == 0 || timeout_ms > 86_400_000 {
            return Err(invalid(
                "execution wait timeout must be 1 to 86400000 milliseconds",
            ));
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            let execution = self.execution(id).await?;
            if matches!(
                execution["state"].as_str(),
                Some("SUCCEEDED" | "FAILED" | "CANCELLED" | "LOST")
            ) {
                return Ok(execution);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(invalid(format!(
                    "execution {id} did not finish within {timeout_ms} ms"
                )));
            }
            tokio::time::sleep(remaining.min(std::time::Duration::from_millis(100))).await;
        }
    }

    pub async fn cancel_execution(&self, id: &str, reason: Option<&str>) -> Result<Value> {
        let execution = id
            .parse::<ExecutionId>()
            .map_err(|_| invalid("invalid execution ID"))?;
        let reason = reason.map(str::trim);
        if reason.is_some_and(str::is_empty) {
            return Err(invalid("cancellation reason cannot be blank"));
        }
        let receipt = self
            .client
            .command(Command::CancelExecution {
                execution,
                reason: reason.map(str::to_owned),
            })
            .await?;
        Ok(serde_json::to_value(receipt)?)
    }

    /// Pages through immutable protocol evidence objects and marks old candidates as stale.
    pub async fn list_evidence(
        &self,
        id: &str,
        after: Option<Digest>,
        limit: u32,
        current_only: bool,
    ) -> Result<Value> {
        if !(1..=100).contains(&limit) {
            return Err(invalid("evidence page limit must be 1–100"));
        }
        let pack = self.pack(id).await?;
        let page = self
            .client
            .query(Query::ListObjectDigests {
                kind: Some(ObjectKind::Evidence),
                after,
                limit: Some(limit),
            })
            .await?;
        let entries = page["objects"]
            .as_array()
            .ok_or_else(|| invalid("invalid evidence index response"))?;
        let mut items = Vec::new();
        for entry in entries {
            let digest: Digest = serde_json::from_value(entry["digest"].clone())?;
            let object = self.evidence(digest).await?;
            let body = &object["envelope"]["body"];
            if body["pack"] != json!(pack.id) {
                continue;
            }
            let stale = body["generation"] != json!(pack.generation)
                || pack
                    .sealed
                    .as_ref()
                    .is_none_or(|seal| body["candidate"] != json!(seal.candidate));
            if !current_only || !stale {
                items.push(json!({"digest":digest,"evidence":body,"stale":stale}));
            }
        }
        Ok(json!({"items":items,"next":page["next"]}))
    }

    /// Changes the intent reference through OpenAEVC's generation-checked structural update.
    pub async fn set_pack_intent(
        &self,
        id: &str,
        expected_generation: u64,
        intent_id: &str,
    ) -> Result<Value> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM intents WHERE id=?1",
            [intent_id],
            |row| row.get(0),
        )?;
        if count == 0 {
            return Err(invalid(format!("unknown intent {intent_id}")));
        }
        let pack = self.pack(id).await?;
        let receipt = self
            .client
            .command(Command::UpdateChangePack {
                pack: pack.id,
                expected_generation,
                intent: Some(json!({"org.calve.intent": intent_id})),
                resource_refs: None,
                required_policies: None,
                extension_bindings: None,
                conflicts_with: None,
                metadata: None,
            })
            .await?;
        self.db.execute(
            "UPDATE pack_metadata SET intent_id=?1 WHERE id=?2",
            params![intent_id, id],
        )?;
        event(&self.db, "pack.intent.changed", id, intent_id)?;
        Ok(serde_json::to_value(receipt)?)
    }

    /// Removes a Calve Intent association through OpenAEVC's structural update.
    pub async fn unlink_pack_intent(
        &self,
        id: &str,
        expected_generation: u64,
        intent_id: &str,
    ) -> Result<Value> {
        self.intent(intent_id)?;
        let pack = self.pack(id).await?;
        if pack
            .intent
            .as_ref()
            .and_then(|value| value["org.calve.intent"].as_str())
            != Some(intent_id)
        {
            return Err(invalid(format!(
                "pack {id} is not linked to intent {intent_id}"
            )));
        }
        let receipt = self
            .client
            .command(Command::UpdateChangePack {
                pack: pack.id,
                expected_generation,
                intent: Some(json!({})),
                resource_refs: None,
                required_policies: None,
                extension_bindings: None,
                conflicts_with: None,
                metadata: None,
            })
            .await?;
        self.db
            .execute("UPDATE pack_metadata SET intent_id=NULL WHERE id=?1", [id])?;
        event(&self.db, "pack.intent.unlinked", id, intent_id)?;
        Ok(serde_json::to_value(receipt)?)
    }

    pub async fn list_packs(&self) -> Result<Vec<Value>> {
        self.refresh_pack_index().await?;
        let mut stmt = self.db.prepare(
            "SELECT m.id,m.title,m.intent_id,s.state,s.generation,s.candidate_digest,s.promoted_digest,
                    s.created_at,s.updated_at,s.changed,s.revision
             FROM pack_metadata m JOIN pack_summaries s ON s.id=m.id ORDER BY m.created_at,m.id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(
                json!({"id":r.get::<_,String>(0)?,"title":r.get::<_,String>(1)?,
                "intent":r.get::<_,Option<String>>(2)?,"state":r.get::<_,String>(3)?,
                "generation":r.get::<_,u64>(4)?,"candidate_digest":r.get::<_,Option<String>>(5)?,
                "promoted_digest":r.get::<_,Option<String>>(6)?,"created_at":r.get::<_,String>(7)?,
                "updated_at":r.get::<_,String>(8)?,"changed":r.get::<_,i64>(9)?,
                "revision":r.get::<_,bool>(10)?}),
            )
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Creates a protocol RevisionPack linked to immutable promoted-pack targets.
    pub async fn create_revision_pack(
        &self,
        title: &str,
        intent: Option<&str>,
        relation: RevisionRelation,
        targets: Vec<Digest>,
    ) -> Result<PackId> {
        self.create_revision_pack_with_requirements(title, intent, relation, targets, false)
            .await
    }

    pub async fn create_revision_pack_with_requirements(
        &self,
        title: &str,
        intent: Option<&str>,
        relation: RevisionRelation,
        targets: Vec<Digest>,
        require_review: bool,
    ) -> Result<PackId> {
        if title.trim().is_empty() || targets.is_empty() {
            return Err(invalid(
                "revision needs a title and at least one promoted target",
            ));
        }
        if let Some(id) = intent {
            let count: i64 =
                self.db
                    .query_row("SELECT COUNT(*) FROM intents WHERE id=?1", [id], |row| {
                        row.get(0)
                    })?;
            if count == 0 {
                return Err(invalid(format!("unknown intent {id}")));
            }
        }
        let spec = PackSpec {
            intent: intent.map(|id| json!({"org.calve.intent":id})),
            required_policies: self.register_pack_policies(false, require_review).await?,
            metadata: Metadata::new(),
            ..PackSpec::default()
        };
        let receipt = self
            .client
            .command(Command::CreateRevisionPack {
                relation,
                targets,
                spec,
            })
            .await?;
        let id: PackId = receipt
            .result
            .id
            .ok_or_else(|| invalid("revision creation did not return an ID"))?
            .parse()
            .map_err(|_| invalid("revision creation returned an invalid ID"))?;
        self.db.execute(
            "INSERT INTO pack_metadata VALUES (?1,?2,?3,?4)",
            params![id.to_string(), title, intent, now()?],
        )?;
        event(&self.db, "revision.created", &id.to_string(), title)?;
        Ok(id)
    }

    pub async fn revision(&self, id: &str) -> Result<ChangePack> {
        let pack = self.pack(id).await?;
        if pack.revision.is_none() {
            return Err(invalid("pack is not a RevisionPack"));
        }
        Ok(pack)
    }

    pub async fn list_revisions(&self) -> Result<Vec<Value>> {
        let mut stmt = self
            .db
            .prepare("SELECT id,title FROM pack_metadata ORDER BY created_at,id")?;
        let ids = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut out = Vec::new();
        for (id, title) in ids {
            let pack = self.pack(&id).await?;
            if let Some(revision) = pack.revision {
                out.push(json!({"id":id,"title":title,"generation":pack.generation,"state":pack.state.as_str(),
                    "relation":revision.relation,"targets":revision.targets,
                    "promoted_digest":pack.promotion.as_ref().map(|promotion| promotion.promoted_pack.to_string())}));
            }
        }
        Ok(out)
    }

    pub async fn list_extensions(&self) -> Result<Value> {
        Ok(self.client.query(Query::ListExtensions {}).await?)
    }

    fn read_capture_file(&self, path: &Path) -> Result<(String, Vec<u8>)> {
        use std::path::Component;
        let path_text = path
            .to_str()
            .ok_or_else(|| invalid("capture path must be UTF-8"))?;
        let mut parts = path.components();
        if (cfg!(unix) && path_text.contains('\\'))
            || parts.clone().next().is_none()
            || parts
                .clone()
                .any(|part| !matches!(part, Component::Normal(_)))
            || parts
                .next()
                .is_some_and(|part| part.as_os_str() == ".calve")
        {
            return Err(invalid(
                "capture path must be a relative file outside .calve",
            ));
        }
        let mut current = self.root.clone();
        for part in path.components() {
            current.push(part);
            if fs::symlink_metadata(&current)?.file_type().is_symlink() {
                return Err(invalid("capture path may not contain a symlink"));
            }
        }
        let metadata = fs::metadata(&current)?;
        if !metadata.is_file() || metadata.len() > MAX_CAPTURE_BYTES {
            return Err(invalid("capture needs a regular file of at most 1 MiB"));
        }
        if !fs::canonicalize(&current)?.starts_with(&self.root) {
            return Err(invalid("capture path escapes the Project"));
        }
        let content = fs::read(&current)?;
        if content.len() as u64 > MAX_CAPTURE_BYTES {
            return Err(invalid("file changed beyond the 1 MiB capture limit"));
        }
        Ok((path_text.replace('\\', "/"), content))
    }

    /// Captures one exact file snapshot through a signed OpenAEVC execution and extension effect.
    pub async fn capture_file(
        &self,
        pack_id: &str,
        expected_generation: u64,
        path: &Path,
    ) -> Result<Value> {
        // A file that is gone but accepted is captured as a deletion.
        let change = match self.read_capture_file(path) {
            Ok((locator, content)) => FileChange::Snapshot(locator, content),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                let locator = path.to_string_lossy().replace('\\', "/");
                validate_locator(&locator)?;
                let previous = self
                    .indexed_digests(true)
                    .await?
                    .get(&locator)
                    .copied()
                    .ok_or_else(|| {
                        invalid(format!("{locator} does not exist and was never accepted"))
                    })?;
                FileChange::Delete {
                    path: locator,
                    previous,
                }
            }
            Err(error) => return Err(error),
        };
        let locator = change.path().to_owned();
        let batch = self
            .capture_snapshots_attempt(pack_id, expected_generation, vec![change], None)
            .await?;
        let item = batch["captured"]
            .as_array()
            .and_then(|items| items.first())
            .or_else(|| {
                batch["unchanged"]
                    .as_array()
                    .and_then(|items| items.first())
            })
            .ok_or_else(|| invalid("capture returned no file result"))?;
        Ok(
            json!({"path":locator,"digest":item["digest"],"generation":batch["generation"],
            "execution":batch["execution"],"work_unit":batch["work_unit"],
            "unchanged":batch["captured"].as_array().is_none_or(Vec::is_empty)}),
        )
    }

    /// `retry` reuses the failed attempt's work unit so OpenAEVC links the successor attempt.
    pub(crate) async fn capture_snapshots_attempt(
        &self,
        pack_id: &str,
        expected_generation: u64,
        files: Vec<FileChange>,
        retry: Option<(WorkUnitId, ExecutionId)>,
    ) -> Result<Value> {
        let pack = self.pack(pack_id).await?;
        if pack.state != PackState::Open || pack.generation != expected_generation {
            return Err(invalid(format!(
                "pack must be OPEN at generation {expected_generation}"
            )));
        }
        if files.is_empty() {
            return Ok(json!({"generation":pack.generation,"captured":[],"unchanged":[]}));
        }
        let mut seen = BTreeSet::new();
        for change in &files {
            let oversized = matches!(change, FileChange::Snapshot(_, c) | FileChange::Rename { content: c, .. } if c.len() as u64 > MAX_CAPTURE_BYTES);
            if !change
                .touched()
                .into_iter()
                .all(|path| seen.insert(path.to_owned()))
                || oversized
            {
                return Err(invalid(
                    "capture batch has duplicate paths or oversized files",
                ));
            }
        }
        if !pack.candidate_effects.is_empty() {
            let unchanged: Vec<Value> = files
                .iter()
                .filter_map(|change| {
                    let FileChange::Snapshot(locator, content) = change else {
                        return None;
                    };
                    let digest = sha256(content);
                    pack.candidate_effects
                        .iter()
                        .rev()
                        .find(|effect| {
                            effect.target.extension == SOFTWARE_EXTENSION
                                && effect.target.locator == *locator
                        })
                        .filter(|effect| {
                            effect.kind == SOFTWARE_EFFECT
                                && effect.payload["digest"] == digest.to_string()
                        })
                        .map(|_| json!({"path":locator,"digest":digest}))
                })
                .collect();
            if unchanged.len() == files.len() {
                return Ok(
                    json!({"generation":pack.generation,"captured":[],"unchanged":unchanged}),
                );
            }
            return Err(invalid(
                "pack already has capture effects; add new or changed files in a new pack so provenance stays valid",
            ));
        }
        let extensions = self.list_extensions().await?;
        if !extensions.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|entry| entry["id"] == SOFTWARE_EXTENSION && entry["active"] == true)
        }) {
            return Err(invalid(
                "enable the Calve software extension before capturing files",
            ));
        }
        self.client
            .command(Command::RegisterProvider {
                provider: ProviderDescriptor {
                    id: SOFTWARE_PROVIDER.into(),
                    version: "0.1.0".into(),
                    worker_kinds: vec![SOFTWARE_HARNESS.into()],
                    harnesses: vec![SOFTWARE_HARNESS.into()],
                    required_actions: vec!["org.calve.software.write".into()],
                    cancellation: true,
                    resumable: false,
                    heartbeat: false,
                    limits: BTreeMap::new(),
                    provenance_fields: vec![],
                    principal: self.identity.created_by,
                },
            })
            .await?;
        let work_unit = match retry {
            Some((work_unit, _)) => work_unit,
            None => {
                self.client
                    .add_work_unit(pack.id, pack.generation, SOFTWARE_HARNESS)
                    .await?
            }
        };
        let generation = self.pack(pack_id).await?.generation;
        let request = ExecutionRequest {
            pack: pack.id,
            expected_generation: generation,
            work_unit,
            provider: SOFTWARE_PROVIDER.into(),
            harness: SOFTWARE_HARNESS.into(),
            worker: Some(WorkerInfo {
                id: "local".into(),
                kind: SOFTWARE_HARNESS.into(),
                attributes: BTreeMap::new(),
            }),
            allowed_resources: files
                .iter()
                .flat_map(FileChange::touched)
                .map(|locator| ResourceSelector {
                    kind: SOFTWARE_RESOURCE.into(),
                    locator_prefix: Some(locator.to_owned()),
                })
                .collect(),
            allowed_effects: vec![
                SOFTWARE_EFFECT.into(),
                "org.calve.software.delete".into(),
                "org.calve.software.rename".into(),
            ],
            context: vec![],
            timeout_ms: 1_800_000,
            budget: BTreeMap::new(),
            max_attempts: CAPTURE_MAX_ATTEMPTS,
            idempotency_key: uuid::Uuid::now_v7().to_string(),
            retry_of: retry.map(|(_, execution)| execution),
        };
        let (execution, lease) = self.client.start_execution(request).await?;
        self.client.heartbeat(&lease).await?;
        let mut captured = Vec::new();
        for change in &files {
            let locator = change.path().to_owned();
            let effect = change.effect();
            let resource = effect.target.clone();
            let applied = match self.client.submit_effect(&lease, effect).await {
                Ok(applied) => applied,
                Err(error) => {
                    let _ = self
                        .client
                        .command(Command::FailExecution {
                            execution,
                            lease: lease.id,
                            reason: "file capture failed".into(),
                        })
                        .await;
                    return Err(error.into());
                }
            };
            if !applied {
                let _ = self
                    .client
                    .command(Command::FailExecution {
                        execution,
                        lease: lease.id,
                        reason: "extension rejected file snapshot".into(),
                    })
                    .await;
                return Err(invalid(format!(
                    "software extension rejected the change to {locator}"
                )));
            }
            self.client.heartbeat(&lease).await?;
            self.client
                .command(Command::AppendObservation {
                    execution,
                    lease: lease.id,
                    kind: "org.calve.software.captured".into(),
                    payload: Some(change.summary()),
                    blob: None,
                    related_resources: vec![resource],
                    related_effects: vec![],
                })
                .await?;
            captured.push(change.summary());
        }
        self.client.heartbeat(&lease).await?;
        self.client.complete_execution(&lease).await?;
        for change in &files {
            let digest = change
                .digest()
                .map_or_else(|| "deleted".to_owned(), |d| d.to_string());
            event(&self.db, "file.captured", change.path(), &digest)?;
        }
        let generation = self.pack(pack_id).await?.generation;
        Ok(
            json!({"generation":generation,"execution":execution,"work_unit":work_unit,"captured":captured,"unchanged":[]}),
        )
    }

    /// Runs the first-party snapshot verifier against a sealed candidate.
    pub async fn verify_snapshots(
        &self,
        pack_id: &str,
        expected_generation: u64,
        expected: Option<(&Path, Digest)>,
    ) -> Result<Value> {
        let pack = self.pack(pack_id).await?;
        if pack.generation != expected_generation || pack.sealed.is_none() {
            return Err(invalid("pack must be sealed at the requested generation"));
        }
        let config = if let Some((path, digest)) = expected {
            use std::path::Component;
            let path_text = path
                .to_str()
                .ok_or_else(|| invalid("expected path must be UTF-8"))?;
            if (cfg!(unix) && path_text.contains('\\'))
                || path.as_os_str().is_empty()
                || path
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
                || path
                    .components()
                    .next()
                    .is_some_and(|part| part.as_os_str() == ".calve")
            {
                return Err(invalid(
                    "expected path must be a Project-relative file outside .calve",
                ));
            }
            json!({"path":path_text.replace('\\', "/"),"digest":digest})
        } else {
            json!({})
        };
        let receipt = self
            .client
            .run_verification(pack.id, pack.generation, SOFTWARE_VERIFIER, config)
            .await?;
        let digest = receipt
            .result
            .digest
            .ok_or_else(|| invalid("verification did not return a result digest"))?;
        let object: Value = self.client.query(Query::GetVerification { digest }).await?;
        let mut result = object["envelope"]["body"]
            .as_object()
            .cloned()
            .ok_or_else(|| invalid("invalid verification result envelope"))?;
        result.insert("digest".into(), json!(digest));
        Ok(Value::Object(result))
    }

    /// Runs the first-party change-size evaluator against a sealed candidate.
    pub async fn evaluate_change_size(
        &self,
        pack_id: &str,
        expected_generation: u64,
        warn_after_bytes: Option<u64>,
        warn_after_files: Option<u64>,
    ) -> Result<Value> {
        let pack = self.pack(pack_id).await?;
        if pack.generation != expected_generation
            || !matches!(pack.state, PackState::Sealed | PackState::Qualified)
        {
            return Err(invalid("pack must be sealed at the requested generation"));
        }
        let mut config = serde_json::Map::new();
        if let Some(bytes) = warn_after_bytes {
            config.insert("warn_after_bytes".into(), json!(bytes));
        }
        if let Some(files) = warn_after_files {
            config.insert("warn_after_files".into(), json!(files));
        }
        let receipt = self
            .client
            .run_evaluation(
                pack.id,
                pack.generation,
                SOFTWARE_EVALUATOR,
                Value::Object(config),
            )
            .await?;
        let digest = receipt
            .result
            .digest
            .ok_or_else(|| invalid("evaluation did not return a result digest"))?;
        let object: Value = self.client.query(Query::GetEvaluation { digest }).await?;
        let mut result = object["envelope"]["body"]
            .as_object()
            .cloned()
            .ok_or_else(|| invalid("invalid evaluation result envelope"))?;
        result.insert("digest".into(), json!(digest));
        Ok(Value::Object(result))
    }

    pub async fn seal(&self, id: &str, expected_generation: u64) -> Result<Digest> {
        let pack = self.pack(id).await?;
        if pack.generation != expected_generation {
            return Err(invalid(format!(
                "generation conflict: current is {}",
                pack.generation
            )));
        }
        Ok(self.client.seal(pack.id, expected_generation).await?)
    }

    pub async fn qualify(&self, id: &str, generation: u64) -> Result<Value> {
        let pack = self.pack(id).await?;
        let receipt = self
            .client
            .refresh_qualification(pack.id, generation)
            .await?;
        Ok(serde_json::to_value(receipt)?)
    }

    pub async fn reopen(&self, id: &str, generation: u64) -> Result<Value> {
        let pack = self.pack(id).await?;
        let receipt = self
            .client
            .command(Command::ReopenChangePack {
                pack: pack.id,
                expected_generation: generation,
            })
            .await?;
        Ok(serde_json::to_value(receipt)?)
    }

    pub async fn quarantine_pack(&self, id: &str, reason: &str) -> Result<Value> {
        if reason.trim().is_empty() {
            return Err(invalid("quarantine needs a reason"));
        }
        let pack = self.pack(id).await?;
        let receipt = self
            .client
            .command(Command::QuarantineChangePack {
                pack: pack.id,
                reason: reason.into(),
            })
            .await?;
        Ok(serde_json::to_value(receipt)?)
    }

    pub async fn release_quarantine(&self, id: &str) -> Result<Value> {
        let pack = self.pack(id).await?;
        let receipt = self
            .client
            .command(Command::ReleaseQuarantine { pack: pack.id })
            .await?;
        Ok(serde_json::to_value(receipt)?)
    }

    pub async fn abandon_pack(&self, id: &str, generation: u64) -> Result<Value> {
        let pack = self.pack(id).await?;
        let receipt = self
            .client
            .command(Command::AbandonChangePack {
                pack: pack.id,
                expected_generation: generation,
            })
            .await?;
        Ok(serde_json::to_value(receipt)?)
    }

    pub async fn promote(&self, id: &str, generation: u64) -> Result<Digest> {
        let pack = self.pack(id).await?;
        Ok(self.client.promote(pack.id, generation).await?)
    }

    async fn pack_requires_review(&self, pack: &ChangePack) -> Result<bool> {
        for digest in &pack.required_policies {
            let object = self
                .client
                .query(Query::GetObject { digest: *digest })
                .await?;
            if object["envelope"]["kind"] == "policy_document"
                && object["envelope"]["body"]["name"] == REVIEW_POLICY_NAME
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn review(
        &self,
        id: &str,
        generation: u64,
        decision: &str,
        reason: &str,
    ) -> Result<String> {
        if !matches!(decision, "APPROVE" | "REJECT" | "COMMENT") {
            return Err(invalid("decision must be APPROVE, REJECT, or COMMENT"));
        }
        let pack = self.pack(id).await?;
        if pack.generation != generation {
            return Err(invalid(format!(
                "generation conflict: current is {}",
                pack.generation
            )));
        }
        if !matches!(pack.state, PackState::Sealed | PackState::Qualified) {
            return Err(invalid("review requires a sealed or qualified pack"));
        }
        let candidate = pack
            .sealed
            .as_ref()
            .ok_or_else(|| invalid("seal the pack before review"))?
            .candidate;
        let requires_review = self.pack_requires_review(&pack).await?;
        let reviewer = self.client.session().principal();
        if decision == "APPROVE" && reviewer == pack.created_by && self.self_review_forbidden(id)? {
            return Err(invalid(
                "this pack forbids self-review: approve as another identity (--as <name>)",
            ));
        }
        let review_id = format!("rev_{}", uuid::Uuid::now_v7());
        let recorded_at = now()?;
        self.db.execute(
            "INSERT INTO reviews(id,pack_id,generation,candidate_digest,reviewer,decision,reason,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                review_id,
                id,
                generation,
                candidate.to_string(),
                reviewer.to_string(),
                decision,
                reason,
                recorded_at
            ],
        )?;
        let publish = async {
            if !requires_review {
                return Ok(None);
            }
            let kind = match decision {
                "APPROVE" => REVIEW_APPROVAL_KIND,
                "REJECT" => REVIEW_REJECTION_KIND,
                _ => return Ok(None),
            };
            let payload = json!({
                "schema_version": 1,
                "review_id": review_id,
                "project_id": self.identity.project_id,
                "pack_id": id,
                "generation": generation,
                "candidate_digest": candidate,
                "reviewer": reviewer,
                "decision": decision,
                "reason": reason,
                "recorded_at": recorded_at,
            });
            let receipt = self
                .client
                .command(Command::RegisterEvidence {
                    pack: pack.id,
                    generation,
                    candidate,
                    kind: kind.into(),
                    payload: Blob {
                        media_type: "application/vnd.calve.review+json".into(),
                        data: serde_json::to_vec(&payload)?,
                    },
                    schema: None,
                    sources: vec![],
                    extension: None,
                })
                .await?;
            let digest = receipt
                .result
                .digest
                .ok_or_else(|| invalid("review evidence receipt has no digest"))?;
            Ok::<Option<Digest>, Error>(Some(digest))
        }
        .await;
        let evidence_digest = match publish {
            Ok(value) => value,
            Err(error) => {
                self.db
                    .execute("DELETE FROM reviews WHERE id=?1", [&review_id])?;
                return Err(error);
            }
        };
        if let Some(digest) = evidence_digest {
            self.db.execute(
                "UPDATE reviews SET evidence_digest=?1 WHERE id=?2",
                params![digest.to_string(), review_id],
            )?;
        }
        event(&self.db, "review.recorded", id, decision)?;
        Ok(review_id)
    }

    pub async fn reviews(&self, id: &str) -> Result<Vec<Value>> {
        // Staleness needs only generation and candidate, which the pack index holds. Callers
        // refresh the index once per read (see `refresh_pack_index`).
        let (generation, current_candidate): (u64, Option<String>) = match self
            .db
            .query_row(
                "SELECT generation,candidate_digest FROM pack_summaries WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
        {
            Some(found) => found,
            None => {
                let pack = self.pack(id).await?;
                (
                    pack.generation,
                    pack.sealed.as_ref().map(|s| s.candidate.to_string()),
                )
            }
        };

        let mut stmt = self.db.prepare("SELECT id,generation,candidate_digest,reviewer,decision,reason,created_at,evidence_digest FROM reviews WHERE pack_id=?1 ORDER BY created_at,id")?;
        let rows = stmt
            .query_map([id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, u64>(6)?,
                    r.get::<_, Option<String>>(7)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows.into_iter().map(|(review_id,row_generation,candidate,reviewer,decision,reason,created_at,evidence_digest)| {
            let stale = row_generation != generation || current_candidate.as_deref() != Some(&candidate);
            json!({"id":review_id,"pack_id":id,"generation":row_generation,"candidate_digest":candidate,"reviewer":reviewer,"decision":decision,"reason":reason,"created_at":created_at,"evidence_digest":evidence_digest,"stale":stale})
        }).collect())
    }

    pub async fn create_baseline(
        &self,
        label: &str,
        members: Vec<Digest>,
    ) -> Result<(BaselineId, Digest)> {
        if label.trim().is_empty() || members.is_empty() {
            return Err(invalid(
                "baseline needs a label and at least one promoted pack digest",
            ));
        }
        let (id, digest) = self.client.create_baseline(members, vec![]).await?;
        self.db.execute(
            "INSERT INTO baseline_metadata VALUES (?1,?2,?3,?4)",
            params![id.to_string(), digest.to_string(), label, now()?],
        )?;
        event(&self.db, "baseline.created", &id.to_string(), label)?;
        Ok((id, digest))
    }

    pub fn list_baselines(&self) -> Result<Vec<Value>> {
        let mut stmt = self
            .db
            .prepare("SELECT id,digest,label FROM baseline_metadata ORDER BY created_at,id")?;
        let rows = stmt.query_map([], |r| Ok(json!({"id":r.get::<_,String>(0)?,"digest":r.get::<_,String>(1)?,"label":r.get::<_,String>(2)?})))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub async fn baseline(&self, id: &str) -> Result<Value> {
        let baseline = self.resolve_baseline_id(id)?;
        Ok(self.client.query(Query::GetBaseline { baseline }).await?)
    }

    fn resolve_baseline_id(&self, id_or_alias: &str) -> Result<BaselineId> {
        if let Ok(id) = id_or_alias.parse::<BaselineId>() {
            return Ok(id);
        }
        let stored: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM preferences WHERE key=?1",
                [format!("baseline.alias.{id_or_alias}")],
                |row| row.get(0),
            )
            .optional()?;
        stored
            .ok_or_else(|| invalid(format!("unknown baseline or alias {id_or_alias}")))?
            .parse()
            .map_err(|_| invalid("invalid stored baseline alias"))
    }

    fn local_baseline_digest(&self, id: BaselineId) -> Result<Digest> {
        let stored: String = self
            .db
            .query_row(
                "SELECT digest FROM baseline_metadata WHERE id=?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    invalid(format!("unknown local baseline {id}"))
                }
                error => Error::Database(error),
            })?;
        stored
            .parse()
            .map_err(|_| invalid("invalid stored baseline digest"))
    }

    pub async fn validate_baseline(&self, id_or_alias: &str) -> Result<Value> {
        let id = self.resolve_baseline_id(id_or_alias)?;
        let digest = self.local_baseline_digest(id)?;
        Ok(self
            .client
            .query(Query::ValidateBaseline { digest })
            .await?)
    }

    pub async fn baseline_graph(&self, id_or_alias: &str) -> Result<Value> {
        let baseline = self.resolve_baseline_id(id_or_alias)?;
        Ok(self
            .client
            .query(Query::GetBaselineClosure { baseline })
            .await?)
    }

    async fn baseline_typed(&self, id_or_alias: &str) -> Result<Baseline> {
        let id = self.resolve_baseline_id(id_or_alias)?;
        let response = self
            .client
            .query(Query::GetBaseline { baseline: id })
            .await?;
        let envelope: ObjectEnvelope = serde_json::from_value(
            response
                .get("envelope")
                .ok_or_else(|| invalid("missing Baseline envelope"))?
                .clone(),
        )?;
        if envelope.kind != ObjectKind::Baseline || envelope.namespace != self.identity.namespace_id
        {
            return Err(invalid("unexpected Baseline object"));
        }
        let baseline: Baseline = serde_json::from_value(envelope.body)?;
        if baseline.id != id {
            return Err(invalid("Baseline identity mismatch"));
        }
        Ok(baseline)
    }

    pub async fn compare_baselines(&self, left: &str, right: &str) -> Result<Value> {
        let a = self.baseline_typed(left).await?;
        let b = self.baseline_typed(right).await?;
        let a_closure = self.baseline_graph(&a.id.to_string()).await?;
        let b_closure = self.baseline_graph(&b.id.to_string()).await?;
        let a_missing: Vec<Digest> = serde_json::from_value(
            a_closure
                .get("missing")
                .ok_or_else(|| invalid("invalid Baseline closure"))?
                .clone(),
        )?;
        let b_missing: Vec<Digest> = serde_json::from_value(
            b_closure
                .get("missing")
                .ok_or_else(|| invalid("invalid Baseline closure"))?
                .clone(),
        )?;
        let a_members: BTreeSet<_> = a.members.iter().copied().collect();
        let b_members: BTreeSet<_> = b.members.iter().copied().collect();
        let a_edges: BTreeSet<_> = a.edges.iter().cloned().collect();
        let b_edges: BTreeSet<_> = b.edges.iter().cloned().collect();
        Ok(json!({
            "left":a.id,"right":b.id,
            "shared_members":a_members.intersection(&b_members).collect::<Vec<_>>(),
            "only_left_members":a_members.difference(&b_members).collect::<Vec<_>>(),
            "only_right_members":b_members.difference(&a_members).collect::<Vec<_>>(),
            "shared_edges":a_edges.intersection(&b_edges).collect::<Vec<_>>(),
            "only_left_edges":a_edges.difference(&b_edges).collect::<Vec<_>>(),
            "only_right_edges":b_edges.difference(&a_edges).collect::<Vec<_>>(),
            "left_heads":a.heads,"right_heads":b.heads,
            "left_graph_digest":a.graph_digest,"right_graph_digest":b.graph_digest,
            "left_missing_objects":a_missing,"right_missing_objects":b_missing,
        }))
    }

    pub fn list_baseline_aliases(&self) -> Result<Vec<Value>> {
        let mut stmt = self.db.prepare(
            "SELECT key,value FROM preferences WHERE key LIKE 'baseline.alias.%' ORDER BY key",
        )?;
        let rows = stmt.query_map([], |row| {
            let key: String = row.get(0)?;
            let target: String = row.get(1)?;
            Ok(json!({"alias":key.trim_start_matches("baseline.alias."),"baseline_id":target}))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn set_baseline_alias(&self, alias: &str, target: &str) -> Result<String> {
        if alias.is_empty()
            || alias.len() > 64
            || !alias.as_bytes()[0].is_ascii_lowercase()
            || !alias
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_'))
        {
            return Err(invalid(
                "alias must start with a lowercase letter and contain only lowercase letters, digits, '-' or '_', up to 64 characters",
            ));
        }
        let id = self.resolve_baseline_id(target)?;
        self.local_baseline_digest(id)?;
        self.db.execute("INSERT INTO preferences(key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![format!("baseline.alias.{alias}"), id.to_string()])?;
        event(&self.db, "baseline.alias.set", alias, &id.to_string())?;
        Ok(id.to_string())
    }

    pub fn remove_baseline_alias(&self, alias: &str) -> Result<()> {
        let changed = self.db.execute(
            "DELETE FROM preferences WHERE key=?1",
            [format!("baseline.alias.{alias}")],
        )?;
        if changed == 0 {
            return Err(invalid(format!("unknown baseline alias {alias}")));
        }
        event(&self.db, "baseline.alias.removed", alias, "")
    }

    pub async fn activate_baseline(&self, id_or_alias: &str) -> Result<String> {
        let id = self.resolve_baseline_id(id_or_alias)?.to_string();
        let validation = self.validate_baseline(&id).await?;
        if validation.get("valid").and_then(Value::as_bool) != Some(true) {
            return Err(invalid(format!(
                "baseline {id} failed validation: {}",
                validation["problems"]
            )));
        }
        self.db.execute("INSERT INTO preferences(key,value) VALUES ('active_baseline',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [&id])?;
        event(&self.db, "baseline.activated", &id, "")?;
        Ok(id)
    }

    pub fn active_baseline(&self) -> Result<Option<String>> {
        let mut stmt = self
            .db
            .prepare("SELECT value FROM preferences WHERE key='active_baseline'")?;
        let mut rows = stmt.query([])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }

    pub fn product_activity(&self, limit: u16) -> Result<Vec<Value>> {
        let mut rows = Vec::new();
        self.for_each_product_activity(i64::from(limit), |row| {
            rows.push(row);
            Ok(())
        })?;
        Ok(rows)
    }

    fn for_each_product_activity(
        &self,
        limit: i64,
        mut visit: impl FnMut(Value) -> Result<()>,
    ) -> Result<()> {
        let mut stmt = self.db.prepare("SELECT seq,kind,subject,detail,created_at,created_at_ns FROM product_events ORDER BY seq DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit], |r| Ok(json!({"sequence":r.get::<_,i64>(0)?,"kind":r.get::<_,String>(1)?,"subject":r.get::<_,String>(2)?,"detail":r.get::<_,String>(3)?,"created_at":r.get::<_,u64>(4)?,"created_at_ns":r.get::<_,i64>(5)?})))?;
        for row in rows {
            visit(row?)?;
        }
        Ok(())
    }

    pub async fn protocol_activity(&self, limit: u16) -> Result<Value> {
        Ok(json!(self.protocol_activity_events(limit).await?))
    }

    async fn protocol_activity_events(&self, limit: u16) -> Result<Vec<Event>> {
        if !(1..=1000).contains(&limit) {
            return Err(invalid("activity limit must be 1–1000"));
        }
        let checkpoint = match self.client.query(Query::GetJournalCheckpoint {}).await {
            Ok(value) => value["envelope"]["body"]["sequence"]
                .as_u64()
                .ok_or_else(|| invalid("invalid OpenAEVC journal checkpoint"))?,
            Err(error) if error.code == ErrorCode::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        let mut recent = VecDeque::<Event>::new();
        self.scan_protocol_events(
            checkpoint.saturating_sub(u64::from(limit) + CHECKPOINT_INTERVAL),
            |event| {
                recent.push_back(event);
                if recent.len() > usize::from(limit) {
                    recent.pop_front();
                }
                Ok(())
            },
        )
        .await?;
        Ok(recent.into())
    }

    async fn scan_protocol_events(
        &self,
        mut cursor: u64,
        mut visit: impl FnMut(Event) -> Result<()>,
    ) -> Result<()> {
        loop {
            let page = self
                .client
                .query(Query::ListEvents {
                    after: cursor,
                    limit: Some(1000),
                    kinds: vec![],
                })
                .await?;
            let page: Vec<Event> = serde_json::from_value(page)?;
            if page.is_empty() {
                break;
            }
            let count = page.len();
            for event in page {
                if event.sequence <= cursor {
                    return Err(invalid("OpenAEVC event cursor did not advance"));
                }
                cursor = event.sequence;
                visit(event)?;
            }
            if count < 1000 {
                break;
            }
        }
        Ok(())
    }

    /// Merges presentation rows while retaining each journal's own event identity and sequence.
    pub async fn activity(&self, limit: u16) -> Result<Vec<Value>> {
        self.activity_with_filter(limit, &ActivityFilter::default())
            .await
    }

    pub async fn activity_with_filter(
        &self,
        limit: u16,
        filter: &ActivityFilter,
    ) -> Result<Vec<Value>> {
        if !(1..=1000).contains(&limit) {
            return Err(invalid("activity limit must be 1–1000"));
        }
        let bounds = filter.time_bounds()?;
        let full_scan = filter.needs_full_scan();
        let mut rows: Vec<ActivityRow> = Vec::new();
        let product_limit = if full_scan {
            i64::MAX
        } else {
            i64::from(limit)
        };
        if filter.source.as_deref() != Some("openaevc") {
            self.for_each_product_activity(product_limit, |product| {
            let sequence = product["sequence"]
                .as_u64()
                .ok_or_else(|| invalid("invalid product activity sequence"))?;
            let nanos = product["created_at_ns"]
                .as_i64()
                .ok_or_else(|| invalid("invalid product activity timestamp"))?;
            let nanos = i128::from(nanos);
            let kind = product["kind"]
                .as_str()
                .ok_or_else(|| invalid("invalid product activity kind"))?;
            let subject = product["subject"]
                .as_str()
                .ok_or_else(|| invalid("invalid product activity subject"))?;
            let detail = product["detail"]
                .as_str()
                .ok_or_else(|| invalid("invalid product activity detail"))?;
            let row = json!({
                "id":format!("calve:{sequence}"),"source":"calve","source_event_id":sequence.to_string(),
                "source_sequence":sequence,"project_id":self.identity.project_id,
                "namespace_id":self.identity.namespace_id,"actor":null,
                "timestamp":Timestamp::from_unix_nanos(nanos).to_string(),"kind":kind,
                "subject":subject,"subjects":[subject],"detail":detail,
                "summary":format!("{kind} {subject}"),"body":null
            });
                push_activity_row(&mut rows, (nanos, "calve", sequence, row), limit, filter, bounds);
                Ok(())
            })?;
        }
        let mut visit_protocol = |event: Event| {
            let nanos = event.timestamp.unix_nanos();
            let subject = event.subjects.first().cloned();
            let sequence = event.sequence;
            let row = json!({
                "id":format!("openaevc:{}",event.id),"source":"openaevc",
                "source_event_id":event.id,"source_sequence":event.sequence,
                "project_id":self.identity.project_id,"namespace_id":event.namespace,
                "actor":event.actor,"timestamp":event.timestamp,"kind":event.kind,
                "subject":subject,"subjects":event.subjects,
                "summary":format!("{} {}",event.kind,subject.as_deref().unwrap_or("")),
                "detail":null,"body":event.body
            });
            push_activity_row(
                &mut rows,
                (nanos, "openaevc", sequence, row),
                limit,
                filter,
                bounds,
            );
            Ok(())
        };
        if filter.source.as_deref() != Some("calve") {
            if full_scan {
                self.scan_protocol_events(0, &mut visit_protocol).await?;
            } else {
                for event in self.protocol_activity_events(limit).await? {
                    visit_protocol(event)?;
                }
            }
        }
        sort_activity_rows(&mut rows);
        rows.truncate(usize::from(limit));
        Ok(rows.into_iter().map(|(_, _, _, row)| row).collect())
    }

    pub async fn authority_principals(&self) -> Result<Vec<Value>> {
        let namespace = self.client.query(Query::GetNamespace {}).await?;
        let mut ids = BTreeSet::<PrincipalId>::new();
        for root in namespace["root_principals"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let id: PrincipalId = serde_json::from_value(root.clone())?;
            ids.insert(id);
        }
        self.scan_protocol_events(0, |event| {
            if event.kind == "principal.registered" {
                let id: PrincipalId =
                    serde_json::from_value(event.body["principal"]["id"].clone())?;
                ids.insert(id);
            }
            Ok(())
        })
        .await?;
        let mut principals = Vec::new();
        for principal in ids {
            principals.push(self.client.query(Query::GetPrincipal { principal }).await?);
        }
        Ok(principals)
    }

    pub async fn authority_grants(&self) -> Result<Vec<Value>> {
        let mut ids = BTreeSet::<GrantId>::new();
        self.scan_protocol_events(0, |event| {
            if event.kind == "grant.issued" {
                let id: GrantId = serde_json::from_value(event.body["grant"].clone())?;
                ids.insert(id);
            }
            Ok(())
        })
        .await?;
        let mut grants = Vec::new();
        for grant in ids {
            grants.push(self.client.query(Query::GetGrant { grant }).await?);
        }
        Ok(grants)
    }

    pub async fn authority_show(&self, id: &str) -> Result<Value> {
        if let Ok(principal) = id.parse::<PrincipalId>() {
            self.client
                .query(Query::GetPrincipal { principal })
                .await
                .map_err(Into::into)
        } else if let Ok(grant) = id.parse::<GrantId>() {
            self.client
                .query(Query::GetGrant { grant })
                .await
                .map_err(Into::into)
        } else {
            Err(invalid("authority show expects a principal or grant ID"))
        }
    }

    pub async fn authority_explain(
        &self,
        action: &str,
        principal: Option<&str>,
        resource: Option<ResourceRef>,
    ) -> Result<Value> {
        if action.trim().is_empty() {
            return Err(invalid("authority action cannot be empty"));
        }
        let principal: PrincipalId = match principal {
            Some(id) => id.parse().map_err(|_| invalid("invalid principal ID"))?,
            None => self.client.session().principal(),
        };
        self.client.query(Query::GetPrincipal { principal }).await?;
        let decision = self
            .client
            .query(Query::Authorize {
                principal,
                action: action.to_owned(),
                resource: resource.clone(),
            })
            .await?;
        let related_grants: Vec<Value> = self
            .authority_grants()
            .await?
            .into_iter()
            .filter(|grant| grant["grant"]["body"]["subject"] == principal.to_string())
            .collect();
        let matched_grants: Vec<Value> = related_grants
            .iter()
            .filter(|grant| {
                decision["grants"]
                    .as_array()
                    .is_some_and(|used| used.iter().any(|digest| *digest == grant["digest"]))
            })
            .cloned()
            .collect();
        let revocations: Vec<Value> = related_grants
            .iter()
            .filter(|grant| grant["revoked"] == true)
            .cloned()
            .collect();
        let grant_limits: Vec<Value> = related_grants
            .iter()
            .map(|grant| {
                json!({
                    "grant_id": grant["grant"]["body"]["id"],
                    "actions": grant["grant"]["body"]["actions"],
                    "resources": grant["grant"]["body"]["resources"],
                    "constraints": grant["grant"]["body"]["constraints"],
                    "not_before": grant["grant"]["body"]["not_before"],
                    "expires_at": grant["grant"]["body"]["expires_at"],
                    "revoked": grant["revoked"]
                })
            })
            .collect();
        Ok(json!({
            "principal":principal,"project_id":self.identity.project_id,
            "namespace_id":self.identity.namespace_id,"action":action,
            "required_capability":action,"resource":resource,
            "related_grants":related_grants,"matching_grants":matched_grants,
            "revocations":revocations,"grant_limits":grant_limits,
            "decision":decision
        }))
    }

    async fn grant_body(&self, options: &GrantOptions) -> Result<GrantBody> {
        let subject: PrincipalId = options
            .subject
            .parse()
            .map_err(|_| invalid("invalid grant subject principal ID"))?;
        self.client
            .query(Query::GetPrincipal { principal: subject })
            .await?;
        if options.actions.is_empty()
            || options
                .actions
                .iter()
                .any(|action| action.trim().is_empty())
        {
            return Err(invalid("grant needs at least one nonempty action"));
        }
        if options.locator_prefix.is_some() && options.resource_kind.is_none() {
            return Err(invalid("--locator-prefix requires --resource-kind"));
        }
        let actions: BTreeSet<String> = options.actions.iter().cloned().collect();
        let parse_time = |value: &str| -> Result<Timestamp> {
            value
                .parse::<Timestamp>()
                .map_err(|e| invalid(e.to_string()))
        };
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("system time before Unix epoch"))?;
        let nanos = i128::try_from(current.as_nanos())
            .map_err(|_| invalid("system time exceeds timestamp range"))?;
        let now = Timestamp::from_unix_nanos(nanos);
        let not_before = options
            .not_before
            .as_deref()
            .map(parse_time)
            .transpose()?
            .unwrap_or(now);
        let expires_at = parse_time(&options.expires_at)?;
        if expires_at <= now || expires_at <= not_before {
            return Err(invalid("grant expiry must be after now and not-before"));
        }
        let parent = options
            .parent
            .as_deref()
            .map(|value| value.parse::<Digest>().map_err(|e| invalid(e.to_string())))
            .transpose()?;
        let resources = options
            .resource_kind
            .as_ref()
            .map_or_else(Vec::new, |kind| {
                vec![ResourceSelector {
                    kind: kind.clone(),
                    locator_prefix: options.locator_prefix.clone(),
                }]
            });
        Ok(GrantBody {
            id: GrantId::from_bytes(*uuid::Uuid::now_v7().as_bytes())
                .map_err(|e| invalid(e.to_string()))?,
            namespace: self.identity.namespace_id,
            issuer: self.client.session().principal(),
            subject,
            actions,
            resources,
            constraints: BTreeMap::new(),
            not_before,
            expires_at,
            delegation_depth: options.delegation_depth,
            parent,
            nonce: uuid::Uuid::now_v7().to_string(),
        })
    }

    pub async fn authority_grant(&self, options: &GrantOptions) -> Result<Value> {
        let body = self.grant_body(options).await?;
        if !options.apply {
            let permission = self
                .client
                .query(Query::Authorize {
                    principal: body.issuer,
                    action: "grant.issue".into(),
                    resource: None,
                })
                .await?;
            return Ok(json!({
                "preview":true,"grant":body,"issuer_permission":permission,
                "broad_scope":body.resources.is_empty() || body.actions.contains("*")
            }));
        }
        let id = body.id;
        let digest = self.client.issue_grant(body).await?;
        let grant = self.client.query(Query::GetGrant { grant: id }).await?;
        Ok(json!({"grant_id":id,"digest":digest,"record":grant}))
    }

    pub async fn authority_revoke(&self, id: &str, reason: Option<&str>) -> Result<Value> {
        let grant: GrantId = id.parse().map_err(|_| invalid("invalid grant ID"))?;
        self.client.query(Query::GetGrant { grant }).await?;
        let receipt = self
            .client
            .command(Command::RevokeCapabilityGrant {
                grant,
                reason: reason.map(str::to_owned),
            })
            .await?;
        let record = self.client.query(Query::GetGrant { grant }).await?;
        Ok(json!({"receipt":receipt,"record":record}))
    }

    async fn refresh_inbox(&self) -> Result<()> {
        let mut sources: Vec<(String, String, String, String, String)> = Vec::new();
        let executions = self.list_executions(None, None).await?;
        for execution in executions
            .as_array()
            .ok_or_else(|| invalid("OpenAEVC execution list was not an array"))?
        {
            let state = execution["state"].as_str().unwrap_or("");
            if matches!(state, "FAILED" | "LOST") {
                let id = execution["id"]
                    .as_str()
                    .ok_or_else(|| invalid("execution has no ID"))?;
                sources.push((
                    format!("execution:{id}:{state}"),
                    "execution".into(),
                    id.into(),
                    format!("Execution {state}"),
                    "danger".into(),
                ));
            }
        }
        for pack in self.list_packs().await? {
            let id = pack["id"]
                .as_str()
                .ok_or_else(|| invalid("pack has no ID"))?;
            if pack["state"] == "QUARANTINED" {
                sources.push((
                    format!("pack:{id}:quarantined"),
                    "quarantined_pack".into(),
                    id.into(),
                    "Pack is quarantined".into(),
                    "warning".into(),
                ));
            }
            for review in self.reviews(id).await? {
                if review["stale"] == true {
                    let review_id = review["id"]
                        .as_str()
                        .ok_or_else(|| invalid("review has no ID"))?;
                    sources.push((
                        format!("review:{review_id}:stale"),
                        "stale_review".into(),
                        id.into(),
                        "Review is stale after candidate change".into(),
                        "warning".into(),
                    ));
                }
            }
        }
        for task in self.tasks_with_protocol().await? {
            let issues = task["inconsistencies"]
                .as_array()
                .ok_or_else(|| invalid("task inconsistency list was not an array"))?;
            if let Some(issue) = issues.first().and_then(Value::as_str) {
                let id = task["id"]
                    .as_str()
                    .ok_or_else(|| invalid("task has no ID"))?;
                sources.push((
                    format!("task:{id}:inconsistent"),
                    "task_inconsistency".into(),
                    id.into(),
                    issue.into(),
                    "warning".into(),
                ));
            }
        }
        let timestamp = now()?;
        let tx = self.db.unchecked_transaction()?;
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS active_inbox_keys(source_key TEXT PRIMARY KEY); DELETE FROM active_inbox_keys;")?;
        for (key, kind, subject, summary, severity) in sources {
            tx.execute(
                "INSERT INTO active_inbox_keys(source_key) VALUES (?1)",
                [&key],
            )?;
            tx.execute(
                "INSERT INTO inbox_items(source_key,kind,subject,summary,severity,first_seen,last_seen)
                 VALUES (?1,?2,?3,?4,?5,?6,?6)
                 ON CONFLICT(source_key) DO UPDATE SET
                 kind=excluded.kind,subject=excluded.subject,summary=excluded.summary,
                 severity=excluded.severity,last_seen=excluded.last_seen,
                 first_seen=CASE WHEN inbox_items.resolved_at IS NULL THEN inbox_items.first_seen ELSE excluded.first_seen END,
                 read_at=CASE WHEN inbox_items.resolved_at IS NULL THEN inbox_items.read_at ELSE NULL END,
                 acknowledged_at=CASE WHEN inbox_items.resolved_at IS NULL THEN inbox_items.acknowledged_at ELSE NULL END,
                 snoozed_until=CASE WHEN inbox_items.resolved_at IS NULL THEN inbox_items.snoozed_until ELSE NULL END,
                 resolved_at=NULL",
                params![key, kind, subject, summary, severity, timestamp],
            )?;
        }
        tx.execute(
            "UPDATE inbox_items SET resolved_at=?1 WHERE resolved_at IS NULL
             AND source_key NOT IN (SELECT source_key FROM active_inbox_keys)",
            [timestamp],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub async fn inbox(&self, include_resolved: bool) -> Result<Vec<Value>> {
        self.refresh_inbox().await?;
        let mut stmt = self.db.prepare(
            "SELECT source_key,kind,subject,summary,severity,first_seen,last_seen,
             read_at,acknowledged_at,snoozed_until,resolved_at FROM inbox_items
             WHERE ?1 OR resolved_at IS NULL ORDER BY resolved_at IS NOT NULL,severity,first_seen,source_key",
        )?;
        let timestamp = now()?;
        let rows = stmt.query_map([include_resolved], |r| {
            let snoozed_until: Option<u64> = r.get(9)?;
            let acknowledged_at: Option<u64> = r.get(8)?;
            let resolved_at: Option<u64> = r.get(10)?;
            Ok(json!({
                "source_key":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,
                "subject":r.get::<_,String>(2)?,"summary":r.get::<_,String>(3)?,
                "severity":r.get::<_,String>(4)?,"first_seen":r.get::<_,u64>(5)?,
                "last_seen":r.get::<_,u64>(6)?,"read_at":r.get::<_,Option<u64>>(7)?,
                "acknowledged_at":acknowledged_at,"snoozed_until":snoozed_until,
                "resolved_at":resolved_at,
                "needs_attention": resolved_at.is_none() && acknowledged_at.is_none() && snoozed_until.is_none_or(|until| until <= timestamp)
            }))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub async fn update_inbox_item(
        &self,
        key: &str,
        action: &str,
        until: Option<u64>,
    ) -> Result<()> {
        self.refresh_inbox().await?;
        let timestamp = now()?;
        let changed = match action {
            "read" => self.db.execute(
                "UPDATE inbox_items SET read_at=COALESCE(read_at,?2) WHERE source_key=?1 AND resolved_at IS NULL",
                params![key, timestamp],
            )?,
            "acknowledge" => self.db.execute(
                "UPDATE inbox_items SET acknowledged_at=COALESCE(acknowledged_at,?2),read_at=COALESCE(read_at,?2) WHERE source_key=?1 AND resolved_at IS NULL",
                params![key, timestamp],
            )?,
            "snooze" => {
                let until = until.ok_or_else(|| invalid("snooze needs an until timestamp"))?;
                if until <= timestamp {
                    return Err(invalid("snooze timestamp must be in the future"));
                }
                let until = i64::try_from(until)
                    .map_err(|_| invalid("snooze timestamp exceeds SQLite range"))?;
                self.db.execute(
                    "UPDATE inbox_items SET snoozed_until=?2 WHERE source_key=?1 AND resolved_at IS NULL",
                    params![key, until],
                )?
            }
            "unsnooze" => self.db.execute(
                "UPDATE inbox_items SET snoozed_until=NULL WHERE source_key=?1 AND resolved_at IS NULL",
                [key],
            )?,
            _ => return Err(invalid("unknown inbox action")),
        };
        if changed == 0 {
            return Err(invalid(format!("no active inbox item {key}")));
        }
        event(&self.db, "inbox.item.updated", key, action)
    }

    /// Derived summary; every field comes from OpenAEVC queries or Calve metadata.
    pub async fn status(&self) -> Result<Value> {
        let packs = self.list_packs().await?;
        let tasks = self.tasks_with_protocol().await?;
        let mut project = serde_json::to_value(&self.identity)?;
        project["name"] = json!(self.display_name);
        let executions = self.list_executions(None, None).await?;
        let active: Vec<&Value> = executions
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| {
                matches!(
                    e["state"].as_str(),
                    Some("PENDING" | "ADMITTED" | "STARTING" | "RUNNING")
                )
            })
            .collect();
        let uncaptured = match self.scan_resources().await {
            Ok(scan) => json!(scan["uncaptured"].as_array().map_or(0, Vec::len)),
            Err(error) => json!({"error":error.to_string()}),
        };
        let attention = self
            .inbox(false)
            .await?
            .into_iter()
            .filter(|item| item["needs_attention"] == true)
            .count();
        let unhealthy: Vec<Value> = self
            .extension_health()
            .await?
            .as_array()
            .into_iter()
            .flatten()
            .filter(|item| item["healthy"] != true)
            .cloned()
            .collect();
        let blocked_tasks = tasks
            .iter()
            .filter(|task| task["state"] == "BLOCKED")
            .count();
        Ok(
            json!({"project":project,"active_baseline":self.active_baseline()?,"packs":packs,
            "tasks":tasks,"active_executions":active,"uncaptured_changes":uncaptured,
            "attention_items":attention,"blocked_tasks":blocked_tasks,
            "extension_problems":unhealthy}),
        )
    }
}
