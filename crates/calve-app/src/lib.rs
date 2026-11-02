//! Calve application layer: Projects, the product store, and every use case behind the API.
#![forbid(unsafe_code)]

pub use calve_api::{ActivityFilter, GrantOptions};

pub mod adopt;
pub mod app;
pub mod authority;
pub mod backup;
pub mod capture;
pub mod catalog;
pub mod checks;
mod claims;
pub mod client;
pub mod closure;
pub mod compatibility;
pub mod composition;
pub mod config;
pub mod content;
pub mod continuity;
pub(crate) mod domains;
pub mod envelope;
mod event_index;
pub mod extensions;
pub mod extsort;
pub mod gc;
pub mod general_ops;
pub mod identities;
pub mod integration;
pub mod journal;
mod lease;
pub mod manifests;
pub mod materialize;
pub mod observe;
pub mod ops;
pub mod promotion;
pub mod providers;
pub mod recovery;
pub mod redact;
pub mod registry;
pub mod resources;
pub mod sandbox;
pub mod supersede;
pub mod supervise;
pub mod views;
pub(crate) mod wal;
pub mod workspace_io;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{StreamExt as _, TryStreamExt as _};
use openaevc::core::{IdGeneratorExt, SystemClock, UuidV7Ids};
use openaevc::crypto::{Signer, SigningKey, sha256};
use openaevc::protocol::{
    Baseline, BaselineId, Blob, ChangePack, Command, Digest, EffectProposal, ErrorCode, Event,
    EvidenceCondition, ExecutionId, ExecutionState, Expr, GrantBody, GrantId, Metadata,
    NamespaceId, NewPrincipal, NodeRef, ObjectEnvelope, ObjectKind, PackId, PackSpec, PackState,
    PolicyDocument, PolicyRule, PrincipalId, PrincipalKind, ProviderDescriptor, Query, ResourceRef,
    ResourceSelector, RevisionRelation, Timestamp, VerificationStatus, VerifierCondition,
    WorkUnitId,
};
use openaevc::runtime::{Admin, Runtime, RuntimeConfig, RuntimeDeps};
use openaevc::store::{SqliteOptions, SqliteStore};
use openaevc_sdk::{OpenAevcClient, Session, TypedClient};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    /// A coded product error with machine-readable detail (`Fault::detail`).
    #[error("{code}: {message}")]
    Detailed {
        code: &'static str,
        message: String,
        detail: serde_json::Value,
    },
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

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

/// A coded product error carrying structured detail, e.g. a `RECOVERY_REQUIRED` reason or the
/// paths of a `MATERIALIZE_CONFLICT`.
pub(crate) fn detailed(
    code: &'static str,
    message: impl Into<String>,
    detail: serde_json::Value,
) -> Error {
    debug_assert!(calve_api::errors::is_code(code), "{code}");
    Error::Detailed {
        code,
        message: message.into(),
        detail,
    }
}

/// A product error with a stable code from [`calve_api::errors::CODES`] (`CODE: message`).
pub(crate) fn coded(code: &'static str, message: impl Into<String>) -> Error {
    debug_assert!(calve_api::errors::is_code(code), "{code}");
    Error::Message(format!("{code}: {}", message.into()))
}

const REVIEW_POLICY_NAME: &str = "org.calve.review.required/v1";
const REVIEW_APPROVAL_KIND: &str = "org.calve.review.approval/v1";
const REVIEW_REJECTION_KIND: &str = "org.calve.review.rejection/v1";
const CHECKPOINT_INTERVAL: u64 = 1000;

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
    )
    .map_err(|e| match e.code {
        openaevc::protocol::ErrorCode::Conflict => Error::Busy(format!(
            "{}; start the daemon so commands can share it",
            e.message
        )),
        _ => e.into(),
    })?;
    let clock = Arc::new(SystemClock);
    let ids = Arc::new(UuidV7Ids::new(clock.clone()));
    let admin = signing_key(&keys.admin_seed)?;
    let config = RuntimeConfig {
        admins: vec![Admin {
            id: keys.admin_id,
            public_key: admin.public_key(),
        }],
        // Installed packages (`<id>/<sha256>/<binary>`, immutable, TUF-verified).
        extension_dirs: extensions::extension_dir().into_iter().collect(),
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

/// `.calve/{cache,run,logs,tmp}` (§12.1), private on Unix.
fn ensure_layout(state: &Path) -> Result<()> {
    for dir in ["cache", "run", "logs", "tmp"] {
        let d = state.join(dir);
        if !d.is_dir() {
            crate::journal::private_dir(&d)?;
        }
    }
    Ok(())
}

/// Keeps `.calve/` out of Git when the Project root is a Git checkout (§12.1): one line in the
/// repository's `info/exclude` (local, never committed). `.git` may be a directory or a
/// `gitdir:` file (worktrees, submodules).
pub fn exclude_from_git(root: &Path) -> Result<()> {
    let dot_git = root.join(".git");
    let git_dir = if dot_git.is_dir() {
        dot_git
    } else if let Ok(text) = fs::read_to_string(&dot_git)
        && let Some(dir) = text.strip_prefix("gitdir:")
    {
        let dir = root.join(dir.trim());
        // A linked worktree keeps `info/` in the common directory.
        match fs::read_to_string(dir.join("commondir")) {
            Ok(common) => dir.join(common.trim()),
            Err(_) => dir,
        }
    } else {
        return Ok(());
    };
    let exclude = git_dir.join("info/exclude");
    let text = fs::read_to_string(&exclude).unwrap_or_default();
    if text
        .lines()
        .any(|l| matches!(l.trim(), "/.calve/" | ".calve/" | "/.calve" | ".calve"))
    {
        return Ok(());
    }
    fs::create_dir_all(git_dir.join("info"))?;
    let sep = if text.is_empty() || text.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    fs::write(
        &exclude,
        format!("{text}{sep}# Calve local state\n/.calve/\n"),
    )?;
    Ok(())
}

/// OpenAEVC pack metadata Calve sets at creation: the title, so the pack index can be rebuilt
/// from OpenAEVC after the product database is lost or restored from an older backup (§10).
fn calve_pack_metadata(title: &str) -> Metadata {
    let mut m = Metadata::new();
    m.insert("org.calve.title".into(), json!(title));
    m
}

/// The public key of a Project's runtime signer (verifies its signed journal checkpoints).
pub(crate) fn project_runtime_key(state: &Path) -> Result<openaevc::protocol::PublicKey> {
    let keys: Keys = toml::from_str(&fs::read_to_string(authority::keys_for(state)?)?)?;
    Ok(signing_key(&keys.runtime_seed)?.public_key())
}

pub(crate) fn write_private(path: &Path, content: &str) -> Result<()> {
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
           created_at_ns INTEGER NOT NULL, actor TEXT
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
         INSERT INTO schema_migrations VALUES (13);
         INSERT INTO schema_migrations VALUES (14);
         CREATE TABLE store_binding (
           id INTEGER PRIMARY KEY CHECK (id = 1),
           project_id TEXT NOT NULL, namespace_id TEXT NOT NULL, genesis_hash TEXT NOT NULL,
           checkpoint_seq INTEGER NOT NULL, checkpoint_hash TEXT NOT NULL,
           signed_checkpoint TEXT, updated_at TEXT NOT NULL
         );";

/// Current product database schema.
pub const PRODUCT_SCHEMA: u32 = 17;

/// Exact counts and the most recent items per live pack state.
type LiveSummary = (BTreeMap<String, u64>, BTreeMap<String, Vec<Value>>);

/// Pack items per live state in `status` (counts stay exact).
const STATUS_ITEMS: u64 = 50;

/// Forward migrations: entry `i` takes version `i + 1` to `i + 2`.
const MIGRATIONS: &[fn(&mut Connection) -> Result<()>] = &[
    migrate_task_dependencies,
    migrate_review_evidence,
    migrate_task_metadata,
    migrate_inbox,
    migrate_intents,
    migrate_task_links,
    migrate_activity_time,
    migrate_intent_references,
    migrate_task_work_units,
    migrate_extension_grants,
    migrate_pack_index,
    migrate_pack_files,
    migrate_store_binding,
    migrate_pack_commitments,
    migrate_read_model_indexes,
    migrate_execution_claims,
];

/// How the product database is opened (§46.4: only a writer migrates, after the gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbOpen {
    Create,
    /// Apply pending migrations, each run preceded by a verified backup.
    Migrate,
    /// Refuse a database that needs migration (`MIGRATION_REQUIRED`).
    Current,
}

/// Schema version of a product database without opening it for writing.
pub fn product_schema_version(path: &Path) -> Result<u32> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(db.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

pub(crate) fn init_db(path: &Path, mode: DbOpen) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | if mode == DbOpen::Create {
            OpenFlags::SQLITE_OPEN_CREATE
        } else {
            OpenFlags::empty()
        };
    let mut db = Connection::open_with_flags(path, flags)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;")?;
    let version: u32 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    match (version, mode) {
        (0, DbOpen::Create) => {
            let tx = db.transaction()?;
            tx.execute_batch(PROJECT_SCHEMA)?;
            tx.execute_batch(PACK_COMMITMENTS_SCHEMA)?;
            read_model_schema(&tx)?;
            tx.execute_batch(EXECUTION_CLAIMS_SCHEMA)?;
            tx.execute_batch("INSERT INTO schema_migrations VALUES (15); INSERT INTO schema_migrations VALUES (17); INSERT INTO schema_migrations VALUES (16);")?;
            tx.execute_batch(&format!("PRAGMA user_version={PRODUCT_SCHEMA}"))?;
            tx.commit()?;
            return Ok(db);
        }
        (_, DbOpen::Create) => return Err(invalid("project database already exists")),
        (v, _) if v > PRODUCT_SCHEMA => {
            return Err(coded(
                "MIGRATION_REQUIRED",
                format!(
                    "project database schema version {v} is newer than this Calve supports ({PRODUCT_SCHEMA}); upgrade Calve"
                ),
            ));
        }
        (v, _) if v == PRODUCT_SCHEMA => return Ok(db),
        (v, DbOpen::Current) => {
            return Err(coded(
                "MIGRATION_REQUIRED",
                format!(
                    "project database schema {v} needs migration to {PRODUCT_SCHEMA}; run a command that changes the Project (it backs the database up first)"
                ),
            ));
        }
        _ => {}
    }
    // The first Calve slice recorded schema_migrations but not SQLite user_version.
    let from = if version == 0 {
        let legacy: Option<u32> = db
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| {
                coded(
                    "CORRUPT_PRODUCT_STATE",
                    "unrecognized project database schema",
                )
            })?
            .flatten();
        if legacy != Some(1) {
            return Err(coded(
                "CORRUPT_PRODUCT_STATE",
                "unrecognized project database schema",
            ));
        }
        1
    } else {
        version
    };
    // §10: a verified backup precedes every migration run.
    crate::backup::take(&db, path, "pre-migration", from)?;
    crate::journal::fault("migration.after_backup");
    for migrate in &MIGRATIONS[(from - 1) as usize..] {
        migrate(&mut db)?;
        crate::journal::fault("migration.step");
    }
    // Migration log (§45.1).
    crate::observe::record(
        "migration",
        serde_json::json!({"database": "project", "path": path, "from": version, "to": PRODUCT_SCHEMA}),
    );
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

/// v15 (§12): the versioned product commitment of each pack. Any product change to a pack's
/// links (task links, intent, title) bumps its version through triggers, so the supersede
/// saga's compare-and-swap sees concurrent changes. A pack without a row is `active` at 0.
const PACK_COMMITMENTS_SCHEMA: &str = "CREATE TABLE pack_commitments (
           pack_id TEXT PRIMARY KEY,
           state TEXT NOT NULL DEFAULT 'active'
             CHECK (state IN ('active','replacement_pending','superseded','conflicted')),
           commitment_version INTEGER NOT NULL DEFAULT 0,
           supersede_id TEXT, replaces TEXT
         );
         CREATE TRIGGER pack_link_added AFTER INSERT ON task_links WHEN NEW.kind = 'pack' BEGIN
           INSERT INTO pack_commitments(pack_id, commitment_version) VALUES (NEW.object_id, 1)
           ON CONFLICT(pack_id) DO UPDATE SET commitment_version = commitment_version + 1;
         END;
         CREATE TRIGGER pack_link_removed AFTER DELETE ON task_links WHEN OLD.kind = 'pack' BEGIN
           INSERT INTO pack_commitments(pack_id, commitment_version) VALUES (OLD.object_id, 1)
           ON CONFLICT(pack_id) DO UPDATE SET commitment_version = commitment_version + 1;
         END;
         CREATE TRIGGER pack_link_moved AFTER UPDATE OF object_id ON task_links WHEN NEW.kind = 'pack' BEGIN
           INSERT INTO pack_commitments(pack_id, commitment_version) VALUES (OLD.object_id, 1)
           ON CONFLICT(pack_id) DO UPDATE SET commitment_version = commitment_version + 1;
           INSERT INTO pack_commitments(pack_id, commitment_version) VALUES (NEW.object_id, 1)
           ON CONFLICT(pack_id) DO UPDATE SET commitment_version = commitment_version + 1;
         END;
         CREATE TRIGGER pack_metadata_changed AFTER UPDATE ON pack_metadata BEGIN
           INSERT INTO pack_commitments(pack_id, commitment_version) VALUES (NEW.id, 1)
           ON CONFLICT(pack_id) DO UPDATE SET commitment_version = commitment_version + 1;
         END;";

fn migrate_pack_commitments(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(PACK_COMMITMENTS_SCHEMA)?;
    tx.execute_batch("INSERT INTO schema_migrations VALUES (15); PRAGMA user_version=15;")?;
    tx.commit()?;
    Ok(())
}

const STORE_BINDING_SCHEMA: &str = "CREATE TABLE store_binding (
           id INTEGER PRIMARY KEY CHECK (id = 1),
           project_id TEXT NOT NULL, namespace_id TEXT NOT NULL, genesis_hash TEXT NOT NULL,
           checkpoint_seq INTEGER NOT NULL, checkpoint_hash TEXT NOT NULL,
           signed_checkpoint TEXT, updated_at TEXT NOT NULL
         );";

/// v14: the §11 store binding and checkpoint, and the actor of product activity (P18).
/// Bounded read models (M6): keyset order of packs and Intents, state and promoted digest
/// lookups, moves by source path, and the latest check result per pack generation (projected
/// from the protocol journal with its own checkpoint). Status, the inbox and the console never
/// enumerate the store or rescan the journal.
const READ_MODEL_INDEXES: &str = "
    CREATE TABLE IF NOT EXISTS pack_results (
      key TEXT PRIMARY KEY, pack TEXT NOT NULL, generation INTEGER NOT NULL,
      bad INTEGER NOT NULL, kind TEXT NOT NULL, summary TEXT NOT NULL, severity TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS pack_results_bad ON pack_results(bad, pack, generation);
    CREATE INDEX IF NOT EXISTS pack_metadata_order ON pack_metadata(created_at, id);
    CREATE INDEX IF NOT EXISTS pack_summaries_state ON pack_summaries(state);
    CREATE INDEX IF NOT EXISTS pack_summaries_promoted ON pack_summaries(promoted_digest);
    CREATE INDEX IF NOT EXISTS pack_files_from ON pack_files(from_path);
    CREATE INDEX IF NOT EXISTS intents_order ON intents(created_at, id);
    CREATE INDEX IF NOT EXISTS product_events_subject ON product_events(subject, seq);
    CREATE INDEX IF NOT EXISTS product_events_detail ON product_events(detail, seq);
";

/// Request id → receipt (OpenAEVC stores receipts under their request id but cannot look
/// one up by it); immutable rows, filled by `refresh_receipt_index`.
pub(crate) const RECEIPT_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS receipt_index (
      request_id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, command TEXT NOT NULL,
      caller TEXT NOT NULL, completed_at TEXT NOT NULL, result TEXT NOT NULL
    );";

/// The read-model schema; idempotent, so a database whose version was lowered (tests, a
/// partial run) migrates again cleanly.
fn read_model_schema(tx: &rusqlite::Transaction) -> Result<()> {
    tx.execute_batch(READ_MODEL_INDEXES)?;
    tx.execute_batch(RECEIPT_SCHEMA)?;
    tx.execute_batch(event_index::SCHEMA)?;
    let has_size: bool = tx.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('pack_files') WHERE name='size'",
        [],
        |r| r.get(0),
    )?;
    if !has_size {
        tx.execute_batch("ALTER TABLE pack_files ADD COLUMN size INTEGER;")?;
    }
    Ok(())
}

fn migrate_read_model_indexes(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    read_model_schema(&tx)?;
    // pack_files gained `size`: the pack projection rebuilds itself from OpenAEVC once. The
    // checkpoint goes to 0 rather than away, so `recover inspect` still reports the lag.
    tx.execute_batch(
        "INSERT INTO projection_checkpoints VALUES ('packs',0)
           ON CONFLICT(name) DO UPDATE SET sequence=0;
         DELETE FROM pack_summaries; DELETE FROM pack_files;
         INSERT INTO schema_migrations VALUES (16);
         PRAGMA user_version=16;",
    )?;
    tx.commit()?;
    Ok(())
}

const EXECUTION_CLAIMS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS execution_claims (
    execution_id TEXT PRIMARY KEY,
    pack_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    paths TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    finished_at INTEGER
);";

fn migrate_execution_claims(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(EXECUTION_CLAIMS_SCHEMA)?;
    tx.execute_batch(
        "INSERT INTO schema_migrations VALUES (17);
         PRAGMA user_version=17;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_store_binding(db: &mut Connection) -> Result<()> {
    let tx = db.transaction()?;
    tx.execute_batch(STORE_BINDING_SCHEMA)?;
    tx.execute_batch(
        "ALTER TABLE product_events ADD COLUMN actor TEXT;
         INSERT INTO schema_migrations VALUES (14);
         PRAGMA user_version=14;",
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
        "INSERT INTO product_events(kind,subject,detail,created_at,created_at_ns,actor) VALUES (?1,?2,?3,?4,?5,?6)",
        params![kind, subject, detail, time.as_secs(), nanos, crate::app::current_actor()],
    )?;
    Ok(())
}

/// One file change recorded by a capture execution (host-generic `calve.file/1` payloads; the
/// effect kinds come from the file domain's signed declaration).
#[derive(Debug, Clone)]
pub(crate) enum FileChange {
    Put(String, Vec<u8>),
    Delete { path: String, previous: Digest },
}

impl FileChange {
    fn path(&self) -> &str {
        match self {
            Self::Put(path, _) | Self::Delete { path, .. } => path,
        }
    }

    fn digest(&self) -> Option<Digest> {
        match self {
            Self::Put(_, content) => Some(sha256(content)),
            Self::Delete { .. } => None,
        }
    }

    fn effect(&self, d: &domains::FileDomain) -> EffectProposal {
        let (kind, payload) = match self {
            // Over the inline limit: a chunked payload whose chunks the capture session fills
            // in after uploading them (rev 10 §13).
            Self::Put(_, content)
                if content.len() as u64 > calve_integration_contract::content::INLINE_MAX
                    && d.decl.put_chunked.is_some() =>
            {
                (
                    d.decl.put_chunked.clone().unwrap_or_default(),
                    json!({"digest":sha256(content),"size":content.len(),"chunks":[]}),
                )
            }
            Self::Put(_, content) => (
                d.decl.put.clone(),
                json!({"digest":sha256(content),"size":content.len(),"content":openaevc::protocol::b64::encode(content)}),
            ),
            Self::Delete { previous, .. } => {
                (d.decl.delete.clone(), json!({"previous_digest":previous}))
            }
        };
        EffectProposal {
            kind,
            target: ResourceRef {
                kind: d.decl.resource_kind.clone(),
                locator: self.path().to_owned(),
                version: None,
                extension: d.extension.clone(),
            },
            payload,
            preconditions: vec![],
            outputs: vec![],
        }
    }

    fn summary(&self) -> Value {
        match self {
            Self::Put(path, content) => {
                json!({"path":path,"change":"snapshot","digest":sha256(content)})
            }
            Self::Delete { path, previous } => {
                json!({"path":path,"change":"delete","previous_digest":previous})
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
    pub client: crate::client::Client,
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
        // Exclusive creation, as before; then private (on Windows created private outright).
        #[cfg(not(windows))]
        fs::create_dir(&staging)?;
        crate::journal::private_dir(&staging)?;
        fs::create_dir(staging.join("extensions"))?;
        ensure_layout(&staging)?;
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
            let admin_client = crate::client::Client::new(
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
            authority::write_keys(&identity.project_id, &toml::to_string(&keys)?)?;
            authority::bind(&identity.project_id, &root)?;
            fs::write(staging.join("project.toml"), toml::to_string(&identity)?)?;
            let db = init_db(&staging.join("product.sqlite3"), DbOpen::Create)?;
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
        exclude_from_git(&root)?;
        Self::open(&root)
    }

    pub(crate) fn tick(&self) {
        let _ = self.runtime.tick();
    }

    /// Walks up from `start` to the first directory holding `.calve/project.toml` (§13.3),
    /// stopping at the filesystem root or at a boundary in `CALVE_DISCOVERY_CEILING` (absolute
    /// directories separated by the platform path separator; the search never looks at or
    /// above one). Diagnostics name both the entered and the canonical path.
    pub fn discover(start: &Path) -> Result<PathBuf> {
        let ceilings: Vec<PathBuf> = std::env::var_os("CALVE_DISCOVERY_CEILING")
            .map(|v| std::env::split_paths(&v).collect())
            .unwrap_or_default();
        Self::discover_bounded(start, &ceilings)
    }

    /// [`Project::discover`] with explicit ceilings (relative entries are ignored).
    pub fn discover_bounded(start: &Path, ceilings: &[PathBuf]) -> Result<PathBuf> {
        let canonical = fs::canonicalize(start).map_err(|e| {
            detailed(
                "PROJECT_NOT_FOUND",
                format!("{}: {e}", start.display()),
                serde_json::json!({"entered": start}),
            )
        })?;
        let ceilings: Vec<PathBuf> = ceilings
            .iter()
            .filter(|p| p.is_absolute())
            .map(|p| fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
            .collect();
        let mut current = canonical.clone();
        if current.is_file() {
            current.pop();
        }
        loop {
            if ceilings.contains(&current) {
                break;
            }
            if current.join(".calve/project.toml").is_file() {
                return Ok(current);
            }
            if !current.pop() {
                break;
            }
        }
        let shown = if canonical == start {
            start.display().to_string()
        } else {
            format!("{} (canonical {})", start.display(), canonical.display())
        };
        Err(detailed(
            "PROJECT_NOT_FOUND",
            format!("no Calve Project at or above {shown}"),
            serde_json::json!({"entered": start, "canonical": canonical, "stopped_at": current,
                "ceilings": ceilings}),
        ))
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
            return Err(crate::coded(
                "MIGRATION_REQUIRED",
                "unsupported project format",
            ));
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

    /// Opens for writing (commands): the §46.4 gate, then migration with a backup, continuity,
    /// and the checkpoint advance.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with(path, true)
    }

    /// Opens for queries: the same gate and continuity check, but never migrates and never
    /// advances the checkpoint.
    pub fn open_reader(path: &Path) -> Result<Self> {
        Self::open_with(path, false)
    }

    fn open_with(path: &Path, writer: bool) -> Result<Self> {
        let root = Self::discover(path)?;
        let state = root.join(".calve");
        if fs::symlink_metadata(&state)?.file_type().is_symlink() {
            return Err(invalid(".calve must be a real project directory"));
        }
        let identity: ProjectIdentity =
            toml::from_str(&fs::read_to_string(state.join("project.toml"))?)?;
        if !matches!(identity.format_version, 1 | 2) {
            return Err(crate::coded(
                "MIGRATION_REQUIRED",
                "unsupported project format",
            ));
        }
        authority::migrate_legacy(&state, &identity, &root)?;
        let key_path = authority::keys_path(&identity.project_id)?;
        if !key_path.is_file() {
            return Err(authority::unavailable(&identity.project_id));
        }
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
        // §46.4 gate, nothing written until every check passed: product database version,
        // OpenAEVC protocol/contract, enabled extensions.
        let db_path = state.join("product.sqlite3");
        if !db_path.is_file() {
            return Err(coded(
                "CORRUPT_PRODUCT_STATE",
                "project product database is missing; restore a backup, or rebuild with `calve recover apply --rebuild-product --yes`, with `calve recover apply --restore-backup <file>`",
            ));
        }
        let version = product_schema_version(&db_path)?;
        if version > PRODUCT_SCHEMA {
            return Err(coded(
                "MIGRATION_REQUIRED",
                format!(
                    "project database schema version {version} is newer than this Calve supports ({PRODUCT_SCHEMA}); upgrade Calve"
                ),
            ));
        }
        let runtime = make_runtime(&state, &keys, false)?;
        let client = crate::client::Client::new(
            runtime.clone(),
            Session::new(
                signing_key(&keys.root_seed)?,
                identity.created_by,
                Some(identity.namespace_id),
            ),
        );
        let gate =
            |q: Query| -> Result<Value> { Ok(runtime.query(client.session().envelope(q)?)?) };
        let info = gate(Query::GetRuntimeInfo {}).map_err(|e| match e {
            // The store does not know this Project's namespace or principal: another store.
            Error::Protocol(p)
                if p.code == ErrorCode::Unauthorized || p.code == ErrorCode::NotFound =>
            {
                detailed(
                    "RECOVERY_REQUIRED",
                    format!(
                        "the OpenAEVC store under {} does not hold this Project's namespace {}",
                        state.display(),
                        identity.namespace_id
                    ),
                    json!({"reason": "identity_mismatch", "openaevc": *p}),
                )
            }
            other => other,
        })?;
        compatibility::check(&serde_json::from_value(info)?)?;
        compatibility::check_enabled_extensions(&gate)?;
        let db = init_db(
            &db_path,
            if writer {
                DbOpen::Migrate
            } else {
                DbOpen::Current
            },
        )?;
        let runtime_key = signing_key(&keys.runtime_seed)?.public_key();
        continuity::verify(
            &db,
            &identity,
            &continuity::RuntimeEvents {
                runtime: &runtime,
                session: client.session(),
            },
            &runtime_key,
            writer,
        )?;
        if writer {
            ensure_layout(&state)?;
            backup::daily_if_due(&db, &db_path, PRODUCT_SCHEMA)?;
        }
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
        self.list_intents_page(None, None)
    }

    /// Intents in `(created_at, id)` order, after the Intent `after` (keyset paging, R15), at
    /// most `limit`. No `limit`: all of them.
    pub fn list_intents_page(&self, after: Option<&str>, limit: Option<u32>) -> Result<Vec<Value>> {
        if let Some(after) = after {
            let known: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM intents WHERE id=?1)",
                [after],
                |r| r.get(0),
            )?;
            if !known {
                return Err(crate::coded("NOT_FOUND", format!("unknown intent {after}")));
            }
        }
        self.intent_rows(
            "WHERE ?1 IS NULL OR (created_at,id) > (SELECT created_at,id FROM intents WHERE id=?1)
             ORDER BY created_at,id LIMIT ?2",
            rusqlite::params![after, limit.map_or(-1, i64::from)],
        )
    }

    fn intent_rows(&self, tail: &str, params: impl rusqlite::Params) -> Result<Vec<Value>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT id,title,description,tags,state,created_at,updated_at,actors,graph_node FROM intents {tail}"
        ))?;
        let rows = stmt.query_map(params, |r| {
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
        self.intent_rows("WHERE id=?1", [id])?
            .into_iter()
            .next()
            .ok_or_else(|| crate::coded("NOT_FOUND", format!("unknown intent {id}")))
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
            return Err(crate::coded("NOT_FOUND", format!("unknown intent {id}")));
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
            .ok_or_else(|| crate::coded("NOT_FOUND", format!("unknown intent {id}")))?;
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
            .ok_or_else(|| crate::coded("NOT_FOUND", format!("unknown intent {intent}")))?;
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
            return Err(crate::coded("NOT_FOUND", format!("unknown task {id}")));
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
            .ok_or_else(|| crate::coded("NOT_FOUND", format!("unknown task {id}")))
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
                    .ok_or_else(|| crate::coded("NOT_FOUND", format!("unknown task {id}")))
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
            let (owner, decl) = self.language_owner(key).await?;
            policies.push(PolicyDocument {
                name: format!("{}.checks-required", owner.id),
                description: Some(format!("Require passing {key} checks on the candidate")),
                rules: vec![PolicyRule {
                    id: "checks-pass".into(),
                    expr: Expr::Verifier(VerifierCondition {
                        kind: decl.verifier,
                        status: VerificationStatus::Pass,
                    }),
                }],
            });
        }
        if require_snapshot_verification {
            let d = self.file_domain().await?;
            let verifier =
                d.decl.verifier.clone().ok_or_else(|| {
                    invalid(format!("{} declares no snapshot verifier", d.extension))
                })?;
            policies.push(PolicyDocument {
                name: format!("{}.snapshot-required", d.extension),
                description: Some(
                    "Require a passing verification of the sealed file snapshots".into(),
                ),
                rules: vec![PolicyRule {
                    id: "snapshot-pass".into(),
                    expr: Expr::Verifier(VerifierCondition {
                        kind: verifier,
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
                return Err(crate::coded("NOT_FOUND", format!("unknown intent {id}")));
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
            metadata: calve_pack_metadata(title),
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

    /// The pack, required OPEN at `generation`: STALE_VIEW when the generation moved,
    /// OPENAEVC_OPERATION_REJECTED when it is no longer open.
    pub(crate) async fn open_pack_at(&self, id: &str, generation: u64) -> Result<ChangePack> {
        let pack = self.pack(id).await?;
        if pack.generation != generation {
            return Err(detailed(
                "STALE_VIEW",
                format!(
                    "the pack is at generation {}, not {generation}",
                    pack.generation
                ),
                json!({"expected": generation, "current": pack.generation}),
            ));
        }
        if pack.state != PackState::Open {
            return Err(detailed(
                "OPENAEVC_OPERATION_REJECTED",
                format!("the pack is {}, not OPEN", pack.state.as_str()),
                json!({"state": pack.state.as_str(), "generation": pack.generation}),
            ));
        }
        Ok(pack)
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
                    // ChangePacks and RevisionPacks.
                    .filter(|s| s.starts_with("cpk_") || s.starts_with("rpk_"))
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
        // Only the dirty ids: an unchanged Project does no full-table read here.
        let mut known: BTreeSet<String> = {
            let mut stmt = self.db.prepare(
                "SELECT id FROM pack_metadata WHERE id IN (SELECT value FROM json_each(?1))",
            )?;
            stmt.query_map([json!(dirty).to_string()], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        // Reconciliation (§10–§11): a Calve pack whose metadata row is missing (database lost
        // or restored from an older backup) is re-adopted from its OpenAEVC metadata.
        let unknown: Vec<String> = dirty
            .iter()
            .filter(|id| !known.contains(*id))
            .cloned()
            .collect();
        for id in &unknown {
            let Ok(pack) = self.pack(id).await else {
                continue;
            };
            let Some(title) = pack.metadata.get("org.calve.title").and_then(Value::as_str) else {
                continue;
            };
            let intent = pack
                .intent
                .as_ref()
                .and_then(|i| i["org.calve.intent"].as_str())
                .filter(|i| {
                    self.db
                        .query_row("SELECT 1 FROM intents WHERE id=?1", [i], |_| Ok(()))
                        .is_ok()
                });
            self.db.execute(
                "INSERT OR IGNORE INTO pack_metadata VALUES (?1,?2,?3,?4)",
                params![id, title, intent, pack.created_at.to_string()],
            )?;
            known.insert(id.clone());
        }
        // The file domain classifies file effects; without one no files are indexed.
        let domain = self.file_domain().await.ok();
        // Every pack is read from OpenAEVC first; the rows are written afterwards in one short
        // transaction with no await inside, so requests sharing this connection meanwhile run
        // their own transactions (M7: a transaction held across awaits made them fail).
        let wanted: Vec<String> = dirty.into_iter().filter(|id| known.contains(id)).collect();
        let packs: Vec<ChangePack> = futures_util::stream::iter(wanted.iter())
            .map(|id| self.pack(id))
            .buffered(READ_BATCH)
            .try_collect()
            .await?;
        crate::journal::fault("projection.after_fetch");
        let tx = self.db.unchecked_transaction()?;
        for (id, pack) in wanted.into_iter().zip(packs) {
            // The intent link is OpenAEVC's (`pack.intent`); a crash after the update but
            // before Calve recorded it is reconciled here.
            let intent = pack
                .intent
                .as_ref()
                .and_then(|i| i["org.calve.intent"].as_str())
                .filter(|i| {
                    tx.query_row("SELECT 1 FROM intents WHERE id=?1", [i], |_| Ok(()))
                        .is_ok()
                });
            tx.execute(
                "UPDATE pack_metadata SET intent_id=?1 WHERE id=?2 AND intent_id IS NOT ?1",
                params![intent, id],
            )?;
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
            for (position, (effect, change)) in pack
                .candidate_effects
                .iter()
                .filter_map(|e| {
                    let d = domain.as_ref()?;
                    d.is_file_effect(e).then_some(())?;
                    Some((e, resources::change_label(d, &e.kind)?))
                })
                .enumerate()
            {
                tx.execute(
                    "INSERT INTO pack_files(pack,position,path,change,digest,from_path,size)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        id,
                        position as i64,
                        effect.target.locator,
                        change,
                        effect.payload["digest"].as_str(),
                        effect.payload["from"].as_str(),
                        effect.payload["size"].as_i64()
                    ],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO projection_checkpoints VALUES ('packs',?1) ON CONFLICT(name) DO UPDATE SET sequence=excluded.sequence",
            [head],
        )?;
        tx.commit()?;
        crate::journal::fault("projection.after_commit");
        Ok(())
    }

    /// Clears derived projections so the next read rebuilds them from OpenAEVC.
    pub(crate) fn reset_pack_index(&self) -> Result<()> {
        // A restored store may lack receipts the index named; it is rebuilt with the rest.
        self.db.execute_batch(RECEIPT_SCHEMA)?;
        self.db.execute_batch(
            "DELETE FROM pack_summaries; DELETE FROM pack_files; DELETE FROM pack_results;
             DELETE FROM receipt_index;
             DELETE FROM event_index; DELETE FROM event_refs;
             DELETE FROM projection_checkpoints
               WHERE name IN ('packs','results','events','events.v2','receipts');",
        )?;
        Ok(())
    }

    /// Projects the latest verification, evaluation and qualification result per pack
    /// generation and check (`pack_results`) from the protocol journal since its checkpoint. A
    /// later result for the same key replaces an earlier one, so a passing re-run resolves a
    /// failure, exactly as a full journal scan would decide it.
    pub(crate) async fn refresh_pack_results(&self) -> Result<()> {
        let checkpoint: u64 = self
            .db
            .query_row(
                "SELECT sequence FROM projection_checkpoints WHERE name='results'",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let mut rows: Vec<(
            String,
            String,
            u64,
            bool,
            &'static str,
            String,
            &'static str,
        )> = Vec::new();
        let mut head = checkpoint;
        self.scan_protocol_events(checkpoint, |e| {
            head = e.sequence;
            let pack = e.body["pack"].as_str().unwrap_or_default().to_owned();
            let Some(g) = e.body["generation"].as_u64() else {
                return Ok(());
            };
            let row = match e.kind.as_str() {
                "verification.completed" => {
                    let (v, st) = (
                        e.body["verifier"].as_str().unwrap_or("?"),
                        e.body["status"].as_str().unwrap_or("?"),
                    );
                    (
                        format!("verification:{pack}:{g}:{v}"),
                        matches!(st, "FAIL" | "ERROR"),
                        "verification_failed",
                        format!("Verification {v}: {st}"),
                        "danger",
                    )
                }
                "evaluation.completed" => {
                    let (v, st) = (
                        e.body["evaluator"].as_str().unwrap_or("?"),
                        e.body["verdict"].as_str().unwrap_or("?"),
                    );
                    (
                        format!("evaluation:{pack}:{g}:{v}"),
                        matches!(st, "WARN" | "DENY"),
                        "evaluation_warning",
                        format!("Evaluation {v}: {st}"),
                        if st == "DENY" { "danger" } else { "warning" },
                    )
                }
                "qualification.evaluated" => (
                    format!("qualification:{pack}:{g}"),
                    e.body["outcome"] == "DENY",
                    "promotion_blocked",
                    "Qualification denied; the pack cannot be promoted".to_owned(),
                    "danger",
                ),
                _ => return Ok(()),
            };
            rows.push((row.0, pack, g, row.1, row.2, row.3, row.4));
            Ok(())
        })
        .await?;
        let tx = self.db.unchecked_transaction()?;
        for (key, pack, g, bad, kind, summary, severity) in rows {
            tx.execute(
                "INSERT INTO pack_results VALUES (?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(key) DO UPDATE SET bad=excluded.bad, kind=excluded.kind,
                 summary=excluded.summary, severity=excluded.severity",
                params![key, pack, g, bad, kind, summary, severity],
            )?;
        }
        tx.execute(
            "INSERT INTO projection_checkpoints VALUES ('results',?1) ON CONFLICT(name) DO UPDATE SET sequence=excluded.sequence",
            [head],
        )?;
        tx.commit()?;
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
            return Err(crate::coded(
                "INVALID_ARGUMENT",
                "receipt page limit must be 1–100",
            ));
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
            return Err(crate::coded(
                "INVALID_ARGUMENT",
                "evidence page limit must be 1–100",
            ));
        }
        let pack = self.pack(id).await?;
        // The pack's registrations come from the event index (bounded by this pack's evidence,
        // not the store); pages keep OpenAEVC's digest order so `--after` means what it did.
        let mut registered: Vec<(Digest, Value)> = Vec::new();
        for event in self
            .events_of_kind_referencing("evidence.registered", &pack.id.to_string())
            .await?
        {
            if event.body["pack"] != json!(pack.id) {
                continue;
            }
            let digest: Digest = serde_json::from_value(event.body["evidence"].clone())?;
            registered.push((digest, event.body));
        }
        registered.sort_by_key(|a| a.0.to_string());
        registered.dedup_by(|a, b| a.0 == b.0);
        let stale = |body: &Value| {
            body["generation"] != json!(pack.generation)
                || pack
                    .sealed
                    .as_ref()
                    .is_none_or(|seal| body["candidate"] != json!(seal.candidate))
        };
        let mut rest = registered
            .into_iter()
            .filter(|(d, _)| after.as_ref().is_none_or(|a| d.to_string() > a.to_string()))
            .filter(|(_, body)| !current_only || !stale(body))
            .peekable();
        let mut items = Vec::new();
        let mut last = None;
        while items.len() < limit as usize
            && let Some((digest, registration)) = rest.next()
        {
            let object = self.evidence(digest).await?;
            let body = &object["envelope"]["body"];
            items.push(json!({"digest":digest,"evidence":body,"stale":stale(&registration)}));
            last = Some(digest);
        }
        let next = if rest.peek().is_some() { last } else { None };
        Ok(json!({"items":items,"next":next}))
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
            return Err(crate::coded(
                "NOT_FOUND",
                format!("unknown intent {intent_id}"),
            ));
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
        self.list_packs_page(None, None).await
    }

    /// Packs in `(created_at, id)` order after the pack `after` (keyset paging, R15), at most
    /// `limit`. No `limit`: all of them.
    pub async fn list_packs_page(
        &self,
        after: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        self.packs_page(after, limit, false, &PackFilter::default())
            .await
    }

    /// `newest_first`: `(created_at, id)` descending, `after` continuing downwards; `filter`
    /// narrows by state, ids or promoted digests through the pack index.
    pub(crate) async fn packs_page(
        &self,
        after: Option<&str>,
        limit: Option<u32>,
        newest_first: bool,
        filter: &PackFilter<'_>,
    ) -> Result<Vec<Value>> {
        self.refresh_pack_index().await?;
        if let Some(after) = after {
            let known: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM pack_metadata WHERE id=?1)",
                [after],
                |r| r.get(0),
            )?;
            if !known {
                return Err(crate::coded("NOT_FOUND", format!("unknown pack {after}")));
            }
        }
        let (cmp, order) = if newest_first {
            ("<", "DESC")
        } else {
            (">", "ASC")
        };
        let mut stmt = self.db.prepare(&format!(
            "SELECT m.id,m.title,m.intent_id,s.state,s.generation,s.candidate_digest,s.promoted_digest,
                    s.created_at,s.updated_at,s.changed,s.revision,c.state
             FROM pack_metadata m JOIN pack_summaries s ON s.id=m.id
             LEFT JOIN pack_commitments c ON c.pack_id=m.id
             WHERE (c.state IS NULL OR c.state != 'replacement_pending')
               AND (?1 IS NULL
                    OR (m.created_at,m.id) {cmp} (SELECT created_at,id FROM pack_metadata WHERE id=?1))
               AND (?3 IS NULL OR s.state=?3)
               AND (?4 IS NULL OR m.id IN (SELECT value FROM json_each(?4)))
               AND (?5 IS NULL OR s.promoted_digest IN (SELECT value FROM json_each(?5)))
             ORDER BY m.created_at {order},m.id {order} LIMIT ?2",
        ))?;
        // A pending supersession is shown on the pack it replaces, never as success (§12).
        let superseding = crate::supersede::pending(&self.root)?;
        let list = |v: Option<&[String]>| v.map(|v| json!(v).to_string());
        let params = rusqlite::params![
            after,
            limit.map_or(-1, i64::from),
            filter.state,
            list(filter.ids),
            list(filter.promoted)
        ];
        let rows = stmt.query_map(params, |r| {
            Ok(
                json!({"id":r.get::<_,String>(0)?,"title":r.get::<_,String>(1)?,
                "intent":r.get::<_,Option<String>>(2)?,"state":r.get::<_,String>(3)?,
                "generation":r.get::<_,u64>(4)?,"candidate_digest":r.get::<_,Option<String>>(5)?,
                "promoted_digest":r.get::<_,Option<String>>(6)?,"created_at":r.get::<_,String>(7)?,
                "updated_at":r.get::<_,String>(8)?,"changed":r.get::<_,i64>(9)?,
                "revision":r.get::<_,bool>(10)?,
                "commitment":r.get::<_,Option<String>>(11)?.unwrap_or_else(|| "active".into())}),
            )
        })?;
        let mut rows = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        for row in &mut rows {
            if let Some((saga, step)) = row["id"].as_str().and_then(|id| superseding.get(id)) {
                row["superseding"] = json!({"saga": saga, "pending_step": step,
                    "display": format!("superseding (pending: {step})")});
            }
        }
        Ok(rows)
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
                return Err(crate::coded("NOT_FOUND", format!("unknown intent {id}")));
            }
        }
        let spec = PackSpec {
            intent: intent.map(|id| json!({"org.calve.intent":id})),
            required_policies: self.register_pack_policies(false, require_review).await?,
            metadata: calve_pack_metadata(title),
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

    /// Captures one file (or its deletion) through the file extension's capture session, a
    /// signed OpenAEVC execution and extension effect. Ignored files may be captured by name.
    pub async fn capture_file(
        &self,
        pack_id: &str,
        expected_generation: u64,
        path: &Path,
    ) -> Result<Value> {
        let locator = resources::relative_locator(path)?;
        let d = self.file_domain().await?;
        let plan = self.plan_paths(&d, std::slice::from_ref(&locator)).await?;
        if let Some((_, reason)) = plan.refused.first() {
            return Err(invalid(format!("CAPTURE_REFUSED: {locator}: {reason}")));
        }
        let batch = self
            .submit_capture(pack_id, expected_generation, &d, plan, None)
            .await?;
        let item = batch["captured"]
            .as_array()
            .and_then(|items| items.first())
            .or_else(|| {
                batch["unchanged"]
                    .as_array()
                    .and_then(|items| items.first())
            })
            .cloned()
            .unwrap_or_else(|| json!({"path":locator,"digest":null}));
        Ok(
            json!({"path":locator,"digest":item["digest"],"generation":batch["generation"],
            "execution":batch["execution"],"work_unit":batch["work_unit"],
            "unchanged":batch["captured"].as_array().is_none_or(Vec::is_empty)}),
        )
    }

    /// Submits a capture plan in one execution. `retry` reuses the failed attempt's work unit so
    /// OpenAEVC links the successor attempt. Relations are recorded verbatim as observations of
    /// their declared kind with the related effects (§6.5b); omissions are recorded too.
    pub(crate) async fn submit_capture(
        &self,
        pack_id: &str,
        expected_generation: u64,
        d: &domains::FileDomain,
        plan: resources::CapturePlan,
        retry: Option<(WorkUnitId, ExecutionId)>,
    ) -> Result<Value> {
        let pack = self.open_pack_at(pack_id, expected_generation).await?;
        let refused: Vec<Value> = plan
            .refused
            .iter()
            .map(|(p, r)| json!({"path":p,"reason":r}))
            .collect();
        let files = plan.changes;
        if files.is_empty() {
            return Ok(
                json!({"generation":pack.generation,"captured":[],"unchanged":[],"refused":refused,"relations":[]}),
            );
        }
        if let Some(big) = files
            .iter()
            .find(|c| matches!(c, FileChange::Put(_, b) if b.len() as u64 > d.capture_limit()))
        {
            return Err(detailed(
                "FILE_TOO_LARGE",
                format!(
                    "{} exceeds the {}-byte capture limit",
                    big.path(),
                    d.capture_limit()
                ),
                json!({"path": big.path(), "limit": d.capture_limit()}),
            ));
        }
        if !pack.candidate_effects.is_empty() {
            let unchanged: Vec<Value> = files
                .iter()
                .filter_map(|change| {
                    let FileChange::Put(locator, content) = change else {
                        return None;
                    };
                    let digest = sha256(content);
                    pack.candidate_effects
                        .iter()
                        .rev()
                        .find(|e| d.is_file_effect(e) && e.target.locator == *locator)
                        .filter(|e| {
                            e.kind == d.decl.put && e.payload["digest"] == digest.to_string()
                        })
                        .map(|_| json!({"path":locator,"digest":digest}))
                })
                .collect();
            if unchanged.len() == files.len() {
                return Ok(
                    json!({"generation":pack.generation,"captured":[],"unchanged":unchanged,"refused":refused,"relations":[]}),
                );
            }
            return Err(invalid(
                "pack already has capture effects; add new or changed files in a new pack so provenance stays valid",
            ));
        }
        let (harness, provider) = (d.capture_harness(), d.provider());
        // §12: the whole plan becomes a spool before any OpenAEVC command.
        let mut observations: Vec<capture::SpoolObservation> = files
            .iter()
            .map(|change| capture::SpoolObservation {
                kind: d.captured_observation(),
                payload: change.summary(),
                related_resources: vec![change.effect(d).target],
                related_paths: vec![],
            })
            .collect();
        let mut relations = Vec::new();
        for r in &plan.relations {
            let paths: Vec<String> = r
                .members
                .iter()
                .filter_map(|i| plan.op_paths.get(*i as usize).cloned())
                .collect();
            relations.push(json!({"kind":r.kind,"paths":paths,"payload":r.payload}));
            observations.push(capture::SpoolObservation {
                kind: r.kind.clone(),
                payload: r.payload.clone(),
                related_resources: vec![],
                related_paths: paths,
            });
        }
        observations.push(capture::SpoolObservation {
            kind: format!("{}.capture-session", d.extension),
            payload: json!({"input_digest":plan.input_digest,"output_digest":plan.output_digest,
                "relations_omitted":plan.omitted,"refused":refused}),
            related_resources: vec![],
            related_paths: vec![],
        });
        // Chunk layout of the files over the inline limit; their bytes go to the session.
        let mut chunked = vec![];
        let mut chunk_data = vec![];
        for (i, c) in files.iter().enumerate() {
            if let FileChange::Put(path, content) = c
                && content.len() as u64 > calve_integration_contract::content::INLINE_MAX
            {
                let digest = sha256(content).to_string();
                let chunks = content
                    .chunks(calve_integration_contract::content::CHUNK_MAX as usize)
                    .map(|b| (sha256(b).to_string(), b.len() as u64))
                    .collect();
                chunked.push(capture::SpoolChunked {
                    index: i,
                    path: path.clone(),
                    digest: digest.clone(),
                    size: content.len() as u64,
                    chunks,
                });
                chunk_data.push((digest, content.clone()));
            }
        }
        let spool = capture::Spool {
            chunk_kind: format!("{}.content-chunk", d.extension),
            chunked,
            pack: pack.id,
            generation: pack.generation,
            provider: ProviderDescriptor {
                id: provider.clone(),
                version: "0.1.0".into(),
                worker_kinds: vec![harness.clone()],
                harnesses: vec![harness.clone()],
                required_actions: vec![d.decl.write_action.clone()],
                cancellation: true,
                resumable: false,
                heartbeat: false,
                limits: BTreeMap::new(),
                provenance_fields: vec![],
                principal: self.identity.created_by,
            },
            harness,
            allowed_resources: files
                .iter()
                .map(|c| ResourceSelector {
                    kind: d.decl.resource_kind.clone(),
                    locator_prefix: Some(c.path().to_owned()),
                })
                .collect(),
            allowed_effects: [
                Some(d.decl.put.clone()),
                Some(d.decl.delete.clone()),
                d.decl.put_chunked.clone(),
            ]
            .into_iter()
            .flatten()
            .collect(),
            proposals: files.iter().map(|c| c.effect(d)).collect(),
            observations,
            captured: files.iter().map(FileChange::summary).collect(),
            refused,
            relations,
            events: files
                .iter()
                .map(|c| {
                    (
                        c.path().to_owned(),
                        c.digest()
                            .map_or_else(|| "deleted".to_owned(), |d| d.to_string()),
                    )
                })
                .collect(),
            input_digest: plan.input_digest.clone(),
            output_digest: plan.output_digest.clone(),
            retry,
        };
        self.run_capture(spool, chunk_data).await
    }

    /// Runs the first-party snapshot verifier against a sealed candidate.
    pub async fn verify_snapshots(
        &self,
        pack_id: &str,
        expected_generation: u64,
        expected: Option<(&Path, Digest)>,
    ) -> Result<Value> {
        let d = self.file_domain().await?;
        let verifier = d
            .decl
            .verifier
            .clone()
            .ok_or_else(|| invalid(format!("{} declares no snapshot verifier", d.extension)))?;
        let pack = self.pack(pack_id).await?;
        if pack.generation != expected_generation || pack.sealed.is_none() {
            return Err(coded(
                "STALE_VIEW",
                "pack must be sealed at the requested generation",
            ));
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
            .run_verification(pack.id, pack.generation, &verifier, config)
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
        let d = self.file_domain().await?;
        let evaluator =
            d.decl.evaluator.clone().ok_or_else(|| {
                invalid(format!("{} declares no change-size evaluator", d.extension))
            })?;
        let pack = self.pack(pack_id).await?;
        if pack.generation != expected_generation
            || !matches!(pack.state, PackState::Sealed | PackState::Qualified)
        {
            return Err(coded(
                "STALE_VIEW",
                "pack must be sealed at the requested generation",
            ));
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
            .run_evaluation(pack.id, pack.generation, &evaluator, Value::Object(config))
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
            return Err(detailed(
                "STALE_VIEW",
                format!("generation conflict: current is {}", pack.generation),
                json!({"expected": expected_generation, "current": pack.generation}),
            ));
        }
        if let Ok(state) = self.db.query_row(
            "SELECT state FROM pack_commitments WHERE pack_id=?1",
            [id],
            |r| r.get::<_, String>(0),
        ) && state == "replacement_pending"
        {
            return Err(detailed(
                "SUPERSEDE_CONFLICT",
                "this pack is a pending replacement; it becomes usable when its supersession completes",
                json!({"pack": id}),
            ));
        }
        // §12 guard: Calve refuses to seal while a capture session is not terminal.
        let captures = self.incomplete_captures(&pack)?;
        if !captures.is_empty() {
            return Err(detailed(
                "CAPTURE_INCOMPLETE",
                "a capture session on this pack has not finished; resume or roll it back first",
                json!({"captures": captures}),
            ));
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
        // OpenAEVC v0.1.0 keeps a pack's effects on reopen and promotes only effects of the
        // current generation, so this reopen would strand the pack for good. Refused here,
        // before anything changes; continuing is an explicit choice, never a side effect.
        if !pack.candidate_effects.is_empty() {
            let effects = pack.candidate_effects.len();
            return Err(detailed(
                "REOPEN_UNSAFE",
                format!(
                    "{id} has {effects} effect(s); after a reopen OpenAEVC v0.1.0 could never promote it. It is unchanged. Continue in a replacement pack: `calve supersede start {id} --keep <0..{effects}> --yes`"
                ),
                json!({"pack": id, "generation": pack.generation, "effects": effects,
                    "next": ["supersede", "start", id, "--keep", effects.to_string()]}),
            ));
        }
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
        self.create_baseline_with(label, members, vec![], None)
            .await
    }

    /// Creates a Baseline from explicit members and caller edges (REQUIRES/ORDERS_AFTER);
    /// OpenAEVC validates the composition. The label (and the base of a derivation) is kept in
    /// the object's metadata too, so the index can be rebuilt from OpenAEVC.
    pub async fn create_baseline_with(
        &self,
        label: &str,
        members: Vec<Digest>,
        edges: Vec<openaevc::protocol::CompositionEdge>,
        derived_from: Option<Digest>,
    ) -> Result<(BaselineId, Digest)> {
        if label.trim().is_empty() || members.is_empty() {
            return Err(invalid(
                "baseline needs a label and at least one promoted pack digest",
            ));
        }
        let receipt = self
            .client
            .command(Command::CreateBaseline {
                members,
                edges,
                policies: vec![],
                metadata: composition::baseline_metadata(label, derived_from),
            })
            .await?;
        let id: BaselineId = receipt
            .result
            .id
            .ok_or_else(|| invalid("baseline creation returned no ID"))?
            .parse()
            .map_err(|_| invalid("baseline creation returned an invalid ID"))?;
        let digest = receipt
            .result
            .digest
            .ok_or_else(|| invalid("baseline creation returned no digest"))?;
        self.db.execute(
            "INSERT INTO baseline_metadata VALUES (?1,?2,?3,?4)",
            params![id.to_string(), digest.to_string(), label, now()?],
        )?;
        event(&self.db, "baseline.created", &id.to_string(), label)?;
        Ok((id, digest))
    }

    /// Every Baseline in the Namespace (OpenAEVC is authoritative; labels from the index or the
    /// object's metadata), with its aliases and whether it is active.
    pub async fn list_baselines(&self) -> Result<Vec<Value>> {
        let active = self.active_baseline()?;
        let aliases = self.list_baseline_aliases()?;
        Ok(self
            .protocol_baselines()
            .await?
            .into_iter()
            .map(|(digest, b)| {
                let id = b.id.to_string();
                json!({"id": id, "digest": digest, "label": self.baseline_label(&b),
                    "members": b.members.len(), "heads": b.heads, "graph_digest": b.graph_digest,
                    "derived_from": b.metadata.get("org.calve.derived_from"),
                    "aliases": aliases.iter().filter(|a| a["baseline_id"] == id.as_str()).map(|a| a["alias"].clone()).collect::<Vec<_>>(),
                    "active": active.as_deref() == Some(id.as_str())})
            })
            .collect())
    }

    /// Rebuilds the Baseline index from OpenAEVC (labels kept, missing rows re-created).
    pub(crate) async fn rebuild_baseline_index(&self) -> Result<usize> {
        let mut n = 0;
        for (digest, b) in self.protocol_baselines().await? {
            let label = self
                .baseline_label(&b)
                .unwrap_or_else(|| "(unlabelled)".into());
            n += self.db.execute(
                "INSERT OR IGNORE INTO baseline_metadata VALUES (?1,?2,?3,?4)",
                params![b.id.to_string(), digest.to_string(), label, now()?],
            )?;
        }
        Ok(n)
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
            .ok_or_else(|| {
                crate::coded(
                    "NOT_FOUND",
                    format!("unknown baseline or alias {id_or_alias}"),
                )
            })?
            .parse()
            .map_err(|_| invalid("invalid stored baseline alias"))
    }

    pub async fn validate_baseline(&self, id_or_alias: &str) -> Result<Value> {
        let (digest, _) = self.baseline_object(id_or_alias).await?;
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
            return Err(crate::coded(
                "CORRUPT_PRODUCT_STATE",
                "Baseline identity mismatch",
            ));
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
            "revisions": {"left": self.baseline_revisions(&a).await?, "right": self.baseline_revisions(&b).await?},
            "resources": self.compare_resources(&a, &b).await?,
        }))
    }

    /// Domain-level difference of two compositions (file state by digest, §27.5).
    async fn compare_resources(&self, a: &Baseline, b: &Baseline) -> Result<Value> {
        let (fa, fb) = (self.composed_files(a).await?, self.composed_files(b).await?);
        let paths: BTreeSet<&String> = fa.files.keys().chain(fb.files.keys()).collect();
        let (mut only_left, mut only_right, mut different, mut same) = (vec![], vec![], vec![], 0);
        for p in paths {
            match (fa.files.get(p), fb.files.get(p)) {
                (Some(x), Some(y)) if x.0 == y.0 => same += 1,
                (Some(x), Some(y)) => different.push(json!({"path": p, "left": x.0, "right": y.0})),
                (Some(x), None) => only_left.push(json!({"path": p, "digest": x.0})),
                (None, Some(y)) => only_right.push(json!({"path": p, "digest": y.0})),
                (None, None) => {}
            }
        }
        Ok(
            json!({"same": same, "only_left": only_left, "only_right": only_right,
            "different": different,
            "unordered_overlaps": {"left": fa.unordered_overlaps, "right": fb.unordered_overlaps}}),
        )
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

    pub async fn set_baseline_alias(&self, alias: &str, target: &str) -> Result<String> {
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
        let id = self.baseline_object(target).await?.1.id;
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
            return Err(crate::coded(
                "NOT_FOUND",
                format!("unknown baseline alias {alias}"),
            ));
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
        self.for_each_product_activity(i64::from(limit), None, |row| {
            rows.push(row);
            Ok(())
        })?;
        Ok(rows)
    }

    /// Product events newest first; `reference` narrows to rows whose subject or detail is it,
    /// the only fields a reference filter can match on a product row (indexed, M6 R5).
    fn for_each_product_activity(
        &self,
        limit: i64,
        reference: Option<&str>,
        mut visit: impl FnMut(Value) -> Result<()>,
    ) -> Result<()> {
        // Separate statements: an `?2 IS NULL OR …` term would keep SQLite off the indexes.
        let mut stmt = self.db.prepare(if reference.is_some() {
            "SELECT seq,kind,subject,detail,created_at,created_at_ns,actor FROM product_events
             WHERE subject=?2 OR detail=?2 ORDER BY seq DESC LIMIT ?1"
        } else {
            "SELECT seq,kind,subject,detail,created_at,created_at_ns,actor FROM product_events
             WHERE ?2 IS NULL ORDER BY seq DESC LIMIT ?1"
        })?;
        let rows = stmt.query_map(params![limit, reference], |r| Ok(json!({"sequence":r.get::<_,i64>(0)?,"kind":r.get::<_,String>(1)?,"subject":r.get::<_,String>(2)?,"detail":r.get::<_,String>(3)?,"created_at":r.get::<_,u64>(4)?,"created_at_ns":r.get::<_,i64>(5)?,"actor":r.get::<_,Option<String>>(6)?})))?;
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
            let reference = [&filter.pack, &filter.task, &filter.execution]
                .into_iter()
                .flatten()
                .next()
                .map(String::as_str);
            self.for_each_product_activity(product_limit, reference, |product| {
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
                "namespace_id":self.identity.namespace_id,"actor":product["actor"],
                "timestamp":Timestamp::from_unix_nanos(nanos).to_string(),"kind":kind,
                "subject":subject,"subjects":[subject],"detail":detail,
                "summary":format!("{kind} {subject}"),"body":null
            });
                push_activity_row(&mut rows, (nanos, "calve", sequence, row), limit, filter, bounds);
                Ok(())
            })?;
        }
        let protocol_row = |event: Event| -> ActivityRow {
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
            (nanos, "openaevc", sequence, row)
        };
        if filter.source.as_deref() != Some("calve") {
            let refs: Vec<&str> = [&filter.pack, &filter.task, &filter.execution]
                .into_iter()
                .flatten()
                .map(String::as_str)
                .collect();
            if full_scan && refs.iter().all(|r| event_index::id_shaped(r)) {
                // Indexed candidates in ranking order; every one still passes `matches`. Stop
                // once `limit` rows are held and the next candidate is older than all of them.
                let c = event_index::Candidates {
                    kind: filter.event_type.as_deref(),
                    kind_prefix: filter.object_kind.as_deref(),
                    actor: filter.actor.as_deref(),
                    severity: filter.severity.as_deref(),
                    since_ns: bounds.0,
                    until_ns: bounds.1,
                    refs,
                };
                self.refresh_event_index().await?;
                let mut before = None;
                'pages: loop {
                    let page = self.candidate_events(&c, before, 200).await?;
                    let Some(last) = page.last() else { break };
                    before = Some((
                        i64::try_from(last.timestamp.unix_nanos()).unwrap_or(i64::MIN),
                        last.sequence,
                    ));
                    for event in page {
                        let nanos = event.timestamp.unix_nanos();
                        push_activity_row(&mut rows, protocol_row(event), limit, filter, bounds);
                        sort_activity_rows(&mut rows);
                        rows.truncate(usize::from(limit));
                        if rows.len() == usize::from(limit)
                            && rows.last().is_some_and(|kth| nanos < kth.0)
                        {
                            break 'pages;
                        }
                    }
                }
            } else if full_scan {
                self.scan_protocol_events(0, |event| {
                    push_activity_row(&mut rows, protocol_row(event), limit, filter, bounds);
                    Ok(())
                })
                .await?;
            } else {
                for event in self.protocol_activity_events(limit).await? {
                    push_activity_row(&mut rows, protocol_row(event), limit, filter, bounds);
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
        for event in self.events_of_kind("principal.registered").await? {
            let id: PrincipalId = serde_json::from_value(event.body["principal"]["id"].clone())?;
            ids.insert(id);
        }
        let mut principals = Vec::new();
        for principal in ids {
            principals.push(self.client.query(Query::GetPrincipal { principal }).await?);
        }
        Ok(principals)
    }

    pub async fn authority_grants(&self) -> Result<Vec<Value>> {
        let mut ids = BTreeSet::<GrantId>::new();
        for event in self.events_of_kind("grant.issued").await? {
            let id: GrantId = serde_json::from_value(event.body["grant"].clone())?;
            ids.insert(id);
        }
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
        // Failed and lost executions only (state-filtered queries, never the whole list).
        for state in [ExecutionState::Failed, ExecutionState::Lost] {
            let executions = self.list_executions(None, Some(state)).await?;
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
                    if state == "FAILED"
                        && let Some(provider) = execution["provider"].as_str()
                    {
                        sources.push((
                            format!("provider:{provider}:failed"),
                            "provider_failure".into(),
                            provider.into(),
                            format!("Provider {provider} has failed runs"),
                            "warning".into(),
                        ));
                    }
                }
            }
        }
        self.refresh_pack_index().await?;
        self.refresh_pack_results().await?;
        // Visible packs, as `pack list` shows them (a pending replacement is not one).
        const VISIBLE: &str = "NOT EXISTS (SELECT 1 FROM pack_commitments c
             WHERE c.pack_id=s.id AND c.state='replacement_pending')";
        {
            let mut q = self.db.prepare(&format!(
                "SELECT s.id FROM pack_summaries s WHERE s.state='QUARANTINED' AND {VISIBLE}"
            ))?;
            for id in q.query_map([], |r| r.get::<_, String>(0))? {
                let id = id?;
                sources.push((
                    format!("pack:{id}:quarantined"),
                    "quarantined_pack".into(),
                    id,
                    "Pack is quarantined".into(),
                    "warning".into(),
                ));
            }
            // A review is stale when its pack moved to another generation or candidate.
            let mut q = self.db.prepare(&format!(
                "SELECT r.id, r.pack_id FROM reviews r JOIN pack_summaries s ON s.id=r.pack_id
                 WHERE (r.generation != s.generation OR s.candidate_digest IS NULL
                        OR s.candidate_digest != r.candidate_digest) AND {VISIBLE}"
            ))?;
            for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
                let (review_id, pack) = row?;
                sources.push((
                    format!("review:{review_id}:stale"),
                    "stale_review".into(),
                    pack,
                    "Review is stale after candidate change".into(),
                    "warning".into(),
                ));
            }
            // Failing results of each live pack's current generation (projected).
            let mut q = self.db.prepare(&format!(
                "SELECT x.key, x.kind, x.pack, x.summary, x.severity FROM pack_results x
                 JOIN pack_summaries s ON s.id=x.pack AND s.generation=x.generation
                 WHERE x.bad=1 AND s.state NOT IN ('PROMOTED','ABANDONED') AND {VISIBLE}"
            ))?;
            for row in q.query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })? {
                sources.push(row?);
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
        // Extension and provider failures.
        for x in self
            .extension_health()
            .await?
            .as_array()
            .into_iter()
            .flatten()
        {
            if x["healthy"] != true && x["active"] == true {
                let id = x["id"].as_str().unwrap_or_default();
                sources.push((
                    format!("extension:{id}:unhealthy"),
                    "extension_failure".into(),
                    id.into(),
                    format!(
                        "Extension {id}: {}",
                        x["problem"].as_str().unwrap_or("unavailable")
                    ),
                    "danger".into(),
                ));
            }
        }
        // A package waiting for a capability it asks for and does not hold.
        for e in self
            .list_extensions()
            .await?
            .as_array()
            .into_iter()
            .flatten()
        {
            let Some(id) = e["id"].as_str() else { continue };
            let held = self.extension_permissions(id).await.unwrap_or(Value::Null);
            let granted = held["granted_host_capabilities"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let missing: Vec<String> = held["requested_host_capabilities"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|c| !granted.contains(c))
                .filter_map(|c| c.as_str().map(str::to_owned))
                .collect();
            if !missing.is_empty() {
                sources.push((
                    format!("extension:{id}:permission"),
                    "extension_permission".into(),
                    id.into(),
                    format!("Extension {id} asks for {}", missing.join(", ")),
                    "warning".into(),
                ));
            }
        }
        // Interrupted or conflicted operations that need recovery.
        for c in crate::capture::list(&self.root)? {
            let st = format!("{:?}", c.state);
            if !crate::capture::TERMINAL.contains(&st.as_str()) {
                let session = c.session.as_str();
                sources.push((
                    format!("capture:{session}"),
                    "recovery_required".into(),
                    c.pack.clone(),
                    format!("Capture session {session} is {st}; run `calve capture resume {session}` or roll it back"),
                    "danger".into(),
                ));
            }
        }
        for sg in crate::supersede::list(&self.root)? {
            let st = format!("{:?}", sg.state);
            if st != crate::supersede::DONE {
                let saga = sg.saga.as_str();
                sources.push((
                    format!("supersede:{saga}"),
                    "recovery_required".into(),
                    sg.pack.clone(),
                    format!("Supersession {saga} is {st}; run `calve supersede resume {saga}` (the original pack is kept)"),
                    "danger".into(),
                ));
            }
        }
        for m in self.unfinished_materializations()? {
            let op = m.op.as_str();
            let conflicted = m.state == calve_api::responses::MaterializeState::Conflicted;
            sources.push((
                format!("materialize:{op}"),
                if conflicted { "materialization_divergence" } else { "recovery_required" }.into(),
                op.into(),
                if conflicted {
                    format!("Materialization {op} found concurrent changes; run `calve materialize resolve {op} --keep ours|theirs`")
                } else {
                    format!("Materialization {op} was interrupted; run `calve materialize resume {op}`")
                },
                "danger".into(),
            ));
        }
        // Project identity conflicts (a duplicate live copy, a mismatched registration).
        if let Ok(registry) = crate::registry::Registry::open_default()
            && let Ok(h) = crate::app::project_health(&registry, &self.root.to_string_lossy())
            && matches!(
                h["status"].as_str(),
                Some("identity_conflict" | "duplicate_copy")
            )
        {
            sources.push((
                format!("identity:{}", self.identity.project_id),
                "identity_conflict".into(),
                self.identity.project_id.clone(),
                h["findings"][0]["message"]
                    .as_str()
                    .unwrap_or("Project identity conflict")
                    .into(),
                "danger".into(),
            ));
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

    /// Exact counts of open, sealed and qualified packs and, per state, the `limit` most recently
    /// updated ones (pending supersessions shown on the pack they replace).
    fn live_pack_summary(&self, limit: u64) -> Result<LiveSummary> {
        const VISIBLE: &str = "NOT EXISTS (SELECT 1 FROM pack_commitments c
             WHERE c.pack_id=s.id AND c.state='replacement_pending')";
        let mut counts = BTreeMap::new();
        let mut items: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        let superseding = crate::supersede::pending(&self.root)?;
        for state in ["OPEN", "SEALED", "QUALIFIED"] {
            let n: u64 = self.db.query_row(
                &format!("SELECT COUNT(*) FROM pack_summaries s WHERE s.state=?1 AND {VISIBLE}"),
                [state],
                |r| r.get(0),
            )?;
            counts.insert(state.to_lowercase(), n);
            let mut q = self.db.prepare(&format!(
                "SELECT s.id, m.title, s.generation FROM pack_summaries s
                 JOIN pack_metadata m ON m.id=s.id
                 WHERE s.state=?1 AND {VISIBLE} ORDER BY s.updated_at DESC, s.id DESC LIMIT ?2"
            ))?;
            let rows = q.query_map(params![state, limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            })?;
            for row in rows {
                let (id, title, generation) = row?;
                let mut item = json!({"id": id, "title": title, "generation": generation});
                if let Some((saga, step)) = superseding.get(&id) {
                    item["superseding"] = json!({"saga": saga, "pending_step": step,
                        "display": format!("superseding (pending: {step})")});
                }
                items.entry(state.to_lowercase()).or_default().push(item);
            }
        }
        Ok((counts, items))
    }

    /// Derived summary (PLAN §17.5); every field comes from OpenAEVC queries or Calve metadata,
    /// never a second authority. `config` supplies the provider profiles to health-check.
    pub async fn status(&self, config: Option<&crate::config::EffectiveConfig>) -> Result<Value> {
        let tasks = self.tasks_with_protocol().await?;
        let mut project = serde_json::to_value(&self.identity)?;
        project["name"] = json!(self.display_name);
        // Active executions only: one state-filtered query per active state.
        let mut active: Vec<Value> = Vec::new();
        for state in [
            ExecutionState::Pending,
            ExecutionState::Admitted,
            ExecutionState::Starting,
            ExecutionState::Running,
        ] {
            let found = self.list_executions(None, Some(state)).await?;
            active.extend(found.as_array().into_iter().flatten().cloned());
        }
        let uncaptured = match self.scan_resources().await {
            Ok(scan) => json!(scan["uncaptured"].as_array().map_or(0, Vec::len)),
            Err(error) => json!({"error":error.to_string()}),
        };
        let inbox = self.inbox(false).await?;
        let attention = inbox
            .iter()
            .filter(|i| i["needs_attention"] == true)
            .count();
        let pick = |kinds: &[&str]| -> Vec<Value> {
            inbox
                .iter()
                .filter(|i| kinds.contains(&i["kind"].as_str().unwrap_or_default()))
                .map(|i| json!({"kind": i["kind"], "pack": i["subject"], "summary": i["summary"], "source_key": i["source_key"]}))
                .collect()
        };
        let unhealthy: Vec<Value> = self
            .extension_health()
            .await?
            .as_array()
            .into_iter()
            .flatten()
            .filter(|item| item["healthy"] != true)
            .cloned()
            .collect();
        let providers: Vec<Value> = config
            .map(|c| {
                c.providers
                    .iter()
                    .filter(|(_, p)| p.enabled)
                    .filter_map(|(id, _)| crate::providers::test_provider(c, id).ok())
                    .filter(|h| h["healthy"] != true)
                    .collect()
            })
            .unwrap_or_default();
        // Exact counts and the most recent items per live state, by indexed queries (the inbox
        // refresh above brought the pack index up to date).
        let (counts, by_state) = self.live_pack_summary(STATUS_ITEMS)?;
        let count = |k: &str| counts.get(k).copied().unwrap_or(0);
        let attention_tasks: Vec<&Value> = tasks
            .iter()
            .filter(|t| {
                t["state"] == "BLOCKED"
                    || t["inconsistencies"]
                        .as_array()
                        .is_some_and(|i| !i.is_empty())
            })
            .collect();
        let active_baseline = match self.active_baseline()? {
            Some(id) => {
                let aliases: Vec<Value> = self
                    .list_baseline_aliases()?
                    .into_iter()
                    .filter(|a| a["baseline_id"] == id.as_str())
                    .map(|a| a["alias"].clone())
                    .collect();
                json!({"id": id, "aliases": aliases})
            }
            None => Value::Null,
        };
        let recovery = pick(&[
            "recovery_required",
            "materialization_divergence",
            "identity_conflict",
        ]);
        let status = json!({"project": project, "active_baseline": active_baseline,
            "packs": {"open": count("open"), "sealed": count("sealed"), "qualified": count("qualified"), "items": by_state, "items_limit": STATUS_ITEMS},
            "tasks": {"total": tasks.len(), "blocked": tasks.iter().filter(|t| t["state"] == "BLOCKED").count(), "attention": attention_tasks},
            "active_executions": active, "uncaptured_changes": uncaptured,
            "blockers": {"verification": pick(&["verification_failed", "evaluation_warning", "promotion_blocked"]),
                "review": pick(&["stale_review"])},
            "recovery": recovery, "attention_items": attention,
            "extension_problems": unhealthy, "provider_problems": providers});
        // Through the contract type: what `status` prints is exactly what it declares.
        let typed: calve_api::responses::Status = serde_json::from_value(status)?;
        Ok(serde_json::to_value(typed)?)
    }
}

/// OpenAEVC reads in flight while a projection catches up; order and atomicity are unchanged.
pub(crate) const READ_BATCH: usize = 16;

/// Narrows [`Project::packs_page`]; every field is optional and they combine.
#[derive(Default)]
pub(crate) struct PackFilter<'a> {
    pub state: Option<&'a str>,
    pub ids: Option<&'a [String]>,
    pub promoted: Option<&'a [String]>,
}
