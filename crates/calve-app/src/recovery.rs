//! `recover inspect | plan | apply` (PLAN §43, rev 10 §10–§11).
//!
//! **inspect is read-only**: the product database is opened read-only, OpenAEVC is read through
//! its store API without starting a runtime (no runtime instance is recorded), nothing is
//! migrated, no lock is taken. It reports the product database (schema, pending migration,
//! integrity, binding), the OpenAEVC store (integrity, journal head, continuity against the
//! binding, interrupted executions from the event journal), the writer lock owner, projection
//! lag, registered extensions vs installed packages, disposable leftovers and the backups.
//! **plan** lists every action with its owner (`CALVE_PRODUCT`, `OPENAEVC_RUNTIME`,
//! `FILESYSTEM_CACHE`, `EXTENSION_CACHE`). **apply** performs them; `--restore-backup` replaces
//! the product database with a backup and then reconciles it against OpenAEVC (§11): binding and
//! continuity, then rebuilt indexes.
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

use crate::{Project, ProjectIdentity, Result};

fn read_only(path: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

/// Execution states from the public event journal (terminal or not).
fn executions(events: &[openaevc::protocol::Event]) -> BTreeMap<String, String> {
    let mut state = BTreeMap::new();
    for e in events {
        if let Some(kind) = e.kind.strip_prefix("execution.")
            && let Some(id) = e.body["execution"].as_str()
        {
            let s = match kind {
                "admitted" | "starting" => "STARTING",
                "running" | "heartbeat" => "RUNNING",
                "succeeded" => "SUCCEEDED",
                "failed" => "FAILED",
                "cancelled" => "CANCELLED",
                "lost" => "LOST",
                _ => continue,
            };
            state.insert(id.to_owned(), s.to_owned());
        }
    }
    state
}

fn product(root: &Path, identity: Option<&ProjectIdentity>) -> (Value, Option<Connection>) {
    let path = root.join(".calve/product.sqlite3");
    if !path.is_file() {
        return (json!({"state": "missing"}), None);
    }
    let db = match read_only(&path) {
        Ok(db) => db,
        Err(e) => return (json!({"state": "unreadable", "error": e.to_string()}), None),
    };
    let version: u32 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap_or(0);
    let integrity: String = db
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .unwrap_or_else(|e| e.to_string());
    let binding = crate::continuity::binding(&db).ok().flatten();
    let report = json!({
        "state": if integrity == "ok" { "ok" } else { "corrupt" },
        "schema": version,
        "supported_schema": crate::PRODUCT_SCHEMA,
        "pending_migration": version < crate::PRODUCT_SCHEMA,
        "newer_than_supported": version > crate::PRODUCT_SCHEMA,
        "integrity": integrity,
        "binding": binding.as_ref().map(|b| json!({"project_id": b.project_id, "namespace_id": b.namespace_id,
            "genesis_hash": b.genesis_hash, "checkpoint_seq": b.checkpoint_seq,
            "matches_project": identity.is_none_or(|i| i.project_id == b.project_id)})),
    });
    (report, Some(db))
}

/// The read-only report.
pub fn inspect(root: &Path) -> Result<Value> {
    let state = root.join(".calve");
    let identity: Option<ProjectIdentity> = fs::read_to_string(state.join("project.toml"))
        .ok()
        .and_then(|t| toml::from_str(&t).ok());
    let (product, db) = product(root, identity.as_ref());
    let mut openaevc = json!({"state": "unknown"});
    let mut interrupted = vec![];
    let mut registered = vec![];
    let mut head = 0u64;
    match openaevc::store::SqliteStore::open(
        &state.join("openaevc"),
        openaevc::store::SqliteOptions::default(),
    ) {
        Err(e) if e.code == openaevc::protocol::ErrorCode::Conflict => {
            openaevc = json!({"state": "in_use", "note": "the daemon or another process holds the runtime; stop it for a full inspection"});
        }
        Err(e) => openaevc = json!({"state": "unavailable", "error": e.message}),
        Ok(store) => {
            use openaevc::store::Store;
            let integrity = store.verify_integrity()?;
            let events = match &identity {
                Some(i) => store.read_events(&i.namespace_id, 0, usize::MAX)?,
                None => vec![],
            };
            head = events.last().map_or(0, |e| e.sequence);
            for (id, s) in executions(&events) {
                if matches!(s.as_str(), "STARTING" | "RUNNING" | "LOST") {
                    interrupted.push(json!({"execution": id, "state": s}));
                }
            }
            let mut ext: BTreeMap<String, Value> = BTreeMap::new();
            for e in events.iter() {
                match e.kind.as_str() {
                    "extension.registered" => {
                        ext.insert(
                            e.body["extension"].as_str().unwrap_or("").to_owned(),
                            e.body.clone(),
                        );
                    }
                    "extension.unregistered" => {
                        ext.remove(e.body["extension"].as_str().unwrap_or(""));
                    }
                    _ => {}
                }
            }
            for (id, body) in ext {
                let artifact = body["artifact"]
                    .as_str()
                    .unwrap_or("")
                    .trim_start_matches("sha256:")
                    .to_owned();
                let installed = crate::extensions::package_by_digest(&artifact)
                    .ok()
                    .flatten();
                let problem = match (&installed, crate::extensions::machine_paths()) {
                    (Some(r), Ok(paths)) => crate::catalog::install::verify_installed(&paths, r)
                        .err()
                        .map(|e| e.message),
                    (Some(_), Err(e)) => Some(e.to_string()),
                    (None, _) => Some("no installed package has this artifact digest".into()),
                };
                registered.push(json!({"id": id, "artifact": body["artifact"],
                    "installed": installed.is_some(), "problem": problem}));
            }
            let continuity = match (&identity, &db) {
                (Some(i), Some(db)) if product["pending_migration"] == false => {
                    let runtime_key = crate::project_runtime_key(&state)?;
                    match crate::continuity::verify(
                        db,
                        i,
                        &crate::continuity::StoreEvents {
                            store: &store,
                            namespace: i.namespace_id,
                        },
                        &runtime_key,
                        false,
                    ) {
                        Ok(r) => json!({"state": "ok", "report": r}),
                        Err(crate::Error::Detailed {
                            message, detail, ..
                        }) => {
                            json!({"state": "recovery_required", "message": message, "detail": detail})
                        }
                        Err(e) => json!({"state": "error", "error": e.to_string()}),
                    }
                }
                _ => json!({"state": "not_checked"}),
            };
            openaevc = json!({"state": if integrity.ok() { "ok" } else { "corrupt" },
                "integrity_problems": integrity.problems, "events": integrity.events,
                "objects": integrity.objects, "journal_head": head, "continuity": continuity});
        }
    }
    let projection_lag = db.as_ref().and_then(|db| {
        db.query_row(
            "SELECT sequence FROM projection_checkpoints WHERE name='packs'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .ok()
        .map(|seq| json!({"packs": head.saturating_sub(seq as u64)}))
    });
    Ok(json!({
        "root": root,
        "read_only": true,
        "identity": identity.as_ref().map(|i| json!({"project_id": i.project_id, "namespace_id": i.namespace_id})),
        "product_db": product,
        "openaevc": openaevc,
        "interrupted_executions": interrupted,
        "writer_lock": crate::app::writer_lock_state(root),
        "projection_lag": projection_lag,
        "extensions": registered,
        "leftovers": plan(root)?,
        "backups": crate::backup::list(&state.join("product.sqlite3"))?,
    }))
}

/// Deterministic actions with owners.
pub fn plan(root: &Path) -> Result<Vec<Value>> {
    let mut actions = crate::ops::recovery_plan(root)?;
    for a in &mut actions {
        let owner = match a["action"].as_str() {
            Some("reconcile_install_journals") => "EXTENSION_CACHE",
            Some("restore_adoption_source") => "CALVE_PRODUCT",
            _ => "FILESYSTEM_CACHE",
        };
        a["owner"] = json!(owner);
    }
    Ok(actions)
}

/// Replaces a lost product database with an empty one, then rebuilds what derives from OpenAEVC.
/// Only for a database that is really gone: a present one is never replaced by this.
pub async fn rebuild_product(root: &Path) -> Result<Value> {
    let db_path = root.join(".calve/product.sqlite3");
    if db_path.exists() {
        return Err(crate::coded(
            "INVALID_ARGUMENT",
            "the product database exists; use --restore-backup to replace it",
        ));
    }
    let db = crate::init_db(&db_path, crate::DbOpen::Create)?;
    db.execute(
        "INSERT INTO preferences(key,value) VALUES ('project.display_name',?1)",
        [root.file_name().unwrap_or_default().to_string_lossy()],
    )?;
    drop(db);
    let project = Project::open(root)?;
    let rebuilt = project.rebuild_projections().await?;
    crate::observe::record("recovery", json!({"root": root, "rebuilt_product": true}));
    Ok(json!({"rebuilt": rebuilt, "owner": "CALVE_PRODUCT",
        "lost": ["intents", "tasks", "review records", "inbox state", "aliases"]}))
}

/// Restores the product database from a backup, then reconciles it against OpenAEVC: the gate,
/// identity and continuity (an unrelated backup is refused), then indexes rebuilt from OpenAEVC.
pub async fn restore_and_reconcile(root: &Path, backup: &str) -> Result<Value> {
    let db_path = root.join(".calve/product.sqlite3");
    let restored = crate::backup::restore(&db_path, backup)?;
    crate::journal::fault("restore.before_reconcile");
    let project = Project::open(root)?;
    let rebuilt = project.rebuild_projections().await?;
    crate::observe::record("recovery", json!({"root": root, "restored": backup}));
    Ok(json!({"restored": restored, "reconciled": rebuilt, "owner": "CALVE_PRODUCT"}))
}
