//! Maintenance GC (PLAN §44): one plan, shown by `--dry-run` and executed otherwise. Each
//! class names its owner, count, estimated bytes and why its items are collectable.
//!
//! - `OPENAEVC_RUNTIME`: objects indexed in no Namespace and orphan CAS files older than the
//!   grace period, by OpenAEVC's own collector (indexed history is never removed).
//! - `CALVE_PRODUCT`: resolved Inbox rows past retention (attention state only, never audit).
//! - `FILESYSTEM_CACHE`: temporary files past the grace period; logs, finished capture
//!   sessions, finished supersede sagas and finished materialization runs (their backups, which
//!   rollback needs) past retention.
//! - Conflict artifacts only with `--conflicts`, only for resolved operations, and only past
//!   `--older-than`; never otherwise.
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

use crate::Result;

/// Retention of finished operational state and resolved attention rows.
pub const RETENTION: Duration = Duration::from_secs(30 * 86_400);
pub const LOG_RETENTION: Duration = Duration::from_secs(14 * 86_400);

#[derive(Default)]
pub struct Options {
    pub grace: Duration,
    /// `Some(age)`: also conflict artifacts of resolved operations older than `age`.
    pub conflicts: Option<Duration>,
}

struct Class {
    class: &'static str,
    owner: &'static str,
    reason: String,
    /// Paths to remove (files or directories) with their sizes.
    paths: Vec<(PathBuf, u64)>,
    /// Count and bytes for classes removed by their owner (no paths).
    counted: Option<(u64, u64)>,
}

fn age(path: &Path) -> Duration {
    fs::symlink_metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok())
        .unwrap_or_default()
}

fn size(path: &Path) -> u64 {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| size(&e.path()))
            .sum(),
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect()
}

fn class(class: &'static str, owner: &'static str, reason: String, paths: Vec<PathBuf>) -> Class {
    Class {
        class,
        owner,
        reason,
        paths: paths
            .into_iter()
            .map(|p| {
                let s = size(&p);
                (p, s)
            })
            .collect(),
        counted: None,
    }
}

/// OpenAEVC's collectable set, computed read-only with its own criteria.
fn protocol(root: &Path, grace: Duration) -> Result<Class> {
    let store = root.join(".calve/openaevc");
    let db = Connection::open_with_flags(
        store.join("runtime.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (mut count, mut bytes): (u64, u64) = db.query_row(
        "SELECT count(*), coalesce(sum(size),0) FROM objects o
         WHERE NOT EXISTS (SELECT 1 FROM object_index i WHERE i.digest = o.digest)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    for shard in entries(&store.join("objects/sha256")) {
        for f in entries(&shard) {
            let name = f
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let known: i64 = db.query_row(
                "SELECT count(*) FROM objects WHERE digest=?1",
                [format!("sha256:{name}")],
                |r| r.get(0),
            )?;
            if known == 0 && age(&f) >= grace {
                count += 1;
                bytes += size(&f);
            }
        }
    }
    Ok(Class {
        class: "openaevc_unreachable_objects",
        owner: "OPENAEVC_RUNTIME",
        reason: format!(
            "indexed in no Namespace, or orphan CAS files older than {}s; indexed history is never removed",
            grace.as_secs()
        ),
        paths: vec![],
        counted: Some((count, bytes)),
    })
}

/// Last `state` recorded in a journal, if it can be read.
fn journal_state(path: &Path, kind: &str) -> Option<String> {
    let opened = crate::journal::Journal::open(path).ok()?;
    opened
        .records
        .iter()
        .rev()
        .find(|r| r.kind == kind)
        .and_then(|r| r.body["state"].as_str().map(str::to_owned))
}

fn plan(root: &Path, o: &Options) -> Result<Vec<Class>> {
    let calve = root.join(".calve");
    let mut out = vec![protocol(root, o.grace)?];
    let old = |p: &Path, d: Duration| age(p) >= d;
    out.push(class(
        "temporary_files",
        "FILESYSTEM_CACHE",
        format!("in .calve/tmp, older than {}s", o.grace.as_secs()),
        entries(&calve.join("tmp"))
            .into_iter()
            .filter(|p| old(p, o.grace))
            .collect(),
    ));
    out.push(class(
        "logs",
        "FILESYSTEM_CACHE",
        format!("older than {} days", LOG_RETENTION.as_secs() / 86_400),
        entries(&calve.join("logs"))
            .into_iter()
            .filter(|p| old(p, LOG_RETENTION))
            .collect(),
    ));
    // Finished capture sessions: journal, spool and chunk bytes.
    let capture = calve.join("run/capture");
    let mut sessions = vec![];
    for (id, _, log) in crate::capture::sessions_raw(root)? {
        let journal = capture.join(format!("{id}.journal"));
        if crate::capture::TERMINAL.contains(&log.as_str()) && old(&journal, RETENTION) {
            for suffix in [".journal", ".spool.json", ".chunks"] {
                let p = capture.join(format!("{id}{suffix}"));
                if p.exists() {
                    sessions.push(p);
                }
            }
        }
    }
    out.push(class(
        "finished_capture_sessions",
        "FILESYSTEM_CACHE",
        "Done, superseded, compensated or abandoned, past retention".into(),
        sessions,
    ));
    let supersede = calve.join("run/supersede");
    out.push(class(
        "finished_supersede_sagas",
        "FILESYSTEM_CACHE",
        "Done, past retention".into(),
        entries(&supersede)
            .into_iter()
            .filter(|p| p.extension().is_some_and(|x| x == "journal"))
            .filter(|p| crate::supersede::finished(p) && old(p, RETENTION))
            .collect(),
    ));
    let runs = crate::wal::runs(root);
    let mut finished_runs = vec![];
    let mut conflicts = vec![];
    for run in entries(&runs) {
        let state = journal_state(&run.join("journal"), "m.state");
        let finished = matches!(state.as_deref(), Some("Completed" | "RolledBack"));
        if finished && old(&run.join("journal"), RETENTION) {
            finished_runs.push(run.clone());
        }
        if let (true, Some(min)) = (finished, o.conflicts) {
            let c = calve
                .join("conflicts")
                .join(run.file_name().unwrap_or_default());
            if c.exists() && old(&c, min) {
                conflicts.push(c);
            }
        }
    }
    out.push(class(
        "finished_materializations",
        "FILESYSTEM_CACHE",
        "Completed or rolled back, past retention (their backups: rollback is no longer possible)"
            .into(),
        finished_runs,
    ));
    if let Some(min) = o.conflicts {
        out.push(class(
            "resolved_conflict_artifacts",
            "FILESYSTEM_CACHE",
            format!(
                "--conflicts: of resolved operations, older than {}s",
                min.as_secs()
            ),
            conflicts,
        ));
    }
    // Resolved Inbox rows past retention (counted read-only).
    let db = calve.join("product.sqlite3");
    let cutoff = crate::now()?.saturating_sub(RETENTION.as_secs());
    let resolved: u64 = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY)?
        .query_row(
            "SELECT count(*) FROM inbox_items WHERE resolved_at IS NOT NULL AND resolved_at < ?1",
            [cutoff],
            |r| r.get(0),
        )?;
    out.push(Class {
        class: "resolved_inbox_rows",
        owner: "CALVE_PRODUCT",
        reason: format!(
            "resolved more than {} days ago (attention state only; audit history stays)",
            RETENTION.as_secs() / 86_400
        ),
        paths: vec![],
        counted: Some((resolved, 0)),
    });
    Ok(out)
}

fn report(classes: &[Class], root: &Path) -> Vec<Value> {
    classes
        .iter()
        .map(|c| {
            let (count, bytes) = c
                .counted
                .unwrap_or((c.paths.len() as u64, c.paths.iter().map(|p| p.1).sum()));
            json!({"class": c.class, "owner": c.owner, "count": count, "estimated_bytes": bytes,
                "reason": c.reason,
                "items": c.paths.iter().take(20).map(|(p, _)| p.strip_prefix(root).unwrap_or(p).to_path_buf()).collect::<Vec<_>>()})
        })
        .collect()
}

/// `--dry-run`: the plan, nothing removed and nothing opened for writing.
pub fn dry_run(root: &Path, o: &Options) -> Result<Value> {
    Ok(
        json!({"dry_run": true, "grace_secs": o.grace.as_secs(), "classes": report(&plan(root, o)?, root)}),
    )
}

/// Executes the plan; the caller holds the Project writer lock (taken for every mutating
/// command) with the runtime closed.
pub fn collect(
    root: &Path,
    o: &Options,
    store: &dyn Fn() -> Result<openaevc::store::GcReport>,
) -> Result<Value> {
    let classes = plan(root, o)?;
    let planned = report(&classes, root);
    let mut removed = vec![];
    for c in &classes {
        match c.class {
            "openaevc_unreachable_objects" => {
                let r = store()?;
                removed.push(json!({"class": c.class, "owner": c.owner, "removed": r.removed, "scanned": r.scanned}));
            }
            "resolved_inbox_rows" => {
                let db = Connection::open(root.join(".calve/product.sqlite3"))?;
                let cutoff = crate::now()?.saturating_sub(RETENTION.as_secs());
                let n = db.execute(
                    "DELETE FROM inbox_items WHERE resolved_at IS NOT NULL AND resolved_at < ?1",
                    [cutoff],
                )?;
                removed.push(json!({"class": c.class, "owner": c.owner, "removed": n}));
            }
            _ => {
                let mut n = 0;
                for (p, _) in &c.paths {
                    let r = if p.is_dir() {
                        fs::remove_dir_all(p)
                    } else {
                        fs::remove_file(p)
                    };
                    if r.is_ok() {
                        n += 1;
                    }
                }
                removed.push(json!({"class": c.class, "owner": c.owner, "removed": n}));
            }
        }
    }
    Ok(
        json!({"dry_run": false, "grace_secs": o.grace.as_secs(), "planned": planned, "removed": removed}),
    )
}
