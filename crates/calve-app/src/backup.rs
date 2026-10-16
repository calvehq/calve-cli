//! Internal backups of the product database (rev 10 §10, ADR 0009): no export/import, only
//! copies Calve can restore and then reconcile against OpenAEVC (§11).
//!
//! `.calve/backups/product-<UTC>-v<schema>-<kind>.db`, written with SQLite's `VACUUM INTO` (a
//! consistent online copy), verified with `PRAGMA integrity_check` before it is kept, with its
//! SHA-256 in `<file>.sha256` (integrity_check does not see damaged row bytes or free pages; the
//! digest does, and restore requires it). Kinds:
//! `daily` (the first write-open of a day; 7 kept), `pre-migration` and `pre-restore` (kept 30
//! days). Backups hold the same product data as the database (never secret values: those are
//! never stored).
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

use crate::{Error, Result};

const DAILY_KEEP: usize = 7;
const DATED_KEEP: Duration = Duration::from_secs(30 * 86_400);

fn coded(code: &'static str, message: impl Into<String>) -> Error {
    crate::coded(code, message)
}

/// `.calve/backups` beside the product database.
pub fn dir(db_path: &Path) -> PathBuf {
    db_path.with_file_name("backups")
}

fn stamp() -> String {
    jiff::Timestamp::now()
        .strftime("%Y%m%dT%H%M%SZ")
        .to_string()
}

/// Integrity of a database file, opened read-only.
pub fn integrity(path: &Path) -> Result<String> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?)
}

fn sidecar(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".sha256");
    PathBuf::from(s)
}

/// Whether `path` still has the SHA-256 recorded when it was taken.
fn digest_ok(path: &Path) -> Result<bool> {
    let recorded = match fs::read_to_string(sidecar(path)) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    Ok(recorded.trim() == crate::journal::sha256_hex(&fs::read(path)?))
}

/// Writes a verified backup of `db` and applies retention.
pub fn take(db: &Connection, db_path: &Path, kind: &str, schema: u32) -> Result<PathBuf> {
    let dir = dir(db_path);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let name = format!("product-{}-v{schema}-{kind}.db", stamp());
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    db.execute("VACUUM INTO ?1", [tmp.to_string_lossy()])?;
    let check = integrity(&tmp)?;
    if check != "ok" {
        let _ = fs::remove_file(&tmp);
        return Err(coded(
            "CORRUPT_PRODUCT_STATE",
            format!("the {kind} backup failed its integrity check: {check}"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::File::open(&tmp)?.sync_all()?;
    let path = dir.join(&name);
    // The digest first: a backup file never exists without one.
    let side = sidecar(&path);
    fs::write(&side, crate::journal::sha256_hex(&fs::read(&tmp)?))?;
    fs::File::open(&side)?.sync_all()?;
    fs::rename(&tmp, &path)?;
    if let Ok(d) = fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    retain(&dir)?;
    crate::observe::record(
        "backup",
        json!({"kind": kind, "schema": schema, "file": name}),
    );
    Ok(path)
}

/// `(file name, kind, schema, modified)` of every backup, newest first.
fn entries(dir: &Path) -> Result<Vec<(String, String, u32, SystemTime)>> {
    let mut out = vec![];
    let Ok(rd) = fs::read_dir(dir) else {
        return Ok(out);
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(stem) = name
            .strip_prefix("product-")
            .and_then(|s| s.strip_suffix(".db"))
        else {
            continue;
        };
        let mut parts = stem.splitn(3, '-');
        let (Some(_), Some(v), Some(kind)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let schema = v.trim_start_matches('v').parse().unwrap_or(0);
        let (kind, modified) = (kind.to_owned(), e.metadata()?.modified()?);
        out.push((name.clone(), kind, schema, modified));
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(out)
}

/// 7 newest daily backups; other kinds for 30 days. ponytail: age from the file mtime, a clock
/// step makes retention keep or drop a little early; never touches the newest backup.
fn retain(dir: &Path) -> Result<()> {
    let all = entries(dir)?;
    let mut daily = 0;
    for (i, (name, kind, _, modified)) in all.iter().enumerate() {
        let drop = if kind == "daily" {
            daily += 1;
            daily > DAILY_KEEP
        } else {
            modified.elapsed().is_ok_and(|age| age > DATED_KEEP)
        };
        if drop && i > 0 {
            fs::remove_file(dir.join(name))?;
            let _ = fs::remove_file(sidecar(&dir.join(name)));
        }
    }
    Ok(())
}

/// A daily backup unless one was taken in the last 24 hours.
pub fn daily_if_due(db: &Connection, db_path: &Path, schema: u32) -> Result<()> {
    let due = !entries(&dir(db_path))?.iter().any(|(_, kind, _, m)| {
        kind == "daily"
            && m.elapsed()
                .is_ok_and(|age| age < Duration::from_secs(86_400))
    });
    if due {
        take(db, db_path, "daily", schema)?;
    }
    Ok(())
}

/// The backups `recover inspect` lists (read-only: integrity checked on read-only handles).
pub fn list(db_path: &Path) -> Result<Vec<Value>> {
    let dir = dir(db_path);
    entries(&dir)?
        .into_iter()
        .map(|(name, kind, schema, modified)| {
            let path = dir.join(&name);
            Ok(json!({"file": name, "kind": kind, "schema": schema,
                "bytes": fs::metadata(&path)?.len(),
                "created": jiff::Timestamp::try_from(modified).map(|t| t.to_string()).unwrap_or_default(),
                "integrity": integrity(&path).unwrap_or_else(|e| e.to_string()),
                "digest_ok": digest_ok(&path)?}))
        })
        .collect()
}

/// Replaces the product database with `backup` (a file name inside `.calve/backups`). The
/// current database is first kept as a `pre-restore` backup when it is readable. The caller
/// holds the writer lock with the Project closed, and reconciles against OpenAEVC afterwards.
pub fn restore(db_path: &Path, backup: &str) -> Result<Value> {
    if backup.contains(['/', '\\']) || !backup.starts_with("product-") {
        return Err(coded(
            "INVALID_ARGUMENT",
            "name a backup file listed by `calve recover inspect`",
        ));
    }
    let source = dir(db_path).join(backup);
    if !source.is_file() {
        return Err(coded("NOT_FOUND", format!("backup {backup} not found")));
    }
    if !digest_ok(&source)? {
        return Err(coded(
            "CORRUPT_PRODUCT_STATE",
            format!("backup {backup} does not match its recorded SHA-256"),
        ));
    }
    let check = integrity(&source)?;
    if check != "ok" {
        return Err(coded(
            "CORRUPT_PRODUCT_STATE",
            format!("backup {backup} failed its integrity check: {check}"),
        ));
    }
    let mut kept = None;
    if db_path.is_file()
        && let Ok(current) = Connection::open(db_path)
        && current
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .is_ok_and(|c| c == "ok")
    {
        let schema: u32 = current.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        kept = Some(take(&current, db_path, "pre-restore", schema)?);
    }
    let tmp = db_path.with_extension("sqlite3.restore");
    fs::copy(&source, &tmp)?;
    fs::File::open(&tmp)?.sync_all()?;
    crate::journal::fault("restore.before_swap");
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", db_path.display()));
    }
    fs::rename(&tmp, db_path)?;
    if let Some(d) = db_path.parent().and_then(|p| fs::File::open(p).ok()) {
        let _ = d.sync_all();
    }
    crate::observe::record("restore", json!({"backup": backup}));
    Ok(json!({"restored": backup,
        "previous_kept_as": kept.and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))}))
}
