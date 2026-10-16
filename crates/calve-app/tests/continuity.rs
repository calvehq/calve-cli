//! Cross-store identity, event continuity, backups and read-only recovery inspection (rev 10
//! §10, §11; PLAN §43, §46.4).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use calve_app::{Error, Project};

fn reason(e: Error) -> String {
    match e {
        Error::Detailed { code, detail, .. } => {
            assert_eq!(code, "RECOVERY_REQUIRED", "{detail}");
            detail["reason"].as_str().unwrap().to_owned()
        }
        other => panic!("expected RECOVERY_REQUIRED, got {other}"),
    }
}

fn code(e: Error) -> String {
    match e {
        Error::Detailed { code, .. } => code.to_owned(),
        Error::Message(m) => m.split(':').next().unwrap().to_owned(),
        other => panic!("{other}"),
    }
}

async fn project_with_packs(dir: &Path, titles: &[&str]) {
    let p = Project::init(dir, Some("p")).await.unwrap();
    for t in titles {
        p.create_pack(t, None).await.unwrap();
    }
}

/// Every file under `.calve` with its bytes (read-only operations must not change any).
fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            let name = p.to_string_lossy().into_owned();
            // SQLite's shared-memory index (`-shm`) and an empty `-wal` are a reader's
            // transients, never data.
            if name.ends_with("-shm")
                || (name.ends_with("-wal")
                    && fs::metadata(&p).map(|m| m.len() == 0).unwrap_or(true))
            {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else {
                out.insert(name, fs::read(&p).unwrap_or_default());
            }
        }
    }
    out
}

#[tokio::test]
async fn the_binding_is_recorded_and_another_projects_database_is_refused() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    project_with_packs(a.path(), &["one"]).await;
    project_with_packs(b.path(), &["two"]).await;
    // Reopen: continuity holds from the recorded checkpoint.
    Project::open(a.path()).unwrap();
    // B's product database inside A.
    fs::copy(
        b.path().join(".calve/product.sqlite3"),
        a.path().join(".calve/product.sqlite3"),
    )
    .unwrap();
    for s in ["-wal", "-shm"] {
        let _ = fs::remove_file(a.path().join(format!(".calve/product.sqlite3{s}")));
    }
    assert_eq!(
        reason(Project::open(a.path()).err().unwrap()),
        "identity_mismatch"
    );
    assert_eq!(
        reason(Project::open_reader(a.path()).err().unwrap()),
        "identity_mismatch"
    );
}

#[tokio::test]
async fn another_store_under_the_same_project_is_an_identity_mismatch() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    project_with_packs(a.path(), &["one"]).await;
    project_with_packs(b.path(), &["two"]).await;
    let store = a.path().join(".calve/openaevc");
    fs::remove_dir_all(&store).unwrap();
    calve_testkit::copy_tree(&b.path().join(".calve/openaevc"), &store);
    // B's store has B's namespace and genesis; A's binding names A's.
    let e = Project::open(a.path()).err().unwrap();
    let got = code_or_reason(e);
    assert_eq!(got, "identity_mismatch");
}

fn code_or_reason(e: Error) -> String {
    match e {
        Error::Detailed { detail, code, .. } => detail["reason"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| code.to_owned()),
        Error::Protocol(p) => p.code.as_str().to_owned(),
        other => other.to_string(),
    }
}

#[tokio::test]
async fn a_modified_event_breaks_continuity_and_a_truncated_journal_is_behind() {
    let d = tempfile::tempdir().unwrap();
    project_with_packs(d.path(), &["one"]).await;
    {
        // The writer open records the checkpoint at the head; later events extend it.
        let p = Project::open(d.path()).unwrap();
        p.create_pack("TAMPERME", None).await.unwrap();
    }
    let store = d.path().join(".calve/openaevc/runtime.sqlite3");
    {
        let db = rusqlite::Connection::open(&store).unwrap();
        let n = db
            .execute(
                "UPDATE event_journal SET body = CAST(replace(CAST(body AS TEXT), '\"changepack.created\"', '\"changepack.creatEd\"') AS BLOB) WHERE sequence = (SELECT MAX(sequence) FROM event_journal WHERE kind='changepack.created')",
                [],
            )
            .unwrap();
        assert!(n > 0, "test hook found the event");
    }
    // OpenAEVC's own integrity check or Calve's continuity check refuses it.
    let got = code_or_reason(Project::open(d.path()).err().unwrap());
    assert!(
        matches!(got.as_str(), "continuity" | "STORAGE_INTEGRITY_ERROR"),
        "{got}"
    );

    // A rewrite with every hash recomputed (the store's own check passes): only the recorded
    // checkpoint shows it.
    let d = tempfile::tempdir().unwrap();
    project_with_packs(d.path(), &["one", "two"]).await;
    Project::open(d.path()).unwrap();
    rewrite_journal_from(&d.path().join(".calve/openaevc/runtime.sqlite3"), 3);
    assert_eq!(reason(Project::open(d.path()).err().unwrap()), "continuity");

    // A journal that ends before the checkpoint.
    let d = tempfile::tempdir().unwrap();
    project_with_packs(d.path(), &["one", "two", "three"]).await;
    Project::open(d.path()).unwrap();
    {
        let db = rusqlite::Connection::open(d.path().join(".calve/product.sqlite3")).unwrap();
        db.execute(
            "UPDATE store_binding SET checkpoint_seq=checkpoint_seq+1000",
            [],
        )
        .unwrap();
    }
    assert_eq!(
        reason(Project::open(d.path()).err().unwrap()),
        "openaevc_behind"
    );
}

#[tokio::test]
async fn recover_inspect_writes_nothing() {
    let d = tempfile::tempdir().unwrap();
    project_with_packs(d.path(), &["one"]).await;
    let before = tree(&d.path().join(".calve"));
    let report = calve_app::recovery::inspect(d.path()).unwrap();
    let after = tree(&d.path().join(".calve"));
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "no file created or removed"
    );
    for (k, v) in &before {
        assert!(after[k] == *v, "{k} changed");
    }
    assert_eq!(report["read_only"], true);
    assert_eq!(report["product_db"]["state"], "ok", "{report}");
    assert_eq!(report["openaevc"]["state"], "ok", "{report}");
    assert_eq!(report["openaevc"]["continuity"]["state"], "ok", "{report}");
    assert!(
        !report["backups"].as_array().unwrap().is_empty(),
        "{report}"
    );
}

#[tokio::test]
async fn migration_is_gated_and_backed_up_and_readers_never_migrate() {
    let d = tempfile::tempdir().unwrap();
    project_with_packs(d.path(), &["one"]).await;
    let db_path = d.path().join(".calve/product.sqlite3");
    {
        // Make it a v13 database again.
        let db = rusqlite::Connection::open(&db_path).unwrap();
        db.execute_batch(
            "DROP TABLE store_binding; ALTER TABLE product_events DROP COLUMN actor;
             DELETE FROM schema_migrations WHERE version=14; PRAGMA user_version=13;",
        )
        .unwrap();
    }
    assert_eq!(
        code(Project::open_reader(d.path()).err().unwrap()),
        "MIGRATION_REQUIRED"
    );
    assert_eq!(
        calve_app::product_schema_version(&db_path).unwrap(),
        13,
        "the reader wrote nothing"
    );
    Project::open(d.path()).unwrap();
    assert_eq!(
        calve_app::product_schema_version(&db_path).unwrap(),
        calve_app::PRODUCT_SCHEMA
    );
    let backups = calve_app::backup::list(&db_path).unwrap();
    let pre = backups
        .iter()
        .find(|b| b["kind"] == "pre-migration")
        .expect("a pre-migration backup");
    assert_eq!(
        (pre["schema"].clone(), pre["integrity"].clone()),
        (serde_json::json!(13), serde_json::json!("ok"))
    );
}

#[tokio::test]
async fn a_lost_or_old_database_is_restored_and_reconciled_against_openaevc() {
    let d = tempfile::tempdir().unwrap();
    let p = Project::init(d.path(), Some("p")).await.unwrap();
    p.create_pack("before backup", None).await.unwrap();
    let intent = p.create_intent("kept").unwrap();
    drop(p);
    let db_path = d.path().join(".calve/product.sqlite3");
    let backup = {
        let db = rusqlite::Connection::open(&db_path).unwrap();
        calve_app::backup::take(&db, &db_path, "daily", calve_app::PRODUCT_SCHEMA).unwrap()
    };
    let backup = backup.file_name().unwrap().to_string_lossy().into_owned();
    // More accepted state after the backup.
    {
        let p = Project::open(d.path()).unwrap();
        p.create_pack("after backup", None).await.unwrap();
    }
    // The database is lost.
    fs::remove_file(&db_path).unwrap();
    for s in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{s}", db_path.display()));
    }
    assert_eq!(
        code(Project::open(d.path()).err().unwrap()),
        "CORRUPT_PRODUCT_STATE"
    );
    let report = calve_app::recovery::restore_and_reconcile(d.path(), &backup)
        .await
        .unwrap();
    assert_eq!(report["restored"]["restored"], backup.as_str());
    let p = Project::open(d.path()).unwrap();
    // Indexes reflect current OpenAEVC (both packs); Calve-owned data is as of the backup.
    let titles: Vec<String> = p
        .list_packs()
        .await
        .unwrap()
        .iter()
        .map(|x| x["title"].as_str().unwrap_or("").to_owned())
        .collect();
    assert!(titles.len() == 2, "{titles:?} {report}");
    assert!(
        p.list_intents()
            .unwrap()
            .iter()
            .any(|i| i["id"] == intent.as_str())
    );

    // A damaged backup is refused before anything is replaced.
    let dir = calve_app::backup::dir(&db_path);
    let bad = dir.join(&backup);
    let mut bytes = fs::read(&bad).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid..mid + 64].fill(0xA5);
    fs::write(&bad, bytes).unwrap();
    drop(p);
    let before = fs::read(&db_path).unwrap();
    assert!(
        calve_app::recovery::restore_and_reconcile(d.path(), &backup)
            .await
            .is_err()
    );
    assert_eq!(fs::read(&db_path).unwrap(), before, "nothing replaced");
}

#[tokio::test]
async fn discovery_stops_at_a_ceiling_and_git_excludes_calve_state() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir_all(d.path().join(".git/info")).unwrap();
    Project::init(d.path(), Some("p")).await.unwrap();
    let exclude = fs::read_to_string(d.path().join(".git/info/exclude")).unwrap();
    assert!(exclude.lines().any(|l| l == "/.calve/"), "{exclude}");
    // Idempotent.
    calve_app::exclude_from_git(d.path()).unwrap();
    assert_eq!(
        fs::read_to_string(d.path().join(".git/info/exclude")).unwrap(),
        exclude
    );
    for dir in ["cache", "run", "logs", "tmp"] {
        assert!(d.path().join(".calve").join(dir).is_dir(), "{dir}");
    }
    let sub = d.path().join("a/b");
    fs::create_dir_all(&sub).unwrap();
    assert!(Project::discover(&sub).is_ok());
    let e = Project::discover_bounded(&sub, &[d.path().join("a")])
        .err()
        .unwrap();
    match e {
        Error::Detailed { code, detail, .. } => {
            assert_eq!(code, "PROJECT_NOT_FOUND");
            assert!(
                detail["entered"].is_string() && detail["canonical"].is_string(),
                "{detail}"
            );
        }
        other => panic!("{other}"),
    }
}

/// Test hook: alters event `from` (its runtime_instance) and recomputes the hash chain from
/// there to the end, as a history rewriter would.
fn rewrite_journal_from(store: &Path, from: i64) {
    let db = rusqlite::Connection::open(store).unwrap();
    let rows: Vec<(i64, Vec<u8>)> = db
        .prepare("SELECT sequence, body FROM event_journal WHERE sequence >= ?1 ORDER BY sequence")
        .unwrap()
        .query_map([from], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let prev: String = db
        .query_row(
            "SELECT hash FROM event_journal WHERE sequence=?1",
            [from - 1],
            |r| r.get(0),
        )
        .unwrap();
    let mut prev: openaevc::protocol::Digest = prev.parse().unwrap();
    for (i, (seq, body)) in rows.into_iter().enumerate() {
        let mut e: openaevc::protocol::Event = serde_json::from_slice(&body).unwrap();
        if i == 0 {
            e.body = serde_json::json!({"rewritten": true});
        }
        e.previous_hash = prev;
        e.hash = openaevc::core::events::event_hash(&e).unwrap();
        prev = e.hash;
        db.execute(
            "UPDATE event_journal SET body=?1, hash=?2, previous_hash=?3 WHERE sequence=?4",
            rusqlite::params![
                serde_json::to_vec(&e).unwrap(),
                e.hash.to_string(),
                e.previous_hash.to_string(),
                seq
            ],
        )
        .unwrap();
    }
}
