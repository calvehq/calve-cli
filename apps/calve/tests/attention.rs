//! Inbox sources (§29, P9), `status` (§17.5, P16) and maintenance GC (§44, P14).
#![cfg(unix)]

use std::fs;

use calve_testkit::Env;
use serde_json::Value;

fn kinds(items: &Value) -> Vec<(String, String)> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["kind"].as_str().unwrap().to_owned(),
                i["source_key"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn attention_status_and_gc() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    let ok = |a: &[&str]| env.ok(&[&["--project", p.as_str()][..], a].concat());
    let pack = |t: &str| {
        ok(&["pack", "create", t])["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    fs::write(root.join("a.txt"), "aaa\n").unwrap();
    let id = pack("P");
    ok(&[
        "pack",
        "capture-tree",
        "--accept-deletions",
        &id,
        ".",
        "--generation",
        "1",
    ]);
    let g = ok(&["pack", "show", &id])["generation"].to_string();
    ok(&["pack", "seal", &id, "--generation", &g]);

    // A failing verification is an item; a later passing run of the same verifier resolves it.
    let zero = format!("sha256:{}", "0".repeat(64));
    ok(&[
        "pack",
        "verify",
        &id,
        "--generation",
        &g,
        "--path",
        "a.txt",
        "--digest",
        &zero,
    ]);
    let items = ok(&["inbox", "list"]);
    assert!(
        kinds(&items)
            .iter()
            .any(|(k, _)| k == "verification_failed"),
        "{items}"
    );
    let status = ok(&["status"]);
    assert_eq!(status["packs"]["sealed"], 1, "{status}");
    assert_eq!(
        status["blockers"]["verification"][0]["kind"],
        "verification_failed"
    );
    ok(&["pack", "verify", &id, "--generation", &g]);
    assert!(
        !kinds(&ok(&["inbox", "list"]))
            .iter()
            .any(|(k, _)| k == "verification_failed")
    );
    // An evaluation warning.
    ok(&[
        "pack",
        "evaluate",
        &id,
        "--generation",
        &g,
        "--warn-after-bytes",
        "0",
    ]);
    assert!(
        kinds(&ok(&["inbox", "list"]))
            .iter()
            .any(|(k, _)| k == "evaluation_warning")
    );

    // An interrupted capture needs recovery until it is resumed.
    let q = pack("Q");
    fs::write(root.join("b.txt"), "bbb\n").unwrap();
    let mut crash = env.vars.clone();
    crash.push(("CALVE_FAULT".into(), "capture.submit.1.1.after_send".into()));
    let saved = std::mem::replace(&mut env.vars, crash);
    let run = env.run(&[
        "--project",
        &p,
        "pack",
        "capture-tree",
        "--accept-deletions",
        &q,
        ".",
        "--generation",
        "1",
    ]);
    env.vars = saved;
    assert!(!run.success);
    let ok = |a: &[&str]| env.ok(&[&["--project", p.as_str()][..], a].concat());
    let items = ok(&["inbox", "list"]);
    let (_, key) = kinds(&items)
        .into_iter()
        .find(|(k, _)| k == "recovery_required")
        .expect("recovery item");
    let status = ok(&["status"]);
    assert_eq!(
        status["recovery"][0]["source_key"],
        key.as_str(),
        "{status}"
    );
    assert_eq!(status["packs"]["open"], 1);
    let session = key.trim_start_matches("capture:");
    ok(&["capture", "resume", session]);
    assert!(
        !kinds(&ok(&["inbox", "list"]))
            .iter()
            .any(|(_, k)| *k == key)
    );
    let all = ok(&["inbox", "list", "--all"]);
    assert!(
        all.as_array()
            .unwrap()
            .iter()
            .any(|i| i["source_key"] == key.as_str() && !i["resolved_at"].is_null())
    );

    // Workspace summary, read from each Project's last refreshed Inbox.
    let summary = env.ok(&["inbox", "summary"]);
    let row = &summary["projects"]
        .as_array()
        .unwrap()
        .iter()
        // Registered paths are canonical (macOS temp dirs live under /private/var).
        .find(|r| r["path"] == fs::canonicalize(&root).unwrap().to_str().unwrap())
        .cloned()
        .unwrap();
    assert!(
        row["inbox"]["attention"].as_u64().unwrap() >= 1,
        "{summary}"
    );

    // GC: the dry run names class, owner, count, bytes and reason and removes nothing.
    fs::create_dir_all(root.join(".calve/tmp")).unwrap();
    fs::write(root.join(".calve/tmp/leftover"), "x").unwrap();
    // Log retention (14 days): a 15-day-old log is collectable, a fresh one is not.
    let logs = root.join(".calve/logs");
    fs::create_dir_all(&logs).unwrap();
    fs::write(logs.join("old.output"), "old").unwrap();
    fs::write(logs.join("fresh.output"), "fresh").unwrap();
    fs::File::options()
        .write(true)
        .open(logs.join("old.output"))
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(15 * 86_400))
        .unwrap();
    let plan = ok(&["maintenance", "gc", "--dry-run", "--grace-secs", "0"]);
    let classes = plan["classes"].as_array().unwrap();
    let tmp = classes
        .iter()
        .find(|c| c["class"] == "temporary_files")
        .unwrap();
    assert_eq!(tmp["owner"], "FILESYSTEM_CACHE");
    assert!(
        tmp["count"].as_u64().unwrap() >= 1 && tmp["estimated_bytes"].as_u64().unwrap() >= 1,
        "{plan}"
    );
    let store = classes
        .iter()
        .find(|c| c["class"] == "openaevc_unreachable_objects")
        .unwrap();
    assert_eq!(store["owner"], "OPENAEVC_RUNTIME");
    assert!(store["reason"].as_str().unwrap().contains("never removed"));
    assert!(
        classes
            .iter()
            .any(|c| c["class"] == "resolved_inbox_rows" && c["owner"] == "CALVE_PRODUCT")
    );
    assert!(
        !classes
            .iter()
            .any(|c| c["class"] == "resolved_conflict_artifacts"),
        "conflicts only on request"
    );
    let log_class = classes.iter().find(|c| c["class"] == "logs").unwrap();
    assert_eq!(log_class["count"], 1, "{plan}");
    assert!(root.join(".calve/tmp/leftover").exists());
    assert!(
        logs.join("old.output").exists(),
        "the dry run removed nothing"
    );
    let done = ok(&["maintenance", "gc", "--grace-secs", "0", "--yes"]);
    assert!(!root.join(".calve/tmp/leftover").exists(), "{done}");
    assert!(!logs.join("old.output").exists(), "{done}");
    assert!(
        logs.join("fresh.output").exists(),
        "within retention: {done}"
    );
    // Accepted state is intact.
    ok(&["pack", "show", &id]);
    assert_eq!(ok(&["maintenance", "check"])["ok"], true);
}

/// The dry run's count is what OpenAEVC's collector then removes, and the dry run removes nothing.
#[test]
fn the_dry_run_counts_with_the_real_collector() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    let shard = root.join(".calve/openaevc/objects/sha256/ab");
    fs::create_dir_all(&shard).unwrap();
    let orphan = shard.join("ab".repeat(32));
    fs::write(&orphan, b"orphan").unwrap();
    let args = [
        "--project",
        p,
        "maintenance",
        "gc",
        "--dry-run",
        "--grace-secs",
        "0",
    ];
    let plan = env.ok(&args);
    let class = plan["classes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["class"] == "openaevc_unreachable_objects")
        .unwrap()
        .clone();
    assert_eq!(class["count"], 1, "{plan}");
    assert_eq!(class["estimated_bytes"], 6, "{plan}");
    assert!(orphan.exists(), "the dry run removed nothing");
    assert!(
        fs::read_dir(root.join(".calve/tmp"))
            .unwrap()
            .next()
            .is_none(),
        "the view is gone"
    );
    env.ok(&[
        "--project",
        p,
        "maintenance",
        "gc",
        "--grace-secs",
        "0",
        "--yes",
    ]);
    assert!(!orphan.exists(), "the collector removed what was counted");
}
