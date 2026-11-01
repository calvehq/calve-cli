//! Operational journal (promoted FG17): protocol — genesis, chain verification, torn tail vs corruption, intent/ack,
//! durable compaction, crash at every transition (real process aborts).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use calve_app::journal::{Error, Journal, compact, verify_archive};
use serde_json::{Value, json};

fn binding() -> Value {
    json!({"project_id": "prj_test", "namespace_id": "ns_test", "genesis_hash": "00"})
}

/// Runs `scenario` in a child copy of this test binary with `CALVE_FAULT=point`.
fn run_child(scenario: &str, dir: &Path, point: &str) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_driver", "--nocapture", "--test-threads=1"])
        .env("CALVE_SCENARIO", scenario)
        .env("CALVE_DIR", dir)
        .env("CALVE_FAULT", point)
        .status()
        .unwrap()
}

/// Child entry point: does nothing unless spawned by `run_child`.
#[test]
fn child_driver() {
    let Ok(scenario) = std::env::var("CALVE_SCENARIO") else {
        return;
    };
    let dir = PathBuf::from(std::env::var("CALVE_DIR").unwrap());
    match scenario.as_str() {
        "append3" => {
            let mut j = Journal::create(&dir.join("j.jsonl"), "capture", "j1", binding()).unwrap();
            for i in 0..3 {
                j.append("step", json!({"i": i})).unwrap();
            }
        }
        "intent" => {
            let mut j =
                Journal::create(&dir.join("j.jsonl"), "materialize", "j2", binding()).unwrap();
            let target = dir.join("target.txt");
            j.with_intent("write", json!({"path": "target.txt"}), || {
                fs::write(&target, b"new").map_err(|e| e.to_string())?;
                Ok((
                    (),
                    json!({"digest": calve_app::journal::sha256_hex(b"new")}),
                ))
            })
            .unwrap()
            .unwrap();
        }
        "compact" => {
            compact(
                &dir.join("j.jsonl"),
                &dir.join("history"),
                "Done",
                json!({"O": "abc"}),
            )
            .unwrap();
        }
        other => panic!("unknown scenario {other}"),
    }
}

#[test]
fn genesis_and_chain_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("j.jsonl");
    let mut j = Journal::create(&p, "capture", "id1", binding()).unwrap();
    for i in 0..5 {
        assert_eq!(j.append("step", json!({"i": i})).unwrap(), i + 1);
    }
    let o = Journal::open(&p).unwrap();
    assert_eq!(o.records.len(), 5);
    assert_eq!(o.journal.header["seq"], 0);
    assert_eq!(o.journal.header["type"], "capture");
    assert!(o.torn.is_none());
    // Continue appending after reopen keeps the chain valid.
    let mut j = o.journal;
    j.append("step", json!({"i": 5})).unwrap();
    assert_eq!(Journal::open(&p).unwrap().records.len(), 6);
}

#[test]
fn torn_tail_unterminated_is_truncated_and_preserved() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("j.jsonl");
    let mut j = Journal::create(&p, "capture", "id1", binding()).unwrap();
    j.append("a", json!({})).unwrap();
    let before = fs::read(&p).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&p)
        .unwrap()
        .write_all_ext(b"{\"seq\":2,\"kind\":\"b");
    let o = Journal::open(&p).unwrap();
    assert_eq!(o.records.len(), 1);
    let torn = o.torn.expect("torn bytes preserved");
    assert_eq!(fs::read(torn).unwrap(), b"{\"seq\":2,\"kind\":\"b");
    assert_eq!(
        fs::read(&p).unwrap(),
        before,
        "truncated to last valid boundary"
    );
}

#[test]
fn complete_last_line_with_bad_hash_is_corruption_not_torn() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("j.jsonl");
    let mut j = Journal::create(&p, "capture", "id1", binding()).unwrap();
    j.append("a", json!({"v": 1})).unwrap();
    let text = fs::read_to_string(&p)
        .unwrap()
        .replace("\"v\":1", "\"v\":2");
    fs::write(&p, text).unwrap();
    assert!(matches!(
        Journal::open(&p),
        Err(Error::Corrupt { line: 2, .. })
    ));
}

#[test]
fn middle_bit_flip_is_corruption() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("j.jsonl");
    let mut j = Journal::create(&p, "capture", "id1", binding()).unwrap();
    for i in 0..3 {
        j.append("a", json!({"i": i})).unwrap();
    }
    let mut lines: Vec<String> = fs::read_to_string(&p)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    lines[2] = lines[2].replace("\"i\":1", "\"i\":9");
    fs::write(&p, lines.join("\n") + "\n").unwrap();
    assert!(matches!(
        Journal::open(&p),
        Err(Error::Corrupt { line: 3, .. })
    ));
}

#[test]
fn reordered_records_are_corruption() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("j.jsonl");
    let mut j = Journal::create(&p, "capture", "id1", binding()).unwrap();
    for i in 0..3 {
        j.append("a", json!({"i": i})).unwrap();
    }
    let mut lines: Vec<String> = fs::read_to_string(&p)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    lines.swap(1, 2);
    fs::write(&p, lines.join("\n") + "\n").unwrap();
    assert!(matches!(Journal::open(&p), Err(Error::Corrupt { .. })));
}

#[test]
fn crash_at_each_append_transition_recovers_a_valid_prefix() {
    for point in [
        "append.before_write",
        "append.after_write",
        "append.after_fsync",
    ] {
        let d = tempfile::tempdir().unwrap();
        let status = run_child("append3", d.path(), point);
        assert!(!status.success(), "{point}: child aborted");
        let o = Journal::open(&d.path().join("j.jsonl")).unwrap_or_else(|e| panic!("{point}: {e}"));
        // The fault fires on the first append; the header alone or header + 1 record survives.
        assert!(o.records.len() <= 1, "{point}: {} records", o.records.len());
        println!(
            "{point}: recovered {} records, torn={:?}",
            o.records.len(),
            o.torn
        );
    }
}

#[test]
fn crash_between_intent_and_ack_is_visible_to_recovery() {
    for (point, expect_unacked, expect_written) in [
        ("write.after_intent", true, false),
        ("write.after_mutation", true, true),
    ] {
        let d = tempfile::tempdir().unwrap();
        assert!(!run_child("intent", d.path(), point).success());
        let o = Journal::open(&d.path().join("j.jsonl")).unwrap();
        let unacked = Journal::unacknowledged(&o.records);
        assert_eq!(!unacked.is_empty(), expect_unacked, "{point}");
        assert_eq!(
            d.path().join("target.txt").exists(),
            expect_written,
            "{point}"
        );
    }
    // Without a fault the intent is acknowledged with the observed digest.
    let d = tempfile::tempdir().unwrap();
    assert!(run_child("intent", d.path(), "none").success());
    let o = Journal::open(&d.path().join("j.jsonl")).unwrap();
    assert!(Journal::unacknowledged(&o.records).is_empty());
    assert_eq!(
        o.records[1].body["observed"]["digest"],
        calve_app::journal::sha256_hex(b"new")
    );
}

fn terminal_journal(dir: &Path) {
    let mut j = Journal::create(&dir.join("j.jsonl"), "capture", "cap-1", binding()).unwrap();
    j.append("done", json!({"state": "Done"})).unwrap();
}

#[test]
fn crash_at_each_compaction_step_converges_and_is_idempotent() {
    for point in [
        "compact.after_archive",
        "compact.after_history",
        "compact.after_delete",
        "none",
    ] {
        let d = tempfile::tempdir().unwrap();
        terminal_journal(d.path());
        let first = run_child("compact", d.path(), point);
        assert_eq!(first.success(), point == "none", "{point}");
        if d.path().join("j.jsonl").exists() {
            // Re-run converges; duplicate history entries are not written.
            assert!(
                run_child("compact", d.path(), "none").success(),
                "{point}: rerun"
            );
        }
        assert!(
            !d.path().join("j.jsonl").exists(),
            "{point}: journal deleted"
        );
        let history = Journal::open(&d.path().join("history/history.jsonl")).unwrap();
        assert_eq!(
            history.records.len(),
            1,
            "{point}: exactly one history entry"
        );
        let entry = &history.records[0].body;
        for key in [
            "journal_id",
            "header_hash",
            "final_seq",
            "final_hash",
            "terminal_state",
            "results",
            "journal_sha256",
        ] {
            assert!(!entry[key].is_null(), "{point}: history keeps {key}");
        }
        verify_archive(&d.path().join("history/archive/cap-1.jsonl"), entry).unwrap();
    }
}

#[test]
fn tampered_archive_fails_commitment() {
    let d = tempfile::tempdir().unwrap();
    terminal_journal(d.path());
    let entry = compact(
        &d.path().join("j.jsonl"),
        &d.path().join("history"),
        "Done",
        json!({}),
    )
    .unwrap();
    let archive = d.path().join("history/archive/cap-1.jsonl");
    let text = fs::read_to_string(&archive)
        .unwrap()
        .replace("Done", "Gone");
    fs::write(&archive, text).unwrap();
    assert!(verify_archive(&archive, &entry).is_err());
}

trait WriteAllExt {
    fn write_all_ext(self, b: &[u8]);
}
impl WriteAllExt for fs::File {
    fn write_all_ext(mut self, b: &[u8]) {
        use std::io::Write;
        self.write_all(b).unwrap();
    }
}

/// A lock-free reader never touches a record being appended; only `open` repairs.
#[test]
fn read_leaves_a_torn_tail_in_place() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("j");
    let mut j = Journal::create(&path, "test", "test", json!({})).unwrap();
    j.append("a", json!({})).unwrap();
    drop(j);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut f, b"{\"partial").unwrap();
    drop(f);
    let before = fs::read(&path).unwrap();
    assert_eq!(Journal::read(&path).unwrap().records.len(), 1);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(
        Journal::read(&path)
            .unwrap()
            .journal
            .append("b", json!({}))
            .is_err()
    );
    assert_eq!(Journal::open(&path).unwrap().records.len(), 1);
    assert!(fs::read(&path).unwrap().len() < before.len());
}
