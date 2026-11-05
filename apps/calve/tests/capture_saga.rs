//! Capture sessions and the supersede saga under crash injection (rev 10 §12; N13, N23).
//!
//! Each crash is a real process abort (`CALVE_FAULT`, debug builds) at an intent, send or state
//! boundary. Every scenario runs twice: resuming inside OpenAEVC's replay window (identical
//! envelopes) and with the window forced to zero (authoritative discovery).
#![cfg(unix)]

use std::fs;
use std::path::Path;

use calve_testkit::Env;
use serde_json::Value;

struct T {
    env: Env,
    p: String,
}

impl T {
    fn new() -> Self {
        let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
        let root = env.path().join("project");
        let p = root.to_str().unwrap().to_owned();
        env.ok(&["init", &p]);
        env.enable_toy(&root);
        fs::write(root.join("toy.toml"), "").unwrap();
        T { env, p }
    }
    fn root(&self) -> &Path {
        Path::new(&self.p)
    }
    fn args<'a>(&'a self, a: &[&'a str]) -> Vec<&'a str> {
        [&["--project", self.p.as_str()][..], a].concat()
    }
    fn ok(&self, a: &[&str]) -> Value {
        self.env.ok(&self.args(a))
    }
    fn fails(&self, a: &[&str]) -> String {
        self.env.fails(&self.args(a))
    }
    /// Runs with a crash point; the process must die.
    fn crash(&mut self, point: &str, window0: bool, a: &[&str]) {
        let saved = self.env.vars.clone();
        self.env.vars.push(("CALVE_FAULT".into(), point.into()));
        let run = self.env.run(&self.args(a));
        self.env.vars = saved;
        if window0 {
            self.env
                .vars
                .push(("CALVE_REPLAY_WINDOW_MS".into(), "0".into()));
        }
        assert!(!run.success, "{point}: expected a crash, got {}", run.value);
    }
    fn pack(&self, title: &str) -> String {
        self.ok(&["pack", "create", title])["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn effects(&self, pack: &str) -> Vec<Value> {
        self.ok(&["pack", "show", pack])["candidate_effects"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    fn session_of(&self, pack: &str) -> Value {
        self.ok(&["capture", "list"])
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["pack"] == pack)
            .cloned()
            .unwrap_or_else(|| panic!("no capture session on {pack}"))
    }
}

fn capture_two(t: &T, pack: &str) {
    fs::write(t.root().join("a.toy"), "aaa").unwrap();
    fs::write(t.root().join("b.toy"), "bbb").unwrap();
    t.ok(&[
        "pack",
        "capture-tree",
        "--accept-deletions",
        pack,
        "--generation",
        "1",
    ]);
}

#[test]
fn an_interrupted_capture_resumes_without_duplicate_effects() {
    for window0 in [false, true] {
        for point in [
            "capture.planned",
            "capture.start.1.after_intent",
            "capture.submit.1.1.after_intent",
            "capture.submit.1.1.after_send",
            "capture.complete.1.after_send",
        ] {
            let mut t = T::new();
            // This test is about resuming WITHIN the crashed attempt's lease. Under load the
            // crash-to-resume time exceeded the 120 s default (M5 lease investigation: resume
            // ran 50 s after expiry) and the attempt was correctly LOST; that lapsed case is
            // covered by `a_lost_attempt_resumes_or_requires_rollback` with a 5 s lease. Test
            // accommodation only; production defaults are unchanged.
            t.env
                .vars
                .push(("CALVE_EXECUTION_LEASE_MS".into(), "3600000".into()));
            let pack = t.pack("P");
            fs::write(t.root().join("a.toy"), "aaa").unwrap();
            fs::write(t.root().join("b.toy"), "bbb").unwrap();
            t.crash(
                point,
                window0,
                &[
                    "pack",
                    "capture-tree",
                    "--accept-deletions",
                    &pack,
                    "--generation",
                    "1",
                ],
            );
            let s = t.session_of(&pack);
            assert_ne!(s["state"], "Done", "{point}: {s}");
            // Calve's guard while the session is not terminal.
            let g = t.ok(&["pack", "show", &pack])["generation"].to_string();
            let refused = t.fails(&["pack", "seal", &pack, "--generation", &g]);
            assert!(
                refused.contains("CAPTURE_INCOMPLETE") || refused.contains("active execution"),
                "{point}: {refused}"
            );
            let done = t.ok(&["capture", "resume", s["session"].as_str().unwrap()]);
            assert_eq!(done["state"], "Done", "{point} window0={window0}: {done}");
            let paths: Vec<String> = t
                .effects(&pack)
                .iter()
                .map(|e| e["target"]["locator"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(
                paths.len(),
                3,
                "{point} window0={window0}: exactly three effects (a, b, toy.toml), {paths:?}"
            );
            let g = t.ok(&["pack", "show", &pack])["generation"].to_string();
            t.ok(&["pack", "seal", &pack, "--generation", &g]);
        }
    }
}

/// An attempt whose lease lapsed while Calve was down is LOST. With no effect applied, resume
/// continues on a new attempt (its own work unit, no `retry_of` across work units) and the pack
/// promotes; with effects applied, those can never be promoted, so resume stops with
/// CAPTURE_INCOMPLETE and the capture is rolled back.
#[test]
fn a_lost_attempt_resumes_or_requires_rollback() {
    for (point, applied) in [
        ("capture.start.1.after_send", false),
        ("capture.submit.1.0.after_send", true),
    ] {
        let mut t = T::new();
        t.env
            .vars
            .push(("CALVE_EXECUTION_LEASE_MS".into(), "5000".into()));
        let pack = t.pack("P");
        fs::write(t.root().join("a.toy"), "aaa").unwrap();
        fs::write(t.root().join("b.toy"), "bbb").unwrap();
        t.crash(
            point,
            false,
            &[
                "pack",
                "capture-tree",
                "--accept-deletions",
                &pack,
                ".",
                "--generation",
                "1",
            ],
        );
        // Only the crashed attempt has the short lease; the resume starts its attempt with the
        // normal one, however slow the machine is.
        t.env.vars.retain(|(k, _)| k != "CALVE_EXECUTION_LEASE_MS");
        std::thread::sleep(std::time::Duration::from_secs(7));
        // Kept for diagnosis: once (M5 closeout, idle host) a resume here found the crashed
        // attempt still live; print its lease and events if that recurs.
        let executions = t.ok(&["execution", "list", "--pack", &pack]);
        let session = t.session_of(&pack)["session"].as_str().unwrap().to_owned();
        if applied {
            let resumed = t.env.run(&t.args(&["capture", "resume", &session]));
            if resumed.success {
                for e in executions.as_array().into_iter().flatten() {
                    let id = e["id"].as_str().unwrap_or_default();
                    eprintln!(
                        "{point}: execution {e}\nlogs {}",
                        t.ok(&["execution", "logs", id])
                    );
                }
            }
            assert!(
                !resumed.success,
                "{point}: resume unexpectedly succeeded: {}",
                resumed.value
            );
            let refused = resumed.stderr;
            assert!(refused.contains("CAPTURE_INCOMPLETE"), "{point}: {refused}");
            assert_eq!(t.session_of(&pack)["state"], "Lost");
            let rolled = t.ok(&["capture", "rollback", &session, "--yes"]);
            assert!(
                rolled.to_string().contains("uperseded"),
                "{point}: {rolled}"
            );
            continue;
        }
        let done = t.ok(&["capture", "resume", &session]);
        assert_eq!(done["state"], "Done", "{point}: {done}");
        assert!(
            t.session_of(&pack)["attempts"].as_u64().unwrap() >= 2,
            "{point}"
        );
        assert_eq!(
            t.effects(&pack).len(),
            3,
            "{point}: a, b and toy.toml once each"
        );
        let g = t.ok(&["pack", "show", &pack])["generation"].to_string();
        for step in ["seal", "qualify", "promote"] {
            t.ok(&["pack", step, &pack, "--generation", &g]);
        }
    }
}

/// Chunk uploads are journaled steps too: a crash around any of them resumes to one chunked
/// effect whose blobs reconstruct the file byte for byte.
#[test]
fn an_interrupted_chunk_upload_resumes_to_identical_content() {
    let big: Vec<u8> = (0..(5u32 << 20))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    for window0 in [false, true] {
        for point in [
            "capture.chunk.0.0.after_intent",
            "capture.chunk.0.0.after_send",
            "capture.chunk.0.1.after_send",
            "capture.submit.1.1.after_send",
        ] {
            let mut t = T::new();
            // Resume must happen within the crashed attempt's lease (see the test above).
            t.env
                .vars
                .push(("CALVE_EXECUTION_LEASE_MS".into(), "3600000".into()));
            let pack = t.pack("P");
            fs::write(t.root().join("big.toy"), &big).unwrap();
            t.crash(
                point,
                window0,
                &[
                    "pack",
                    "capture-tree",
                    "--accept-deletions",
                    &pack,
                    "--generation",
                    "1",
                ],
            );
            let s = t.session_of(&pack);
            let done = t.ok(&["capture", "resume", s["session"].as_str().unwrap()]);
            assert_eq!(done["state"], "Done", "{point} window0={window0}: {done}");
            let effects = t.effects(&pack);
            let chunked: Vec<&Value> = effects
                .iter()
                .filter(|e| e["target"]["locator"] == "big.toy")
                .collect();
            assert_eq!(chunked.len(), 1, "{point} window0={window0}");
            assert_eq!(chunked[0]["kind"], "org.example.toy.put-chunked");
            assert_eq!(chunked[0]["payload"]["chunks"].as_array().unwrap().len(), 2);
            fs::remove_file(t.root().join("big.toy")).unwrap();
            let m = t.ok(&[
                "resource",
                "materialize",
                "big.toy",
                "--from",
                &pack,
                "--apply",
            ]);
            assert_eq!(m["applied"], true, "{point}: {m}");
            assert!(
                fs::read(t.root().join("big.toy")).unwrap() == big,
                "{point} window0={window0}"
            );
        }
    }
}

#[test]
fn an_interrupted_capture_rolls_back_by_supersede_or_compensate() {
    // Supersede: the pack is replaced by one holding its pre-capture effects (none); tasks follow.
    let mut t = T::new();
    let pack = t.pack("P");
    let intent = t.ok(&["intent", "create", "I"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let task = t.ok(&["task", "create", &intent, "T"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.ok(&["task", "link-pack", &task, &pack]);
    fs::write(t.root().join("a.toy"), "aaa").unwrap();
    fs::write(t.root().join("b.toy"), "bbb").unwrap();
    t.crash(
        "capture.submit.1.1.after_send",
        false,
        &[
            "pack",
            "capture-tree",
            "--accept-deletions",
            &pack,
            "--generation",
            "1",
        ],
    );
    let s = t.session_of(&pack)["session"].as_str().unwrap().to_owned();
    let r = t.ok(&["capture", "rollback", &s, "--yes"]);
    assert_eq!(r["state"], "Done", "{r}");
    let replacement = r["replacement"].as_str().unwrap().to_owned();
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "ABANDONED");
    assert!(t.effects(&replacement).is_empty());
    assert_eq!(t.session_of(&pack)["state"], "Superseded");
    let task_packs = t.ok(&["task", "show", &task]).to_string();
    assert!(
        task_packs.contains(&replacement) && !task_packs.contains(&pack),
        "{task_packs}"
    );

    // Compensate: effects restoring the pre-capture files are appended (RSE yes, CCE no).
    let mut t = T::new();
    let pack = t.pack("P");
    fs::write(t.root().join("a.toy"), "aaa").unwrap();
    fs::write(t.root().join("b.toy"), "bbb").unwrap();
    t.crash(
        "capture.submit.1.1.after_send",
        false,
        &[
            "pack",
            "capture-tree",
            "--accept-deletions",
            &pack,
            "--generation",
            "1",
        ],
    );
    let s = t.session_of(&pack)["session"].as_str().unwrap().to_owned();
    let r = t.ok(&["capture", "rollback", &s, "--mode", "compensate", "--yes"]);
    assert_eq!(
        (r["rse_holds"].clone(), r["cce_holds"].clone()),
        (Value::Bool(true), Value::Bool(false)),
        "{r}"
    );
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "OPEN");
}

/// A pack with two captured files (a.toy, b.toy) whose supersession keeps the first.
fn supersede_setup() -> (T, String, String) {
    let t = T::new();
    let pack = t.pack("P");
    let intent = t.ok(&["intent", "create", "I"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let task = t.ok(&["task", "create", &intent, "T"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.ok(&["task", "link-pack", &task, &pack]);
    capture_two(&t, &pack);
    (t, pack, task)
}

/// The uninterrupted saga: one replacement holding the first effect, the original abandoned.
#[test]
fn a_supersession_without_crashes_completes() {
    let (t, pack, _) = supersede_setup();
    let done = t.ok(&["supersede", "start", &pack, "--keep", "1", "--yes"]);
    assert_eq!(saga_of(&t, &pack)["state"], "Done", "{done}");
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "ABANDONED");
}

/// A replay attempt that dies after applying effects can never be promoted, so the saga must
/// compensate and leave the original usable, not finish Done on a dead replacement.
#[test]
fn a_replay_attempt_that_dies_keeps_the_original_pack() {
    let (mut t, pack, _) = supersede_setup();
    let effects = t.effects(&pack).len();
    t.env
        .vars
        .push(("CALVE_EXECUTION_LEASE_MS".into(), "5000".into()));
    t.crash(
        "supersede.replay.1.0.after_send",
        false,
        &["supersede", "start", &pack, "--keep", "1", "--yes"],
    );
    t.env.vars.retain(|(k, _)| k != "CALVE_EXECUTION_LEASE_MS");
    std::thread::sleep(std::time::Duration::from_secs(7));
    let saga = saga_of(&t, &pack);
    let resumed = t.env.run(&[
        "--project",
        &t.p,
        "supersede",
        "resume",
        saga["saga"].as_str().unwrap(),
    ]);
    let saga = saga_of(&t, &pack);
    assert_ne!(saga["state"], "Done", "{}: {saga}", resumed.stderr);
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "OPEN", "{saga}");
    assert_eq!(
        t.effects(&pack).len(),
        effects,
        "the original keeps its work"
    );
}

/// A crash at each compensation step converges on the same end: P usable, links restored.
#[test]
fn a_crash_during_compensation_converges() {
    for point in ["supersede.C1", "supersede.C2"] {
        let (mut t, pack, _) = supersede_setup();
        t.crash(
            "supersede.Revalidated",
            false,
            &["supersede", "start", &pack, "--keep", "1", "--yes"],
        );
        let intent = t.ok(&["intent", "create", "J"])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let other = t.ok(&["task", "create", &intent, "U"])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        t.ok(&["task", "link-pack", &other, &pack]);
        let saga = saga_of(&t, &pack)["saga"].as_str().unwrap().to_owned();
        t.crash(point, false, &["supersede", "resume", &saga]);
        let again = t.fails(&["supersede", "resume", &saga]);
        assert!(again.contains("SUPERSEDE_CONFLICT"), "{point}: {again}");
        assert_eq!(saga_of(&t, &pack)["state"], "Conflicted", "{point}");
        assert_eq!(t.ok(&["pack", "show", &pack])["state"], "OPEN", "{point}");
    }
}

/// A crash between the relink's commit and its journal record: resume sees the commit.
#[test]
fn a_crash_between_relink_commit_and_ack_converges() {
    let (mut t, pack, _) = supersede_setup();
    t.crash(
        "supersede.S7.before_ack",
        false,
        &["supersede", "start", &pack, "--keep", "1", "--yes"],
    );
    let saga = saga_of(&t, &pack)["saga"].as_str().unwrap().to_owned();
    let done = t.ok(&["supersede", "resume", &saga]);
    assert_eq!(done["state"], "Done", "{done}");
    assert_eq!(done["rse_holds"], true, "{done}");
    assert_eq!(done["cce_holds"], true, "{done}");
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "ABANDONED");
}

/// A sealed pack with effects, the case a reopen cannot serve.
fn sealed_setup() -> (T, String, u64) {
    let (t, pack, _) = supersede_setup();
    let g = t.ok(&["pack", "show", &pack])["generation"]
        .as_u64()
        .unwrap();
    t.ok(&["pack", "seal", &pack, "--generation", &g.to_string()]);
    (t, pack, g)
}

/// Scenario C on OpenAEVC v0.1.0: the reopen is refused before anything changes, and the explicit
/// replacement carries the work on to a promotion, with the original kept as history.
#[test]
fn an_effect_bearing_pack_refuses_reopen_and_is_replaced_explicitly() {
    let (t, pack, g) = sealed_setup();
    let before = t.ok(&["pack", "show", &pack]);
    let refused = t.fails(&["pack", "reopen", &pack, "--generation", &g.to_string()]);
    assert!(refused.contains("REOPEN_UNSAFE"), "{refused}");
    assert!(refused.contains("supersede start"), "{refused}");
    assert_eq!(t.ok(&["pack", "show", &pack]), before, "nothing changed");
    // Nothing happens on its own: the original is still the live pack.
    assert!(t.ok(&["supersede", "list"]).as_array().unwrap().is_empty());

    let done = t.ok(&["supersede", "start", &pack, "--keep", "1", "--yes"]);
    assert_eq!(done["state"], "Done", "{done}");
    assert_eq!(done["rse_holds"], true, "{done}");
    assert_eq!(done["cce_holds"], true, "{done}");
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "ABANDONED");
    let replacement = done["replacement"].as_str().unwrap();
    let g = t.ok(&["pack", "show", replacement])["generation"].to_string();
    t.ok(&["pack", "seal", replacement, "--generation", &g]);
    t.ok(&["pack", "qualify", replacement, "--generation", &g]);
    t.ok(&["pack", "promote", replacement, "--generation", &g]);
    assert_eq!(t.ok(&["pack", "show", replacement])["state"], "PROMOTED");
    // History stays: the abandoned pack's effects can still be read.
    assert_eq!(
        t.effects(&pack).len(),
        before["candidate_effects"].as_array().unwrap().len()
    );
}

/// A crash at any step from a sealed original converges on one replacement, original last.
#[test]
fn replacing_a_sealed_pack_converges_after_a_crash_at_every_step() {
    for point in [
        "supersede.S0",
        "supersede.ReplacementCreated",
        "supersede.replay.1.0.after_send",
        "supersede.Verified",
        "supersede.S7.before_ack",
        "supersede.abandon_original.after_send",
    ] {
        let (mut t, pack, _) = sealed_setup();
        t.crash(
            point,
            false,
            &["supersede", "start", &pack, "--keep", "1", "--yes"],
        );
        let saga = saga_of(&t, &pack);
        if saga["state"] != "Done" {
            assert_ne!(t.ok(&["pack", "show", &pack])["state"], "OPEN", "{point}");
            let done = t.ok(&["supersede", "resume", saga["saga"].as_str().unwrap()]);
            assert_eq!(done["state"], "Done", "{point}: {done}");
        }
        assert_eq!(
            t.ok(&["pack", "show", &pack])["state"],
            "ABANDONED",
            "{point}"
        );
    }
}

/// The original changing under the saga stops it; the original keeps its state and its work.
#[test]
fn a_conflict_while_replacing_a_sealed_pack_keeps_the_original() {
    let (mut t, pack, _) = sealed_setup();
    let effects = t.effects(&pack).len();
    t.crash(
        "supersede.ReplayCompleted",
        false,
        &["supersede", "start", &pack, "--keep", "1", "--yes"],
    );
    t.ok(&["pack", "quarantine", &pack, "--reason", "hold"]);
    let saga = saga_of(&t, &pack)["saga"].as_str().unwrap().to_owned();
    let err = t.fails(&["supersede", "resume", &saga]);
    assert!(err.contains("SUPERSEDE"), "{err}");
    assert_eq!(saga_of(&t, &pack)["state"], "Conflicted");
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "QUARANTINED");
    t.ok(&["pack", "release-quarantine", &pack]);
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "SEALED");
    assert_eq!(t.effects(&pack).len(), effects);
}

/// A replay cancelled or lost after applying effects compensates: the sealed original survives.
#[test]
fn a_cancelled_or_lost_replay_keeps_a_sealed_original() {
    for cancel in [true, false] {
        let (mut t, pack, _) = sealed_setup();
        let lease = if cancel { "600000" } else { "5000" };
        t.env
            .vars
            .push(("CALVE_EXECUTION_LEASE_MS".into(), lease.into()));
        t.crash(
            "supersede.replay.1.0.after_send",
            false,
            &["supersede", "start", &pack, "--keep", "1", "--yes"],
        );
        t.env.vars.retain(|(k, _)| k != "CALVE_EXECUTION_LEASE_MS");
        let saga = saga_of(&t, &pack);
        if cancel {
            let replacement = saga["replacement"].as_str().unwrap();
            let list = t.ok(&["execution", "list", "--pack", replacement]);
            let exe = list[0]["id"].as_str().unwrap().to_owned();
            t.ok(&["execution", "cancel", &exe, "--reason", "changed my mind"]);
        } else {
            std::thread::sleep(std::time::Duration::from_secs(7));
        }
        let _ = t
            .env
            .run(&t.args(&["supersede", "resume", saga["saga"].as_str().unwrap()]));
        assert_ne!(saga_of(&t, &pack)["state"], "Done", "cancel={cancel}");
        assert_eq!(
            t.ok(&["pack", "show", &pack])["state"],
            "SEALED",
            "cancel={cancel}"
        );
    }
}

fn saga_of(t: &T, pack: &str) -> Value {
    t.ok(&["supersede", "list"])
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["pack"] == pack)
        .cloned()
        .unwrap()
}

#[test]
fn a_crash_at_every_saga_step_converges_to_one_replacement() {
    let points = [
        "supersede.S0",
        "supersede.CaptureClosed",
        "supersede.create.after_intent",
        "supersede.create.after_send",
        "supersede.ReplacementCreated",
        "supersede.work_unit.1.after_send",
        "supersede.start.1.after_send",
        "supersede.ReplayStarted",
        "supersede.replay.1.0.after_intent",
        "supersede.replay.1.0.after_send",
        "supersede.complete.1.after_send",
        "supersede.ReplayCompleted",
        "supersede.Verified",
        "supersede.Revalidated",
        "supersede.S7.after_intent",
        "supersede.S7.after_commit",
        "supersede.ProductRelinked",
        "supersede.abandon_original.after_send",
        "supersede.OriginalAbandoned",
    ];
    for window0 in [false, true] {
        for point in points {
            let (mut t, pack, task) = supersede_setup();
            t.crash(
                point,
                window0,
                &["supersede", "start", &pack, "--keep", "1", "--yes"],
            );
            let saga = saga_of(&t, &pack);
            if saga["state"] != "Done" {
                // While pending, the original shows the pending supersession and P' is hidden.
                let listed = t.ok(&["pack", "list"]);
                let row = listed
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["id"] == pack.as_str())
                    .cloned();
                if let Some(row) = row
                    && row["state"] == "OPEN"
                {
                    assert!(
                        row["superseding"]["display"]
                            .as_str()
                            .unwrap_or("")
                            .starts_with("superseding (pending"),
                        "{point}: {row}"
                    );
                }
                let done = t.ok(&["supersede", "resume", saga["saga"].as_str().unwrap()]);
                assert_eq!(done["state"], "Done", "{point} window0={window0}: {done}");
            }
            let saga = saga_of(&t, &pack);
            let replacement = saga["replacement"].as_str().unwrap().to_owned();
            assert_eq!(
                t.ok(&["pack", "show", &pack])["state"],
                "ABANDONED",
                "{point}"
            );
            let effects = t.effects(&replacement);
            assert_eq!(effects.len(), 1, "{point} window0={window0}: replay once");
            assert_eq!(effects[0]["target"]["locator"], "a.toy");
            let listed = t.ok(&["pack", "list"]).to_string();
            assert!(
                listed.contains(&replacement),
                "{point}: the replacement is active"
            );
            let shown = t.ok(&["task", "show", &task]).to_string();
            assert!(
                shown.contains(&replacement),
                "{point}: the task follows: {shown}"
            );
            // Exactly one replacement carries the saga id.
            let creates = t
                .ok(&[
                    "activity",
                    "--source",
                    "openaevc",
                    "--type",
                    "changepack.created",
                ])
                .as_array()
                .map_or(0, Vec::len);
            assert_eq!(
                creates, 2,
                "{point} window0={window0}: P and exactly one P'"
            );
        }
    }
}

#[test]
fn concurrent_changes_stop_the_saga_and_keep_the_original() {
    // A product link changes after revalidation: the S7 compare-and-swap fails.
    let (mut t, pack, _) = supersede_setup();
    t.crash(
        "supersede.Revalidated",
        false,
        &["supersede", "start", &pack, "--keep", "1", "--yes"],
    );
    let intent = t.ok(&["intent", "create", "J"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let other = t.ok(&["task", "create", &intent, "U"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.ok(&["task", "link-pack", &other, &pack]);
    let saga = saga_of(&t, &pack)["saga"].as_str().unwrap().to_owned();
    let err = t.fails(&["supersede", "resume", &saga]);
    assert!(err.contains("SUPERSEDE_CONFLICT"), "{err}");
    assert_eq!(
        t.ok(&["pack", "show", &pack])["state"],
        "OPEN",
        "P untouched"
    );
    let s = saga_of(&t, &pack);
    assert_eq!(s["state"], "Conflicted");
    assert_eq!(
        t.ok(&["pack", "show", s["replacement"].as_str().unwrap()])["state"],
        "ABANDONED",
        "C1"
    );

    // P changes between S6b and S8: abandon refused by the generation check → C1 + C2.
    let (mut t, pack, task) = supersede_setup();
    t.crash(
        "supersede.ProductRelinked",
        false,
        &["supersede", "start", &pack, "--keep", "1", "--yes"],
    );
    bump_generation(&t, &pack);
    let saga = saga_of(&t, &pack)["saga"].as_str().unwrap().to_owned();
    let err = t.fails(&["supersede", "resume", &saga]);
    assert!(err.contains("SUPERSEDE_CONFLICT"), "{err}");
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "OPEN");
    let shown = t.ok(&["task", "show", &task]).to_string();
    assert!(shown.contains(&pack), "C2 undid the relink: {shown}");

    // P' changes during compensation: C1 refuses, both packs are kept, RECOVERY_REQUIRED.
    let (mut t, pack, _) = supersede_setup();
    t.crash(
        "supersede.Revalidated",
        false,
        &["supersede", "start", &pack, "--keep", "1", "--yes"],
    );
    bump_generation(&t, &pack);
    let saga = saga_of(&t, &pack);
    let id = saga["saga"].as_str().unwrap().to_owned();
    t.crash("supersede.Conflict", false, &["supersede", "resume", &id]);
    let replacement = saga_of(&t, &pack)["replacement"]
        .as_str()
        .unwrap()
        .to_owned();
    bump_generation(&t, &replacement);
    let err = t.fails(&["supersede", "resume", &id]);
    assert!(err.contains("RECOVERY_REQUIRED"), "{err}");
    assert_eq!(t.ok(&["pack", "show", &pack])["state"], "OPEN");
    assert_eq!(
        t.ok(&["pack", "show", &replacement])["state"],
        "OPEN",
        "both kept"
    );
}

/// Another OpenAEVC client changes a pack (a work unit bumps its generation).
fn bump_generation(t: &T, pack: &str) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        use openaevc_sdk::{OpenAevcClient as _, TypedClient as _};
        calve_app::authority::use_data_root(&t.env.path().join("d/calve"));
        let project = calve_app::Project::open(t.root()).unwrap();
        let p = project.pack(pack).await.unwrap();
        project
            .client
            .add_work_unit(p.id, p.generation, "org.example.external")
            .await
            .unwrap();
        let _ = project.client.session();
    });
}

/// N42 retention (gc's documented policy, `RETENTION` = 30 days): finished capture sessions
/// (Done, Superseded, Compensated, Abandoned) and finished supersede sagas (Done) are removed
/// past retention; resolved Inbox rows past retention are deleted. Unfinished operations are
/// never collected and still resume afterwards; recent ones and unresolved rows stay; accepted
/// history and every pack stay intact.
#[test]
fn retention_removes_only_finished_or_resolved_records_past_it() {
    let mut t = T::new();
    t.env
        .vars
        .push(("CALVE_EXECUTION_LEASE_MS".into(), "3600000".into()));
    let backdate = |path: std::path::PathBuf, days: u64| {
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .set_modified(
                std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400),
            )
            .unwrap();
    };
    let run = t.root().join(".calve/run");
    let capture_crash = |t: &mut T, pack: &str, name: &str| {
        fs::write(t.root().join(name), name).unwrap();
        t.crash(
            "capture.submit.1.1.after_send",
            false,
            &[
                "pack",
                "capture-tree",
                "--accept-deletions",
                pack,
                "--generation",
                "1",
            ],
        );
        t.session_of(pack)["session"].as_str().unwrap().to_owned()
    };

    // Capture sessions: finished and old, finished and recent, unfinished and old.
    let done_old = t.pack("done-old");
    capture_two(&t, &done_old);
    let s_done_old = t.session_of(&done_old)["session"]
        .as_str()
        .unwrap()
        .to_owned();
    let recent = t.pack("recent");
    let s_recent = capture_crash(&mut t, &recent, "r.toy");
    // The Inbox records an item when it is read; resuming then resolves it.
    t.ok(&["inbox", "list"]);
    t.ok(&["capture", "resume", &s_recent]);
    let open = t.pack("open");
    let s_open = capture_crash(&mut t, &open, "o.toy");

    // Supersede sagas: one finished, one interrupted.
    let sup_done = t.pack("sup-done");
    fs::write(t.root().join("s.toy"), "sss").unwrap();
    t.ok(&[
        "pack",
        "capture-tree",
        "--accept-deletions",
        &sup_done,
        "--generation",
        "1",
    ]);
    t.ok(&["supersede", "start", &sup_done, "--keep", "1", "--yes"]);
    let saga_done = saga_of(&t, &sup_done);
    assert_eq!(saga_done["state"], "Done");
    let sup_open = t.pack("sup-open");
    fs::write(t.root().join("u.toy"), "uuu").unwrap();
    t.ok(&[
        "pack",
        "capture-tree",
        "--accept-deletions",
        &sup_open,
        "--generation",
        "1",
    ]);
    t.crash(
        "supersede.Verified",
        false,
        &["supersede", "start", &sup_open, "--keep", "1", "--yes"],
    );
    let saga_open = saga_of(&t, &sup_open);
    assert_ne!(saga_open["state"], "Done");

    // Inbox: the resolved recovery item of `recent`, backdated; `open`'s stays unresolved.
    let items = t.ok(&["inbox", "list", "--all"]);
    let key = |s: &str| format!("capture:{s}");
    let has = |items: &Value, k: &str| {
        items
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["source_key"] == k)
    };
    assert!(
        has(&items, &key(&s_recent)) && has(&items, &key(&s_open)),
        "{items}"
    );
    let db = rusqlite::Connection::open(t.root().join(".calve/product.sqlite3")).unwrap();
    let old = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 31 * 86_400;
    assert_eq!(
        db.execute(
            "UPDATE inbox_items SET resolved_at = ?1 WHERE source_key = ?2 AND resolved_at IS NOT NULL",
            rusqlite::params![old as i64, key(&s_recent)],
        )
        .unwrap(),
        1
    );
    drop(db);

    backdate(run.join(format!("capture/{s_done_old}.journal")), 31);
    backdate(run.join(format!("capture/{s_open}.journal")), 365);
    backdate(
        run.join(format!(
            "supersede/{}.journal",
            saga_done["saga"].as_str().unwrap()
        )),
        31,
    );
    backdate(
        run.join(format!(
            "supersede/{}.journal",
            saga_open["saga"].as_str().unwrap()
        )),
        365,
    );
    let effects_before = (
        t.effects(&done_old),
        t.effects(saga_done["replacement"].as_str().unwrap()),
    );
    let plan = t.ok(&["maintenance", "gc", "--dry-run", "--grace-secs", "0"]);
    let count = |class: &str| {
        plan["classes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["class"] == class)
            .unwrap_or_else(|| panic!("{class}: {plan}"))["count"]
            .clone()
    };
    // Only the old finished session's files (journal and spool; chunks only for large files).
    let capture_items = plan["classes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["class"] == "finished_capture_sessions")
        .unwrap()["items"]
        .clone();
    assert!(
        count("finished_capture_sessions").as_u64().unwrap() >= 1,
        "{plan}"
    );
    assert!(
        capture_items
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i.to_string().contains(&s_done_old)),
        "{plan}"
    );
    assert_eq!(count("finished_supersede_sagas"), 1, "{plan}");
    assert_eq!(count("resolved_inbox_rows"), 1, "{plan}");
    let done = t.ok(&["maintenance", "gc", "--grace-secs", "0", "--yes"]);

    assert!(
        !run.join(format!("capture/{s_done_old}.journal")).exists(),
        "{done}"
    );
    assert!(
        run.join(format!("capture/{s_recent}.journal")).exists(),
        "recent: {done}"
    );
    assert!(
        run.join(format!("capture/{s_open}.journal")).exists(),
        "unfinished: {done}"
    );
    let sagas = |s: &Value| run.join(format!("supersede/{}.journal", s["saga"].as_str().unwrap()));
    assert!(!sagas(&saga_done).exists(), "{done}");
    assert!(sagas(&saga_open).exists(), "unfinished saga: {done}");
    let items = t.ok(&["inbox", "list", "--all"]);
    assert!(
        !has(&items, &key(&s_recent)),
        "resolved past retention: {items}"
    );
    assert!(has(&items, &key(&s_open)), "unresolved stays: {items}");

    // Accepted history and every pack are intact; unfinished work resumes after the cleanup.
    assert_eq!(t.ok(&["maintenance", "check"])["ok"], true);
    assert_eq!(t.effects(&done_old), effects_before.0);
    assert_eq!(t.ok(&["pack", "show", &sup_done])["state"], "ABANDONED");
    let replacement = saga_done["replacement"].as_str().unwrap();
    assert_eq!(t.effects(replacement), effects_before.1);
    t.ok(&["capture", "resume", &s_open]);
    assert_eq!(t.session_of(&open)["state"], "Done");
    let resumed = t.ok(&["supersede", "resume", saga_open["saga"].as_str().unwrap()]);
    assert_eq!(saga_of(&t, &sup_open)["state"], "Done", "{resumed}");
}
