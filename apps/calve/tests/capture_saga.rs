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
    t.ok(&["pack", "capture-tree", pack, "--generation", "1"]);
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
            let pack = t.pack("P");
            fs::write(t.root().join("a.toy"), "aaa").unwrap();
            fs::write(t.root().join("b.toy"), "bbb").unwrap();
            t.crash(
                point,
                window0,
                &["pack", "capture-tree", &pack, "--generation", "1"],
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
        &["pack", "capture-tree", &pack, "--generation", "1"],
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
        &["pack", "capture-tree", &pack, "--generation", "1"],
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
