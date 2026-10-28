//! M4 outcomes as typed errors (requirement 4): each is produced for real, then checked in both
//! representations: the `--json` envelope on stderr (code, exit_code equal to the process exit
//! status, typed detail) and the human line `calve: CODE: message` with the same exit status.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use calve_testkit::Env;
use serde_json::Value;

struct T {
    env: Env,
    p: String,
}

struct Failure {
    status: i32,
    error: Value,
    human: String,
}

impl T {
    fn new() -> Self {
        let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
        let root = env.path().join("project");
        let p = root.to_str().unwrap().to_owned();
        env.ok(&["init", &p]);
        env.enable_toy(&root);
        T { env, p }
    }
    fn root(&self) -> PathBuf {
        PathBuf::from(&self.p)
    }
    fn args<'a>(&'a self, a: &[&'a str]) -> Vec<&'a str> {
        [&["--project", self.p.as_str()][..], a].concat()
    }
    fn ok(&self, a: &[&str]) -> Value {
        self.env.ok(&self.args(a))
    }
    fn cmd(&self, json: bool, extra: &[(&str, &str)], a: &[&str]) -> std::process::Output {
        let mut c = Command::new(&self.env.calve);
        c.env("XDG_DATA_HOME", self.env.path().join("d"))
            .env("XDG_CONFIG_HOME", self.env.path().join("c"))
            .envs(self.env.vars.iter().map(|(k, v)| (k, v)))
            .envs(extra.iter().copied())
            .arg("--no-daemon-start");
        if json {
            c.arg("--json");
        }
        c.args(self.args(a)).output().unwrap()
    }
    /// Runs `a` twice (JSON, then human), each expected to fail with `code`; `setup` restores
    /// the failing situation before the second run when the first one changed it.
    fn fails(&self, code: &str, extra: &[(&str, &str)], a: &[&str], setup: &dyn Fn()) -> Failure {
        setup();
        let j = self.cmd(true, extra, a);
        assert!(!j.status.success(), "{a:?} succeeded");
        let env: Value = serde_json::from_slice(&j.stderr).unwrap_or_else(|e| {
            panic!(
                "{a:?}: stderr is not the envelope ({e}): {}",
                String::from_utf8_lossy(&j.stderr)
            )
        });
        let error = env["error"].clone();
        assert_eq!(error["code"], code, "{a:?}: {error}");
        let status = j.status.code().unwrap();
        assert_eq!(error["exit_code"], status, "{a:?}");
        assert_eq!(
            status,
            calve_api::errors::exit_code(code),
            "{code}: documented exit code"
        );
        assert!(error["message"].as_str().is_some_and(|m| !m.is_empty()));
        setup();
        let h = self.cmd(false, extra, a);
        let human = String::from_utf8_lossy(&h.stderr).into_owned();
        assert_eq!(h.status.code(), Some(status), "{a:?}: human exit status");
        assert!(
            human.starts_with(&format!("calve: {code}: ")),
            "{a:?}: {human}"
        );
        assert!(
            !human.contains("{\""),
            "human output carries no raw JSON: {human}"
        );
        Failure {
            status,
            error,
            human,
        }
    }
}

fn nothing() {}

#[test]
fn m4_outcomes_are_typed_in_json_and_human_output() {
    let t = T::new();
    let root = t.root();
    let pack = |title: &str| {
        t.ok(&["pack", "create", title])["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    // CONFIRMATION_REQUIRED: capture-tree would record the deletion of an accepted file.
    fs::write(root.join("a.txt"), "a").unwrap();
    let p0 = pack("P0");
    t.ok(&["pack", "capture", &p0, "a.txt", "--generation", "1"]);
    let g0 = t.ok(&["pack", "show", &p0])["generation"].to_string();
    for step in ["seal", "qualify", "promote"] {
        t.ok(&["pack", step, &p0, "--generation", &g0]);
    }
    let p = pack("P");
    t.ok(&[
        "pack",
        "capture-tree",
        "--accept-deletions",
        &p,
        ".",
        "--generation",
        "1",
    ]);
    let gp = t.ok(&["pack", "show", &p])["generation"].to_string();
    fs::remove_file(root.join("a.txt")).unwrap();
    let f = t.fails(
        "CONFIRMATION_REQUIRED",
        &[],
        &["pack", "capture-tree", &p, ".", "--generation", &gp],
        &nothing,
    );
    assert!(
        f.error["detail"].to_string().contains("a.txt"),
        "{}",
        f.error
    );
    fs::write(root.join("a.txt"), "a").unwrap();

    // FILE_TOO_LARGE: over the largest chunked file (sparse).
    let big = root.join("huge.bin");
    fs::File::create(&big)
        .unwrap()
        .set_len(calve_integration_contract::content::FILE_MAX + 1)
        .unwrap();
    let f = t.fails(
        "FILE_TOO_LARGE",
        &[],
        &[
            "pack",
            "capture-tree",
            "--accept-deletions",
            &p,
            ".",
            "--generation",
            &gp,
        ],
        &nothing,
    );
    assert_eq!(f.error["detail"]["path"], "huge.bin");
    assert_eq!(
        f.error["detail"]["limit"],
        calve_integration_contract::content::FILE_MAX
    );
    fs::remove_file(&big).unwrap();

    // LIMIT_EXCEEDED: more bytes than one capture-tree batch takes (sparse files, each under
    // the per-file limit).
    let many = root.join("many");
    fs::create_dir(&many).unwrap();
    for i in 0..3 {
        fs::File::create(many.join(format!("{i}.bin")))
            .unwrap()
            .set_len(200 << 20)
            .unwrap();
    }
    t.fails(
        "LIMIT_EXCEEDED",
        &[],
        &[
            "pack",
            "capture-tree",
            "--accept-deletions",
            &p,
            "many",
            "--generation",
            &gp,
        ],
        &nothing,
    );
    fs::remove_dir_all(&many).unwrap();

    // CAPTURE_INCOMPLETE, then CAPTURE_DIVERGED: an interrupted session blocks sealing; a capture
    // by someone else in between makes its resume diverge.
    let q = pack("Q");
    fs::write(root.join("b.txt"), "b").unwrap();
    let crash = t.cmd(
        true,
        &[("CALVE_FAULT", "capture.start.1.after_intent")],
        &[
            "pack",
            "capture-tree",
            "--accept-deletions",
            &q,
            ".",
            "--generation",
            "1",
        ],
    );
    assert!(!crash.status.success());
    let g = t.ok(&["pack", "show", &q])["generation"].to_string();
    let f = t.fails(
        "CAPTURE_INCOMPLETE",
        &[],
        &["pack", "seal", &q, "--generation", &g],
        &nothing,
    );
    assert!(f.human.contains("capture"), "{}", f.human);
    fs::write(root.join("c.txt"), "c").unwrap();
    t.ok(&["pack", "capture", &q, "c.txt", "--generation", &g]);
    let session = t
        .ok(&["capture", "list"])
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["pack"] == q.as_str() && s["state"] != "Done")
        .unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();
    let f = t.fails(
        "CAPTURE_DIVERGED",
        &[],
        &["capture", "resume", &session],
        &nothing,
    );
    assert_eq!(f.error["detail"]["session"], session.as_str());
    assert_eq!(f.error["detail"]["paths"], serde_json::json!(["c.txt"]));
    assert_eq!(f.status, 3);

    // SUPERSEDE_CONFLICT: a second supersession of a pack whose first one is pending.
    let s = pack("S");
    fs::write(root.join("s1.txt"), "1").unwrap();
    fs::write(root.join("s2.txt"), "2").unwrap();
    t.ok(&[
        "pack",
        "capture-tree",
        "--accept-deletions",
        &s,
        ".",
        "--generation",
        "1",
    ]);
    let crash = t.cmd(
        true,
        &[("CALVE_FAULT", "supersede.ReplayStarted")],
        &["supersede", "start", &s, "--keep", "1", "--yes"],
    );
    assert!(!crash.status.success());
    let f = t.fails(
        "SUPERSEDE_CONFLICT",
        &[],
        &["supersede", "start", &s, "--keep", "1", "--yes"],
        &nothing,
    );
    assert!(f.error["detail"]["saga"].is_string(), "{}", f.error);

    // MATERIALIZE_CONFLICT(unsafe_fs): no atomic primitives, replacing refused.
    let m = pack("M");
    fs::write(root.join("m.txt"), "accepted").unwrap();
    t.ok(&["pack", "capture", &m, "m.txt", "--generation", "1"]);
    fs::write(root.join("m.txt"), "local").unwrap();
    let f = t.fails(
        "MATERIALIZE_CONFLICT",
        &[("CALVE_FS_PRIMITIVES", "fallback")],
        &[
            "resource",
            "materialize",
            "m.txt",
            "--from",
            &m,
            "--apply",
            "--discard",
        ],
        &nothing,
    );
    assert_eq!(f.error["detail"]["reason"], "unsafe_fs");

    // CONTENT_CORRUPT: a chunk blob damaged on disk.
    let c = pack("C");
    let bytes: Vec<u8> = (0..(2u32 << 20)).map(|i| (i % 251) as u8).collect();
    fs::write(root.join("big.bin"), &bytes).unwrap();
    t.ok(&["pack", "capture", &c, "big.bin", "--generation", "1"]);
    let effect = t.ok(&["pack", "show", &c])["candidate_effects"][0].clone();
    let blob = effect["payload"]["chunks"][0]["blob_digest"]
        .as_str()
        .unwrap()
        .trim_start_matches("sha256:")
        .to_owned();
    let object = root
        .join(".calve/openaevc/objects/sha256")
        .join(&blob[..2])
        .join(&blob);
    let original = fs::read(&object).unwrap();
    let mut damaged = original.clone();
    let mid = damaged.len() / 2;
    damaged[mid] ^= 0xff;
    fs::write(&object, &damaged).unwrap();
    fs::remove_file(root.join("big.bin")).unwrap();
    t.fails(
        "CONTENT_CORRUPT",
        &[],
        &[
            "resource",
            "materialize",
            "big.bin",
            "--from",
            &c,
            "--apply",
        ],
        &nothing,
    );
    assert!(!root.join("big.bin").exists(), "nothing partial");
    fs::write(&object, &original).unwrap();

    // RECOVERY_REQUIRED: a damaged operational journal.
    let journal = fs::read_dir(root.join(".calve/run/capture"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "journal"))
        .unwrap();
    let kept = fs::read(&journal).unwrap();
    let mut bad = kept.clone();
    let at = bad.len() / 2;
    bad[at] = b'#';
    fs::write(&journal, &bad).unwrap();
    t.fails("RECOVERY_REQUIRED", &[], &["capture", "list"], &nothing);
    fs::write(&journal, &kept).unwrap();

    // MIGRATION_REQUIRED: a read on an older product schema.
    let db = root.join(".calve/product.sqlite3");
    let downgrade = || {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "DROP TRIGGER IF EXISTS pack_link_added; DROP TRIGGER IF EXISTS pack_link_removed;
             DROP TRIGGER IF EXISTS pack_link_moved; DROP TRIGGER IF EXISTS pack_metadata_changed;
             DROP TABLE IF EXISTS pack_commitments; DELETE FROM schema_migrations WHERE version>=15;
             PRAGMA user_version=14;",
        )
        .unwrap();
    };
    downgrade();
    t.fails("MIGRATION_REQUIRED", &[], &["intent", "list"], &nothing);
    t.ok(&["intent", "create", "migrates"]);
    adopt_errors(&t, &root);
}

/// CLOSURE_UNCLASSIFIED: a transfer whose refs document is unavailable fails closed.
fn adopt_errors(t: &T, root: &Path) {
    {
        fs::write(root.join("x.txt"), "x").unwrap();
        let id = t.ok(&["pack", "create", "X"])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        t.ok(&["pack", "capture", &id, "x.txt", "--generation", "1"]);
        let g = t.ok(&["pack", "show", &id])["generation"].to_string();
        for s in ["seal", "qualify"] {
            t.ok(&["pack", s, &id, "--generation", &g]);
        }
        t.ok(&["pack", "promote", &id, "--generation", &g]);
    }
    let copy = t.env.path().join("copy");
    calve_testkit::copy_tree(root, &copy);
    let refs = t.env.path().join("d/calve/refs");
    let moved = t.env.path().join("d/calve/refs.away");
    fs::rename(&refs, &moved).unwrap();
    let c = copy.to_str().unwrap();
    let j = Command::new(&t.env.calve)
        .env("XDG_DATA_HOME", t.env.path().join("d"))
        .env("XDG_CONFIG_HOME", t.env.path().join("c"))
        .envs(t.env.vars.iter().map(|(k, v)| (k, v)))
        .args(["--json", "--no-daemon-start", "project", "adopt-copy", c])
        .output()
        .unwrap();
    let env: Value = serde_json::from_slice(&j.stderr).unwrap();
    assert_eq!(env["error"]["code"], "CLOSURE_UNCLASSIFIED", "{env}");
    assert_eq!(
        j.status.code(),
        Some(calve_api::errors::exit_code("CLOSURE_UNCLASSIFIED"))
    );
    let h = Command::new(&t.env.calve)
        .env("XDG_DATA_HOME", t.env.path().join("d"))
        .env("XDG_CONFIG_HOME", t.env.path().join("c"))
        .args(["--no-daemon-start", "project", "adopt-copy", c])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&h.stderr).starts_with("calve: CLOSURE_UNCLASSIFIED: "));
    assert!(copy.join(".calve").is_dir(), "the copy is untouched");
    fs::rename(&moved, &refs).unwrap();
}

/// P19 and P18: a busy Project names the writer that holds it (pid, session, start) in JSON and
/// human output; product events record the acting principal.
#[test]
fn the_lock_owner_and_the_actor_are_recorded() {
    let t = T::new();
    t.env.ok(&[
        "provider",
        "add",
        "shell",
        "--kind",
        "local-process",
        "--executable",
        "sh",
    ]);
    let config = t.ok(&["config", "edit-path", "--scope", "project"]);
    fs::write(
        config["path"].as_str().unwrap(),
        "format_version = 1\n[harnesses.slow]\nprovider = \"shell\"\nmode = \"check\"\ncommand = [\"-c\", \"sleep 6\"]\n",
    )
    .unwrap();
    let pack = t.ok(&["pack", "create", "busy"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut child = Command::new(&t.env.calve)
        .env("XDG_DATA_HOME", t.env.path().join("d"))
        .env("XDG_CONFIG_HOME", t.env.path().join("c"))
        .envs(t.env.vars.iter().map(|(k, v)| (k, v)))
        .args(t.args(&[
            "--no-daemon-start",
            "--direct",
            "execution",
            "start",
            &pack,
            "--harness",
            "slow",
            "--generation",
            "1",
        ]))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let lock = t.root().join(".calve/writer.lock");
    let started = std::time::Instant::now();
    while !fs::read_to_string(&lock).is_ok_and(|s| s.contains(&format!("\"pid\":{}", child.id()))) {
        assert!(
            started.elapsed().as_secs() < 30,
            "the child never took the writer lock"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let f = t.fails(
        "PROJECT_LOCKED",
        &[],
        &["--direct", "intent", "create", "blocked"],
        &nothing,
    );
    assert_eq!(f.error["detail"]["owner"]["pid"], child.id(), "{}", f.error);
    assert!(f.error["detail"]["owner"]["session"].is_string());
    assert!(
        f.human.contains(&format!("pid {}", child.id())),
        "{}",
        f.human
    );
    let _ = child.wait();
    // The acting principal of product events.
    let principal = t.ok(&["status"])["project"]["created_by"]
        .as_str()
        .unwrap()
        .to_owned();
    t.ok(&["intent", "create", "after"]);
    let activity = t.ok(&["activity"]);
    let product: Vec<&Value> = activity
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["source"] == "calve" && e["kind"] == "intent.created")
        .collect();
    assert!(!product.is_empty(), "{activity}");
    assert!(
        product.iter().all(|e| e["actor"] == principal.as_str()),
        "{product:?}"
    );
}
