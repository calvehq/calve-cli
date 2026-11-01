//! Overlapping executions in one Project, under a real daemon: what may run together, what
//! collides, and what a run leaves behind when the daemon dies under it.
#![cfg(unix)]

use std::fs;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use calve_testkit::Env;
use serde_json::Value;

struct T {
    env: Env,
    p: String,
    root: std::path::PathBuf,
}

impl T {
    fn new(harnesses: &str) -> Self {
        let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
        let root = env.path().join("project");
        let p = root.to_str().unwrap().to_owned();
        env.ok(&["init", &p]);
        env.enable_toy(&root);
        env.ok(&[
            "provider",
            "add",
            "shell",
            "--kind",
            "local-process",
            "--executable",
            "sh",
        ]);
        fs::write(root.join("toy.toml"), "").unwrap();
        fs::write(
            root.join(".calve/config.toml"),
            format!("format_version = 1\n{harnesses}"),
        )
        .unwrap();
        let t = T { env, p, root };
        t.ok(&["config", "approve"]);
        t
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
    fn pack(&self, title: &str) -> String {
        self.ok(&["pack", "create", title])["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    /// `execution start` as its own process; the worker outlives this call.
    fn start(&self, pack: &str, harness: &str) -> Child {
        Command::new(env!("CARGO_BIN_EXE_calve"))
            .env("XDG_DATA_HOME", self.env.path().join("d"))
            .env("XDG_CONFIG_HOME", self.env.path().join("c"))
            .envs(self.env.vars.iter().map(|(k, v)| (k, v)))
            .args(self.args(&["--json", "--no-daemon-start", "execution", "start", pack]))
            .args(["--harness", harness, "--generation", "1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
    fn running(&self, pack: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let list = self.ok(&["execution", "list", "--pack", pack]);
            if let Some(e) = list
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["state"] == "RUNNING")
            {
                return e["id"].as_str().unwrap().to_owned();
            }
            assert!(Instant::now() < deadline, "no RUNNING execution: {list}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

const HARNESSES: &str = r#"
[harnesses.a]
provider = "shell"
mode = "change"
paths = ["a"]
command = ["-c", "mkdir -p a; echo live-line; echo a > a/f.toy; touch a/ready; sleep 60"]
[harnesses.a2]
provider = "shell"
mode = "change"
paths = ["a/inner"]
command = ["-c", "true"]
[harnesses.d]
provider = "shell"
mode = "change"
paths = ["d"]
command = ["-c", "mkdir -p d; echo d > d/f.toy"]
[harnesses.stray]
provider = "shell"
mode = "change"
paths = ["d"]
command = ["-c", "echo x > outside.toy"]
"#;

#[test]
fn runs_overlap_unless_they_really_collide() {
    let t = T::new(HARNESSES);
    let (pa, pa2, pd, ps) = (t.pack("A"), t.pack("A2"), t.pack("D"), t.pack("S"));
    t.env.ok(&["daemon", "start"]);
    let mut a = t.start(&pa, "a");
    let exe = t.running(&pa);

    // Work on other things goes on during a run.
    t.ok(&["intent", "create", "unrelated"]);
    assert!(t.pack("unrelated").starts_with("cpk_"));

    // Output is readable while the worker runs, and `next` continues from there.
    let deadline = Instant::now() + Duration::from_secs(30);
    let logs = loop {
        let logs = t.ok(&["execution", "logs", &exe]);
        if logs["next"].as_u64().unwrap_or(0) > 0 || Instant::now() > deadline {
            break logs;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(logs["output"][0]["text"], "live-line", "{logs}");
    let rest = t.ok(&["execution", "logs", &exe, "--after", "1"]);
    assert_eq!(rest["output"].as_array().unwrap().len(), 0, "{rest}");

    // Same pack, and paths inside the running scope, collide.
    let again = t.fails(&[
        "execution",
        "start",
        &pa,
        "--harness",
        "d",
        "--generation",
        "2",
    ]);
    assert!(
        again.contains("PROJECT_LOCKED") || again.contains("generation"),
        "{again}"
    );
    let nested = t.fails(&[
        "execution",
        "start",
        &pa2,
        "--harness",
        "a2",
        "--generation",
        "1",
    ]);
    assert!(nested.contains(&exe), "{nested}");
    // Commands that touch those paths collide too; others do not.
    while !t.root.join("a/ready").exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    let capture = t.fails(&["pack", "capture", &pd, "a/f.toy", "--generation", "1"]);
    assert!(capture.contains(&exe), "{capture}");
    let baseline = t.fails(&["baseline", "materialize", "nothing", "--apply"]);
    assert!(
        baseline.contains(&exe) || baseline.contains("NOT_FOUND"),
        "{baseline}"
    );

    // A disjoint scope runs alongside it, and is not blamed for the other's files.
    let d = t.ok(&[
        "execution",
        "start",
        &pd,
        "--harness",
        "d",
        "--generation",
        "1",
    ]);
    assert_eq!(d["state"], "SUCCEEDED", "{d}");
    assert_eq!(d["effects"].as_array().unwrap().len(), 1, "{d}");
    // A real stray is still a failure, with a run going on next to it.
    let s = t.ok(&[
        "execution",
        "start",
        &ps,
        "--harness",
        "stray",
        "--generation",
        "1",
    ]);
    assert_eq!(s["state"], "FAILED", "{s}");
    assert!(s["reason"].as_str().unwrap().contains("outside"), "{s}");

    t.ok(&["execution", "cancel", &exe, "--reason", "done"]);
    assert!(a.wait().unwrap().success());
    // Its claim is gone: the same paths can run now.
    let pa3 = t.pack("A3");
    let free = t.ok(&[
        "execution",
        "start",
        &pa3,
        "--harness",
        "a2",
        "--generation",
        "1",
    ]);
    assert_ne!(free["state"], "RUNNING", "{free}");
    t.env.ok(&["daemon", "stop"]);
}

/// A daemon killed under a run: the output survives, the execution ends LOST, and the claim it
/// left does not block the paths forever.
#[test]
fn a_dead_daemon_leaves_output_and_no_lasting_claim() {
    let mut t = T::new(HARNESSES);
    t.env
        .vars
        .push(("CALVE_EXECUTION_LEASE_MS".into(), "5000".into()));
    let pa = t.pack("A");
    let daemon = t.env.ok(&["daemon", "start"])["pid"].as_u64().unwrap();
    let mut client = t.start(&pa, "a");
    let exe = t.running(&pa);
    let deadline = Instant::now() + Duration::from_secs(30);
    while t.ok(&["execution", "logs", &exe])["next"]
        .as_u64()
        .unwrap_or(0)
        == 0
    {
        assert!(Instant::now() < deadline, "no output");
        std::thread::sleep(Duration::from_millis(100));
    }
    Command::new("kill")
        .args(["-9", &daemon.to_string()])
        .status()
        .unwrap();
    let _ = client.wait();
    t.env.ok(&["daemon", "start"]);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if t.ok(&["execution", "show", &exe])["state"] == "LOST" {
            break;
        }
        assert!(Instant::now() < deadline, "never LOST");
        std::thread::sleep(Duration::from_millis(200));
    }
    let logs = t.ok(&["execution", "logs", &exe]);
    assert_eq!(logs["output"][0]["text"], "live-line", "{logs}");
    let next = t.pack("next");
    let done = t.ok(&[
        "execution",
        "start",
        &next,
        "--harness",
        "a2",
        "--generation",
        "1",
    ]);
    assert_eq!(done["state"], "SUCCEEDED", "{done}");
    t.env.ok(&["daemon", "stop"]);
}
