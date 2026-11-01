use std::fs;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use calve_testkit::Env;
use serde_json::Value;

fn calve_env(env: &Env, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_calve"));
    command
        .env("XDG_DATA_HOME", env.path().join("d"))
        .env_remove("XDG_RUNTIME_DIR")
        .env("XDG_CONFIG_HOME", env.path().join("c"))
        .env("CALVE_EXECUTION_LEASE_MS", "5000")
        .arg("--json")
        .args(args);
    command
}

fn daemon_ok(env: &Env, args: &[&str]) -> Value {
    let output = calve_env(env, args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    calve_testkit::json_data(&output.stdout)
}

/// Scenario K: a daemon crash mid-execution is reconciled by OpenAEVC as LOST after restart;
/// nothing is reported as succeeded.
#[test]
fn crash_during_execution_is_reported_lost() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    // A file domain, so the execution really runs (without one it fails right after the lease
    // grant; that failure is now recorded, where it used to sit RUNNING until LOST).
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
    let config = env.ok(&["--project", p, "config", "edit-path", "--scope", "project"]);
    fs::write(
        config["path"].as_str().unwrap(),
        "format_version = 1\n[harnesses.slow]\nprovider = \"shell\"\nmode = \"check\"\ncommand = [\"-c\", \"sleep 8\"]\n",
    )
    .unwrap();
    env.ok(&["--project", p, "config", "approve"]);
    let pack = env.ok(&["--project", p, "pack", "create", "slow"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    daemon_ok(&env, &["daemon", "start"]);
    let mut run = calve_env(
        &env,
        &[
            "--project",
            p,
            "execution",
            "start",
            &pack,
            "--harness",
            "slow",
            "--generation",
            "1",
        ],
    )
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
    let started = Instant::now();
    let execution = loop {
        let list = daemon_ok(
            &env,
            &["--project", p, "execution", "list", "--pack", &pack],
        );
        if let Some(e) = list
            .as_array()
            .and_then(|l| l.iter().find(|e| e["state"] == "RUNNING"))
        {
            break e["id"].as_str().unwrap().to_owned();
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "execution never started: {list}"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let pid = fs::read_to_string(env.path().join("d/calve/daemon.pid")).unwrap();
    assert!(
        Command::new("kill")
            .args(["-KILL", pid.trim()])
            .status()
            .unwrap()
            .success()
    );
    let _ = run.wait();
    // Restart and let the lease lapse; OpenAEVC expires it on the next namespace access.
    daemon_ok(&env, &["daemon", "start"]);
    std::thread::sleep(Duration::from_secs(7));
    let shown = daemon_ok(&env, &["--project", p, "execution", "show", &execution]);
    assert_eq!(shown["state"], "LOST", "{shown}");
    let executions = daemon_ok(
        &env,
        &["--project", p, "execution", "list", "--pack", &pack],
    );
    assert!(
        !executions
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["state"] == "SUCCEEDED")
    );
    let inbox = daemon_ok(&env, &["--project", p, "inbox", "list"]);
    assert!(
        inbox
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["summary"] == "Execution LOST"),
        "{inbox}"
    );
    daemon_ok(&env, &["daemon", "stop"]);
}

/// Scenario L: an install interrupted after staging leaves the active package untouched, and
/// recovery removes the leftovers.
#[test]
fn interrupted_extension_install_is_recoverable() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    env.trust_fixture();
    // The install crashes right after its first durable journal record (I0).
    let crashed = calve_env(
        &env,
        &[
            "extension",
            "install",
            "org.example.toy",
            "--acknowledge-native",
        ],
    )
    .env("CALVE_FAULT", "append.after_fsync")
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .unwrap();
    assert!(!crashed.success());
    assert_eq!(
        env.ok(&["extension", "list", "--installed"]),
        serde_json::json!([])
    );
    let plan = env.ok(&["--project", p, "recover", "plan"]);
    assert!(
        plan["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "reconcile_install_journals"),
        "{plan}"
    );
    env.ok(&["--project", p, "recover", "apply", "--yes"]);
    let plan = env.ok(&["--project", p, "recover", "plan"]);
    assert_eq!(plan["actions"], serde_json::json!([]), "{plan}");
    // The interrupted install left nothing behind; a fresh one succeeds and runs.
    env.enable_toy(&root);
    assert_eq!(
        env.ok(&["--project", p, "extension", "health"])[0]["healthy"],
        true
    );
}
