//! Lease experiments (M5 E; the M4 120 s anomalies). Explicit, deterministic versions of the
//! suspected causes with a short lease ([`LEASE_MS`]):
//! - heartbeat: a worker running longer than the lease keeps it renewed;
//! - expiry: a step that blocks longer than the lease without renewing it (debug hook
//!   `CALVE_TEST_PAUSE=execution.after_worker=<ms>`, standing in for a slow whole-Project
//!   digest on a loaded machine) must not lose the execution.
//!
//! The journal's lease-renewal events give the measured gaps.

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// 60 s (renewed every 15 s): a worker or blocked step of 75 s outlives it, while renewal
/// stalls up to 45 s do not (13–14 s seen with the host overloaded; 5 s and then 20 s proved
/// too tight under the full suite).
const LEASE_MS: &str = "60000";

fn calve(data: &Path, vars: &[(&str, &str)], args: &[&str]) -> (bool, Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_calve"))
        .env("XDG_DATA_HOME", data.join("d"))
        .env("XDG_CONFIG_HOME", data.join("c"))
        .env("CALVE_EXECUTION_LEASE_MS", LEASE_MS)
        .env("CALVE_TEST_KEEPER_LOG", "1")
        .envs(vars.iter().copied())
        .args(["--json", "--no-daemon-start"])
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        calve_testkit::json_data(&output.stdout),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn ok(data: &Path, args: &[&str]) -> Value {
    let (success, value, stderr) = calve(data, &[], args);
    assert!(success, "{args:?}: {stderr}");
    value
}

struct T {
    _temp: tempfile::TempDir,
    _catalog: Option<calve_testkit::ToyCatalog>,
    data: std::path::PathBuf,
    p: String,
}

/// `file_domain`: enable the toy file extension (a whole-Project digest needs one).
fn setup(file_domain: bool) -> T {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().to_path_buf();
    let p = data.join("project").to_str().unwrap().to_owned();
    ok(&data, &["init", &p]);
    let catalog = file_domain.then(calve_testkit::ToyCatalog::new);
    if let Some(catalog) = &catalog {
        let add: Vec<String> = catalog.add_args();
        ok(&data, &add.iter().map(String::as_str).collect::<Vec<_>>());
        ok(
            &data,
            &[
                &["--project", p.as_str()][..],
                &calve_testkit::ENABLE_TOY[..],
            ]
            .concat(),
        );
    }
    ok(
        &data,
        &[
            "provider",
            "add",
            "shell",
            "--kind",
            "local-process",
            "--executable",
            "sh",
        ],
    );
    let config = ok(
        &data,
        &["--project", &p, "config", "edit-path", "--scope", "project"],
    );
    fs::write(
        config["path"].as_str().unwrap(),
        r#"format_version = 1
[harnesses.long]
provider = "shell"
mode = "check"
timeout_ms = 240000
command = ["-c", "sleep 75"]

[harnesses.quick]
provider = "shell"
mode = "check"
command = ["-c", "true"]
"#,
    )
    .unwrap();
    T {
        _temp: temp,
        _catalog: catalog,
        data,
        p,
    }
}

/// Starts `harness` on a new pack; returns (state, execution id, lease event gaps in ms).
fn run(t: &T, harness: &str, vars: &[(&str, &str)]) -> (String, String, Vec<i64>) {
    let pack = ok(&t.data, &["--project", &t.p, "pack", "create", harness])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let started = std::time::Instant::now();
    let (success, v, stderr) = calve(
        &t.data,
        vars,
        &[
            "--project",
            &t.p,
            "execution",
            "start",
            &pack,
            "--harness",
            harness,
            "--generation",
            "1",
        ],
    );
    println!(
        "start {harness}: success={success} in {:?} {v} {}",
        started.elapsed(),
        stderr
            .lines()
            .find(|l| l.contains("\"message\""))
            .unwrap_or("")
    );
    let execution = v["execution"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| {
            // A lost execution may surface as an error; find it in the list.
            ok(&t.data, &["--project", &t.p, "execution", "list"])
                .as_array()
                .and_then(|a| a.last().cloned())
                .and_then(|e| e["id"].as_str().map(str::to_owned))
                .unwrap_or_else(|| panic!("no execution: {stderr}"))
        });
    let shown = ok(
        &t.data,
        &["--project", &t.p, "execution", "show", &execution],
    );
    let record = shown.get("execution").unwrap_or(&shown);
    let state = record["state"].as_str().unwrap_or_default().to_owned();
    let logs = ok(
        &t.data,
        &["--project", &t.p, "execution", "logs", &execution],
    );
    // Lease renewals: granted at `execution.starting`, renewed by each `execution.heartbeat`;
    // the gap between consecutive ones is what must stay under the lease.
    let events: Vec<(String, i64)> = logs["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let at = e["timestamp"].as_str()?.parse::<jiff::Timestamp>().ok()?;
            Some((e["kind"].as_str()?.to_owned(), at.as_millisecond()))
        })
        .collect();
    let renewals: Vec<i64> = events
        .iter()
        .filter(|(k, _)| k == "execution.starting" || k == "execution.heartbeat")
        .map(|(_, at)| *at)
        .collect();
    let gaps = renewals.windows(2).map(|w| w[1] - w[0]).collect();
    let t0 = events.first().map_or(0, |e| e.1);
    let kinds: Vec<String> = events
        .iter()
        .map(|(k, at)| format!("{k}@+{}ms", at - t0))
        .collect();
    println!("{harness} {vars:?}: {state}; renewal gaps (ms) {gaps:?}; events {kinds:?}");
    for line in stderr.lines().filter(|l| l.starts_with("lease keeper:")) {
        println!("  {line}");
    }
    (state, execution, gaps)
}

#[test]
fn a_worker_longer_than_the_lease_keeps_it() {
    let t = setup(true);
    let (state, _, gaps) = run(&t, "long", &[]);
    assert_eq!(state, "SUCCEEDED");
    assert!(gaps.iter().all(|g| *g < 60_000), "{gaps:?}");
}

#[test]
fn a_step_blocked_longer_than_the_lease_does_not_lose_the_execution() {
    let t = setup(true);
    let (state, _, _) = run(
        &t,
        "quick",
        &[("CALVE_TEST_PAUSE", "execution.after_worker=75000")],
    );
    assert_eq!(state, "SUCCEEDED");
}

/// An error after the lease was granted (here: no file domain for the whole-Project digest)
/// records a failure with its reason; it never leaves the execution RUNNING to be reported
/// LOST when the lease expires.
#[test]
fn an_error_after_the_lease_is_granted_fails_the_execution() {
    let t = setup(false);
    let (state, execution, _) = run(&t, "quick", &[]);
    assert_eq!(state, "FAILED", "{execution}");
    std::thread::sleep(std::time::Duration::from_secs(62));
    let shown = ok(
        &t.data,
        &["--project", &t.p, "execution", "show", &execution],
    );
    let record = shown.get("execution").unwrap_or(&shown);
    assert_eq!(
        record["state"], "FAILED",
        "still FAILED after the lease would have expired"
    );
}

/// Control: the same blocked step without the lease keeper loses the execution (the mechanism
/// behind the M4 losses, now deterministic), so the test above is not vacuous.
#[test]
fn without_the_keeper_the_blocked_step_loses_the_execution() {
    let t = setup(true);
    let (state, _, _) = run(
        &t,
        "quick",
        &[
            ("CALVE_TEST_PAUSE", "execution.after_worker=75000"),
            ("CALVE_TEST_NO_LEASE_KEEPER", "1"),
        ],
    );
    assert_eq!(state, "LOST");
}
