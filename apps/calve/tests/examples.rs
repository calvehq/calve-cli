//! Every example under `examples/` is CI-validated (PLAN §54): each script asserts its own
//! outcomes and exits non-zero on the first failed expectation. The generic examples run against
//! the fixture catalog (`org.example.toy` as the file domain); the ones that show first-party
//! semantics (Rust checks, notes and checklists) need the calve-extensions catalog and run with
//! `--ignored` when `CALVE_CATALOG_ADD` names it (the cross-repo e2e does).

use std::path::Path;
use std::process::Command;

use calve_testkit::ToyCatalog;

/// The scripts run one at a time: two of them start a real daemon, whose readiness window
/// (5 s) a debug build can miss when every script competes for the machine.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The scripts' shell. On Windows `bash` on PATH is the WSL launcher; the scripts run in Git for
/// Windows' bash, found from `git --exec-path` (`<git>/mingw64/libexec/git-core`).
fn bash() -> Command {
    if cfg!(windows) {
        let out = Command::new("git")
            .arg("--exec-path")
            .output()
            .expect("git");
        let exec = std::path::PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
        let git = exec.ancestors().nth(3).expect("git installation root");
        Command::new(git.join("bin").join("bash.exe"))
    } else {
        Command::new("bash")
    }
}

fn run_example(name: &str) {
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let toy = ToyCatalog::new();
    let mut command = bash();
    if std::env::var_os("CALVE_CATALOG_ADD").is_none() {
        command
            .env("CALVE_CATALOG_ADD", toy.add_args().join("\n"))
            .env("CALVE_FILES_EXT", "org.example.toy");
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
        .join("run.sh");
    // Output goes to files and the wait is on the script itself, bounded: a process the script
    // leaves behind cannot hold the run open, and a hang fails with what the script printed.
    let logs = tempfile::tempdir().unwrap();
    let (out, err) = (logs.path().join("stdout"), logs.path().join("stderr"));
    let mut child = command
        .arg(&root)
        .env("CALVE", env!("CARGO_BIN_EXE_clv"))
        .stdout(std::fs::File::create(&out).unwrap())
        .stderr(std::fs::File::create(&err).unwrap())
        .spawn()
        .expect("run example");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15 * 60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    let read =
        |p: &Path| String::from_utf8_lossy(&std::fs::read(p).unwrap_or_default()).into_owned();
    assert!(
        status.is_some_and(|s| s.success()),
        "{name} {}\n{}\n{}",
        if status.is_none() {
            "did not finish in 15 minutes"
        } else {
            "failed"
        },
        read(&out),
        read(&err)
    );
}

#[test]
#[ignore = "needs the first-party catalog in CALVE_CATALOG_ADD"]
fn general_project() {
    run_example("general-project");
}

#[test]
#[ignore = "needs the first-party catalog in CALVE_CATALOG_ADD"]
fn software_project() {
    run_example("software-project");
}

#[test]
fn parallel_intents() {
    run_example("parallel-intents");
}

#[test]
fn multi_baseline() {
    run_example("multi-baseline");
}

#[test]
fn revision() {
    run_example("revision");
}

#[test]
fn local_agent() {
    run_example("local-agent");
}

/// §57 Scenario A runs with the first-party general-project extension.
#[test]
#[ignore = "needs the first-party catalog in CALVE_CATALOG_ADD"]
fn scenario_a() {
    run_example("scenario-a");
}

#[test]
fn scenario_d() {
    run_example("scenario-d");
}

#[test]
fn scenario_e() {
    run_example("scenario-e");
}

#[test]
fn scenario_i() {
    run_example("scenario-i");
}

/// §57 Scenario B needs the first-party software and language extensions.
#[test]
#[ignore = "needs the first-party catalog in CALVE_CATALOG_ADD"]
fn scenario_b() {
    run_example("scenario-b");
}

#[test]
fn scenario_c() {
    run_example("scenario-c");
}

#[test]
fn scenario_f() {
    run_example("scenario-f");
}

#[test]
fn scenario_j() {
    run_example("scenario-j");
}

#[test]
fn scenario_k() {
    run_example("scenario-k");
}

#[test]
fn scenario_m() {
    run_example("scenario-m");
}

#[test]
fn scenario_o() {
    run_example("scenario-o");
}
