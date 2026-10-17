//! Every example under `examples/` is CI-validated (PLAN §54): each script asserts its own
//! outcomes and exits non-zero on the first failed expectation. The generic examples run against
//! the fixture catalog (`org.example.toy` as the file domain); the ones that show first-party
//! semantics (Rust checks, notes and checklists) need the calve-extensions catalog and run with
//! `--ignored` when `CALVE_CATALOG_ADD` names it (the cross-repo e2e does).

use std::path::Path;
use std::process::Command;

use calve_testkit::ToyCatalog;

fn run_example(name: &str) {
    let toy = ToyCatalog::new();
    let mut command = Command::new("bash");
    if std::env::var_os("CALVE_CATALOG_ADD").is_none() {
        command
            .env("CALVE_CATALOG_ADD", toy.add_args().join("\n"))
            .env("CALVE_FILES_EXT", "org.example.toy");
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
        .join("run.sh");
    let output = command
        .arg(&root)
        .env("CALVE", env!("CARGO_BIN_EXE_calve"))
        .output()
        .expect("run example");
    assert!(
        output.status.success(),
        "{name} failed\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
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
