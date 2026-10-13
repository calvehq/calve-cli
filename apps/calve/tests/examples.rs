//! Every example under `examples/` is CI-validated (PLAN §54): each script asserts its own
//! outcomes and exits non-zero on the first failed expectation.

use std::path::Path;
use std::process::Command;

fn run_example(name: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
        .join("run.sh");
    let output = Command::new("bash")
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
fn general_project() {
    run_example("general-project");
}

#[test]
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
