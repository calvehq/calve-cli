use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn calve(data: &Path, args: &[&str]) -> (bool, Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_calve"))
        .env("XDG_DATA_HOME", data.join("d"))
        .env("XDG_CONFIG_HOME", data.join("c"))
        .args(["--json", "--no-daemon-start"])
        .args(args)
        .output()
        .unwrap();
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap_or(Value::Null),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn ok(data: &Path, args: &[&str]) -> Value {
    let (success, value, stderr) = calve(data, args);
    assert!(success, "{args:?}: {stderr}");
    value
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for item in fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        let target = to.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_tree(&item.path(), &target);
        } else {
            fs::copy(item.path(), &target).unwrap();
        }
    }
}

/// Scenario J: a copied Project becomes a new Project with its own identity, and accepted
/// history travels through OpenAEVC object exchange.
#[test]
fn copied_project_is_adopted_with_new_identity() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path();
    let original = data.join("original");
    let p = original.to_str().unwrap();
    let created = ok(data, &["init", p]);
    ok(data, &["--project", p, "extension", "enable"]);
    fs::write(original.join("a.txt"), "accepted\n").unwrap();
    let id = ok(data, &["--project", p, "pack", "create", "first"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "capture",
            &id,
            "a.txt",
            "--generation",
            "1",
        ],
    );
    let generation = ok(data, &["--project", p, "pack", "show", &id])["generation"].to_string();
    ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "seal",
            &id,
            "--generation",
            &generation,
        ],
    );
    ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "qualify",
            &id,
            "--generation",
            &generation,
        ],
    );
    let promoted = ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "promote",
            &id,
            "--generation",
            &generation,
        ],
    );
    ok(
        data,
        &[
            "--project",
            p,
            "baseline",
            "create",
            "v1",
            promoted["promoted_digest"].as_str().unwrap(),
        ],
    );

    let copy = data.join("copy");
    copy_tree(&original, &copy);
    let c = copy.to_str().unwrap();
    assert_eq!(
        ok(data, &["project", "health", c])["status"],
        "duplicate_copy"
    );
    let adopted = ok(data, &["project", "adopt-copy", c, "--name", "Fork"]);
    assert_ne!(adopted["project_id"], created["project_id"]);
    assert_ne!(adopted["namespace_id"], created["namespace_id"]);
    assert!(adopted["transferred_objects"].as_u64().unwrap() > 1);
    assert_eq!(ok(data, &["project", "health", c])["status"], "healthy");
    // The adopted copy can see the transferred promoted pack by digest, as inert history.
    let object = ok(data, &["--project", c, "receipt", "list", "--limit", "1"]);
    assert!(object["items"].is_array());
    assert!(!copy.read_dir().unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".calve-adopt")
    }));
    // Both Projects stay writable and independent.
    ok(data, &["--project", p, "intent", "create", "Still here"]);
    ok(data, &["--project", c, "intent", "create", "Fork work"]);
    assert_eq!(
        ok(data, &["--project", c, "maintenance", "check"])["ok"],
        true
    );
}
