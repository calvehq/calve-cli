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
        calve_testkit::json_data(&output.stdout),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn ok(data: &Path, args: &[&str]) -> Value {
    let (success, value, stderr) = calve(data, args);
    assert!(success, "{args:?}: {stderr}");
    value
}

/// Scenario M: materialization refuses to destroy uncaptured work, and an explicit discard
/// backs the content up and records provenance.
#[test]
fn baseline_materialization_protects_uncaptured_work() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path();
    let root = data.join("project");
    let p = root.to_str().unwrap();
    ok(data, &["init", p]);
    let catalog = calve_testkit::ToyCatalog::new();
    ok(
        data,
        &catalog
            .add_args()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    ok(
        data,
        &[&["--project", p][..], &calve_testkit::ENABLE_TOY[..]].concat(),
    );
    let promote = |files: &[(&str, &str)]| -> String {
        for (path, content) in files {
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(root.join(parent)).unwrap();
            }
            fs::write(root.join(path), content).unwrap();
        }
        let id = ok(data, &["--project", p, "pack", "create", "change"])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        ok(
            data,
            &[
                "--project",
                p,
                "pack",
                "capture-tree",
                "--accept-deletions",
                &id,
                ".",
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
        ok(
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
        )["promoted_digest"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let v1 = promote(&[("a.txt", "one\n"), ("dir/b.txt", "bee\n")]);
    let baseline = ok(data, &["--project", p, "baseline", "create", "v1", &v1]);
    let baseline = baseline["id"].as_str().unwrap();

    // Captured-but-changed content is safe to replace; uncaptured edits are not.
    fs::remove_file(root.join("dir/b.txt")).unwrap();
    fs::write(root.join("a.txt"), "local edit\n").unwrap();
    let plan = ok(data, &["--project", p, "baseline", "materialize", baseline]);
    assert_eq!(plan["applied"], false);
    assert_eq!(plan["blocked"], serde_json::json!(["a.txt"]));
    let refused = ok(
        data,
        &[
            "--project",
            p,
            "baseline",
            "materialize",
            baseline,
            "--apply",
        ],
    );
    assert_eq!(refused["applied"], false);
    assert_eq!(
        fs::read_to_string(root.join("a.txt")).unwrap(),
        "local edit\n"
    );
    assert!(!root.join("dir/b.txt").exists());

    let applied = ok(
        data,
        &[
            "--project",
            p,
            "baseline",
            "materialize",
            baseline,
            "--apply",
            "--discard",
            "a.txt",
            "--activate",
        ],
    );
    assert_eq!(applied["applied"], true, "{applied}");
    assert_eq!(applied["active_baseline"], baseline);
    assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "one\n");
    assert_eq!(fs::read_to_string(root.join("dir/b.txt")).unwrap(), "bee\n");
    let backups: Vec<_> = fs::read_dir(root.join(".calve/cache/discarded"))
        .unwrap()
        .collect();
    assert_eq!(backups.len(), 1);
    let logs = ok(
        data,
        &[
            "--project",
            p,
            "execution",
            "logs",
            applied["execution"].as_str().unwrap(),
        ],
    );
    assert_eq!(logs["state"], "SUCCEEDED");

    // Single-file materialization from a pack follows the same rules.
    fs::write(root.join("a.txt"), "another local edit\n").unwrap();
    let packs = ok(data, &["--project", p, "pack", "list"]);
    let source = packs.as_array().unwrap()[0]["id"].as_str().unwrap();
    let blocked = ok(
        data,
        &[
            "--project",
            p,
            "resource",
            "materialize",
            "a.txt",
            "--from",
            source,
            "--apply",
        ],
    );
    assert_eq!(blocked["applied"], false);
    ok(
        data,
        &[
            "--project",
            p,
            "resource",
            "materialize",
            "a.txt",
            "--from",
            source,
            "--apply",
            "--discard",
        ],
    );
    assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "one\n");
}
