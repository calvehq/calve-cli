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

#[test]
fn language_checks_gate_promotion_through_openaevc() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path();
    let root = data.join("project");
    let p = root.to_str().unwrap();
    ok(data, &["init", p]);
    ok(data, &["--project", p, "extension", "enable"]);
    let rust = ok(
        data,
        &["--project", p, "extension", "enable", "org.calve.rust"],
    );
    assert_eq!(rust["id"], "org.calve.rust");
    ok(
        data,
        &["--project", p, "extension", "enable", "org.calve.go"],
    );
    ok(
        data,
        &["--project", p, "extension", "enable", "org.calve.shell"],
    );
    let config = ok(
        data,
        &["--project", p, "config", "edit-path", "--scope", "project"],
    );
    fs::write(
        config["path"].as_str().unwrap(),
        r#"format_version = 1
[integrations."org.calve.rust".checks]
content = ["sh", "-c", "grep -q candidate src/lib.rs"]
[integrations."org.calve.go".checks]
test = ["calve-definitely-missing-tool"]
[integrations."org.calve.shell".checks]
lint = ["sh", "-c", "exit 4"]
"#,
    )
    .unwrap();
    fs::write(root.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
    fs::create_dir(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "// candidate\n").unwrap();
    fs::create_dir(root.join("target")).unwrap();
    fs::write(root.join("target/junk"), "x").unwrap();
    assert_eq!(
        ok(data, &["--project", p, "ignore", "check", "target/junk"])["source"],
        "software default"
    );

    let pack = ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "create",
            "Rust change",
            "--require-check",
            "rust",
        ],
    );
    let id = pack["id"].as_str().unwrap();
    ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "capture",
            id,
            "src/lib.rs",
            "--generation",
            "1",
        ],
    );
    // The working copy moves on; checks must still see the sealed candidate.
    fs::write(root.join("src/lib.rs"), "// working\n").unwrap();
    let generation = ok(data, &["--project", p, "pack", "show", id])["generation"].to_string();
    ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "seal",
            id,
            "--generation",
            &generation,
        ],
    );
    let (promoted, _, _) = calve(
        data,
        &[
            "--project",
            p,
            "pack",
            "promote",
            id,
            "--generation",
            &generation,
        ],
    );
    assert!(!promoted, "promotion must wait for the required check");
    let checked = ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "check",
            id,
            "--generation",
            &generation,
            "--language",
            "rust",
        ],
    );
    assert_eq!(
        checked["languages"][0]["verification"]["status"], "PASS",
        "{checked}"
    );
    assert_eq!(checked["drift"][0], "src/lib.rs");
    ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "qualify",
            id,
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
            id,
            "--generation",
            &generation,
        ],
    );

    let other = ok(data, &["--project", p, "pack", "create", "Other"]);
    let other = other["id"].as_str().unwrap();
    fs::write(root.join("run.sh"), "echo hi\n").unwrap();
    ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "capture",
            other,
            "run.sh",
            "--generation",
            "1",
        ],
    );
    let generation = ok(data, &["--project", p, "pack", "show", other])["generation"].to_string();
    ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "seal",
            other,
            "--generation",
            &generation,
        ],
    );
    let checked = ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "check",
            other,
            "--generation",
            &generation,
            "--language",
            "go",
            "--language",
            "shell",
        ],
    );
    let languages = checked["languages"].as_array().unwrap();
    assert_eq!(languages[0]["checks"][0]["tool_available"], false);
    assert_eq!(languages[0]["verification"]["status"], "INCONCLUSIVE");
    assert_eq!(languages[1]["verification"]["status"], "FAIL");
}

#[test]
fn general_project_resources_follow_accepted_history() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path();
    let root = data.join("project");
    let p = root.to_str().unwrap();
    ok(data, &["init", p]);
    ok(
        data,
        &["--project", p, "extension", "enable", "org.calve.general"],
    );
    let promote = |sets: &[&str], removes: &[&str]| -> String {
        let pack = ok(data, &["--project", p, "pack", "create", "Plan"]);
        let id = pack["id"].as_str().unwrap().to_owned();
        let mut args = vec!["--project", p, "resource", "set", &id, "--generation", "1"];
        for set in sets {
            args.extend(["--set", set]);
        }
        for remove in removes {
            args.extend(["--remove", remove]);
        }
        ok(data, &args);
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
    let (rejected, _, stderr) = calve(
        data,
        &[
            "--project",
            p,
            "resource",
            "set",
            "x",
            "--generation",
            "1",
            "--set",
            r#"record:r={"fields":{"a":[1]}}"#,
        ],
    );
    assert!(!rejected && stderr.contains("scalar"), "{stderr}");
    let first = promote(
        &[
            r#"note:plan={"text":"ship it"}"#,
            r#"checklist:launch={"items":[{"text":"docs","done":false}]}"#,
            r#"artifact:spec={"uri":"https://example.com/spec.pdf"}"#,
        ],
        &[],
    );
    assert_eq!(
        ok(data, &["--project", p, "resource", "show", "note:plan"])["value"]["text"],
        "ship it"
    );
    let second = promote(
        &[r#"checklist:launch={"items":[{"text":"docs","done":true}]}"#],
        &["artifact:spec"],
    );
    let listed = ok(
        data,
        &["--project", p, "resource", "list", "--domain", "general"],
    );
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert_eq!(
        ok(
            data,
            &["--project", p, "resource", "show", "checklist:launch"]
        )["value"]["items"][0]["done"],
        true
    );
    // With a Baseline holding only the first pack active, that history is what applies.
    let baseline = ok(
        data,
        &["--project", p, "baseline", "create", "first", &first],
    );
    ok(
        data,
        &[
            "--project",
            p,
            "baseline",
            "activate",
            baseline["id"].as_str().unwrap(),
        ],
    );
    assert_eq!(
        ok(
            data,
            &["--project", p, "resource", "show", "checklist:launch"]
        )["value"]["items"][0]["done"],
        false
    );
    assert!(
        ok(data, &["--project", p, "resource", "show", "artifact:spec"])["value"]["uri"]
            .is_string()
    );
    let _ = second;
}
