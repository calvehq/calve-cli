//! Extensions end to end through the real CLI (rev 10 §7–§9): a signed TUF catalog, the trust /
//! compatibility / permission gates, the T2 acknowledgment, grants and capability widening on
//! update, rollback refusal, uninstall guarded by use — and the CIC-driven product paths
//! (capture with derived relations, classified scans, extension diff, checks, resources) on the
//! fixture package `org.example.toy`.

use std::fs;
use std::path::{Path, PathBuf};

use calve_testkit::Env;
use calve_testkit::tuf::{Package, Repo, sha};
use serde_json::json;

fn fixture_ext() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_calve"))
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("fixture_ext{}", std::env::consts::EXE_SUFFIX))
}

/// The trailer fixture (`org.example.fixture`, openaevc-only) at `version` requesting `caps`.
fn openaevc_only(version: &'static str, caps: &[&str]) -> Package<'static> {
    let mut bytes = fs::read(fixture_ext()).unwrap();
    bytes.extend(
        format!(
            "\nCALVE-FIXTURE:{}",
            json!({"version": version, "caps": caps})
        )
        .as_bytes(),
    );
    Package {
        id: "org.example.fixture",
        version,
        kind: "openaevc-only",
        native: ("fixture_ext", bytes),
        cic: None,
        metadata: None,
    }
}

fn trust(env: &Env, name: &str, r: &Repo) {
    let root = r.root_bytes(1);
    let file = env.path().join(format!("{name}-root.json"));
    fs::write(&file, &root).unwrap();
    let wrong = env.fails(&[
        "extension",
        "catalog",
        "add",
        name,
        r.path().to_str().unwrap(),
        "--root",
        file.to_str().unwrap(),
        "--root-digest",
        &"0".repeat(64),
    ]);
    assert!(wrong.contains("pin"), "{wrong}");
    env.ok(&[
        "extension",
        "catalog",
        "add",
        name,
        r.path().to_str().unwrap(),
        "--root",
        file.to_str().unwrap(),
        "--root-digest",
        &sha(&root),
    ]);
}

#[test]
fn catalog_install_grant_update_rollback_and_uninstall() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let mut r = Repo::new();
    r.add_package("targets", openaevc_only("1.0.0", &["clock.read"]));
    r.targets.insert(
        "index.json".into(),
        br#"{"schema":"calve.index/1","ids":["org.example.fixture"]}"#.to_vec(),
    );
    r.publish();
    let old = r.freeze();
    trust(&env, "example", &r);
    let listed = env.ok(&["extension", "catalog", "list"]);
    assert_eq!(listed[0]["state"], "fresh", "{listed}");
    assert_eq!(
        env.ok(&["extension", "search", "fixture"])[0]["package"]["versions"][0]["version"],
        "1.0.0"
    );

    // Native code never runs without the T2 acknowledgment.
    let refused = env.fails(&["extension", "install", "org.example.fixture"]);
    assert!(refused.contains("T2_ACKNOWLEDGMENT_REQUIRED"), "{refused}");
    let installed = env.ok(&[
        "extension",
        "install",
        "org.example.fixture",
        "--acknowledge-native",
    ]);
    assert_eq!(installed["kind"], "openaevc-only");

    let project = env.path().join("project");
    let p = project.to_str().unwrap();
    env.ok(&["init", p]);
    let refused = env.fails(&["--project", p, "extension", "enable", "org.example.fixture"]);
    assert!(
        refused.contains("T2_ACKNOWLEDGMENT_REQUIRED"),
        "the acknowledgment is per Project and artifact: {refused}"
    );
    let enabled = env.ok(&[
        "--project",
        p,
        "extension",
        "enable",
        "org.example.fixture",
        "--acknowledge-native",
    ]);
    assert_eq!(
        enabled["ungranted_requests"],
        json!(["clock.read"]),
        "{enabled}"
    );
    assert!(
        env.fails(&[
            "--project",
            p,
            "extension",
            "grant",
            "org.example.fixture",
            "network.connect"
        ])
        .contains("does not request")
    );
    assert_eq!(
        env.ok(&[
            "--project",
            p,
            "extension",
            "grant",
            "org.example.fixture",
            "clock.read"
        ])["granted"],
        json!(["clock.read"])
    );
    let busy = env.fails(&["extension", "uninstall", "org.example.fixture"]);
    assert!(busy.contains("EXTENSION_IN_USE"), "{busy}");

    // A new version requesting more is held until the widening is granted.
    r.add_package(
        "targets",
        openaevc_only("1.1.0", &["clock.read", "network.connect"]),
    );
    r.publish();
    let held = env.ok(&[
        "--project",
        p,
        "extension",
        "update",
        "org.example.fixture",
        "--acknowledge-native",
    ]);
    assert_eq!(
        held["permission_widening"],
        json!(["network.connect"]),
        "{held}"
    );
    let updated = env.ok(&[
        "--project",
        p,
        "extension",
        "update",
        "org.example.fixture",
        "--grant",
        "network.connect",
        "--acknowledge-native",
    ]);
    assert_eq!(
        (
            updated["version"].as_str(),
            updated["previous_version"].as_str()
        ),
        (Some("1.1.0"), Some("1.0.0"))
    );

    // A mirror replaying older metadata is a rollback: refused, trust state unchanged.
    fs::remove_dir_all(r.path().join("metadata")).unwrap();
    calve_testkit::copy_tree(&old.path().join("metadata"), &r.path().join("metadata"));
    let err = env.fails(&["extension", "catalog", "refresh", "example"]);
    assert!(
        err.contains("CATALOG_UNTRUSTED") || err.contains("ollback"),
        "{err}"
    );

    env.ok(&[
        "--project",
        p,
        "extension",
        "disable",
        "org.example.fixture",
    ]);
    let removed = env.ok(&["extension", "uninstall", "org.example.fixture"]);
    assert_eq!(removed["removed"].as_array().unwrap().len(), 2, "{removed}");
}

#[test]
fn cic_product_paths_on_the_fixture_package() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let project = env.path().join("project");
    let p = project.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    let enabled = env.enable_toy(&project);
    assert_eq!(enabled["trust_tier"], "T2 native (not confined)");
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(project.join("src/a.txt"), "one\n").unwrap();
    fs::write(project.join("src/gen.tmp"), "x").unwrap();
    fs::write(project.join("src/.toyignore"), "*.tmp\n").unwrap();
    fs::create_dir_all(project.join("target")).unwrap();
    fs::write(project.join("target/big.bin"), "ignored by the extension").unwrap();
    fs::write(project.join("toy.toml"), "").unwrap();
    let pr = |args: &[&str]| -> Vec<String> {
        [&["--project", &p][..], args]
            .concat()
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    let run =
        |env: &Env, args: &[&str]| env.ok(&pr(args).iter().map(String::as_str).collect::<Vec<_>>());

    // Classified scan: the extension decides what is ignored.
    let listed = run(&env, &["resource", "list"]);
    let paths: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"src/a.txt")
            && !paths.contains(&"src/gen.tmp")
            && !paths.iter().any(|p| p.starts_with("target")),
        "{paths:?}"
    );
    let checked = run(&env, &["ignore", "check", "src/gen.tmp"]);
    assert_eq!(
        (checked["ignored"].as_bool(), checked["rule"].as_str()),
        (Some(true), Some("src/.toyignore:1")),
        "{checked}"
    );

    // Capture a tree, promote, then a rename is captured as delete + add with a relation.
    let pack = run(&env, &["pack", "create", "first"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let cap = run(
        &env,
        &["pack", "capture-tree", &pack, ".", "--generation", "1"],
    );
    assert!(
        cap["captured"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["path"] == "src/a.txt"),
        "{cap}"
    );
    let g = cap["generation"].as_u64().unwrap().to_string();
    run(&env, &["pack", "seal", &pack, "--generation", &g]);
    let verified = run(&env, &["pack", "verify", &pack, "--generation", &g]);
    assert_eq!(verified["status"], "PASS", "{verified}");
    run(&env, &["pack", "qualify", &pack, "--generation", &g]);
    run(&env, &["pack", "promote", &pack, "--generation", &g]);
    fs::rename(project.join("src/a.txt"), project.join("src/b.txt")).unwrap();
    let second = run(&env, &["pack", "create", "rename"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let cap = run(
        &env,
        &["pack", "capture-tree", &second, "src", "--generation", "1"],
    );
    assert_eq!(
        cap["relations"][0]["kind"], "org.example.toy.rename",
        "{cap}"
    );
    assert_eq!(
        cap["relations"][0]["payload"],
        json!({"from": "src/a.txt", "to": "src/b.txt"})
    );
    let diff = run(&env, &["resource", "diff", &second, "src/b.txt"]);
    assert_eq!(diff["state"], "unchanged", "{diff}");
    fs::write(project.join("src/b.txt"), "two\n").unwrap();
    let diff = run(&env, &["resource", "diff", &second, "src/b.txt"]);
    assert_eq!(
        diff["changes"][0]["lines"],
        json!(["-one", "+two"]),
        "{diff}"
    );

    // Checks: detection and the plan come from the extension; a missing tool is never a pass.
    let g2 = cap["generation"].as_u64().unwrap().to_string();
    run(&env, &["pack", "seal", &second, "--generation", &g2]);
    let checks = run(&env, &["pack", "check", &second, "--generation", &g2]);
    assert_eq!(checks["languages"][0]["language"], "toy", "{checks}");
    assert_eq!(checks["languages"][0]["checks"][0]["tool_available"], false);
    assert_eq!(
        checks["languages"][0]["verification"]["status"], "INCONCLUSIVE",
        "{checks}"
    );

    // Declared non-file resources.
    let note_pack = run(&env, &["pack", "create", "note"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let set = run(
        &env,
        &[
            "resource",
            "set",
            &note_pack,
            "--generation",
            "1",
            "--set",
            r#"note:plan={"text":"ship"}"#,
        ],
    );
    assert_eq!(set["applied"], json!(["note:plan"]), "{set}");
    let bad = env.fails(
        &pr(&[
            "resource",
            "set",
            &note_pack,
            "--generation",
            &set["generation"].to_string(),
            "--set",
            r#"note:x={"oops":1}"#,
        ])
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>(),
    );
    assert!(
        bad.contains("pack already has effects") || bad.contains("rejected"),
        "{bad}"
    );
}
