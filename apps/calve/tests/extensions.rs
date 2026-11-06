//! Extensions end to end through the real CLI (rev 10 §7–§9): a signed TUF catalog, the trust /
//! compatibility / permission gates, the T2 acknowledgment, grants and capability widening on
//! update, rollback refusal, uninstall guarded by use — and the CIC-driven product paths
//! (capture with derived relations, classified scans, extension diff, checks, resources) on the
//! fixture package `org.example.toy`.

use std::fs;
use std::path::{Path, PathBuf};

use calve_testkit::Env;
use calve_testkit::tuf::{Package, Repo, sha};
use serde_json::{Value, json};

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
        refs: None,
    }
}

fn openaevc_only_bytes(bytes: Vec<u8>) -> Package<'static> {
    Package {
        native: ("fixture_ext", bytes),
        ..openaevc_only("1.0.0", &[])
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
    let revoked = env.ok(&[
        "--project",
        p,
        "extension",
        "revoke",
        "org.example.fixture",
        "clock.read",
    ]);
    assert_eq!(revoked["granted"], json!([]), "{revoked}");
    env.ok(&[
        "--project",
        p,
        "extension",
        "grant",
        "org.example.fixture",
        "clock.read",
    ]);
    let busy = env.fails(&["extension", "uninstall", "org.example.fixture", "--yes"]);
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
    let removed = env.ok(&["extension", "uninstall", "org.example.fixture", "--yes"]);
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
        &[
            "pack",
            "capture-tree",
            "--accept-deletions",
            &pack,
            ".",
            "--generation",
            "1",
        ],
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
        &[
            "pack",
            "capture-tree",
            "--accept-deletions",
            &second,
            "src",
            "--generation",
            "1",
        ],
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
    // The package's own plan runs only once approved by the digest the refusal printed.
    let check = pr(&["pack", "check", &second, "--generation", &g2]);
    let check: Vec<&str> = check.iter().map(String::as_str).collect();
    let refused = env.fails(&check);
    let digest = refused
        .split_whitespace()
        .find(|w| w.len() == 64 && w.bytes().all(|b| b.is_ascii_hexdigit()))
        .expect("plan digest in the refusal")
        .to_owned();
    let checks = run(
        &env,
        &[
            "pack",
            "check",
            &second,
            "--generation",
            &g2,
            "--approve-plan",
            &digest,
        ],
    );
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

/// ADR 0005 residual, asserted: an enabled T2 native extension runs with the user's permissions
/// and can write outside its install directory. Calve records the acknowledgment; it does not
/// claim confinement.
#[cfg(unix)]
#[test]
fn t2_native_code_is_not_confined_residual() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let project = env.path().join("project");
    let p = project.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&project);
    fs::write(project.join("a.txt"), "one\n").unwrap();
    let id = env.ok(&["--project", &p, "pack", "create", "Probe"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    env.ok(&[
        "--project",
        &p,
        "pack",
        "capture",
        &id,
        "a.txt",
        "--generation",
        "1",
    ]);
    let g = env.ok(&["--project", &p, "pack", "show", &id])["generation"].to_string();
    env.ok(&["--project", &p, "pack", "seal", &id, "--generation", &g]);
    let hex: String = uuid_like(&p);
    let marker = std::path::PathBuf::from(format!("/tmp/calve-t2-escape-{hex}"));
    let _ = fs::remove_file(&marker);
    let digest = format!("sha256:{hex}");
    let _ = env.run(&[
        "--project",
        &p,
        "pack",
        "verify",
        &id,
        "--generation",
        &g,
        "--path",
        "t2-escape",
        "--digest",
        &digest,
    ]);
    assert!(
        marker.exists(),
        "the residual changed: T2 code could not write outside its directory"
    );
    fs::remove_file(&marker).unwrap();
}

/// 64 hex characters unique to this test run.
fn uuid_like(seed: &str) -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    for i in 0..4u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write(seed.as_bytes());
        h.write_u64(i);
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

/// The catalog with `org.example.fixture` 1.0.0 requesting `clock.read`, enabled in a Project.
fn fixture_project(env: &Env, r: &mut Repo) -> String {
    r.add_package("targets", openaevc_only("1.0.0", &["clock.read"]));
    r.targets.insert(
        "index.json".into(),
        br#"{"schema":"calve.index/1","ids":["org.example.fixture"]}"#.to_vec(),
    );
    r.publish();
    trust(env, "example", r);
    let project = env.path().join("project");
    let p = project.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.ok(&[
        "--project",
        &p,
        "extension",
        "enable",
        "org.example.fixture",
        "--acknowledge-native",
    ]);
    p
}

/// §57 P with real signed packages: each passes every other check and is judged on its protocol
/// range alone. Lower, higher and malformed ranges are refused before anything is written, and
/// a range touching the supported version at either end is accepted.
#[test]
fn scenario_p_a_package_is_judged_on_its_protocol_range() {
    for (range, accepted) in [
        (json!([[0, 0], [0, 0]]), false),
        (json!([[0, 2], [0, 3]]), false),
        (json!([[9, 0], [9, 1]]), false),
        (json!([[0, 3], [0, 0]]), false),
        (json!([[0, 0], [0, 1]]), true),
        (json!([[0, 1], [0, 2]]), true),
    ] {
        let env = Env::new(env!("CARGO_BIN_EXE_calve"));
        let mut r = Repo::new();
        let mut bytes = fs::read(fixture_ext()).unwrap();
        bytes.extend(
            format!(
                "\nCALVE-FIXTURE:{}",
                json!({"version": "1.0.0", "caps": [], "protocol": range})
            )
            .as_bytes(),
        );
        r.add_package("targets", openaevc_only_bytes(bytes));
        r.targets.insert(
            "index.json".into(),
            br#"{"schema":"calve.index/1","ids":["org.example.fixture"]}"#.to_vec(),
        );
        r.publish();
        trust(&env, "example", &r);
        let root = env.path().join("project");
        let p = root.to_str().unwrap();
        env.ok(&["init", p]);
        let before = env.ok(&["--project", p, "activity"]).to_string();
        let enable = [
            "--project",
            p,
            "extension",
            "enable",
            "org.example.fixture",
            "--acknowledge-native",
        ];
        if accepted {
            env.ok(&enable);
            continue;
        }
        let refused = env.fails(&enable);
        assert!(
            refused.contains("EXTENSION_INCOMPATIBLE"),
            "{range}: {refused}"
        );
        assert!(
            refused.to_lowercase().contains("protocol"),
            "{range}: {refused}"
        );
        let listed = env.ok(&["--project", p, "extension", "list"]);
        assert_eq!(listed.as_array().unwrap().len(), 0, "{range}");
        assert_eq!(
            env.ok(&["--project", p, "activity"]).to_string(),
            before,
            "{range}"
        );
    }
}

/// The two catalog commands that change trust: moving an id to another publisher, and the
/// audited reset, which needs both confirmations.
#[test]
fn publisher_switch_and_catalog_reset() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let mut first = Repo::new();
    let _project = fixture_project(&env, &mut first);
    let mut second = Repo::new();
    second.add_package("targets", openaevc_only("1.0.0", &["clock.read"]));
    second.targets.insert(
        "index.json".into(),
        br#"{"schema":"calve.index/1","ids":["org.example.fixture"]}"#.to_vec(),
    );
    second.publish();
    trust(&env, "second", &second);
    let id = "org.example.fixture";
    let switch = ["extension", "switch-publisher", id, "--catalog", "second"];
    assert!(env.fails(&switch).contains("yes"));
    let moved = env.ok(&[&switch[..], &["--yes", "--acknowledge-native"]].concat());
    // A refused reset leaves the catalog as it was.
    let bad_root = env.path().join("bad-root.json");
    fs::write(&bad_root, b"{}").unwrap();
    env.fails(&[
        "extension",
        "catalog",
        "reset",
        "second",
        "--root",
        bad_root.to_str().unwrap(),
        "--root-digest",
        &sha(b"{}"),
        "--yes",
        "--i-understand-rollback-risk",
    ]);
    assert!(
        env.ok(&["extension", "catalog", "list"])
            .to_string()
            .contains("second")
    );
    // A refused add can be tried again.
    env.fails(&[
        "extension",
        "catalog",
        "add",
        "third",
        second.path().to_str().unwrap(),
        "--root",
        bad_root.to_str().unwrap(),
        "--root-digest",
        &sha(b"{}"),
    ]);
    trust(&env, "third", &second);
    assert_eq!(moved["catalog"], "second", "{moved}");

    let root = env.path().join("example-root.json");
    let root = root.to_str().unwrap();
    let digest = sha(&first.root_bytes(1));
    let reset = [
        "extension",
        "catalog",
        "reset",
        "example",
        "--root",
        root,
        "--root-digest",
        &digest,
    ];
    let refused = env.fails(&[&reset[..], &["--yes"]].concat());
    assert!(refused.contains("rollback"), "{refused}");
    env.ok(&[&reset[..], &["--yes", "--i-understand-rollback-risk"]].concat());
    let catalogs = env.ok(&["extension", "catalog", "list"]);
    assert!(catalogs.to_string().contains("example"), "{catalogs}");
}

fn registered(env: &Env, p: &str) -> Value {
    env.ok(&["--project", p, "extension", "list"])[0].clone()
}

/// §57 H: v1 granted A; v2 requests A+B; the update check detects the widening and activation
/// is blocked; approving B updates, and the grant binds to the new version and digest.
#[test]
fn scenario_h_permission_widening() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let mut r = Repo::new();
    // 1–2. v1 installed with capability set A, granted.
    let p = fixture_project(&env, &mut r);
    env.ok(&[
        "--project",
        &p,
        "extension",
        "grant",
        "org.example.fixture",
        "clock.read",
    ]);
    let v1 = registered(&env, &p);
    assert_eq!(v1["version"], "1.0.0");
    // 3. v2 requires A+B.
    r.add_package(
        "targets",
        openaevc_only("1.1.0", &["clock.read", "process.execute"]),
    );
    r.publish();
    // 4–5. The update detects the widening; automatic activation is blocked.
    let held = env.ok(&[
        "--project",
        &p,
        "extension",
        "update",
        "org.example.fixture",
        "--acknowledge-native",
    ]);
    assert_eq!(
        held["permission_widening"],
        json!(["process.execute"]),
        "{held}"
    );
    assert_eq!(registered(&env, &p), v1, "nothing activated");
    // 6–7. The user approves B: new version, new digest, grant bound to them.
    let updated = env.ok(&[
        "--project",
        &p,
        "extension",
        "update",
        "org.example.fixture",
        "--grant",
        "process.execute",
        "--acknowledge-native",
    ]);
    assert_eq!(updated["version"], "1.1.0", "{updated}");
    let v2 = registered(&env, &p);
    assert_eq!(v2["version"], "1.1.0");
    assert_ne!(v2["manifest"], v1["manifest"], "the digest changed");
    assert_eq!(
        v2["granted_host_capabilities"],
        json!(["process.execute", "clock.read"]),
        "{v2}"
    );
    assert_eq!(v2["active"], true);
}

/// §57 L: an update interrupted after the first durable install record leaves the previous
/// version active and valid; recovery cleans up; the catalog stays valid; a retry succeeds.
#[test]
fn scenario_l_crash_during_extension_install() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let mut r = Repo::new();
    let p = fixture_project(&env, &mut r);
    let v1 = registered(&env, &p);
    r.add_package("targets", openaevc_only("1.1.0", &["clock.read"]));
    r.publish();
    env.ok(&["extension", "catalog", "refresh", "example"]);
    // 1. Interrupted after download, before activation.
    let crashed = std::process::Command::new(env!("CARGO_BIN_EXE_calve"))
        .env("XDG_DATA_HOME", env.path().join("d"))
        .env("XDG_CONFIG_HOME", env.path().join("c"))
        .env("CALVE_FAULT", "append.after_fsync")
        .args(["--json", "--no-daemon-start", "--project", &p])
        .args([
            "extension",
            "update",
            "org.example.fixture",
            "--acknowledge-native",
        ])
        .output()
        .unwrap();
    assert!(!crashed.status.success(), "the update crashed");
    // 2–3. After restart the active mapping is still the previous valid version.
    assert_eq!(registered(&env, &p), v1, "previous version stays active");
    assert_eq!(
        env.ok(&["--project", &p, "extension", "health"])[0]["healthy"],
        true
    );
    // 4. Temporary content is cleaned safely.
    let plan = env.ok(&["--project", &p, "recover", "plan"]);
    assert!(
        plan["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["action"] == "reconcile_install_journals"),
        "{plan}"
    );
    env.ok(&["--project", &p, "recover", "apply", "--yes"]);
    assert_eq!(
        env.ok(&["--project", &p, "recover", "plan"])["actions"],
        json!([])
    );
    // 5. Catalog and package integrity stay valid: the retry installs the new version.
    assert_eq!(
        env.ok(&["extension", "catalog", "list"])[0]["state"],
        "fresh"
    );
    assert_eq!(registered(&env, &p), v1);
    let retried = env.ok(&[
        "--project",
        &p,
        "extension",
        "update",
        "org.example.fixture",
        "--acknowledge-native",
    ]);
    assert_eq!(retried["version"], "1.1.0", "{retried}");
}

/// §57 N: a conforming extension with no Calve metadata (openaevc-only) enables, its manifest is
/// visible, its evidence is recorded and read through the generic paths, with no Calve code
/// knowing it. DEVIATION: creating resource instances needs integration metadata (acceptance.md).
#[test]
fn scenario_n_third_party_extension() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let mut r = Repo::new();
    // 1–2. Installed and enabled with no Calve metadata beyond the package.
    let p = fixture_project(&env, &mut r);
    let info = env.ok(&["--project", &p, "extension", "info", "org.example.fixture"]);
    assert_eq!(info["manifest"]["id"], "org.example.fixture", "{info}");
    assert_eq!(
        env.ok(&["--project", &p, "extension", "health"])[0]["healthy"],
        true
    );
    // 3. Its resources are created and viewed from nothing but its signed manifest.
    let kind = "org.example.fixture.record.set";
    let edit = env.ok(&["--project", &p, "pack", "create", "records"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    env.ok(&[
        "--project",
        &p,
        "resource",
        "set",
        &edit,
        "--generation",
        "1",
        "--set",
        &format!("{kind}:item-1={{\"score\":3}}"),
    ]);
    let refused = env.fails(&[
        "--project",
        &p,
        "resource",
        "set",
        &edit,
        "--generation",
        "1",
        "--set",
        &format!("{kind}:item-2=[1]"),
    ]);
    assert!(!refused.is_empty());
    let generation = env.ok(&["--project", &p, "pack", "show", &edit])["generation"].to_string();
    env.ok(&[
        "--project",
        &p,
        "pack",
        "seal",
        &edit,
        "--generation",
        &generation,
    ]);
    env.ok(&[
        "--project",
        &p,
        "pack",
        "qualify",
        &edit,
        "--generation",
        &generation,
    ]);
    env.ok(&[
        "--project",
        &p,
        "pack",
        "promote",
        &edit,
        "--generation",
        &generation,
    ]);
    let shown = env.ok(&[
        "--project",
        &p,
        "resource",
        "show",
        &format!("{kind}:item-1"),
    ]);
    assert!(shown.to_string().contains("score"), "{shown}");
    // 3. Its evidence is created and viewed by kind.
    let pack = env.ok(&["--project", &p, "pack", "create", "third party"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    env.ok(&["--project", &p, "pack", "seal", &pack, "--generation", "1"]);
    let file = env.path().join("report.json");
    fs::write(&file, br#"{"score": 3}"#).unwrap();
    let added = env.ok(&[
        "--project",
        &p,
        "evidence",
        "add",
        &pack,
        "--generation",
        "1",
        "--kind",
        "org.example.fixture.report/v1",
        "--file",
        file.to_str().unwrap(),
    ]);
    let listed = env.ok(&["--project", &p, "evidence", "list", &pack]);
    let digest = listed["items"][0]["digest"].as_str().unwrap().to_owned();
    assert_eq!(
        listed["items"][0]["evidence"]["kind"], "org.example.fixture.report/v1",
        "{added}"
    );
    // 4. The generic renderer shows it without any Calve-specific code.
    let human = std::process::Command::new(env!("CARGO_BIN_EXE_calve"))
        .env("XDG_DATA_HOME", env.path().join("d"))
        .env("XDG_CONFIG_HOME", env.path().join("c"))
        .args([
            "--no-daemon-start",
            "--project",
            &p,
            "evidence",
            "show",
            &digest,
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(
        human.status.success() && text.contains("org.example.fixture.report/v1"),
        "{text}"
    );
    assert!(
        !text.trim_start().starts_with('{'),
        "structured text, not a raw dump:\n{text}"
    );
}

/// Two independent processes refreshing one catalog and installing one package: trust state
/// stays whole, floors never fall, and the package is installed once.
#[test]
fn two_processes_share_catalog_state_safely() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let mut r = Repo::new();
    r.add_package("targets", openaevc_only("1.0.0", &["clock.read"]));
    r.targets.insert(
        "index.json".into(),
        br#"{"schema":"calve.index/1","ids":["org.example.fixture"]}"#.to_vec(),
    );
    r.publish();
    trust(&env, "example", &r);
    let spawn = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_calve"))
            .env("XDG_DATA_HOME", env.path().join("d"))
            .env("XDG_CONFIG_HOME", env.path().join("c"))
            .args(["--json", "--no-daemon-start"])
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    let floors = || -> Value {
        serde_json::from_slice(
            &fs::read(env.path().join("d/calve/catalogs/example/floors.json")).unwrap(),
        )
        .unwrap()
    };
    let mut last = floors()["versions"]["timestamp"].as_u64().unwrap();
    for _ in 0..4 {
        r.publish();
        let (a, b) = (
            spawn(&["extension", "catalog", "refresh", "example"]),
            spawn(&["extension", "catalog", "refresh", "example"]),
        );
        let results = [a.wait_with_output().unwrap(), b.wait_with_output().unwrap()];
        assert!(results.iter().any(|o| o.status.success()), "{results:?}");
        for o in results.iter().filter(|o| !o.status.success()) {
            let e = String::from_utf8_lossy(&o.stderr);
            assert!(e.contains("try again"), "only a clean retry may fail: {e}");
        }
        let now = floors()["versions"]["timestamp"].as_u64().unwrap();
        assert!(now >= last, "floors fell: {now} < {last}");
        last = now;
    }
    let install = [
        "extension",
        "install",
        "org.example.fixture",
        "--acknowledge-native",
    ];
    let (a, b) = (spawn(&install), spawn(&install));
    let results = [a.wait_with_output().unwrap(), b.wait_with_output().unwrap()];
    assert!(results.iter().all(|o| o.status.success()), "{results:?}");
    let packages = env.path().join("d/calve/packages/org.example.fixture");
    assert_eq!(fs::read_dir(packages).unwrap().count(), 1, "installed once");
    env.ok(&["extension", "catalog", "list"]);
}

/// L1 authority boundary: a verifier or evaluator name binds to an extension only through the
/// kinds that extension declared in its signed, installed manifest. Through the real path
/// (signed catalog → `extension enable` → OpenAEVC registration) and Calve's own OpenAEVC
/// client, raw `RunVerification` / `RunEvaluation` with an undeclared, lookalike, empty,
/// wrong-type or other-extension (`org.example.other.*`, not installed) name are refused by OpenAEVC before any extension is invoked
/// ("no registered extension provides …"), and OpenAEVC records no verification, evaluation,
/// evidence, policy decision or completion event, the pack and its effects are unchanged. The
/// declared names, as positive controls, run and add exactly one result each.
#[test]
fn undeclared_verifier_and_evaluator_names_obtain_no_result() {
    use openaevc::protocol::{Command, ObjectKind, PackId, Query};
    use openaevc_sdk::OpenAevcClient;

    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    let ok = |a: &[&str]| env.ok(&[&["--project", p.as_str()][..], a].concat());
    let pack = ok(&["pack", "create", "P"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::write(root.join("a.toy"), "aaa").unwrap();
    ok(&[
        "pack",
        "capture-tree",
        "--accept-deletions",
        &pack,
        "--generation",
        "1",
    ]);
    let g = ok(&["pack", "show", &pack])["generation"].as_u64().unwrap();
    ok(&["pack", "seal", &pack, "--generation", &g.to_string()]);
    let pack_before = ok(&["pack", "show", &pack]);

    calve_app::authority::use_data_root(&env.path().join("d/calve"));
    let project = calve_app::Project::open(&root).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pack_id: PackId = pack.parse().unwrap();
    let query = |q: Query| runtime.block_on(project.client.query(q)).unwrap();
    // What OpenAEVC has recorded: result objects by kind, and the completion events.
    let recorded = || {
        let objects = |kind| {
            query(Query::ListObjectDigests {
                kind: Some(kind),
                after: None,
                limit: Some(1000),
            })["objects"]
                .clone()
        };
        let events = |kind: &str| {
            query(Query::ListEvents {
                after: Default::default(),
                limit: None,
                kinds: vec![kind.into()],
            })
            .as_array()
            .unwrap()
            .len()
        };
        json!({
            "verifications": objects(ObjectKind::VerificationResult),
            "evaluations": objects(ObjectKind::EvaluationResult),
            "evidence": objects(ObjectKind::Evidence),
            "decisions": objects(ObjectKind::PolicyDecision),
            "verification.completed": events("verification.completed"),
            "evaluation.completed": events("evaluation.completed"),
            "qualification.evaluated": events("qualification.evaluated"),
        })
    };
    // Errors as text: the SDK error type is large (clippy::result_large_err).
    let verify = |name: &str| {
        runtime
            .block_on(project.client.command(Command::RunVerification {
                pack: pack_id,
                generation: g,
                verifier: name.into(),
                config: None,
                evidence: vec![],
            }))
            .map_err(|e| e.to_string())
    };
    let evaluate = |name: &str| {
        runtime
            .block_on(project.client.command(Command::RunEvaluation {
                pack: pack_id,
                generation: g,
                evaluator: name.into(),
                config: None,
                inputs: vec![],
            }))
            .map_err(|e| e.to_string())
    };
    let before = recorded();

    // Declared by the toy's signed manifest: verifiers .verify and .checks, evaluator .size.
    let refused_names = [
        "",
        "org.example.toy.verifyx",
        "org.example.toy.Verify",
        "org.example.toy.verify ",
        " org.example.toy.verify",
        "org.example.toy",
        "org.example.toy.undeclared",
        "org.example.other.verify",
        "org.example.other.size",
    ];
    let mut seen = vec![];
    // An evaluator asked for as a verifier, and verifiers asked for as evaluators.
    for name in refused_names
        .iter()
        .copied()
        .chain(["org.example.toy.size"])
    {
        let e = verify(name).expect_err(name);
        assert!(
            e.contains(&format!("no registered extension provides verifier {name}")),
            "verifier {name:?}: {e}"
        );
        seen.push(format!("verifier {name:?}: {e}"));
    }
    for name in refused_names
        .iter()
        .copied()
        .chain(["org.example.toy.verify", "org.example.toy.checks"])
    {
        let e = evaluate(name).expect_err(name);
        assert!(
            e.contains(&format!(
                "no registered extension provides evaluator {name}"
            )),
            "evaluator {name:?}: {e}"
        );
        seen.push(format!("evaluator {name:?}: {e}"));
    }
    eprintln!("refused before dispatch:\n{}", seen.join("\n"));
    let after_refusals = recorded();
    assert_eq!(after_refusals, before, "a refused name left a result");

    // Positive controls: the declared names are dispatched and add exactly one result each.
    let v = verify("org.example.toy.verify").expect("declared verifier");
    let e = evaluate("org.example.toy.size").expect("declared evaluator");
    let after = recorded();
    let len = |r: &Value, k: &str| r[k].as_array().unwrap().len();
    assert_eq!(
        len(&after, "verifications"),
        len(&before, "verifications") + 1,
        "{after}"
    );
    assert_eq!(
        len(&after, "evaluations"),
        len(&before, "evaluations") + 1,
        "{after}"
    );
    assert_eq!(
        after["verification.completed"],
        json!(before["verification.completed"].as_u64().unwrap() + 1)
    );
    assert_eq!(
        after["evaluation.completed"],
        json!(before["evaluation.completed"].as_u64().unwrap() + 1)
    );
    let digest = |r: &openaevc::protocol::CommandReceipt| json!(r.result.digest.unwrap());
    assert!(
        after["verifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["digest"] == digest(&v))
    );
    assert!(
        after["evaluations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["digest"] == digest(&e))
    );
    eprintln!(
        "recorded before: {before}\nafter refusals: {after_refusals}\nafter controls: {after}"
    );
    drop(project);
    // The pack and its effects: unchanged by the refusals and by the controls alike.
    let pack_after = ok(&["pack", "show", &pack]);
    assert_eq!(
        pack_after["candidate_effects"],
        pack_before["candidate_effects"]
    );
    assert_eq!(pack_after["state"], pack_before["state"]);
    assert_eq!(pack_after["generation"], pack_before["generation"]);
}
