use std::fs;

use calve_testkit::Env;

/// Deletes and renames flow through the lifecycle. A rename is captured as a delete plus an add
/// (canonical per-path ops, §6.5) with a derived relation recorded as an observation; the host
/// never interprets the relation.
#[test]
fn deletes_and_renames_flow_through_the_lifecycle() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    env.enable_toy(std::path::Path::new(p));
    let promote = |title: &str| -> (String, String) {
        let id = env.ok(&["--project", p, "pack", "create", title])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        env.ok(&[
            "--project",
            p,
            "pack",
            "capture-tree",
            &id,
            ".",
            "--generation",
            "1",
        ]);
        let g = env.ok(&["--project", p, "pack", "show", &id])["generation"].to_string();
        env.ok(&["--project", p, "pack", "seal", &id, "--generation", &g]);
        env.ok(&["--project", p, "pack", "qualify", &id, "--generation", &g]);
        let digest = env.ok(&["--project", p, "pack", "promote", &id, "--generation", &g])["promoted_digest"]
            .as_str()
            .unwrap()
            .to_owned();
        (id, digest)
    };
    fs::write(root.join("keep.txt"), "keep\n").unwrap();
    fs::write(root.join("old.txt"), "gone soon\n").unwrap();
    fs::write(root.join("move.txt"), "moving\n").unwrap();
    let (_, v1) = promote("initial");

    fs::remove_file(root.join("old.txt")).unwrap();
    fs::rename(root.join("move.txt"), root.join("moved.txt")).unwrap();
    let (second, v2) = promote("delete and rename");
    let pack = env.ok(&["--project", p, "view", "pack", &second]);
    let files = pack["files"].as_array().unwrap();
    assert_eq!(
        files.len(),
        3,
        "unchanged keep.txt is not recaptured: {files:?}"
    );
    let status = |path: &str| {
        files
            .iter()
            .find(|f| f["path"] == path)
            .map(|f| f["status"].clone())
    };
    assert_eq!(status("old.txt"), Some("deleted".into()));
    assert_eq!(status("move.txt"), Some("deleted".into()));
    assert_eq!(status("moved.txt"), Some("added".into()));
    let history = env.ok(&["--project", p, "resource", "history", "move.txt"]);
    assert_eq!(
        history["history"].as_array().unwrap().last().unwrap()["change"],
        "deleted"
    );
    // The relation is recorded verbatim in the capture execution's observations.
    let execs = env.ok(&["--project", p, "execution", "list", "--pack", &second]);
    let exec = execs.as_array().unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let logs = env
        .ok(&["--project", p, "execution", "logs", &exec])
        .to_string();
    assert!(
        logs.contains("org.example.toy.rename") && logs.contains("moved.txt"),
        "{logs}"
    );

    // v1 restores the deleted and renamed-away files and removes moved.txt.
    let b1 = env.ok(&["--project", p, "baseline", "create", "v1", &v1])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let b2 = env.ok(&["--project", p, "baseline", "create", "v2", &v1, &v2])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    env.ok(&["--project", p, "baseline", "materialize", &b1, "--apply"]);
    assert!(root.join("old.txt").exists() && root.join("move.txt").exists());
    assert!(!root.join("moved.txt").exists());
    env.ok(&["--project", p, "baseline", "materialize", &b2, "--apply"]);
    assert!(!root.join("old.txt").exists() && !root.join("move.txt").exists());
    assert_eq!(
        fs::read_to_string(root.join("moved.txt")).unwrap(),
        "moving\n"
    );

    // A locally edited file the Baseline deletes is protected like any uncaptured work.
    fs::write(root.join("old.txt"), "recreated by hand\n").unwrap();
    let plan = env.ok(&["--project", p, "baseline", "materialize", &b2, "--apply"]);
    assert_eq!(plan["blocked"][0], "old.txt");

    // Capturing a single missing accepted file records a delete.
    fs::remove_file(root.join("old.txt")).unwrap();
    fs::remove_file(root.join("keep.txt")).unwrap();
    let pack = env.ok(&["--project", p, "pack", "create", "remove keep"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let captured = env.ok(&[
        "--project",
        p,
        "pack",
        "capture",
        &pack,
        "keep.txt",
        "--generation",
        "1",
    ]);
    assert_eq!(captured["path"], "keep.txt");
    let scan = env.ok(&["--project", p, "resource", "scan"]);
    assert!(
        scan["uncaptured"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["path"] != "keep.txt")
    );
}
