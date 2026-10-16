//! Seal and promotion preflight, expected candidate, idempotent retry and result (P11).

use std::fs;
use std::process::Command;

use calve_testkit::Env;

#[test]
fn promotion_preflight_expected_candidate_retry_and_result() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    fs::write(root.join("toy.toml"), "").unwrap();
    fs::write(root.join("a.toy"), "one").unwrap();
    let run = |args: &[&str]| env.ok(&[&["--project", p.as_str()][..], args].concat());
    let id = run(&["pack", "create", "P"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    run(&["pack", "capture", &id, "a.toy", "--generation", "1"]);
    let g = run(&["pack", "show", &id])["generation"].to_string();
    let seal = run(&["pack", "seal", &id, "--generation", &g, "--preflight"]);
    assert_eq!(seal["candidate"]["effects"], 1, "{seal}");
    assert!(seal["blockers"].as_array().unwrap().is_empty(), "{seal}");
    let candidate = run(&["pack", "seal", &id, "--generation", &g])["candidate_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    // Not yet qualified: the preflight says so and is not ready.
    let pre = run(&["pack", "promote", &id, "--generation", &g, "--preflight"]);
    assert_eq!(pre["ready"], false, "{pre}");
    assert_eq!(pre["candidate"], candidate.as_str());
    assert_eq!(pre["capability"]["allowed"], true);
    run(&["pack", "qualify", &id, "--generation", &g]);
    let pre = run(&["pack", "promote", &id, "--generation", &g, "--preflight"]);
    assert_eq!(pre["ready"], true, "{pre}");
    assert!(pre["qualification"]["current"] == true, "{pre}");

    // A candidate other than the reviewed one: STALE_VIEW (exit 3), JSON and human.
    let other = format!("sha256:{}", "0".repeat(64));
    let stale = |json: bool| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_calve"));
        c.env("XDG_DATA_HOME", env.path().join("d"))
            .env("XDG_CONFIG_HOME", env.path().join("c"))
            .args(["--no-daemon-start", "--project", &p]);
        if json {
            c.arg("--json");
        }
        c.args([
            "pack",
            "promote",
            &id,
            "--generation",
            &g,
            "--candidate",
            &other,
        ]);
        c.output().unwrap()
    };
    let out = stale(true);
    assert_eq!(out.status.code(), Some(3));
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["error"]["code"], "STALE_VIEW");
    assert_eq!(err["error"]["detail"]["current"], candidate.as_str());
    let out = stale(false);
    assert_eq!(out.status.code(), Some(3));
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.starts_with("calve: STALE_VIEW: "), "{text}");

    let promoted = run(&[
        "pack",
        "promote",
        &id,
        "--generation",
        &g,
        "--candidate",
        &candidate,
    ]);
    let digest = promoted["promoted_digest"].as_str().unwrap().to_owned();
    assert!(promoted["receipt"].is_string(), "{promoted}");
    assert_eq!(
        promoted["promotion_record"]["record"]["candidate"],
        candidate.as_str()
    );
    assert!(
        promoted["follow_up"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f.as_str().unwrap().contains(&digest))
    );
    // A retry is the same promotion, not a second one.
    let again = run(&["pack", "promote", &id, "--generation", &g]);
    assert_eq!(again["already_promoted"], true);
    assert_eq!(again["promoted_digest"], digest.as_str());
    assert_eq!(
        again["promotion_record"]["digest"],
        promoted["promotion_record"]["digest"]
    );
}
