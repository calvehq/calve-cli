//! Domain paths through package declarations (INV-022): language checks planned by the
//! package's CIC `check_plan` and judged by its verifier gate promotion through OpenAEVC policy;
//! declared non-file resources follow accepted history and the active Baseline. The fixture
//! package `org.example.toy` stands in for every first-party domain (whose semantics are tested
//! in calve-extensions).

use std::fs;

use calve_testkit::Env;

#[test]
fn language_checks_gate_promotion_through_openaevc() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    let config = env.ok(&["--project", &p, "config", "edit-path", "--scope", "project"]);
    let config_path = config["path"].as_str().unwrap().to_owned();
    fs::write(&config_path, "format_version = 1\n[integrations.\"org.example.toy\".checks]\ncontent = [\"sh\", \"-c\", \"grep -q candidate src/lib.toy\"]\n").unwrap();
    fs::write(root.join("toy.toml"), "").unwrap();
    fs::create_dir(root.join("src")).unwrap();
    fs::write(root.join("src/lib.toy"), "// candidate\n").unwrap();
    fs::create_dir(root.join("target")).unwrap();
    fs::write(root.join("target/junk"), "x").unwrap();
    let ignored = env.ok(&["--project", &p, "ignore", "check", "target/junk"]);
    assert_eq!(
        (ignored["ignored"].as_bool(), ignored["source"].as_str()),
        (Some(true), Some("org.example.toy")),
        "{ignored}"
    );

    let id = env.ok(&[
        "--project",
        &p,
        "pack",
        "create",
        "Toy change",
        "--require-check",
        "toy",
    ])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    env.ok(&[
        "--project",
        &p,
        "pack",
        "capture",
        &id,
        "src/lib.toy",
        "--generation",
        "1",
    ]);
    // The working copy moves on; checks must still see the sealed candidate.
    fs::write(root.join("src/lib.toy"), "// working\n").unwrap();
    let generation = env.ok(&["--project", &p, "pack", "show", &id])["generation"].to_string();
    env.ok(&[
        "--project",
        &p,
        "pack",
        "seal",
        &id,
        "--generation",
        &generation,
    ]);
    assert!(
        !env.run(&[
            "--project",
            &p,
            "pack",
            "promote",
            &id,
            "--generation",
            &generation
        ])
        .success,
        "promotion waits for the required check"
    );
    let checked = env.ok(&[
        "--project",
        &p,
        "pack",
        "check",
        &id,
        "--generation",
        &generation,
        "--language",
        "toy",
    ]);
    assert_eq!(
        checked["languages"][0]["verification"]["status"], "PASS",
        "{checked}"
    );
    assert_eq!(checked["drift"][0], "src/lib.toy");
    env.ok(&[
        "--project",
        &p,
        "pack",
        "qualify",
        &id,
        "--generation",
        &generation,
    ]);
    env.ok(&[
        "--project",
        &p,
        "pack",
        "promote",
        &id,
        "--generation",
        &generation,
    ]);

    // A failing check is FAIL; without an override the package's own plan names a tool that is
    // not installed, which is INCONCLUSIVE, never a pass.
    let run_checks = |env: &Env, content: &str| {
        fs::write(&config_path, content).unwrap();
        let other = env.ok(&["--project", &p, "pack", "create", "Other"])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        fs::write(root.join("run.toy"), format!("{content:?}")).unwrap();
        env.ok(&[
            "--project",
            &p,
            "pack",
            "capture",
            &other,
            "run.toy",
            "--generation",
            "1",
        ]);
        let g = env.ok(&["--project", &p, "pack", "show", &other])["generation"].to_string();
        env.ok(&["--project", &p, "pack", "seal", &other, "--generation", &g]);
        let check = ["--project", &p, "pack", "check", &other, "--generation", &g];
        if content.contains("checks]") {
            return env.ok(&check);
        }
        // The package's own plan runs only after the user approved it.
        let refused = env.fails(&check);
        assert!(
            refused.contains("CHECK_PLAN_UNAPPROVED") && refused.contains("toy-check"),
            "{refused}"
        );
        // Approving another digest approves nothing; the printed one approves that plan.
        let other = "0".repeat(64);
        assert!(
            env.fails(&[&check[..], &["--approve-plan", &other]].concat())
                .contains("CHECK_PLAN_UNAPPROVED")
        );
        let digest = refused
            .split_whitespace()
            .find(|w| w.len() == 64 && w.bytes().all(|b| b.is_ascii_hexdigit()))
            .expect("digest in the refusal")
            .to_owned();
        env.ok(&[&check[..], &["--approve-plan", &digest]].concat())
    };
    let failed = run_checks(
        &env,
        "format_version = 1\n[integrations.\"org.example.toy\".checks]\nlint = [\"sh\", \"-c\", \"exit 4\"]\n",
    );
    assert_eq!(
        failed["languages"][0]["verification"]["status"], "FAIL",
        "{failed}"
    );
    let missing = run_checks(&env, "format_version = 1\n");
    assert_eq!(
        missing["languages"][0]["checks"][0]["tool_available"], false,
        "{missing}"
    );
    assert_eq!(
        missing["languages"][0]["verification"]["status"],
        "INCONCLUSIVE"
    );
    assert!(
        env.fails(&[
            "--project",
            &p,
            "pack",
            "create",
            "x",
            "--require-check",
            "cobol"
        ])
        .contains("unknown language")
    );
}

#[test]
fn declared_resources_follow_accepted_history() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    let promote = |env: &Env, sets: &[&str], removes: &[&str]| -> String {
        let id = env.ok(&["--project", &p, "pack", "create", "Plan"])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut args = vec!["--project", &p, "resource", "set", &id, "--generation", "1"];
        for set in sets {
            args.extend(["--set", set]);
        }
        for remove in removes {
            args.extend(["--remove", remove]);
        }
        env.ok(&args);
        let g = env.ok(&["--project", &p, "pack", "show", &id])["generation"].to_string();
        env.ok(&["--project", &p, "pack", "seal", &id, "--generation", &g]);
        env.ok(&["--project", &p, "pack", "qualify", &id, "--generation", &g]);
        env.ok(&["--project", &p, "pack", "promote", &id, "--generation", &g])["promoted_digest"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let rejected = env.fails(&[
        "--project",
        &p,
        "resource",
        "set",
        "x",
        "--generation",
        "1",
        "--set",
        r#"note:n={"oops":1}"#,
    ]);
    assert!(
        rejected.contains("pack") || rejected.contains("note"),
        "{rejected}"
    );
    let unknown = env.fails(&["--project", &p, "resource", "show", "checklist:launch"]);
    assert!(unknown.contains("unknown resource kind"), "{unknown}");
    let first = promote(
        &env,
        &[
            r#"note:plan={"text":"ship it"}"#,
            r#"note:old={"text":"stale"}"#,
        ],
        &[],
    );
    assert_eq!(
        env.ok(&["--project", &p, "resource", "show", "note:plan"])["value"]["text"],
        "ship it"
    );
    promote(&env, &[r#"note:plan={"text":"shipped"}"#], &["note:old"]);
    let listed = env.ok(&["--project", &p, "resource", "list", "--domain", "general"]);
    assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
    assert_eq!(
        env.ok(&["--project", &p, "resource", "show", "note:plan"])["value"]["text"],
        "shipped"
    );
    // With a Baseline holding only the first pack active, that history is what applies.
    let baseline = env.ok(&["--project", &p, "baseline", "create", "first", &first]);
    env.ok(&[
        "--project",
        &p,
        "baseline",
        "activate",
        baseline["id"].as_str().unwrap(),
    ]);
    assert_eq!(
        env.ok(&["--project", &p, "resource", "show", "note:plan"])["value"]["text"],
        "ship it"
    );
    assert_eq!(
        env.ok(&["--project", &p, "resource", "show", "note:old"])["value"]["text"],
        "stale"
    );
}

/// A check-plan approval names the plan, the package and the executable PATH resolves to
/// (path and content): replacing the executable or changing PATH needs a new approval.
#[cfg(unix)]
#[test]
fn check_plan_approval_is_bound_to_the_resolved_executable() {
    use std::os::unix::fs::PermissionsExt;
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    fs::write(root.join("toy.toml"), "").unwrap();
    let base = env.path().to_owned();
    let tool = |dir: &str, body: &str| {
        let d = base.join(dir);
        fs::create_dir_all(&d).unwrap();
        let f = d.join("toy-check");
        fs::write(&f, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        d
    };
    let system = std::env::var_os("PATH").unwrap_or_default();
    let path_with = |d: &std::path::Path| {
        let mut v = d.as_os_str().to_owned();
        v.push(":");
        v.push(&system);
        ("PATH".to_owned(), v)
    };
    let a = tool("bin-a", "exit 0");
    env.vars = vec![path_with(&a)];
    let id = env.ok(&["--project", &p, "pack", "create", "Checked"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::write(root.join("x.toy"), "x").unwrap();
    env.ok(&[
        "--project",
        &p,
        "pack",
        "capture",
        &id,
        "x.toy",
        "--generation",
        "1",
    ]);
    let g = env.ok(&["--project", &p, "pack", "show", &id])["generation"].to_string();
    env.ok(&["--project", &p, "pack", "seal", &id, "--generation", &g]);
    let check = ["--project", &p, "pack", "check", &id, "--generation", &g];
    let digest_of = |refused: &str| {
        assert!(refused.contains("CHECK_PLAN_UNAPPROVED"), "{refused}");
        refused
            .split_whitespace()
            .find(|w| w.len() == 64 && w.bytes().all(|b| b.is_ascii_hexdigit()))
            .expect("digest in the refusal")
            .to_owned()
    };
    let refused = env.fails(&check);
    assert!(refused.contains("bin-a/toy-check (sha256:"), "{refused}");
    let first = digest_of(&refused);
    let ran = env.ok(&[&check[..], &["--approve-plan", &first]].concat());
    assert_eq!(
        ran["languages"][0]["checks"][0]["tool_available"], true,
        "{ran}"
    );
    assert_eq!(ran["languages"][0]["checks"][0]["exit_code"], 0, "{ran}");
    // The approved plan keeps running unchanged.
    env.ok(&check);

    // The executable is replaced in place: the old approval no longer covers it.
    tool("bin-a", "exit 7");
    let second = digest_of(&env.fails(&check));
    assert_ne!(second, first);
    assert!(
        env.fails(&[&check[..], &["--approve-plan", &first]].concat())
            .contains("CHECK_PLAN_UNAPPROVED")
    );

    // PATH now resolves the name elsewhere (identical content): a new approval again.
    let b = tool("bin-b", "exit 0");
    env.vars = vec![path_with(&b)];
    let third = digest_of(&env.fails(&check));
    assert!(third != first && third != second);
}
