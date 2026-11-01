use calve_testkit::Env;

/// Reviewers are separate OpenAEVC principals; self-review can be forbidden per pack, and a
/// reviewer's grant limits what it can do.
#[test]
fn reviewer_identity_and_self_review_rule() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    env.enable_toy(std::path::Path::new(p));
    let reviewer = env.ok(&["--project", p, "authority", "identity-add", "reviewer"]);
    assert!(reviewer["principal"].as_str().unwrap().starts_with("pri_"));
    assert_eq!(
        env.ok(&["--project", p, "authority", "identities"])[0]["name"],
        "reviewer"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let project = env.ok(&["project", "list"])[0]["project_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let key = env
            .path()
            .join("d/calve/authority")
            .join(project)
            .join("identities/reviewer.toml");
        let mode = std::fs::metadata(key).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "identity keys are private");
    }
    std::fs::write(root.join("a.txt"), "a\n").unwrap();
    let pack = env.ok(&[
        "--project",
        p,
        "pack",
        "create",
        "change",
        "--require-review",
        "--forbid-self-review",
    ]);
    let id = pack["id"].as_str().unwrap();
    env.ok(&[
        "--project",
        p,
        "pack",
        "capture",
        id,
        "a.txt",
        "--generation",
        "1",
    ]);
    let g = env.ok(&["--project", p, "pack", "show", id])["generation"].to_string();
    // The reviewer's grant does not include sealing; OpenAEVC refuses it.
    let denied = env.fails(&[
        "--project",
        p,
        "--as",
        "reviewer",
        "pack",
        "seal",
        id,
        "--generation",
        &g,
    ]);
    assert!(denied.contains("FORBIDDEN"), "{denied}");
    env.ok(&["--project", p, "pack", "seal", id, "--generation", &g]);
    let own = env.fails(&[
        "--project",
        p,
        "pack",
        "approve",
        id,
        "--generation",
        &g,
        "--reason",
        "mine",
    ]);
    assert!(own.contains("self-review"), "{own}");
    let explain = env.ok(&["--project", p, "view", "pack", id])["explain"].clone();
    assert!(
        explain["satisfied"]
            .to_string()
            .contains("self-review forbidden"),
        "{explain}"
    );
    env.ok(&[
        "--project",
        p,
        "--as",
        "reviewer",
        "pack",
        "approve",
        id,
        "--generation",
        &g,
        "--reason",
        "looks good",
    ]);
    let reviews = env.ok(&["--project", p, "pack", "review", id]);
    assert_eq!(reviews[0]["reviewer"], reviewer["principal"]);
    env.ok(&["--project", p, "pack", "qualify", id, "--generation", &g]);
    env.ok(&["--project", p, "pack", "promote", id, "--generation", &g]);
    let removed = env.ok(&[
        "--project",
        p,
        "authority",
        "identity-remove",
        "reviewer",
        "--yes",
    ]);
    assert_eq!(removed["revoked_grants"].as_array().unwrap().len(), 1);
    env.fails(&["--project", p, "--as", "reviewer", "status"]);
}
