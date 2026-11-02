//! The rest of the `--json` command surface (PLAN §17, ADR 0020): commands no other end-to-end
//! test runs. Each succeeds here, so `cargo xtask json-schemas` records its output and its v1
//! schema is enforced.

use std::fs;

use calve_testkit::Env;

fn id(v: &serde_json::Value) -> String {
    v["id"].as_str().expect("id").to_owned()
}

#[test]
fn remaining_commands_succeed_with_json() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    let pr = |args: &[&str]| -> Vec<String> {
        ["--project", p.as_str()]
            .iter()
            .chain(args)
            .map(|s| (*s).to_owned())
            .collect()
    };
    let run = |env: &Env, args: &[&str]| {
        let a = pr(args);
        env.ok(&a.iter().map(String::as_str).collect::<Vec<_>>())
    };

    // Workspaces and Projects.
    let project_id = env.ok(&["project", "list"])[0]["project_id"]
        .as_str()
        .unwrap()
        .to_owned();
    env.ok(&["workspace", "create", "team"]);
    env.ok(&["workspace", "rename", "team", "crew"]);
    env.ok(&["workspace", "add-project", "crew", &project_id]);
    env.ok(&["workspace", "set-default-project", "crew", &project_id]);
    env.ok(&["workspace", "remove-project", "crew", &project_id]);
    env.ok(&["project", "unregister", &project_id, "--yes"]);
    env.ok(&["project", "register", &p]);
    run(&env, &["config", "list"]);

    // Intents and Tasks.
    let intent = id(&run(&env, &["intent", "create", "Ship"]));
    run(&env, &["intent", "list"]);
    let a = id(&run(&env, &["task", "create", &intent, "A"]));
    let b = id(&run(&env, &["task", "create", &intent, "B"]));
    run(&env, &["task", "depends-on", &a, &b]);
    run(&env, &["task", "remove-dependency", &a, &b]);
    run(&env, &["task", "assign", &a, "alex"]);

    // Pack review decisions and reopen.
    fs::write(root.join("toy.toml"), "").unwrap();
    fs::write(root.join("a.toy"), "one").unwrap();
    let pack = id(&run(&env, &["pack", "create", "Review me"]));
    run(
        &env,
        &["pack", "capture", &pack, "a.toy", "--generation", "1"],
    );
    let g = run(&env, &["pack", "show", &pack])["generation"].to_string();
    run(&env, &["pack", "seal", &pack, "--generation", &g]);
    run(
        &env,
        &["review", "comment", &pack, "--generation", &g, "looks fine"],
    );
    run(
        &env,
        &[
            "review",
            "reject",
            &pack,
            "--generation",
            &g,
            "--reason",
            "not yet",
        ],
    );
    run(
        &env,
        &[
            "pack",
            "reject",
            &pack,
            "--generation",
            &g,
            "--reason",
            "still not",
        ],
    );
    let empty = id(&run(&env, &["pack", "create", "empty"]));
    run(&env, &["pack", "seal", &empty, "--generation", "1"]);
    run(&env, &["pack", "reopen", &empty, "--generation", "1"]);

    // A promoted pack, a revision through its whole lifecycle, Baselines and aliases.
    let p1 = id(&run(&env, &["pack", "create", "P1"]));
    run(
        &env,
        &["pack", "capture", &p1, "a.toy", "--generation", "1"],
    );
    let g1 = run(&env, &["pack", "show", &p1])["generation"].to_string();
    run(&env, &["pack", "seal", &p1, "--generation", &g1]);
    run(&env, &["pack", "qualify", &p1, "--generation", &g1]);
    let p1_digest = run(&env, &["pack", "promote", &p1, "--generation", &g1])["promoted_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::write(root.join("a.toy"), "two").unwrap();
    let r = id(&run(
        &env,
        &["revision", "create", "R1", "--of", &p1_digest],
    ));
    run(
        &env,
        &["revision", "capture", &r, "a.toy", "--generation", "1"],
    );
    run(&env, &["revision", "diff", &r]);
    let gr = run(&env, &["revision", "show", &r])["generation"].to_string();
    run(&env, &["revision", "seal", &r, "--generation", &gr]);
    run(&env, &["revision", "verify", &r, "--generation", &gr]);
    run(&env, &["revision", "evaluate", &r, "--generation", &gr]);
    run(&env, &["revision", "review", &r]);
    run(
        &env,
        &[
            "revision",
            "reject",
            &r,
            "--generation",
            &gr,
            "--reason",
            "first look",
        ],
    );
    run(
        &env,
        &[
            "revision",
            "approve",
            &r,
            "--generation",
            &gr,
            "--reason",
            "fine",
        ],
    );
    let refused = env.fails(
        &pr(&["revision", "check", &r, "--generation", &gr])
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let plan = refused
        .split_whitespace()
        .find(|w| w.len() == 64 && w.bytes().all(|c| c.is_ascii_hexdigit()))
        .expect("plan digest")
        .to_owned();
    run(
        &env,
        &[
            "revision",
            "check",
            &r,
            "--generation",
            &gr,
            "--approve-plan",
            &plan,
        ],
    );
    run(&env, &["pack", "qualify", &r, "--generation", &gr]);
    run(&env, &["revision", "promote", &r, "--generation", &gr]);
    run(&env, &["revision", "list"]);
    let baseline = id(&run(&env, &["baseline", "create", "B0", &p1_digest]));
    run(&env, &["baseline", "list"]);
    run(&env, &["baseline", "show", &baseline]);
    run(&env, &["baseline", "alias", "set", "stable", &baseline]);
    run(&env, &["baseline", "alias", "remove", "stable"]);

    // Inbox items come from attention the pack and tasks created.
    let items = run(&env, &["inbox", "list", "--all"]);
    if let Some(key) = items
        .as_array()
        .and_then(|a| a.first())
        .and_then(|i| i["source_key"].as_str())
        .map(str::to_owned)
    {
        run(&env, &["inbox", "show", &key]);
        run(&env, &["inbox", "read", &key]);
        run(&env, &["inbox", "ack", &key]);
        run(&env, &["inbox", "unack", &key]);
        run(&env, &["inbox", "snooze", &key, "--until", "1h"]);
        run(&env, &["inbox", "unsnooze", &key]);
    } else {
        panic!("expected inbox items: {items}");
    }

    // Providers, harnesses, extension catalogs, daemon status.
    env.ok(&[
        "provider",
        "add",
        "sh",
        "--kind",
        "local-process",
        "--executable",
        "sh",
    ]);
    env.ok(&["provider", "disable", "sh"]);
    env.ok(&["provider", "enable", "sh"]);
    env.ok(&["provider", "show", "sh"]);
    run(&env, &["harness", "list"]);
    run(&env, &["harness", "show", "capture"]);
    env.ok(&["extension", "catalog", "refresh"]);
    env.ok(&["daemon", "status"]);
    env.ok(&["extension", "catalog", "remove", "test", "--yes"]);
}

/// `execution cancel` stops a real worker under a real daemon, and `task link-execution` links
/// the cancelled execution.
#[cfg(unix)]
#[test]
fn a_running_execution_is_cancelled_and_linked_to_a_task() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    let at = |args: &[&str]| -> Vec<String> {
        ["--project", p.as_str()]
            .iter()
            .chain(args)
            .map(|s| (*s).to_owned())
            .collect()
    };
    let run = |env: &Env, args: &[&str]| {
        let a = at(args);
        env.ok(&a.iter().map(String::as_str).collect::<Vec<_>>())
    };
    env.ok(&[
        "provider",
        "add",
        "shell",
        "--kind",
        "local-process",
        "--executable",
        "sh",
    ]);
    fs::write(
        root.join(".calve/config.toml"),
        "format_version = 1\n[harnesses.slow]\nprovider = \"shell\"\nmode = \"check\"\ncommand = [\"-c\", \"echo working; sleep 60\"]\n",
    )
    .unwrap();
    run(&env, &["config", "approve"]);
    let pack = id(&run(&env, &["pack", "create", "Slow"]));
    env.ok(&["daemon", "start"]);
    let client = std::process::Command::new(env!("CARGO_BIN_EXE_calve"))
        .env("XDG_DATA_HOME", env.path().join("d"))
        .env("XDG_CONFIG_HOME", env.path().join("c"))
        .args(at(&[
            "--json",
            "--no-daemon-start",
            "execution",
            "start",
            &pack,
        ]))
        .args(["--harness", "slow", "--generation", "1"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let execution = (0..300)
        .find_map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(200));
            run(&env, &["execution", "list", "--pack", &pack])
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["state"] == "RUNNING")
                .map(id)
        })
        .expect("the execution starts");
    // Reads work during the run, and none of them disturbs the runtime it depends on.
    run(&env, &["inbox", "list"]);
    run(
        &env,
        &["pack", "seal", &pack, "--generation", "2", "--preflight"],
    );
    run(&env, &["maintenance", "gc", "--dry-run"]);
    assert!(run(&env, &["status"])["project"].is_object());
    let check = run(&env, &["maintenance", "check"]);
    assert_eq!(check["store"]["state"], "in_use", "{check}");
    let refused = at(&["maintenance", "verify-store"]);
    let refused = env.fails(&refused.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(refused.contains("PROJECT_LOCKED"), "{refused}");
    run(
        &env,
        &["execution", "cancel", &execution, "--reason", "not needed"],
    );
    let done = run(
        &env,
        &["execution", "wait", &execution, "--timeout-ms", "30000"],
    );
    assert_eq!(done["state"], "CANCELLED", "{done}");
    // The client that started it gets a clean result, and a cancelled worker's output survives.
    let started = client.wait_with_output().unwrap();
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let started = calve_testkit::json_data(&started.stdout);
    assert_eq!(started["state"], "CANCELLED", "{started}");
    let log = fs::read_to_string(started["log"].as_str().unwrap()).unwrap();
    assert!(log.contains("working"), "{log}");

    // A relative path means the caller's directory, not the daemon's.
    let bundle = std::process::Command::new(env!("CARGO_BIN_EXE_calve"))
        .env("XDG_DATA_HOME", env.path().join("d"))
        .env("XDG_CONFIG_HOME", env.path().join("c"))
        .current_dir(env.path())
        .args(at(&[
            "--json",
            "--no-daemon-start",
            "doctor",
            "--bundle",
            "bundle.out",
            "--yes",
        ]))
        .output()
        .unwrap();
    assert!(
        env.path().join("bundle.out").exists(),
        "{}",
        String::from_utf8_lossy(&bundle.stderr)
    );

    let intent = id(&run(&env, &["intent", "create", "Why"]));
    let task = id(&run(&env, &["task", "create", &intent, "Work"]));
    run(&env, &["task", "link-execution", &task, &execution]);
    let shown = run(&env, &["task", "show", &task]);
    assert!(shown.to_string().contains(&execution), "{shown}");
    env.ok(&["daemon", "stop"]);
}
