//! A confined worker against the state that gives authority: real attempts by a real worker
//! through a real daemon, each of which must fail. T2 native extensions and other same-user
//! processes are outside this boundary, and `t2_native_code_is_not_confined_residual` says so.
#![cfg(target_os = "linux")]

use std::fs;

use calve_testkit::Env;
use serde_json::Value;

fn id(v: &Value) -> String {
    v["id"].as_str().expect("id").to_owned()
}

fn project(env: &mut Env) -> (std::path::PathBuf, String) {
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    env.ok(&[
        "provider",
        "add",
        "shell",
        "--kind",
        "local-process",
        "--executable",
        "sh",
        "--env",
        "PATH",
        "--env",
        "HOME",
    ]);
    (root, p)
}

fn harness(root: &std::path::Path, mode: &str, script: &str) {
    fs::write(
        root.join(".calve/config.toml"),
        format!(
            "format_version = 1\n[harnesses.probe]\nprovider = \"shell\"\nmode = \"{mode}\"\ncommand = [\"-c\", '''{script}''']\n"
        ),
    )
    .unwrap();
}

/// Every route to authority fails, with HOME and the data directory inside the worker's roots.
#[test]
fn a_worker_cannot_reach_authority_or_the_daemon() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let home = env.path().to_path_buf();
    env.vars.push(("HOME".into(), home.into()));
    let (root, p) = project(&mut env);
    let pid = env.ok(&["project", "list"])[0]["project_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let keys = env
        .path()
        .join("d/calve/authority")
        .join(&pid)
        .join("keys.toml");
    let daemon = env.ok(&["daemon", "start"])["pid"].as_u64().unwrap();
    let socket = env.path().join("d/calve/daemon.sock");
    // Positive control: all of it exists and is reachable from outside the worker.
    assert!(keys.is_file() && socket.exists() && root.join(".calve/project.toml").is_file());
    let (k, s, r) = (keys.display(), socket.display(), root.display());
    let script = format!(
        r#"probe() {{ if "$@" >/dev/null 2>&1; then echo "BREACH: $*"; fi; }}
echo probed
probe cat {k}
probe ls {r}/.calve/project.toml
probe cat {r}/.calve/product.sqlite3
probe cat {r}/.calve/../.calve/config.toml
probe sh -c 'echo x >> {r}/.calve/config.toml'
probe sh -c 'echo x > {r}/.calve/new-file'
probe test -e {s}
probe cat /proc/{daemon}/root{k}
probe umount {r}/.calve
probe umount -l {r}/.calve
probe unshare -Urm sh -c 'umount {r}/.calve && cat {r}/.calve/project.toml'
ln -s {k} escape; probe cat escape; rm -f escape
ln -s {r}/.calve/project.toml escape; probe cat escape; rm -f escape
probe {r}/../target/nothing
echo ok-in-project > allowed-write; cat allowed-write; rm allowed-write
"#
    );
    harness(&root, "check", &script);
    env.ok(&["--project", &p, "config", "approve"]);
    let pack = id(&env.ok(&["--project", &p, "pack", "create", "probe"]));
    let done = env.ok(&[
        "--project",
        &p,
        "execution",
        "start",
        &pack,
        "--harness",
        "probe",
        "--generation",
        "1",
    ]);
    let logs = env
        .ok(&[
            "--project",
            &p,
            "execution",
            "logs",
            done["execution"].as_str().unwrap(),
        ])
        .to_string();
    assert!(logs.contains("probed"), "the worker ran: {done} {logs}");
    assert!(
        logs.contains("ok-in-project"),
        "it still works in the Project: {logs}"
    );
    assert!(!logs.contains("BREACH"), "{logs}");
    assert_eq!(done["containment"]["namespace"], true, "{done}");
    assert_ne!(done["containment"]["landlock"], "none", "{done}");
    env.ok(&["daemon", "stop"]);
}

/// Configuration a worker could have written is powerless until the host approves those bytes.
#[test]
fn unapproved_project_configuration_runs_nothing() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let (root, p) = project(&mut env);
    harness(&root, "check", "echo planted");
    let pack = id(&env.ok(&["--project", &p, "pack", "create", "c"]));
    let start = [
        "--project",
        &p,
        "execution",
        "start",
        &pack,
        "--harness",
        "probe",
        "--generation",
        "1",
    ];
    assert!(env.fails(&start).contains("CONFIG_UNAPPROVED"));

    env.ok(&["--project", &p, "config", "approve"]);
    assert!(
        env.ok(&["--project", &p, "harness", "show", "probe"])
            .is_object(),
        "approved bytes count"
    );
    // Changing one byte after approval takes the power away again, and a host edit on top of
    // the changed file does not bless it.
    harness(&root, "check", "echo changed");
    env.ok(&[
        "--project",
        &p,
        "config",
        "set",
        "ui.page_size",
        "40",
        "--scope",
        "project",
    ]);
    assert!(env.fails(&start).contains("CONFIG_UNAPPROVED"));
    let list = env.ok(&["--project", &p, "config", "list"]);
    assert!(list["unapproved"].is_string(), "{list}");
}

/// A planted check command does not run as approved: it needs the host's approval of the file.
#[test]
fn planted_check_commands_are_ignored_until_approved() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let (root, p) = project(&mut env);
    fs::write(
        root.join(".calve/config.toml"),
        "format_version = 1\n[integrations.\"org.example.toy\".checks]\nplanted = [\"sh\", \"-c\", \"touch planted\"]\n",
    )
    .unwrap();
    let list = env.ok(&["--project", &p, "config", "list"]);
    assert!(
        list["integrations"].as_object().unwrap().is_empty(),
        "{list}"
    );
    assert!(list["unapproved"].is_string(), "{list}");
}
