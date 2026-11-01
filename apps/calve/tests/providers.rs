use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn calve(data: &Path, args: &[&str]) -> (bool, Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_calve"))
        .env("XDG_DATA_HOME", data.join("d"))
        .env("XDG_CONFIG_HOME", data.join("c"))
        .env("CALVE_TEST_SECRET", "s3cret")
        .args(["--json", "--no-daemon-start"])
        .args(args)
        .output()
        .unwrap();
    let value = calve_testkit::json_data(&output.stdout);
    (
        output.status.success(),
        value,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn ok(data: &Path, args: &[&str]) -> Value {
    let (success, value, stderr) = calve(data, args);
    assert!(success, "{args:?}: {stderr}");
    value
}

#[test]
fn harness_executions_supervise_workers() {
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
    ok(
        data,
        &[
            "provider",
            "add",
            "shell",
            "--kind",
            "local-process",
            "--executable",
            "sh",
            "--secret",
            "TOKEN=env:CALVE_TEST_SECRET",
        ],
    );
    ok(
        data,
        &[
            "provider",
            "add",
            "agent",
            "--kind",
            "stdio-agent",
            "--executable",
            "sh",
        ],
    );
    assert_eq!(ok(data, &["provider", "test", "shell"])["healthy"], true);
    let config = ok(
        data,
        &["--project", p, "config", "edit-path", "--scope", "project"],
    );
    let config = config["path"].as_str().unwrap();
    fs::write(
        config,
        r#"format_version = 1
[harnesses.write]
provider = "shell"
mode = "change"
paths = ["out"]
command = ["-c", "mkdir -p out && echo \"home=$HOME token=$TOKEN\" > out/a.txt"]

[harnesses.flaky]
provider = "shell"
mode = "change"
paths = ["out"]
command = ["-c", "test -f ready || exit 3; mkdir -p out; echo ok > out/b.txt"]

[harnesses.escape]
provider = "shell"
mode = "change"
paths = ["out"]
command = ["-c", "echo nope > outside.txt"]

[harnesses.slow]
provider = "shell"
mode = "check"
timeout_ms = 300
command = ["-c", "sleep 5"]

[harnesses.agent]
provider = "agent"
mode = "change"
command = ["-c", "read ctx; echo '{\"type\":\"log\",\"text\":\"hi\"}'; echo '{\"type\":\"propose\",\"path\":\"agent.txt\",\"content_base64\":\"YWdlbnQK\"}'; echo '{\"type\":\"done\",\"status\":\"succeeded\"}'"]
"#,
    )
    .unwrap();
    ok(data, &["--project", p, "config", "approve"]);
    let pack = |title: &str| {
        ok(data, &["--project", p, "pack", "create", title])["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    let first = pack("write");
    let run = ok(
        data,
        &[
            "--project",
            p,
            "execution",
            "start",
            &first,
            "--harness",
            "write",
            "--generation",
            "1",
        ],
    );
    assert_eq!(run["state"], "SUCCEEDED");
    assert_eq!(run["effects"][0]["path"], "out/a.txt");
    // §23.4 (P10): the worker context is recorded in OpenAEVC and consumed by the execution;
    // the OpenAEVC idempotency key derives from the Calve request id (P17).
    let context = run["context"].as_str().expect("context digest").to_owned();
    let shown = ok(
        data,
        &[
            "--project",
            p,
            "execution",
            "show",
            run["execution"].as_str().unwrap(),
        ],
    );
    let record = shown.get("execution").unwrap_or(&shown);
    assert_eq!(record["context"][0], context.as_str(), "{shown}");
    assert!(
        record["idempotency_key"]
            .as_str()
            .is_some_and(|k| k.starts_with("calve:") && k.ends_with(":execution:0")),
        "{shown}"
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    let body = rt.block_on(async {
        use openaevc_sdk::OpenAevcClient as _;
        calve_app::authority::use_data_root(&data.join("d/calve"));
        let project = calve_app::Project::open(&root).unwrap();
        let digest: openaevc::protocol::Digest = context.parse().unwrap();
        project
            .client
            .query(openaevc::protocol::Query::GetObject { digest })
            .await
            .unwrap()
    });
    let blob: openaevc::protocol::Blob =
        serde_json::from_value(body["envelope"]["body"].clone()).unwrap();
    let recorded: Value = serde_json::from_slice(&blob.data).unwrap();
    assert_eq!(recorded["type"], "org.calve.worker-context/v1");
    assert_eq!(recorded["harness"], "org.calve.harness.write");
    assert_eq!(recorded["secrets"], serde_json::json!(["TOKEN"]));
    assert_eq!(recorded["paths"], serde_json::json!(["out"]));
    assert!(
        !recorded.to_string().contains("s3cret"),
        "names only: {recorded}"
    );
    // The environment is cleared; only referenced secrets reach the worker.
    assert_eq!(
        fs::read_to_string(root.join("out/a.txt")).unwrap(),
        "home= token=s3cret\n"
    );
    let shown = ok(data, &["--project", p, "pack", "show", &first]);
    let generation = shown["generation"].to_string();
    ok(
        data,
        &[
            "--project",
            p,
            "pack",
            "seal",
            &first,
            "--generation",
            &generation,
        ],
    );

    let flaky = pack("flaky");
    let failed = ok(
        data,
        &[
            "--project",
            p,
            "execution",
            "start",
            &flaky,
            "--harness",
            "flaky",
            "--generation",
            "1",
        ],
    );
    assert_eq!(failed["state"], "FAILED");
    assert_eq!(failed["exit_code"], 3);
    fs::write(root.join("ready"), "").unwrap();
    let retried = ok(
        data,
        &[
            "--project",
            p,
            "execution",
            "retry",
            failed["execution"].as_str().unwrap(),
        ],
    );
    assert_eq!(retried["state"], "SUCCEEDED");
    assert_eq!(retried["retry_of"], failed["execution"]);
    let logs = ok(
        data,
        &[
            "--project",
            p,
            "execution",
            "logs",
            failed["execution"].as_str().unwrap(),
        ],
    );
    assert!(!logs["events"].as_array().unwrap().is_empty());

    let escape = pack("escape");
    let escaped = ok(
        data,
        &[
            "--project",
            p,
            "execution",
            "start",
            &escape,
            "--harness",
            "escape",
            "--generation",
            "1",
        ],
    );
    assert_eq!(escaped["state"], "FAILED");
    assert!(escaped["reason"].as_str().unwrap().contains("outside.txt"));
    fs::remove_file(root.join("outside.txt")).unwrap();

    let slow = pack("slow");
    let timed_out = ok(
        data,
        &[
            "--project",
            p,
            "execution",
            "start",
            &slow,
            "--harness",
            "slow",
            "--generation",
            "1",
        ],
    );
    assert_eq!(timed_out["state"], "FAILED");
    assert!(timed_out["reason"].as_str().unwrap().contains("timed out"));

    let agent = pack("agent");
    let proposed = ok(
        data,
        &[
            "--project",
            p,
            "execution",
            "start",
            &agent,
            "--harness",
            "agent",
            "--generation",
            "1",
        ],
    );
    assert_eq!(proposed["state"], "SUCCEEDED", "{proposed}");
    assert_eq!(proposed["effects"][0]["path"], "agent.txt");

    ok(data, &["provider", "disable", "shell"]);
    let other = pack("disabled");
    let (success, _, stderr) = calve(
        data,
        &[
            "--project",
            p,
            "execution",
            "start",
            &other,
            "--harness",
            "write",
            "--generation",
            "1",
        ],
    );
    assert!(!success && stderr.contains("disabled"), "{stderr}");
    assert_eq!(ok(data, &["harness", "test", "write"])["healthy"], false);
    ok(data, &["provider", "remove", "shell", "--yes"]);
    assert_eq!(ok(data, &["provider", "list"]).as_array().unwrap().len(), 1);
}

/// `keyring:` references resolve through the credential store command at launch only.
#[test]
fn keyring_secrets_resolve_at_launch() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path();
    let store = data.join("store.sh");
    fs::write(
        &store,
        "#!/bin/sh\n[ \"$1\" = api-token ] && echo from-keyring\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_calve"))
            .env("XDG_DATA_HOME", data.join("d"))
            .env("XDG_CONFIG_HOME", data.join("c"))
            .env("CALVE_KEYRING_COMMAND", &store)
            .args(["--json", "--no-daemon-start"])
            .args(args)
            .output()
            .unwrap();
        (
            output.status.success(),
            calve_testkit::json_data(&output.stdout),
        )
    };
    let root = data.join("p");
    let p = root.to_str().unwrap();
    assert!(run(&["init", p]).0);
    let catalog = calve_testkit::ToyCatalog::new();
    assert!(
        run(&catalog
            .add_args()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>())
        .0
    );
    assert!(run(&[&["--project", p][..], &calve_testkit::ENABLE_TOY[..]].concat()).0);
    assert!(
        run(&[
            "provider",
            "add",
            "sh",
            "--kind",
            "local-process",
            "--executable",
            "sh",
            "--secret",
            "TOKEN=keyring:api-token"
        ])
        .0
    );
    assert_eq!(run(&["provider", "test", "sh"]).1["healthy"], true);
    let config = run(&["--project", p, "config", "edit-path", "--scope", "project"]).1;
    fs::write(
        config["path"].as_str().unwrap(),
        "format_version = 1\n[harnesses.w]\nprovider = \"sh\"\nmode = \"change\"\ncommand = [\"-c\", \"echo $TOKEN > t.txt\"]\n",
    )
    .unwrap();
    run(&["--project", p, "config", "approve"]);
    let pack = run(&["--project", p, "pack", "create", "t"]).1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let result = run(&[
        "--project",
        p,
        "execution",
        "start",
        &pack,
        "--harness",
        "w",
        "--generation",
        "1",
    ])
    .1;
    assert_eq!(result["state"], "SUCCEEDED", "{result}");
    assert_eq!(
        fs::read_to_string(root.join("t.txt")).unwrap(),
        "from-keyring\n"
    );
    // The secret value is not stored anywhere Calve writes configuration.
    assert!(
        !fs::read_to_string(data.join("c/calve/config.toml"))
            .unwrap()
            .contains("from-keyring")
    );
    assert!(
        run(&[
            "provider",
            "edit",
            "sh",
            "--secret",
            "TOKEN=keyring:missing"
        ])
        .0
    );
    assert_eq!(run(&["provider", "test", "sh"]).1["healthy"], false);
}

/// M6 R7: limits configured on a provider (`provider add --memory-limit-bytes`) reach the OS
/// supervisor: the same check harness passes on an unlimited provider and fails on a limited
/// one; a limit the platform cannot enforce is refused at configuration.
#[test]
#[cfg(target_os = "linux")]
fn provider_limits_reach_the_worker() {
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
    ok(
        data,
        &[
            "provider",
            "add",
            "free",
            "--kind",
            "local-process",
            "--executable",
            "sh",
        ],
    );
    ok(
        data,
        &[
            "provider",
            "add",
            "small",
            "--kind",
            "local-process",
            "--executable",
            "sh",
            "--memory-limit-bytes",
            "67108864",
        ],
    );
    let (refused, _, stderr) = calve(
        data,
        &[
            "provider",
            "add",
            "nproc",
            "--kind",
            "local-process",
            "--executable",
            "sh",
            "--process-limit",
            "4",
        ],
    );
    assert!(
        !refused && stderr.contains("CONTAINMENT_UNAVAILABLE"),
        "{stderr}"
    );
    let config = ok(
        data,
        &["--project", p, "config", "edit-path", "--scope", "project"],
    );
    let alloc = "[\"-c\", \"dd if=/dev/zero of=/dev/null bs=200M count=1\"]";
    fs::write(
        config["path"].as_str().unwrap(),
        format!(
            "format_version = 1\n[harnesses.free]\nprovider = \"free\"\nmode = \"check\"\ncommand = {alloc}\n\
             [harnesses.small]\nprovider = \"small\"\nmode = \"check\"\ncommand = {alloc}\n"
        ),
    )
    .unwrap();
    ok(data, &["--project", p, "config", "approve"]);
    for (harness, expected) in [("free", "SUCCEEDED"), ("small", "FAILED")] {
        let pack = ok(data, &["--project", p, "pack", "create", harness])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (_, run, stderr) = calve(
            data,
            &[
                "--project",
                p,
                "execution",
                "start",
                &pack,
                "--harness",
                harness,
                "--generation",
                "1",
            ],
        );
        assert_eq!(run["state"], expected, "{harness}: {run} {stderr}");
    }
}
