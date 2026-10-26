#![cfg(unix)]

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use calve_app::app::{Action, IntentCommand, Outcome, Request, RequestScope};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli(data: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_calve"))
        .env("XDG_DATA_HOME", data)
        .env_remove("XDG_RUNTIME_DIR")
        .env("XDG_CONFIG_HOME", data.join("config"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn daemon_ipc_and_project_writer() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let endpoint = data.join("calve/daemon.sock");
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_calved"))
            .env("XDG_DATA_HOME", &data)
            .env_remove("XDG_RUNTIME_DIR")
            .arg("--endpoint")
            .arg(&endpoint)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    for _ in 0..300 {
        if endpoint.exists() {
            break;
        }
        if let Some(status) = daemon.0.try_wait().unwrap() {
            let mut stderr = String::new();
            daemon
                .0
                .stderr
                .as_mut()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("daemon exited before binding: {status}: {stderr}");
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(endpoint.exists());

    let version = cli(
        &data,
        &[
            "--endpoint",
            endpoint.to_str().unwrap(),
            "--json",
            "version",
        ],
    );
    assert!(
        version.status.success(),
        "{}",
        String::from_utf8_lossy(&version.stderr)
    );
    let version = calve_testkit::json_data(&version.stdout);
    assert_eq!(version["api_version"], 1);

    let mut socket = UnixStream::connect(&endpoint).unwrap();
    let hello =
        serde_json::json!({"kind":"hello","payload":{"api_version":999,"product_version":"test"}})
            .to_string();
    socket
        .write_all(&(hello.len() as u32).to_be_bytes())
        .unwrap();
    socket.write_all(hello.as_bytes()).unwrap();
    let mut size = [0; 4];
    socket.read_exact(&mut size).unwrap();
    let mut body = vec![0; u32::from_be_bytes(size) as usize];
    socket.read_exact(&mut body).unwrap();
    let ack: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ack["payload"]["accepted"], false);

    let second = Command::new(env!("CARGO_BIN_EXE_calved"))
        .arg("--endpoint")
        .arg(&endpoint)
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already running"));

    let project = temp.path().join("project");
    let init = cli(&data, &["--json", "init", project.to_str().unwrap()]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let request = Request::local(
        RequestScope {
            project: Some(project.clone()),
            workspace: None,
            config_file: None,
            actor: None,
        },
        Action::Intent {
            command: IntentCommand::Create {
                title: "once".into(),
                description: None,
                tags: vec![],
                actors: vec![],
                graph_node: None,
            },
        },
    );
    let first = runtime
        .block_on(calve_ipc::request(&endpoint, request.clone()))
        .unwrap();
    let repeated = runtime
        .block_on(calve_ipc::request(&endpoint, request.clone()))
        .unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&repeated).unwrap()
    );
    assert!(matches!(first.outcome, Outcome::Ok { .. }));
    let mut reused = request;
    reused.action = Action::Intent {
        command: IntentCommand::Create {
            title: "changed".into(),
            description: None,
            tags: vec![],
            actors: vec![],
            graph_node: None,
        },
    };
    let rejected = runtime
        .block_on(calve_ipc::request(&endpoint, reused))
        .unwrap();
    match rejected.outcome {
        Outcome::Error { error } => assert_eq!(error.code, "REQUEST_ID_REUSED"),
        Outcome::Ok { .. } => panic!("reused request ID was accepted"),
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(project.join(".calve/writer.lock"))
        .unwrap_or_else(|_| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(project.join(".calve/writer.lock"))
                .unwrap()
        });
    lock.try_lock().unwrap();
    let blocked = cli(
        &data,
        &[
            "--direct",
            "--project",
            project.to_str().unwrap(),
            "intent",
            "create",
            "blocked",
        ],
    );
    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("PROJECT_LOCKED"));
    drop(lock);
    let created = cli(
        &data,
        &[
            "--project",
            project.to_str().unwrap(),
            "--json",
            "intent",
            "create",
            "works",
        ],
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created = calve_testkit::json_data(&created.stdout);
    assert!(created["id"].is_string());
    let signal = Command::new("kill")
        .arg("-TERM")
        .arg(daemon.0.id().to_string())
        .status()
        .unwrap();
    assert!(signal.success());
    for _ in 0..150 {
        if daemon.0.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        daemon.0.try_wait().unwrap().is_some(),
        "daemon did not stop on SIGTERM"
    );
    assert!(
        !endpoint.exists(),
        "daemon left its endpoint after graceful shutdown"
    );
}

#[test]
fn daemon_rejects_public_socket_directory_without_changing_it() {
    let temp = tempfile::tempdir().unwrap();
    let public = temp.path().join("public");
    std::fs::create_dir(&public).unwrap();
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_calved"))
        .arg("--endpoint")
        .arg(public.join("daemon.sock"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("directory must be private"));
    assert_eq!(
        std::fs::metadata(&public).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

/// `daemon stop` asks over the authenticated IPC (no signal, no kill(1)): the daemon acks with
/// its pid, finishes, and removes its socket.
#[test]
fn daemon_stop_uses_the_ipc_shutdown_frame() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let endpoint = data.join("calve/daemon.sock");
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_calved"))
            .env("XDG_DATA_HOME", &data)
            .env_remove("XDG_RUNTIME_DIR")
            .arg("--endpoint")
            .arg(&endpoint)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..300 {
        if endpoint.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let stopped = cli(
        &data,
        &[
            "--endpoint",
            endpoint.to_str().unwrap(),
            "--json",
            "daemon",
            "stop",
        ],
    );
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    let stopped = calve_testkit::json_data(&stopped.stdout);
    assert_eq!(stopped["running"], false);
    assert_eq!(stopped["stopped_pid"], daemon.0.id().to_string());
    let status = daemon.0.wait().unwrap();
    assert!(status.success(), "{status}");
    assert!(!endpoint.exists());
}
