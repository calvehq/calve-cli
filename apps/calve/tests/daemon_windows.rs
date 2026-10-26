//! Native Windows daemon IPC (§16.2): the named pipe accepts this user's client, a daemon from
//! another image path is refused, a second daemon cannot take the pipe, and `daemon stop` uses
//! the IPC shutdown frame. Cross-built binaries carry Linux paths in `CARGO_BIN_EXE_*`, so the
//! runner points `CALVE_WIN_BIN` at the directory holding `calve.exe` and `calved.exe`.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration;

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn bin(name: &str) -> PathBuf {
    match std::env::var_os("CALVE_WIN_BIN") {
        Some(dir) => PathBuf::from(dir).join(name),
        None => PathBuf::from(match name {
            "calve.exe" => env!("CARGO_BIN_EXE_calve"),
            _ => env!("CARGO_BIN_EXE_calved"),
        }),
    }
}

fn daemon(exe: &Path, data: &Path, pipe: &str) -> Daemon {
    Daemon(
        Command::new(exe)
            .env("LOCALAPPDATA", data)
            .arg("--endpoint")
            .arg(pipe)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

fn cli(data: &Path, pipe: &str, args: &[&str]) -> Output {
    Command::new(bin("calve.exe"))
        .env("LOCALAPPDATA", data)
        .args(["--endpoint", pipe, "--json"])
        .args(args)
        .output()
        .unwrap()
}

fn data(out: &Output) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    v["data"].clone()
}

fn wait_running(data_root: &Path, pipe: &str) {
    for _ in 0..100 {
        let out = cli(data_root, pipe, &["version"]);
        if out.status.success() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("daemon on {pipe} never answered");
}

fn unique_pipe() -> String {
    format!(
        r"\\.\pipe\calve-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

#[test]
fn same_user_client_is_served_and_stop_uses_the_pipe() {
    let temp = tempfile::tempdir().unwrap();
    let pipe = unique_pipe();
    let mut d = daemon(&bin("calved.exe"), temp.path(), &pipe);
    wait_running(temp.path(), &pipe);

    // FILE_FLAG_FIRST_PIPE_INSTANCE: a second daemon cannot take the same pipe.
    let second = Command::new(bin("calved.exe"))
        .env("LOCALAPPDATA", temp.path())
        .args(["--endpoint", &pipe])
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("already running"),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let status = cli(temp.path(), &pipe, &["daemon", "status"]);
    assert_eq!(data(&status)["running"], true);

    let stopped = cli(temp.path(), &pipe, &["daemon", "stop"]);
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    let stopped = data(&stopped);
    assert_eq!(stopped["running"], false);
    assert_eq!(stopped["stopped_pid"], d.0.id().to_string());
    let exit = d.0.wait().unwrap();
    assert!(exit.success(), "{exit}");
    let after = cli(temp.path(), &pipe, &["daemon", "status"]);
    assert_eq!(data(&after)["running"], false);
}

#[test]
fn a_daemon_from_another_image_path_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let stale = temp.path().join("stale");
    std::fs::create_dir_all(&stale).unwrap();
    let copy = stale.join("calved.exe");
    std::fs::copy(bin("calved.exe"), &copy).unwrap();
    let pipe = unique_pipe();
    let _d = daemon(&copy, temp.path(), &pipe);
    let mut refused = None;
    for _ in 0..100 {
        let out = cli(temp.path(), &pipe, &["version"]);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        if stderr.contains("DAEMON_INCOMPATIBLE") {
            refused = Some(out);
            break;
        }
        assert!(!out.status.success(), "a stale daemon was trusted");
        thread::sleep(Duration::from_millis(100));
    }
    let out = refused.expect("client never reached the stale daemon");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing the daemon pipe"), "{stderr}");
    eprintln!("refusal: {stderr}");
}
