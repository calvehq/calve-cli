//! Supervisor sockets live in a short, private, per-user directory (`calve_app::paths::
//! socket_dir`): a worker starts however deep the data root is (macOS limits a socket path to
//! 104 bytes), concurrent spawns never collide or leave sockets behind, and sockets a dead
//! supervisor left are swept.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use calve_app::supervise::{Supervised, Termination};
use calve_testkit::Isolated;

/// Where the child's `XDG_RUNTIME_DIR` points.
#[derive(Clone, Copy)]
enum Runtime {
    /// None, as on macOS.
    Unset,
    /// A directory of its own (on macOS under the long `$TMPDIR`, so it may not fit).
    Own,
    /// One too deep for any socket path: Calve must fall back to `/tmp`.
    TooDeep,
}

/// Runs `name` in a child of this test binary with a data root `depth` bytes deep and the given
/// runtime directory.
fn isolated(name: &str, depth: usize, runtime: Runtime) -> bool {
    let t = tempfile::tempdir().unwrap();
    let mut data = t.path().join("data");
    while data.as_os_str().len() < depth {
        data.push("deeper-than-any-socket-path-may-be");
    }
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([name, "--exact", "--nocapture"])
        .env("CALVE_ISOLATED_TEST", "1")
        .isolated(&data, t.path().join("config"))
        .env("CALVE_SANDBOX_PROGRAM", env!("CARGO_BIN_EXE_calve"))
        .env("WORK", t.path());
    match runtime {
        Runtime::Unset => {
            cmd.env_remove("XDG_RUNTIME_DIR");
        }
        Runtime::Own | Runtime::TooDeep => {
            let mut run = t.path().join("run");
            if matches!(runtime, Runtime::TooDeep) {
                run.push("x".repeat(110));
                cmd.env("EXPECT_TMP", "1");
            }
            std::fs::create_dir_all(&run).unwrap();
            cmd.env("XDG_RUNTIME_DIR", &run);
        }
    }
    cmd.status().unwrap().success()
}

fn inside() -> bool {
    std::env::var_os("CALVE_ISOLATED_TEST").is_some()
}

fn work() -> PathBuf {
    PathBuf::from(std::env::var_os("WORK").unwrap())
}

fn run_ok(script: &str) {
    let argv: Vec<String> = vec!["/bin/sh".into(), "-c".into(), script.into()];
    let env = [("PATH", "/usr/local/bin:/usr/bin:/bin")];
    let mut s = Supervised::spawn(&argv, &env, &work()).unwrap();
    assert_eq!(
        s.wait().unwrap(),
        Termination::Finished {
            exit_code: Some(0),
            signal: None
        }
    );
}

fn sockets(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sock"))
        .collect()
}

#[test]
fn a_worker_starts_under_a_deep_data_root() {
    if inside() {
        let data = calve_app::paths::data_root().unwrap();
        assert!(data.as_os_str().len() >= 300, "{}", data.display());
        let dir = calve_app::paths::socket_dir().unwrap();
        // The longest socket path: the directory and a 16-hex name with ".sock".
        assert!(dir.as_os_str().len() + 1 + 21 < 104, "{}", dir.display());
        if std::env::var_os("EXPECT_TMP").is_some() {
            assert!(dir.starts_with("/tmp"), "{}", dir.display());
        }
        run_ok("exit 0");
        return;
    }
    for runtime in [Runtime::Own, Runtime::Unset, Runtime::TooDeep] {
        assert!(isolated(
            "a_worker_starts_under_a_deep_data_root",
            300,
            runtime
        ));
    }
}

#[test]
fn concurrent_spawns_get_their_own_sockets_and_leave_none() {
    if inside() {
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| run_ok("sleep 0.2"));
            }
        });
        let dir = calve_app::paths::socket_dir().unwrap();
        assert!(sockets(&dir).is_empty(), "{:?}", sockets(&dir));
        return;
    }
    assert!(isolated(
        "concurrent_spawns_get_their_own_sockets_and_leave_none",
        0,
        Runtime::Own
    ));
}

#[test]
fn sockets_a_dead_supervisor_left_are_swept() {
    if inside() {
        let dir = calve_app::paths::socket_dir().unwrap();
        let old = dir.join("0000000000000000.sock");
        let recent = dir.join("1111111111111111.sock");
        for p in [&old, &recent] {
            std::fs::write(p, "").unwrap();
        }
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        run_ok("exit 0");
        assert!(!old.exists(), "an hour-old socket is a leftover");
        assert!(
            recent.exists(),
            "a recent one may belong to a spawn in progress"
        );
        std::fs::remove_file(&recent).unwrap();
        return;
    }
    assert!(isolated(
        "sockets_a_dead_supervisor_left_are_swept",
        0,
        Runtime::Own
    ));
}
