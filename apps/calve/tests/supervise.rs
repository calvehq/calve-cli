//! Unix supervision (rev 10 §16.3, ADR 0017, N32/N41/N48/N61/N72): one process group per
//! worker under `calve __exec-confined`, result before the group kill, PDEATHSIG and its race,
//! the fallback result file under Landlock, termination classification, reaping, and the
//! residuals that are asserted rather than hidden.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use calve_app::supervise::{Supervised, Termination};

/// Runs `name` in a child process of this test binary with private data and runtime dirs.
fn isolated(name: &str, extra: &[(&str, &str)]) -> (bool, PathBuf, tempfile::TempDir) {
    let t = tempfile::tempdir().unwrap();
    // As in production, the runtime directory lies outside the worker's directory, temp and home
    // (otherwise Landlock could not hide the spawn records). Left behind on purpose: tmpfs.
    // /dev/shm stands in for /run/user/<uid> (absent without a systemd login session).
    let run = PathBuf::from("/dev/shm").join(format!(
        "ct-{}",
        &uuid::Uuid::now_v7().simple().to_string()[24..]
    ));
    fs::create_dir(&run).unwrap();
    let _ = fs::create_dir(t.path().join("run"));
    std::os::unix::fs::symlink(&run, t.path().join("run/rt")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--nocapture"])
        .env("CALVE_ISOLATED_TEST", "1")
        .env("XDG_DATA_HOME", t.path().join("data"))
        .env("XDG_CONFIG_HOME", t.path().join("config"))
        .env("XDG_RUNTIME_DIR", &run)
        .env("CALVE_SANDBOX_PROGRAM", env!("CARGO_BIN_EXE_calve"))
        .env("CALVE_KEEP_SPAWN_RECORDS", "1")
        .env("WORK", t.path())
        .envs(extra.iter().copied())
        .status()
        .unwrap();
    (status.success(), t.path().to_owned(), t)
}

fn inside() -> bool {
    std::env::var_os("CALVE_ISOLATED_TEST").is_some()
}

fn work() -> PathBuf {
    PathBuf::from(std::env::var_os("WORK").unwrap())
}

fn env() -> Vec<(&'static str, &'static str)> {
    vec![("PATH", "/usr/local/bin:/usr/bin:/bin")]
}

fn sh(script: &str) -> Vec<String> {
    vec!["/bin/sh".into(), "-c".into(), script.into()]
}

fn alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", "--", pid])
        .status()
        .unwrap()
        .success()
}

fn group_alive(pgid: i32) -> bool {
    alive(&format!("-{pgid}"))
}

fn eventually(mut f: impl FnMut() -> bool, secs: u64) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn spawn_dir(root: &Path) -> PathBuf {
    let run = root.join("run/rt/calve");
    let key = fs::read_dir(&run).unwrap().next().unwrap().unwrap().path();
    key.join("spawn")
}

fn journal_kinds(dir: &Path) -> Vec<String> {
    let j = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "journal"))
        .expect("a spawn journal");
    fs::read_to_string(j)
        .unwrap()
        .lines()
        .skip(1)
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn normal_exit_reports_before_the_group_is_killed() {
    if inside() {
        let w = work();
        let mut s = Supervised::spawn(
            &sh(&format!(
                "sleep 60 & echo $! > {}/grandchild; exit 3",
                w.display()
            )),
            &env(),
            &w,
        )
        .unwrap();
        let t = s.wait().unwrap();
        assert_eq!(
            t,
            Termination::Finished {
                exit_code: Some(3),
                signal: None
            }
        );
        let gc = fs::read_to_string(w.join("grandchild")).unwrap();
        assert!(
            eventually(|| !alive(gc.trim()), 5),
            "the grandchild went with the group"
        );
        return;
    }
    let (ok, root, _t) = isolated("normal_exit_reports_before_the_group_is_killed", &[]);
    assert!(ok);
    let kinds = journal_kinds(&spawn_dir(&root));
    assert_eq!(
        kinds,
        ["spawned", "result", "helper_exit"],
        "result journaled and acked before the helper's own group kill"
    );
}

#[test]
fn cancellation_kills_helper_worker_and_double_forked_grandchild() {
    if inside() {
        let w = work();
        let mut s = Supervised::spawn(
            &sh(&format!(
                "(sh -c 'sleep 60 & echo $! > {0}/gc; wait') & echo $$ > {0}/worker; wait",
                w.display()
            )),
            &env(),
            &w,
        )
        .unwrap();
        assert!(eventually(
            || w.join("gc").exists() && w.join("worker").exists(),
            10
        ));
        let pgid = s.child.id() as i32;
        assert_eq!(s.cancel().unwrap(), Termination::Cancelled);
        assert!(eventually(|| !group_alive(pgid), 5));
        for f in ["gc", "worker"] {
            let pid = fs::read_to_string(w.join(f)).unwrap();
            assert!(eventually(|| !alive(pid.trim()), 5), "{f}");
        }
        return;
    }
    let (ok, root, _t) = isolated(
        "cancellation_kills_helper_worker_and_double_forked_grandchild",
        &[],
    );
    assert!(ok);
    assert_eq!(
        journal_kinds(&spawn_dir(&root)),
        ["spawned", "cancel_intent", "cancelled"]
    );
}

/// The parent dies (abort) while the worker runs: PDEATHSIG makes the helper kill the group.
#[test]
fn parent_death_kills_the_whole_group() {
    if inside() {
        let w = work();
        let s = Supervised::spawn(
            &sh(&format!("sleep 60 & echo $! > {}/gc; wait", w.display())),
            &env(),
            &w,
        )
        .unwrap();
        fs::write(w.join("pgid"), s.child.id().to_string()).unwrap();
        assert!(eventually(|| w.join("gc").exists(), 10));
        std::process::abort();
    }
    let (ok, root, _t) = isolated("parent_death_kills_the_whole_group", &[]);
    assert!(!ok, "the parent aborted");
    let pgid: i32 = fs::read_to_string(root.join("pgid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(
        eventually(|| !group_alive(pgid), 10),
        "PDEATHSIG → helper → group kill"
    );
}

/// The parent dies before the helper registers PDEATHSIG (delay injected): the helper's
/// getppid check kills the group and the worker never starts.
#[test]
fn the_pdeathsig_registration_race_is_closed() {
    if inside() {
        let w = work();
        let mut e = env();
        e.push(("CALVE_HELPER_DELAY_MS", "1500"));
        // The parent dies while the helper is still before its PDEATHSIG registration.
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(400));
            std::process::abort();
        });
        let _ = Supervised::spawn(
            &sh(&format!("touch {}/started; sleep 60", w.display())),
            &e,
            &w,
        );
        std::thread::sleep(Duration::from_secs(10));
        return;
    }
    let (ok, root, _t) = isolated("the_pdeathsig_registration_race_is_closed", &[]);
    assert!(!ok);
    let j = fs::read_dir(spawn_dir(&root))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "journal"))
        .unwrap();
    let header: serde_json::Value =
        serde_json::from_str(fs::read_to_string(j).unwrap().lines().next().unwrap()).unwrap();
    let pgid = header["binding"]["pgid"].as_i64().unwrap() as i32;
    assert!(
        eventually(|| !group_alive(pgid), 10),
        "the helper saw a foreign parent and ended its group"
    );
    std::thread::sleep(Duration::from_millis(500));
    assert!(!root.join("started").exists(), "the worker never ran");
}

/// The parent is alive but never acks (stuck): after the timeout the helper writes the result
/// through the file it opened before Landlock, then ends its group. The worker could neither
/// open that file nor see the descriptor.
#[test]
fn without_an_ack_the_result_goes_through_the_file_under_landlock() {
    if inside() {
        let w = work();
        let dir = calve_app::supervise::spawn_dir().unwrap();
        let script = format!(
            "for f in {d}/*.result; do cat \"$f\" >/dev/null 2>&1 && echo read >> {w}/probe; echo x 2>/dev/null >> \"$f\" && echo wrote >> {w}/probe; done; ls -l /proc/self/fd/ > {w}/fds; exit 7",
            d = dir.display(),
            w = w.display()
        );
        let mut s = Supervised::spawn(&sh(&script), &env(), &w).unwrap();
        assert_eq!(
            s.wait().unwrap(),
            Termination::Finished {
                exit_code: Some(7),
                signal: None
            }
        );
        let result = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "result"))
            .unwrap();
        let written = fs::read_to_string(result).unwrap();
        assert!(
            written.contains("\"exit_code\":7"),
            "the helper used the file: {written}"
        );
        return;
    }
    let (ok, root, _t) = isolated(
        "without_an_ack_the_result_goes_through_the_file_under_landlock",
        &[("CALVE_SUPERVISE_NO_ACK", "1")],
    );
    assert!(ok);
    let fds = fs::read_to_string(root.join("fds")).unwrap();
    assert!(
        !fds.contains(".result"),
        "the worker never holds the result file: {fds}"
    );
    let probe = fs::read_to_string(root.join("probe")).unwrap_or_default();
    assert!(
        probe.is_empty(),
        "Landlock hides the spawn directory from the worker: {probe}"
    );
}

/// The helper is SIGKILLed from outside: no result (HELPER_LOST), and the orphaned rest of its
/// group is ended right away.
#[test]
fn a_killed_helper_is_lost_and_its_orphaned_group_ended() {
    if inside() {
        let w = work();
        let mut s = Supervised::spawn(
            &sh(&format!("sleep 60 & echo $! > {}/gc; wait", w.display())),
            &env(),
            &w,
        )
        .unwrap();
        assert!(eventually(|| w.join("gc").exists(), 10));
        let pgid = s.child.id() as i32;
        assert!(
            Command::new("kill")
                .args(["-KILL", &pgid.to_string()])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(s.wait().unwrap(), Termination::HelperLost);
        let gc = fs::read_to_string(w.join("gc")).unwrap();
        assert!(
            eventually(|| !alive(gc.trim()), 5),
            "no straggler outlives a lost helper"
        );
        return;
    }
    let (ok, root, _t) = isolated("a_killed_helper_is_lost_and_its_orphaned_group_ended", &[]);
    assert!(ok);
    assert_eq!(journal_kinds(&spawn_dir(&root)), ["spawned", "lost"]);
}

/// A descendant that calls setsid leaves the group and survives cancellation (residual).
#[test]
fn a_setsid_descendant_escapes_cancellation() {
    if inside() {
        let w = work();
        let mut s = Supervised::spawn(
            &sh(&format!(
                "setsid sh -c 'echo $$ > {}/escaped; sleep 60' & wait",
                w.display()
            )),
            &env(),
            &w,
        )
        .unwrap();
        assert!(eventually(|| w.join("escaped").exists(), 10));
        s.cancel().unwrap();
        let pid = fs::read_to_string(w.join("escaped")).unwrap();
        assert!(
            alive(pid.trim()),
            "residual asserted: setsid escapes the group"
        );
        let _ = Command::new("kill").args(["-KILL", pid.trim()]).status();
        return;
    }
    assert!(isolated("a_setsid_descendant_escapes_cancellation", &[]).0);
}

/// Reaping only kills a recorded group when its helper is still the same process (start time):
/// a reused PID is never killed. A record whose parent is alive is never reaped.
#[test]
fn reaping_checks_parent_and_start_time() {
    if inside() {
        let w = work();
        let dir = calve_app::supervise::spawn_dir().unwrap();
        // A victim process standing in for "a reused PID".
        let mut victim = Command::new("sleep")
            .arg("60")
            .process_group_compat()
            .spawn()
            .unwrap();
        let pid = victim.id() as i32;
        // A record whose id is not ours, or does not match its file name, is never acted on
        // (its id names files reaping would delete).
        let traversal = calve_app::journal::Journal::create(
            &dir.join("ffffffffffffffffffffffffffffffff.journal"),
            "spawn",
            "../../../victim",
            serde_json::json!({"pgid": 1, "helper_pid": 1, "start_time": "1", "parent_pid": 999_999_999, "parent_start_time": "1"}),
        )
        .unwrap();
        drop(traversal);
        let id = "0123456789abcdef0123456789abcdef";
        let forged = calve_app::journal::Journal::create(
            &dir.join(format!("{id}.journal")),
            "spawn",
            id,
            serde_json::json!({"pgid": pid, "helper_pid": pid, "start_time": "1",
                "parent_pid": 999_999_999, "parent_start_time": "1", "program": "x"}),
        )
        .unwrap();
        drop(forged);
        let reaped = calve_app::supervise::reap().unwrap();
        assert_eq!(reaped.len(), 1);
        assert_eq!(
            reaped[0]["killed"], false,
            "start time differs: not the recorded helper"
        );
        assert!(alive(&pid.to_string()));
        let _ = victim.kill();
        let _ = victim.wait();
        // A live parent's record is left alone.
        let mut s = Supervised::spawn(&sh("sleep 60"), &env(), &w).unwrap();
        assert!(calve_app::supervise::reap().unwrap().is_empty());
        s.cancel().unwrap();
        return;
    }
    assert!(isolated("reaping_checks_parent_and_start_time", &[]).0);
}

trait GroupCompat {
    fn process_group_compat(&mut self) -> &mut Self;
}

impl GroupCompat for Command {
    fn process_group_compat(&mut self) -> &mut Self {
        use std::os::unix::process::CommandExt;
        self.process_group(0)
    }
}

/// The worker's own program may live outside every read-write root (a provider installed in
/// /srv, a volume, a temp dir): it is readable and executable, nothing more.
#[test]
fn a_program_outside_every_root_runs_but_cannot_write_beside_itself() {
    if inside() {
        let w = work();
        let bin = PathBuf::from("/dev/shm").join(format!(
            "cp-{}",
            &uuid::Uuid::now_v7().simple().to_string()[24..]
        ));
        fs::create_dir(&bin).unwrap();
        let prog = bin.join("prog.sh");
        fs::write(
            &prog,
            format!(
                "#!/bin/sh\necho ran > {w}/ran\necho x 2>/dev/null > {b}/x\nexit 0\n",
                w = w.display(),
                b = bin.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&prog, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut s = Supervised::spawn(&[prog.display().to_string()], &env(), &w).unwrap();
        let end = s.wait().unwrap();
        let wrote_beside = bin.join("x").exists();
        fs::remove_dir_all(&bin).unwrap();
        assert_eq!(
            end,
            Termination::Finished {
                exit_code: Some(0),
                signal: None
            }
        );
        assert!(w.join("ran").exists(), "the program did not run");
        assert!(!wrote_beside, "the program wrote beside itself");
        return;
    }
    let (ok, _, _t) = isolated(
        "a_program_outside_every_root_runs_but_cannot_write_beside_itself",
        &[],
    );
    assert!(ok);
}

/// M6 R7: a provider's resource limits reach the OS. Under the real helper and Landlock, a
/// 200 MB allocation succeeds unlimited and fails under a 64 MiB memory limit; a busy loop is
/// stopped by a 1-second CPU limit; a process-count limit is refused on Unix, never ignored.
#[test]
fn provider_resource_limits_are_enforced_by_the_os() {
    if inside() {
        use calve_app::config::ResourceLimits;
        let w = work();
        let alloc = sh("dd if=/dev/zero of=/dev/null bs=200M count=1 2>/dev/null");
        let mut free = Supervised::spawn(&alloc, &env(), &w).unwrap();
        assert_eq!(
            free.wait().unwrap(),
            Termination::Finished {
                exit_code: Some(0),
                signal: None
            },
            "unlimited: the allocation succeeds"
        );
        let memory = ResourceLimits {
            memory_bytes: Some(64 * 1024 * 1024),
            ..Default::default()
        };
        let mut limited = Supervised::spawn_limited(&alloc, &env(), &w, &memory).unwrap();
        match limited.wait().unwrap() {
            Termination::Finished { exit_code, .. } => {
                assert_ne!(exit_code, Some(0), "64 MiB: the allocation fails")
            }
            other => panic!("{other:?}"),
        }
        let cpu = ResourceLimits {
            cpu_seconds: Some(1),
            ..Default::default()
        };
        let started = Instant::now();
        let mut spin =
            Supervised::spawn_limited(&sh("while :; do :; done"), &env(), &w, &cpu).unwrap();
        match spin.wait().unwrap() {
            Termination::Finished { exit_code, signal } => assert!(
                signal.is_some() || exit_code.is_some_and(|c| c != 0),
                "stopped by the CPU limit: {exit_code:?} {signal:?}"
            ),
            other => panic!("{other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(30));
        let processes = ResourceLimits {
            processes: Some(4),
            ..Default::default()
        };
        let refused = Supervised::spawn_limited(&sh("true"), &env(), &w, &processes);
        assert!(
            refused.is_err(),
            "a process limit Unix cannot bound is refused"
        );
        return;
    }
    let (ok, _root, _t) = isolated("provider_resource_limits_are_enforced_by_the_os", &[]);
    assert!(ok);
}
