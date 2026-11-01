//! Supervised child processes (rev 10 §16.3, ADR 0017).
//!
//! Unix: the parent spawns `calve __exec-confined` as the leader of a new process group; the
//! helper sets PDEATHSIG, closes the registration race, kills its group on SIGTERM/SIGINT/SIGHUP,
//! applies Landlock (Linux), runs the worker inside its group and **reports the result before
//! killing the group**: over a Unix socket the parent acks after journaling it, or, if the parent
//! is gone, through a result file the helper opened before Landlock (CLOEXEC, so the worker never
//! holds it). Every spawn has a journal in the runtime directory (`spawn/<id>.journal`), so a
//! restarted parent reaps groups whose parent died. Processes that leave the group (`setsid`,
//! `setpgid`) or are started by other services are not contained (asserted residual).
//!
//! Windows: the child is created suspended, assigned to a parent-owned Job Object
//! (`KILL_ON_JOB_CLOSE`, never inheritable or duplicated) and resumed; cancellation terminates
//! the job (`calve-win-sec`).
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde_json::Value;

use crate::{Error, Result};

/// The hidden helper mode: `calve __exec-confined <parent pid> <spawn dir> <id> -- <argv>`.
pub const HELPER_MODE: &str = "__exec-confined";
/// Trampoline that sets the worker's resource limits on itself, then becomes the worker.
pub const RLIMIT_MODE: &str = "__exec-limited";

/// How a supervised process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Termination {
    /// The worker finished; the result was reported before the group was killed.
    Finished {
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    /// Cancelled by the parent (journaled before the group kill).
    Cancelled,
    /// The helper died without a result (killed externally, crashed).
    HelperLost,
}

pub struct Supervised {
    /// The helper (Unix) or the worker itself (Windows). Its stdio are the worker's.
    pub child: Child,
    #[cfg(unix)]
    inner: unix::Inner,
    #[cfg(windows)]
    job: calve_win_sec::Job,
}

fn coded(code: &'static str, m: impl Into<String>) -> Error {
    crate::coded(code, m)
}

/// `<runtime dir>/spawn`, owner-only.
pub fn spawn_dir() -> Result<PathBuf> {
    let dir = crate::registry::runtime_dir()?.join("spawn");
    // Every directory created here is private: the runtime directory also holds the daemon
    // socket, which refuses a directory others can read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    crate::journal::private_dir(&dir)?;
    Ok(dir)
}

impl Supervised {
    /// Spawns `argv` in `cwd` with exactly `env`, stdio piped, under supervision.
    pub fn spawn(argv: &[String], env: &[(&str, &str)], cwd: &Path) -> Result<Self> {
        Self::spawn_limited(argv, env, cwd, &Default::default())
    }

    /// As [`Supervised::spawn`], with OS-enforced resource limits on the worker.
    pub fn spawn_limited(
        argv: &[String],
        env: &[(&str, &str)],
        cwd: &Path,
        limits: &crate::config::ResourceLimits,
    ) -> Result<Self> {
        if argv.is_empty() {
            return Err(coded("INVALID_ARGUMENT", "empty command"));
        }
        #[cfg(unix)]
        return unix::spawn(argv, env, cwd, limits);
        #[cfg(windows)]
        return windows::spawn(argv, env, cwd, limits);
    }

    /// Waits for the end and classifies it.
    pub fn wait(&mut self) -> Result<Termination> {
        #[cfg(unix)]
        return unix::wait(self);
        #[cfg(windows)]
        return windows::wait(self);
    }

    /// Cancels: journaled first, then the whole group (job) is killed.
    pub fn cancel(&mut self) -> Result<Termination> {
        #[cfg(unix)]
        return unix::cancel(self);
        #[cfg(windows)]
        return windows::cancel(self);
    }
}

#[cfg(unix)]
mod unix {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{Duration, Instant};

    use serde_json::json;

    use crate::journal::Journal;

    /// How long the helper waits for the parent's ack before using the result file.
    const ACK_TIMEOUT: Duration = Duration::from_secs(5);

    fn jerr(e: crate::journal::Error) -> Error {
        coded("RECOVERY_REQUIRED", format!("spawn journal: {e}"))
    }
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    use rustix::process::{Pid, Signal, kill_process_group};

    use super::*;

    pub struct Inner {
        pub id: String,
        pub dir: PathBuf,
        pub pgid: i32,
        pub journal: Journal,
        pub conn: Option<UnixStream>,
        pub done: Option<Termination>,
    }

    /// Start time of `pid` (clock ticks since boot on Linux, `ps` lstart on macOS); `None` when
    /// the process is gone.
    pub fn start_time(pid: i32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // Field 22, counted after the parenthesized command (which may contain spaces).
            let rest = &stat[stat.rfind(')')? + 2..];
            rest.split(' ').nth(19).map(str::to_owned)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let out = Command::new("ps")
                .args(["-o", "lstart=", "-p", &pid.to_string()])
                .output()
                .ok()?;
            let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            (!s.is_empty()).then_some(s)
        }
    }

    /// Whether Landlock can hide the spawn directory from this worker: it lies outside the
    /// worker's read-write roots (directory, temp, home). Linux only.
    fn result_hidden(dir: &Path, cwd: &Path, env: &[(&str, &str)]) -> bool {
        let var = |k: &str| {
            env.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        };
        cfg!(target_os = "linux")
            && !rw_roots(Some(cwd), var("TMPDIR"), var("HOME"))
                .iter()
                .any(|r| dir.starts_with(r))
    }

    /// The worker's read-write roots, from its own environment (the helper runs with exactly
    /// that environment, so the parent's `result_hidden` and the helper's Landlock rules agree).
    /// The worker's read-write roots. Fails closed: an unknown cwd, an empty or relative path,
    /// or `/` itself is left out rather than widening the rule.
    pub(super) fn rw_roots(
        cwd: Option<&Path>,
        tmpdir: Option<String>,
        home: Option<String>,
    ) -> Vec<PathBuf> {
        let tmp = tmpdir
            .filter(|t| !t.is_empty())
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        [
            Some(tmp),
            cwd.map(Path::to_path_buf),
            home.map(PathBuf::from),
        ]
        .into_iter()
        .flatten()
        .filter(|p| p.is_absolute() && p.parent().is_some())
        .collect()
    }

    fn kill_group(pgid: i32) {
        if let Some(p) = Pid::from_raw(pgid) {
            let _ = kill_process_group(p, Signal::KILL);
        }
    }

    pub fn spawn(
        argv: &[String],
        env: &[(&str, &str)],
        cwd: &Path,
        limits: &crate::config::ResourceLimits,
    ) -> Result<Supervised> {
        if limits.processes.is_some() {
            return Err(coded(
                "CONTAINMENT_UNAVAILABLE",
                "a per-worker process limit cannot be enforced on this platform",
            ));
        }
        let dir = spawn_dir()?;
        let id = uuid::Uuid::now_v7().simple().to_string();
        let sock = dir.join(format!("{id}.sock"));
        let listener = UnixListener::bind(&sock).map_err(|e| {
            coded(
                "CONTAINMENT_UNAVAILABLE",
                format!("supervisor socket {}: {e}", sock.display()),
            )
        })?;
        listener.set_nonblocking(true)?;
        let exe = crate::sandbox::sandbox_program()
            .map_err(|e| coded("CONTAINMENT_UNAVAILABLE", format!("{e:?}")))?;
        let mut child = Command::new(exe)
            .arg(HELPER_MODE)
            .arg(std::process::id().to_string())
            .arg(&dir)
            .arg(&id)
            .arg(limit_arg(limits))
            .arg("--")
            .args(argv)
            .current_dir(cwd)
            .env_clear()
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()?;
        let pgid = child.id() as i32;
        let mut journal = Journal::create(
            &dir.join(format!("{id}.journal")),
            "spawn",
            &id,
            json!({"pgid": pgid, "helper_pid": pgid, "start_time": start_time(pgid),
                "parent_pid": std::process::id(), "parent_start_time": start_time(std::process::id() as i32),
                "program": argv[0], "result_hidden": result_hidden(&dir, cwd, env)}),
        )
        .map_err(jerr)?;
        journal
            .append("spawned", json!({"pgid": pgid}))
            .map_err(jerr)?;
        // The helper connects first thing; a helper that dies before is lost.
        let started = Instant::now();
        let conn = loop {
            match listener.accept() {
                // Linux: only the helper may report (any other same-user connector is dropped).
                #[cfg(target_os = "linux")]
                Ok((s, _))
                    if rustix::net::sockopt::socket_peercred(&s)
                        .map(|c| c.pid.as_raw_nonzero().get())
                        .ok()
                        != Some(pgid) =>
                {
                    drop(s);
                    continue;
                }
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if child.try_wait()?.is_some() || started.elapsed() > Duration::from_secs(30) {
                        kill_group(pgid);
                        let _ = child.wait();
                        let _ = journal.append("lost", json!({"reason": "helper did not connect"}));
                        return Err(coded(
                            "CONTAINMENT_UNAVAILABLE",
                            "the supervisor helper did not start",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e.into()),
            }
        };
        let _ = std::fs::remove_file(&sock);
        conn.set_nonblocking(false)?;
        Ok(Supervised {
            child,
            inner: Inner {
                id,
                dir,
                pgid,
                journal,
                conn: Some(conn),
                done: None,
            },
        })
    }

    fn finish(s: &mut Supervised, t: Termination) -> Result<Termination> {
        let kind = match &t {
            Termination::Finished { .. } => "result",
            Termination::Cancelled => "cancelled",
            Termination::HelperLost => "lost",
        };
        if kind != "result" {
            s.inner.journal.append(kind, json!({})).map_err(jerr)?;
        }
        // Debug builds: tests read the records afterwards.
        if !(cfg!(debug_assertions) && std::env::var_os("CALVE_KEEP_SPAWN_RECORDS").is_some()) {
            cleanup(&s.inner.dir, &s.inner.id);
        }
        s.inner.done = Some(t.clone());
        Ok(t)
    }

    pub fn cleanup(dir: &Path, id: &str) {
        for suffix in ["journal", "result", "sock"] {
            let _ = std::fs::remove_file(dir.join(format!("{id}.{suffix}")));
        }
    }

    fn parse_result(v: &Value) -> Termination {
        Termination::Finished {
            exit_code: v["exit_code"].as_i64().map(|c| c as i32),
            signal: v["signal"].as_i64().map(|c| c as i32),
        }
    }

    pub fn wait(s: &mut Supervised) -> Result<Termination> {
        if let Some(t) = &s.inner.done {
            return Ok(t.clone());
        }
        let mut line = String::new();
        let got = match s.inner.conn.take() {
            Some(conn) => {
                let mut r = BufReader::new(conn.try_clone()?);
                let n = r.read_line(&mut line).unwrap_or(0);
                (n > 0).then(|| (conn, serde_json::from_str::<Value>(line.trim())))
            }
            None => None,
        };
        if let Some((mut conn, Ok(result))) = got {
            // Journaled (fsync) before the ack: only then may the helper kill its group.
            s.inner
                .journal
                .append("result", result.clone())
                .map_err(jerr)?;
            crate::journal::fault("supervise.before_ack");
            // Debug builds: a parent that never acks (its helper must use the result file).
            if !(cfg!(debug_assertions) && std::env::var_os("CALVE_SUPERVISE_NO_ACK").is_some()) {
                let _ = conn.write_all(b"ack\n");
            }
            let status = s.child.wait()?;
            s.inner
                .journal
                .append(
                    "helper_exit",
                    json!({"signal": status.signal(), "code": status.code()}),
                )
                .map_err(jerr)?;
            return finish(s, parse_result(&result));
        }
        let _ = s.child.wait();
        let records = Journal::open(&s.inner.dir.join(format!("{}.journal", s.inner.id)))
            .map(|o| o.records)
            .unwrap_or_default();
        if records.iter().any(|r| r.kind == "cancel_intent") {
            return finish(s, Termination::Cancelled);
        }
        // The helper reported through its result file (no ack arrived).
        let fallback = std::fs::read_to_string(s.inner.dir.join(format!("{}.result", s.inner.id)));
        if let Some(v) = fallback
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(t.lines().last().unwrap_or("")).ok())
        {
            s.inner
                .journal
                .append("result", json!({"fallback": true, "result": v}))
                .map_err(jerr)?;
            return finish(s, parse_result(&v));
        }
        // The helper is gone but its group may not be: the kernel never reuses a PID as a group
        // id while members remain, so the orphaned group is ours to end.
        kill_group(s.inner.pgid);
        finish(s, Termination::HelperLost)
    }

    pub fn cancel(s: &mut Supervised) -> Result<Termination> {
        if let Some(t) = &s.inner.done {
            return Ok(t.clone());
        }
        s.inner
            .journal
            .append("cancel_intent", json!({}))
            .map_err(jerr)?;
        kill_group(s.inner.pgid);
        s.inner.conn = None;
        let _ = s.child.wait();
        finish(s, Termination::Cancelled)
    }

    /// Reaps spawn records whose parent is gone: kills the recorded group if its helper is still
    /// the same process (start time), records a fallback result if one was written, and removes
    /// the records. Never touches a group whose parent is alive.
    pub fn reap() -> Result<Vec<Value>> {
        let dir = spawn_dir()?;
        let mut out = vec![];
        for e in std::fs::read_dir(&dir)?.flatten() {
            let path = e.path();
            if path.extension().is_none_or(|x| x != "journal") {
                continue;
            }
            let Ok(opened) = Journal::open(&path) else {
                continue;
            };
            let b = &opened.journal.header["binding"];
            let parent = b["parent_pid"].as_i64().unwrap_or(0) as i32;
            let parent_alive = start_time(parent).is_some()
                && start_time(parent).as_deref() == b["parent_start_time"].as_str();
            if parent_alive {
                continue;
            }
            // The id names the files reaping removes: it must be ours (32 hex) and match the
            // journal's own file name.
            let id = opened.journal.header["journal_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) || id != stem {
                continue;
            }
            let pgid = b["pgid"].as_i64().unwrap_or(0) as i32;
            // The recorded helper still runs (same start time), or it is gone and its orphaned
            // group remains (a PID is not reused as a group id while members exist). A live
            // process with another start time is a reused PID: never killed.
            let leader = start_time(pgid);
            let group_exists = Pid::from_raw(pgid)
                .is_some_and(|p| rustix::process::test_kill_process_group(p).is_ok());
            let same = match leader {
                Some(t) => Some(t.as_str()) == b["start_time"].as_str(),
                None => group_exists,
            };
            if same {
                kill_group(pgid);
            }
            let fallback = std::fs::read_to_string(dir.join(format!("{id}.result")))
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(t.lines().last().unwrap_or("")).ok());
            out.push(json!({"id": id, "pgid": pgid, "killed": same, "result": fallback}));
            cleanup(&dir, &id);
        }
        Ok(out)
    }

    /// The helper. Returns its exit code only on set-up failure; otherwise it ends by killing
    /// its own group.
    pub fn helper(args: &[String]) -> i32 {
        let [parent, dir, id, limits, dashdash, argv @ ..] = args else {
            return 2;
        };
        let limited = limits != "-";
        if dashdash != "--" || argv.is_empty() {
            return 2;
        }
        let me = rustix::process::getpid();
        let pgid = me.as_raw_nonzero().get();
        // Debug builds: widen the registration race for its test.
        if cfg!(debug_assertions)
            && let Some(ms) = std::env::var("CALVE_HELPER_DELAY_MS")
                .ok()
                .and_then(|v| v.parse().ok())
        {
            std::thread::sleep(Duration::from_millis(ms));
        }
        // 1. Parent death → SIGTERM (Linux). 2. Close the race: the parent may have died first.
        #[cfg(target_os = "linux")]
        let _ = rustix::process::set_parent_process_death_signal(Some(Signal::TERM));
        let ppid = rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get());
        if parent.parse::<i32>().ok() != Some(ppid) {
            kill_group(pgid);
            return 1;
        }
        // 3. Any termination signal kills the whole group.
        match signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGHUP,
        ]) {
            Ok(mut signals) => {
                std::thread::spawn(move || {
                    if signals.forever().next().is_some() {
                        kill_group(pgid);
                    }
                });
            }
            Err(_) => return 3,
        }
        let dir = PathBuf::from(dir);
        // The result file and the socket are opened before Landlock; both are CLOEXEC.
        let fallback = {
            let mut o = std::fs::OpenOptions::new();
            o.create(true).append(true);
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            o.open(dir.join(format!("{id}.result")))
        };
        let (Ok(mut fallback), Ok(mut conn)) = (
            fallback,
            UnixStream::connect(dir.join(format!("{id}.sock"))),
        ) else {
            return 4;
        };
        // 4. Landlock: the worker can read system paths and work in its directory, temp and
        // home; the spawn directory (runtime dir) is outside every rule.
        // A limited worker starts through the trampoline, which must stay executable too.
        let me = std::env::current_exe().ok();
        #[cfg(target_os = "linux")]
        let landlock =
            restrict_worker(&dir, Path::new(&argv[0]), me.as_deref().filter(|_| limited));
        #[cfg(not(target_os = "linux"))]
        let landlock = "unsupported";
        // 5. The worker inherits the helper's group, stdio, environment and directory.
        let started = Instant::now();
        let status = match (&me, limited) {
            (Some(me), true) => Command::new(me)
                .arg(RLIMIT_MODE)
                .arg(limits)
                .arg("--")
                .args(argv)
                .status(),
            // Limits are refused rather than dropped when they cannot be applied.
            (None, true) => Err(std::io::Error::other(
                "cannot find calve to apply the resource limits",
            )),
            (_, false) => Command::new(&argv[0]).args(&argv[1..]).status(),
        };
        let result = match status {
            Ok(s) => {
                json!({"exit_code": s.code(), "signal": s.signal(), "wall_ms": started.elapsed().as_millis() as u64, "landlock": landlock})
            }
            Err(e) => {
                json!({"exit_code": 127, "signal": null, "spawn_error": e.to_string(), "landlock": landlock})
            }
        };
        crate::journal::fault("helper.before_result");
        // 6. Report, then wait for the ack; without one, the result file.
        let line = format!("{result}\n");
        let acked = conn.write_all(line.as_bytes()).is_ok()
            && conn.set_read_timeout(Some(ACK_TIMEOUT)).is_ok()
            && {
                let mut ack = String::new();
                BufReader::new(&conn)
                    .read_line(&mut ack)
                    .is_ok_and(|n| n > 0 && ack.trim() == "ack")
            };
        if !acked {
            let _ = fallback.write_all(line.as_bytes());
            let _ = fallback.sync_all();
        }
        // 7. Only now the group (stragglers, then the helper itself).
        kill_group(pgid);
        0
    }

    /// Applies the worker ruleset; returns how far the kernel enforced it.
    #[cfg(target_os = "linux")]
    fn restrict_worker(
        spawn_dir: &Path,
        program: &Path,
        trampoline: Option<&Path>,
    ) -> &'static str {
        use landlock::{
            ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        };
        let abi = ABI::V2;
        let read = AccessFs::from_read(abi);
        let all = AccessFs::from_all(abi);
        let cwd = std::env::current_dir().ok();
        let mut rw: Vec<PathBuf> = [
            "/dev/null",
            "/dev/zero",
            "/dev/full",
            "/dev/tty",
            "/dev/pts",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        rw.extend(rw_roots(
            cwd.as_deref(),
            std::env::var("TMPDIR").ok(),
            std::env::var("HOME").ok(),
        ));
        // Read-only system paths, never a parent of the spawn directory. The read-write roots
        // stay even when one contains it (then the spawn records are not hidden; the spawn
        // journal says so): taking a worker's home away would break it silently.
        let ro = [
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/etc",
            "/proc",
            "/sys",
            "/opt",
            "/nix",
            "/snap",
            "/run/current-system",
            "/dev/urandom",
            "/dev/random",
        ];
        let ruleset = Ruleset::default()
            .handle_access(all)
            .and_then(|r| r.create());
        let Ok(mut r) = ruleset else {
            return "none";
        };
        for p in ro
            .iter()
            .map(PathBuf::from)
            .filter(|p| !spawn_dir.starts_with(p))
        {
            if let Ok(fd) = PathFd::new(&p) {
                r = match r.add_rule(PathBeneath::new(fd, read)) {
                    Ok(r) => r,
                    Err(_) => return "none",
                };
            }
        }
        for p in rw {
            if let Ok(fd) = PathFd::new(&p) {
                r = match r.add_rule(PathBeneath::new(fd, all)) {
                    Ok(r) => r,
                    Err(_) => return "none",
                };
            }
        }
        // The worker's own program, wherever it is installed (outside every root above, a
        // configured provider could not even start).
        for exe in std::iter::once(program).chain(trampoline) {
            if let Ok(fd) = PathFd::new(exe) {
                r = match r.add_rule(PathBeneath::new(fd, AccessFs::Execute | AccessFs::ReadFile)) {
                    Ok(r) => r,
                    Err(_) => return "none",
                };
            }
        }
        match r.restrict_self().map(|st| st.ruleset) {
            Ok(landlock::RulesetStatus::FullyEnforced) => "full",
            Ok(landlock::RulesetStatus::PartiallyEnforced) => "partial",
            _ => "none",
        }
    }
}

#[cfg(unix)]
pub use unix::{helper, reap};

/// The helper's limits argument: `<memory bytes>,<cpu seconds>` (`-` for none), or `-`.
#[cfg(unix)]
fn limit_arg(limits: &crate::config::ResourceLimits) -> String {
    if limits.memory_bytes.is_none() && limits.cpu_seconds.is_none() {
        return "-".into();
    }
    let part = |v: Option<u64>| v.map_or("-".to_owned(), |n| n.to_string());
    format!("{},{}", part(limits.memory_bytes), part(limits.cpu_seconds))
}

/// `calve __exec-limited <limits> -- <argv>`: sets the limits on itself (hard and soft, so the
/// worker cannot raise them) and replaces itself with the worker; limits survive `exec`.
/// The worker's command is built before the limits apply, so nothing here allocates after.
#[cfg(unix)]
pub fn rlimit_exec(args: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;
    let [limits, dashdash, argv @ ..] = args else {
        return 2;
    };
    if dashdash != "--" || argv.is_empty() {
        return 2;
    }
    let mut parts = limits.split(',').map(|p| p.parse::<u64>().ok());
    let (memory, cpu) = (parts.next().flatten(), parts.next().flatten());
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    for (resource, value) in [
        (rustix::process::Resource::As, memory),
        (rustix::process::Resource::Cpu, cpu),
    ] {
        if let Some(n) = value {
            let limit = rustix::process::Rlimit {
                current: Some(n),
                maximum: Some(n),
            };
            if let Err(e) = rustix::process::setrlimit(resource, limit) {
                eprintln!("calve: cannot apply the worker resource limit: {e}");
                return 126;
            }
        }
    }
    let e = command.exec();
    // Fail closed: a worker that cannot start within its limits does not run unlimited.
    eprintln!("calve: worker did not start within its resource limits: {e}");
    127
}

#[cfg(windows)]
mod windows {
    use super::*;

    pub fn spawn(
        argv: &[String],
        env: &[(&str, &str)],
        cwd: &Path,
        limits: &crate::config::ResourceLimits,
    ) -> Result<Supervised> {
        if limits.cpu_seconds.is_some() {
            return Err(coded(
                "CONTAINMENT_UNAVAILABLE",
                "a per-worker CPU limit cannot be enforced on this platform",
            ));
        }
        let job = calve_win_sec::Job::new(calve_win_sec::Limits {
            memory_bytes: limits.memory_bytes,
            active_processes: limits.processes,
        })
        .map_err(|e| {
            coded(
                "CONTAINMENT_UNAVAILABLE",
                format!("cannot create a Job Object: {e}"),
            )
        })?;
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .current_dir(cwd)
            .env_clear()
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = job.spawn_suspended_in_job(&mut cmd).map_err(|e| {
            coded(
                "CONTAINMENT_UNAVAILABLE",
                format!("cannot place the process in its job: {e}"),
            )
        })?;
        Ok(Supervised { child, job })
    }

    pub fn wait(s: &mut Supervised) -> Result<Termination> {
        let status = s.child.wait()?;
        // Stragglers of a finished worker go with the job.
        let _ = s.job.terminate(1);
        Ok(Termination::Finished {
            exit_code: status.code(),
            signal: None,
        })
    }

    pub fn cancel(s: &mut Supervised) -> Result<Termination> {
        s.job.terminate(1).map_err(Error::from)?;
        let _ = s.child.wait();
        Ok(Termination::Cancelled)
    }
}

#[cfg(windows)]
pub fn reap() -> Result<Vec<Value>> {
    // The parent-owned job dies with its parent (KILL_ON_JOB_CLOSE): nothing outlives it.
    Ok(vec![])
}

#[cfg(all(test, unix))]
mod tests {
    use super::unix::rw_roots;
    use std::path::{Path, PathBuf};

    #[test]
    fn read_write_roots_fail_closed() {
        let roots = rw_roots(None, Some(String::new()), Some("/".into()));
        assert_eq!(roots, vec![PathBuf::from("/tmp")]);
        let roots = rw_roots(
            Some(Path::new("rel")),
            Some("/".into()),
            Some(String::new()),
        );
        assert!(roots.is_empty(), "{roots:?}");
        let roots = rw_roots(Some(Path::new("/w")), Some("/t".into()), Some("/h".into()));
        assert_eq!(roots, ["/t", "/w", "/h"].map(PathBuf::from));
    }
}
