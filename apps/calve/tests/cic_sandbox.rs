//! Supervised CIC sandbox (`calve __cic-sandbox`, rev 10 §6.7, ADR 0018): the child serves the
//! same bytes as the in-process host, refuses a module whose digest differs from the installed
//! one, and is killed on the hard wall-clock deadline even when the guest evades fuel slicing.

use std::path::Path;
use std::time::{Duration, Instant};

use calve_app::sandbox::{CalveHost, HostConfig, SandboxDriver, sha256_hex};
use calve_integration_contract::driver::{HostError, Session};
use calve_testkit::cic::*;
use serde_json::json;

fn calve() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_calve"))
}

fn supervised(path: &Path, cfg: &HostConfig) -> SandboxDriver {
    let digest = sha256_hex(&std::fs::read(path).unwrap());
    SandboxDriver::spawn(calve(), path, &digest, cfg).unwrap()
}

#[test]
fn supervised_bytes_equal_in_process_bytes() {
    let (base, work) = scenario(40);
    for g in ["ref-rust", "ref-min"] {
        let run = |d: Box<dyn calve_integration_contract::driver::Driver>| {
            let mut s = Session::open(d, &host_hello(), &toy_metadata()).unwrap();
            let a = s.request("describe", json!({})).unwrap();
            let (ops, c) = capture(&mut s, &base, &work, json!({}), 5).unwrap();
            (a, ops, c)
        };
        let sup = run(Box::new(supervised(&guest_path(g), &HostConfig::default())));
        let inp = run(Box::new(
            CalveHost::new(&guest(g), HostConfig::default()).unwrap(),
        ));
        assert_eq!(sup, inp, "{g}");
    }
}

#[test]
fn module_digest_mismatch_is_refused_by_the_child() {
    let d = SandboxDriver::spawn(
        calve(),
        &guest_path("ref-min"),
        &"0".repeat(64),
        &HostConfig::default(),
    )
    .unwrap();
    let e = Session::open(d, &host_hello(), &toy_metadata())
        .err()
        .unwrap();
    assert_eq!(e.code(), "ABI_VIOLATION", "{e}");
}

#[test]
fn hard_deadline_kills_a_guest_that_evades_fuel_slicing() {
    // 60 MiB memory.fill per iteration: few instructions, a lot of work each. Soft limits are
    // disabled in the child, so only the parent's wall clock can stop it.
    let hello = br#"{"guest":{"abi":1,"capabilities":{"optional":["describe.v1","detect.v1","relate.v1"],"required":["capture.v1"]},"cic":[{"major":1,"max_minor":0,"min_minor":0}],"extension_id":"org.example.toy","schema":1,"version":"0.1.0"},"hello":0}"#;
    let esc: String = hello.iter().map(|c| format!("\\{c:02x}")).collect();
    let wasm = wat::parse_str(format!(
        r#"(module
  (memory (export "memory") 1024)
  (global $bump (mut i32) (i32.const 65536))
  (func (export "cic_abi_version") (result i32) (i32.const 1))
  (func (export "cic_alloc") (param i32) (result i32) (local $p i32) global.get $bump local.set $p global.get $bump local.get 0 i32.add global.set $bump local.get $p)
  (func (export "cic_free") (param i32 i32))
  (func (export "cic_init") (param i32 i32) (result i64) (i64.const {init}))
  (func (export "cic_call") (param i32 i32) (result i64) (loop $l (memory.fill (i32.const 0) (i32.const 7) (i32.const 62914560)) (br $l)) (i64.const 0))
  (data (i32.const 1024) "{esc}"))"#,
        init = (1024i64 << 32) | hello.len() as i64
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bulk.wasm");
    std::fs::write(&path, &wasm).unwrap();
    // Above the sandbox start-up time on a loaded machine (the open is under the same deadline).
    let hard = Duration::from_secs(5);
    let cfg = HostConfig {
        fuel_slice: 1_000_000_000,
        fuel_per_call: u64::MAX,
        soft_deadline: Duration::from_secs(3600),
        hard_deadline: hard,
        ..HostConfig::default()
    };
    let mut s = Session::open(supervised(&path, &cfg), &host_hello(), &toy_metadata()).unwrap();
    let t = Instant::now();
    let r = s.raw("describe", json!({}));
    assert_eq!(r.unwrap_err(), HostError::DeadlineExceeded);
    assert!(
        t.elapsed() <= hard + Duration::from_secs(1),
        "killed within deadline + 1 s: {:?}",
        t.elapsed()
    );
    assert!(s.raw("describe", json!({})).is_err(), "session discarded");
}

fn reference(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("ref.wasm");
    std::fs::write(&path, guest("ref-rust")).unwrap();
    path
}

/// A stall while the child starts or compiles is the supervisor's own deadline: classified as
/// such, the child killed, and no guest time charged.
#[test]
fn a_stalled_startup_is_its_own_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let path = reference(dir.path());
    for stage in ["startup", "compile"] {
        let cfg = HostConfig {
            startup: Duration::from_millis(500),
            stall: Some((stage, Duration::from_secs(5))),
            ..HostConfig::default()
        };
        let started = Instant::now();
        let e = Session::open(supervised(&path, &cfg), &host_hello(), &toy_metadata())
            .map(|_| ())
            .unwrap_err();
        assert!(
            e.to_string().contains(calve_app::sandbox::STARTUP_DEADLINE),
            "{stage}: {e}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{stage}: killed early"
        );
    }
}

/// A slow start within its budget costs the guest nothing: its deadline begins at ready.
#[test]
fn a_slow_compile_within_budget_leaves_the_guest_deadline_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = reference(dir.path());
    let cfg = HostConfig {
        hard_deadline: Duration::from_secs(2),
        stall: Some(("compile", Duration::from_secs(3))),
        ..HostConfig::default()
    };
    let mut s = Session::open(supervised(&path, &cfg), &host_hello(), &toy_metadata()).unwrap();
    assert!(s.raw("describe", json!({})).unwrap().is_ok());
}

/// The session's absolute bound holds however promptly each message is answered.
#[test]
fn the_session_bound_is_absolute() {
    let dir = tempfile::tempdir().unwrap();
    let path = reference(dir.path());
    // Long enough that starting the child and opening the session fit on a loaded host (1.5 s
    // did not, once: the open itself hit the bound); the loop must still run into it.
    let cfg = HostConfig {
        session: Duration::from_secs(6),
        ..HostConfig::default()
    };
    let started = Instant::now();
    let mut s = Session::open(supervised(&path, &cfg), &host_hello(), &toy_metadata()).unwrap();
    let e = loop {
        match s.raw("describe", json!({})) {
            Ok(_) => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => break e,
        }
        assert!(started.elapsed() < Duration::from_secs(20), "never bounded");
    };
    assert!(
        e.to_string().contains(calve_app::sandbox::SESSION_DEADLINE),
        "{e}"
    );
}

/// Dropping a session while the child is still starting ends the child.
#[test]
fn cancelling_during_startup_kills_the_child() {
    let dir = tempfile::tempdir().unwrap();
    let path = reference(dir.path());
    let cfg = HostConfig {
        startup: Duration::from_millis(300),
        stall: Some(("startup", Duration::from_secs(30))),
        ..HostConfig::default()
    };
    let driver = supervised(&path, &cfg);
    let pid = driver.child_id();
    drop(driver);
    std::thread::sleep(Duration::from_millis(200));
    #[cfg(target_os = "linux")]
    assert!(
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_or(true, |s| s.split(' ').nth(2) == Some("Z")),
        "child {pid} still running"
    );
    let _ = pid;
}
