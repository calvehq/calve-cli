//! M6 R7 on Windows: provider limits reach the worker's Job Object through the supervisor; a
//! limit a Job cannot enforce (CPU seconds) is refused, never ignored.
#![cfg(windows)]

use calve_app::config::ResourceLimits;
use calve_app::supervise::{Supervised, Termination};

fn cmd(script: &str) -> Vec<String> {
    vec!["cmd".into(), "/c".into(), script.into()]
}

#[test]
fn job_limits_come_from_the_provider() {
    let dir = tempfile::tempdir().unwrap();
    let env = [
        ("SystemRoot", "C:\\Windows"),
        ("PATH", "C:\\Windows\\System32"),
    ];
    let two = cmd("ping -n 2 127.0.0.1 >nul");
    let mut free = Supervised::spawn(&two, &env, dir.path()).unwrap();
    assert!(matches!(
        free.wait().unwrap(),
        Termination::Finished {
            exit_code: Some(0),
            ..
        }
    ));
    let one = ResourceLimits {
        processes: Some(1),
        ..Default::default()
    };
    let mut limited = Supervised::spawn_limited(&two, &env, dir.path(), &one).unwrap();
    match limited.wait().unwrap() {
        Termination::Finished { exit_code, .. } => {
            assert_ne!(
                exit_code,
                Some(0),
                "cmd may not start ping inside a one-process job"
            )
        }
        other => panic!("{other:?}"),
    }
    let cpu = ResourceLimits {
        cpu_seconds: Some(1),
        ..Default::default()
    };
    assert!(Supervised::spawn_limited(&two, &env, dir.path(), &cpu).is_err());
}
