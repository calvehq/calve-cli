//! §57 scenarios that need fixture catalogs or fault injection, each one complete run through
//! the real binary: G (capability denial), H (permission widening), L (crash during install),
//! N (third-party extension), P (version incompatibility).

use std::fs;

use calve_testkit::Env;
use serde_json::Value;

struct P<'a> {
    env: &'a Env,
    root: String,
}

impl P<'_> {
    fn ok(&self, args: &[&str]) -> Value {
        self.env
            .ok(&[&["--project", self.root.as_str()][..], args].concat())
    }
    fn run(&self, args: &[&str]) -> calve_testkit::Run {
        self.env
            .run(&[&["--project", self.root.as_str()][..], args].concat())
    }
    /// A sealed pack holding one file.
    fn sealed(&self, title: &str, file: &str) -> (String, String) {
        let id = self.ok(&["pack", "create", title])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        fs::write(std::path::Path::new(&self.root).join(file), "content\n").unwrap();
        self.ok(&["pack", "capture", &id, file, "--generation", "1"]);
        let g = self.ok(&["pack", "show", &id])["generation"].to_string();
        self.ok(&["pack", "seal", &id, "--generation", &g]);
        (id, g)
    }
}

/// §57 G: an extension without `process.execute` is denied by OpenAEVC, Calve explains the
/// missing capability, a scoped grant makes the retry succeed, and a revoke denies it again.
#[test]
#[cfg(unix)]
fn scenario_g_capability_denial() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let project = root.to_str().unwrap().to_owned();
    env.ok(&["init", &project]);
    // 1. The extension requests process.execute and holds no grant.
    env.enable_toy(&root);
    let p = P {
        root: project,
        env: &env,
    };
    let permissions = p.ok(&["extension", "permissions", "org.example.toy"]);
    assert_eq!(
        permissions["requested_host_capabilities"],
        serde_json::json!(["process.execute"]),
        "{permissions}"
    );
    assert_eq!(
        permissions["granted_host_capabilities"],
        serde_json::json!([]),
        "{permissions}"
    );
    // 2–4. The execution attempt is denied by OpenAEVC and Calve names what is missing.
    let (pack, g) = p.sealed("probe", "process-probe.toy");
    let denied = p.run(&["pack", "verify", &pack, "--generation", &g]);
    assert!(!denied.success);
    println!("denied: {}", denied.stderr);
    assert!(
        denied.stderr.contains("process.execute"),
        "{}",
        denied.stderr
    );
    assert!(
        denied.stderr.contains("extension grant"),
        "{}",
        denied.stderr
    );
    // 5–6. A scoped grant: the retry succeeds.
    p.ok(&["extension", "grant", "org.example.toy", "process.execute"]);
    assert_eq!(
        p.ok(&["pack", "verify", &pack, "--generation", &g])["status"],
        "PASS"
    );
    // 7. Revoked: a future operation is denied again.
    p.ok(&["extension", "revoke", "org.example.toy", "process.execute"]);
    let again = p.run(&["pack", "verify", &pack, "--generation", &g]);
    assert!(
        !again.success && again.stderr.contains("process.execute"),
        "{}",
        again.stderr
    );
}

/// §57 P: against an unsupported OpenAEVC protocol, writes are blocked before any mutation and
/// doctor reports the exact mismatch and the supported range.
#[test]
fn scenario_p_version_incompatibility() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("p");
    let project = root.to_str().unwrap().to_owned();
    env.ok(&["init", &project]);
    env.ok(&["--project", &project, "pack", "create", "before"]);
    let events = |env: &Env| {
        env.ok(&["--project", &project, "activity"])
            .as_array()
            .unwrap()
            .len()
    };
    let before = events(&env);
    // 1. An unsupported runtime (debug-only report override; the real check runs on it).
    env.vars
        .push(("CALVE_TEST_RUNTIME_PROTOCOL".into(), "9".into()));
    // 2. Writes are blocked before mutation.
    let write = env.run(&["--project", &project, "pack", "create", "after"]);
    assert!(!write.success);
    assert!(
        write.stderr.contains("OPENAEVC_INCOMPATIBLE"),
        "{}",
        write.stderr
    );
    // 3. Doctor reports the exact mismatch and the supported range.
    let doctor = env.run(&["--project", &project, "doctor"]);
    assert!(!doctor.success);
    assert!(
        doctor.stderr.contains("runtime 9.0.0..=9.0.1"),
        "{}",
        doctor.stderr
    );
    assert!(
        doctor.stderr.contains("Calve SDK 0.1.0..=0.1.0"),
        "{}",
        doctor.stderr
    );
    // Nothing changed: with the supported runtime the Project is exactly as it was.
    env.vars.clear();
    assert_eq!(events(&env), before, "no event from the refused write");
    let packs = env.ok(&["--project", &project, "pack", "list"]);
    assert_eq!(packs.as_array().unwrap().len(), 1, "{packs}");
}
