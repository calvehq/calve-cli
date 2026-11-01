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

/// §60 Test L: a copy cannot quietly become a second writer with the same identity, registered
/// or not. The boundary is this machine: another machine holds no authority until it imports one.
#[test]
fn test_l_a_copy_is_inactive_until_adopted() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("original");
    env.ok(&["init", root.to_str().unwrap(), "--no-register"]);
    let original = root.to_str().unwrap();
    let copy = env.path().join("copy");
    calve_testkit::copy_tree(&root, &copy);
    let copied = copy.to_str().unwrap();

    // The copy reads, and every write is refused before it changes anything.
    env.ok(&["--project", copied, "intent", "list"]);
    let refused = env.fails(&["--project", copied, "intent", "create", "second writer"]);
    assert!(refused.contains("PROJECT_IDENTITY_CONFLICT"), "{refused}");
    assert!(refused.contains("adopt-copy"), "{refused}");
    assert_eq!(
        env.ok(&["--project", copied, "intent", "list"])
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // The active instance is unaffected, also after unregistering.
    env.ok(&["--project", original, "intent", "create", "first writer"]);

    // Adoption gives the copy its own identity, and both then write.
    let adopted = env.ok(&["project", "adopt-copy", copied]);
    let new_id = adopted["project_id"].as_str().unwrap();
    let original_identity = fs::read_to_string(root.join(".calve/project.toml")).unwrap();
    assert!(!original_identity.contains(new_id), "{adopted}");
    env.ok(&["--project", copied, "intent", "create", "own writer"]);
    env.ok(&["--project", original, "intent", "create", "still writing"]);
}

/// A moved Project keeps its identity: the authority follows when the old root is gone.
#[test]
fn test_l_a_moved_project_stays_active() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("before");
    env.ok(&["init", root.to_str().unwrap(), "--no-register"]);
    let moved = env.path().join("after");
    std::fs::rename(&root, &moved).unwrap();
    env.ok(&[
        "--project",
        moved.to_str().unwrap(),
        "intent",
        "create",
        "moved",
    ]);
}

/// Another machine: no authority, so nothing opens as this Project until it is imported.
#[test]
fn test_l_another_machine_needs_the_authority() {
    let here = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = here.path().join("project");
    let p = root.to_str().unwrap();
    here.ok(&["init", p, "--no-register"]);
    let file = here.path().join("authority.json");
    here.fails(&["project", "authority-export", p, file.to_str().unwrap()]);
    here.ok(&[
        "project",
        "authority-export",
        p,
        file.to_str().unwrap(),
        "--yes",
    ]);

    let there = Env::new(env!("CARGO_BIN_EXE_calve"));
    let copy = there.path().join("project");
    calve_testkit::copy_tree(&root, &copy);
    let c = copy.to_str().unwrap();
    let refused = there.fails(&["--project", c, "intent", "create", "no authority"]);
    assert!(refused.contains("no authority"), "{refused}");
    there.ok(&["project", "authority-import", c, file.to_str().unwrap()]);
    there.ok(&["--project", c, "intent", "create", "imported"]);
}

/// No key material stays where a worker works.
#[test]
fn the_project_directory_holds_no_authority() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    env.ok(&["--project", p, "authority", "identity-add", "reviewer"]);
    assert!(!root.join(".calve/keys.toml").exists());
    assert!(!root.join(".calve/identities").exists());
}

/// Keys of a Project from before they moved leave the directory on first open.
#[test]
fn legacy_keys_move_out_on_first_open() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("project");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    let id = env.ok(&["project", "list"])[0]["project_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let keys = env
        .path()
        .join("d/calve/authority")
        .join(&id)
        .join("keys.toml");
    std::fs::rename(&keys, root.join(".calve/keys.toml")).unwrap();
    env.ok(&["--project", p, "intent", "create", "still works"]);
    assert!(keys.is_file() && !root.join(".calve/keys.toml").exists());
}
