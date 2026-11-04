//! The materialization WAL through the CLI (rev 10 §14, N14/N28 Linux): a real process abort at
//! every record boundary converges on resume; a concurrent writer is detected and its bytes kept
//! with no automatic reversal; weak filesystems are refused by default; rollback is byte for
//! byte.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};

use calve_testkit::Env;
use serde_json::Value;

struct T {
    env: Env,
    p: String,
    v1: String,
    v2: String,
}

impl T {
    fn root(&self) -> PathBuf {
        PathBuf::from(&self.p)
    }
    fn args<'a>(&'a self, a: &[&'a str]) -> Vec<&'a str> {
        [&["--project", self.p.as_str()][..], a].concat()
    }
    fn ok(&self, a: &[&str]) -> Value {
        self.env.ok(&self.args(a))
    }
    fn run(&self, vars: &[(&str, &str)], a: &[&str]) -> calve_testkit::Run {
        let mut env = Env {
            temp: tempfile::tempdir().unwrap(),
            calve: self.env.calve.clone(),
            catalog: None,
            vars: self.env.vars.clone(),
        };
        // Same machine data and config as the fixture environment.
        env.vars
            .push(("XDG_DATA_HOME".into(), self.env.path().join("d").into()));
        env.vars
            .push(("XDG_CONFIG_HOME".into(), self.env.path().join("c").into()));
        env.vars
            .extend(vars.iter().map(|(k, v)| ((*k).to_owned(), (*v).into())));
        env.run(&self.args(a))
    }
    fn materialize(&self, baseline: &str) -> Value {
        self.ok(&["baseline", "materialize", baseline, "--apply"])
    }
    fn tree(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = vec![];
        walk(&self.root(), "", &mut out);
        out.sort();
        out
    }
    fn ops(&self) -> Vec<Value> {
        self.ok(&["materialize", "list"])
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
    for e in fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = format!("{prefix}{}", e.file_name().to_string_lossy());
        if name == ".calve" {
            continue;
        }
        if e.file_type().unwrap().is_dir() {
            walk(&e.path(), &format!("{name}/"), out);
        } else {
            out.push((name, fs::read(e.path()).unwrap()));
        }
    }
}

/// v1 = {a.txt: one, dir/b.txt: bee}; v2 = {a.txt: two, c.txt: sea}. The tree starts at v2, so
/// materializing v1 replaces a.txt (f1), deletes c.txt (f2) and creates dir/b.txt (f3).
/// `prims`: `CALVE_FS_PRIMITIVES` for every command (`displace` = the Windows replacement
/// algorithm on Linux renames), or the probed default.
fn setup_with(prims: Option<&str>) -> T {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    if let Some(p) = prims {
        env.vars.push(("CALVE_FS_PRIMITIVES".into(), p.into()));
    }
    let root = env.path().join("project");
    let p = root.to_str().unwrap().to_owned();
    env.ok(&["init", &p]);
    env.enable_toy(&root);
    let promote = |env: &Env| -> String {
        let id = env.ok(&["--project", &p, "pack", "create", "change"])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        env.ok(&[
            "--project",
            &p,
            "pack",
            "capture-tree",
            "--accept-deletions",
            &id,
            ".",
            "--generation",
            "1",
        ]);
        let g = env.ok(&["--project", &p, "pack", "show", &id])["generation"].to_string();
        for step in ["seal", "qualify"] {
            env.ok(&["--project", &p, "pack", step, &id, "--generation", &g]);
        }
        env.ok(&["--project", &p, "pack", "promote", &id, "--generation", &g])["promoted_digest"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    fs::create_dir(root.join("dir")).unwrap();
    fs::write(root.join("a.txt"), "one\n").unwrap();
    fs::write(root.join("dir/b.txt"), "bee\n").unwrap();
    let d1 = promote(&env);
    fs::write(root.join("a.txt"), "two\n").unwrap();
    fs::remove_file(root.join("dir/b.txt")).unwrap();
    fs::write(root.join("c.txt"), "sea\n").unwrap();
    let d2 = promote(&env);
    let v1 = env.ok(&["--project", &p, "baseline", "create", "v1", &d1])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let v2 = env.ok(&["--project", &p, "baseline", "create", "v2", &d1, &d2])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    T { env, p, v1, v2 }
}

fn setup() -> T {
    setup_with(None)
}

fn v1_tree() -> Vec<(String, Vec<u8>)> {
    vec![
        ("a.txt".into(), b"one\n".to_vec()),
        ("dir/b.txt".into(), b"bee\n".to_vec()),
    ]
}

#[test]
fn a_crash_at_every_record_boundary_converges_on_resume() {
    crash_at_every_boundary(None, &[]);
}

/// The displace-then-place replacement (Windows' algorithm), including a crash between its two
/// renames.
#[test]
fn displace_then_place_converges_after_a_crash_at_every_boundary() {
    crash_at_every_boundary(Some("displace"), &["materialize.replace.after_displace"]);
}

fn crash_at_every_boundary(prims: Option<&str>, extra: &[&str]) {
    let t = setup_with(prims);
    let v2_tree = t.tree();
    let base = [
        "materialize.f1.after_intent",
        "materialize.f1.after_backup",
        "materialize.f1.after_temp",
        "materialize.f1.after_mutate",
        "materialize.f1.after_done",
        "materialize.f2.after_intent",
        "materialize.f2.after_backup",
        "materialize.f2.after_mutate",
        "materialize.f3.after_intent",
        "materialize.f3.after_temp",
        "materialize.f3.after_mutate",
        "materialize.after_completed",
        "materialize.provenance.after_intent",
        "materialize.provenance.before_ack",
    ];
    let points = base.iter().chain(extra);
    for &point in points {
        let run = t.run(
            &[("CALVE_FAULT", point)],
            &["baseline", "materialize", &t.v1, "--apply"],
        );
        assert!(!run.success, "{point}: expected a crash");
        let ops = t.ops();
        let op = ops.last().unwrap();
        assert_eq!(op["state"], "Interrupted", "{point}: {op}");
        // A new materialization waits for the unfinished one.
        let refused = t.run(&[], &["baseline", "materialize", &t.v2, "--apply"]);
        assert!(
            refused.stderr.contains("unfinished_operation"),
            "{point}: {}",
            refused.stderr
        );
        let done = t.ok(&["materialize", "resume", op["op"].as_str().unwrap()]);
        assert_eq!(done["state"], "Completed", "{point}: {done}");
        assert_eq!(t.tree(), v1_tree(), "{point}");
        let journal = fs::read_to_string(
            t.root()
                .join(".calve/run/materialize")
                .join(op["op"].as_str().unwrap())
                .join("journal"),
        )
        .unwrap();
        assert_eq!(
            journal.matches("\"p.ack\"").count(),
            1,
            "{point}: one provenance record"
        );
        // Back to v2 for the next point.
        assert_eq!(t.materialize(&t.v2)["state"], "Completed");
        assert_eq!(t.tree(), v2_tree, "{point}");
    }
}

/// N62: a mutation is done only with verified evidence of what it replaced. A crash after the
/// replacement leaves the new bytes; if the backup of the old bytes is then missing or no longer
/// matches, resume does not mark it done: it is `Conflicted(evidence_missing)`, the bytes stay
/// as they are, and nothing is reversed.
#[test]
fn a_mutation_without_verified_evidence_is_conflicted_evidence_missing() {
    let t = setup();
    for damage in ["missing", "changed"] {
        let run = t.run(
            &[("CALVE_FAULT", "materialize.f1.after_mutate")],
            &["baseline", "materialize", &t.v1, "--apply"],
        );
        assert!(!run.success, "{damage}: expected a crash");
        let id = t.ops().last().unwrap()["op"].as_str().unwrap().to_owned();
        let backup = t
            .root()
            .join(".calve/run/materialize")
            .join(&id)
            .join("f1.backup");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "two\n", "{damage}");
        match damage {
            "missing" => fs::remove_file(&backup).unwrap(),
            _ => fs::write(&backup, "not what was replaced\n").unwrap(),
        }
        let resumed = t.run(&[], &["materialize", "resume", &id]);
        assert!(!resumed.success, "{damage}: done without evidence");
        assert!(
            resumed.stderr.contains("evidence_missing"),
            "{damage}: {}",
            resumed.stderr
        );
        let op = t.ops().last().unwrap().clone();
        assert_eq!(op["state"], "Conflicted", "{damage}: {op}");
        assert_eq!(
            fs::read_to_string(t.root().join("a.txt")).unwrap(),
            "one\n",
            "{damage}: the new bytes stay; nothing is reversed"
        );
        let resolved = t.ok(&["materialize", "resolve", &id, "--keep", "ours"]);
        assert_eq!(resolved["state"], "Completed", "{damage}: {resolved}");
        assert_eq!(t.tree(), v1_tree(), "{damage}");
        assert_eq!(t.materialize(&t.v2)["state"], "Completed", "{damage}");
    }
}

/// N71: a rename's source must still hold the expected bytes, and after the mutation the
/// destination must be Calve's own inode with the expected digest. Either failing is a
/// conflict that keeps every version and reverses nothing (no automatic swap-back).
#[test]
fn rename_source_preconditions_and_post_mutation_identity() {
    let t = setup();
    let a = t.root().join("a.txt");
    // Post-mutation identity: a write lands on the path right after Calve's rename.
    let run = t.run(
        &[(
            "CALVE_TEST_WRITE",
            &format!("f1.after_mutate={}", a.display()),
        )],
        &["baseline", "materialize", &t.v1, "--apply"],
    );
    assert!(!run.success);
    assert!(
        run.stderr.contains("post_mutation_identity"),
        "{}",
        run.stderr
    );
    let id = t.ops().last().unwrap()["op"].as_str().unwrap().to_owned();
    assert_eq!(t.ops().last().unwrap()["state"], "Conflicted");
    assert_eq!(
        fs::read_to_string(&a).unwrap(),
        "one\nconcurrent\n",
        "no swap-back"
    );
    let artifacts = t.root().join(".calve/conflicts").join(&id).join("f1");
    assert_eq!(fs::read_to_string(artifacts.join("ours")).unwrap(), "one\n");
    assert_eq!(
        fs::read_to_string(artifacts.join("displaced")).unwrap(),
        "two\n"
    );
    let resolved = t.ok(&["materialize", "resolve", &id, "--keep", "ours"]);
    assert_eq!(resolved["state"], "Completed", "{resolved}");
    assert_eq!(t.tree(), v1_tree());
    assert_eq!(t.materialize(&t.v2)["state"], "Completed");

    // Source precondition: the file changes after its intent is journaled and before it is
    // read for the backup. Nothing is mutated: the writer's bytes stay where they are.
    let run = t.run(
        &[(
            "CALVE_TEST_WRITE",
            &format!("f1.after_intent={}", a.display()),
        )],
        &["baseline", "materialize", &t.v1, "--apply"],
    );
    assert!(!run.success);
    assert!(
        run.stderr.contains("changed_before_mutation"),
        "{}",
        run.stderr
    );
    let op = t.ops().last().unwrap().clone();
    assert_eq!(op["state"], "Conflicted", "{op}");
    assert_eq!(
        fs::read_to_string(&a).unwrap(),
        "two\nconcurrent\n",
        "untouched"
    );
    let id = op["op"].as_str().unwrap();
    let resolved = t.ok(&["materialize", "resolve", id, "--keep", "theirs"]);
    assert_eq!(resolved["state"], "Completed", "{resolved}");
    assert_eq!(fs::read_to_string(&a).unwrap(), "two\nconcurrent\n");
}

#[test]
fn a_concurrent_writer_is_kept_and_nothing_is_reversed() {
    concurrent_writer(None);
}

#[test]
fn displace_then_place_keeps_a_concurrent_writer() {
    concurrent_writer(Some("displace"));
}

fn concurrent_writer(prims: Option<&str>) {
    let t = setup_with(prims);
    // Between preserve (2) and mutate (3): the exchange displaces the writer's bytes.
    let a = t.root().join("a.txt");
    let run = t.run(
        &[(
            "CALVE_TEST_WRITE",
            &format!("f1.after_backup={}", a.display()),
        )],
        &["baseline", "materialize", &t.v1, "--apply"],
    );
    assert!(!run.success);
    assert!(
        run.stderr.contains("MATERIALIZE_CONFLICT") && run.stderr.contains("displaced_changed"),
        "{}",
        run.stderr
    );
    assert_eq!(
        fs::read_to_string(&a).unwrap(),
        "one\n",
        "Calve's bytes stay; no swap-back"
    );
    let op = t.ops().last().unwrap().clone();
    let id = op["op"].as_str().unwrap();
    assert_eq!(op["state"], "Conflicted");
    let artifacts = t.root().join(".calve/conflicts").join(id).join("f1");
    assert_eq!(
        fs::read_to_string(artifacts.join("displaced")).unwrap(),
        "two\nconcurrent\n"
    );
    assert_eq!(fs::read_to_string(artifacts.join("ours")).unwrap(), "one\n");
    // Keep the writer's version, then the rest of the operation runs; artifacts stay.
    let resolved = t.ok(&["materialize", "resolve", id, "--keep", "theirs"]);
    assert_eq!(resolved["state"], "Completed", "{resolved}");
    assert_eq!(fs::read_to_string(&a).unwrap(), "two\nconcurrent\n");
    assert_eq!(
        fs::read_to_string(t.root().join("dir/b.txt")).unwrap(),
        "bee\n"
    );
    assert!(artifacts.join("displaced").is_file());

    // A writer holding the old inode open writes after the swap: preserved as displaced.
    fs::write(&a, "two\n").unwrap();
    assert_eq!(t.materialize(&t.v2)["state"], "Completed");
    let run = t.run(
        &[("CALVE_TEST_WRITE", "f1.after_mutate=@displaced")],
        &["baseline", "materialize", &t.v1, "--apply"],
    );
    assert!(run.stderr.contains("displaced_changed"), "{}", run.stderr);
    let id = t.ops().last().unwrap()["op"].as_str().unwrap().to_owned();
    let displaced = t
        .root()
        .join(".calve/conflicts")
        .join(&id)
        .join("f1/displaced");
    assert_eq!(fs::read_to_string(displaced).unwrap(), "two\nconcurrent\n");
    let resolved = t.ok(&["materialize", "resolve", &id, "--keep", "ours"]);
    assert_eq!(resolved["state"], "Completed");
    assert_eq!(t.tree(), v1_tree());
}

#[test]
fn weak_filesystems_are_refused_unless_acknowledged_and_rollback_is_exact() {
    let t = setup();
    let v2_tree = t.tree();
    let weak = [("CALVE_FS_PRIMITIVES", "fallback")];
    let run = t.run(&weak, &["baseline", "materialize", &t.v1, "--apply"]);
    assert!(run.stderr.contains("unsafe_fs"), "{}", run.stderr);
    assert_eq!(t.tree(), v2_tree, "nothing written");
    assert!(t.ops().is_empty(), "refused before any journal");
    // Opt-in: applied with the residual documented; a write in the final window is lost.
    let a = t.root().join("a.txt");
    let w = format!("f1.after_backup={}", a.display());
    let run = t.run(
        &[weak[0], ("CALVE_TEST_WRITE", &w)],
        &[
            "baseline",
            "materialize",
            &t.v1,
            "--apply",
            "--allow-unsafe-fs",
        ],
    );
    assert!(run.success, "{}", run.stderr);
    assert!(
        run.value["warning"]
            .as_str()
            .unwrap()
            .contains("allow-unsafe-fs")
    );
    assert_eq!(
        t.tree(),
        v1_tree(),
        "the concurrent write was lost (documented residual)"
    );
    let id = t.ops().last().unwrap()["op"].as_str().unwrap().to_owned();
    let journal = fs::read_to_string(
        t.root()
            .join(".calve/run/materialize")
            .join(&id)
            .join("journal"),
    )
    .unwrap();
    assert!(journal.contains("\"allow_unsafe_fs\":true"));
    // Rollback restores the verified originals byte for byte.
    let back = t.ok(&["materialize", "rollback", &id, "--yes"]);
    assert_eq!(back["state"], "RolledBack", "{back}");
    assert_eq!(t.tree(), v2_tree);
}

/// ENOSPC while writing the temp file or the backup: the step fails, the tree is untouched, no
/// partial file is left, and a resume (space freed) completes the operation.
#[test]
fn disk_full_leaves_the_tree_untouched_and_resume_completes() {
    let t = setup();
    let v2_tree = t.tree();
    for point in ["f1.temp", "f1.backup"] {
        let run = t.run(
            &[("CALVE_TEST_ENOSPC", point)],
            &["baseline", "materialize", &t.v1, "--apply"],
        );
        assert!(!run.success, "{point}");
        assert!(
            run.stderr.contains("No space left on device"),
            "{point}: {}",
            run.stderr
        );
        assert_eq!(t.tree(), v2_tree, "{point}: tree untouched");
        let leftovers: Vec<_> = fs::read_dir(t.root())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".calve-"))
            .collect();
        assert!(leftovers.is_empty(), "{point}: {leftovers:?}");
        let op = t.ops().last().unwrap().clone();
        assert_eq!(op["state"], "Interrupted", "{point}: {op}");
        let done = t.ok(&["materialize", "resume", op["op"].as_str().unwrap()]);
        assert_eq!(done["state"], "Completed", "{point}: {done}");
        assert_eq!(t.tree(), v1_tree(), "{point}");
        assert_eq!(t.materialize(&t.v2)["state"], "Completed");
    }
}

/// Two materializations started at once: one runs, the other is refused before writing; the
/// tree ends exactly at the target and every operation is accounted for.
#[test]
fn concurrent_materializations_are_serialized() {
    let t = setup();
    let spawn = || {
        std::process::Command::new(&t.env.calve)
            .env("XDG_DATA_HOME", t.env.path().join("d"))
            .env("XDG_CONFIG_HOME", t.env.path().join("c"))
            .envs(t.env.vars.iter().map(|(k, v)| (k, v)))
            .args(["--json", "--no-daemon-start", "--project", &t.p])
            .args(["baseline", "materialize", &t.v1, "--apply"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    let (a, b) = (spawn(), spawn());
    let outs = [a.wait_with_output().unwrap(), b.wait_with_output().unwrap()];
    let ok = outs.iter().filter(|o| o.status.success()).count();
    let stderr: Vec<_> = outs
        .iter()
        .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
        .collect();
    assert!(ok >= 1, "{stderr:?}");
    for (o, e) in outs.iter().zip(&stderr) {
        if !o.status.success() {
            // The project writer lock (or, if the first already journaled, the WAL gate).
            assert!(
                e.contains("PROJECT_LOCKED") || e.contains("unfinished_operation"),
                "{e}"
            );
        }
    }
    assert_eq!(t.tree(), v1_tree());
    let ops = t.ops();
    assert!(ops.iter().all(|o| o["state"] == "Completed"), "{ops:?}");
}
