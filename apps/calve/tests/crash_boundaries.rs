//! Crash injection at the authoritative cross-store boundaries (P25, requirement 5): the process
//! aborts right after OpenAEVC accepted a command (`openaevc.<Command>`), before Calve's own
//! store records it, and in the middle of product-DB migration and restore. Every case must
//! converge on the next run, or stop in an explicit RECOVERY_REQUIRED, with nothing lost or
//! applied twice. (Capture sessions, the supersede saga, installs and the materialization WAL
//! have their own crash matrices.)
#![cfg(unix)]

use std::fs;
use std::path::PathBuf;

use calve_testkit::Env;
use serde_json::Value;

struct T {
    env: Env,
    p: String,
}

impl T {
    fn new() -> Self {
        let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
        env.vars
            .push(("CALVE_JSON_RECORD".into(), env.path().join("rec").into()));
        let root = env.path().join("project");
        let p = root.to_str().unwrap().to_owned();
        env.ok(&["init", &p]);
        env.enable_toy(&root);
        T { env, p }
    }
    fn root(&self) -> PathBuf {
        PathBuf::from(&self.p)
    }
    fn args<'a>(&'a self, a: &[&'a str]) -> Vec<&'a str> {
        [&["--project", self.p.as_str()][..], a].concat()
    }
    fn ok(&self, a: &[&str]) -> Value {
        self.env.ok(&self.args(a))
    }
    /// Runs `a` with a crash point; the process must die there.
    fn crash(&mut self, point: &str, a: &[&str]) {
        let saved = self.env.vars.clone();
        self.env.vars.push(("CALVE_FAULT".into(), point.into()));
        let run = self.env.run(&self.args(a));
        self.env.vars = saved;
        assert!(!run.success, "{point}: expected a crash, got {}", run.value);
    }
    fn promoted(&self, title: &str, file: &str) -> (String, String) {
        fs::write(self.root().join(file), title).unwrap();
        let id = self.ok(&["pack", "create", title])["id"]
            .as_str()
            .unwrap()
            .to_owned();
        self.ok(&["pack", "capture", &id, file, "--generation", "1"]);
        let g = self.ok(&["pack", "show", &id])["generation"].to_string();
        self.ok(&["pack", "seal", &id, "--generation", &g]);
        self.ok(&["pack", "qualify", &id, "--generation", &g]);
        let d = self.ok(&["pack", "promote", &id, "--generation", &g])["promoted_digest"]
            .as_str()
            .unwrap()
            .to_owned();
        (id, d)
    }
    fn packs_titled(&self, title: &str) -> Vec<Value> {
        self.ok(&["pack", "list"])
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["title"] == title)
            .cloned()
            .collect()
    }
}

#[test]
fn a_crash_after_each_openaevc_command_converges() {
    let mut t = T::new();
    // Pack creation: OpenAEVC holds the pack (and its title); Calve's index is rebuilt from it.
    t.crash("openaevc.CreateChangePack", &["pack", "create", "orphan"]);
    let found = t.packs_titled("orphan");
    assert_eq!(
        found.len(),
        1,
        "the pack is listed once, with its title: {found:?}"
    );
    let orphan = found[0]["id"].as_str().unwrap().to_owned();
    fs::write(t.root().join("o.txt"), "o").unwrap();
    t.ok(&["pack", "capture", &orphan, "o.txt", "--generation", "1"]);

    // Seal: the state shown is OpenAEVC's; a retry is refused, not re-applied.
    let g = t.ok(&["pack", "show", &orphan])["generation"].to_string();
    t.crash(
        "openaevc.SealChangePack",
        &["pack", "seal", &orphan, "--generation", &g],
    );
    assert_eq!(t.ok(&["pack", "show", &orphan])["state"], "SEALED");
    assert_eq!(t.packs_titled("orphan")[0]["state"], "SEALED");
    t.ok(&["pack", "qualify", &orphan, "--generation", &g]);

    // Promotion: one record; the retry returns the same digest.
    t.crash(
        "openaevc.PromoteChangePack",
        &["pack", "promote", &orphan, "--generation", &g],
    );
    assert_eq!(t.ok(&["pack", "show", &orphan])["state"], "PROMOTED");
    let again = t.ok(&["pack", "promote", &orphan, "--generation", &g]);
    assert_eq!(again["already_promoted"], true, "{again}");
    let digest = again["promoted_digest"].as_str().unwrap().to_owned();

    // Baseline: listed once with its label (kept in OpenAEVC metadata).
    t.crash(
        "openaevc.CreateBaseline",
        &["baseline", "create", "crashed", &digest],
    );
    let baselines = t.ok(&["baseline", "list"]);
    let labelled: Vec<&Value> = baselines
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["label"] == "crashed")
        .collect();
    assert_eq!(labelled.len(), 1, "{baselines}");

    // Abandon.
    let doomed = t.ok(&["pack", "create", "doomed"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.crash(
        "openaevc.AbandonChangePack",
        &["pack", "abandon", &doomed, "--generation", "1", "--yes"],
    );
    assert_eq!(t.ok(&["pack", "show", &doomed])["state"], "ABANDONED");

    // Extension registration: re-enabling converges to one active registration.
    t.ok(&["extension", "disable", "org.example.toy"]);
    t.crash(
        "openaevc.RegisterExtension",
        &[
            "extension",
            "enable",
            "org.example.toy",
            "--acknowledge-native",
        ],
    );
    t.ok(&[
        "extension",
        "enable",
        "org.example.toy",
        "--acknowledge-native",
    ]);
    let active: Vec<Value> = t
        .ok(&["extension", "list"])
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["id"] == "org.example.toy" && e["active"] == true)
        .cloned()
        .collect();
    assert_eq!(active.len(), 1);

    assert_eq!(t.ok(&["maintenance", "check"])["ok"], true);
    assert_eq!(t.ok(&["maintenance", "verify-store"])["ok"], true);
}

#[test]
fn a_crash_after_the_remaining_commands_converges() {
    let mut t = T::new();
    // RegisterPolicy (review requirement) then CreateChangePack.
    t.crash(
        "openaevc.RegisterPolicy",
        &["pack", "create", "reviewed", "--require-review"],
    );
    assert!(t.packs_titled("reviewed").is_empty(), "no pack exists yet");
    let id = t.ok(&["pack", "create", "reviewed", "--require-review"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(t.packs_titled("reviewed").len(), 1);
    fs::write(t.root().join("r.txt"), "r").unwrap();
    t.ok(&["pack", "capture", &id, "r.txt", "--generation", "1"]);
    let g = t.ok(&["pack", "show", &id])["generation"].to_string();
    t.ok(&["pack", "seal", &id, "--generation", &g]);
    // Verification, evaluation and evidence: recorded once in OpenAEVC, visible after the crash.
    t.crash(
        "openaevc.RunVerification",
        &["pack", "verify", &id, "--generation", &g],
    );
    t.crash(
        "openaevc.RunEvaluation",
        &["pack", "evaluate", &id, "--generation", &g],
    );
    fs::write(t.root().join("ev.bin"), "evidence").unwrap();
    let ev = t.root().join("ev.bin");
    t.crash(
        "openaevc.RegisterEvidence",
        &[
            "evidence",
            "add",
            &id,
            "--generation",
            &g,
            "--kind",
            "org.example.note",
            "--file",
            ev.to_str().unwrap(),
        ],
    );
    assert_eq!(
        t.ok(&["evidence", "list", &id])["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Qualification is a refresh: a crash and a rerun give one current decision.
    t.crash(
        "openaevc.RefreshQualification",
        &["pack", "qualify", &id, "--generation", &g],
    );
    t.ok(&["pack", "qualify", &id, "--generation", &g]);
    // Reopen moves to a new generation exactly once.
    t.crash(
        "openaevc.ReopenChangePack",
        &["pack", "reopen", &id, "--generation", &g],
    );
    let shown = t.ok(&["pack", "show", &id]);
    assert_eq!(shown["state"], "OPEN");
    assert_eq!(
        shown["generation"].as_u64().unwrap(),
        g.parse::<u64>().unwrap() + 1
    );
    let refused = t
        .env
        .run(&t.args(&["pack", "reopen", &id, "--generation", &g]));
    assert!(!refused.success, "a stale reopen is refused");
    // Quarantine and release.
    t.crash(
        "openaevc.QuarantineChangePack",
        &["pack", "quarantine", &id, "--reason", "check"],
    );
    assert_eq!(t.ok(&["pack", "show", &id])["state"], "QUARANTINED");
    t.crash(
        "openaevc.ReleaseQuarantine",
        &["pack", "release-quarantine", &id],
    );
    assert_eq!(t.ok(&["pack", "show", &id])["state"], "OPEN");
    // A revision of a promoted pack.
    let (_, digest) = t.promoted("base", "b.txt");
    t.crash(
        "openaevc.CreateRevisionPack",
        &[
            "revision",
            "create",
            "R",
            "--of",
            &digest,
            "--relation",
            "amends",
        ],
    );
    assert_eq!(t.packs_titled("R").len(), 1, "listed once, with its title");
    // A principal for a named identity, then its grant.
    t.crash(
        "openaevc.RegisterPrincipal",
        &[
            "authority",
            "identity-add",
            "agent",
            "--action",
            "changepack.create",
        ],
    );
    let again = t.env.run(&t.args(&[
        "authority",
        "identity-add",
        "agent",
        "--action",
        "changepack.create",
    ]));
    assert!(
        again.success,
        "the interrupted identity is completed or replaced: {}",
        again.stderr
    );
    // The pack's Intent link (UpdateChangePack): OpenAEVC's link is shown after the crash.
    let intent = t.ok(&["intent", "create", "goal"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let g = t.ok(&["pack", "show", &id])["generation"].to_string();
    t.crash(
        "openaevc.UpdateChangePack",
        &["pack", "set-intent", &id, &intent, "--generation", &g],
    );
    assert_eq!(t.packs_titled("reviewed")[0]["intent"], intent.as_str());
    // Grants: after a crash the issued grant is OpenAEVC's and is shown; revocation likewise.
    let actor = t
        .ok(&["authority", "identities"])
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "agent")
        .map(|i| i["principal"].as_str().unwrap().to_owned())
        .expect("agent identity");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let expiry =
        openaevc::protocol::Timestamp::from_unix_nanos(now as i128 + 3_600_000_000_000).to_string();
    let grant = [
        "authority",
        "grant",
        actor.as_str(),
        "--action",
        "org.calve.test.read",
        "--expires-at",
        expiry.as_str(),
        "--apply",
    ];
    t.crash("openaevc.IssueCapabilityGrant", &grant);
    let grants = t.ok(&["authority", "grants"]);
    let issued: Vec<&Value> = grants
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g.to_string().contains("org.calve.test.read"))
        .collect();
    assert_eq!(issued.len(), 1, "{grants}");
    let gid = issued[0]["grant"]["body"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{}", issued[0]))
        .to_owned();
    t.crash(
        "openaevc.RevokeCapabilityGrant",
        &["authority", "revoke", &gid, "--yes"],
    );
    assert_eq!(t.ok(&["authority", "show", &gid])["revoked"], true);
    // Adopt-copy imports the closure; a crash mid-import leaves the copy restorable.
    let copy = t.env.path().join("copy");
    calve_testkit::copy_tree(&t.root(), &copy);
    let c = copy.to_str().unwrap().to_owned();
    let saved = t.env.vars.clone();
    t.env
        .vars
        .push(("CALVE_FAULT".into(), "openaevc.PutImmutableObject".into()));
    assert!(
        !t.env
            .run(&["project", "adopt-copy", &c, "--name", "Fork"])
            .success
    );
    t.env.vars = saved;
    let plan = t.env.ok(&["--project", &c, "recover", "plan"]);
    assert!(
        plan.to_string().contains("adopt"),
        "the interrupted adoption is listed: {plan}"
    );
    t.env.ok(&["--project", &c, "recover", "apply", "--yes"]);
    let adopted = t.env.ok(&["project", "adopt-copy", &c, "--name", "Fork"]);
    assert!(
        adopted["transferred_objects"].as_u64().unwrap() > 1,
        "{adopted}"
    );
    // A crash after the adoption completed: the adopted Project stays, the source backup goes.
    let copy2 = t.env.path().join("copy2");
    calve_testkit::copy_tree(&t.root(), &copy2);
    let c2 = copy2.to_str().unwrap().to_owned();
    let saved = t.env.vars.clone();
    t.env
        .vars
        .push(("CALVE_FAULT".into(), "adopt.after_complete".into()));
    assert!(!t.env.run(&["project", "adopt-copy", &c2]).success);
    t.env.vars = saved;
    let plan = t.env.ok(&["--project", &c2, "recover", "plan"]);
    assert!(plan.to_string().contains("completed adoption"), "{plan}");
    t.env.ok(&["--project", &c2, "recover", "apply", "--yes"]);
    let id2 = t.env.ok(&["--project", &c2, "status"])["project"]["project_id"].clone();
    assert_ne!(
        id2,
        t.ok(&["status"])["project"]["project_id"],
        "the copy has its own identity"
    );
    assert!(
        !t.env
            .ok(&["--project", &c2, "receipt", "list", "--limit", "100"])["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Disable: OpenAEVC unregisters; Calve's view follows.
    t.crash(
        "openaevc.UnregisterExtension",
        &["extension", "disable", "org.example.toy"],
    );
    let toy: Vec<Value> = t
        .ok(&["extension", "list"])
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["id"] == "org.example.toy" && e["active"] == true)
        .cloned()
        .collect();
    assert!(toy.is_empty(), "{toy:?}");
    assert_eq!(t.ok(&["maintenance", "check"])["ok"], true);
}

/// Init sends one OpenAEVC command (CreateNamespace) and then publishes its staged `.calve`
/// with one rename, so the only cross-store crash is after the Namespace exists.
#[test]
fn a_crash_during_init_is_recoverable() {
    let mut env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let root = env.path().join("fresh");
    let p = root.to_str().unwrap().to_owned();
    env.vars
        .push(("CALVE_FAULT".into(), "openaevc.CreateNamespace".into()));
    assert!(!env.run(&["init", &p]).success);
    env.vars.pop();
    // Nothing was published: no half Project to open.
    assert!(!root.join(".calve").exists());
    assert!(!env.run(&["--project", &p, "status"]).success);
    let again = env.run(&["init", &p]);
    assert!(again.success, "{}", again.stderr);
    assert!(env.ok(&["--project", &p, "status"])["project"]["project_id"].is_string());
    // The staging directory left behind is Calve's, never captured as user content; recovery
    // removes it once it is provably stale.
    let staged: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".calve-init-"))
        .collect();
    assert_eq!(staged.len(), 1, "{staged:?}");
    env.enable_toy(&root);
    let scan = env.ok(&["--project", &p, "resource", "scan"]);
    assert!(!scan.to_string().contains(".calve-init-"), "{scan}");
}

#[test]
fn a_crash_during_migration_or_restore_converges() {
    let mut t = T::new();
    let (pack, _) = t.promoted("kept", "k.txt");
    let intent = t.ok(&["intent", "create", "survives"])["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let db_path = t.root().join(".calve/product.sqlite3");
    let downgrade = || {
        let db = rusqlite::Connection::open(&db_path).unwrap();
        db.execute_batch(
            "DROP TRIGGER pack_link_added; DROP TRIGGER pack_link_removed;
             DROP TRIGGER pack_link_moved; DROP TRIGGER pack_metadata_changed;
             DROP TABLE pack_commitments; DELETE FROM schema_migrations WHERE version=15;
             PRAGMA user_version=14;",
        )
        .unwrap();
    };
    let version = || -> u32 {
        rusqlite::Connection::open(&db_path)
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    };
    for point in ["migration.after_backup", "migration.step"] {
        downgrade();
        t.crash(point, &["intent", "create", "migrating"]);
        // The step is one transaction: the database is at 14 or 15, never in between.
        assert!(matches!(version(), 14 | 15), "{point}");
        // Reads refuse an old schema (MIGRATION_REQUIRED); a write migrates.
        t.ok(&["intent", "create", "after the crash"]);
        assert_eq!(version(), 15, "{point}");
        assert_eq!(t.ok(&["pack", "show", &pack])["state"], "PROMOTED");
        assert!(t.ok(&["intent", "show", &intent])["id"].is_string());
    }

    // Restore: a crash before the swap leaves the current database; before reconciliation, the
    // restored one, which the rerun reconciles.
    let backups = t.ok(&["recover", "inspect"])["backups"].clone();
    let file = backups
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["kind"] == "pre-migration")
        .map(|b| b["file"].as_str().unwrap().to_owned())
        .expect("a pre-migration backup");
    for point in ["restore.before_swap", "restore.before_reconcile"] {
        t.crash(
            point,
            &["recover", "apply", "--restore-backup", &file, "--yes"],
        );
        let done = t.ok(&["recover", "apply", "--restore-backup", &file, "--yes"]);
        assert!(done.to_string().contains(&file), "{point}: {done}");
        assert_eq!(
            t.ok(&["pack", "show", &pack])["state"],
            "PROMOTED",
            "{point}"
        );
        assert_eq!(t.packs_titled("kept").len(), 1, "{point}");
        assert_eq!(t.ok(&["maintenance", "check"])["ok"], true, "{point}");
    }
}
