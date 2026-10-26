//! FG15 rerun on sigstore-tuf 0.15.0 (rev 10 §9.2): crash at every commit step over three
//! consecutive refreshes, damage and loss of every artifact, orphan and foreign generations,
//! interrupted root rotation, delegation removal, root pin and the audited reset — plus the
//! G1-TUF additions: lazily loaded delegated roles persist in the generation, the stored state
//! is replayed through the verifier, and a clock stepped back cannot resurrect expired metadata.

use std::fs;
use std::path::Path;

use calve_app::catalog::state::*;
use calve_app::catalog::tuf::Mirror;
use calve_testkit::tuf::*;

fn repo() -> Repo {
    let mut r = Repo::new();
    r.delegate("acme", "targets", &["acme/*"], false)
        .targets
        .insert("acme/pkg".into(), b"v0".to_vec());
    r
}

fn publish(r: &mut Repo, content: &[u8]) {
    r.deleg("acme")
        .targets
        .insert("acme/pkg".into(), content.to_vec());
    r.publish();
}

fn boot(r: &Repo, dir: &Path) -> Catalog {
    let root = r.root_bytes(1);
    Catalog::bootstrap(dir, &root, &sha(&root), &Mirror::dir(r.path())).unwrap()
}

#[test]
fn fg15_crash_at_every_step_over_three_refreshes() {
    for step in STEPS {
        let mut r = repo();
        publish(&mut r, b"v1");
        let old = r.freeze();
        let d = tempfile::tempdir().unwrap();
        let mut c = boot(&r, d.path());
        publish(&mut r, b"v1b");
        c.resolve(&Mirror::dir(r.path()), "acme/pkg", None)
            .unwrap()
            .unwrap();
        for round in 0..3 {
            publish(&mut r, format!("v{}", round + 2).as_bytes());
            let before = c.versions.clone();
            let res = c.resolve(&Mirror::dir(r.path()), "acme/pkg", Some(step));
            assert_eq!(res, Err(GenError::Crash(step)));
            let c2 =
                Catalog::open(d.path()).unwrap_or_else(|e| panic!("{step:?} round {round}: {e:?}"));
            assert!(
                c2.versions.at_least(&before),
                "{step:?}: effective floors never drop"
            );
            let mut c3 = Catalog::open(d.path()).unwrap();
            assert!(
                c3.refresh(&Mirror::dir(old.path()), None).is_err(),
                "{step:?}: rollback after recovery"
            );
            c = Catalog::open(d.path()).unwrap();
            let t = c
                .resolve(&Mirror::dir(r.path()), "acme/pkg", None)
                .unwrap()
                .unwrap();
            assert_eq!(t.length, 2);
        }
        println!(
            "{step:?}: 3 crashes recovered, rollback refused, refresh continues (root {} ts {} acme {:?})",
            c.versions.root,
            c.versions.timestamp,
            c.versions.delegations.get("acme")
        );
    }
}

#[test]
fn fg15_delegated_role_persists_and_replays() {
    let mut r = repo();
    publish(&mut r, b"v1");
    let d = tempfile::tempdir().unwrap();
    let mut c = boot(&r, d.path());
    assert!(
        !d.path()
            .join(format!("gen-{}/tuf/acme.json", c.active))
            .exists(),
        "refresh alone loads no delegated role"
    );
    c.resolve(&Mirror::dir(r.path()), "acme/pkg", None)
        .unwrap()
        .unwrap();
    let g = d.path().join(format!("gen-{}", c.active));
    assert!(
        g.join("tuf/acme.json").exists(),
        "lazily loaded role stored in the new generation"
    );
    // Stored bytes are exactly the fetched bytes (no re-serialization).
    assert_eq!(
        fs::read(g.join("tuf/acme.json")).unwrap(),
        fs::read(r.path().join("metadata/1.acme.json")).unwrap()
    );
    let st: serde_json::Value =
        serde_json::from_slice(&fs::read(g.join("state.json")).unwrap()).unwrap();
    let at = st["accepted_at"].as_str().unwrap().parse().unwrap();
    let set = replay(&r.root_bytes(1), &g.join(TUF_DIR), at).unwrap();
    assert!(
        set.targets_role("acme").is_some(),
        "replay verifies the delegated role through its delegator"
    );
    // A stored delegated role signed by someone else (state digest repaired) → RecoveryRequired.
    let mut v: serde_json::Value =
        serde_json::from_slice(&fs::read(g.join("tuf/acme.json")).unwrap()).unwrap();
    v["signed"]["targets"]["acme/pkg"]["length"] = serde_json::json!(999);
    fs::write(g.join("tuf/acme.json"), serde_json::to_vec(&v).unwrap()).unwrap();
    let mut st2 = st.clone();
    st2["state_digest"] = serde_json::json!(state_digest(&g).unwrap());
    fs::write(g.join("state.json"), serde_json::to_vec(&st2).unwrap()).unwrap();
    let sha_state = sha(&fs::read(g.join("state.json")).unwrap());
    fs::write(
        d.path().join("CURRENT"),
        serde_json::to_vec(&serde_json::json!({"gen": c.active, "state_sha256": sha_state}))
            .unwrap(),
    )
    .unwrap();
    let e = Catalog::open(d.path()).unwrap_err();
    println!("tampered delegated role with repaired digests: {e:?}");
    assert!(matches!(e, GenError::RecoveryRequired(m) if m.contains("verifier refused")));
}

#[test]
fn fg15_floors_artifacts_lost_or_ahead() {
    let mut r = repo();
    publish(&mut r, b"v1");
    let d = tempfile::tempdir().unwrap();
    let mut c = boot(&r, d.path());
    publish(&mut r, b"v2");
    c.refresh(&Mirror::dir(r.path()), None).unwrap();
    let v = c.versions.clone();
    fs::remove_file(d.path().join("floors.json")).unwrap();
    assert_eq!(
        Catalog::open(d.path()).unwrap().versions,
        v,
        "floors.json deleted → rewritten from activated state"
    );
    fs::remove_file(d.path().join("floors.json")).unwrap();
    let _ = fs::remove_file(d.path().join("floors.prev.json"));
    assert_eq!(
        Catalog::open(d.path()).unwrap().versions,
        v,
        "both floors files deleted"
    );
    let mut f: serde_json::Value =
        serde_json::from_slice(&fs::read(d.path().join("floors.json")).unwrap()).unwrap();
    f["versions"]["timestamp"] = serde_json::json!(v.timestamp + 5);
    fs::write(
        d.path().join("floors.json"),
        serde_json::to_vec(&f).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        Catalog::open(d.path()),
        Err(GenError::RecoveryRequired(_))
    ));
    // Bootstrap root or REPO_ID damaged → RecoveryRequired.
    f["versions"]["timestamp"] = serde_json::json!(v.timestamp);
    fs::write(
        d.path().join("floors.json"),
        serde_json::to_vec(&f).unwrap(),
    )
    .unwrap();
    assert!(Catalog::open(d.path()).is_ok());
    fs::write(d.path().join("bootstrap-root.json"), b"{}").unwrap();
    assert!(
        matches!(Catalog::open(d.path()), Err(GenError::RecoveryRequired(m)) if m.contains("REPO_ID"))
    );
}

#[test]
fn fg15_damaged_or_foreign_generations() {
    let mut r = repo();
    publish(&mut r, b"v1");
    let d = tempfile::tempdir().unwrap();
    let mut c = boot(&r, d.path());
    publish(&mut r, b"v2");
    c.refresh(&Mirror::dir(r.path()), None).unwrap();
    let active = c.active;
    for f in [
        "targets.json",
        "timestamp.json",
        "snapshot.json",
        "root.json",
        "root_history/1.root.json",
    ] {
        let t = d.path().join(format!("gen-{active}/tuf/{f}"));
        let orig = fs::read(&t).unwrap();
        let mut bad = orig.clone();
        let i = bad.len() / 2;
        bad[i] ^= 1;
        fs::write(&t, &bad).unwrap();
        assert!(
            matches!(Catalog::open(d.path()), Err(GenError::RecoveryRequired(_))),
            "{f} corrupt"
        );
        fs::remove_file(&t).unwrap();
        assert!(
            matches!(Catalog::open(d.path()), Err(GenError::RecoveryRequired(_))),
            "{f} missing"
        );
        fs::write(&t, &orig).unwrap();
    }
    fs::write(d.path().join("CURRENT"), b"{garbage").unwrap();
    assert_eq!(
        Catalog::open(d.path()).unwrap().active,
        active,
        "CURRENT lost → chain selection"
    );
    let c = Catalog::open(d.path()).unwrap();
    for (k, patch) in [
        (active + 1, ("client_accepted", serde_json::json!(false))),
        (active + 1, ("parent_state_digest", serde_json::json!("ff"))),
        (active + 1, ("repo_id", serde_json::json!("other"))),
    ] {
        let g = d.path().join(format!("gen-{k}"));
        let _ = fs::remove_dir_all(&g);
        copy_dir(&d.path().join(format!("gen-{active}")), &g);
        let mut st: serde_json::Value = serde_json::from_slice(
            &fs::read(d.path().join(format!("gen-{active}/state.json"))).unwrap(),
        )
        .unwrap();
        st["gen"] = serde_json::json!(k);
        st["parent_gen"] = serde_json::json!(active);
        st["parent_state_digest"] = serde_json::json!(c.active_state_digest);
        st["state_digest"] = serde_json::json!(state_digest(&g).unwrap());
        st[patch.0] = patch.1.clone();
        fs::write(g.join("state.json"), serde_json::to_vec(&st).unwrap()).unwrap();
        let reopened = Catalog::open(d.path()).unwrap();
        assert_eq!(reopened.active, active, "{}: not activated", patch.0);
        assert!(!g.exists(), "{}: quarantined", patch.0);
    }
    println!(
        "corrupt/missing activated files → RecoveryRequired; CURRENT lost → chain; unaccepted/orphan/foreign → quarantined"
    );
}

#[test]
fn fg15_interrupted_root_rotation() {
    let mut r = repo();
    publish(&mut r, b"v1");
    let d = tempfile::tempdir().unwrap();
    let mut c = boot(&r, d.path());
    r.rotate_root();
    publish(&mut r, b"v2");
    let before = c.versions.clone();
    for step in [Step::ClientAccepted, Step::Prepared, Step::FloorsWritten] {
        let mut c = Catalog::open(d.path()).unwrap();
        let _ = c.refresh(&Mirror::dir(r.path()), Some(step));
        let o = Catalog::open(d.path()).unwrap();
        assert!(
            o.versions == before || o.versions.root > before.root,
            "{step:?}: stays on the activated root or completes the accepted rotation"
        );
    }
    c = Catalog::open(d.path()).unwrap();
    c.refresh(&Mirror::dir(r.path()), None).unwrap();
    assert_eq!(c.versions.root, 2);
    // A root v3 signed only by the old (rotated-out) key is refused.
    r.root = SignKey::new();
    r.old_root = None;
    r.touch_root();
    publish(&mut r, b"v3");
    let e = c.refresh(&Mirror::dir(r.path()), None).unwrap_err();
    println!("root v3 not signed by the current root key: {e:?}");
    assert!(matches!(e, GenError::Refused(_)));
    assert_eq!(Catalog::open(d.path()).unwrap().versions.root, 2);
}

#[test]
fn fg15_delegation_removal_refused_by_client() {
    let mut r = repo();
    publish(&mut r, b"v1");
    let d = tempfile::tempdir().unwrap();
    let mut c = boot(&r, d.path());
    publish(&mut r, b"v2");
    c.refresh(&Mirror::dir(r.path()), None).unwrap();
    let before = c.versions.clone();
    r.deleg("acme").in_snapshot = false;
    r.publish();
    let e = c.refresh(&Mirror::dir(r.path()), None);
    println!("delegation removed from the snapshot: {e:?}");
    assert!(
        matches!(e, Err(GenError::Refused(_))),
        "TUF snapshot rule: a listed role must stay listed"
    );
    assert_eq!(Catalog::open(d.path()).unwrap().versions, before);
}

#[test]
fn fg15_root_pin_and_reset() {
    let mut r = repo();
    publish(&mut r, b"v1");
    let d = tempfile::tempdir().unwrap();
    let root = r.root_bytes(1);
    assert!(
        Catalog::bootstrap(d.path(), &root, &"0".repeat(64), &Mirror::dir(r.path())).is_err(),
        "root digest pin enforced"
    );
    let _c = boot(&r, d.path());
    let mut f: serde_json::Value =
        serde_json::from_slice(&fs::read(d.path().join("floors.json")).unwrap()).unwrap();
    f["versions"]["snapshot"] = serde_json::json!(99);
    fs::write(
        d.path().join("floors.json"),
        serde_json::to_vec(&f).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        Catalog::open(d.path()),
        Err(GenError::RecoveryRequired(_))
    ));
    let c = Catalog::reset(d.path(), &root, &sha(&root), &Mirror::dir(r.path())).unwrap();
    assert!(d.path().join("catalog-reset.log").exists());
    assert!(fs::read_dir(d.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("archive-")
    }));
    assert!(Catalog::open(d.path()).is_ok());
    println!(
        "pin mismatch refused; RecoveryRequired → audited reset → gen {}",
        c.active
    );
}

#[test]
fn fg15_clock_stepped_back_cannot_revive_expired_metadata() {
    // accepted_at in the floors is in the future of the system clock (clock stepped back): the
    // verifier clock stays at accepted_at, so metadata expiring before it is refused.
    let mut r = repo();
    r.expires.insert("timestamp", in_days(1));
    publish(&mut r, b"v1");
    let d = tempfile::tempdir().unwrap();
    let mut c = boot(&r, d.path());
    c.accepted_at = Some(in_days(2));
    publish(&mut r, b"v2"); // timestamp still expires in 1 day: current for the system clock
    let e = c.refresh(&Mirror::dir(r.path()), None).unwrap_err();
    println!("system clock behind the last accepted time: {e:?}");
    assert!(matches!(e, GenError::Refused(m) if m.contains("expired")));
}

/// Security review of ee47ddc: a delegated role named like a Calve file (`state`) is stored in
/// the verifier's own directory and cannot collide with `state.json`, so recovery still works.
#[test]
fn fg15_delegated_role_named_like_a_calve_file_cannot_collide() {
    for name in ["state", "CURRENT", "floors", "REPO_ID"] {
        let mut r = Repo::new();
        r.delegate(name, "targets", &["acme/*"], false)
            .targets
            .insert("acme/pkg".into(), b"x".to_vec());
        r.publish();
        let d = tempfile::tempdir().unwrap();
        let mut c = boot(&r, d.path());
        assert!(
            c.resolve(&Mirror::dir(r.path()), "acme/pkg", None)
                .unwrap()
                .is_some(),
            "{name}"
        );
        let reopened = Catalog::open(d.path()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(reopened.active, c.active, "{name}");
    }
}

/// A refresh after the publisher re-signed its role (new version pinned by the new snapshot)
/// must leave a loadable state: the previous generation's lazily loaded role is stale, so it is
/// pruned from the new generation and fetched again on demand (found by the M5 delegated
/// publisher workflow: before, the next open was RecoveryRequired).
#[test]
fn fg15_refresh_after_a_delegated_role_changed_stays_loadable() {
    let mut r = repo();
    publish(&mut r, b"v1");
    let d = tempfile::tempdir().unwrap();
    let mut c = boot(&r, d.path());
    let m = Mirror::dir(r.path());
    c.resolve(&m, "acme/pkg", None).unwrap().unwrap();
    publish(&mut r, b"v2");
    c.refresh(&m, None).unwrap();
    let g = d.path().join(format!("gen-{}", c.active));
    assert!(
        !g.join("tuf/acme.json").exists(),
        "the stale role is not carried into the new generation"
    );
    let mut c = Catalog::open(d.path()).expect("state stays loadable");
    let got = c.fetch_all(&m, &["acme/pkg"], None).unwrap();
    assert_eq!(got[0].as_ref().unwrap().1, b"v2");
    Catalog::open(d.path()).expect("loadable after the role is fetched again");
}
