//! G1-TUF regression tests (Decision 1): delegation traversal, path restrictions, terminating
//! roles, unusual role names, consistent-snapshot paths, timestamp behaviour, bounded errors.
//! Each case corresponds to an FG2c failure class of tough 0.24 (docs/audit/spikes/FG02.md).

use calve_app::catalog::tuf::{Limits, Mirror, TrustClient, TrustError, encode_role};
use calve_testkit::tuf::*;
use jiff::Timestamp;

/// A client over `repo`'s directory mirror, bootstrapped from root v1, no store.
fn client(repo: &Repo) -> (TrustClient, Mirror) {
    let m = Mirror::dir(repo.path());
    (
        TrustClient::new(m.clone(), &repo.root_bytes(1), None, Limits::default()).unwrap(),
        m,
    )
}

fn now() -> Timestamp {
    Timestamp::now()
}

fn metas(m: &Mirror) -> Vec<String> {
    m.fetched()
        .into_iter()
        .filter(|f| f.starts_with("m:"))
        .map(|f| f[2..].to_owned())
        .collect()
}

/// Fetched delegated role names (version prefix stripped, `.json` removed).
fn roles_fetched(m: &Mirror) -> Vec<String> {
    metas(m)
        .into_iter()
        .filter_map(|n| {
            let n = n.strip_suffix(".json")?;
            let n = n.split_once('.').map_or(n, |(v, r)| {
                if v.bytes().all(|b| b.is_ascii_digit()) {
                    r
                } else {
                    n
                }
            });
            (!["root", "timestamp", "snapshot", "targets"].contains(&n) && !n.ends_with("root"))
                .then(|| n.to_owned())
        })
        .collect()
}

#[test]
fn lazy_preorder_traversal_fetches_only_the_search_path() {
    let mut r = Repo::new();
    r.delegate("a", "targets", &["*"], false);
    r.delegate("a1", "a", &["*"], false);
    r.delegate("b", "targets", &["*"], false)
        .targets
        .insert("x".into(), b"in-b".to_vec());
    r.delegate("c", "targets", &["*"], false);
    r.delegate("z", "targets", &["other/*"], false);
    r.publish();
    let (mut c, m) = client(&r);
    c.refresh(now()).unwrap();
    assert!(
        roles_fetched(&m).is_empty(),
        "refresh loads no delegated role: {:?}",
        metas(&m)
    );
    let t = c.resolve("x", now()).unwrap().expect("found in b");
    assert_eq!(t.length, 4);
    // Pre-order DFS: a, then a's child a1, then b (found) — never c (after the hit) nor z (path).
    assert_eq!(roles_fetched(&m), ["a", "a1", "b"]);
    assert_eq!(c.download(&t).unwrap(), b"in-b");
}

#[test]
fn terminating_delegation_stops_the_search() {
    let mut r = Repo::new();
    r.delegate("a", "targets", &["*"], true);
    r.delegate("b", "targets", &["*"], false)
        .targets
        .insert("x".into(), b"b".to_vec());
    r.publish();
    let (mut c, m) = client(&r);
    c.refresh(now()).unwrap();
    assert!(
        c.resolve("x", now()).unwrap().is_none(),
        "a is terminating and lacks x"
    );
    assert_eq!(roles_fetched(&m), ["a"], "b is never consulted");
}

#[test]
fn terminating_only_applies_when_its_paths_match() {
    let mut r = Repo::new();
    r.delegate("a", "targets", &["other/*"], true);
    r.delegate("b", "targets", &["*"], false)
        .targets
        .insert("x".into(), b"b".to_vec());
    r.publish();
    let (mut c, m) = client(&r);
    c.refresh(now()).unwrap();
    assert!(c.resolve("x", now()).unwrap().is_some());
    assert_eq!(roles_fetched(&m), ["b"]);
}

#[test]
fn out_of_path_targets_are_not_trusted_and_do_not_break_resolution() {
    let mut r = Repo::new();
    let a = r.delegate("acme", "targets", &["acme/*"], false);
    a.targets.insert("acme/ok".into(), b"ok".to_vec());
    a.targets.insert("evil/pkg".into(), b"evil".to_vec()); // outside acme's paths
    r.delegate("evil", "targets", &["evil/*"], false);
    r.publish();
    let (mut c, _) = client(&r);
    c.refresh(now()).unwrap();
    assert!(
        c.resolve("acme/ok", now()).unwrap().is_some(),
        "one bad entry does not fail the role"
    );
    assert!(
        c.resolve("evil/pkg", now()).unwrap().is_none(),
        "acme cannot sign outside acme/*"
    );
    // Glob is per path segment: acme/* does not cover acme/sub/x.
    r.deleg("acme")
        .targets
        .insert("acme/sub/x".into(), b"deep".to_vec());
    r.publish();
    let (mut c, _) = client(&r);
    c.refresh(now()).unwrap();
    assert!(c.resolve("acme/sub/x", now()).unwrap().is_none());
}

#[test]
fn unusual_role_names_are_fetched_encoded_and_contained() {
    for name in ["?", "#", "/x", "../x", "..", "a b", "%41", "role.with.dots"] {
        let mut r = Repo::new();
        r.delegate(name, "targets", &["*"], false)
            .targets
            .insert("t".into(), name.as_bytes().to_vec());
        r.publish();
        let (mut c, m) = client(&r);
        c.refresh(now()).unwrap();
        let t = c
            .resolve("t", now())
            .unwrap()
            .unwrap_or_else(|| panic!("{name:?}: not resolved; fetched {:?}", metas(&m)));
        assert_eq!(c.download(&t).unwrap(), name.as_bytes());
        let enc = encode_role(name);
        assert!(
            metas(&m).contains(&format!("1.{enc}.json")),
            "{name:?}: fetched {:?}",
            metas(&m)
        );
        assert!(!enc.contains('/'));
    }
}

#[test]
fn top_level_role_names_cannot_be_delegated() {
    let mut r = Repo::new();
    r.delegate("snapshot", "targets", &["*"], false)
        .targets
        .insert("t".into(), b"x".to_vec());
    r.publish();
    let (mut c, m) = client(&r);
    c.refresh(now()).unwrap();
    assert!(c.resolve("t", now()).unwrap().is_none());
    assert!(roles_fetched(&m).is_empty());
}

#[test]
fn consistent_snapshot_target_path_prefixes_the_file_name_only() {
    let mut r = Repo::new();
    r.targets
        .insert("acme/1.0.0/pkg.tar".into(), b"payload".to_vec());
    r.publish();
    let (mut c, m) = client(&r);
    c.refresh(now()).unwrap();
    let t = c.resolve("acme/1.0.0/pkg.tar", now()).unwrap().unwrap();
    assert_eq!(c.download(&t).unwrap(), b"payload");
    let want = format!("t:acme/1.0.0/{}.pkg.tar", sha(b"payload"));
    assert!(m.fetched().contains(&want), "fetched {:?}", m.fetched());
    // Consistent snapshot also versions every metadata file except timestamp.
    assert!(
        metas(&m).contains(&"1.snapshot.json".to_owned())
            && metas(&m).contains(&"1.targets.json".to_owned())
    );
}

#[test]
fn same_version_timestamp_with_changed_content_is_ignored() {
    let mut r = Repo::new();
    r.publish();
    let (mut c, m) = client(&r);
    c.refresh(now()).unwrap();
    // Same version 1, new expiry (content change): keep the trusted copy, no error.
    r.expires.insert("timestamp", in_days(60));
    r.write_timestamp(1, 1);
    c.refresh(now()).unwrap();
    let ts = c.trusted().timestamp().unwrap();
    assert!(
        ts.expires < in_days(45),
        "the changed same-version timestamp was not adopted"
    );
    // No re-fetch of snapshot or targets when the timestamp is unchanged.
    assert_eq!(
        metas(&m).iter().filter(|n| n.contains("snapshot")).count(),
        1
    );
}

#[test]
fn timestamp_and_snapshot_rollback_rejected() {
    let mut r = Repo::new();
    r.publish();
    r.publish();
    let (mut c, _) = client(&r);
    c.refresh(now()).unwrap();
    r.write_timestamp(1, 1);
    assert!(
        matches!(c.refresh(now()), Err(TrustError::Tuf(_))),
        "timestamp version rollback"
    );
    r.write_timestamp(3, 1);
    assert!(
        c.refresh(now()).is_err(),
        "timestamp pinning an older snapshot"
    );
}

#[test]
fn expired_metadata_rejected_at_every_level() {
    for role in ["root", "timestamp", "snapshot", "targets"] {
        let mut r = Repo::new();
        r.expires.insert(role, in_days(-1));
        r.publish();
        let (mut c, _) = client(&r);
        assert!(c.refresh(now()).is_err(), "{role} expired");
    }
    // An expired delegated role: refresh succeeds, resolution through it fails closed.
    let mut r = Repo::new();
    r.delegate("a", "targets", &["*"], false)
        .targets
        .insert("x".into(), b"x".to_vec());
    r.publish();
    let (mut c, _) = client(&r);
    c.refresh(now()).unwrap();
    assert!(
        c.resolve("x", now() + jiff::SignedDuration::from_hours(24 * 40))
            .is_err()
    );
}

#[test]
fn delegated_role_signed_by_the_wrong_key_or_not_in_snapshot() {
    let mut r = Repo::new();
    r.delegate("a", "targets", &["*"], false)
        .targets
        .insert("x".into(), b"x".to_vec());
    r.publish();
    // Re-sign a's metadata with a foreign key but keep the snapshot pin consistent.
    let foreign = SignKey::new();
    let path = r.path().join("metadata/1.a.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let forged = envelope(v["signed"].clone(), &[&foreign]);
    std::fs::write(&path, &forged).unwrap();
    let (mut c, _) = client(&r);
    c.refresh(now()).unwrap();
    assert!(
        c.resolve("x", now()).is_err(),
        "hash pin and signature both fail"
    );

    let mut r = Repo::new();
    r.delegate("a", "targets", &["*"], false)
        .targets
        .insert("x".into(), b"x".to_vec());
    r.deleg("a").in_snapshot = false;
    r.publish();
    let (mut c, m) = client(&r);
    c.refresh(now()).unwrap();
    assert!(c.resolve("x", now()).unwrap().is_none());
    assert!(
        roles_fetched(&m).is_empty(),
        "a role absent from the snapshot is never fetched"
    );
}

#[test]
fn delegation_cycles_and_fanout_are_bounded() {
    let mut r = Repo::new();
    r.delegate("a", "targets", &["*"], false);
    r.delegate("b", "a", &["*"], false);
    r.delegate("a", "b", &["*"], false); // b delegates back to a (cycle)
    r.publish();
    let (mut c, _) = client(&r);
    c.refresh(now()).unwrap();
    let t0 = std::time::Instant::now();
    assert!(matches!(c.resolve("x", now()), Ok(None) | Err(_)));
    assert!(t0.elapsed().as_secs() < 5);

    let mut r = Repo::new();
    for i in 0..40 {
        r.delegate(&format!("r{i}"), "targets", &["*"], false);
    }
    r.deleg("r39").targets.insert("x".into(), b"x".to_vec());
    r.publish();
    let m = Mirror::dir(r.path());
    let mut cfg = Limits::default();
    cfg.max_delegations = 8;
    let mut c = TrustClient::new(m.clone(), &r.root_bytes(1), None, cfg).unwrap();
    c.refresh(now()).unwrap();
    assert!(
        c.resolve("x", now()).unwrap().is_none(),
        "search stops at max_delegations"
    );
    assert!(
        roles_fetched(&m).len() <= 8,
        "fetched {}",
        roles_fetched(&m).len()
    );
}

#[test]
fn non_consistent_repository_paths() {
    // Calve's policy refuses this (consistent_snapshot must be true); the verifier fetched the
    // unversioned names before policy refused the root.
    let mut r = Repo::new();
    r.consistent = false;
    r.targets.insert("d/f".into(), b"f".to_vec());
    r.publish();
    let (mut c, m) = client(&r);
    assert!(matches!(c.refresh(now()), Err(TrustError::Policy(_))));
    assert!(metas(&m).contains(&"snapshot.json".to_owned()));
    // A caller that ignores the refused refresh still cannot resolve through it.
    assert!(matches!(
        c.resolve("d/f", now()),
        Err(TrustError::Policy(_))
    ));
}
