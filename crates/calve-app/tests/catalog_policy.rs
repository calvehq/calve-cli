//! G1-TUF: Calve's signed-catalog policy (ADR 0021) on top of the verifier. Each case is
//! accepted by TUF itself and refused by policy, proving the layer is not vacuous.

use calve_app::catalog::tuf::{Limits, Mirror, TrustClient, TrustError};
use calve_testkit::tuf::*;
use jiff::Timestamp;
use serde_json::json;

/// A client over `repo`'s directory mirror, bootstrapped from root v1, no store.
fn client(repo: &Repo) -> (TrustClient, Mirror) {
    let m = Mirror::dir(repo.path());
    (
        TrustClient::new(m.clone(), &repo.root_bytes(1), None, Limits::default()).unwrap(),
        m,
    )
}

fn refused(r: &Repo, target: Option<&str>) -> String {
    let (mut c, _) = client(r);
    let res = c.refresh(Timestamp::now()).and_then(|()| match target {
        Some(t) => c.resolve(t, Timestamp::now()).map(|_| ()),
        None => Ok(()),
    });
    match res {
        Err(TrustError::Policy(m)) => m,
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

#[test]
fn baseline_is_accepted() {
    let mut r = Repo::new();
    r.delegate("a", "targets", &["*"], false)
        .targets
        .insert("x".into(), b"x".to_vec());
    r.publish();
    let (mut c, _) = client(&r);
    c.refresh(Timestamp::now()).unwrap();
    assert!(c.resolve("x", Timestamp::now()).unwrap().is_some());
}

#[test]
fn root_key_policy() {
    // Non-ed25519 key listed in root (unused by any role: TUF accepts).
    let mut r = Repo::new();
    let ec = json!({"keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256", "keyval": {"public": "04abcdef"}});
    r.root_extra_keys.insert(sha(&canonical(&ec)), ec);
    r.publish();
    assert!(refused(&r, None).contains("ed25519"));

    // Declared key id that is not the hash of the key.
    let mut r = Repo::new();
    let k = SignKey::new();
    r.root_extra_keys.insert("00".repeat(32), k.json());
    r.publish();
    assert!(refused(&r, None).contains("computed"));

    // The same key material under two ids (would let one key count twice toward a threshold).
    let mut r = Repo::new();
    let mut alias = r.timestamp.json();
    alias["keyval"]["public"] = json!(r.timestamp.public_hex().to_uppercase());
    r.root_extra_keys.insert(sha(&canonical(&alias)), alias);
    r.publish();
    assert!(refused(&r, None).contains("more than one id"));

    // Producer-specific extra fields on a key.
    let mut r = Repo::new();
    let mut extra = SignKey::new().json();
    extra["x-tuf-on-ci-keyowner"] = json!("@someone");
    r.root_extra_keys.insert(sha(&canonical(&extra)), extra);
    r.publish();
    assert!(refused(&r, None).contains("non-standard"));
}

#[test]
fn consistent_snapshot_required() {
    let mut r = Repo::new();
    r.consistent = false;
    r.publish();
    assert!(refused(&r, None).contains("consistent_snapshot"));
}

#[test]
fn sha256_target_hash_required() {
    let mut r = Repo::new();
    r.hash_algos = vec!["sha512"];
    r.targets.insert("x".into(), b"x".to_vec());
    r.publish();
    assert!(refused(&r, Some("x")).contains("sha256"));
}

#[test]
fn delegation_keys_follow_the_same_policy() {
    // A delegator listing an extra non-ed25519 key in its delegations block.
    let mut r = Repo::new();
    r.delegate("a", "targets", &["*"], false)
        .targets
        .insert("x".into(), b"x".to_vec());
    r.publish();
    // Rewrite targets with an extra delegation key, re-sign, and repin snapshot/timestamp.
    let mpath = r.path().join("metadata/1.targets.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&mpath).unwrap()).unwrap();
    let ec =
        json!({"keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256", "keyval": {"public": "x"}});
    let id = sha(&canonical(&ec));
    v["signed"]["delegations"]["keys"][id] = ec;
    let tb = envelope(v["signed"].clone(), &[&r.targets_key]);
    std::fs::write(&mpath, &tb).unwrap();
    // Snapshot pins targets.json by version only, so the timestamp/snapshot stay valid.
    assert!(refused(&r, Some("x")).contains("ed25519"));
}
