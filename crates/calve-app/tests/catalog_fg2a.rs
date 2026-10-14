//! FG2a rerun on sigstore-tuf 0.15.0 (rev 10 §9.2, F23): the verifier's accepted state (the
//! exact bytes written through its store) is persisted, restored after a restart including
//! delegated roles and a rotated root, continues updating, and rejects rollback.

use std::fs;

use calve_app::catalog::state::*;
use calve_app::catalog::tuf::{Limits, Mirror, TrustClient};
use calve_testkit::tuf::*;
use sigstore_tuf::FileStore;

fn now() -> jiff::Timestamp {
    jiff::Timestamp::now()
}

fn repo() -> Repo {
    let mut r = Repo::new();
    r.delegate("acme", "targets", &["acme/*"], false)
        .targets
        .insert("acme/pkg".into(), b"v1".to_vec());
    r.publish();
    r
}

/// A client over `mirror` that starts from the bootstrap root and the persisted store `dir`.
fn restart(r: &Repo, mirror: Mirror, dir: &std::path::Path) -> TrustClient {
    TrustClient::new(
        mirror,
        &r.root_bytes(1),
        Some(Box::new(FileStore::new(dir))),
        Limits::default(),
    )
    .unwrap()
}

#[test]
fn fg2a_restart_restores_delegations_and_continues() {
    let mut r = repo();
    let ds = tempfile::tempdir().unwrap();
    let mut c = restart(&r, Mirror::dir(r.path()), ds.path());
    c.refresh(now()).unwrap();
    c.resolve("acme/pkg", now()).unwrap().unwrap();
    assert!(
        ds.path().join("acme.json").exists(),
        "delegated role persisted"
    );
    // Restart: the persisted delegated role replays through its delegator.
    let at = now();
    let replayed = replay(&r.root_bytes(1), ds.path(), at).unwrap();
    assert_eq!(replayed.targets_role("acme").unwrap().version, 1);
    // Continue: a new publication is accepted from the restored state.
    r.deleg("acme")
        .targets
        .insert("acme/pkg".into(), b"v2".to_vec());
    r.publish();
    let mut c = restart(&r, Mirror::dir(r.path()), ds.path());
    c.refresh(now()).unwrap();
    let t = c.resolve("acme/pkg", now()).unwrap().unwrap();
    assert_eq!(c.download(&t).unwrap(), b"v2");
    assert_eq!(c.trusted().timestamp().unwrap().version, 2);
}

#[test]
fn fg2a_restored_state_enforces_rollback_floors() {
    let mut r = repo();
    let v1 = r.freeze();
    r.publish();
    let ds = tempfile::tempdir().unwrap();
    restart(&r, Mirror::dir(r.path()), ds.path())
        .refresh(now())
        .unwrap();
    // A copy of the accepted state (a generation) against the frozen v1 mirror.
    let generation = tempfile::tempdir().unwrap();
    copy_dir(ds.path(), generation.path());
    let mut c = restart(&r, Mirror::dir(v1.path()), generation.path());
    let e = c.refresh(now()).unwrap_err();
    println!("restored state + v1 mirror: {e}");
    assert!(
        e.to_string().contains("rollback")
            || e.to_string().contains("Rollback")
            || e.to_string().contains("version")
    );
}

#[test]
fn fg2a_rotated_root_persists_across_restart() {
    let mut r = repo();
    let ds = tempfile::tempdir().unwrap();
    restart(&r, Mirror::dir(r.path()), ds.path())
        .refresh(now())
        .unwrap();
    r.rotate_root();
    r.publish();
    restart(&r, Mirror::dir(r.path()), ds.path())
        .refresh(now())
        .unwrap();
    // Restart against a mirror that no longer serves 2.root.json: the persisted chain is used,
    // never a re-walk from the bootstrap root over the network.
    let m = r.freeze();
    fs::remove_file(m.path().join("metadata/2.root.json")).unwrap();
    let c = restart(&r, Mirror::dir(m.path()), ds.path());
    assert_eq!(c.trusted().root().version, 2);
    let mut c = c;
    c.refresh(now()).unwrap();
    // The rotated-out root key alone cannot sign root v3.
    r.root = SignKey::new();
    r.touch_root();
    r.publish();
    assert!(
        restart(&r, Mirror::dir(r.path()), ds.path())
            .refresh(now())
            .is_err()
    );
}

#[test]
fn fg2a_delegated_rollback_after_restart_rejected() {
    let mut r = repo();
    let frozen = r.freeze();
    r.publish();
    let ds = tempfile::tempdir().unwrap();
    let mut c = restart(&r, Mirror::dir(r.path()), ds.path());
    c.refresh(now()).unwrap();
    c.resolve("acme/pkg", now()).unwrap();
    // Mirror: current top-level metadata, but the old delegated role served under the new name.
    let mixed = r.freeze();
    fs::copy(
        frozen.path().join("metadata/1.acme.json"),
        mixed.path().join("metadata/2.acme.json"),
    )
    .unwrap();
    let fresh = tempfile::tempdir().unwrap();
    let mut c = restart(&r, Mirror::dir(mixed.path()), fresh.path());
    c.refresh(now()).unwrap();
    assert!(
        c.resolve("acme/pkg", now()).is_err(),
        "delegated role must match the snapshot pin"
    );
}

#[test]
fn fg2a_tampered_store_never_bypasses_verification() {
    let r = repo();
    let ds = tempfile::tempdir().unwrap();
    let mut c = restart(&r, Mirror::dir(r.path()), ds.path());
    c.refresh(now()).unwrap();
    // The verifier silently skips an invalid cached file (it is only a cache to it), so it
    // re-fetches; Calve's generations treat the same damage as RecoveryRequired (fg15).
    fs::write(ds.path().join("timestamp.json"), b"{not json").unwrap();
    let mut c = restart(&r, Mirror::dir(r.path()), ds.path());
    c.refresh(now()).unwrap();
    assert!(
        replay(&r.root_bytes(1), ds.path(), now()).is_ok(),
        "re-fetched bytes replace the damaged file"
    );
    // A forged cached root (not signed by the chain) is ignored, never trusted.
    fs::create_dir_all(ds.path().join("root_history")).unwrap();
    fs::write(
        ds.path().join("root_history/2.root.json"),
        b"{\"signed\":{}}",
    )
    .unwrap();
    let c = restart(&r, Mirror::dir(r.path()), ds.path());
    assert_eq!(c.trusted().root().version, 1);
}
