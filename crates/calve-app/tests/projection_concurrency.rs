//! The pack projection under concurrency (M7, M6 review): requests that share a Project's
//! connection while a refresh is reading from OpenAEVC must neither fail nor have their writes
//! tied to the refresh's transaction, and the projection must equal what a single uncontended
//! refresh produces.

use calve_app::Project;

#[tokio::test(flavor = "current_thread")]
async fn writes_during_a_pack_refresh_are_independent_and_the_result_is_exact() {
    let d = tempfile::tempdir().unwrap();
    let p = Project::init(d.path(), Some("contention")).await.unwrap();
    // Many packs whose summaries the next refresh has to fetch, one await per pack.
    for i in 0..120 {
        p.create_pack(&format!("pack {i}"), None).await.unwrap();
    }
    let writer = async {
        let mut created = Vec::new();
        for i in 0..200 {
            tokio::task::yield_now().await;
            created.push(p.create_intent(&format!("intent {i}")));
        }
        created
    };
    let (status, created) = tokio::join!(p.status(None), writer);
    status.unwrap();
    let failed: Vec<String> = created
        .iter()
        .filter_map(|r| r.as_ref().err().map(|e| e.to_string()))
        .collect();
    assert!(
        failed.is_empty(),
        "writes interleaved with the refresh failed: {failed:?}"
    );
    assert_eq!(
        p.list_intents().unwrap().len(),
        200,
        "every write committed on its own"
    );
    // The projection equals the uncontended one: every pack listed, newest page complete.
    let listed = p.list_packs().await.unwrap();
    assert_eq!(listed.len(), 120);
    assert!(
        listed
            .iter()
            .all(|r| r["state"] == "OPEN" && r["generation"] == 1)
    );
}

/// Overlapping refreshes while packs change state: a slower refresh may finish last, but the
/// checkpoint it writes is its own, so the next refresh re-reads anything newer. The projection
/// must converge on OpenAEVC's state, never keep a stale row behind a newer checkpoint.
#[tokio::test(flavor = "current_thread")]
async fn overlapping_refreshes_converge_on_the_authoritative_state() {
    let d = tempfile::tempdir().unwrap();
    let p = Project::init(d.path(), Some("overlap")).await.unwrap();
    let mut ids = Vec::new();
    for i in 0..60 {
        ids.push(
            p.create_pack(&format!("pack {i}"), None)
                .await
                .unwrap()
                .to_string(),
        );
    }
    let sealer = async {
        for id in &ids {
            p.seal(id, 1).await.unwrap();
        }
    };
    let (a, b, c, ()) = tokio::join!(p.list_packs(), p.status(None), p.list_packs(), sealer);
    a.unwrap();
    b.unwrap();
    c.unwrap();
    let listed = p.list_packs().await.unwrap();
    assert_eq!(listed.len(), 60);
    for row in &listed {
        let id = row["id"].as_str().unwrap();
        let pack = p.pack(id).await.unwrap();
        assert_eq!(row["state"], pack.state.as_str(), "{id}");
        assert_eq!(row["generation"], pack.generation, "{id}");
    }
}
