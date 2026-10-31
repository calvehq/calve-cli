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
