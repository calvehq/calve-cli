//! §55 / R14–R15: 10,000 Intents and 10,000 Packs are listed through keyset pages without
//! loading the whole list. Long; run explicitly (release) and keep the printed timings as
//! evidence: `cargo test --release -p calve-app --test perf_10k -- --ignored --nocapture`.
//! `CALVE_PERF_N` overrides the count.

use std::time::{Duration, Instant};

use calve_app::Project;

fn timed<T>(label: &str, f: impl FnOnce() -> T) -> (T, Duration) {
    let t = Instant::now();
    let v = f();
    let d = t.elapsed();
    println!("perf: {label}: {d:?}");
    (v, d)
}

async fn timed_async<T>(label: &str, f: impl std::future::Future<Output = T>) -> (T, Duration) {
    let t = Instant::now();
    let v = f.await;
    let d = t.elapsed();
    println!("perf: {label}: {d:?}");
    (v, d)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "long: seeds 10k Intents and 10k Packs"]
async fn ten_thousand_intents_and_packs_page_quickly() {
    let n: usize = std::env::var("CALVE_PERF_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let d = tempfile::tempdir().unwrap();
    let p = Project::init(d.path(), Some("perf")).await.unwrap();

    let (_, seed) = timed(&format!("seed {n} intents"), || {
        for i in 0..n {
            p.create_intent(&format!("intent {i}")).unwrap();
        }
    });
    println!("perf: per intent: {:?}", seed / n as u32);
    let t = Instant::now();
    for i in 0..n {
        p.create_pack(&format!("pack {i}"), None).await.unwrap();
    }
    let seed = t.elapsed();
    println!(
        "perf: seed {n} packs: {seed:?} ({:?} each)",
        seed / n as u32
    );

    let (all, _) = timed("intents: full list", || p.list_intents().unwrap());
    assert_eq!(all.len(), n);
    let mid = all[n / 2]["id"].as_str().unwrap().to_owned();
    let last = all[n - 2]["id"].as_str().unwrap().to_owned();
    let mut worst = Duration::ZERO;
    for (label, after) in [
        ("first", None),
        ("middle", Some(&mid)),
        ("end", Some(&last)),
    ] {
        let (page, d) = timed(&format!("intents: page of 50 ({label})"), || {
            p.list_intents_page(after.map(String::as_str), Some(50))
                .unwrap()
        });
        assert!(!page.is_empty() && page.len() <= 50);
        worst = worst.max(d);
    }
    let (one, d) = timed("intents: show one", || p.intent(&mid).unwrap());
    assert_eq!(one["id"], mid.as_str());
    worst = worst.max(d);

    let (all, _) = timed_async("packs: full list", p.list_packs()).await;
    let all = all.unwrap();
    assert_eq!(all.len(), n);
    let mid = all[n / 2]["id"].as_str().unwrap().to_owned();
    let last = all[n - 2]["id"].as_str().unwrap().to_owned();
    for (label, after) in [
        ("first", None),
        ("middle", Some(&mid)),
        ("end", Some(&last)),
    ] {
        let (page, d) = timed_async(
            &format!("packs: page of 50 ({label})"),
            p.list_packs_page(after.map(String::as_str), Some(50)),
        )
        .await;
        let page = page.unwrap();
        assert!(!page.is_empty() && page.len() <= 50);
        worst = worst.max(d);
    }
    println!("perf: worst page/lookup: {worst:?}");
    // §55 is an engineering target, not a guarantee; this bound only catches a full scan.
    assert!(worst < Duration::from_secs(2), "{worst:?}");
}
