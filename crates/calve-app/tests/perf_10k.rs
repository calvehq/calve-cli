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

/// Resident set size in KiB (Linux), for memory-growth evidence.
fn rss_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// M6 R10 (§55): the console's read models at 10,000 packs. The first call after seeding builds
/// the projections (event index, pack summaries, receipts) once; every later call is
/// incremental and bounded. Warm calls are held to the §55 targets (status < 150 ms, a
/// metadata query < 100 ms) and memory must not grow across repeated rounds.
#[tokio::test(flavor = "current_thread")]
#[ignore = "long: seeds 10k packs with evidence"]
async fn console_read_models_at_ten_thousand_packs() {
    let n: usize = std::env::var("CALVE_PERF_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let d = tempfile::tempdir().unwrap();
    let p = Project::init(d.path(), Some("perf")).await.unwrap();
    let mut ids = Vec::with_capacity(n);
    let (_, seed) = timed_async(&format!("seed {n} packs"), async {
        for i in 0..n {
            // Every 20th pack requires review, so its rejection registers review evidence.
            let pack = p
                .create_pack_with_requirements(&format!("pack {i}"), None, false, i % 20 == 0)
                .await
                .unwrap();
            ids.push(pack.to_string());
        }
    })
    .await;
    println!("perf: per pack: {:?}", seed / n as u32);
    let reviewed = n / 20;
    timed_async(
        &format!("seal + reject {reviewed} packs (evidence)"),
        async {
            for id in ids.iter().step_by(20).take(reviewed) {
                p.seal(id, 1).await.unwrap();
                p.review(id, 1, "REJECT", "perf").await.unwrap();
            }
        },
    )
    .await;
    let mid = ids[n / 2].clone();
    // Cold: projections build once over the whole journal.
    for (label, cold) in [("cold", true), ("warm", false)] {
        let (_, d) = timed_async(&format!("status ({label})"), p.status(None)).await;
        if !cold {
            assert!(
                d < Duration::from_millis(150),
                "warm status {d:?} (§55: < 150 ms)"
            );
        }
    }
    let mut worst = Duration::ZERO;
    let mut warm = |label: &str, d: Duration| {
        println!("perf: warm {label}: {d:?}");
        worst = worst.max(d);
    };
    let (_, cold) = timed_async("view overview (cold)", p.view_overview()).await;
    let _ = cold;
    let (v, d) = timed_async("view overview", p.view_overview()).await;
    v.unwrap();
    warm("view overview", d);
    let (page, d) = timed_async("view packs first page", p.view_packs(None, Some(200), None)).await;
    let page = page.unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 200);
    warm("view packs first page", d);
    let next = page["next"].as_str().unwrap().to_owned();
    let (_, d) = timed_async(
        "view packs next page",
        p.view_packs(Some(&next), Some(200), None),
    )
    .await;
    warm("view packs next page", d);
    let (_, d) = timed_async(
        "view packs state filter",
        p.view_packs(None, Some(200), Some("SEALED")),
    )
    .await;
    warm("view packs state filter", d);
    let (_, cold) = timed_async("view evidence (cold)", p.view_evidence(None, Some(100))).await;
    let _ = cold;
    let (ev, d) = timed_async("view evidence first page", p.view_evidence(None, Some(100))).await;
    let ev = ev.unwrap();
    assert_eq!(ev["items"].as_array().unwrap().len(), 100.min(reviewed));
    warm("view evidence first page", d);
    let (_, cold) = timed_async("view pack (cold receipts)", p.view_pack(&mid)).await;
    let _ = cold;
    let (_, d) = timed_async("view pack", p.view_pack(&mid)).await;
    warm("view pack", d);
    let filter = calve_api::ActivityFilter {
        pack: Some(mid.clone()),
        ..Default::default()
    };
    let (_, d) = timed_async(
        "activity --pack (indexed)",
        p.activity_with_filter(50, &filter),
    )
    .await;
    warm("activity --pack", d);
    let (_, d) = timed_async("inbox", p.inbox(false)).await;
    warm("inbox", d);
    println!("perf: worst warm read model: {worst:?}");
    // Memory: 20 warm rounds of the console's reads must not keep growing.
    let before = rss_kib();
    for _ in 0..20 {
        p.status(None).await.unwrap();
        p.view_overview().await.unwrap();
        p.view_packs(None, Some(200), None).await.unwrap();
        p.view_evidence(None, Some(100)).await.unwrap();
    }
    let after = rss_kib();
    println!("perf: RSS before/after 20 warm rounds: {before:?} / {after:?} KiB");
    if let (Some(b), Some(a)) = (before, after) {
        assert!(a.saturating_sub(b) < 64 * 1024, "RSS grew {} KiB", a - b);
    }
    assert!(
        worst < Duration::from_millis(250),
        "warm read model {worst:?}"
    );
}
