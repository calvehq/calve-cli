//! Production CIC sessions (rev 10 §6.5, §6.5b, §6.6): capture over stored manifests with the
//! ops spool, relate through the on-disk grouping, agreement with the in-memory reference
//! driver, batch / chunk / max_group invariance (property tests), and the disk caps.

use calve_app::extsort::SortLimits;
use calve_app::integration::{self, SessionLimits};
use calve_app::manifests::Manifest;
use calve_app::sandbox::{CalveHost, HostConfig};
use calve_integration_contract::driver::{Driver, Session};
use calve_integration_contract::wire::{Entry, EntryKind};
use calve_testkit::cic::*;
use proptest::prelude::*;
use serde_json::{Value, json};

fn session(g: &str) -> Session<Box<dyn Driver>> {
    let d: Box<dyn Driver> = Box::new(CalveHost::new(&guest(g), HostConfig::default()).unwrap());
    Session::open(d, &host_hello(), &toy_metadata()).unwrap()
}

struct Dirs {
    _t: tempfile::TempDir,
    cache: std::path::PathBuf,
    run: std::path::PathBuf,
}

fn dirs() -> Dirs {
    let t = tempfile::tempdir().unwrap();
    Dirs {
        cache: t.path().join("cache/manifests"),
        run: t.path().join("run"),
        _t: t,
    }
}

fn manifests(d: &Dirs, base: &[Entry], work: &[Entry]) -> (Manifest, Manifest) {
    (
        Manifest::from_entries(base, &d.cache, &d.run).unwrap(),
        Manifest::from_entries(work, &d.cache, &d.run).unwrap(),
    )
}

fn limits(batch: usize, group_chunk: usize, max_group: u64) -> SessionLimits {
    SessionLimits {
        batch,
        group_chunk,
        max_group,
        ..SessionLimits::default()
    }
}

/// (ops, O, I, R, relations count) of a production capture + relate.
fn run(
    g: &str,
    base: &[Entry],
    work: &[Entry],
    l: &SessionLimits,
) -> (Vec<Value>, String, String, String, usize) {
    let d = dirs();
    let (mb, mw) = manifests(&d, base, work);
    let cap = integration::capture(&mut session(g), &mb, &mw, json!({}), &d.run, l).unwrap();
    let ops: Vec<Value> = cap.spool.ops().unwrap().map(Result::unwrap).collect();
    let rel =
        integration::relate(&mut session(g), &toy_metadata(), &cap, json!({}), &d.run, l).unwrap();
    (
        ops,
        cap.out.output_digest.clone(),
        cap.out.input_digest.clone(),
        rel.r,
        rel.relations.len(),
    )
}

#[test]
fn production_sessions_equal_the_in_memory_reference() {
    let (base, work) = scenario(120);
    let (ops, o, i, r, n) = run("ref-rust", &base, &work, &SessionLimits::default());
    let mut s = session("ref-rust");
    let (ref_ops, ref_cap) = capture(&mut s, &base, &work, json!({}), 2048).unwrap();
    let ref_rel = relate(
        &mut session("ref-rust"),
        &toy_metadata(),
        &ref_cap.output_digest,
        &ref_ops,
        json!({}),
        64,
        256,
    )
    .unwrap();
    assert_eq!(
        (ops, o, i, r, n),
        (
            ref_ops,
            ref_cap.output_digest,
            ref_cap.input_digest,
            ref_rel.r,
            ref_rel.relations.len()
        )
    );
    assert!(n >= 10);
}

#[test]
fn spool_and_runs_are_deleted_and_caps_are_limit_exceeded() {
    let (base, work) = scenario(200);
    let d = dirs();
    let (mb, mw) = manifests(&d, &base, &work);
    let tiny = SessionLimits {
        max_ops_bytes: 500,
        ..SessionLimits::default()
    };
    let e = integration::capture(&mut session("ref-min"), &mb, &mw, json!({}), &d.run, &tiny)
        .err()
        .unwrap();
    assert_eq!(e.code(), "LIMIT_EXCEEDED");
    let cap = integration::capture(
        &mut session("ref-min"),
        &mb,
        &mw,
        json!({}),
        &d.run,
        &SessionLimits::default(),
    )
    .unwrap();
    let small_sort = SessionLimits {
        sort: SortLimits {
            memory_bytes: 256,
            disk_bytes: 2000,
        },
        ..SessionLimits::default()
    };
    let e = integration::relate(
        &mut session("ref-min"),
        &toy_metadata(),
        &cap,
        json!({}),
        &d.run,
        &small_sort,
    )
    .err()
    .unwrap();
    assert_eq!(e.code(), "LIMIT_EXCEEDED");
    drop(cap);
    let left: Vec<_> = std::fs::read_dir(&d.run)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "spool and sort runs removed: {left:?}");
}

#[test]
fn relate_over_many_small_sort_runs_is_unchanged() {
    let (base, work) = scenario(150);
    let normal = run("ref-min", &base, &work, &SessionLimits::default());
    let spilled = SessionLimits {
        sort: SortLimits {
            memory_bytes: 512,
            disk_bytes: 1 << 30,
        },
        ..SessionLimits::default()
    };
    assert_eq!(run("ref-min", &base, &work, &spilled), normal);
}

fn entry(p: String, d: u8, size: u64) -> Entry {
    Entry {
        path: p,
        kind: EntryKind::File,
        digest: Some(format!("{d:02x}").repeat(32)),
        size: Some(size),
        mode: Some(0o644),
        target: None,
    }
}

/// Random base/work manifests over a small path alphabet: adds, deletes, edits and renames.
fn arb_manifests() -> impl Strategy<Value = (Vec<Entry>, Vec<Entry>)> {
    let path = "[a-c]{1,2}(/[a-c]{1,2}){0,2}";
    (
        proptest::collection::btree_map(path, (0u8..6, 1u64..5000), 0..40),
        proptest::collection::btree_map(path, (0u8..6, 1u64..5000), 0..40),
    )
        .prop_map(|(b, w)| {
            let to = |m: std::collections::BTreeMap<String, (u8, u64)>| {
                let mut v: Vec<Entry> = m.into_iter().map(|(p, (d, s))| entry(p, d, s)).collect();
                v.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
                v
            };
            (to(b), to(w))
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10, ..ProptestConfig::default() })]

    /// §6.6: for random manifests and batch sizes {1, 2, 7, 64, 2048}, `O`, the op list and
    /// the relations are identical; relations are also invariant over group chunk sizes and
    /// any max_group ≥ the largest group (at most 80 ops here).
    #[test]
    fn batch_and_chunk_invariance((base, work) in arb_manifests()) {
        let reference = run("ref-rust", &base, &work, &limits(2048, 256, 100));
        for (batch, gchunk) in [(1, 1), (2, 3), (7, 64), (64, 2)] {
            prop_assert_eq!(&run("ref-rust", &base, &work, &limits(batch, gchunk, 100)), &reference);
        }
        prop_assert_eq!(&run("ref-min", &base, &work, &limits(7, 5, 128)), &reference, "independent guest, larger max_group");
    }
}

/// §6.6 scheduled perf job (run in release: `cargo test --release -p calve-app --test
/// cic_sessions -- --ignored --nocapture`): 200 000 tuples through capture and relate with the
/// peak RSS of the sessions sampled (Linux VmHWM after resetting it). Manifests are streamed
/// into the builder, never held in memory.
#[test]
#[ignore]
fn perf_200k_tuples_rss_stays_bounded() {
    let d = dirs();
    let build = |work: bool| {
        let mut b =
            calve_app::manifests::ManifestBuilder::new(&d.cache, &d.run, SortLimits::default())
                .unwrap();
        for i in 0..200_000u64 {
            // half unchanged, a quarter modified, an eighth added, an eighth deleted / renamed
            let keep = i % 8 < 4;
            let modified = i % 8 >= 4 && i % 8 < 6;
            let only_base = i % 8 == 6;
            let only_work = i % 8 == 7;
            if (only_base && work) || (only_work && !work) {
                continue;
            }
            let digest = if modified && work {
                i + 1_000_000
            } else if only_work {
                i - 1
            } else {
                i
            };
            let _ = keep;
            b.push(&entry_d(
                format!("dir{:03}/file{i:07}.txt", i % 997),
                digest,
                100,
            ))
            .unwrap();
        }
        b.finish().unwrap()
    };
    let (mb, mw) = (build(false), build(true));
    let peak = || -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        s.lines()
            .find(|l| l.starts_with("VmHWM"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    };
    let rss = || -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        s.lines()
            .find(|l| l.starts_with("VmRSS"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    };
    let base_rss = rss();
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let t = std::time::Instant::now();
    let l = SessionLimits::default();
    // ref-rust: cic-ref-min's bump allocator never frees, so a 200k-tuple session exceeds the
    // 64 MiB guest cap and the host reports OUT_OF_MEMORY (asserted below) — a fixture bound.
    let cap =
        integration::capture(&mut session("ref-rust"), &mb, &mw, json!({}), &d.run, &l).unwrap();
    let rel = integration::relate(
        &mut session("ref-rust"),
        &toy_metadata(),
        &cap,
        json!({}),
        &d.run,
        &l,
    )
    .unwrap();
    let growth = peak().saturating_sub(base_rss);
    println!(
        "200k tuples: {} ops, {} relations in {:?}; peak RSS growth {} KiB (base {} KiB)",
        cap.spool.count,
        rel.relations.len(),
        t.elapsed(),
        growth,
        base_rss
    );
    // Bound (§6.6): request + response (8 MiB) + chunk + 16 MiB sort buffer ≈ 42 MiB, plus
    // the guest's linear memory (≤ 64 MiB cap) and wasmi engine overhead.
    assert!(growth < 160 * 1024, "peak RSS growth {growth} KiB");
    let e = integration::capture(&mut session("ref-min"), &mb, &mw, json!({}), &d.run, &l)
        .err()
        .unwrap();
    assert_eq!(
        e.code(),
        "OUT_OF_MEMORY",
        "the guest cap holds for a guest that never frees"
    );
}

fn entry_d(p: String, d: u64, size: u64) -> Entry {
    Entry {
        path: p,
        kind: EntryKind::File,
        digest: Some(format!("{d:064x}")),
        size: Some(size),
        mode: Some(0o644),
        target: None,
    }
}
