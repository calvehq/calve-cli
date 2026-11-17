//! CIC fixtures (rev 10 §6.8): the two independent reference guests, their toy metadata, the
//! host hello used by tests, and a deterministic toy workspace scenario.

use std::path::PathBuf;

use calve_integration_contract::hello::{CicRange, HostHello};
use calve_integration_contract::metadata::Metadata;
use calve_integration_contract::wire::{Entry, EntryKind};

/// `CIC_FIXTURES` overrides the compiled-in path (cross-compiled runs on another OS).
pub fn fixtures() -> PathBuf {
    std::env::var_os("CIC_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/cic"))
}

/// `ref-rust` (on the contract crate) or `ref-min` (independent `no_std`).
pub fn guest_path(name: &str) -> PathBuf {
    fixtures().join(format!("{name}.wasm"))
}

pub fn guest(name: &str) -> Vec<u8> {
    let p = guest_path(name);
    std::fs::read(&p).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (run crates/calve-testkit/guests/build.sh)",
            p.display()
        )
    })
}

pub fn toy_metadata() -> Metadata {
    serde_json::from_slice(
        &std::fs::read(fixtures().join("toy-metadata.json")).expect("toy-metadata.json"),
    )
    .expect("metadata")
}

pub fn host_hello() -> HostHello {
    HostHello {
        abi: vec![1],
        cic: vec![CicRange {
            major: 1,
            min_minor: 0,
            max_minor: 0,
        }],
        capabilities: ["capture.v1", "describe.v1", "detect.v1", "relate.v1"]
            .map(String::from)
            .to_vec(),
        schemas: vec![1],
    }
}

/// Deterministic toy workspace: deletes, adds, renames, edits, unchanged, too-large files, a
/// symlink and a path needing escapes. Both manifests sorted byte-wise.
pub fn scenario(n: usize) -> (Vec<Entry>, Vec<Entry>) {
    let f = |p: String, d: String, size: u64| Entry {
        path: p,
        kind: EntryKind::File,
        digest: Some(d),
        size: Some(size),
        mode: Some(0o644),
        target: None,
    };
    let (mut base, mut work) = (vec![], vec![]);
    for i in 0..n {
        let d = format!("{i:064x}");
        match i % 6 {
            0 => base.push(f(format!("src/{i:05}.rs"), d, 10)),
            1 => work.push(f(format!("src/{i:05}.rs"), d, 10)),
            2 => {
                base.push(f(format!("old/{i:05}.txt"), d.clone(), 5));
                work.push(f(format!("new/{i:05}.txt"), d, 5));
            }
            3 => {
                base.push(f(format!("doc/{i:05}.md"), d, 7));
                work.push(f(
                    format!("doc/{i:05}.md"),
                    format!("{:064x}", i + 1_000_000),
                    8,
                ));
            }
            4 => {
                base.push(f(format!("keep/{i:05}"), d.clone(), 1));
                work.push(f(format!("keep/{i:05}"), d, 1));
            }
            _ => work.push(f(format!("big/{i:05}.bin"), d, 2 * 1024 * 1024)),
        }
    }
    work.push(Entry {
        path: "link".into(),
        kind: EntryKind::Symlink,
        digest: None,
        size: None,
        mode: None,
        target: Some("keep/00004".into()),
    });
    work.push(Entry {
        path: "quote\"\\\n\u{e9}".into(),
        kind: EntryKind::File,
        digest: Some("ab".repeat(32)),
        size: Some(3),
        mode: None,
        target: None,
    });
    base.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    work.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    (base, work)
}

use calve_integration_contract::driver::{self, CaptureOut, Driver, HostError, RelateOut, Session};
use calve_integration_contract::session::{commitment, group_ops, merge_join};
use serde_json::Value;

/// A capture session over in-memory manifests: merge join, then the contract's streaming driver.
pub fn capture<D: Driver>(
    s: &mut Session<D>,
    base: &[Entry],
    work: &[Entry],
    params: Value,
    batch: usize,
) -> Result<(Vec<Value>, CaptureOut), HostError> {
    let tuples = merge_join(base, work);
    let (mb, mw) = (driver::manifest_digest(base), driver::manifest_digest(work));
    let mut ops = vec![];
    let out = driver::capture(
        s,
        &mb,
        &mw,
        tuples.len() as u64,
        params,
        tuples,
        batch,
        |o| {
            ops.push(o.clone());
            Ok(())
        },
    )?;
    Ok((ops, out))
}

/// A relate session over in-memory ops (in-memory grouping; production uses the on-disk sort).
pub fn relate<D: Driver>(
    s: &mut Session<D>,
    meta: &Metadata,
    source_o: &str,
    ops: &[Value],
    params: Value,
    max_group: u64,
    chunk: usize,
) -> Result<RelateOut, HostError> {
    let groups = group_ops(ops, max_group);
    let c = commitment(&groups);
    driver::relate(s, meta, source_o, params, max_group, c, groups, chunk)
}

/// Signed metadata of the fixture package (`fixture.wasm`).
pub fn fixture_metadata() -> Metadata {
    serde_json::from_slice(
        &std::fs::read(fixtures().join("fixture-metadata.json")).expect("fixture-metadata.json"),
    )
    .expect("metadata")
}
