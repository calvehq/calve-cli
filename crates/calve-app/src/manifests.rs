//! Manifests (rev 10 §6.5): sorted, path-unique entry sequences stored as JSONL in the
//! content-addressed cache `.calve/cache/manifests/<M>.jsonl`, where
//! `M = SHA-256(Σ JCS(entry) ‖ 0x0A)`. Entries arrive in any order and are put in byte-wise
//! path order through the bounded external sort, so manifest size is limited by disk, not
//! memory. The streaming merge join yields `{path, base?, work?}` tuples.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use calve_integration_contract::digest::LineHasher;
use calve_integration_contract::jcs;
use calve_integration_contract::wire::{Entry, Tuple};

use crate::extsort::{SortError, SortLimits, Sorter};

#[derive(Debug)]
pub enum ManifestError {
    Duplicate(String),
    Sort(SortError),
    Io(std::io::Error),
    Corrupt(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Duplicate(p) => write!(f, "duplicate manifest path {p:?}"),
            ManifestError::Sort(e) => write!(f, "{e}"),
            ManifestError::Io(e) => write!(f, "{e}"),
            ManifestError::Corrupt(m) => write!(f, "manifest corrupt: {m}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<std::io::Error> for ManifestError {
    fn from(e: std::io::Error) -> Self {
        ManifestError::Io(e)
    }
}
impl From<SortError> for ManifestError {
    fn from(e: SortError) -> Self {
        ManifestError::Sort(e)
    }
}

/// A stored manifest: its file, digest and entry count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub path: PathBuf,
    pub digest: String,
    pub count: u64,
}

fn line(e: &Entry) -> Vec<u8> {
    jcs::to_vec(&serde_json::to_value(e).expect("entry")).expect("integer-only entry")
}

/// Collects entries in any order and stores the sorted manifest under `cache_dir`.
pub struct ManifestBuilder {
    sorter: Sorter,
    cache_dir: PathBuf,
}

impl ManifestBuilder {
    /// `cache_dir` = `.calve/cache/manifests`; sort runs go to `run_dir`.
    pub fn new(
        cache_dir: &Path,
        run_dir: &Path,
        limits: SortLimits,
    ) -> Result<Self, ManifestError> {
        std::fs::create_dir_all(cache_dir)?;
        Ok(ManifestBuilder {
            sorter: Sorter::new(run_dir, limits)?,
            cache_dir: cache_dir.to_owned(),
        })
    }

    pub fn push(&mut self, e: &Entry) -> Result<(), ManifestError> {
        Ok(self.sorter.push(e.path.as_bytes().to_vec(), line(e))?)
    }

    pub fn finish(self) -> Result<Manifest, ManifestError> {
        let sorted = self.sorter.finish()?;
        let tmp = self
            .cache_dir
            .join(format!(".tmp-{}", uuid::Uuid::now_v7().simple()));
        let mut w = BufWriter::new(File::create(&tmp)?);
        let mut h = LineHasher::new();
        let mut last: Option<Vec<u8>> = None;
        let res = (|| -> Result<(), ManifestError> {
            for item in sorted.iter()? {
                let (key, rec) = item?;
                if last.as_ref() == Some(&key) {
                    return Err(ManifestError::Duplicate(
                        String::from_utf8_lossy(&key).into_owned(),
                    ));
                }
                let v: serde_json::Value = serde_json::from_slice(&rec)
                    .map_err(|e| ManifestError::Corrupt(e.to_string()))?;
                h.push(&v)
                    .map_err(|_| ManifestError::Corrupt("float".into()))?;
                w.write_all(&rec)?;
                w.write_all(b"\n")?;
                last = Some(key);
            }
            w.flush()?;
            // Sync through the writable handle (Windows FlushFileBuffers needs write access).
            w.get_ref().sync_all()?;
            Ok(())
        })();
        if let Err(e) = res {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        drop(w);
        let count = h.count();
        let digest = h.finish();
        let path = self.cache_dir.join(format!("{digest}.jsonl"));
        crate::workspace_io::rename_durable(&tmp, &path)?;
        Ok(Manifest {
            path,
            digest,
            count,
        })
    }
}

impl Manifest {
    /// Builds a manifest from entries already in memory (tests, small inputs).
    pub fn from_entries(
        entries: &[Entry],
        cache_dir: &Path,
        run_dir: &Path,
    ) -> Result<Self, ManifestError> {
        let mut b = ManifestBuilder::new(cache_dir, run_dir, SortLimits::default())?;
        for e in entries {
            b.push(e)?;
        }
        b.finish()
    }

    /// Opens a cached manifest, re-verifying its digest and order (a damaged cache file is an
    /// error, never silently used).
    pub fn open(cache_dir: &Path, digest: &str) -> Result<Self, ManifestError> {
        let path = cache_dir.join(format!("{digest}.jsonl"));
        let mut h = LineHasher::new();
        let mut last: Option<String> = None;
        let probe = Manifest {
            path: path.clone(),
            digest: digest.into(),
            count: 0,
        };
        for e in probe.entries()? {
            let e = e?;
            if last
                .as_deref()
                .is_some_and(|l| l.as_bytes() >= e.path.as_bytes())
            {
                return Err(ManifestError::Corrupt(format!("order at {:?}", e.path)));
            }
            h.push(&serde_json::to_value(&e).expect("entry"))
                .map_err(|_| ManifestError::Corrupt("float".into()))?;
            last = Some(e.path);
        }
        let count = h.count();
        if h.finish() != digest {
            return Err(ManifestError::Corrupt(format!("{digest}: digest mismatch")));
        }
        Ok(Manifest {
            path,
            digest: digest.into(),
            count,
        })
    }

    pub fn entries(
        &self,
    ) -> Result<impl Iterator<Item = Result<Entry, ManifestError>> + use<>, ManifestError> {
        let r = BufReader::new(File::open(&self.path)?);
        Ok(r.lines().map(|l| {
            let l = l?;
            serde_json::from_str::<Entry>(&l).map_err(|e| ManifestError::Corrupt(e.to_string()))
        }))
    }
}

/// Streaming merge join of two path-sorted manifests (§6.5) in byte-wise path order.
pub struct MergeJoin<
    A: Iterator<Item = Result<Entry, ManifestError>>,
    B: Iterator<Item = Result<Entry, ManifestError>>,
> {
    base: std::iter::Peekable<A>,
    work: std::iter::Peekable<B>,
}

pub fn merge_join<A, B>(base: A, work: B) -> MergeJoin<A, B>
where
    A: Iterator<Item = Result<Entry, ManifestError>>,
    B: Iterator<Item = Result<Entry, ManifestError>>,
{
    MergeJoin {
        base: base.peekable(),
        work: work.peekable(),
    }
}

impl<A, B> Iterator for MergeJoin<A, B>
where
    A: Iterator<Item = Result<Entry, ManifestError>>,
    B: Iterator<Item = Result<Entry, ManifestError>>,
{
    type Item = Result<Tuple, ManifestError>;

    fn next(&mut self) -> Option<Self::Item> {
        use std::cmp::Ordering::*;
        let ord = match (self.base.peek(), self.work.peek()) {
            (None, None) => return None,
            (Some(Err(_)), _) => return self.base.next().and_then(|r| r.err()).map(Err),
            (_, Some(Err(_))) => return self.work.next().and_then(|r| r.err()).map(Err),
            (Some(Ok(b)), Some(Ok(w))) => b.path.as_bytes().cmp(w.path.as_bytes()),
            (Some(_), None) => Less,
            (None, Some(_)) => Greater,
        };
        let (b, w) = match ord {
            Less => (self.base.next(), None),
            Greater => (None, self.work.next()),
            Equal => (self.base.next(), self.work.next()),
        };
        let b = b.map(|r| r.expect("checked ok"));
        let w = w.map(|r| r.expect("checked ok"));
        let path = b.as_ref().or(w.as_ref()).expect("one side").path.clone();
        Some(Ok(Tuple {
            path,
            base: b,
            work: w,
        }))
    }
}

/// Number of tuples a merge join of the two manifests yields (the `expected_tuples` sent at
/// `capture.begin`); one streaming pass.
pub fn tuple_count(base: &Manifest, work: &Manifest) -> Result<u64, ManifestError> {
    let mut n = 0;
    for t in merge_join(base.entries()?, work.entries()?) {
        t?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use calve_integration_contract::wire::EntryKind;

    fn e(p: &str) -> Entry {
        Entry {
            path: p.into(),
            kind: EntryKind::File,
            digest: Some("ab".repeat(32)),
            size: Some(1),
            mode: None,
            target: None,
        }
    }

    #[test]
    fn builds_sorted_digest_addressed_and_detects_damage() {
        let d = tempfile::tempdir().unwrap();
        let (cache, run) = (d.path().join("m"), d.path().join("run"));
        let m = Manifest::from_entries(&[e("b"), e("a/z"), e("a"), e("ä")], &cache, &run).unwrap();
        let paths: Vec<_> = m.entries().unwrap().map(|e| e.unwrap().path).collect();
        assert_eq!(paths, ["a", "a/z", "b", "ä"]);
        assert_eq!(
            m.digest,
            calve_integration_contract::driver::manifest_digest(&[
                e("a"),
                e("a/z"),
                e("b"),
                e("ä")
            ])
        );
        assert_eq!(Manifest::open(&cache, &m.digest).unwrap(), m);
        std::fs::write(
            &m.path,
            std::fs::read_to_string(&m.path)
                .unwrap()
                .replace("\"b\"", "\"c\""),
        )
        .unwrap();
        assert!(matches!(
            Manifest::open(&cache, &m.digest),
            Err(ManifestError::Corrupt(_))
        ));
        assert!(matches!(
            Manifest::from_entries(&[e("x"), e("x")], &cache, &run),
            Err(ManifestError::Duplicate(_))
        ));
    }

    #[test]
    fn streaming_merge_join_equals_the_contract_reference() {
        let d = tempfile::tempdir().unwrap();
        let (cache, run) = (d.path().join("m"), d.path().join("run"));
        let base: Vec<Entry> = ["a", "c", "d", "f"].map(e).to_vec();
        let work: Vec<Entry> = ["b", "c", "e", "f", "g"].map(e).to_vec();
        let (mb, mw) = (
            Manifest::from_entries(&base, &cache, &run).unwrap(),
            Manifest::from_entries(&work, &cache, &run).unwrap(),
        );
        let got: Vec<Tuple> = merge_join(mb.entries().unwrap(), mw.entries().unwrap())
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            got,
            calve_integration_contract::session::merge_join(&base, &work)
        );
        assert_eq!(tuple_count(&mb, &mw).unwrap(), 7);
    }
}
