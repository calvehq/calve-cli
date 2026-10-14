//! Bounded on-disk external sort (rev 10 §6.5, §6.6): records are buffered up to a memory
//! budget, sorted, written as runs, then k-way merged. Used for manifests (by path) and for
//! the generic relate grouping (by `group_key, path, op_index`). Memory stays at the budget
//! plus one record per run, independent of input size; disk is capped and the run directory is
//! deleted when the sorter (or its merge) is dropped.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum SortError {
    /// Run files would exceed the disk cap.
    LimitExceeded(String),
    Io(io::Error),
}

impl std::fmt::Display for SortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortError::LimitExceeded(m) => write!(f, "LIMIT_EXCEEDED: {m}"),
            SortError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SortError {}

impl From<io::Error> for SortError {
    fn from(e: io::Error) -> Self {
        SortError::Io(e)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SortLimits {
    /// In-memory buffer before a run is written.
    pub memory_bytes: usize,
    /// Total bytes of run files.
    pub disk_bytes: u64,
}

impl Default for SortLimits {
    fn default() -> Self {
        SortLimits {
            memory_bytes: 16 * 1024 * 1024,
            disk_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

/// A run directory removed on drop.
struct RunDir(PathBuf);

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sorts `(key, record)` pairs by `key` bytes; equal keys keep insertion order (stable).
pub struct Sorter {
    dir: RunDir,
    limits: SortLimits,
    buf: Vec<(Vec<u8>, u64, Vec<u8>)>,
    buf_bytes: usize,
    seq: u64,
    runs: Vec<PathBuf>,
    disk: u64,
}

fn write_field(w: &mut impl Write, b: &[u8]) -> io::Result<()> {
    w.write_all(&(b.len() as u32).to_le_bytes())?;
    w.write_all(b)
}

fn read_field(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut b = vec![0u8; u32::from_le_bytes(len) as usize];
    r.read_exact(&mut b)?;
    Ok(Some(b))
}

impl Sorter {
    /// Runs live in a fresh directory under `parent` (e.g. `.calve/run/`).
    pub fn new(parent: &Path, limits: SortLimits) -> Result<Self, SortError> {
        std::fs::create_dir_all(parent)?;
        let dir = parent.join(format!("sort-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir(&dir)?;
        Ok(Sorter {
            dir: RunDir(dir),
            limits,
            buf: Vec::new(),
            buf_bytes: 0,
            seq: 0,
            runs: Vec::new(),
            disk: 0,
        })
    }

    pub fn push(&mut self, key: Vec<u8>, record: Vec<u8>) -> Result<(), SortError> {
        self.buf_bytes += key.len() + record.len() + 32;
        self.buf.push((key, self.seq, record));
        self.seq += 1;
        if self.buf_bytes >= self.limits.memory_bytes {
            self.spill()?;
        }
        Ok(())
    }

    fn spill(&mut self) -> Result<(), SortError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        self.buf.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
        let path = self.dir.0.join(format!("run-{}", self.runs.len()));
        let mut w = BufWriter::new(File::create(&path)?);
        for (k, s, r) in self.buf.drain(..) {
            let add = (k.len() + r.len() + 16) as u64;
            if self.disk + add > self.limits.disk_bytes {
                return Err(SortError::LimitExceeded(format!(
                    "sort runs exceed {} bytes",
                    self.limits.disk_bytes
                )));
            }
            self.disk += add;
            write_field(&mut w, &k)?;
            w.write_all(&s.to_le_bytes())?;
            write_field(&mut w, &r)?;
        }
        w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        self.runs.push(path);
        self.buf_bytes = 0;
        Ok(())
    }

    /// Finishes input; the result can be merged any number of times (two-pass consumers).
    pub fn finish(mut self) -> Result<Sorted, SortError> {
        self.spill()?;
        Ok(Sorted {
            _dir: self.dir,
            runs: self.runs,
        })
    }
}

/// The sorted runs; [`Sorted::iter`] streams the merge.
pub struct Sorted {
    _dir: RunDir,
    runs: Vec<PathBuf>,
}

impl Sorted {
    pub fn iter(&self) -> Result<Merge, SortError> {
        let mut readers = Vec::with_capacity(self.runs.len());
        let mut heap = BinaryHeap::new();
        for (i, p) in self.runs.iter().enumerate() {
            let mut r = BufReader::with_capacity(64 * 1024, File::open(p)?);
            if let Some(head) = next_record(&mut r)? {
                heap.push(Reverse((head.0, head.1, i, head.2)));
            }
            readers.push(r);
        }
        Ok(Merge { readers, heap })
    }
}

type Record = (Vec<u8>, u64, Vec<u8>);
/// A run head in the merge heap: (key, insertion seq, run index, record).
type Head = Reverse<(Vec<u8>, u64, usize, Vec<u8>)>;

fn next_record(r: &mut impl Read) -> io::Result<Option<Record>> {
    let Some(k) = read_field(r)? else {
        return Ok(None);
    };
    let mut s = [0u8; 8];
    r.read_exact(&mut s)?;
    let rec = read_field(r)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated run"))?;
    Ok(Some((k, u64::from_le_bytes(s), rec)))
}

pub struct Merge {
    readers: Vec<BufReader<File>>,
    heap: BinaryHeap<Head>,
}

impl Iterator for Merge {
    /// `(key, record)` in key order.
    type Item = io::Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let Reverse((k, _, i, rec)) = self.heap.pop()?;
        match next_record(&mut self.readers[i]) {
            Ok(Some(head)) => self.heap.push(Reverse((head.0, head.1, i, head.2))),
            Ok(None) => {}
            Err(e) => return Some(Err(e)),
        }
        Some(Ok((k, rec)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_across_runs_stably_and_cleans_up() {
        let parent = tempfile::tempdir().unwrap();
        let mut s = Sorter::new(
            parent.path(),
            SortLimits {
                memory_bytes: 200,
                disk_bytes: 1 << 20,
            },
        )
        .unwrap();
        let mut want = vec![];
        for i in 0..500u32 {
            let k = format!("{:03}", (i * 7919) % 97).into_bytes();
            want.push((k.clone(), i.to_le_bytes().to_vec()));
            s.push(k, i.to_le_bytes().to_vec()).unwrap();
        }
        want.sort_by(|a, b| a.0.cmp(&b.0)); // stable: equal keys keep insertion order
        let sorted = s.finish().unwrap();
        assert!(sorted.runs.len() > 10, "spilled to many runs");
        let got: Vec<_> = sorted.iter().unwrap().map(Result::unwrap).collect();
        assert_eq!(got, want);
        assert_eq!(sorted.iter().unwrap().count(), 500, "second pass");
        drop(sorted);
        assert_eq!(
            std::fs::read_dir(parent.path()).unwrap().count(),
            0,
            "runs deleted"
        );
    }

    #[test]
    fn disk_cap_is_limit_exceeded() {
        let parent = tempfile::tempdir().unwrap();
        let mut s = Sorter::new(
            parent.path(),
            SortLimits {
                memory_bytes: 64,
                disk_bytes: 1000,
            },
        )
        .unwrap();
        let r = (0..1000).try_for_each(|i: u32| s.push(i.to_be_bytes().to_vec(), vec![0; 32]));
        assert!(matches!(
            r.and_then(|()| s.finish().map(drop)),
            Err(SortError::LimitExceeded(_))
        ));
    }
}
