//! CIC sessions in production (rev 10 §6.5–§6.6): capture over on-disk manifests with an ops
//! spool, and the generic relate grouping through the bounded external sort. Memory per
//! session is bounded by the request/response limits, one chunk and the sort buffer; disk by
//! the spool and sort caps (`LIMIT_EXCEEDED`, with spool and runs deleted).

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use calve_integration_contract::digest::LineHasher;
use calve_integration_contract::driver::{self, CaptureOut, Driver, HostError, RelateOut, Session};
use calve_integration_contract::hello::{CicRange, HostHello};
use calve_integration_contract::jcs;
use calve_integration_contract::metadata::Metadata;
use calve_integration_contract::session::{Group, Member};
use serde_json::Value;

use crate::extsort::{SortError, SortLimits, Sorter};
use crate::manifests::{Manifest, merge_join, tuple_count};

/// Capabilities this host implements (`hello/0` `host.capabilities`).
pub const HOST_CAPABILITIES: &[&str] = &[
    "capture.v1",
    "check_plan.v1",
    "classify.v1",
    "describe.v1",
    "detect.v1",
    "diff.v1",
    "relate.v1",
];

/// Metadata schema numbers this host understands (`calve.integration/N`).
pub const HOST_SCHEMAS: &[u32] = &[1];

pub fn host_hello() -> HostHello {
    HostHello {
        abi: vec![calve_integration_contract::abi::ABI_VERSION as u32],
        cic: vec![CicRange {
            major: 1,
            min_minor: 0,
            max_minor: 0,
        }],
        capabilities: HOST_CAPABILITIES.iter().map(|c| c.to_string()).collect(),
        schemas: HOST_SCHEMAS.to_vec(),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SessionLimits {
    /// Tuples per `capture.chunk`.
    pub batch: usize,
    /// Groups per `relate.groups`.
    pub group_chunk: usize,
    pub max_group: u64,
    /// Ops spool cap (`max_capture_ops_bytes`).
    pub max_ops_bytes: u64,
    pub sort: SortLimits,
}

impl Default for SessionLimits {
    fn default() -> Self {
        let l = calve_integration_contract::abi::Limits::default();
        SessionLimits {
            // 512 tuples ≈ 1.5e8 fuel for the reference guest (~288k fuel/tuple, release), a
            // 3x margin under `fuel_per_call`; the contract's 2048 is the maximum, not a target
            // (evidence/m2/logs/a2-fuel-per-tuple.txt).
            batch: (l.chunk_entries as usize).min(512),
            group_chunk: 256,
            max_group: l.max_group as u64,
            max_ops_bytes: 2 * 1024 * 1024 * 1024,
            sort: SortLimits {
                memory_bytes: 16 * 1024 * 1024,
                disk_bytes: 4 * 1024 * 1024 * 1024,
            },
        }
    }
}

fn limit(m: impl Into<String>) -> HostError {
    HostError::Guest(calve_integration_contract::wire::WireError {
        code: "LIMIT_EXCEEDED".into(),
        message: m.into(),
        retryable: false,
    })
}

fn io(e: impl std::fmt::Display) -> HostError {
    HostError::Internal(e.to_string())
}

fn sort_err(e: SortError) -> HostError {
    match e {
        SortError::LimitExceeded(m) => limit(m),
        SortError::Io(e) => io(e),
    }
}

/// Free bytes on the filesystem holding `path`, when the platform reports it.
pub fn disk_free(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        rustix::fs::statvfs(path)
            .ok()
            .map(|s| s.f_bavail.saturating_mul(s.f_frsize))
    }
    #[cfg(windows)]
    {
        calve_win_sec::disk_free(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        None
    }
}

/// The ops of one finished capture session, spooled as canonical JSON lines. Deleted on drop
/// unless [`OpsSpool::keep`] moves it into a session record.
pub struct OpsSpool {
    pub path: PathBuf,
    pub count: u64,
    pub bytes: u64,
    keep: bool,
}

impl Drop for OpsSpool {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl OpsSpool {
    pub fn keep(mut self) -> PathBuf {
        self.keep = true;
        self.path.clone()
    }

    pub fn ops(&self) -> Result<impl Iterator<Item = Result<Value, HostError>> + use<>, HostError> {
        let r = BufReader::new(File::open(&self.path).map_err(io)?);
        Ok(r.lines()
            .map(|l| serde_json::from_str(&l.map_err(io)?).map_err(io)))
    }
}

pub struct CaptureRun {
    pub out: CaptureOut,
    pub spool: OpsSpool,
}

/// One capture session (§6.5) over two stored manifests. Ops go to a spool in `run_dir`
/// (capped); free space for the spool cap is checked before `begin`. Any failure deletes the
/// spool and returns the error; nothing is partially accepted.
pub fn capture<D: Driver>(
    s: &mut Session<D>,
    base: &Manifest,
    work: &Manifest,
    params: Value,
    run_dir: &Path,
    limits: &SessionLimits,
) -> Result<CaptureRun, HostError> {
    std::fs::create_dir_all(run_dir).map_err(io)?;
    if disk_free(run_dir).is_some_and(|free| free < limits.max_ops_bytes.min(256 * 1024 * 1024)) {
        return Err(limit("not enough free disk space for the capture spool"));
    }
    let expected = tuple_count(base, work).map_err(io)?;
    let path = run_dir.join(format!("ops-{}.jsonl", uuid::Uuid::now_v7().simple()));
    let mut spool = OpsSpool {
        path: path.clone(),
        count: 0,
        bytes: 0,
        keep: false,
    };
    let mut w = BufWriter::new(File::create(&path).map_err(io)?);
    let tuples = merge_join(base.entries().map_err(io)?, work.entries().map_err(io)?);
    let mut read_err = None;
    let tuples = tuples.map_while(|t| match t {
        Ok(t) => Some(t),
        Err(e) => {
            read_err = Some(e);
            None
        }
    });
    let (mut count, mut bytes) = (0u64, 0u64);
    let out = driver::capture(
        s,
        &base.digest,
        &work.digest,
        expected,
        params,
        tuples,
        limits.batch,
        |op| {
            let line =
                jcs::to_vec(op).map_err(|_| HostError::AbiViolation("float in op".into()))?;
            bytes += line.len() as u64 + 1;
            if bytes > limits.max_ops_bytes {
                return Err(limit(format!(
                    "capture ops exceed {} bytes",
                    limits.max_ops_bytes
                )));
            }
            w.write_all(&line)
                .and_then(|()| w.write_all(b"\n"))
                .map_err(io)?;
            count += 1;
            Ok(())
        },
    );
    if let Some(e) = read_err {
        return Err(io(e));
    }
    let out = out?;
    w.flush().map_err(io)?;
    drop(w);
    spool.count = count;
    spool.bytes = bytes;
    Ok(CaptureRun { out, spool })
}

/// Groups the spooled ops by their opaque `group_key` (§6.5): sorted by `(key, path,
/// op_index)` on disk, groups above `max_group` delivered as overflow (count only). Returns the
/// sorted runs; [`groups`] streams them (twice: commitment, then delivery).
pub fn group_spool(
    spool: &OpsSpool,
    run_dir: &Path,
    sort: SortLimits,
) -> Result<crate::extsort::Sorted, HostError> {
    let mut sorter = Sorter::new(run_dir, sort).map_err(sort_err)?;
    for (i, op) in spool.ops()?.enumerate() {
        let op = op?;
        let (Some(key), Some(path)) = (
            op.get("group_key").and_then(Value::as_str),
            op.get("path").and_then(Value::as_str),
        ) else {
            continue;
        };
        let mut k = Vec::with_capacity(key.len() + path.len() + 10);
        k.extend_from_slice(key.as_bytes());
        k.push(0);
        k.extend_from_slice(path.as_bytes());
        k.push(0);
        k.extend_from_slice(&(i as u64).to_be_bytes());
        let member = Member {
            op: op.clone(),
            op_index: i as u64,
            path: path.to_owned(),
        };
        let mut rec = key.as_bytes().to_vec();
        rec.push(0);
        rec.extend(serde_json::to_vec(&member).map_err(io)?);
        sorter.push(k, rec).map_err(sort_err)?;
    }
    sorter.finish().map_err(sort_err)
}

/// Streams groups from sorted members, holding at most `max_group` members at a time.
pub fn groups(
    sorted: &crate::extsort::Sorted,
    max_group: u64,
) -> Result<impl Iterator<Item = Result<Group, HostError>> + '_, HostError> {
    let mut merge = sorted.iter().map_err(sort_err)?.peekable();
    Ok(std::iter::from_fn(move || {
        let mut key: Option<String> = None;
        let (mut members, mut count) = (Vec::new(), 0u64);
        loop {
            let next_key = match merge.peek() {
                None => None,
                Some(Err(_)) => {
                    return merge
                        .next()
                        .map(|r| Err(io(r.expect_err("peeked an error"))));
                }
                Some(Ok((_, rec))) => {
                    Some(rec.split(|b| *b == 0).next().unwrap_or_default().to_vec())
                }
            };
            match (&key, next_key) {
                (_, None) => break,
                (Some(k), Some(nk)) if k.as_bytes() != nk.as_slice() => break,
                (_, Some(nk)) => {
                    let (_, rec) = merge.next().expect("peeked").expect("ok");
                    key.get_or_insert_with(|| String::from_utf8_lossy(&nk).into_owned());
                    count += 1;
                    if count <= max_group {
                        let m: Member = match serde_json::from_slice(&rec[nk.len() + 1..]) {
                            Ok(m) => m,
                            Err(e) => return Some(Err(io(e))),
                        };
                        members.push(m);
                    } else {
                        members.clear();
                    }
                }
            }
        }
        let key = key?;
        Some(Ok(if count > max_group {
            Group {
                count,
                key,
                members: None,
                overflow: Some(true),
            }
        } else {
            Group {
                count,
                key,
                members: Some(members),
                overflow: None,
            }
        }))
    }))
}

/// One relate session (§6.5b) over a finished capture: commitment pass, then delivery.
pub fn relate<D: Driver>(
    s: &mut Session<D>,
    meta: &Metadata,
    capture: &CaptureRun,
    params: Value,
    run_dir: &Path,
    limits: &SessionLimits,
) -> Result<RelateOut, HostError> {
    let sorted = group_spool(&capture.spool, run_dir, limits.sort)?;
    let mut h = LineHasher::new();
    let (mut tg, mut tm) = (0u64, 0u64);
    for g in groups(&sorted, limits.max_group)? {
        let g = g?;
        h.push(&serde_json::to_value(&g).map_err(io)?)
            .map_err(|_| io("float"))?;
        tg += 1;
        tm += g.delivered_members();
    }
    let commitment = (tg, tm, h.finish());
    let mut first_err = None;
    let delivered = groups(&sorted, limits.max_group)?.map_while(|g| match g {
        Ok(g) => Some(g),
        Err(e) => {
            first_err = Some(e);
            None
        }
    });
    let out = driver::relate(
        s,
        meta,
        &capture.out.output_digest,
        params,
        limits.max_group,
        commitment,
        delivered,
        limits.group_chunk,
    );
    if let Some(e) = first_err {
        return Err(e);
    }
    out
}
