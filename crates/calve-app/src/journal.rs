//! Hash-chained, append-only operational journal (rev 10 §24; promoted from FG17).
//!
//! Format: one JSON object per line, newline-terminated. Record 0 is the genesis header
//! `{seq:0, format:1, type, journal_id, binding, created, hash}`; every later record is
//! `{seq, prev_hash, kind, body, ts, hash}` with `hash = SHA-256(JCS(record without hash))` and
//! `prev_hash` = the previous record's hash. JCS here is serde_json's sorted-key compact form
//! over integer-only values (the schema has no floats).
//!
//! Recovery distinguishes a **torn tail** (last line without newline or unparsable: crash during
//! append — truncated after copying the bytes aside) from **corruption** (any complete line with a
//! bad hash, seq gap or prev mismatch — never repaired).
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

pub const FORMAT: u64 = 1;

/// Aborts the process when `CALVE_FAULT` names this point (crash injection for tests). Debug
/// builds only: release binaries never read the variable.
pub fn fault(point: &str) {
    if cfg!(debug_assertions) && std::env::var("CALVE_FAULT").is_ok_and(|v| v == point) {
        std::process::abort();
    }
}

/// Debug builds: `CALVE_TEST_PAUSE=<point>=<ms>` blocks the calling thread at `point` for that
/// long (stands in for a slow step that renews nothing; lease experiments).
pub fn pause(point: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    if let Some(ms) = std::env::var("CALVE_TEST_PAUSE").ok().and_then(|v| {
        v.split_once('=')
            .filter(|(p, _)| *p == point)
            .and_then(|(_, ms)| ms.parse().ok())
    }) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Corrupt { line: usize, reason: String },
    Format(String),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Corrupt { line, reason } => {
                write!(f, "journal corrupt at line {line}: {reason}")
            }
            Error::Format(m) => write!(f, "journal format: {m}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Canonical bytes: the contract crate's JCS (explicitly sorted keys, compact, integers only).
/// Not serde_json's own serializer: `preserve_order` is unified on in this workspace.
pub fn jcs(v: &Value) -> Vec<u8> {
    calve_integration_contract::jcs::to_vec(v).expect("journal values are integer-only")
}

/// Creates `path` (and parents) as a private directory: 0700 on Unix; on Windows a protected
/// DACL for the user and SYSTEM applied at creation (R18, `calve_win_sec::create_private_dir`).
pub fn private_dir(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return calve_win_sec::create_private_dir(path);
    #[cfg(not(windows))]
    {
        std::fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    crate::workspace_io::sha256_hex(bytes)
}

fn record_hash(record: &Map<String, Value>) -> String {
    let mut r = record.clone();
    r.remove("hash");
    sha256_hex(&jcs(&Value::Object(r)))
}

/// Milliseconds since the epoch: hashed records stay within the JCS safe-integer range (2^53),
/// which nanoseconds exceed.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Flushes a file Calve wrote. Opened writable: Windows' FlushFileBuffers refuses a read-only
/// handle ("Access is denied").
pub fn sync_file(path: &Path) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .sync_all()
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(windows)]
    calve_win_sec::flush_dir_handle(&cap_std::fs::Dir::open_ambient_dir(
        dir,
        cap_std::ambient_authority(),
    )?)?;
    #[cfg(not(any(unix, windows)))]
    let _ = dir;
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub seq: u64,
    pub kind: String,
    pub body: Value,
    pub hash: String,
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: File,
    next_seq: u64,
    last_hash: String,
    pub header: Value,
}

#[derive(Debug)]
pub struct Opened {
    pub journal: Journal,
    pub records: Vec<Record>,
    /// Path of the preserved torn bytes, when a torn tail was truncated.
    pub torn: Option<PathBuf>,
}

impl Journal {
    pub fn create(
        path: &Path,
        journal_type: &str,
        journal_id: &str,
        binding: Value,
    ) -> Result<Self> {
        let mut header = Map::new();
        header.insert("seq".into(), json!(0));
        header.insert("format".into(), json!(FORMAT));
        header.insert("type".into(), json!(journal_type));
        header.insert("journal_id".into(), json!(journal_id));
        header.insert("binding".into(), binding);
        header.insert("created".into(), json!(now_ms()));
        let hash = record_hash(&header);
        header.insert("hash".into(), json!(hash));
        let mut file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(path)?;
        let mut line = jcs(&Value::Object(header.clone()));
        line.push(b'\n');
        file.write_all(&line)?;
        file.sync_all()?;
        fsync_dir(path.parent().unwrap_or(Path::new(".")))?;
        Ok(Journal {
            path: path.to_owned(),
            file,
            next_seq: 1,
            last_hash: hash,
            header: Value::Object(header),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    pub fn last_seq(&self) -> u64 {
        self.next_seq - 1
    }

    /// Appends one record durably (write + fsync) and returns its seq.
    pub fn append(&mut self, kind: &str, body: Value) -> Result<u64> {
        let mut rec = Map::new();
        rec.insert("seq".into(), json!(self.next_seq));
        rec.insert("prev_hash".into(), json!(self.last_hash));
        rec.insert("kind".into(), json!(kind));
        rec.insert("body".into(), body);
        rec.insert("ts".into(), json!(now_ms()));
        let hash = record_hash(&rec);
        rec.insert("hash".into(), json!(hash));
        let mut line = jcs(&Value::Object(rec));
        line.push(b'\n');
        fault("append.before_write");
        self.file.write_all(&line)?;
        fault("append.after_write");
        self.file.sync_all()?;
        fault("append.after_fsync");
        self.last_hash = hash;
        self.next_seq += 1;
        Ok(self.next_seq - 1)
    }

    /// Intent-before-mutation, ack-after-mutation (§24). `mutate` returns the observed result,
    /// which is recorded in the ack. A crash between the two leaves an unacknowledged intent that
    /// recovery reconciles by observation.
    pub fn with_intent<T>(
        &mut self,
        op: &str,
        intent: Value,
        mutate: impl FnOnce() -> std::result::Result<(T, Value), String>,
    ) -> Result<std::result::Result<T, String>> {
        let seq = self.append(&format!("{op}.intent"), intent)?;
        fault(&format!("{op}.after_intent"));
        match mutate() {
            Ok((value, observed)) => {
                fault(&format!("{op}.after_mutation"));
                self.append(
                    &format!("{op}.ack"),
                    json!({"intent_seq": seq, "observed": observed}),
                )?;
                Ok(Ok(value))
            }
            Err(e) => {
                self.append(
                    &format!("{op}.failed"),
                    json!({"intent_seq": seq, "error": e}),
                )?;
                Ok(Err(e))
            }
        }
    }

    /// Opens and fully verifies a journal. A torn tail is truncated (bytes preserved beside the
    /// journal); any other inconsistency is `Error::Corrupt`.
    pub fn open(path: &Path) -> Result<Opened> {
        Self::load(path, true)
    }

    /// Verifies a journal without writing to it, for paths that hold no lock: a torn tail may be
    /// a record being appended right now, so it is ignored and left in place. The returned
    /// journal cannot append.
    pub fn read(path: &Path) -> Result<Opened> {
        Self::load(path, false)
    }

    fn load(path: &Path, repair: bool) -> Result<Opened> {
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;
        let mut records = Vec::new();
        let mut header: Option<Value> = None;
        let mut prev = String::new();
        let mut offset = 0usize;
        let mut line_no = 0usize;
        let mut torn = None;
        while offset < bytes.len() {
            line_no += 1;
            let rest = &bytes[offset..];
            let (line, complete) = match rest.iter().position(|&b| b == b'\n') {
                Some(i) => (&rest[..i], true),
                None => (rest, false),
            };
            let parsed: Option<Map<String, Value>> = serde_json::from_slice(line).ok();
            let is_last = offset + line.len() + usize::from(complete) >= bytes.len();
            let Some(rec) = parsed.filter(|_| complete) else {
                if is_last && line_no > 1 && !repair {
                    break;
                }
                if is_last && line_no > 1 {
                    // Torn tail: preserve and truncate to the last valid boundary.
                    let aside = path.with_extension(format!("torn-{}", now_ns()));
                    fs::write(&aside, line)?;
                    let f = OpenOptions::new().write(true).open(path)?;
                    f.set_len(offset as u64)?;
                    f.sync_all()?;
                    torn = Some(aside);
                    break;
                }
                return Err(Error::Corrupt {
                    line: line_no,
                    reason: "unparsable or unterminated line".into(),
                });
            };
            let expect_seq = line_no as u64 - 1;
            if rec.get("seq").and_then(Value::as_u64) != Some(expect_seq) {
                return Err(Error::Corrupt {
                    line: line_no,
                    reason: format!("seq != {expect_seq}"),
                });
            }
            let stored = rec
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if record_hash(&rec) != stored {
                return Err(Error::Corrupt {
                    line: line_no,
                    reason: "hash mismatch".into(),
                });
            }
            if expect_seq == 0 {
                if rec.get("format").and_then(Value::as_u64) != Some(FORMAT) {
                    return Err(Error::Format("unsupported format".into()));
                }
                header = Some(Value::Object(rec.clone()));
            } else {
                if rec.get("prev_hash").and_then(Value::as_str) != Some(prev.as_str()) {
                    return Err(Error::Corrupt {
                        line: line_no,
                        reason: "prev_hash mismatch".into(),
                    });
                }
                records.push(Record {
                    seq: expect_seq,
                    kind: rec["kind"].as_str().unwrap_or_default().to_owned(),
                    body: rec.get("body").cloned().unwrap_or(Value::Null),
                    hash: stored.clone(),
                });
            }
            prev = stored;
            offset += line.len() + 1;
        }
        let header = header.ok_or(Error::Corrupt {
            line: 1,
            reason: "missing header".into(),
        })?;
        let file = if repair {
            OpenOptions::new().append(true).open(path)?
        } else {
            File::open(path)?
        };
        let next_seq = records.len() as u64 + 1;
        Ok(Opened {
            journal: Journal {
                path: path.to_owned(),
                file,
                next_seq,
                last_hash: prev,
                header,
            },
            records,
            torn,
        })
    }

    /// Records whose intent has no ack/failed record (crash between intent and acknowledgment).
    pub fn unacknowledged(records: &[Record]) -> Vec<&Record> {
        records
            .iter()
            .filter(|r| r.kind.ends_with(".intent"))
            .filter(|i| {
                !records.iter().any(|r| {
                    (r.kind.ends_with(".ack") || r.kind.ends_with(".failed"))
                        && r.body.get("intent_seq").and_then(Value::as_u64) == Some(i.seq)
                })
            })
            .collect()
    }
}

/// Durable compaction of a **terminal** journal (§24): archive copy → history entry (itself a
/// hash-chained journal) → delete. Every step is idempotent so a crash anywhere converges.
pub fn compact(
    journal_path: &Path,
    history_dir: &Path,
    terminal_state: &str,
    results: Value,
) -> Result<Value> {
    let opened = Journal::open(journal_path)?;
    let header = opened.journal.header.clone();
    let journal_id = header["journal_id"].as_str().unwrap_or_default().to_owned();
    let bytes = fs::read(journal_path)?;
    let journal_sha = sha256_hex(&bytes);
    fs::create_dir_all(history_dir.join("archive"))?;
    let archive = history_dir
        .join("archive")
        .join(format!("{journal_id}.jsonl"));
    if !archive.exists() || sha256_hex(&fs::read(&archive)?) != journal_sha {
        let tmp = archive.with_extension("tmp");
        let mut f = File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        crate::workspace_io::rename_durable(&tmp, &archive)?;
    }
    fault("compact.after_archive");
    let history_path = history_dir.join("history.jsonl");
    let mut history = if history_path.exists() {
        Journal::open(&history_path)?.journal
    } else {
        Journal::create(&history_path, "history", "history", json!({}))?
    };
    let entry = json!({
        "journal_id": journal_id,
        "type": header["type"],
        "binding": header["binding"],
        "header_hash": header["hash"],
        "final_seq": opened.journal.last_seq(),
        "final_hash": opened.journal.last_hash(),
        "terminal_state": terminal_state,
        "results": results,
        "journal_sha256": journal_sha,
        "archive_path": archive.file_name().and_then(|n| n.to_str()),
    });
    let already = Journal::open(&history_path)?.records.iter().any(|r| {
        r.body.get("journal_id") == entry.get("journal_id")
            && r.body.get("final_hash") == entry.get("final_hash")
    });
    if !already {
        history.append("compacted", entry.clone())?;
    }
    fault("compact.after_history");
    fs::remove_file(journal_path)?;
    fsync_dir(journal_path.parent().unwrap_or(Path::new(".")))?;
    fault("compact.after_delete");
    Ok(entry)
}

/// Re-verifies an archived journal against its history commitment.
pub fn verify_archive(archive: &Path, entry: &Value) -> Result<()> {
    let bytes = fs::read(archive)?;
    if Some(sha256_hex(&bytes).as_str()) != entry["journal_sha256"].as_str() {
        return Err(Error::Corrupt {
            line: 0,
            reason: "archive sha256 mismatch".into(),
        });
    }
    let opened = Journal::open(archive)?;
    if Some(opened.journal.last_hash()) != entry["final_hash"].as_str() {
        return Err(Error::Corrupt {
            line: 0,
            reason: "archive final hash mismatch".into(),
        });
    }
    Ok(())
}
