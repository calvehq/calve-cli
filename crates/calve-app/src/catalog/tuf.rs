//! TUF adapter (rev 10 §9.1, ADR 0007): `sigstore-tuf` =0.15.0 as the verifier, behind
//! Calve's own bounded transport ([`Mirror`]), Calve's signed-catalog policy ([`policy`]) and a
//! synchronous [`TrustClient`] whose public API carries only Calve types. Only this module and
//! `catalog::state` name `sigstore_tuf` (xtask rule), so the library stays replaceable.
//! Promoted from the G1-TUF spike (docs/audit/milestones/G1-TUF.md).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use sigstore_tuf::transport::FetchFuture;
use sigstore_tuf::{Error, Repository, TargetFile, TrustedMetadataSet, Updater};

pub use sigstore_tuf::UpdaterConfig as Limits;

pub fn sha(b: &[u8]) -> String {
    crate::workspace_io::sha256_hex(b)
}

/// `User-Agent` of every catalog request: product and version only — never a user name, e-mail
/// address, credential or local path (M2 requirement 9).
pub const USER_AGENT: &str = concat!("calve/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Src {
    Dir(PathBuf),
    Http(String),
}

/// Calve's mirror transport. Every fetch is capped at the verifier's `max_length` while reading
/// (never buffered past it), HTTP has connect and whole-request deadlines (slow retrieval), and
/// paths are validated so no metadata or target name can leave the mirror base.
#[derive(Debug, Clone)]
pub struct Mirror {
    meta: Src,
    targets: Src,
    agent: ureq::Agent,
    /// Every fetch, in order (`m:<name>` / `t:<path>`), for traversal assertions.
    pub log: Arc<Mutex<Vec<String>>>,
}

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

impl Mirror {
    fn with(meta: Src, targets: Src, timeout: Duration) -> Mirror {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(timeout.min(Duration::from_secs(10))))
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .user_agent(USER_AGENT)
            // A mirror may close keep-alive connections at any time and ureq does not retry a
            // stale pooled connection (conformance run: "Peer disconnected"). One connection per
            // fetch. ponytail: no pooling; add a single retry-on-stale if fetch volume matters.
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .build()
            .new_agent();
        Mirror {
            meta,
            targets,
            agent,
            log: Arc::default(),
        }
    }

    /// `<root>/metadata/` and `<root>/targets/` on disk.
    pub fn dir(root: &Path) -> Mirror {
        Mirror::with(
            Src::Dir(root.join("metadata")),
            Src::Dir(root.join("targets")),
            DEFAULT_TIMEOUT,
        )
    }

    pub fn http(metadata_base: &str, targets_base: &str, timeout: Duration) -> Mirror {
        let slash = |s: &str| {
            if s.ends_with('/') {
                s.to_owned()
            } else {
                format!("{s}/")
            }
        };
        Mirror::with(
            Src::Http(slash(metadata_base)),
            Src::Http(slash(targets_base)),
            timeout,
        )
    }

    pub fn fetched(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn get(&self, src: &Src, name: &str, max: u64, target: bool) -> Result<Option<Vec<u8>>, Error> {
        check_name(name, target)?;
        match src {
            Src::Dir(base) => {
                let f = match std::fs::File::open(base.join(name)) {
                    Ok(f) => f,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(Error::transport(format!("{name}: {e}"))),
                };
                let mut buf = Vec::new();
                f.take(max + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| Error::transport(format!("{name}: {e}")))?;
                if buf.len() as u64 > max {
                    return Err(Error::transport(format!(
                        "{name}: exceeds max length {max}"
                    )));
                }
                Ok(Some(buf))
            }
            Src::Http(base) => {
                // Metadata names arrive already percent-encoded by the verifier; target path
                // segments are encoded here.
                let rel = if target {
                    name.split('/').map(pct).collect::<Vec<_>>().join("/")
                } else {
                    name.to_owned()
                };
                let url = format!("{base}{rel}");
                let mut resp = self
                    .agent
                    .get(&url)
                    .call()
                    .map_err(|e| Error::transport(format!("GET {url}: {e}")))?;
                let status = resp.status().as_u16();
                if status == 404 || status == 403 {
                    return Ok(None);
                }
                if !(200..300).contains(&status) {
                    return Err(Error::transport(format!("GET {url}: status {status}")));
                }
                if let Some(len) = resp.body().content_length()
                    && len > max
                {
                    return Err(Error::transport(format!(
                        "GET {url}: content-length {len} exceeds max {max}"
                    )));
                }
                // ureq's limit refuses a body of exactly `limit` bytes: read one past the cap.
                let buf = resp
                    .body_mut()
                    .with_config()
                    .limit(max.saturating_add(1))
                    .read_to_vec()
                    .map_err(|e| Error::transport(format!("GET {url}: {e}")))?;
                if buf.len() as u64 > max {
                    return Err(Error::transport(format!(
                        "GET {url}: exceeds max length {max}"
                    )));
                }
                Ok(Some(buf))
            }
        }
    }
}

/// A mirror-relative name: non-empty, relative, `/`-separated (targets only), no empty, `.` or
/// `..` segment, no backslash or NUL.
fn check_name(name: &str, target: bool) -> Result<(), Error> {
    let bad = name.is_empty()
        || name.contains(['\\', '\0'])
        || (!target && name.contains('/'))
        || name
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..");
    if bad {
        Err(Error::transport(format!("refusing mirror path {name:?}")))
    } else {
        Ok(())
    }
}

/// python-tuf `quote(role, safe="")`: the file name of a delegated role's metadata.
pub fn encode_role(role: &str) -> String {
    pct(role)
}

fn pct(seg: &str) -> String {
    let mut o = String::new();
    for &b in seg.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

impl Repository for Mirror {
    fn fetch_metadata<'a>(&'a self, name: &'a str, max_length: u64) -> FetchFuture<'a> {
        self.log.lock().unwrap().push(format!("m:{name}"));
        // ponytail: blocking I/O inside the future; M2's daemon runs this on a blocking thread.
        let r = self.get(&self.meta, name, max_length, false);
        Box::pin(async move { r })
    }

    fn fetch_target<'a>(&'a self, path: &'a str, max_length: u64) -> FetchFuture<'a> {
        self.log.lock().unwrap().push(format!("t:{path}"));
        let r = self.get(&self.targets, path, max_length, true);
        Box::pin(async move { r })
    }
}

// ---------------------------------------------------------------------------------------------
// Calve signed-catalog policy (ADR 0021): on top of TUF, never instead of it.
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
pub enum TrustError {
    /// The TUF verifier refused.
    Tuf(Error),
    /// TUF accepted, Calve's catalog policy refused.
    Policy(String),
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::Tuf(e) => write!(f, "tuf: {e}"),
            TrustError::Policy(e) => write!(f, "policy: {e}"),
        }
    }
}

impl From<Error> for TrustError {
    fn from(e: Error) -> Self {
        TrustError::Tuf(e)
    }
}

pub mod policy {
    use super::*;
    use sigstore_tuf::Key;

    fn deny(m: String) -> TrustError {
        TrustError::Policy(m)
    }

    /// ed25519 only; every declared key id equals sha256(canonical {keytype, scheme, keyval});
    /// no key material listed twice (a threshold must count distinct keys, not distinct ids).
    pub fn check_keys(keys: &BTreeMap<String, Key>, whose: &str) -> Result<(), TrustError> {
        let mut seen = std::collections::BTreeSet::new();
        for (id, k) in keys {
            if k.keytype != "ed25519" || k.scheme != "ed25519" {
                return Err(deny(format!(
                    "{whose}: key {id} is {}/{}; catalog policy is ed25519",
                    k.keytype, k.scheme
                )));
            }
            if !k.keyval.extra.is_empty() || !k.extra.is_empty() {
                return Err(deny(format!(
                    "{whose}: key {id} carries non-standard fields"
                )));
            }
            let computed = k.key_id().map_err(TrustError::Tuf)?;
            if &computed != id {
                return Err(deny(format!("{whose}: key id {id} != computed {computed}")));
            }
            if !seen.insert(k.keyval.public.to_ascii_lowercase()) {
                return Err(deny(format!(
                    "{whose}: key material listed under more than one id"
                )));
            }
        }
        Ok(())
    }

    pub fn check_root(set: &TrustedMetadataSet) -> Result<(), TrustError> {
        let root = set.root();
        if !root.consistent_snapshot {
            return Err(deny("root: consistent_snapshot must be true".into()));
        }
        check_keys(&root.keys, "root")
    }

    /// Every loaded targets role reachable from `targets`: its delegation keys follow the key
    /// policy. Run after resolution, before any result is used (fail closed).
    pub fn check_delegations(set: &TrustedMetadataSet) -> Result<(), TrustError> {
        let mut todo = vec!["targets".to_owned()];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(r) = todo.pop() {
            if !seen.insert(r.clone()) {
                continue;
            }
            let Some(t) = set.targets_role(&r) else {
                continue;
            };
            if let Some(d) = &t.delegations {
                check_keys(&d.keys, &r)?;
                todo.extend(d.roles.iter().map(|c| c.name.clone()));
            }
        }
        Ok(())
    }

    pub fn check_target(path: &str, t: &TargetFile) -> Result<(), TrustError> {
        match t.hashes.get("sha256") {
            Some(h) if h.len() == 64 => Ok(()),
            _ => Err(deny(format!(
                "{path}: catalog policy requires a sha256 target hash"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// TrustClient: synchronous facade over the verifier + policy, in Calve types.
// ---------------------------------------------------------------------------------------------

/// A target the verifier authorized (and Calve's policy accepted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    pub path: String,
    pub length: u64,
    pub sha256: String,
    /// The target's `custom` metadata, verbatim.
    pub custom: Option<Value>,
}

/// Versions of the trusted top-level roles plus the snapshot pins of delegated roles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustVersions {
    pub root: u64,
    pub timestamp: u64,
    pub snapshot: u64,
    pub targets: u64,
    pub delegations: BTreeMap<String, u64>,
}

pub struct TrustClient {
    updater: Updater,
    resolved: BTreeMap<String, TargetFile>,
}

impl TrustClient {
    pub fn new(
        mirror: Mirror,
        root: &[u8],
        store: Option<Box<dyn sigstore_tuf::MetadataStore>>,
        limits: Limits,
    ) -> Result<TrustClient, TrustError> {
        let mut u = Updater::new(mirror, root)?.with_config(limits);
        if let Some(s) = store {
            u = u.with_store(BoxStore(s));
        }
        Ok(TrustClient {
            updater: u,
            resolved: BTreeMap::new(),
        })
    }

    pub fn refresh(&mut self, now: jiff::Timestamp) -> Result<(), TrustError> {
        self.resolved.clear();
        futures_executor::block_on(self.updater.refresh(now))?;
        policy::check_root(self.updater.trusted())
    }

    /// Resolves `path` through the delegation tree (lazy pre-order search). Policy is checked
    /// on root and on every loaded delegation before the result is returned.
    pub fn resolve(
        &mut self,
        path: &str,
        now: jiff::Timestamp,
    ) -> Result<Option<TargetInfo>, TrustError> {
        // Root policy again: a caller that ignored a refused refresh never resolves through it.
        policy::check_root(self.updater.trusted())?;
        let t = futures_executor::block_on(self.updater.get_target_info(path, now))?;
        policy::check_delegations(self.updater.trusted())?;
        let Some(t) = t else { return Ok(None) };
        policy::check_target(path, &t)?;
        let info = TargetInfo {
            path: path.to_owned(),
            length: t.length,
            sha256: t.hashes["sha256"].to_ascii_lowercase(),
            custom: t.custom.clone(),
        };
        self.resolved.insert(path.to_owned(), t);
        Ok(Some(info))
    }

    /// One bounded fetch (cap = pinned length), then length + hash verification; a violation is
    /// a single error. Only targets resolved by this client can be downloaded.
    pub fn download(&self, t: &TargetInfo) -> Result<Vec<u8>, TrustError> {
        let file = self.resolved.get(&t.path).ok_or_else(|| {
            TrustError::Policy(format!("{} was not resolved by this client", t.path))
        })?;
        Ok(futures_executor::block_on(
            self.updater.download_target(file, &t.path),
        )?)
    }

    pub fn versions(&self) -> TrustVersions {
        versions_of(self.updater.trusted())
    }

    /// The verifier's trusted set (tests and `catalog::state` only).
    #[doc(hidden)]
    pub fn trusted(&self) -> &TrustedMetadataSet {
        self.updater.trusted()
    }
}

pub(crate) fn versions_of(set: &TrustedMetadataSet) -> TrustVersions {
    TrustVersions {
        root: set.root().version,
        timestamp: set.timestamp().map_or(0, |t| t.version),
        snapshot: set.snapshot().map_or(0, |s| s.version),
        targets: set.targets_role("targets").map_or(0, |t| t.version),
        delegations: set
            .snapshot()
            .map(|s| {
                s.meta
                    .iter()
                    .filter(|(n, _)| *n != "targets.json")
                    .filter_map(|(n, m)| Some((n.strip_suffix(".json")?.to_owned(), m.version)))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

struct BoxStore(Box<dyn sigstore_tuf::MetadataStore>);

impl sigstore_tuf::MetadataStore for BoxStore {
    fn load(&self, name: &str) -> sigstore_tuf::Result<Option<Vec<u8>>> {
        self.0.load(name)
    }
    fn store(&self, name: &str, bytes: &[u8]) -> sigstore_tuf::Result<()> {
        self.0.store(name, bytes)
    }
}
