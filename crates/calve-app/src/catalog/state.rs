//! Trust-state persistence (rev 10 §9.2, ADR 0008): generations of verifier-accepted state,
//! floors, recovery. Promoted from the G1-TUF FG15 rerun on sigstore-tuf 0.15.0.
//!
//! Same commit protocol and recovery rules as the M0 tough prototype; what changed with the
//! verifier:
//! - A generation holds the **exact verified bytes** the client wrote through its
//!   `MetadataStore` (no re-serialization, so no separate `raw/` copy).
//! - The bootstrap root is kept next to `REPO_ID` (= its sha256) and every generation keeps the
//!   root chain (`root_history/N.root.json`).
//! - Restore replays the stored files through `TrustedMetadataSet` explicitly, as of the time
//!   the state was accepted; every error propagates (never a silent cache miss).
//! - Delegated roles are loaded lazily inside a transition that resolves a target, so they land
//!   in the new generation; delegation floors come from the snapshot pins.
//! - The verifier's clock is `max(system clock, last accepted time)`: a clock stepped back can
//!   never make expired metadata current again.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sigstore_tuf::{MetadataStore, TrustedMetadataSet, UpdaterConfig};

use super::tuf::{Mirror, TargetInfo, TrustClient, TrustError, encode_role, policy, sha};

/// A target resolved in a transition, with its verified bytes when downloaded.
type Resolved = (TargetInfo, Option<Vec<u8>>);
/// A target with its verified bytes.
pub type Fetched = (TargetInfo, Vec<u8>);

/// Verifier-written files live in `gen-N/tuf/`, apart from Calve's own `state.json`: a delegated
/// role's metadata is stored under its (encoded) role name, so a role named `state` must not be
/// able to collide with a Calve file (security review of ee47ddc).
pub const TUF_DIR: &str = "tuf";

/// Fault points of the commit protocol (crash = return early, leaving the disk as is).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    TmpCopied,
    ClientAccepted,
    StateWritten,
    Prepared,
    Verified,
    FloorsPrevWritten,
    FloorsWritten,
    Activated,
    Pruning,
}

pub const STEPS: [Step; 9] = [
    Step::TmpCopied,
    Step::ClientAccepted,
    Step::StateWritten,
    Step::Prepared,
    Step::Verified,
    Step::FloorsPrevWritten,
    Step::FloorsWritten,
    Step::Activated,
    Step::Pruning,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenError {
    Crash(Step),
    /// The TUF verifier refused the transition.
    Refused(String),
    /// Calve's policy refused a verifier-accepted transition (catalog policy, floors, repo id).
    Policy(String),
    RecoveryRequired(String),
    Io(String),
}

fn io(e: impl std::fmt::Display) -> GenError {
    GenError::Io(e.to_string())
}

fn trust(e: TrustError) -> GenError {
    match e {
        TrustError::Tuf(e) => GenError::Refused(e.to_string()),
        TrustError::Policy(m) => GenError::Policy(m),
    }
}

/// Versions of an accepted state (what floors are made of).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Versions {
    pub root: u64,
    pub timestamp: u64,
    pub snapshot: u64,
    pub targets: u64,
    /// Delegated role → version pinned by the snapshot.
    pub delegations: BTreeMap<String, u64>,
}

impl Versions {
    fn to_json(&self) -> Value {
        json!({"root": self.root, "timestamp": self.timestamp, "snapshot": self.snapshot, "targets": self.targets, "delegations": self.delegations})
    }
    fn from_json(v: &Value) -> Option<Versions> {
        Some(Versions {
            root: v["root"].as_u64()?,
            timestamp: v["timestamp"].as_u64()?,
            snapshot: v["snapshot"].as_u64()?,
            targets: v["targets"].as_u64()?,
            delegations: serde_json::from_value(v["delegations"].clone()).ok()?,
        })
    }
    pub fn at_least(&self, floor: &Versions) -> bool {
        self.root >= floor.root
            && self.timestamp >= floor.timestamp
            && self.snapshot >= floor.snapshot
            && self.targets >= floor.targets
            && floor
                .delegations
                .iter()
                .all(|(r, v)| self.delegations.get(r).is_none_or(|x| x >= v))
    }
    fn max_merge(&self, o: &Versions) -> Versions {
        let mut d = self.delegations.clone();
        for (r, v) in &o.delegations {
            let e = d.entry(r.clone()).or_default();
            *e = (*e).max(*v);
        }
        Versions {
            root: self.root.max(o.root),
            timestamp: self.timestamp.max(o.timestamp),
            snapshot: self.snapshot.max(o.snapshot),
            targets: self.targets.max(o.targets),
            delegations: d,
        }
    }
    fn of(set: &TrustedMetadataSet) -> Result<Versions, GenError> {
        let (Some(t), Some(s), Some(g)) =
            (set.timestamp(), set.snapshot(), set.targets_role("targets"))
        else {
            return Err(GenError::Refused("incomplete trusted state".into()));
        };
        Ok(Versions {
            root: set.root().version,
            timestamp: t.version,
            snapshot: s.version,
            targets: g.version,
            delegations: s
                .meta
                .iter()
                .filter(|(n, _)| *n != "targets.json")
                .filter_map(|(n, m)| Some((n.strip_suffix(".json")?.to_owned(), m.version)))
                .collect(),
        })
    }
}

/// The verifier's write-through store, pointed at a generation being prepared. Target bytes are
/// never part of trust state.
struct GenStore(sigstore_tuf::FileStore);

impl MetadataStore for GenStore {
    fn load(&self, name: &str) -> sigstore_tuf::Result<Option<Vec<u8>>> {
        self.0.load(name)
    }
    fn store(&self, name: &str, bytes: &[u8]) -> sigstore_tuf::Result<()> {
        if name.starts_with("targets/") {
            Ok(())
        } else {
            self.0.store(name, bytes)
        }
    }
}

fn now_max(floor: Option<jiff::Timestamp>) -> jiff::Timestamp {
    let n = jiff::Timestamp::now();
    floor.map_or(n, |f| n.max(f))
}

fn files(dir: &Path, rel: &str, out: &mut Vec<String>) -> Result<(), GenError> {
    for e in fs::read_dir(dir.join(rel)).map_err(io)? {
        let e = e.map_err(io)?;
        let name = format!("{rel}{}", e.file_name().to_string_lossy());
        if e.file_type().map_err(io)?.is_dir() {
            files(dir, &format!("{name}/"), out)?;
        } else if name != "state.json" && !name.contains(".tmp") {
            out.push(name);
        }
    }
    Ok(())
}

/// Digest over every file of a generation except state.json.
pub fn state_digest(gen_dir: &Path) -> Result<String, GenError> {
    let mut names = Vec::new();
    files(gen_dir, "", &mut names)?;
    names.sort();
    let mut acc = Vec::new();
    for n in names {
        acc.extend_from_slice(n.as_bytes());
        acc.push(0);
        acc.extend_from_slice(sha(&fs::read(gen_dir.join(&n)).map_err(io)?).as_bytes());
        acc.push(0);
    }
    Ok(sha(&acc))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), GenError> {
    use std::io::Write;
    let tmp = path.with_extension("tmp-write");
    // Sync through the writable handle: Windows FlushFileBuffers needs write access.
    let mut f = fs::File::create(&tmp).map_err(io)?;
    f.write_all(bytes).and_then(|()| f.sync_all()).map_err(io)?;
    drop(f);
    // Unix: rename + directory fsync; Windows: MOVEFILE_WRITE_THROUGH (calve-win-sec).
    crate::workspace_io::rename_durable(&tmp, path).map_err(io)?;
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), GenError> {
    let mut names = Vec::new();
    files(from, "", &mut names)?;
    for n in names {
        let d = to.join(&n);
        fs::create_dir_all(d.parent().unwrap()).map_err(io)?;
        fs::copy(from.join(&n), d).map_err(io)?;
    }
    Ok(())
}

/// Explicit restore: replay a generation's stored bytes through the verifier as of `at` (the
/// time it was accepted). Errors propagate; an unexpected or unverifiable file is an error.
pub fn replay(
    bootstrap: &[u8],
    gen_dir: &Path,
    at: jiff::Timestamp,
) -> Result<TrustedMetadataSet, String> {
    let rd = |n: &str| fs::read(gen_dir.join(n)).map_err(|e| format!("{n}: {e}"));
    let mut set = TrustedMetadataSet::from_root(bootstrap).map_err(|e| e.to_string())?;
    let mut v = set.root().version + 1;
    while let Ok(b) = fs::read(gen_dir.join(format!("root_history/{v}.root.json"))) {
        set.update_root(&b).map_err(|e| format!("root v{v}: {e}"))?;
        v += 1;
    }
    if rd("root.json")? != set.root_bytes() {
        return Err("root.json is not the end of the stored root chain".into());
    }
    set.update_timestamp(&rd("timestamp.json")?, at)
        .map_err(|e| format!("timestamp: {e}"))?;
    set.update_snapshot(&rd("snapshot.json")?, at)
        .map_err(|e| format!("snapshot: {e}"))?;
    set.update_targets(&rd("targets.json")?, at)
        .map_err(|e| format!("targets: {e}"))?;
    // Delegated roles present in the generation, each through the delegator that names it.
    let mut todo = vec!["targets".to_owned()];
    while let Some(parent) = todo.pop() {
        let kids: Vec<String> = set
            .targets_role(&parent)
            .and_then(|t| t.delegations.as_ref())
            .map(|d| d.roles.iter().map(|r| r.name.clone()).collect())
            .unwrap_or_default();
        for k in kids {
            if set.targets_role(&k).is_some() {
                continue;
            }
            if let Ok(b) = fs::read(gen_dir.join(format!("{}.json", encode_role(&k)))) {
                set.update_delegated_targets(&b, &k, &parent, at)
                    .map_err(|e| format!("{k}: {e}"))?;
                todo.push(k);
            }
        }
    }
    Ok(set)
}

/// Removes delegated role files that no longer verify under the generation's own top-level
/// metadata (a refresh copies the previous generation, then updates only what it touched: a
/// lazily fetched role pinned to an older snapshot version is stale, not corrupt). They are
/// fetched and verified again when next needed; everything that stays passes [`replay`].
fn prune_stale_delegations(
    bootstrap: &[u8],
    gen_dir: &Path,
    at: jiff::Timestamp,
) -> Result<(), String> {
    let rd = |n: &str| fs::read(gen_dir.join(n)).map_err(|e| format!("{n}: {e}"));
    let mut set = TrustedMetadataSet::from_root(bootstrap).map_err(|e| e.to_string())?;
    let mut v = set.root().version + 1;
    while let Ok(b) = fs::read(gen_dir.join(format!("root_history/{v}.root.json"))) {
        set.update_root(&b).map_err(|e| format!("root v{v}: {e}"))?;
        v += 1;
    }
    set.update_timestamp(&rd("timestamp.json")?, at)
        .map_err(|e| format!("timestamp: {e}"))?;
    set.update_snapshot(&rd("snapshot.json")?, at)
        .map_err(|e| format!("snapshot: {e}"))?;
    set.update_targets(&rd("targets.json")?, at)
        .map_err(|e| format!("targets: {e}"))?;
    let mut todo = vec!["targets".to_owned()];
    while let Some(parent) = todo.pop() {
        let kids: Vec<String> = set
            .targets_role(&parent)
            .and_then(|t| t.delegations.as_ref())
            .map(|d| d.roles.iter().map(|r| r.name.clone()).collect())
            .unwrap_or_default();
        for k in kids {
            if set.targets_role(&k).is_some() {
                continue;
            }
            let file = gen_dir.join(format!("{}.json", encode_role(&k)));
            if let Ok(b) = fs::read(&file) {
                if set.update_delegated_targets(&b, &k, &parent, at).is_ok() {
                    todo.push(k);
                } else {
                    fs::remove_file(&file).map_err(|e| format!("{k}: {e}"))?;
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct Catalog {
    pub dir: PathBuf,
    pub repo_id: String,
    pub active: u64,
    pub active_state_digest: String,
    pub versions: Versions,
    pub history: BTreeMap<String, u64>,
    /// Latest accepted time (the verifier's clock never goes below it).
    pub accepted_at: Option<jiff::Timestamp>,
    /// Cap for any downloaded target (a package file); the verifier also caps each fetch at
    /// the target's pinned length.
    pub max_target_bytes: u64,
    bootstrap: Vec<u8>,
}

/// Default cap for one package file.
pub const MAX_TARGET_BYTES: u64 = 256 * 1024 * 1024;

impl Catalog {
    fn gen_dir(&self, n: u64) -> PathBuf {
        self.dir.join(format!("gen-{n}"))
    }

    /// Bootstrap from a root pinned by digest.
    pub fn bootstrap(
        dir: &Path,
        root: &[u8],
        pinned: &str,
        mirror: &Mirror,
    ) -> Result<Catalog, GenError> {
        if sha(root) != pinned {
            return Err(GenError::Policy(
                "root digest does not match the pin".into(),
            ));
        }
        fs::create_dir_all(dir).map_err(io)?;
        write_atomic(&dir.join("bootstrap-root.json"), root)?;
        write_atomic(&dir.join("REPO_ID"), pinned.as_bytes())?;
        let zero = dir.join("gen-0");
        fs::create_dir_all(&zero).map_err(io)?;
        let mut c = Catalog {
            dir: dir.into(),
            repo_id: pinned.into(),
            active: 0,
            active_state_digest: state_digest(&zero)?,
            versions: Versions::default(),
            history: BTreeMap::new(),
            accepted_at: None,
            bootstrap: root.to_vec(),
            max_target_bytes: MAX_TARGET_BYTES,
        };
        c.refresh(mirror, None)?;
        fs::remove_dir_all(&zero).map_err(io)?;
        Ok(c)
    }

    pub fn refresh(&mut self, mirror: &Mirror, fault: Option<Step>) -> Result<Versions, GenError> {
        self.transition(mirror, fault, &[], false).map(|(v, _)| v)
    }

    /// A refresh that also resolves `target`, loading the delegated roles on its search path
    /// into the new generation.
    pub fn resolve(
        &mut self,
        mirror: &Mirror,
        target: &str,
        fault: Option<Step>,
    ) -> Result<Option<TargetInfo>, GenError> {
        let (_, mut t) = self.transition(mirror, fault, &[target], false)?;
        Ok(t.pop().flatten().map(|(i, _)| i))
    }

    /// [`Catalog::resolve`] plus the verified bytes of the target (one bounded fetch through the
    /// verifier, length and sha256 checked). A failed download discards the transition.
    pub fn fetch(
        &mut self,
        mirror: &Mirror,
        target: &str,
        fault: Option<Step>,
    ) -> Result<Option<(TargetInfo, Vec<u8>)>, GenError> {
        Ok(self.fetch_all(mirror, &[target], fault)?.pop().flatten())
    }

    /// Several targets resolved and downloaded in **one** transition, so every file of a
    /// package comes from the same accepted trust state.
    pub fn fetch_all(
        &mut self,
        mirror: &Mirror,
        targets: &[&str],
        fault: Option<Step>,
    ) -> Result<Vec<Option<Fetched>>, GenError> {
        let (_, t) = self.transition(mirror, fault, targets, true)?;
        Ok(t.into_iter()
            .map(|r| r.map(|(i, b)| (i, b.expect("downloaded"))))
            .collect())
    }

    fn transition(
        &mut self,
        mirror: &Mirror,
        fault: Option<Step>,
        targets: &[&str],
        download: bool,
    ) -> Result<(Versions, Vec<Option<Resolved>>), GenError> {
        let crash = |s: Step| {
            if fault == Some(s) {
                Err(GenError::Crash(s))
            } else {
                Ok(())
            }
        };
        // Trust state is per machine and processes share it: one transition at a time, and only
        // from the state this process actually read, so a stale one can never lower the floors.
        let lock = fs::File::create(self.dir.join("transition.lock")).map_err(io)?;
        lock.lock().map_err(io)?;
        if read_current(&self.dir).is_some_and(|k| k != self.active) {
            return Err(GenError::Io(
                "another process changed this catalog; try again".into(),
            ));
        }
        let n = self.active + 1;
        let tmp = self.dir.join(format!("gen-{n}.tmp"));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).map_err(io)?;
        copy_tree(&self.gen_dir(self.active), &tmp)?;
        crash(Step::TmpCopied)?;
        let now = now_max(self.accepted_at);
        let accepted = (|| {
            let store: Box<dyn MetadataStore> =
                Box::new(GenStore(sigstore_tuf::FileStore::new(tmp.join(TUF_DIR))));
            let mut c = TrustClient::new(mirror.clone(), &self.bootstrap, Some(store), {
                let mut l = UpdaterConfig::default();
                l.target_max_length = self.max_target_bytes;
                l
            })
            .map_err(trust)?;
            c.refresh(now).map_err(trust)?;
            let mut t = Vec::with_capacity(targets.len());
            for p in targets {
                t.push(match c.resolve(p, now).map_err(trust)? {
                    Some(info) if download => {
                        let bytes = c.download(&info).map_err(trust)?;
                        Some((info, Some(bytes)))
                    }
                    other => other.map(|i| (i, None)),
                });
            }
            Ok((Versions::of(c.trusted())?, t))
        })();
        let (v, found) = match accepted {
            Ok(x) => x,
            Err(e) => {
                let _ = fs::remove_dir_all(&tmp);
                return Err(e);
            }
        };
        crash(Step::ClientAccepted)?;
        if let Err(e) = prune_stale_delegations(&self.bootstrap, &tmp.join(TUF_DIR), now) {
            let _ = fs::remove_dir_all(&tmp);
            return Err(GenError::Policy(format!("trust state: {e}")));
        }
        let digest = state_digest(&tmp)?;
        let mut state = json!({
            "repo_id": self.repo_id, "gen": n, "parent_gen": self.active, "parent_state_digest": self.active_state_digest,
            "state_digest": digest, "client_accepted": true, "phase": "Prepared", "versions": v.to_json(), "accepted_at": now.to_string(),
        });
        write_atomic(
            &tmp.join("state.json"),
            &serde_json::to_vec(&state).unwrap(),
        )?;
        crash(Step::StateWritten)?;
        let dest = self.gen_dir(n);
        fs::rename(&tmp, &dest).map_err(io)?;
        crash(Step::Prepared)?;
        let floors = self.floors();
        if !v.at_least(&floors) {
            fs::rename(&dest, self.rejected(n)).map_err(io)?;
            return Err(GenError::Policy(format!(
                "below floors: {v:?} < {floors:?}"
            )));
        }
        state["phase"] = json!("Verified");
        write_atomic(
            &dest.join("state.json"),
            &serde_json::to_vec(&state).unwrap(),
        )?;
        crash(Step::Verified)?;
        self.activate(n, &digest, &v, now, fault)?;
        Ok((v, found))
    }

    fn rejected(&self, n: u64) -> PathBuf {
        let r = self.dir.join("rejected");
        let _ = fs::create_dir_all(&r);
        r.join(format!(
            "gen-{n}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn floors(&self) -> Versions {
        let mut f = self.versions.clone();
        f.delegations = self.history.clone();
        f
    }

    fn activate(
        &mut self,
        n: u64,
        digest: &str,
        v: &Versions,
        at: jiff::Timestamp,
        fault: Option<Step>,
    ) -> Result<(), GenError> {
        let crash = |s: Step| {
            if fault == Some(s) {
                Err(GenError::Crash(s))
            } else {
                Ok(())
            }
        };
        let fpath = self.dir.join("floors.json");
        if let Ok(b) = fs::read(&fpath) {
            write_atomic(&self.dir.join("floors.prev.json"), &b)?;
        }
        crash(Step::FloorsPrevWritten)?;
        let merged = self.floors().max_merge(v);
        let at = self.accepted_at.map_or(at, |a| a.max(at));
        let floors = json!({"repo_id": self.repo_id, "gen": n, "versions": Versions { delegations: BTreeMap::new(), ..merged.clone() }.to_json(), "delegation_history": merged.delegations, "accepted_at": at.to_string()});
        write_atomic(&fpath, &serde_json::to_vec(&floors).unwrap())?;
        crash(Step::FloorsWritten)?;
        let state_sha = sha(&fs::read(self.gen_dir(n).join("state.json")).map_err(io)?);
        write_atomic(
            &self.dir.join("CURRENT"),
            &serde_json::to_vec(&json!({"gen": n, "state_sha256": state_sha})).unwrap(),
        )?;
        crash(Step::Activated)?;
        let prev = self.active;
        self.active = n;
        self.active_state_digest = digest.into();
        self.versions = v.clone();
        self.history = merged.delegations;
        self.accepted_at = Some(at);
        for e in fs::read_dir(&self.dir).map_err(io)?.filter_map(|e| e.ok()) {
            let name = e.file_name().into_string().unwrap();
            if let Some(k) = name
                .strip_prefix("gen-")
                .and_then(|k| k.parse::<u64>().ok())
                && k != n
                && k != prev
            {
                crash(Step::Pruning)?;
                fs::remove_dir_all(e.path()).map_err(io)?;
            }
        }
        Ok(())
    }

    /// Deterministic recovery (§9.2): never re-validates from the network, never activates on
    /// checksums alone, never falls back to a parent of the activated generation.
    pub fn open(dir: &Path) -> Result<Catalog, GenError> {
        let rr = |m: &str| GenError::RecoveryRequired(m.into());
        let pinned_repo = fs::read_to_string(dir.join("REPO_ID"))
            .map_err(|_| rr("trust_state: REPO_ID missing"))?;
        let bootstrap = fs::read(dir.join("bootstrap-root.json"))
            .map_err(|_| rr("trust_state: bootstrap root missing"))?;
        if sha(&bootstrap) != pinned_repo {
            return Err(rr("trust_state: bootstrap root does not match REPO_ID"));
        }
        let mut gens: BTreeMap<u64, Value> = BTreeMap::new();
        for e in fs::read_dir(dir).map_err(io)?.filter_map(|e| e.ok()) {
            let name = e.file_name().into_string().unwrap();
            if name.ends_with(".tmp") {
                fs::remove_dir_all(e.path()).map_err(io)?;
                continue;
            }
            if let Some(k) = name
                .strip_prefix("gen-")
                .and_then(|k| k.parse::<u64>().ok())
                && let Ok(s) = fs::read(e.path().join("state.json"))
                && let Ok(v) = serde_json::from_slice::<Value>(&s)
            {
                if v["repo_id"].as_str() == Some(pinned_repo.as_str()) {
                    gens.insert(k, v);
                } else {
                    let q = dir.join("rejected");
                    fs::create_dir_all(&q).map_err(io)?;
                    fs::rename(e.path(), q.join(format!("{name}-foreign"))).map_err(io)?;
                }
            }
        }
        let gen_dir = |k: u64| dir.join(format!("gen-{k}"));
        let intact = |k: u64, st: &Value| {
            state_digest(&gen_dir(k)).is_ok_and(|d| Some(d.as_str()) == st["state_digest"].as_str())
        };
        let current = read_current(dir);
        let active = match current {
            Some(k) => k,
            None => {
                let chained = |k: u64| -> bool {
                    let mut k = k;
                    loop {
                        let Some(st) = gens.get(&k) else { return false };
                        if !intact(k, st)
                            || st["client_accepted"] != json!(true)
                            || st["phase"] != json!("Verified")
                        {
                            return false;
                        }
                        let p = st["parent_gen"].as_u64().unwrap_or(0);
                        match gens.get(&p) {
                            Some(ps) if ps["state_digest"] == st["parent_state_digest"] => k = p,
                            None => return !gens.keys().any(|&x| x < k),
                            _ => return false,
                        }
                    }
                };
                *gens
                    .keys()
                    .rev()
                    .find(|&&k| chained(k))
                    .ok_or_else(|| rr("trust_state: CURRENT lost and no intact chain"))?
            }
        };
        let st = gens
            .get(&active)
            .ok_or_else(|| rr("trust_state: activated generation missing"))?
            .clone();
        if !intact(active, &st) {
            return Err(rr("trust_state: activated generation corrupt"));
        }
        let at: jiff::Timestamp = st["accepted_at"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| rr("trust_state: accepted_at unreadable"))?;
        // The verifier must accept the stored state as of its acceptance time.
        let set = replay(&bootstrap, &gen_dir(active).join(TUF_DIR), at)
            .map_err(|e| rr(&format!("trust_state: verifier refused stored state: {e}")))?;
        policy::check_root(&set).map_err(|e| rr(&format!("trust_state: {e}")))?;
        let v = Versions::of(&set)?;
        let repo_id = st["repo_id"].as_str().unwrap_or_default().to_owned();
        let mut c = Catalog {
            dir: dir.into(),
            repo_id: repo_id.clone(),
            active,
            active_state_digest: st["state_digest"].as_str().unwrap().into(),
            versions: v.clone(),
            history: BTreeMap::new(),
            accepted_at: Some(at),
            bootstrap,
            max_target_bytes: MAX_TARGET_BYTES,
        };
        // A damaged file must not lower the floors, so the previous ones stand in for it.
        let read_floors = |name: &str| {
            fs::read(dir.join(name))
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .filter(|f| f["repo_id"] == json!(repo_id))
        };
        let current_floors = read_floors("floors.json");
        let floors = current_floors
            .clone()
            .or_else(|| read_floors("floors.prev.json"));
        let floor_versions = match &floors {
            Some(f) => {
                Some(Versions::from_json(&f["versions"]).ok_or_else(|| rr("floors unreadable"))?)
            }
            None => None,
        };
        if let Some(fa) = floors
            .as_ref()
            .and_then(|f| f["accepted_at"].as_str())
            .and_then(|s| s.parse::<jiff::Timestamp>().ok())
        {
            c.accepted_at = Some(fa.max(at));
        }
        c.history = match &floors {
            Some(f) => serde_json::from_value(f["delegation_history"].clone()).unwrap_or_default(),
            None => v.delegations.clone(),
        };
        // Roll forward exactly one client-accepted child of the activated state.
        for (&k, st) in gens.range(active + 1..) {
            let child = st["client_accepted"] == json!(true)
                && st["parent_gen"].as_u64() == Some(active)
                && st["parent_state_digest"].as_str() == Some(c.active_state_digest.as_str())
                && st["repo_id"] == json!(c.repo_id)
                && intact(k, st);
            let v = Versions::from_json(&st["versions"]);
            let kat = st["accepted_at"]
                .as_str()
                .and_then(|s| s.parse::<jiff::Timestamp>().ok());
            let verified = child
                && kat.is_some_and(|kat| {
                    replay(&c.bootstrap, &gen_dir(k).join(TUF_DIR), kat).is_ok()
                });
            if verified && k == c.active + 1 && v.as_ref().is_some_and(|v| v.at_least(&c.floors()))
            {
                let digest = st["state_digest"].as_str().unwrap().to_owned();
                let mut s = st.clone();
                s["phase"] = json!("Verified");
                write_atomic(
                    &gen_dir(k).join("state.json"),
                    &serde_json::to_vec(&s).unwrap(),
                )?;
                c.activate(k, &digest, &v.unwrap(), kat.unwrap(), None)?;
            } else {
                fs::rename(gen_dir(k), c.rejected(k)).map_err(io)?;
            }
        }
        match floor_versions {
            Some(fv) if !c.versions.at_least(&fv) => {
                return Err(rr(
                    "trust_state: floors exceed the activated state (lost newer state)",
                ));
            }
            _ if current_floors.is_some() => {}
            _ => {
                let av = c.versions.clone();
                let at = c.accepted_at.unwrap().to_string();
                write_atomic(&dir.join("floors.json"), &serde_json::to_vec(&json!({"repo_id": repo_id, "gen": c.active, "versions": Versions { delegations: BTreeMap::new(), ..av }.to_json(), "delegation_history": c.history, "accepted_at": at})).unwrap())?;
            }
        }
        Ok(c)
    }

    /// Audited privileged reset (§9.3): new bootstrap from `root`, old state archived.
    pub fn reset(
        dir: &Path,
        root: &[u8],
        pinned: &str,
        mirror: &Mirror,
    ) -> Result<Catalog, GenError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let archive = dir.join(format!("archive-{ts}"));
        fs::create_dir_all(&archive).map_err(io)?;
        for e in fs::read_dir(dir).map_err(io)?.filter_map(|e| e.ok()) {
            if e.path() != archive && !e.file_name().to_string_lossy().starts_with("archive-") {
                fs::rename(e.path(), archive.join(e.file_name())).map_err(io)?;
            }
        }
        let log = json!({"event": "catalog-reset", "root_digest": pinned, "archived": archive.file_name().unwrap().to_string_lossy()});
        fs::write(
            dir.join("catalog-reset.log"),
            serde_json::to_vec(&log).unwrap(),
        )
        .map_err(io)?;
        let reset = Catalog::bootstrap(dir, root, pinned, mirror);
        if reset.is_err() {
            // The old trust state goes back: a refused reset must leave the catalog as it was.
            for e in fs::read_dir(dir).map_err(io)?.filter_map(|e| e.ok()) {
                if !e.file_name().to_string_lossy().starts_with("archive-") {
                    let _ = fs::remove_dir_all(e.path()).or_else(|_| fs::remove_file(e.path()));
                }
            }
            for e in fs::read_dir(&archive).map_err(io)?.filter_map(|e| e.ok()) {
                fs::rename(e.path(), dir.join(e.file_name())).map_err(io)?;
            }
            let _ = fs::remove_dir(&archive);
        }
        reset
    }
}

/// The activated generation `CURRENT` names, if its state file is intact.
fn read_current(dir: &Path) -> Option<u64> {
    let c: Value = serde_json::from_slice(&fs::read(dir.join("CURRENT")).ok()?).ok()?;
    let k = c["gen"].as_u64()?;
    let st = fs::read(dir.join(format!("gen-{k}")).join("state.json")).ok()?;
    (sha(&st) == c["state_sha256"].as_str()?).then_some(k)
}
