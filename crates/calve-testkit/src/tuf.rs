//! Independent TUF test publisher (rev 10 §9.4, promoted from the G1-TUF spike): plain TUF 1.0
//! JSON signed with aws-lc-rs ed25519. It shares no code with the verifier, so tests exercise
//! sigstore-tuf against an independent producer: delegations (paths, terminating, nesting,
//! unusual names), consistent snapshots, root rotation, expiry and same-version timestamps.

use std::collections::BTreeMap;
use std::path::Path;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

pub struct SignKey {
    pair: Ed25519KeyPair,
    pub id: String,
}

impl Default for SignKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SignKey {
    pub fn new() -> SignKey {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut k = SignKey {
            pair,
            id: String::new(),
        };
        k.id = sha(&canonical(&k.json()));
        k
    }
    pub fn public_hex(&self) -> String {
        hex(self.pair.public_key().as_ref())
    }
    pub fn json(&self) -> Value {
        json!({"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": self.public_hex()}})
    }
    fn sign(&self, msg: &[u8]) -> String {
        hex(self.pair.sign(msg).as_ref())
    }
}

/// Canonical JSON for our own content (ASCII keys, integers only): sorted keys, compact. Uses
/// the contract crate's explicit sort, because serde_json's `preserve_order` feature is
/// unified on in this workspace and would keep insertion order.
pub fn canonical(v: &Value) -> Vec<u8> {
    calve_integration_contract::jcs::to_vec(v).expect("integer-only")
}

/// Envelope with signatures over the canonical `signed`; written pretty-printed so the raw
/// bytes (hashed by snapshot/timestamp) differ from the signed bytes.
pub fn envelope(signed: Value, keys: &[&SignKey]) -> Vec<u8> {
    let c = canonical(&signed);
    let sigs: Vec<Value> = keys
        .iter()
        .map(|k| json!({"keyid": k.id, "sig": k.sign(&c)}))
        .collect();
    serde_json::to_vec_pretty(&json!({"signed": signed, "signatures": sigs})).unwrap()
}

/// python-tuf `quote(role, safe="")`.
pub fn encode_role(role: &str) -> String {
    pct(role)
}

pub fn ts(t: jiff::Timestamp) -> String {
    t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn in_days(d: i64) -> jiff::Timestamp {
    jiff::Timestamp::now() + jiff::SignedDuration::from_hours(24 * d)
}

pub struct Deleg {
    pub name: String,
    pub parent: String,
    pub paths: Vec<String>,
    pub terminating: bool,
    pub key: SignKey,
    pub targets: BTreeMap<String, Vec<u8>>,
    pub version: u64,
    pub in_snapshot: bool,
}

pub struct Repo {
    pub dir: tempfile::TempDir,
    pub consistent: bool,
    pub root: SignKey,
    pub old_root: Option<SignKey>,
    pub timestamp: SignKey,
    pub snapshot: SignKey,
    pub targets_key: SignKey,
    /// Extra entries merged into root `keys` (policy tests).
    pub root_extra_keys: BTreeMap<String, Value>,
    pub root_version: u64,
    root_dirty: bool,
    pub version: u64,
    pub expires: BTreeMap<&'static str, jiff::Timestamp>,
    pub targets: BTreeMap<String, Vec<u8>>,
    pub delegs: Vec<Deleg>,
    pub hash_algos: Vec<&'static str>,
}

impl Default for Repo {
    fn default() -> Self {
        Self::new()
    }
}

impl Repo {
    pub fn new() -> Repo {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("metadata")).unwrap();
        std::fs::create_dir_all(dir.path().join("targets")).unwrap();
        Repo {
            dir,
            consistent: true,
            root: SignKey::new(),
            old_root: None,
            timestamp: SignKey::new(),
            snapshot: SignKey::new(),
            targets_key: SignKey::new(),
            root_extra_keys: BTreeMap::new(),
            root_version: 0,
            root_dirty: true,
            version: 0,
            expires: BTreeMap::new(),
            targets: BTreeMap::new(),
            delegs: Vec::new(),
            hash_algos: vec!["sha256"],
        }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }
    pub fn root_bytes(&self, v: u64) -> Vec<u8> {
        std::fs::read(self.path().join(format!("metadata/{v}.root.json"))).unwrap()
    }
    pub fn freeze(&self) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        copy_dir(self.path(), d.path());
        d
    }

    /// Adds a delegation (`parent` is `targets` or another delegated role); order of calls is
    /// the delegation order within each parent.
    pub fn delegate(
        &mut self,
        name: &str,
        parent: &str,
        paths: &[&str],
        terminating: bool,
    ) -> &mut Deleg {
        self.delegs.push(Deleg {
            name: name.into(),
            parent: parent.into(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            terminating,
            key: SignKey::new(),
            targets: BTreeMap::new(),
            version: 0,
            in_snapshot: true,
        });
        self.delegs.last_mut().unwrap()
    }
    pub fn deleg(&mut self, name: &str) -> &mut Deleg {
        self.delegs.iter_mut().find(|d| d.name == name).unwrap()
    }

    pub fn rotate_root(&mut self) {
        self.old_root = Some(std::mem::take(&mut self.root));
        self.root_dirty = true;
    }
    pub fn touch_root(&mut self) {
        self.root_dirty = true;
    }

    fn exp(&self, role: &'static str) -> String {
        ts(self
            .expires
            .get(role)
            .copied()
            .unwrap_or_else(|| in_days(30)))
    }

    fn target_meta(&self, t: &BTreeMap<String, Vec<u8>>) -> Value {
        let mut m = serde_json::Map::new();
        for (p, b) in t {
            let mut h = serde_json::Map::new();
            for a in &self.hash_algos {
                let d = match *a {
                    "sha256" => sha(b),
                    "sha512" => hex(&sha2::Sha512::digest(b)),
                    _ => unreachable!(),
                };
                h.insert(a.to_string(), json!(d));
            }
            m.insert(p.clone(), json!({"length": b.len(), "hashes": h}));
        }
        Value::Object(m)
    }

    fn delegations_of(&self, parent: &str) -> Option<Value> {
        let kids: Vec<&Deleg> = self.delegs.iter().filter(|d| d.parent == parent).collect();
        if kids.is_empty() {
            return None;
        }
        let keys: serde_json::Map<String, Value> = kids
            .iter()
            .map(|d| (d.key.id.clone(), d.key.json()))
            .collect();
        let roles: Vec<Value> = kids
            .iter()
            .map(|d| json!({"name": d.name, "keyids": [d.key.id], "threshold": 1, "terminating": d.terminating, "paths": d.paths}))
            .collect();
        Some(json!({"keys": keys, "roles": roles}))
    }

    fn targets_signed(&self, name: &str, version: u64, t: &BTreeMap<String, Vec<u8>>) -> Value {
        let mut s = json!({"_type": "targets", "spec_version": "1.0.31", "version": version, "expires": self.exp("targets"), "targets": self.target_meta(t)});
        if let Some(d) = self.delegations_of(name) {
            s["delegations"] = d;
        }
        s
    }

    fn put_meta(&self, role_file: &str, version: u64, bytes: &[u8]) {
        let m = self.path().join("metadata");
        std::fs::write(m.join(format!("{role_file}.json")), bytes).unwrap();
        std::fs::write(m.join(format!("{version}.{role_file}.json")), bytes).unwrap();
    }

    fn put_targets(&self, t: &BTreeMap<String, Vec<u8>>) {
        for (p, b) in t {
            let full = self.path().join("targets").join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, b).unwrap();
            let name = full.file_name().unwrap().to_string_lossy().into_owned();
            let h = if self.hash_algos[0] == "sha256" {
                sha(b)
            } else {
                hex(&sha2::Sha512::digest(b))
            };
            std::fs::write(full.with_file_name(format!("{h}.{name}")), b).unwrap();
        }
    }

    pub fn write_root(&mut self) {
        self.root_version += 1;
        let mut keys = serde_json::Map::new();
        for k in [
            &self.root,
            &self.timestamp,
            &self.snapshot,
            &self.targets_key,
        ] {
            keys.insert(k.id.clone(), k.json());
        }
        for (id, k) in &self.root_extra_keys {
            keys.insert(id.clone(), k.clone());
        }
        let role = |k: &SignKey| json!({"keyids": [k.id], "threshold": 1});
        let signed = json!({
            "_type": "root", "spec_version": "1.0.31", "version": self.root_version, "expires": self.exp("root"),
            "consistent_snapshot": self.consistent, "keys": keys,
            "roles": {"root": role(&self.root), "timestamp": role(&self.timestamp), "snapshot": role(&self.snapshot), "targets": role(&self.targets_key)},
        });
        let mut signers = vec![&self.root];
        if let Some(o) = &self.old_root {
            signers.push(o);
        }
        let bytes = envelope(signed, &signers);
        let m = self.path().join("metadata");
        std::fs::write(m.join(format!("{}.root.json", self.root_version)), &bytes).unwrap();
        std::fs::write(m.join("root.json"), &bytes).unwrap();
        self.old_root = None;
        self.root_dirty = false;
    }

    /// Writes timestamp only, with the given version (same-version/rollback tests).
    pub fn write_timestamp(&self, version: u64, snapshot_version: u64) {
        let snap = std::fs::read(
            self.path()
                .join(format!("metadata/{snapshot_version}.snapshot.json")),
        )
        .unwrap();
        let signed = json!({"_type": "timestamp", "spec_version": "1.0.31", "version": version, "expires": self.exp("timestamp"),
            "meta": {"snapshot.json": {"version": snapshot_version, "length": snap.len(), "hashes": {"sha256": sha(&snap)}}}});
        std::fs::write(
            self.path().join("metadata/timestamp.json"),
            envelope(signed, &[&self.timestamp]),
        )
        .unwrap();
    }

    /// A full new version: root (if changed), every delegated role, targets, snapshot, timestamp.
    pub fn publish(&mut self) {
        if self.root_dirty {
            self.write_root();
        }
        self.version += 1;
        let mut snap_meta = serde_json::Map::new();
        for i in 0..self.delegs.len() {
            self.delegs[i].version += 1;
            let d = &self.delegs[i];
            let bytes = envelope(
                self.targets_signed(&d.name, d.version, &d.targets),
                &[&d.key],
            );
            self.put_meta(&encode_role(&d.name), d.version, &bytes);
            self.put_targets(&d.targets);
            if d.in_snapshot {
                snap_meta.insert(format!("{}.json", d.name), json!({"version": d.version, "length": bytes.len(), "hashes": {"sha256": sha(&bytes)}}));
            }
        }
        let tb = envelope(
            self.targets_signed("targets", self.version, &self.targets),
            &[&self.targets_key],
        );
        self.put_meta("targets", self.version, &tb);
        self.put_targets(&self.targets);
        snap_meta.insert("targets.json".into(), json!({"version": self.version}));
        let snap = envelope(
            json!({"_type": "snapshot", "spec_version": "1.0.31", "version": self.version, "expires": self.exp("snapshot"), "meta": snap_meta}),
            &[&self.snapshot],
        );
        self.put_meta("snapshot", self.version, &snap);
        self.write_timestamp(self.version, self.version);
    }
}

pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// One package version to publish (catalog conventions in `calve_app::catalog::install`).
pub struct Package<'a> {
    pub id: &'a str,
    pub version: &'a str,
    /// `cic-capable` or `openaevc-only`.
    pub kind: &'a str,
    /// `(file name, bytes)` of the native artifact for this host's platform.
    pub native: (&'a str, Vec<u8>),
    pub cic: Option<Vec<u8>>,
    pub metadata: Option<Vec<u8>>,
    /// `calve-refs.json` (required when the native manifest declares `calve.refs/1`).
    pub refs: Option<Vec<u8>>,
}

/// The exact target triple of this host (the key Calve looks up in `package.json`).
pub fn host_platform() -> String {
    calve_integration_contract::catalog::HOST_TARGET.into()
}

impl Repo {
    /// The targets map of `role` (`targets` or a delegated role name).
    pub fn role_targets(&mut self, role: &str) -> &mut BTreeMap<String, Vec<u8>> {
        if role == "targets" {
            &mut self.targets
        } else {
            &mut self.deleg(role).targets
        }
    }

    /// Adds a package version under `role`: the host's native build at
    /// `<id>/<version>/<triple>/<file>`, other files at `<id>/<version>/<file>`, and a merged
    /// `<id>/package.json`. Call [`Repo::publish`] afterwards.
    pub fn add_package(&mut self, role: &str, p: Package) {
        let mut files: Vec<(String, Vec<u8>)> = vec![];
        let mut entry = json!({"version": p.version, "kind": p.kind, "native": {}});
        if let Some(c) = p.cic {
            files.push(("cic.wasm".into(), c));
            entry["cic"] = json!("cic.wasm");
        }
        if let Some(m) = p.metadata {
            files.push(("calve-integration.json".into(), m));
            entry["metadata"] = json!("calve-integration.json");
        }
        if let Some(r) = p.refs {
            files.push(("calve-refs.json".into(), r));
            entry["refs"] = json!("calve-refs.json");
        }
        let index_path = format!("{}/package.json", p.id);
        let t = self.role_targets(role);
        for (name, bytes) in files {
            t.insert(format!("{}/{}/{name}", p.id, p.version), bytes);
        }
        let mut index: Value = t
            .get(&index_path)
            .map(|b| serde_json::from_slice(b).unwrap())
            .unwrap_or_else(|| json!({"schema": "calve.package/1", "id": p.id, "versions": []}));
        index["versions"]
            .as_array_mut()
            .unwrap()
            .retain(|v| v["version"] != p.version);
        index["versions"].as_array_mut().unwrap().push(entry);
        t.insert(index_path, serde_json::to_vec(&index).unwrap());
        self.add_native(
            role,
            p.id,
            p.version,
            &host_platform(),
            p.native.0,
            p.native.1,
        );
    }

    /// Adds (or replaces) the native build for `target` to an existing package version.
    pub fn add_native(
        &mut self,
        role: &str,
        id: &str,
        version: &str,
        target: &str,
        file: &str,
        bytes: Vec<u8>,
    ) {
        let index_path = format!("{id}/package.json");
        let digest = sha(&bytes);
        let t = self.role_targets(role);
        t.insert(
            calve_integration_contract::catalog::native_path(id, version, target, file),
            bytes,
        );
        let mut index: Value = serde_json::from_slice(&t[&index_path]).unwrap();
        for v in index["versions"].as_array_mut().unwrap() {
            if v["version"] == version {
                v["native"][target] = json!({"file": file, "sha256": digest});
            }
        }
        t.insert(index_path, serde_json::to_vec(&index).unwrap());
    }

    /// Top-level `revocations.json`.
    pub fn revoke(&mut self, id: &str, version: Option<&str>, reason: &str) {
        let mut doc: Value = self
            .targets
            .get("revocations.json")
            .map(|b| serde_json::from_slice(b).unwrap())
            .unwrap_or_else(|| json!({"revoked": []}));
        let mut r = json!({"id": id, "reason": reason});
        if let Some(v) = version {
            r["version"] = json!(v);
        }
        doc["revoked"].as_array_mut().unwrap().push(r);
        self.targets
            .insert("revocations.json".into(), serde_json::to_vec(&doc).unwrap());
    }

    /// Top-level `id-policy.json`: allowed id prefixes per delegated role.
    pub fn id_policy(&mut self, role: &str, prefixes: &[&str]) {
        let mut doc: Value = self
            .targets
            .get("id-policy.json")
            .map(|b| serde_json::from_slice(b).unwrap())
            .unwrap_or_else(|| json!({"roles": {}}));
        doc["roles"][role] = json!(prefixes);
        self.targets
            .insert("id-policy.json".into(), serde_json::to_vec(&doc).unwrap());
    }
}
