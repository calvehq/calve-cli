//! Extension manager: catalogs, a content-addressed package cache, install/update/uninstall,
//! Project enablement and host-capability grants. OpenAEVC owns the extension contract,
//! handshake and runtime authorization; this module only decides what to hand it.
//!
//! Catalog format (a directory holding `catalog.json`):
//! ```json
//! {"signed": {"name": "...", "version": 3, "expires": 1893456000,
//!             "packages": [{"id": "org.example.x", "version": "1.2.0",
//!                           "artifact": "x-1.2.0", "digest": "sha256:...",
//!                           "summary": "..."}]},
//!  "signatures": [{"public_key": "ed25519:...", "signature": "..."}]}
//! ```
//! Signatures are Ed25519 over `CATALOG_DOMAIN || json(signed)` with sorted keys. A catalog is
//! trusted only through `extension catalog-trust`, which pins its keys and threshold; Calve
//! refuses expired metadata and any version older than the last one it accepted.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use openaevc::crypto::sha256;
use openaevc::protocol::{
    Digest, ExtensionManifest, HostCapability, PublicKey, Query, SUPPORTED_CONTRACT, Signature,
};
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::registry::default_data_root;
use crate::{Error, Project, Result, event, now};

pub const CATALOG_DOMAIN: &[u8] = b"calve.catalog.v1\n";
const BUNDLED: &str = "bundled";
const MAX_ARTIFACT: u64 = 256 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogPackage {
    pub id: String,
    pub version: String,
    /// Artifact path relative to the catalog directory.
    pub artifact: String,
    pub digest: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogBody {
    pub name: String,
    pub version: u64,
    pub expires: u64,
    pub packages: Vec<CatalogPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogSignature {
    pub public_key: PublicKey,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCatalog {
    pub signed: Value,
    pub signatures: Vec<CatalogSignature>,
}

/// Local trust state for one catalog: the current root and the highest accepted version of
/// every role (rollback floors).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedCatalog {
    pub location: PathBuf,
    /// `signed` body of the newest verified root.
    pub root: Value,
    #[serde(default)]
    pub versions: BTreeMap<String, u64>,
}

/// Keys and threshold for one role, as listed in a root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleKeys {
    pub keys: Vec<PublicKey>,
    pub threshold: usize,
}

const ROLES: [&str; 4] = ["root", "targets", "snapshot", "timestamp"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRecord {
    pub id: String,
    pub version: String,
    pub digest: Digest,
    /// Entrypoint relative to the package cache, as registered with OpenAEVC.
    pub entrypoint: String,
    pub manifest: ExtensionManifest,
    pub source: String,
    pub installed_at: u64,
    /// Metadata is kept after uninstall so historical bindings stay explainable.
    #[serde(default)]
    pub uninstalled: bool,
}

/// Bytes a catalog signer signs; shared by verification and the publishing tool.
pub fn catalog_message(signed: &Value) -> Result<Vec<u8>> {
    // serde_json::Value keeps object keys sorted, which makes this encoding deterministic.
    let mut message = CATALOG_DOMAIN.to_vec();
    message.extend(serde_json::to_vec(signed)?);
    Ok(message)
}

/// Signs any role body with each seed.
pub fn sign_role(signed: Value, seeds: &[[u8; 32]]) -> Result<SignedCatalog> {
    use ed25519_dalek::Signer;
    let message = catalog_message(&signed)?;
    let signatures = seeds
        .iter()
        .map(|seed| {
            let key = ed25519_dalek::SigningKey::from_bytes(seed);
            CatalogSignature {
                public_key: PublicKey::from_bytes(key.verifying_key().to_bytes()),
                signature: Signature::from_bytes(key.sign(&message).to_bytes()),
            }
        })
        .collect();
    Ok(SignedCatalog { signed, signatures })
}

pub fn public_key(seed: &[u8; 32]) -> PublicKey {
    PublicKey::from_bytes(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    )
}

fn role_file(dir: &Path, name: &str) -> Result<(Vec<u8>, SignedCatalog)> {
    let path = dir.join(name);
    let bytes = fs::read(&path)
        .map_err(|error| invalid(format!("cannot read {}: {error}", path.display())))?;
    let parsed = serde_json::from_slice(&bytes)?;
    Ok((bytes, parsed))
}

fn write_role(dir: &Path, name: &str, file: &SignedCatalog) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(file)?;
    fs::write(dir.join(name), &bytes)?;
    Ok(bytes)
}

fn version_of(dir: &Path, name: &str) -> u64 {
    role_file(dir, name)
        .ok()
        .and_then(|(_, f)| f.signed["version"].as_u64())
        .unwrap_or(0)
}

/// Publishes or refreshes a catalog: `targets.body.json` (a [`CatalogBody`]) becomes signed
/// `targets.json`, then a new `snapshot.json` and `timestamp.json`. A root is created on first
/// publish. Every role here uses the same keys; rotate with [`rotate_root`].
pub fn publish_catalog(
    dir: &Path,
    seeds: &[[u8; 32]],
    threshold: usize,
    expires_days: u64,
) -> Result<Value> {
    if seeds.is_empty() || threshold == 0 || threshold > seeds.len() {
        return Err(invalid(
            "threshold must be between 1 and the number of keys",
        ));
    }
    let expires = now()? + expires_days * 86_400;
    if !dir.join("root.json").exists() {
        let keys = RoleKeys {
            keys: seeds.iter().map(public_key).collect(),
            threshold,
        };
        let roles: BTreeMap<&str, &RoleKeys> = ROLES.iter().map(|r| (*r, &keys)).collect();
        let root = sign_role(
            json!({"type":"root","version":1,"expires":expires,"roles":roles}),
            seeds,
        )?;
        write_role(dir, "root.json", &root)?;
        write_role(dir, "root.1.json", &root)?;
    }
    let mut body: Value = serde_json::from_slice(&fs::read(dir.join("targets.body.json"))?)?;
    for package in body["packages"].as_array().into_iter().flatten() {
        let digest: Digest = serde_json::from_value(package["digest"].clone())?;
        let artifact = package["artifact"].as_str().unwrap_or_default();
        if sha256(&fs::read(dir.join(artifact))?) != digest {
            return Err(invalid(format!(
                "{artifact} does not match its listed digest"
            )));
        }
    }
    body["type"] = json!("targets");
    let targets_version = version_of(dir, "targets.json") + 1;
    body["version"] = json!(targets_version);
    body["expires"] = json!(expires);
    let targets = write_role(dir, "targets.json", &sign_role(body, seeds)?)?;
    let snapshot_version = version_of(dir, "snapshot.json") + 1;
    let snapshot = write_role(
        dir,
        "snapshot.json",
        &sign_role(
            json!({"type":"snapshot","version":snapshot_version,"expires":expires,
            "targets":{"version":targets_version,"digest":sha256(&targets)}}),
            seeds,
        )?,
    )?;
    let timestamp_version = version_of(dir, "timestamp.json") + 1;
    // Timestamps expire soon so a frozen mirror is noticed quickly.
    write_role(
        dir,
        "timestamp.json",
        &sign_role(
            json!({"type":"timestamp","version":timestamp_version,"expires":now()? + (7 * 86_400u64).min(expires_days * 86_400),
            "snapshot":{"version":snapshot_version,"digest":sha256(&snapshot)}}),
            seeds,
        )?,
    )?;
    Ok(
        json!({"targets":targets_version,"snapshot":snapshot_version,"timestamp":timestamp_version,
        "root_digest":sha256(&fs::read(dir.join("root.json"))?)}),
    )
}

/// Writes the next root, signed by the current root keys and the new keys, and re-signs the
/// other roles with the new keys.
pub fn rotate_root(
    dir: &Path,
    old: &[[u8; 32]],
    new: &[[u8; 32]],
    threshold: usize,
    expires_days: u64,
) -> Result<Value> {
    if new.is_empty() || threshold == 0 || threshold > new.len() {
        return Err(invalid(
            "threshold must be between 1 and the number of new keys",
        ));
    }
    let version = version_of(dir, "root.json") + 1;
    let keys = RoleKeys {
        keys: new.iter().map(public_key).collect(),
        threshold,
    };
    let roles: BTreeMap<&str, &RoleKeys> = ROLES.iter().map(|r| (*r, &keys)).collect();
    let mut seeds = old.to_vec();
    seeds.extend_from_slice(new);
    let root = sign_role(
        json!({"type":"root","version":version,"expires":now()? + expires_days * 86_400,"roles":roles}),
        &seeds,
    )?;
    write_role(dir, &format!("root.{version}.json"), &root)?;
    write_role(dir, "root.json", &root)?;
    let mut result = publish_catalog(dir, new, threshold, expires_days)?;
    result["root"] = json!(version);
    Ok(result)
}

fn cache_root() -> Result<PathBuf> {
    Ok(default_data_root()?.join("extensions"))
}

/// Cache location for runtime lookup; absent when no data directory can be resolved.
pub fn cache_dir() -> Option<PathBuf> {
    cache_root().ok()
}

/// Directory OpenAEVC searches for cached extension entrypoints.
pub fn package_cache_dir() -> Result<PathBuf> {
    let root = cache_root()?;
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn digest_dir(digest: &Digest) -> String {
    digest.to_string().replace(':', "_")
}

fn trust_path() -> Result<PathBuf> {
    Ok(default_data_root()?.join("catalogs.json"))
}

fn usage_path() -> Result<PathBuf> {
    Ok(cache_root()?.join("usage.json"))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().ok_or_else(|| invalid("path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".{}.tmp", uuid::Uuid::now_v7()));
    fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn read_json<T: for<'a> Deserialize<'a> + Default>(path: &Path) -> Result<T> {
    match fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(error) => Err(error.into()),
    }
}

fn trusted() -> Result<BTreeMap<String, TrustedCatalog>> {
    read_json(&trust_path()?)
}

/// Project IDs that have each artifact digest enabled; uninstall consults it.
// ponytail: whole-file rewrite without a lock; concurrent enables across Projects could race.
fn usage() -> Result<BTreeMap<String, BTreeSet<String>>> {
    read_json(&usage_path()?)
}

fn set_usage(digest: &Digest, project: &str, used: bool) -> Result<()> {
    let mut map = usage()?;
    let entry = map.entry(digest.to_string()).or_default();
    if used {
        entry.insert(project.to_owned());
    } else {
        entry.remove(project);
    }
    map.retain(|_, projects| !projects.is_empty());
    write_json(&usage_path()?, &map)
}

pub fn installed() -> Result<Vec<PackageRecord>> {
    let root = cache_root()?;
    let mut records = Vec::new();
    let Ok(entries) = fs::read_dir(&root) else {
        return Ok(records);
    };
    for entry in entries {
        let path = entry?.path().join("package.json");
        if path.is_file() {
            records.push(serde_json::from_slice::<PackageRecord>(&fs::read(path)?)?);
        }
    }
    records.sort_by(|a, b| {
        (a.id.as_str(), version_key(&a.version)).cmp(&(b.id.as_str(), version_key(&b.version)))
    });
    Ok(records)
}

/// Numeric-aware ordering for dotted versions ("1.10.0" > "1.9.0").
fn version_key(version: &str) -> Vec<(u64, String)> {
    version
        .split(['.', '-', '+'])
        .map(|part| (part.parse().unwrap_or(0), part.to_owned()))
        .collect()
}

fn newest<'a>(records: impl Iterator<Item = &'a PackageRecord>) -> Option<&'a PackageRecord> {
    records.max_by(|a, b| version_key(&a.version).cmp(&version_key(&b.version)))
}

fn artifact_filename(id: &str) -> String {
    let base = id.replace('.', "_");
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base
    }
}

/// Copies an artifact into the cache, handshakes it and records its manifest.
/// Staging plus rename means a crash never leaves a half-installed package visible.
pub fn install_artifact(
    source_path: &Path,
    expected: Option<&CatalogPackage>,
    source: &str,
) -> Result<PackageRecord> {
    let metadata = fs::metadata(source_path)?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT {
        return Err(invalid(
            "extension artifact must be a regular file of at most 256 MiB",
        ));
    }
    let bytes = fs::read(source_path)?;
    let digest = sha256(&bytes);
    if let Some(expected) = expected
        && expected.digest != digest
    {
        return Err(invalid(format!(
            "artifact digest {digest} does not match catalog digest {}",
            expected.digest
        )));
    }
    let root = package_cache_dir()?;
    let final_dir = root.join(digest_dir(&digest));
    let record_path = final_dir.join("package.json");
    if record_path.is_file() {
        let mut record: PackageRecord = serde_json::from_slice(&fs::read(&record_path)?)?;
        let artifact = root.join(&record.entrypoint);
        if !artifact.is_file() || sha256(&fs::read(&artifact)?) != digest {
            // Reinstall over uninstalled or damaged metadata.
            fs::remove_dir_all(&final_dir)?;
        } else {
            if record.uninstalled {
                record.uninstalled = false;
                write_json(&record_path, &record)?;
            }
            return Ok(record);
        }
    }
    let staging = root.join(format!(".staging-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&staging)?;
    let result = (|| {
        // The manifest id is unknown until the handshake, so stage under a neutral name.
        let staged = staging.join(if cfg!(windows) {
            "artifact.exe"
        } else {
            "artifact"
        });
        fs::write(&staged, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))?;
        }
        let (manifest, _) = openaevc::extension::host::handshake(
            &openaevc::extension::host::Entrypoint {
                program: staged.clone(),
                args: vec![],
            },
            &openaevc::extension::host::HostLimits {
                deadline: std::time::Duration::from_secs(60),
                ..openaevc::extension::host::HostLimits::default()
            },
        )
        .map_err(|error| invalid(format!("extension handshake failed: {error:?}")))?;
        if manifest.artifact_digest != digest {
            return Err(invalid(
                "extension reports a different artifact digest than its bytes",
            ));
        }
        if let Some(expected) = expected
            && (manifest.id != expected.id || manifest.version != expected.version)
        {
            return Err(invalid(format!(
                "artifact is {}@{}, catalog promised {}@{}",
                manifest.id, manifest.version, expected.id, expected.version
            )));
        }
        crate::compatibility::check_range(
            "extension contract",
            &SUPPORTED_CONTRACT,
            &manifest.contract,
        )?;
        let filename = artifact_filename(&manifest.id);
        fs::rename(&staged, staging.join(&filename))?;
        let record = PackageRecord {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
            digest,
            entrypoint: format!("{}/{filename}", digest_dir(&digest)),
            manifest,
            source: source.to_owned(),
            installed_at: now()?,
            uninstalled: false,
        };
        write_json(&staging.join("package.json"), &record)?;
        crate::observe::record(
            "extension.install",
            json!({"id":record.id,"version":record.version,"digest":record.digest,"source":record.source}),
        );
        Ok(record)
    })();
    match result {
        Ok(record) => {
            if let Err(error) = fs::rename(&staging, &final_dir) {
                let _ = fs::remove_dir_all(&staging);
                if !final_dir.join("package.json").is_file() {
                    return Err(error.into());
                }
            }
            Ok(record)
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            Err(error)
        }
    }
}

/// Digest of a bundled artifact, memoized by path, size and mtime so lookups do not rehash
/// every shipped binary.
fn bundled_digest(path: &Path) -> Result<Digest> {
    let metadata = fs::metadata(path)?;
    let stamp = format!(
        "{}:{}:{:?}",
        path.display(),
        metadata.len(),
        metadata.modified()?
    );
    let index_path = cache_root()?.join("bundled-digests.json");
    let mut index: BTreeMap<String, Digest> = read_json(&index_path)?;
    if let Some(digest) = index.get(&stamp) {
        return Ok(*digest);
    }
    let digest = sha256(&fs::read(path)?);
    index.retain(|key, _| !key.starts_with(&format!("{}:", path.display())));
    index.insert(stamp, digest);
    write_json(&index_path, &index)?;
    Ok(digest)
}

/// Staging directories left by an interrupted install (older than ten minutes, so a running
/// install is never disturbed). The installed packages themselves stay valid.
pub fn staging_leftovers() -> Vec<Value> {
    let Ok(root) = cache_root() else {
        return vec![];
    };
    let Ok(entries) = fs::read_dir(&root) else {
        return vec![];
    };
    entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".staging-"))
        .filter(|entry| {
            entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age.as_secs() > 600)
        })
        .map(|entry| {
            json!({"action":"remove_staging_dir","path":entry.path(),
            "reason":"left by an interrupted extension install"})
        })
        .collect()
}

/// Packages shipped beside the calve executable; trusted as part of the same installation.
fn bundled_packages() -> Result<Vec<(CatalogPackage, PathBuf)>> {
    let exe = std::env::current_exe()?;
    let Some(dir) = exe.parent() else {
        return Ok(vec![]);
    };
    let mut packages = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let executable = path.extension().is_none()
            || cfg!(windows) && path.extension().is_some_and(|ext| ext == "exe");
        if !name.starts_with("calve_ext_") || !executable || !path.is_file() {
            continue;
        }
        // First-party naming convention; install verifies the manifest agrees.
        let id = format!(
            "org.calve.{}",
            name.trim_start_matches("calve_ext_").replace('_', "-")
        );
        let digest = bundled_digest(&path)?;
        let version = env!("CARGO_PKG_VERSION").to_owned();
        packages.push((
            CatalogPackage {
                id,
                version,
                artifact: path.display().to_string(),
                digest,
                summary: Some("Bundled with Calve".into()),
            },
            path,
        ));
    }
    Ok(packages)
}

fn role_keys(root: &Value, role: &str) -> Result<RoleKeys> {
    serde_json::from_value(root["roles"][role].clone())
        .map_err(|_| invalid(format!("root does not define the {role} role")))
}

/// Counts distinct valid signatures from `keys` and checks the threshold and role type.
fn check_signatures(file: &SignedCatalog, keys: &RoleKeys, role: &str) -> Result<()> {
    if file.signed["type"] != role {
        return Err(invalid(format!("{role} metadata has the wrong type")));
    }
    let message = catalog_message(&file.signed)?;
    let mut valid = BTreeSet::new();
    for entry in &file.signatures {
        if !keys.keys.contains(&entry.public_key) {
            continue;
        }
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(entry.public_key.as_bytes()) else {
            continue;
        };
        let signature = ed25519_dalek::Signature::from_bytes(entry.signature.as_bytes());
        if key.verify_strict(&message, &signature).is_ok() {
            valid.insert(entry.public_key);
        }
    }
    if valid.len() < keys.threshold {
        return Err(invalid(format!(
            "{role}: {} of {} required trusted signatures are valid",
            valid.len(),
            keys.threshold
        )));
    }
    Ok(())
}

fn fresh(file: &SignedCatalog, role: &str, floor: u64) -> Result<u64> {
    let version = file.signed["version"]
        .as_u64()
        .ok_or_else(|| invalid(format!("{role} has no version")))?;
    if version < floor {
        return Err(invalid(format!(
            "{role} version {version} is older than accepted version {floor} (possible rollback)"
        )));
    }
    if file.signed["expires"].as_u64().unwrap_or(0) <= now()? {
        return Err(invalid(format!(
            "{role} metadata expired; refresh it from the publisher"
        )));
    }
    Ok(version)
}

/// Full TUF-style verification: root chain, timestamp, snapshot, targets. Returns the targets
/// body and the trust state to persist.
fn verify_catalog(name: &str, trust: &TrustedCatalog) -> Result<(CatalogBody, TrustedCatalog)> {
    let dir = &trust.location;
    let mut next = trust.clone();
    let floor = |role: &str| trust.versions.get(role).copied().unwrap_or(0);
    // 1. Walk root rotations: each new root is signed by the old and the new root keys.
    loop {
        let current = next.root["version"].as_u64().unwrap_or(0);
        let Ok((_, candidate)) = role_file(dir, &format!("root.{}.json", current + 1)) else {
            break;
        };
        check_signatures(&candidate, &role_keys(&next.root, "root")?, "root")?;
        check_signatures(&candidate, &role_keys(&candidate.signed, "root")?, "root")?;
        if candidate.signed["version"].as_u64() != Some(current + 1) {
            return Err(invalid("root rotation skipped a version"));
        }
        next.root = candidate.signed;
    }
    if next.root["expires"].as_u64().unwrap_or(0) <= now()? {
        return Err(invalid(format!(
            "catalog {name}: root expired; the publisher must rotate it"
        )));
    }
    let root_version = next.root["version"].as_u64().unwrap_or(0);
    // 2. Timestamp vouches for the snapshot; 3. snapshot vouches for targets.
    let (_, timestamp) = role_file(dir, "timestamp.json")?;
    check_signatures(
        &timestamp,
        &role_keys(&next.root, "timestamp")?,
        "timestamp",
    )?;
    let timestamp_version = fresh(&timestamp, "timestamp", floor("timestamp"))?;
    let (snapshot_bytes, snapshot) = role_file(dir, "snapshot.json")?;
    if timestamp.signed["snapshot"]["digest"] != json!(sha256(&snapshot_bytes))
        || timestamp.signed["snapshot"]["version"] != snapshot.signed["version"]
    {
        return Err(invalid(format!(
            "catalog {name}: snapshot does not match the timestamp"
        )));
    }
    check_signatures(&snapshot, &role_keys(&next.root, "snapshot")?, "snapshot")?;
    let snapshot_version = fresh(&snapshot, "snapshot", floor("snapshot"))?;
    let (targets_bytes, targets) = role_file(dir, "targets.json")?;
    if snapshot.signed["targets"]["digest"] != json!(sha256(&targets_bytes))
        || snapshot.signed["targets"]["version"] != targets.signed["version"]
    {
        return Err(invalid(format!(
            "catalog {name}: targets do not match the snapshot"
        )));
    }
    check_signatures(&targets, &role_keys(&next.root, "targets")?, "targets")?;
    let targets_version = fresh(&targets, "targets", floor("targets"))?;
    let mut signed = targets.signed.clone();
    if let Some(map) = signed.as_object_mut() {
        map.remove("type");
    }
    let body: CatalogBody = serde_json::from_value(signed)?;
    if body.name != name {
        return Err(invalid(format!(
            "catalog {name}: metadata names itself {}",
            body.name
        )));
    }
    next.versions = BTreeMap::from([
        ("root".to_owned(), root_version),
        ("timestamp".to_owned(), timestamp_version),
        ("snapshot".to_owned(), snapshot_version),
        ("targets".to_owned(), targets_version),
    ]);
    Ok((body, next))
}

/// Verified catalogs; persists advanced roots and rollback floors.
fn catalogs() -> Result<Vec<(String, Result<CatalogBody>)>> {
    let mut trust = trusted()?;
    let mut out = Vec::new();
    let mut changed = false;
    for (name, entry) in trust.iter_mut() {
        match verify_catalog(name, entry) {
            Ok((body, next)) => {
                if next.versions != entry.versions || next.root != entry.root {
                    *entry = next;
                    changed = true;
                }
                out.push((name.clone(), Ok(body)));
            }
            Err(error) => out.push((name.clone(), Err(error))),
        }
    }
    if changed {
        write_json(&trust_path()?, &trust)?;
    }
    Ok(out)
}

pub fn list_catalogs() -> Result<Value> {
    let mut items = vec![json!({"name":BUNDLED,"trust":"bundled-with-calve",
        "packages":bundled_packages()?.len()})];
    let trust = trusted()?;
    for (name, body) in catalogs()? {
        let entry = &trust[&name];
        items.push(match body {
            Ok(body) => json!({"name":name,"trust":"signed","location":entry.location,
                "versions":entry.versions,"root_keys":entry.root["roles"]["root"],
                "expires":body.expires,"packages":body.packages.len(),"valid":true}),
            Err(error) => json!({"name":name,"trust":"signed","location":entry.location,
                "valid":false,"problem":error.to_string()}),
        });
    }
    Ok(json!(items))
}

/// Root digest of the first-party catalog, embedded by release builds
/// (`CALVE_FIRST_PARTY_ROOT_DIGEST` at compile time).
pub const FIRST_PARTY_ROOT_DIGEST: Option<&str> = option_env!("CALVE_FIRST_PARTY_ROOT_DIGEST");

/// Trusts a catalog by pinning the digest of its current `root.json` (TUF bootstrap).
pub fn trust_catalog(name: &str, location: &Path, root_digest: Option<&str>) -> Result<Value> {
    let root_digest = match (root_digest, name, FIRST_PARTY_ROOT_DIGEST) {
        (Some(digest), _, _) => digest,
        (None, "first-party", Some(embedded)) => embedded,
        (None, _, _) => return Err(invalid("--root-digest is required to trust this catalog")),
    };
    if name == BUNDLED || !crate::config::valid_id(name) {
        return Err(invalid(format!("invalid catalog name {name:?}")));
    }
    let location = fs::canonicalize(location)?;
    let (bytes, root) = role_file(&location, "root.json")?;
    let expected: Digest = root_digest
        .parse()
        .map_err(|_| invalid("invalid --root-digest"))?;
    if sha256(&bytes) != expected {
        return Err(invalid("root.json does not match the pinned digest"));
    }
    check_signatures(&root, &role_keys(&root.signed, "root")?, "root")?;
    let entry = TrustedCatalog {
        location,
        root: root.signed,
        versions: BTreeMap::new(),
    };
    // Verify everything before persisting so an unusable catalog is never trusted.
    let (body, entry) = verify_catalog(name, &entry)?;
    let mut all = trusted()?;
    all.insert(name.to_owned(), entry.clone());
    write_json(&trust_path()?, &all)?;
    Ok(json!({"name":name,"versions":entry.versions,"packages":body.packages.len()}))
}

pub fn untrust_catalog(name: &str) -> Result<Value> {
    let mut all = trusted()?;
    if all.remove(name).is_none() {
        return Err(invalid(format!("catalog {name} is not trusted")));
    }
    write_json(&trust_path()?, &all)?;
    Ok(json!({"untrusted":name}))
}

struct Candidate {
    catalog: String,
    package: CatalogPackage,
    artifact: PathBuf,
}

fn candidates() -> Result<(Vec<Candidate>, Vec<String>)> {
    let mut found: Vec<Candidate> = bundled_packages()?
        .into_iter()
        .map(|(package, artifact)| Candidate {
            catalog: BUNDLED.into(),
            package,
            artifact,
        })
        .collect();
    let trust = trusted()?;
    let mut warnings = Vec::new();
    for (name, body) in catalogs()? {
        match body {
            Ok(body) => {
                for package in body.packages {
                    let relative = Path::new(&package.artifact);
                    if relative.is_absolute()
                        || relative
                            .components()
                            .any(|part| !matches!(part, std::path::Component::Normal(_)))
                    {
                        warnings.push(format!(
                            "catalog {name}: ignored unsafe artifact path {}",
                            package.artifact
                        ));
                        continue;
                    }
                    found.push(Candidate {
                        artifact: trust[&name].location.join(relative),
                        catalog: name.clone(),
                        package,
                    });
                }
            }
            Err(error) => warnings.push(error.to_string()),
        }
    }
    Ok((found, warnings))
}

pub fn search(query: Option<&str>) -> Result<Value> {
    let (found, warnings) = candidates()?;
    let query = query.map(str::to_lowercase);
    let installed = installed()?;
    let items: Vec<Value> = found
        .iter()
        .filter(|candidate| {
            query.as_ref().is_none_or(|query| {
                candidate.package.id.to_lowercase().contains(query)
                    || candidate
                        .package
                        .summary
                        .as_ref()
                        .is_some_and(|summary| summary.to_lowercase().contains(query))
            })
        })
        .map(|candidate| {
            json!({"id":candidate.package.id,"version":candidate.package.version,
                "catalog":candidate.catalog,"digest":candidate.package.digest,
                "summary":candidate.package.summary,
                "installed":installed.iter().any(|record| record.digest == candidate.package.digest && !record.uninstalled)})
        })
        .collect();
    Ok(json!({"packages":items,"warnings":warnings}))
}

fn best_candidate(id: &str, version: Option<&str>) -> Result<Candidate> {
    let (found, warnings) = candidates()?;
    found
        .into_iter()
        .filter(|candidate| {
            candidate.package.id == id && version.is_none_or(|v| candidate.package.version == v)
        })
        .max_by(|a, b| version_key(&a.package.version).cmp(&version_key(&b.package.version)))
        .ok_or_else(|| {
            invalid(format!(
                "no trusted catalog offers {id}{}{}",
                version.map(|v| format!("@{v}")).unwrap_or_default(),
                if warnings.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", warnings.join("; "))
                }
            ))
        })
}

pub fn install(id: &str, version: Option<&str>) -> Result<Value> {
    let candidate = best_candidate(id, version)?;
    let source = format!("{}:{}", candidate.catalog, candidate.package.version);
    let record = install_artifact(&candidate.artifact, Some(&candidate.package), &source)?;
    Ok(
        json!({"id":record.id,"version":record.version,"digest":record.digest,
        "catalog":candidate.catalog,"requested_host_capabilities":record.manifest.host_capabilities}),
    )
}

pub fn list_installed() -> Result<Value> {
    let usage = usage()?;
    Ok(json!(
        installed()?
            .into_iter()
            .map(
                |record| json!({"id":record.id,"version":record.version,"digest":record.digest,
            "source":record.source,"uninstalled":record.uninstalled,
            "enabled_in":usage.get(&record.digest.to_string()).cloned().unwrap_or_default()})
            )
            .collect::<Vec<_>>()
    ))
}

/// Refuses while any Project still has the artifact enabled; keeps metadata for history.
pub fn uninstall(id: &str, version: Option<&str>) -> Result<Value> {
    let usage = usage()?;
    let root = cache_root()?;
    let mut removed = Vec::new();
    for mut record in installed()?.into_iter().filter(|record| {
        record.id == id && !record.uninstalled && version.is_none_or(|v| record.version == v)
    }) {
        if let Some(projects) = usage.get(&record.digest.to_string()) {
            return Err(invalid(format!(
                "{}@{} is enabled in Project(s) {}; disable it there first",
                record.id,
                record.version,
                projects.iter().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
        let dir = root.join(digest_dir(&record.digest));
        let _ = fs::remove_file(root.join(&record.entrypoint));
        record.uninstalled = true;
        write_json(&dir.join("package.json"), &record)?;
        removed.push(json!({"id":record.id,"version":record.version,"digest":record.digest}));
    }
    if removed.is_empty() {
        return Err(invalid(format!("{id} is not installed")));
    }
    Ok(json!({"uninstalled":removed}))
}

fn parse_capabilities(names: &[String]) -> Result<Vec<HostCapability>> {
    names
        .iter()
        .map(|name| {
            serde_json::from_value(json!(name))
                .map_err(|_| invalid(format!("unknown host capability {name}")))
        })
        .collect()
}

fn capability_names(capabilities: &[HostCapability]) -> Vec<String> {
    capabilities
        .iter()
        .filter_map(|cap| serde_json::to_value(cap).ok()?.as_str().map(str::to_owned))
        .collect()
}

impl Project {
    fn granted_capabilities(&self, id: &str, digest: &Digest) -> Result<Vec<HostCapability>> {
        let mut stmt = self.db.prepare(
            "SELECT capability FROM extension_grants WHERE extension_id=?1 AND artifact_digest=?2 ORDER BY capability",
        )?;
        let names = stmt
            .query_map([id, &digest.to_string()], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        parse_capabilities(&names)
    }

    fn record_grants(&self, record: &PackageRecord, capabilities: &[HostCapability]) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM extension_grants WHERE extension_id=?1 AND artifact_digest=?2",
            [&record.id, &record.digest.to_string()],
        )?;
        for name in capability_names(capabilities) {
            tx.execute(
                "INSERT INTO extension_grants VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![
                    record.id,
                    record.version,
                    record.digest.to_string(),
                    name,
                    now()?
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Registers a cached package with OpenAEVC, approving exactly `grants`.
    async fn register_package(
        &self,
        record: &PackageRecord,
        grants: &[HostCapability],
    ) -> Result<Value> {
        let requested = &record.manifest.host_capabilities;
        if let Some(extra) = grants.iter().find(|cap| !requested.contains(cap)) {
            return Err(invalid(format!(
                "{} does not request {}; only requested capabilities can be granted",
                record.id,
                capability_names(&[*extra]).join("")
            )));
        }
        let manifest_digest = self
            .client
            .register_extension(&record.entrypoint, record.digest, grants.to_vec())
            .await?;
        self.record_grants(record, grants)?;
        set_usage(&record.digest, &self.identity.project_id, true)?;
        event(&self.db, "extension.enabled", &record.id, &record.version)?;
        let pending: Vec<&HostCapability> = requested
            .iter()
            .filter(|cap| !grants.contains(cap))
            .collect();
        Ok(
            json!({"id":record.id,"version":record.version,"artifact_digest":record.digest,
            "manifest_digest":manifest_digest,"granted":capability_names(grants),
            "ungranted_requests":capability_names(&pending.into_iter().copied().collect::<Vec<_>>())}),
        )
    }

    /// `spec` is a local artifact path or an extension id resolved through the cache/catalogs.
    pub async fn enable_extension(&self, spec: &str, grants: &[String]) -> Result<Value> {
        let grants = parse_capabilities(grants)?;
        let path = Path::new(spec);
        let record = if path.is_file() {
            install_artifact(
                path,
                None,
                &format!("local:{}", fs::canonicalize(path)?.display()),
            )?
        } else {
            let cached = installed()?;
            match newest(cached.iter().filter(|r| r.id == spec && !r.uninstalled)) {
                Some(record) => record.clone(),
                None => {
                    let candidate = best_candidate(spec, None)?;
                    install_artifact(
                        &candidate.artifact,
                        Some(&candidate.package),
                        &format!("{}:{}", candidate.catalog, candidate.package.version),
                    )?
                }
            }
        };
        if let Some(active) = self.active_package(&record.id).await?
            && active.digest != record.digest
        {
            set_usage(&active.digest, &self.identity.project_id, false)?;
        }
        self.register_package(&record, &grants).await
    }

    /// The cached package behind the extension currently registered under `id`.
    async fn active_package(&self, id: &str) -> Result<Option<PackageRecord>> {
        let listed = self.list_extensions().await?;
        let Some(entry) = listed
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["id"] == id && e["active"] == true)
        else {
            return Ok(None);
        };
        let digest: Digest = serde_json::from_value(entry["manifest"].clone())?;
        let manifest = self.client.query(Query::GetObject { digest }).await?;
        let artifact: Digest =
            serde_json::from_value(manifest["envelope"]["body"]["artifact_digest"].clone())?;
        Ok(installed()?
            .into_iter()
            .find(|record| record.digest == artifact))
    }

    async fn require_active(&self, id: &str) -> Result<PackageRecord> {
        self.active_package(id).await?.ok_or_else(|| {
            invalid(format!(
                "{id} is not enabled from the package cache in this Project"
            ))
        })
    }

    pub async fn grant_extension(&self, id: &str, capabilities: &[String]) -> Result<Value> {
        let record = self.require_active(id).await?;
        let mut grants = self.granted_capabilities(id, &record.digest)?;
        for cap in parse_capabilities(capabilities)? {
            if !grants.contains(&cap) {
                grants.push(cap);
            }
        }
        self.register_package(&record, &grants).await
    }

    pub async fn revoke_extension(&self, id: &str, capabilities: &[String]) -> Result<Value> {
        let record = self.require_active(id).await?;
        let revoke = parse_capabilities(capabilities)?;
        let grants: Vec<HostCapability> = self
            .granted_capabilities(id, &record.digest)?
            .into_iter()
            .filter(|cap| !revoke.contains(cap))
            .collect();
        self.register_package(&record, &grants).await
    }

    /// Installs the newest catalog version; switches this Project only if no capability widens
    /// beyond current grants, unless those capabilities are granted explicitly.
    pub async fn update_extension(&self, id: &str, grants: &[String]) -> Result<Value> {
        let candidate = best_candidate(id, None)?;
        let current = self.active_package(id).await?;
        if let Some(current) = &current
            && version_key(&candidate.package.version) <= version_key(&current.version)
        {
            return Ok(
                json!({"id":id,"version":current.version,"updated":false,"reason":"already newest"}),
            );
        }
        let record = install_artifact(
            &candidate.artifact,
            Some(&candidate.package),
            &format!("{}:{}", candidate.catalog, candidate.package.version),
        )?;
        let Some(current) = current else {
            return Ok(
                json!({"id":id,"version":record.version,"installed":true,"updated":false,
                "reason":"not enabled in this Project"}),
            );
        };
        let mut approved = self.granted_capabilities(id, &current.digest)?;
        for cap in parse_capabilities(grants)? {
            if !approved.contains(&cap) {
                approved.push(cap);
            }
        }
        let widening: Vec<HostCapability> = record
            .manifest
            .host_capabilities
            .iter()
            .filter(|cap| {
                !current.manifest.host_capabilities.contains(cap) && !approved.contains(cap)
            })
            .copied()
            .collect();
        if !widening.is_empty() {
            return Ok(
                json!({"id":id,"installed_version":record.version,"active_version":current.version,
                "updated":false,"permission_widening":capability_names(&widening),
                "reason":"new version requests more host capabilities; rerun with --grant for each to accept"}),
            );
        }
        approved.retain(|cap| record.manifest.host_capabilities.contains(cap));
        set_usage(&current.digest, &self.identity.project_id, false)?;
        let mut result = self.register_package(&record, &approved).await?;
        result["updated"] = json!(true);
        result["previous_version"] = json!(current.version);
        Ok(result)
    }

    pub(crate) async fn release_extension_usage(&self, id: &str) -> Result<()> {
        if let Some(record) = self.active_package(id).await? {
            set_usage(&record.digest, &self.identity.project_id, false)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_numerically() {
        assert!(version_key("1.10.0") > version_key("1.9.3"));
        assert!(version_key("0.2.0") > version_key("0.1.9"));
    }

    #[test]
    fn signed_catalog_round_trips_and_detects_tampering() {
        let body = CatalogBody {
            name: "demo".into(),
            version: 1,
            expires: u64::MAX,
            packages: vec![],
        };
        let catalog = sign_role(serde_json::to_value(&body).unwrap(), &[[7; 32]]).unwrap();
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(catalog.signatures[0].public_key.as_bytes())
                .unwrap();
        let signature =
            ed25519_dalek::Signature::from_bytes(catalog.signatures[0].signature.as_bytes());
        assert!(
            key.verify_strict(&catalog_message(&catalog.signed).unwrap(), &signature)
                .is_ok()
        );
        let mut tampered = catalog.signed.clone();
        tampered["version"] = json!(2);
        assert!(
            key.verify_strict(&catalog_message(&tampered).unwrap(), &signature)
                .is_err()
        );
    }
}
