//! Package installation from signed catalogs (rev 10 §8, §9.3–§9.4, ADR 0006): the
//! machine-level half of the lifecycle. Installed = a verified package at an immutable,
//! content-addressed path inside the runtime's extension directory; registration and per-Project
//! activation (grants, T2 acknowledgment) are separate (catalog activation in `crate::app`).
//!
//! Catalog conventions (all ordinary TUF targets, signed like any other):
//! - `index.json` (top-level `targets` role): `{"schema":"calve.index/1","ids":[…]}` for search;
//! - `revocations.json` (top-level): `{"revoked":[{"id","version"?,"digest"?,"reason"}]}`;
//! - `id-policy.json` (top-level): `{"roles":{"<delegation chain>":["<id prefix>", …]}}`, keyed by
//!   the full chain from the top with each role name percent-encoded (`acme`,
//!   `acme/examples`, `acme%2Fexamples` for one role named `acme/examples`), never a bare
//!   nested role name;
//! - `<id>/package.json` (signed by the role authorized for `<id>/*`): the layout in
//!   [`calve_integration_contract::catalog`]; native builds keyed by exact target triple with
//!   their sha256, at `<id>/<version>/<triple>/<file>`, every other file at
//!   `<id>/<version>/<file>`.
//!
//! Every install is journaled (I0–I4, hash-chained, §24); a crash at any step converges on
//! recovery. Nothing is executed before the trust gate, and no native code runs without the
//! T2 acknowledgment.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use calve_integration_contract::driver::{Driver, Session};
use calve_integration_contract::metadata::Metadata;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::state::{Catalog, GenError};
use super::tuf::{Mirror, TargetInfo, sha};
use crate::journal::Journal;
use crate::sandbox::{CalveHost, HostConfig, SandboxDriver, validate_module};

/// Coded install outcome (error codes per the §41 contract; M3 maps them to exit codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for InstallError {}

impl From<InstallError> for crate::Error {
    fn from(e: InstallError) -> Self {
        crate::Error::Message(e.to_string())
    }
}

fn err(code: &'static str, message: impl Into<String>) -> InstallError {
    InstallError {
        code,
        message: message.into(),
    }
}

fn io(e: impl std::fmt::Display) -> InstallError {
    err("IO_ERROR", e.to_string())
}

/// Windows services inspect a freshly written executable and hold it open briefly (seen: the
/// telemetry service), which refuses the rename. A holder that lasts past 5 s still fails, named.
fn rename_staged(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut retries = if cfg!(windows) { 50 } else { 0 };
    loop {
        match fs::rename(from, to) {
            Err(e) if retries > 0 && e.kind() == std::io::ErrorKind::PermissionDenied => {
                retries -= 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            result => return result,
        }
    }
}

/// Windows: which processes hold files under `dir` open (a refused rename's usual cause); a
/// note for the error message. Directory handles (a process's working directory) are not
/// visible to the Restart Manager, so "none" points at those.
fn holders_note(dir: &Path) -> String {
    #[cfg(windows)]
    {
        let files: Vec<PathBuf> = fs::read_dir(dir)
            .map(|r| r.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default();
        let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
        return match calve_win_sec::file_holders(&refs) {
            Ok(h) if h.is_empty() => "; no process holds a file in it open".into(),
            Ok(h) => format!(
                "; held open by {}",
                h.iter()
                    .map(|(pid, name)| format!("pid {pid} {name}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Err(e) => format!("; holders unknown ({e})"),
        };
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        String::new()
    }
}

/// An I/O error naming the operation and path (diagnosable on every platform).
fn io_at<'a>(what: &'a str, path: &'a Path) -> impl Fn(std::io::Error) -> InstallError + 'a {
    move |e| err("IO_ERROR", format!("{what} {}: {e}", path.display()))
}

fn gen_err(e: GenError) -> InstallError {
    match e {
        GenError::Refused(m) => err("CATALOG_UNTRUSTED", m),
        GenError::Policy(m) => err("CATALOG_POLICY", m),
        GenError::RecoveryRequired(m) => err("CATALOG_RECOVERY_REQUIRED", m),
        GenError::Crash(s) => err("CRASH_INJECTED", format!("{s:?}")),
        GenError::Io(m) => err("IO_ERROR", m),
    }
}

pub type Result<T> = std::result::Result<T, InstallError>;

/// Where machine-level catalog and package state lives.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `<data>`: `catalogs/<name>/`, `run/install/`, `extensions/pins.json`.
    pub data: PathBuf,
    /// The runtime's extension directory: packages at `<id>/<artifact-sha256>/`.
    pub extension_dir: PathBuf,
}

impl Paths {
    fn catalog_dir(&self, name: &str) -> PathBuf {
        self.data.join("catalogs").join(name)
    }
    fn journals(&self) -> PathBuf {
        self.data.join("run/install")
    }
    fn pins(&self) -> PathBuf {
        self.data.join("extensions/pins.json")
    }
}

/// How CIC sessions run during validation: always supervised in production; in-process only
/// for tests of this module.
#[derive(Debug, Clone)]
pub enum CicRunner {
    Supervised(PathBuf),
    InProcess,
}

/// The key of native builds in `package.json`: this build's exact target triple.
pub fn platform() -> &'static str {
    calve_integration_contract::catalog::HOST_TARGET
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Extension ids: lowercase dotted segments of `[a-z0-9-]` (safe as one path segment).
pub fn valid_id(id: &str) -> bool {
    id.len() <= 128
        && id.split('.').count() >= 2
        && id.split('.').all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn valid_file(name: &str) -> bool {
    crate::workspace_io::validate_locator(name).is_ok() && !name.contains('/')
}

fn write_json(path: &Path, v: &impl Serialize) -> Result<()> {
    use std::io::Write;
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(io)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", uuid::Uuid::now_v7().simple()));
    let mut f = fs::File::create(&tmp).map_err(io_at("create", &tmp))?;
    f.write_all(&serde_json::to_vec_pretty(v).map_err(io)?)
        .and_then(|()| f.sync_all())
        .map_err(io_at("write", &tmp))?;
    drop(f);
    crate::workspace_io::rename_durable(&tmp, path).map_err(io_at("rename into", path))
}

fn read_json<T: for<'a> Deserialize<'a> + Default>(path: &Path) -> Result<T> {
    match fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map_err(io),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(io(e)),
    }
}

// ------------------------------------------------------------------------------------ catalogs

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogSource {
    pub name: String,
    /// `https://…` (or `http://` for local test servers) or a local directory with
    /// `metadata/` and `targets/`.
    pub url: String,
    pub root_digest: String,
}

impl CatalogSource {
    pub fn mirror(&self) -> Mirror {
        if self.url.starts_with("https://") || self.url.starts_with("http://") {
            let base = self.url.trim_end_matches('/');
            Mirror::http(
                &format!("{base}/metadata"),
                &format!("{base}/targets"),
                super::tuf::DEFAULT_TIMEOUT,
            )
        } else {
            Mirror::dir(Path::new(&self.url))
        }
    }
}

/// Trusts a catalog: the root is pinned by its SHA-256 (`REPO_ID`) and the first refresh is
/// accepted by the verifier before anything is stored as trusted.
pub fn add_catalog(
    paths: &Paths,
    name: &str,
    url: &str,
    root: &[u8],
    root_digest: &str,
) -> Result<Value> {
    if !valid_name(name) {
        return Err(err(
            "INVALID_INPUT",
            "catalog names are [a-z0-9-], at most 64 characters",
        ));
    }
    let dir = paths.catalog_dir(name);
    if dir.join("REPO_ID").exists() {
        return Err(err(
            "ALREADY_EXISTS",
            format!("catalog {name} is already trusted"),
        ));
    }
    let src = CatalogSource {
        name: name.into(),
        url: url.into(),
        root_digest: root_digest.into(),
    };
    let c = Catalog::bootstrap(&dir, root, root_digest, &src.mirror()).map_err(gen_err)?;
    write_json(&dir.join("source.json"), &src)?;
    Ok(
        json!({"name": name, "url": url, "root_digest": root_digest, "generation": c.active, "root_version": c.versions.root}),
    )
}

pub fn catalog_names(paths: &Paths) -> Result<Vec<String>> {
    let mut names = vec![];
    if let Ok(rd) = fs::read_dir(paths.data.join("catalogs")) {
        for e in rd {
            let e = e.map_err(io)?;
            if e.path().join("source.json").is_file() {
                names.push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    names.sort();
    Ok(names)
}

fn source(paths: &Paths, name: &str) -> Result<CatalogSource> {
    let p = paths.catalog_dir(name).join("source.json");
    let b = fs::read(&p).map_err(|_| err("NOT_FOUND", format!("catalog {name} is not trusted")))?;
    serde_json::from_slice(&b).map_err(io)
}

pub fn open_catalog(paths: &Paths, name: &str) -> Result<(Catalog, CatalogSource)> {
    let src = source(paths, name)?;
    Ok((
        Catalog::open(&paths.catalog_dir(name)).map_err(gen_err)?,
        src,
    ))
}

/// Freshness of the last accepted state (§9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Fresh,
    /// Older than the refresh interval but within `revocation_max_age`.
    Stale,
    /// Older than `revocation_max_age`.
    Expired,
}

pub fn freshness(accepted_at: Option<jiff::Timestamp>, max_age: std::time::Duration) -> Freshness {
    let Some(at) = accepted_at else {
        return Freshness::Expired;
    };
    let age = jiff::Timestamp::now().duration_since(at);
    if age < jiff::SignedDuration::from_hours(1) {
        Freshness::Fresh
    } else if age.as_secs() as u64 <= max_age.as_secs() {
        Freshness::Stale
    } else {
        Freshness::Expired
    }
}

pub fn refresh_catalog(paths: &Paths, name: &str) -> Result<Value> {
    let (mut c, src) = open_catalog(paths, name)?;
    let v = c.refresh(&src.mirror(), None).map_err(gen_err)?;
    Ok(
        json!({"name": name, "generation": c.active, "root": v.root, "timestamp": v.timestamp, "snapshot": v.snapshot, "targets": v.targets}),
    )
}

/// Audited privileged reset (§9.3): bootstraps from a new pinned root; the old state is
/// archived and the reset logged. Never automatic.
pub fn reset_catalog(paths: &Paths, name: &str, root: &[u8], root_digest: &str) -> Result<Value> {
    let mut src = source(paths, name)?;
    let dir = paths.catalog_dir(name);
    let old = src.root_digest.clone();
    let c = Catalog::reset(&dir, root, root_digest, &src.mirror()).map_err(gen_err)?;
    src.root_digest = root_digest.into();
    write_json(&dir.join("source.json"), &src)?;
    Ok(
        json!({"name": name, "previous_root_digest": old, "root_digest": root_digest, "generation": c.active}),
    )
}

// ------------------------------------------------------------------------------- package model

pub use calve_integration_contract::catalog::{Kind, NativeBuild, PackageIndex, VersionEntry};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Revocations {
    #[serde(default)]
    revoked: Vec<Revocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Revocation {
    id: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    digest: Option<String>,
    reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IdPolicy {
    #[serde(default)]
    roles: BTreeMap<String, Vec<String>>,
}

/// Cross-catalog publisher pins: `id → (catalog, role)` fixed at first install (§9.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pin {
    pub catalog: String,
    pub role: String,
}

/// The installed record, `package.json` inside the immutable package directory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageRecord {
    pub id: String,
    pub version: String,
    pub kind: Kind,
    pub catalog: String,
    pub role: String,
    /// The exact target triple the native build was selected for.
    pub target: String,
    /// sha256 of each file by role (`native`, `cic`, `metadata`, `ui`), each equal to its TUF
    /// target hash.
    pub digests: BTreeMap<String, String>,
    /// Native artifact path relative to the extension directory (`<id>/<sha256>/<file>`).
    pub entrypoint: String,
    pub manifest: openaevc::protocol::ExtensionManifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui: Option<Value>,
    /// The T2 acknowledgment ("runs as native code with your user permissions") given at
    /// install, recorded with the package.
    pub native_acknowledged: bool,
    pub installed_at: String,
}

impl PackageRecord {
    pub fn native_digest(&self) -> &str {
        &self.digests["native"]
    }
}

/// Every installed package (records of complete package directories).
pub fn installed(paths: &Paths) -> Result<Vec<PackageRecord>> {
    let mut out = vec![];
    let Ok(ids) = fs::read_dir(&paths.extension_dir) else {
        return Ok(out);
    };
    for id in ids {
        let id = id.map_err(io)?;
        if id.file_name().to_string_lossy().starts_with('.') || !id.path().is_dir() {
            continue;
        }
        for pkg in fs::read_dir(id.path()).map_err(io)? {
            let rec = pkg.map_err(io)?.path().join("package.json");
            if let Ok(b) = fs::read(&rec) {
                out.push(serde_json::from_slice(&b).map_err(io)?);
            }
        }
    }
    out.sort_by(|a: &PackageRecord, b| {
        (&a.id, version_key(&a.version)).cmp(&(&b.id, version_key(&b.version)))
    });
    Ok(out)
}

pub fn version_key(v: &str) -> Vec<(u64, String)> {
    v.split(['.', '-', '+'])
        .map(|p| (p.parse().unwrap_or(0), p.to_owned()))
        .collect()
}

/// Re-hashes every file of an installed package against its record (OpenAEVC re-hashes the
/// native artifact per spawn too, F4).
pub fn verify_installed(paths: &Paths, r: &PackageRecord) -> Result<()> {
    if r.target != platform() {
        return Err(err(
            "EXTENSION_INCOMPATIBLE",
            format!(
                "{}@{} is the {} build, not {}",
                r.id,
                r.version,
                r.target,
                platform()
            ),
        ));
    }
    let dir = paths.extension_dir.join(&r.id).join(r.native_digest());
    for (role, digest) in &r.digests {
        let name = match role.as_str() {
            "native" => r
                .entrypoint
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_owned(),
            "cic" => "cic.wasm".into(),
            "metadata" => "calve-integration.json".into(),
            "ui" => "calve-ui.json".into(),
            "refs" => "calve-refs.json".into(),
            _ => return Err(err("PACKAGE_INVALID", format!("unknown file role {role}"))),
        };
        let bytes = fs::read(dir.join(&name))
            .map_err(|e| err("PACKAGE_TAMPERED", format!("{name}: {e}")))?;
        if &sha(&bytes) != digest {
            return Err(err(
                "PACKAGE_TAMPERED",
                format!(
                    "{}/{}: {name} differs from the installed digest",
                    r.id, r.version
                ),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------- installing

#[derive(Debug, Clone)]
pub struct InstallRequest<'a> {
    pub id: &'a str,
    pub version: Option<&'a str>,
    /// Restrict to one catalog (required when several offer the id and none is pinned).
    pub catalog: Option<&'a str>,
    /// The T2 acknowledgment; native code never runs without it.
    pub acknowledge_native: bool,
    /// Confirmed `switch-publisher`: replaces an existing pin for this id.
    pub switch_publisher: bool,
}

/// Fault points of the install journal (tests): the process "crashes" right after recording
/// the step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallStep {
    Resolved,
    Downloaded,
    Validated,
    Installed,
    Recorded,
    /// Retirement: after R0 (marked retiring, before the in-use re-check).
    Retiring,
}

pub struct Installer {
    pub paths: Paths,
    pub cic: CicRunner,
    /// Faults for crash tests.
    pub fault: Option<InstallStep>,
}

struct Staged {
    staging: PathBuf,
    record: PackageRecord,
}

impl Installer {
    pub fn new(paths: Paths, cic: CicRunner) -> Self {
        Installer {
            paths,
            cic,
            fault: None,
        }
    }

    fn crash(&self, s: InstallStep) -> Result<()> {
        if self.fault == Some(s) {
            Err(err("CRASH_INJECTED", format!("{s:?}")))
        } else {
            Ok(())
        }
    }

    fn pins(&self) -> Result<BTreeMap<String, Pin>> {
        read_json(&self.paths.pins())
    }

    /// Chooses the catalog for `id`: its pin, else the requested catalog, else the only
    /// trusted catalog that lists `<id>/package.json`.
    fn choose_catalog(&self, req: &InstallRequest) -> Result<String> {
        if let Some(pin) = self.pins()?.get(req.id)
            && !req.switch_publisher
        {
            if req.catalog.is_some_and(|c| c != pin.catalog) {
                return Err(err(
                    "PUBLISHER_NOT_AUTHORIZED",
                    format!(
                        "{} is pinned to catalog {}; confirm `extension switch-publisher` to change it",
                        req.id, pin.catalog
                    ),
                ));
            }
            return Ok(pin.catalog.clone());
        }
        if let Some(c) = req.catalog {
            return Ok(c.to_owned());
        }
        let mut offering = vec![];
        for name in catalog_names(&self.paths)? {
            let (mut c, src) = open_catalog(&self.paths, &name)?;
            if c.resolve(&src.mirror(), &format!("{}/package.json", req.id), None)
                .map_err(gen_err)?
                .is_some()
            {
                offering.push(name);
            }
        }
        match offering.len() {
            0 => Err(err(
                "NOT_FOUND",
                format!("no trusted catalog offers {}", req.id),
            )),
            1 => Ok(offering.remove(0)),
            _ => Err(err(
                "AMBIGUOUS",
                format!(
                    "{} is offered by catalogs {offering:?}; choose one with --catalog",
                    req.id
                ),
            )),
        }
    }

    /// Installs (I0–I4). Returns the record; an identical package already installed is
    /// returned unchanged (idempotent).
    pub fn install(&self, req: &InstallRequest) -> Result<PackageRecord> {
        if !valid_id(req.id) {
            return Err(err(
                "INVALID_INPUT",
                format!("invalid extension id {:?}", req.id),
            ));
        }
        let catalog = self.choose_catalog(req)?;
        fs::create_dir_all(self.paths.journals()).map_err(io)?;
        let jid = uuid::Uuid::now_v7().simple().to_string();
        let jpath = self.paths.journals().join(format!("{jid}.journal"));
        let mut j = Journal::create(
            &jpath,
            "install",
            &jid,
            json!({"id": req.id, "catalog": catalog}),
        )
        .map_err(io)?;
        let staged = match self.stage(&mut j, req, &catalog) {
            Ok(s) => s,
            Err(e) => {
                if e.code != "CRASH_INJECTED" {
                    let _ = j.append("failed", json!({"code": e.code, "message": e.message}));
                    let _ = crate::journal::compact(
                        &jpath,
                        &self.paths.journals().join("history"),
                        "failed",
                        json!({"code": e.code}),
                    );
                }
                return Err(e);
            }
        };
        self.finish(&mut j, &jpath, staged, req.switch_publisher)
    }

    /// I0–I2: resolve, download (verified), stage and validate.
    fn stage(&self, j: &mut Journal, req: &InstallRequest, catalog: &str) -> Result<Staged> {
        let (mut c, src) = open_catalog(&self.paths, catalog)?;
        let mirror = src.mirror();
        // I0: the package index and the catalog-level documents, from one accepted state.
        let index_path = format!("{}/package.json", req.id);
        let docs = c
            .fetch_all(
                &mirror,
                &[&index_path, "revocations.json", "id-policy.json"],
                None,
            )
            .map_err(gen_err)?;
        let (index_info, index_bytes) = docs[0].clone().ok_or_else(|| {
            err(
                "NOT_FOUND",
                format!("catalog {catalog} does not offer {}", req.id),
            )
        })?;
        let index: PackageIndex = serde_json::from_slice(&index_bytes)
            .map_err(|e| err("PACKAGE_INVALID", format!("package.json: {e}")))?;
        if index.schema != calve_integration_contract::catalog::PACKAGE_SCHEMA || index.id != req.id
        {
            return Err(err("PACKAGE_INVALID", "package.json schema or id mismatch"));
        }
        let revocations: Revocations = match &docs[1] {
            Some((i, b)) if i.role == "targets" => serde_json::from_slice(b)
                .map_err(|e| err("CATALOG_POLICY", format!("revocations.json: {e}")))?,
            Some((i, _)) => {
                return Err(err(
                    "CATALOG_POLICY",
                    format!(
                        "revocations.json signed by {}, not the top-level targets role",
                        i.role
                    ),
                ));
            }
            None => Revocations::default(),
        };
        let policy: IdPolicy = match &docs[2] {
            Some((i, b)) if i.role == "targets" => serde_json::from_slice(b)
                .map_err(|e| err("CATALOG_POLICY", format!("id-policy.json: {e}")))?,
            Some((i, _)) => {
                return Err(err(
                    "CATALOG_POLICY",
                    format!(
                        "id-policy.json signed by {}, not the top-level targets role",
                        i.role
                    ),
                ));
            }
            None => IdPolicy::default(),
        };
        let entry = match req.version {
            Some(v) => index.versions.iter().find(|e| e.version == v),
            None => index
                .versions
                .iter()
                .max_by_key(|e| version_key(&e.version)),
        }
        .ok_or_else(|| {
            err(
                "NOT_FOUND",
                format!("{} has no version {}", req.id, req.version.unwrap_or("?")),
            )
        })?
        .clone();
        let build = entry
            .native
            .get(platform())
            .ok_or_else(|| {
                err(
                    "EXTENSION_INCOMPATIBLE",
                    format!(
                        "{}@{} has no build for {}",
                        req.id,
                        entry.version,
                        platform()
                    ),
                )
            })?
            .clone();
        if !calve_integration_contract::catalog::valid_sha256(&build.sha256) {
            return Err(err(
                "PACKAGE_INVALID",
                "native build sha256 is not lowercase hex",
            ));
        }
        let native = build.file.clone();
        let mut files: Vec<(&str, String)> = vec![("native", native.clone())];
        match entry.kind {
            Kind::CicCapable => {
                let (Some(cic), Some(meta)) = (&entry.cic, &entry.metadata) else {
                    return Err(err(
                        "PACKAGE_INVALID",
                        "a cic-capable package needs cic.wasm and calve-integration.json",
                    ));
                };
                files.push(("cic", cic.clone()));
                files.push(("metadata", meta.clone()));
            }
            Kind::OpenaevcOnly if entry.cic.is_some() => {
                return Err(err(
                    "PACKAGE_INVALID",
                    "cic.wasm without metadata (openaevc-only package)",
                ));
            }
            Kind::OpenaevcOnly => {}
        }
        if let Some(ui) = &entry.ui {
            files.push(("ui", ui.clone()));
        }
        if let Some(refs) = &entry.refs {
            files.push(("refs", refs.clone()));
        }
        if files.iter().any(|(_, f)| !valid_file(f)) {
            return Err(err(
                "PACKAGE_INVALID",
                "package file names must be single safe path segments",
            ));
        }
        // Publisher identity (§9.4): the role that signed the index must be authorized for the id.
        let role = index_info.role.clone();
        if role != "targets" {
            let allowed = policy.roles.get(&role).ok_or_else(|| {
                err(
                    "PUBLISHER_NOT_AUTHORIZED",
                    format!("role {role} has no id policy in catalog {catalog}"),
                )
            })?;
            if !allowed.iter().any(|p| req.id.starts_with(p.as_str())) {
                return Err(err(
                    "PUBLISHER_NOT_AUTHORIZED",
                    format!("role {role} may publish {allowed:?}, not {}", req.id),
                ));
            }
        }
        if let Some(pin) = self.pins()?.get(req.id)
            && !req.switch_publisher
            && (pin.catalog != catalog || pin.role != role)
        {
            return Err(err(
                "PUBLISHER_NOT_AUTHORIZED",
                format!(
                    "{} is pinned to {}:{}; offered by {catalog}:{role}",
                    req.id, pin.catalog, pin.role
                ),
            ));
        }
        j.append("I0.resolved", json!({"version": entry.version, "kind": entry.kind, "files": files.iter().map(|(r, f)| json!([r, f])).collect::<Vec<_>>(), "role": role}))
            .map_err(|e| err("IO_ERROR", format!("install journal: {e}")))?;
        self.crash(InstallStep::Resolved)?;

        // I1: download every file in one transition (same accepted state), size-capped and
        // verified by the verifier; all must be signed by the index's role.
        let paths: Vec<String> = files
            .iter()
            .map(|(r, f)| match *r {
                "native" => calve_integration_contract::catalog::native_path(
                    req.id,
                    &entry.version,
                    platform(),
                    f,
                ),
                _ => format!("{}/{}/{f}", req.id, entry.version),
            })
            .collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let fetched = c.fetch_all(&mirror, &refs, None).map_err(gen_err)?;
        let staging = self.paths.extension_dir.join(format!(
            ".staging-{}",
            j.header["journal_id"].as_str().unwrap_or("x")
        ));
        fs::create_dir_all(&staging).map_err(io_at("create", &staging))?;
        let mut digests = BTreeMap::new();
        let mut bytes_by_role: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
        for ((role_name, file), got) in files.iter().zip(fetched) {
            let (info, bytes): (TargetInfo, Vec<u8>) = got.ok_or_else(|| {
                err(
                    "PACKAGE_INVALID",
                    format!("{file} is not a target of {}@{}", req.id, entry.version),
                )
            })?;
            if info.role != role {
                return Err(err(
                    "PUBLISHER_NOT_AUTHORIZED",
                    format!(
                        "{file} is signed by {}, the package index by {role}",
                        info.role
                    ),
                ));
            }
            if *role_name == "native" && info.sha256 != build.sha256 {
                return Err(err(
                    "PACKAGE_INVALID",
                    format!(
                        "{}@{} {}: the target hash differs from the package index's native digest",
                        req.id,
                        entry.version,
                        platform()
                    ),
                ));
            }
            for r in &revocations.revoked {
                let hit = r.id == req.id
                    && (r.version.as_deref().is_none_or(|v| v == entry.version)
                        && r.digest.as_deref().is_none_or(|d| d == info.sha256));
                if hit {
                    return Err(err(
                        "EXTENSION_REVOKED",
                        format!("{}@{}: {}", req.id, entry.version, r.reason),
                    ));
                }
            }
            let local = match *role_name {
                "native" => native.clone(),
                "cic" => "cic.wasm".into(),
                "metadata" => "calve-integration.json".into(),
                "refs" => "calve-refs.json".into(),
                _ => "calve-ui.json".into(),
            };
            let to = staging.join(&local);
            fs::write(&to, &bytes).map_err(io_at("write", &to))?;
            digests.insert(role_name.to_string(), info.sha256.clone());
            bytes_by_role.insert(role_name, bytes);
        }
        j.append("I1.downloaded", json!({"staging": staging.file_name().map(|n| n.to_string_lossy()), "digests": digests}))
            .map_err(|e| err("IO_ERROR", format!("install journal: {e}")))?;
        self.crash(InstallStep::Downloaded)?;

        // I2: validation — kind rules, metadata, module, describe == signed metadata, then (with
        // the T2 acknowledgment) the native handshake.
        let mut metadata = None;
        if entry.kind == Kind::CicCapable {
            let meta_bytes = &bytes_by_role["metadata"];
            let meta: Metadata = serde_json::from_slice(meta_bytes)
                .map_err(|e| err("PACKAGE_INVALID", format!("calve-integration.json: {e}")))?;
            meta.validate().map_err(|e| err("PACKAGE_INVALID", e))?;
            if !crate::integration::HOST_SCHEMAS.contains(&meta.schema_number().unwrap_or(0)) {
                return Err(err(
                    "PACKAGE_INVALID",
                    format!("unsupported metadata schema {}", meta.schema),
                ));
            }
            if meta.extension_id != req.id || meta.version != entry.version {
                return Err(err(
                    "PACKAGE_INVALID",
                    "metadata id/version differ from the package",
                ));
            }
            if let Some(c) = meta
                .capabilities
                .required
                .iter()
                .find(|c| !crate::integration::HOST_CAPABILITIES.contains(&c.as_str()))
            {
                return Err(err(
                    "INCOMPATIBLE_CIC",
                    format!("required capability {c} is not supported by this host"),
                ));
            }
            let wasm = &bytes_by_role["cic"];
            validate_module(wasm, &HostConfig::default())
                .map_err(|e| err("PACKAGE_INVALID", format!("cic.wasm: {e}")))?;
            self.describe_matches(&staging.join("cic.wasm"), wasm, &meta)?;
            metadata = Some(meta);
        }
        let ui = match bytes_by_role.get("ui") {
            Some(b) => Some(
                serde_json::from_slice::<Value>(b)
                    .map_err(|e| err("PACKAGE_INVALID", format!("calve-ui.json: {e}")))?,
            ),
            None => None,
        };
        if !req.acknowledge_native {
            return Err(err(
                "T2_ACKNOWLEDGMENT_REQUIRED",
                format!(
                    "{}@{} runs as native code with your user permissions (not confined); install again with the acknowledgment",
                    req.id, entry.version
                ),
            ));
        }
        let native_path = staging.join(&native);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&native_path, fs::Permissions::from_mode(0o700)).map_err(io)?;
        }
        let (manifest, _) = openaevc::extension::host::handshake(
            &openaevc::extension::host::Entrypoint {
                program: native_path.clone(),
                args: vec![],
            },
            &openaevc::extension::host::HostLimits {
                deadline: std::time::Duration::from_secs(60),
                ..openaevc::extension::host::HostLimits::default()
            },
        )
        .map_err(|e| err("PACKAGE_INVALID", format!("native handshake failed: {e:?}")))?;
        if manifest.artifact_digest.hex() != digests["native"] {
            return Err(err(
                "PACKAGE_INVALID",
                "native artifact reports a different digest than its bytes",
            ));
        }
        // §13: the reference schema the manifest binds by content hash travels with the package.
        let declared = manifest
            .schemas
            .get(calve_integration_contract::refs::SCHEMA);
        match (declared, bytes_by_role.get("refs")) {
            (None, None) => {}
            (Some(h), Some(b)) => {
                if openaevc::crypto::sha256(b) != *h {
                    return Err(err(
                        "PACKAGE_INVALID",
                        "calve-refs.json does not match the manifest's calve.refs/1 hash",
                    ));
                }
                let doc: Value = serde_json::from_slice(b)
                    .map_err(|e| err("PACKAGE_INVALID", format!("calve-refs.json: {e}")))?;
                calve_integration_contract::refs::parse(&doc)
                    .map_err(|e| err("PACKAGE_INVALID", e))?;
            }
            (Some(_), None) => {
                return Err(err(
                    "PACKAGE_INVALID",
                    "the manifest declares calve.refs/1 but the package ships no calve-refs.json",
                ));
            }
            (None, Some(_)) => {
                return Err(err(
                    "PACKAGE_INVALID",
                    "calve-refs.json is not bound by the manifest (schemas[\"calve.refs/1\"])",
                ));
            }
        }
        if manifest.id != req.id || manifest.version != entry.version {
            return Err(err(
                "PACKAGE_INVALID",
                format!(
                    "native artifact is {}@{}, package {}@{}",
                    manifest.id, manifest.version, req.id, entry.version
                ),
            ));
        }
        crate::compatibility::check_range(
            "extension contract",
            &openaevc::protocol::SUPPORTED_CONTRACT,
            &manifest.contract,
        )
        .map_err(|e| err("EXTENSION_INCOMPATIBLE", e.to_string()))?;
        let record = PackageRecord {
            id: req.id.into(),
            version: entry.version.clone(),
            kind: entry.kind.clone(),
            catalog: catalog.into(),
            role: role.clone(),
            target: platform().into(),
            entrypoint: format!("{}/{}/{native}", req.id, digests["native"]),
            digests,
            manifest,
            metadata,
            ui,
            native_acknowledged: true,
            installed_at: jiff::Timestamp::now().to_string(),
        };
        write_json(&staging.join("package.json"), &record)?;
        j.append("I2.validated", json!({"entrypoint": record.entrypoint}))
            .map_err(|e| err("IO_ERROR", format!("install journal: {e}")))?;
        self.crash(InstallStep::Validated)?;
        Ok(Staged { staging, record })
    }

    /// `describe` over a fresh session equals the signed metadata (canonical compare, §8).
    fn describe_matches(&self, path: &Path, wasm: &[u8], meta: &Metadata) -> Result<()> {
        let cfg = HostConfig::default();
        let driver: Box<dyn Driver> = match &self.cic {
            CicRunner::Supervised(program) => Box::new(
                SandboxDriver::spawn(program, path, &sha(wasm), &cfg)
                    .map_err(|e| err("PACKAGE_INVALID", e.to_string()))?,
            ),
            CicRunner::InProcess => Box::new(
                CalveHost::new(wasm, cfg).map_err(|e| err("PACKAGE_INVALID", e.to_string()))?,
            ),
        };
        let mut s =
            Session::open(driver, &crate::integration::host_hello(), meta).map_err(|e| {
                err(
                    if e.code() == "INCOMPATIBLE_CIC" {
                        "INCOMPATIBLE_CIC"
                    } else {
                        "PACKAGE_INVALID"
                    },
                    format!("cic hello: {e}"),
                )
            })?;
        let described = s
            .request("describe", json!({}))
            .map_err(|e| err("PACKAGE_INVALID", format!("describe: {e}")))?;
        let signed = serde_json::to_value(meta).map_err(io)?;
        let canon = |v: &Value| {
            calve_integration_contract::jcs::to_vec(v)
                .map_err(|_| err("PACKAGE_INVALID", "metadata is not integer-only JSON"))
        };
        if canon(&described)? != canon(&signed)? {
            return Err(err(
                "PACKAGE_INVALID",
                "describe differs from the signed calve-integration.json",
            ));
        }
        Ok(())
    }

    /// I3–I4: rename to the immutable digest path, make it read-only, record the pin.
    fn finish(
        &self,
        j: &mut Journal,
        jpath: &Path,
        staged: Staged,
        switch: bool,
    ) -> Result<PackageRecord> {
        let Staged { staging, record } = staged;
        let final_dir = self
            .paths
            .extension_dir
            .join(&record.id)
            .join(record.native_digest());
        fs::create_dir_all(final_dir.parent().expect("id dir")).map_err(io)?;
        // The reference schema outlives the package (retirement removes the directory, history
        // stays walkable): content-addressed, written once.
        let staged_refs = staging.join("calve-refs.json");
        if staged_refs.is_file() {
            refs_put(&self.paths, &fs::read(&staged_refs).map_err(io)?)?;
        }
        if final_dir.join("package.json").is_file() {
            // Already installed with the same digests? Keep the existing directory.
            let existing: PackageRecord =
                serde_json::from_slice(&fs::read(final_dir.join("package.json")).map_err(io)?)
                    .map_err(io)?;
            if existing.digests == record.digests
                && verify_installed(&self.paths, &existing).is_ok()
            {
                remove_tree(&staging)?;
            } else {
                return Err(err(
                    "PACKAGE_TAMPERED",
                    format!(
                        "{} exists with different content; remove it with `extension uninstall`",
                        final_dir.display()
                    ),
                ));
            }
        } else {
            // Read-only only after the move: renaming a directory to a new parent updates its
            // `..` entry, which needs write permission on the directory itself.
            rename_staged(&staging, &final_dir).map_err(|e| {
                let base = io_at("rename staging to", &final_dir)(e);
                err(
                    base.code,
                    format!("{}{}", base.message, holders_note(&staging)),
                )
            })?;
            set_read_only(&final_dir, true)?;
        }
        j.append(
            "I3.installed",
            json!({"dir": format!("{}/{}", record.id, record.native_digest())}),
        )
        .map_err(|e| err("IO_ERROR", format!("install journal: {e}")))?;
        self.crash(InstallStep::Installed)?;
        let mut pins = self.pins()?;
        let pin = Pin {
            catalog: record.catalog.clone(),
            role: record.role.clone(),
        };
        let previous = pins.get(&record.id).cloned();
        if previous.as_ref() != Some(&pin) && (previous.is_none() || switch) {
            pins.insert(record.id.clone(), pin);
            write_json(&self.paths.pins(), &pins)?;
        }
        j.append(
            "I4.recorded",
            json!({"pin": pins.get(&record.id), "switched": switch && previous.is_some()}),
        )
        .map_err(|e| err("IO_ERROR", format!("install journal: {e}")))?;
        self.crash(InstallStep::Recorded)?;
        crate::journal::compact(
            jpath,
            &self.paths.journals().join("history"),
            "installed",
            json!({"id": record.id, "version": record.version, "native": record.native_digest()}),
        )
        .map_err(io)?;
        crate::observe::record(
            "extension.install",
            json!({"id": record.id, "version": record.version, "digest": record.native_digest(), "catalog": record.catalog, "role": record.role}),
        );
        Ok(record)
    }

    /// Crash reconciliation for every unfinished install journal (§9.4 table): before I3 the
    /// staging directory is removed (the user reruns the install); at I3 a verifying final
    /// directory completes I4; I4 compacts. Returns one line per journal handled.
    pub fn recover(&self) -> Result<Vec<Value>> {
        let mut done = vec![];
        let Ok(rd) = fs::read_dir(self.paths.journals()) else {
            return Ok(done);
        };
        for e in rd {
            let p = e.map_err(io)?.path();
            if p.extension().and_then(|s| s.to_str()) == Some("retire") {
                done.push(self.recover_retire(&p)?);
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) != Some("journal") {
                continue;
            }
            let opened = Journal::open(&p).map_err(io)?;
            let jid = opened.journal.header["journal_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let last = opened
                .records
                .last()
                .map(|r| r.kind.clone())
                .unwrap_or_default();
            let staging = self.paths.extension_dir.join(format!(".staging-{jid}"));
            let outcome = match last.as_str() {
                "I3.installed" | "I4.recorded" => {
                    let rel = opened
                        .records
                        .iter()
                        .find(|r| r.kind == "I3.installed")
                        .and_then(|r| r.body["dir"].as_str().map(str::to_owned))
                        .unwrap_or_default();
                    let rec: Option<PackageRecord> =
                        fs::read(self.paths.extension_dir.join(&rel).join("package.json"))
                            .ok()
                            .and_then(|b| serde_json::from_slice(&b).ok());
                    match rec {
                        Some(r) if verify_installed(&self.paths, &r).is_ok() => {
                            let mut pins = self.pins()?;
                            pins.entry(r.id.clone()).or_insert(Pin {
                                catalog: r.catalog.clone(),
                                role: r.role.clone(),
                            });
                            write_json(&self.paths.pins(), &pins)?;
                            "installed"
                        }
                        _ => "abandoned",
                    }
                }
                _ => "abandoned",
            };
            if staging.exists() {
                remove_tree(&staging)?;
            }
            crate::journal::compact(
                &p,
                &self.paths.journals().join("history"),
                outcome,
                json!({"last": last}),
            )
            .map_err(io)?;
            done.push(json!({"journal": jid, "last_step": last, "outcome": outcome}));
        }
        Ok(done)
    }

    /// Retirement crash reconciliation: before the in-use re-check (R0) the package is restored;
    /// after it (R1) the deletion completes.
    fn recover_retire(&self, p: &Path) -> Result<Value> {
        let opened = Journal::open(p).map_err(io)?;
        let jid = opened.journal.header["journal_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let b = &opened.journal.header["binding"];
        let dir = self
            .paths
            .extension_dir
            .join(b["id"].as_str().unwrap_or("_"))
            .join(b["native"].as_str().unwrap_or("_"));
        let retiring = self.paths.extension_dir.join(format!(".retiring-{jid}"));
        let last = opened
            .records
            .last()
            .map(|r| r.kind.clone())
            .unwrap_or_default();
        let outcome = match last.as_str() {
            "R1.rechecked" | "R2.deleted" => {
                remove_tree(&retiring)?;
                "retired"
            }
            _ => {
                if retiring.exists() && !dir.exists() {
                    fs::rename(&retiring, &dir).map_err(io)?;
                    set_read_only(&dir, true)?;
                }
                "restored"
            }
        };
        crate::journal::compact(
            p,
            &self.paths.journals().join("history"),
            outcome,
            json!({"last": last}),
        )
        .map_err(io)?;
        Ok(json!({"journal": jid, "last_step": last, "outcome": outcome}))
    }

    /// Retirement (R0–R2): an installed version is deleted only when `in_use` says no
    /// namespace has it registered and no non-terminal work references it — checked before
    /// and again after marking it retiring.
    pub fn retire(&self, r: &PackageRecord, in_use: impl Fn(&PackageRecord) -> bool) -> Result<()> {
        if in_use(r) {
            return Err(err(
                "EXTENSION_IN_USE",
                format!(
                    "{}@{} is registered or used by active work",
                    r.id, r.version
                ),
            ));
        }
        let dir = self.paths.extension_dir.join(&r.id).join(r.native_digest());
        fs::create_dir_all(self.paths.journals()).map_err(io)?;
        let jid = uuid::Uuid::now_v7().simple().to_string();
        let jpath = self.paths.journals().join(format!("{jid}.retire"));
        let mut j = Journal::create(
            &jpath,
            "retire",
            &jid,
            json!({"id": r.id, "native": r.native_digest()}),
        )
        .map_err(io)?;
        let retiring = self.paths.extension_dir.join(format!(".retiring-{jid}"));
        set_read_only(&dir, false)?;
        fs::rename(&dir, &retiring).map_err(io)?;
        j.append("R0.retiring", json!({}))
            .map_err(|e| err("IO_ERROR", format!("install journal: {e}")))?;
        self.crash(InstallStep::Retiring)?;
        if in_use(r) {
            fs::rename(&retiring, &dir).map_err(io)?;
            set_read_only(&dir, true)?;
            j.append("R1.restored", json!({"reason": "in use"}))
                .map_err(|e| err("IO_ERROR", format!("install journal: {e}")))?;
            return Err(err(
                "EXTENSION_IN_USE",
                format!("{}@{} became in use during retirement", r.id, r.version),
            ));
        }
        j.append("R1.rechecked", json!({}))
            .map_err(|e| err("IO_ERROR", format!("install journal: {e}")))?;
        remove_tree(&retiring)?;
        j.append("R2.deleted", json!({}))
            .map_err(|e| err("IO_ERROR", format!("install journal: {e}")))?;
        crate::journal::compact(
            &jpath,
            &self.paths.journals().join("history"),
            "retired",
            json!({"id": r.id, "version": r.version}),
        )
        .map_err(io)?;
        Ok(())
    }
}

/// The machine's content-addressed store of `calve.refs/1` documents (`<data>/refs/<hex>.json`).
pub fn refs_dir(paths: &Paths) -> PathBuf {
    paths.data.join("refs")
}

/// Stores a refs document by its SHA-256 (idempotent; existing content is re-verified).
pub fn refs_put(paths: &Paths, bytes: &[u8]) -> Result<String> {
    let hex = sha(bytes);
    let dir = refs_dir(paths);
    fs::create_dir_all(&dir).map_err(io)?;
    let path = dir.join(format!("{hex}.json"));
    if path.is_file() && sha(&fs::read(&path).map_err(io)?) == hex {
        return Ok(hex);
    }
    let tmp = dir.join(format!(".{hex}.tmp"));
    fs::write(&tmp, bytes).map_err(io)?;
    crate::journal::sync_file(&tmp).map_err(io)?;
    fs::rename(&tmp, &path).map_err(io)?;
    Ok(hex)
}

/// A refs document by content hash (`sha256:<hex>` or `<hex>`), verified.
pub fn refs_get(paths: &Paths, hash: &str) -> Result<Option<Vec<u8>>> {
    let hex = hash.trim_start_matches("sha256:");
    match fs::read(refs_dir(paths).join(format!("{hex}.json"))) {
        Ok(b) if sha(&b) == hex => Ok(Some(b)),
        Ok(_) => Err(err(
            "CONTENT_CORRUPT",
            format!("refs document {hex} fails its hash"),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(e)),
    }
}

/// Read-only after install (0500 dirs / 0400 files, native 0500; Windows read-only attribute).
/// Immutable means content-addressed and never rewritten by Calve, not tamper-proof against the
/// same OS user (trusted boundary).
fn set_read_only(dir: &Path, ro: bool) -> Result<()> {
    for e in fs::read_dir(dir).map_err(io_at("list", dir))? {
        let p = e.map_err(io_at("list", dir))?.path();
        let mut perm = fs::metadata(&p).map_err(io_at("stat", &p))?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let exec = fs::metadata(&p).map_err(io)?.permissions().mode() & 0o100 != 0;
            perm.set_mode(match (ro, exec) {
                (true, true) => 0o500,
                (true, false) => 0o400,
                (false, true) => 0o700,
                (false, false) => 0o600,
            });
        }
        #[cfg(not(unix))]
        perm.set_readonly(ro);
        fs::set_permissions(&p, perm).map_err(io_at("set permissions on", &p))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            dir,
            fs::Permissions::from_mode(if ro { 0o500 } else { 0o700 }),
        )
        .map_err(io)?;
    }
    Ok(())
}

fn remove_tree(dir: &Path) -> Result<()> {
    if dir.exists() {
        let _ = set_read_only(dir, false);
        fs::remove_dir_all(dir).map_err(io_at("remove", dir))?;
    }
    Ok(())
}
