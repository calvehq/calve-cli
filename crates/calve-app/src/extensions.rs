//! Extension manager (rev 10 §7–§9, ADR 0005–0007): signed TUF catalogs, machine-level package
//! installation (`catalog::install`), and per-Project activation. The three gates stay
//! independent: trust (TUF + catalog policy), compatibility (protocol/contract, CIC, platform,
//! schema) and permission (host-capability grants plus the T2 acknowledgment). OpenAEVC owns the
//! extension contract and runtime authorization; this module decides what to hand it.
//!
//! Activation per Project (A0–A2): A0 the permission gate (grants ⊆ requested, the native
//! acknowledgment recorded with the grants); A1 `RegisterExtension` at the immutable
//! `<id>/<sha256>/<binary>` path with the TUF-verified digest; A2 the desired state recorded.
//! A re-registration of a new version is refused (`EXTENSION_IN_USE`) while non-terminal work in
//! the namespace references the extension (F21: OpenAEVC resolves extensions per submission).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use openaevc::protocol::{Digest, HostCapability, Query};
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::{Value, json};

use crate::catalog::install::{
    self, CicRunner, InstallRequest, Installer, PackageRecord, Paths, freshness, installed,
    version_key,
};
use crate::registry::default_data_root;
use crate::{Error, Project, Result, event, now};

/// The manifest OpenAEVC recorded at registration equals the installed one (id, version,
/// artifact digest and every declared kind and capability).
pub fn registration_matches(r: &PackageRecord, body: &Value) -> std::result::Result<(), String> {
    let got: openaevc::protocol::ExtensionManifest =
        serde_json::from_value(body.clone()).map_err(|e| format!("registered manifest: {e}"))?;
    if got == r.manifest {
        return Ok(());
    }
    Err(format!(
        "OpenAEVC registered {}@{} (artifact {}), the installed package is {}@{} (artifact {})",
        got.id,
        got.version,
        got.artifact_digest,
        r.manifest.id,
        r.manifest.version,
        r.manifest.artifact_digest
    ))
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

/// Grant marker recording the T2 acknowledgment ("runs as native code with your user
/// permissions, not confined") next to the host-capability grants of that exact artifact.
pub const T2_ACKNOWLEDGED: &str = "calve:t2-acknowledged";

/// Grant-marker prefix recording the user's approval of one exact check plan
/// (`calve:check-plan:<sha256>`) of this artifact; grant changes keep it, an upgrade does not.
pub const CHECK_PLAN_APPROVED: &str = "calve:check-plan:";

/// Default `revocation_max_age` (§9.3).
pub const REVOCATION_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// Machine-level package locations: `<data>/catalogs`, `<data>/run/install`, and the runtime's
/// extension directory `<data>/packages`.
pub fn machine_paths() -> Result<Paths> {
    let data = default_data_root()?;
    Ok(Paths {
        extension_dir: data.join("packages"),
        data,
    })
}

/// The directory OpenAEVC resolves registered entrypoints in.
pub fn extension_dir() -> Option<PathBuf> {
    machine_paths().ok().map(|p| p.extension_dir)
}

fn installer() -> Result<Installer> {
    let program = crate::sandbox::sandbox_program().map_err(|e| invalid(e.to_string()))?;
    Ok(Installer::new(
        machine_paths()?,
        CicRunner::Supervised(program),
    ))
}

fn usage_path() -> Result<PathBuf> {
    Ok(machine_paths()?.data.join("extensions/usage.json"))
}

fn usage() -> Result<BTreeMap<String, BTreeSet<String>>> {
    match fs::read(usage_path()?) {
        Ok(b) => Ok(serde_json::from_slice(&b)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e.into()),
    }
}

/// Which Projects registered which native digest (uninstall/retirement guard).
fn set_usage(digest: &str, project: &str, used: bool) -> Result<()> {
    let mut all = usage()?;
    let entry = all.entry(digest.to_owned()).or_default();
    if used {
        entry.insert(project.to_owned());
    } else {
        entry.remove(project);
    }
    all.retain(|_, projects| !projects.is_empty());
    let path = usage_path()?;
    fs::create_dir_all(path.parent().expect("parent"))?;
    let tmp = path.with_extension(format!("tmp-{}", uuid::Uuid::now_v7().simple()));
    fs::write(&tmp, serde_json::to_vec_pretty(&all)?)?;
    crate::workspace_io::rename_durable(&tmp, &path)?;
    Ok(())
}

// ----------------------------------------------------------------------------- machine level

/// `extension catalog add`: trusts a catalog whose root is pinned by SHA-256 (obtained out of
/// band from the publisher).
pub fn catalog_add(name: &str, url: &str, root_file: &Path, root_digest: &str) -> Result<Value> {
    let root = fs::read(root_file)?;
    Ok(install::add_catalog(
        &machine_paths()?,
        name,
        url,
        &root,
        root_digest,
    )?)
}

pub fn catalog_list() -> Result<Value> {
    let paths = machine_paths()?;
    let mut out = vec![];
    for name in install::catalog_names(&paths)? {
        match install::open_catalog(&paths, &name) {
            Ok((c, src)) => out.push(
                json!({"name": name, "url": src.url, "root_digest": src.root_digest,
                "generation": c.active, "root_version": c.versions.root,
                "last_success": c.accepted_at.map(|t| t.to_string()),
                "state": freshness(c.accepted_at, REVOCATION_MAX_AGE)}),
            ),
            Err(e) => out.push(
                json!({"name": name, "state": "recovery_required", "problem": e.to_string()}),
            ),
        }
    }
    Ok(json!(out))
}

pub fn catalog_refresh(name: Option<&str>) -> Result<Value> {
    let paths = machine_paths()?;
    let names = match name {
        Some(n) => vec![n.to_owned()],
        None => install::catalog_names(&paths)?,
    };
    let mut out = vec![];
    for n in names {
        out.push(install::refresh_catalog(&paths, &n)?);
    }
    Ok(json!(out))
}

/// The audited privileged reset (§9.3); the caller has confirmed (TTY or
/// `--yes --i-understand-rollback-risk`).
pub fn catalog_reset(name: &str, root_file: &Path, root_digest: &str) -> Result<Value> {
    let root = fs::read(root_file)?;
    Ok(install::reset_catalog(
        &machine_paths()?,
        name,
        &root,
        root_digest,
    )?)
}

/// Stops trusting a catalog; its trust state is archived, installed packages stay.
pub fn catalog_remove(name: &str) -> Result<Value> {
    let paths = machine_paths()?;
    let dir = paths.data.join("catalogs").join(name);
    if !dir.join("source.json").is_file() {
        return Err(invalid(format!("catalog {name} is not trusted")));
    }
    let archive = paths
        .data
        .join("catalogs-removed")
        .join(format!("{name}-{}", uuid::Uuid::now_v7().simple()));
    fs::create_dir_all(archive.parent().expect("parent"))?;
    fs::rename(&dir, &archive)?;
    crate::observe::record("extension.catalog_removed", json!({"name": name}));
    Ok(json!({"name": name, "removed": true}))
}

/// Ids (from each catalog's signed `index.json`) matching `query`, with their versions.
pub fn search(query: Option<&str>) -> Result<Value> {
    let paths = machine_paths()?;
    let mut out = vec![];
    for name in install::catalog_names(&paths)? {
        let (mut c, src) = install::open_catalog(&paths, &name)?;
        let mirror = src.mirror();
        let Some((_, index)) = c
            .fetch(&mirror, "index.json", None)
            .map_err(|e| invalid(format!("{name}: {e:?}")))?
        else {
            continue;
        };
        let index: Value = serde_json::from_slice(&index)?;
        for id in index["ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if query.is_some_and(|q| !id.contains(q)) || !install::valid_id(id) {
                continue;
            }
            let versions = match c.fetch(&mirror, &format!("{id}/package.json"), None) {
                Ok(Some((info, b))) => serde_json::from_slice::<install::PackageIndex>(&b)
                    .map(|p| json!({"versions": p.versions.iter().map(|v| json!({"version": v.version, "kind": v.kind, "targets": v.native.keys().collect::<Vec<_>>()})).collect::<Vec<_>>(), "publisher": info.role}))
                    .unwrap_or_else(|e| json!({"problem": e.to_string()})),
                Ok(None) => json!({"problem": "listed in index.json but not offered"}),
                Err(e) => json!({"problem": format!("{e:?}")}),
            };
            out.push(json!({"id": id, "catalog": name, "package": versions}));
        }
    }
    Ok(json!(out))
}

pub fn install_package(
    id: &str,
    version: Option<&str>,
    catalog: Option<&str>,
    acknowledge_native: bool,
) -> Result<Value> {
    let rec = installer()?.install(&InstallRequest {
        id,
        version,
        catalog,
        acknowledge_native,
        switch_publisher: false,
    })?;
    Ok(record_view(&rec))
}

/// `extension switch-publisher`: the confirmed, audited change of an id's pinned catalog.
pub fn switch_publisher(id: &str, catalog: &str, acknowledge_native: bool) -> Result<Value> {
    let rec = installer()?.install(&InstallRequest {
        id,
        version: None,
        catalog: Some(catalog),
        acknowledge_native,
        switch_publisher: true,
    })?;
    crate::observe::record(
        "extension.publisher_switched",
        json!({"id": id, "catalog": catalog, "role": rec.role}),
    );
    Ok(record_view(&rec))
}

fn record_view(r: &PackageRecord) -> Value {
    json!({"id": r.id, "version": r.version, "kind": r.kind, "catalog": r.catalog, "publisher": r.role,
        "digests": r.digests, "entrypoint": r.entrypoint, "native_acknowledged": r.native_acknowledged,
        "installed_at": r.installed_at})
}

pub fn list_installed() -> Result<Value> {
    let used = usage()?;
    let records = installed(&machine_paths()?)?;
    Ok(json!(
        records
            .iter()
            .map(|r| {
                let mut v = record_view(r);
                v["projects"] = json!(used.get(r.native_digest()).cloned().unwrap_or_default());
                v
            })
            .collect::<Vec<_>>()
    ))
}

/// Removes installed versions no Project uses (R0–R2 with an in-use re-check).
pub fn uninstall(id: &str, version: Option<&str>) -> Result<Value> {
    let paths = machine_paths()?;
    let targets: Vec<PackageRecord> = installed(&paths)?
        .into_iter()
        .filter(|r| r.id == id && version.is_none_or(|v| v == r.version))
        .collect();
    if targets.is_empty() {
        return Err(invalid(format!("{id} is not installed")));
    }
    let inst = installer()?;
    let mut removed = vec![];
    for r in targets {
        inst.retire(&r, |r| {
            usage()
                .map(|u| u.get(r.native_digest()).is_some_and(|p| !p.is_empty()))
                .unwrap_or(true)
        })?;
        removed.push(json!({"id": r.id, "version": r.version}));
    }
    Ok(json!({"removed": removed}))
}

/// Crash reconciliation of unfinished install/retire journals (`calve recover`).
pub fn recover_installs() -> Result<Value> {
    Ok(json!(installer()?.recover()?))
}

/// The installed package with this native digest.
pub fn package_by_digest(digest: &str) -> Result<Option<PackageRecord>> {
    Ok(installed(&machine_paths()?)?
        .into_iter()
        .find(|r| r.native_digest() == digest))
}

fn newest_installed(id: &str) -> Result<Option<PackageRecord>> {
    Ok(installed(&machine_paths()?)?
        .into_iter()
        .filter(|r| r.id == id)
        .max_by_key(|r| version_key(&r.version)))
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

// ------------------------------------------------------------------------------ per Project

impl Project {
    fn grant_rows(&self, id: &str, digest: &str) -> Result<Vec<String>> {
        let mut stmt = self.db.prepare(
            "SELECT capability FROM extension_grants WHERE extension_id=?1 AND artifact_digest=?2 ORDER BY capability",
        )?;
        let names = stmt
            .query_map([id, &format!("sha256:{digest}")], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(names)
    }

    fn granted_capabilities(&self, id: &str, digest: &str) -> Result<Vec<HostCapability>> {
        let names: Vec<String> = self
            .grant_rows(id, digest)?
            .into_iter()
            .filter(|n| !n.starts_with("calve:"))
            .collect();
        parse_capabilities(&names)
    }

    pub(crate) fn check_plan_approved(&self, r: &PackageRecord, plan: &str) -> Result<bool> {
        let marker = format!("{CHECK_PLAN_APPROVED}{plan}");
        Ok(self.grant_rows(&r.id, r.native_digest())?.contains(&marker))
    }

    pub(crate) fn approve_check_plan(&self, r: &PackageRecord, plan: &str) -> Result<()> {
        self.db.execute(
            "INSERT INTO extension_grants VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                r.id,
                r.version,
                format!("sha256:{}", r.native_digest()),
                format!("{CHECK_PLAN_APPROVED}{plan}"),
                now()?
            ],
        )?;
        Ok(())
    }

    fn native_acknowledged(&self, id: &str, digest: &str) -> Result<bool> {
        Ok(self
            .grant_rows(id, digest)?
            .iter()
            .any(|n| n == T2_ACKNOWLEDGED))
    }

    /// A0's record: grants and the T2 acknowledgment for exactly this artifact.
    fn record_grants(
        &self,
        r: &PackageRecord,
        capabilities: &[HostCapability],
        acknowledged: bool,
    ) -> Result<()> {
        let digest = format!("sha256:{}", r.native_digest());
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM extension_grants WHERE extension_id=?1 AND artifact_digest=?2
             AND capability NOT LIKE 'calve:check-plan:%'",
            [&r.id, &digest],
        )?;
        let mut names = capability_names(capabilities);
        if acknowledged {
            names.push(T2_ACKNOWLEDGED.into());
        }
        for name in names {
            tx.execute(
                "INSERT INTO extension_grants VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![r.id, r.version, digest, name, now()?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The installed package behind the registration of `id` in this namespace.
    pub(crate) async fn active_package(&self, id: &str) -> Result<Option<PackageRecord>> {
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
        package_by_digest(&artifact.hex())
    }

    /// Upgrade guard (§9.4, F21): non-terminal executions in this namespace that reference the
    /// extension (by recorded provenance or by effect kinds they may submit).
    async fn work_using(&self, r: &PackageRecord) -> Result<Vec<String>> {
        let kinds: BTreeSet<&str> = r
            .manifest
            .effect_kinds
            .iter()
            .map(|k| k.kind.as_str())
            .collect();
        let all = self.list_executions(None, None).await?;
        Ok(all
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| matches!(e["state"].as_str(), Some("PENDING" | "RUNNING" | "LOST")))
            .filter(|e| {
                e["extensions"]
                    .as_array()
                    .is_some_and(|x| x.iter().any(|x| x["id"] == r.id.as_str()))
                    || e["allowed_effects"].as_array().is_some_and(|x| {
                        x.iter()
                            .any(|k| k.as_str().is_some_and(|k| kinds.contains(k)))
                    })
            })
            .filter_map(|e| e["id"].as_str().map(str::to_owned))
            .collect())
    }

    /// A0–A2 for an installed package.
    async fn activate(
        &self,
        r: &PackageRecord,
        grants: &[HostCapability],
        acknowledge_native: bool,
    ) -> Result<Value> {
        // A0: the permission gate, independent of trust and compatibility.
        let requested = &r.manifest.host_capabilities;
        if let Some(extra) = grants.iter().find(|cap| !requested.contains(cap)) {
            return Err(invalid(format!(
                "{} does not request {}; only requested capabilities can be granted",
                r.id,
                capability_names(&[*extra]).join("")
            )));
        }
        let acknowledged =
            acknowledge_native || self.native_acknowledged(&r.id, r.native_digest())?;
        if !acknowledged {
            return Err(invalid(format!(
                "T2_ACKNOWLEDGMENT_REQUIRED: {}@{} runs as native code with your user permissions (not confined); enable again with --acknowledge-native",
                r.id, r.version
            )));
        }
        install::verify_installed(&machine_paths()?, r)?;
        let previous = self.active_package(&r.id).await?;
        if let Some(prev) = &previous
            && prev.native_digest() != r.native_digest()
        {
            let busy = self.work_using(prev).await?;
            if !busy.is_empty() {
                return Err(invalid(format!(
                    "EXTENSION_IN_USE: {} is used by non-terminal executions {busy:?}; let them finish or cancel them first",
                    r.id
                )));
            }
        }
        // A1: register the immutable path with the TUF-verified digest (OpenAEVC re-hashes it
        // and requires equality with the manifest's artifact digest, F20).
        let digest: Digest = format!("sha256:{}", r.native_digest())
            .parse()
            .map_err(|_| invalid("invalid digest"))?;
        let manifest_digest = self
            .client
            .register_extension(&r.entrypoint, digest, grants.to_vec())
            .await?;
        // A1b: what OpenAEVC registered (it re-runs the handshake) must be exactly the installed
        // manifest; a binary that answers differently now is unregistered, never activated.
        let registered = self
            .client
            .query(Query::GetObject {
                digest: manifest_digest,
            })
            .await?;
        if let Err(why) = registration_matches(r, &registered["envelope"]["body"]) {
            let _ = self
                .client
                .command(openaevc::protocol::Command::UnregisterExtension {
                    extension: r.manifest.id.clone(),
                })
                .await;
            return Err(invalid(format!("EXTENSION_IDENTITY_MISMATCH: {why}")));
        }
        // A2: the desired state.
        self.record_grants(r, grants, true)?;
        set_usage(r.native_digest(), &self.identity.project_id, true)?;
        if let Some(prev) = previous
            && prev.native_digest() != r.native_digest()
        {
            set_usage(prev.native_digest(), &self.identity.project_id, false)?;
        }
        event(&self.db, "extension.enabled", &r.id, &r.version)?;
        let pending: Vec<HostCapability> = requested
            .iter()
            .filter(|c| !grants.contains(c))
            .copied()
            .collect();
        Ok(
            json!({"id": r.id, "version": r.version, "artifact_digest": digest, "manifest_digest": manifest_digest,
            "publisher": r.role, "catalog": r.catalog, "granted": capability_names(grants),
            "ungranted_requests": capability_names(&pending), "native_acknowledged": true,
            "trust_tier": "T2 native (not confined)"}),
        )
    }

    /// `extension enable <id>`: installs from the trusted catalogs when needed, then activates.
    pub async fn enable_extension(
        &self,
        id: &str,
        grants: &[String],
        acknowledge_native: bool,
    ) -> Result<Value> {
        let grants = parse_capabilities(grants)?;
        let r = match newest_installed(id)? {
            Some(r) => r,
            None => installer()?.install(&InstallRequest {
                id,
                version: None,
                catalog: None,
                acknowledge_native,
                switch_publisher: false,
            })?,
        };
        self.activate(&r, &grants, acknowledge_native).await
    }

    pub async fn grant_extension(&self, id: &str, capabilities: &[String]) -> Result<Value> {
        let r = self.require_active(id).await?;
        let mut grants = self.granted_capabilities(&r.id, r.native_digest())?;
        for cap in parse_capabilities(capabilities)? {
            if !grants.contains(&cap) {
                grants.push(cap);
            }
        }
        self.activate(&r, &grants, false).await
    }

    pub async fn revoke_extension(&self, id: &str, capabilities: &[String]) -> Result<Value> {
        let r = self.require_active(id).await?;
        let revoke = parse_capabilities(capabilities)?;
        let grants: Vec<HostCapability> = self
            .granted_capabilities(&r.id, r.native_digest())?
            .into_iter()
            .filter(|c| !revoke.contains(c))
            .collect();
        self.activate(&r, &grants, false).await
    }

    async fn require_active(&self, id: &str) -> Result<PackageRecord> {
        self.active_package(id).await?.ok_or_else(|| {
            invalid(format!(
                "{id} is not enabled from an installed package in this Project"
            ))
        })
    }

    /// Installs the newest catalog version and switches this Project to it, unless a host
    /// capability widens beyond current grants (then `--grant` each) or work is in flight.
    pub async fn update_extension(
        &self,
        id: &str,
        grants: &[String],
        acknowledge_native: bool,
    ) -> Result<Value> {
        let current = self.require_active(id).await?;
        let r = installer()?.install(&InstallRequest {
            id,
            version: None,
            catalog: None,
            acknowledge_native,
            switch_publisher: false,
        })?;
        if version_key(&r.version) <= version_key(&current.version) {
            return Ok(
                json!({"id": id, "version": current.version, "updated": false, "reason": "already newest"}),
            );
        }
        let mut approved = self.granted_capabilities(&current.id, current.native_digest())?;
        for cap in parse_capabilities(grants)? {
            if !approved.contains(&cap) {
                approved.push(cap);
            }
        }
        let widening: Vec<HostCapability> = r
            .manifest
            .host_capabilities
            .iter()
            .filter(|c| !current.manifest.host_capabilities.contains(c) && !approved.contains(c))
            .copied()
            .collect();
        if !widening.is_empty() {
            return Ok(
                json!({"id": id, "installed_version": r.version, "active_version": current.version, "updated": false,
                "permission_widening": capability_names(&widening),
                "reason": "new version requests more host capabilities; rerun with --grant for each to accept"}),
            );
        }
        approved.retain(|c| r.manifest.host_capabilities.contains(c));
        let mut out = self.activate(&r, &approved, acknowledge_native).await?;
        out["updated"] = json!(true);
        out["previous_version"] = json!(current.version);
        Ok(out)
    }

    pub(crate) async fn release_extension_usage(&self, id: &str) -> Result<()> {
        if let Some(r) = self.active_package(id).await? {
            set_usage(r.native_digest(), &self.identity.project_id, false)?;
        }
        Ok(())
    }

    /// Signed integration metadata of every active cic-capable package in this Project, with
    /// the installed record (the source of all domain declarations; no literals in the host).
    pub(crate) async fn active_packages(&self) -> Result<Vec<PackageRecord>> {
        let mut out = vec![];
        for e in self
            .list_extensions()
            .await?
            .as_array()
            .into_iter()
            .flatten()
        {
            if e["active"] != true {
                continue;
            }
            if let Some(id) = e["id"].as_str()
                && let Some(r) = self.active_package(id).await?
            {
                out.push(r);
            }
        }
        Ok(out)
    }
}
