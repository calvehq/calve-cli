//! A Project's authority on this machine: its keys, local identities and the digest of its
//! approved configuration. All of it lives under the machine data directory, outside the Project
//! directory a worker works in, and is bound to one Project root. That binding is what makes a
//! copy inactive: it can be read, and it writes only after `project adopt-copy` gives it its own
//! identity. It cannot see copies on another machine or restored from a backup there: those hold
//! no authority here until one is imported, and nothing coordinates between machines.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{ProjectIdentity, Result, coded, invalid};

thread_local! {
    static TEST_DATA_ROOT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Tests that open in-process a Project made by a CLI child with its own data directory.
#[doc(hidden)]
pub fn use_data_root(path: &Path) {
    TEST_DATA_ROOT.with(|r| *r.borrow_mut() = Some(path.to_owned()));
}

fn dir(project_id: &str) -> Result<PathBuf> {
    if !project_id.starts_with("prj_")
        || !project_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(invalid(format!("invalid project id {project_id:?}")));
    }
    let data = match TEST_DATA_ROOT.with(|r| r.borrow().clone()) {
        Some(path) => path,
        None => crate::registry::default_data_root()?,
    };
    Ok(data.join("authority").join(project_id))
}

fn ensure(project_id: &str) -> Result<PathBuf> {
    let d = dir(project_id)?;
    if let Some(parent) = d.parent() {
        crate::journal::private_dir(parent)?;
    }
    crate::journal::private_dir(&d)?;
    Ok(d)
}

fn identity_of(state: &Path) -> Result<ProjectIdentity> {
    Ok(toml::from_str(&fs::read_to_string(
        state.join("project.toml"),
    )?)?)
}

pub(crate) fn keys_path(project_id: &str) -> Result<PathBuf> {
    Ok(dir(project_id)?.join("keys.toml"))
}

pub(crate) fn write_keys(project_id: &str, keys: &str) -> Result<()> {
    crate::write_private(&ensure(project_id)?.join("keys.toml"), keys)
}

pub(crate) fn identities_dir(project_id: &str) -> Result<PathBuf> {
    let d = ensure(project_id)?.join("identities");
    crate::journal::private_dir(&d)?;
    Ok(d)
}

/// Replaces an owner-only file atomically.
fn replace_private(path: &Path, text: &str) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    crate::write_private(&tmp, text)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Binding {
    root: PathBuf,
}

/// Binds the Project's authority to `root`.
pub(crate) fn bind(project_id: &str, root: &Path) -> Result<()> {
    let root = fs::canonicalize(root)?;
    replace_private(
        &ensure(project_id)?.join("binding.toml"),
        &toml::to_string(&Binding { root })?,
    )
}

fn bound_root(project_id: &str) -> Option<PathBuf> {
    let text = fs::read_to_string(dir(project_id).ok()?.join("binding.toml")).ok()?;
    Some(toml::from_str::<Binding>(&text).ok()?.root)
}

/// Older Projects kept keys and identities in `.calve/`. They move once, on first open; a copy
/// of such a Project made before that is then an inactive copy like any other.
pub(crate) fn migrate_legacy(state: &Path, identity: &ProjectIdentity, root: &Path) -> Result<()> {
    let legacy = state.join("keys.toml");
    if !legacy.is_file() {
        return Ok(());
    }
    let id = &identity.project_id;
    if !keys_path(id)?.is_file() {
        write_keys(id, &fs::read_to_string(&legacy)?)?;
        bind(id, root)?;
    }
    let names = state.join("identities");
    if let Ok(entries) = fs::read_dir(&names) {
        let target = identities_dir(id)?;
        for entry in entries.flatten() {
            let to = target.join(entry.file_name());
            if !to.exists() {
                crate::write_private(&to, &fs::read_to_string(entry.path())?)?;
            }
        }
        fs::remove_dir_all(&names)?;
    }
    fs::remove_file(&legacy)?;
    Ok(())
}

/// Refuses a write through a directory other than the bound instance. If the bound root no
/// longer holds this Project it has moved, and the authority follows it.
pub(crate) fn ensure_instance(root: &Path) -> Result<()> {
    let state = root.join(".calve");
    let identity = identity_of(&state)?;
    let id = &identity.project_id;
    if !keys_path(id)?.is_file() && !state.join("keys.toml").is_file() {
        return Err(unavailable(id));
    }
    let here = fs::canonicalize(root)?;
    match bound_root(id) {
        Some(bound) if bound == here => Ok(()),
        Some(bound)
            if identity_of(&bound.join(".calve")).is_ok_and(|other| other.project_id == *id) =>
        {
            Err(crate::detailed(
                "PROJECT_IDENTITY_CONFLICT",
                format!(
                    "{} is an inactive copy of Project {id}, which is active at {}; it is read-only until `calve project adopt-copy` gives it its own identity",
                    here.display(),
                    bound.display()
                ),
                json!({"project_id": id, "active_root": bound, "copy_root": here}),
            ))
        }
        _ => bind(id, &here),
    }
}

pub(crate) fn unavailable(project_id: &str) -> crate::Error {
    coded(
        "PROJECT_IDENTITY_CONFLICT",
        format!(
            "this machine holds no authority for Project {project_id}; adopt the copy with `calve project adopt-copy` after `calve project authority-import`"
        ),
    )
}

/// The key material for `state`, wherever it is.
pub(crate) fn keys_for(state: &Path) -> Result<PathBuf> {
    let keys = keys_path(&identity_of(state)?.project_id)?;
    Ok(if keys.is_file() {
        keys
    } else {
        state.join("keys.toml")
    })
}

/// Writes the Project's authority to `file`, owner-only. Whoever holds it can act as the Project.
pub(crate) fn export(root: &Path, file: &Path) -> Result<Value> {
    let identity = identity_of(&root.join(".calve"))?;
    let id = &identity.project_id;
    let mut identities = serde_json::Map::new();
    if let Ok(entries) = fs::read_dir(identities_dir(id)?) {
        for entry in entries.flatten() {
            identities.insert(
                entry.file_name().to_string_lossy().into_owned(),
                json!(fs::read_to_string(entry.path())?),
            );
        }
    }
    let bundle = json!({"format": 1, "project_id": id,
        "keys": fs::read_to_string(keys_path(id)?).map_err(|_| unavailable(id))?,
        "identities": identities});
    crate::write_private(file, &serde_json::to_string(&bundle)?)?;
    Ok(json!({"project_id": id, "file": file}))
}

/// Installs an exported authority for the Project at `root`; never replaces one held here.
pub(crate) fn import(root: &Path, file: &Path) -> Result<Value> {
    let identity = identity_of(&root.join(".calve"))?;
    let id = &identity.project_id;
    let bundle: Value = serde_json::from_slice(&fs::read(file)?)?;
    if bundle["project_id"].as_str() != Some(id) {
        return Err(invalid("this authority belongs to another Project"));
    }
    if keys_path(id)?.is_file() {
        return Err(coded(
            "ALREADY_EXISTS",
            format!("this machine already holds the authority of {id}"),
        ));
    }
    let keys = bundle["keys"]
        .as_str()
        .ok_or_else(|| invalid("authority file has no keys"))?;
    let target = identities_dir(id)?;
    for (name, text) in bundle["identities"].as_object().into_iter().flatten() {
        if name.contains(['/', '\\']) || name.starts_with('.') {
            return Err(invalid("authority file has an invalid identity name"));
        }
        crate::write_private(
            &target.join(name),
            text.as_str()
                .ok_or_else(|| invalid("authority file has an invalid identity"))?,
        )?;
    }
    write_keys(id, keys)?;
    bind(id, root)?;
    Ok(json!({"project_id": id, "root": fs::canonicalize(root)?}))
}

fn config_digest(config: &[u8]) -> String {
    crate::journal::sha256_hex(config)
}

/// The Project id a `<root>/.calve/config.toml` belongs to.
fn owner(config: &Path) -> Option<String> {
    Some(identity_of(config.parent()?).ok()?.project_id)
}

/// Whether the host approved exactly these bytes of a Project's configuration.
pub(crate) fn config_approved(config: &Path, bytes: &[u8]) -> bool {
    owner(config)
        .and_then(|id| fs::read_to_string(dir(&id).ok()?.join("config.approved")).ok())
        .is_some_and(|approved| approved.trim() == config_digest(bytes))
}

/// Records the bytes now in `config` as approved by the user, through the host.
pub(crate) fn approve_config(config: &Path) -> Result<String> {
    let id = owner(config).ok_or_else(|| invalid("no Project owns this configuration"))?;
    let digest = config_digest(&fs::read(config)?);
    replace_private(&ensure(&id)?.join("config.approved"), &digest)?;
    Ok(digest)
}
