//! `project adopt-copy` (PLAN §13.6): turn a copied Project directory into a new Project with
//! its own ProjectId and Namespace, carrying accepted history across through OpenAEVC object
//! exchange. Imported objects are inert by protocol design (AEVC-XCH-0003): they can be
//! inspected and verified, but never authorize, gate, or join a new Baseline.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use openaevc::protocol::{Command, Digest, ObjectKind, Query, b64};
use openaevc_sdk::OpenAevcClient;
use serde_json::{Value, json};

use crate::{Error, Project, Result, event};

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

const BACKUP_PREFIX: &str = ".calve-adopt-source-";
/// Written into the source backup once the new Project is recorded and its store verified; only
/// then may recovery discard the source. Without it the adoption did not finish.
const COMPLETE_MARKER: &str = "adoption-complete";

/// Refs documents from the machine store (filled at install).
pub(crate) fn machine_refs(hash: &str) -> Result<Option<Vec<u8>>> {
    Ok(crate::catalog::install::refs_get(
        &crate::extensions::machine_paths()?,
        hash,
    )?)
}

/// Accepted history: promoted packs and Baselines with their transfer closure (native plus
/// supplemental refs edges, rev 10 §13), as `(roots, objects, refs documents)`.
async fn export_accepted(
    source: &Project,
) -> Result<(Vec<Digest>, Vec<(Digest, Vec<u8>)>, Bundle)> {
    let mut roots = Vec::new();
    for kind in [ObjectKind::PromotedPack, ObjectKind::Baseline] {
        let mut after = None;
        loop {
            let page = source
                .client
                .query(Query::ListObjectDigests {
                    kind: Some(kind),
                    after,
                    limit: Some(100),
                })
                .await?;
            for entry in page["objects"].as_array().into_iter().flatten() {
                roots.push(serde_json::from_value::<Digest>(entry["digest"].clone())?);
            }
            match page["next"].as_str() {
                Some(next) => {
                    after = Some(next.parse().map_err(|_| invalid("invalid page cursor"))?)
                }
                None => break,
            }
        }
    }
    let (digests, used) = source.transfer_closure(&roots, &machine_refs).await?;
    let mut refs = Bundle::new();
    for h in used {
        let doc = machine_refs(&h)?.ok_or_else(|| {
            crate::coded(
                "CLOSURE_UNCLASSIFIED",
                format!("refs document {h} vanished"),
            )
        })?;
        refs.insert(h, doc);
    }
    let mut objects = Vec::new();
    for digest in digests {
        let object = source.client.query(Query::GetObject { digest }).await?;
        let bytes = b64::decode(object["canonical"].as_str().unwrap_or_default())
            .map_err(|_| invalid(format!("object {digest} has no canonical bytes")))?;
        objects.push((digest, bytes));
    }
    Ok((roots, objects, refs))
}

/// Refs documents carried with a transfer, by content hash.
type Bundle = std::collections::BTreeMap<String, Vec<u8>>;

/// Adopts the copy at `path`. The source `.calve` is kept aside until the new Project has
/// imported and verified everything, so any failure restores the copy untouched.
pub async fn adopt_copy(path: &Path, name: Option<&str>) -> Result<(Project, Value)> {
    let root = Project::discover(path)?;
    if root != fs::canonicalize(path)? {
        return Err(invalid("adopt-copy needs the Project root of the copy"));
    }
    crate::app::evict_project(&root);
    let lock = crate::app::project_writer(&root)?;
    let source = Project::open(&root)?;
    let source_id = source.identity.project_id.clone();
    let source_namespace = source.identity.namespace_id.to_string();
    let display_name = name
        .map(str::to_owned)
        .unwrap_or_else(|| source.display_name.clone());
    let (roots, objects, refs) = export_accepted(&source).await?;
    drop(source);
    drop(lock);

    let state = root.join(".calve");
    let backup = root.join(format!("{BACKUP_PREFIX}{}", uuid::Uuid::now_v7()));
    fs::rename(&state, &backup)?;
    let adopted = async {
        let project = Project::init(&root, Some(&display_name)).await?;
        for (digest, bytes) in &objects {
            project
                .client
                .command(Command::PutImmutableObject {
                    digest: *digest,
                    bytes: bytes.clone(),
                })
                .await
                .map_err(|error| {
                    invalid(format!(
                        "OpenAEVC refused to import {digest}: {}",
                        error.message
                    ))
                })?;
        }
        // Integrity gate before the Project is used: every imported object is indexed and the
        // store verifies.
        let digests: Vec<Digest> = objects.iter().map(|(digest, _)| *digest).collect();
        for chunk in digests.chunks(500) {
            let present = project
                .client
                .query(Query::HasObject {
                    digests: chunk.to_vec(),
                })
                .await?;
            if let Some(missing) = chunk
                .iter()
                .find(|digest| present[digest.to_string()] != true)
            {
                return Err(invalid(format!(
                    "imported object {missing} is not visible after import"
                )));
            }
        }
        // Fail closed: the destination, with only the carried refs documents, must reproduce the
        // same closure.
        let carried = |h: &str| Ok(refs.get(h).cloned());
        let (at_destination, _) = project.transfer_closure(&roots, &carried).await?;
        let sent: BTreeSet<Digest> = objects.iter().map(|(d, _)| *d).collect();
        if at_destination != sent {
            return Err(crate::coded(
                "CONTENT_NOT_PORTABLE",
                "the transferred history does not reproduce its closure at the destination",
            ));
        }
        let detail = json!({"objects":objects.len(),"source_path":root});
        project.db.execute(
            "INSERT INTO adoptions VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                source_id,
                source_namespace,
                root.display().to_string(),
                crate::now()?,
                detail.to_string()
            ],
        )?;
        event(
            &project.db,
            "project.adopted",
            &source_id,
            &detail.to_string(),
        )?;
        Ok::<Project, Error>(project)
    }
    .await;
    match adopted {
        Ok(project) => {
            // OpenAEVC admits one runtime per data root, so close ours before verifying.
            drop(project);
            let store = crate::ops::verify_store(&root);
            if !store.as_ref().is_ok_and(|report| report["ok"] == true) {
                let _ = fs::remove_dir_all(&state);
                fs::rename(&backup, &state)?;
                return Err(invalid(format!(
                    "new Project failed store verification: {store:?}"
                )));
            }
            let marker = backup.join(COMPLETE_MARKER);
            fs::write(&marker, source_id.as_bytes())?;
            fs::File::open(&marker)?.sync_all()?;
            crate::journal::fault("adopt.after_complete");
            fs::remove_dir_all(&backup)?;
            let project = Project::open(&root)?;
            let summary = json!({"project_id":project.identity.project_id,
                "namespace_id":project.identity.namespace_id,"adopted_from":source_id,
                "transferred_objects":objects.len(),
                "refs_documents":refs.len(),
                "note":"transferred history is inert: inspectable and verifiable, but it cannot authorize, gate, or join new Baselines"});
            Ok((project, summary))
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&state);
            fs::rename(&backup, &state)?;
            Err(error)
        }
    }
}

/// Recovery view of an interrupted adoption: restore the source if the new state is unusable.
pub fn adoption_leftovers(root: &Path) -> Result<Vec<Value>> {
    let mut actions = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(BACKUP_PREFIX) && entry.file_type()?.is_dir() {
            // A new `.calve` that opens is not proof of success: a crash mid-import leaves one.
            let complete =
                entry.path().join(COMPLETE_MARKER).is_file() && Project::peek(root).is_ok();
            actions.push(if complete {
                json!({"action":"remove_staging_dir","path":entry.path(),
                    "reason":"source state left by a completed adoption"})
            } else {
                json!({"action":"restore_adoption_source","path":entry.path(),
                    "reason":"adoption was interrupted; restore the copied Project's original state"})
            });
        }
    }
    Ok(actions)
}
