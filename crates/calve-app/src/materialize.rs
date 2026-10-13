//! Safe materialization of accepted file state into the working tree (PLAN §27.6).
//!
//! Local content that matches no snapshot Calve knows about is uncaptured work. It blocks
//! materialization unless the user names that exact path with `--discard`; discarded content is
//! copied to `.calve/cache/discarded/` first. Writes happen inside an OpenAEVC execution whose
//! observations record every file, so the working-tree change has receipts and provenance.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use openaevc_crypto::sha256;
use openaevc_protocol::{
    Command, Digest, ExecutionRequest, PackSpec, ProviderDescriptor, Query, ResourceRef,
    WorkerInfo, b64,
};
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::{Value, json};

use crate::{Error, Project, Result, event};

const SOFTWARE_EXTENSION: &str = "org.calve.software";
const SOFTWARE_RESOURCE: &str = "org.calve.software.file";
const HARNESS: &str = "org.calve.software.materialize";
const PROVIDER: &str = "org.calve.software.local";
const WRITE_ACTION: &str = "org.calve.software.write";

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

/// Desired content per path; `None` means the path must not exist.
type Desired = BTreeMap<String, Option<Vec<u8>>>;

impl Project {
    /// Every snapshot digest this Project has recorded for each path, from any pack.
    async fn known_snapshots(&self) -> Result<BTreeMap<String, BTreeSet<String>>> {
        let mut known: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for summary in self.list_packs().await? {
            let Some(id) = summary["id"].as_str() else {
                continue;
            };
            for effect in self.pack(id).await?.candidate_effects {
                if crate::resources::is_file_effect(&effect.kind)
                    && let Some(digest) = effect.payload["digest"].as_str()
                {
                    known
                        .entry(effect.target.locator)
                        .or_default()
                        .insert(digest.to_owned());
                }
            }
        }
        Ok(known)
    }

    fn snapshot_content(effect: &openaevc_protocol::AppliedEffect) -> Result<Vec<u8>> {
        let content = b64::decode(effect.payload["content"].as_str().unwrap_or_default())
            .map_err(|_| invalid("snapshot content is not valid base64"))?;
        if effect.payload["digest"].as_str() != Some(&sha256(&content).to_string()) {
            return Err(invalid(format!(
                "snapshot of {} fails its digest",
                effect.target.locator
            )));
        }
        Ok(content)
    }

    /// Accepted file state of a Baseline: member packs in promotion order, later writes win.
    async fn baseline_files(&self, id_or_alias: &str) -> Result<(String, Desired)> {
        let validation = self.validate_baseline(id_or_alias).await?;
        if validation["valid"] != true {
            return Err(invalid(format!(
                "baseline failed OpenAEVC validation: {}",
                validation["problems"]
            )));
        }
        let baseline = self.baseline_typed(id_or_alias).await?;
        let members: BTreeSet<String> = baseline.members.iter().map(ToString::to_string).collect();
        let mut state = crate::resources::FileState::default();
        // list_packs is in creation order; promoted_digest ties packs to Baseline members.
        for summary in self.list_packs().await? {
            let Some(digest) = summary["promoted_digest"].as_str() else {
                continue;
            };
            if !members.contains(digest) {
                continue;
            }
            let promoted: Digest = digest
                .parse()
                .map_err(|_| invalid("invalid promoted digest"))?;
            self.client
                .query(Query::GetPromotedPack {
                    pack: None,
                    digest: Some(promoted),
                })
                .await?;
            let id = summary["id"].as_str().unwrap_or_default();
            for effect in self.pack(id).await?.candidate_effects {
                if crate::resources::is_file_effect(&effect.kind) {
                    crate::validate_locator(&effect.target.locator)?;
                    state.apply(&effect)?;
                }
            }
        }
        let mut desired: Desired = state
            .files
            .into_iter()
            .map(|(path, content)| (path, Some(content)))
            .collect();
        for path in state.removed {
            desired.entry(path).or_insert(None);
        }
        // Paths other accepted packs introduced are absent from this composition, so a faithful
        // switch removes them too (still only when they hold recorded content).
        let everything = self.accepted_state(None).await?;
        for path in everything.files.keys().chain(everything.removed.iter()) {
            desired.entry(path.clone()).or_insert(None);
        }
        Ok((baseline.id.to_string(), desired))
    }

    /// Classifies each desired path against the working tree.
    async fn materialization_plan(
        &self,
        desired: &Desired,
        discard: &[String],
    ) -> Result<Vec<Value>> {
        let known = self.known_snapshots().await?;
        let mut plan = Vec::new();
        for (path, content) in desired {
            let target = digest_of_file(&self.root.join(path))?;
            let Some(content) = content else {
                // The Baseline removed this path: delete it only if it holds recorded content.
                let action = match &target {
                    None => "unchanged",
                    Some(current) if known.get(path).is_some_and(|d| d.contains(current)) => {
                        "delete"
                    }
                    Some(_) if discard.contains(path) => "discard_and_delete",
                    Some(_) => "blocked_uncaptured_changes",
                };
                plan.push(
                    json!({"path":path,"action":action,"current":target,"desired":"deleted"}),
                );
                continue;
            };
            let wanted = sha256(content).to_string();
            let action = match &target {
                None => "create",
                Some(current) if *current == wanted => "unchanged",
                Some(current)
                    if known
                        .get(path)
                        .is_some_and(|digests| digests.contains(current)) =>
                {
                    "update"
                }
                Some(_) if discard.contains(path) => "discard_and_update",
                Some(_) => "blocked_uncaptured_changes",
            };
            plan.push(json!({"path":path,"action":action,"current":target,"desired":wanted}));
        }
        for path in discard {
            if !desired.contains_key(path) {
                return Err(invalid(format!(
                    "--discard {path} is not part of this materialization"
                )));
            }
        }
        Ok(plan)
    }

    async fn apply_materialization(
        &self,
        label: &str,
        desired: &Desired,
        plan: &[Value],
    ) -> Result<Value> {
        let principal = self.client.session().principal();
        for step in plan.iter().filter(|step| step["action"] != "unchanged") {
            let decision = self
                .client
                .query(Query::Authorize {
                    principal,
                    action: WRITE_ACTION.into(),
                    resource: Some(ResourceRef {
                        kind: SOFTWARE_RESOURCE.into(),
                        locator: step["path"].as_str().unwrap_or_default().into(),
                        version: None,
                        extension: SOFTWARE_EXTENSION.into(),
                    }),
                })
                .await?;
            if decision["allowed"] != true {
                return Err(invalid(format!("not authorized to write {}", step["path"])));
            }
        }
        // A dedicated pack carries the execution so the writes have OpenAEVC provenance; it is
        // abandoned afterwards because it proposes no candidate change.
        let pack = self
            .client
            .create_change_pack(PackSpec {
                metadata: [("org.calve.materialize".to_owned(), json!(label))].into(),
                ..PackSpec::default()
            })
            .await?;
        self.db.execute(
            "INSERT INTO pack_metadata VALUES (?1,?2,NULL,?3)",
            rusqlite::params![
                pack.to_string(),
                format!("Materialize {label}"),
                crate::now()?
            ],
        )?;
        self.client
            .command(Command::RegisterProvider {
                provider: ProviderDescriptor {
                    id: PROVIDER.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    worker_kinds: vec![HARNESS.into()],
                    harnesses: vec![HARNESS.into()],
                    required_actions: vec![WRITE_ACTION.into()],
                    cancellation: true,
                    resumable: false,
                    heartbeat: false,
                    limits: BTreeMap::new(),
                    provenance_fields: vec![],
                    principal,
                },
            })
            .await?;
        let work_unit = self.client.add_work_unit(pack, 1, HARNESS).await?;
        let generation = self.client.get_change_pack(pack).await?.generation;
        let (execution, lease) = self
            .client
            .start_execution(ExecutionRequest {
                pack,
                expected_generation: generation,
                work_unit,
                provider: PROVIDER.into(),
                harness: HARNESS.into(),
                worker: Some(WorkerInfo {
                    id: "local".into(),
                    kind: HARNESS.into(),
                    attributes: BTreeMap::new(),
                }),
                allowed_resources: vec![],
                allowed_effects: vec![],
                context: vec![],
                timeout_ms: 1_800_000,
                budget: BTreeMap::new(),
                max_attempts: 1,
                idempotency_key: uuid::Uuid::now_v7().to_string(),
                retry_of: None,
            })
            .await?;
        let discard_dir = self.root.join(".calve/cache/discarded");
        let mut written = Vec::new();
        let result: Result<()> = async {
            for step in plan.iter().filter(|step| step["action"] != "unchanged") {
                let path = step["path"].as_str().unwrap_or_default();
                let target = self.root.join(path);
                let mut observation =
                    json!({"path":path,"action":step["action"],"digest":step["desired"]});
                // Canonical protocol JSON forbids null, so a created file has no `previous`.
                if step["current"].is_string() {
                    observation["previous"] = step["current"].clone();
                }
                if step["action"] == "discard_and_update" || step["action"] == "discard_and_delete"
                {
                    fs::create_dir_all(&discard_dir)?;
                    let previous = fs::read(&target)?;
                    let backup = discard_dir.join(sha256(&previous).to_string().replace(':', "_"));
                    fs::write(&backup, &previous)?;
                    observation["backup"] =
                        json!(backup.strip_prefix(&self.root).unwrap_or(&backup));
                }
                match &desired[path] {
                    Some(content) => write_atomically(&self.root, path, content)?,
                    None => fs::remove_file(&target)?,
                }
                self.client.heartbeat(&lease).await?;
                self.client
                    .command(Command::AppendObservation {
                        execution,
                        lease: lease.id,
                        kind: "org.calve.software.materialized".into(),
                        payload: Some(observation),
                        blob: None,
                        related_resources: vec![ResourceRef {
                            kind: SOFTWARE_RESOURCE.into(),
                            locator: path.into(),
                            version: None,
                            extension: SOFTWARE_EXTENSION.into(),
                        }],
                        related_effects: vec![],
                    })
                    .await?;
                written.push(path.to_owned());
            }
            // Post-state verification: every desired file now has the desired digest.
            for (path, content) in desired {
                let expected = content.as_deref().map(|c| sha256(c).to_string());
                if digest_of_file(&self.root.join(path))? != expected {
                    return Err(invalid(format!("post-check failed for {path}")));
                }
            }
            Ok(())
        }
        .await;
        match &result {
            Ok(()) => {
                self.client.complete_execution(&lease).await?;
            }
            Err(error) => {
                self.client
                    .command(Command::FailExecution {
                        execution,
                        lease: lease.id,
                        reason: error.to_string(),
                    })
                    .await?;
            }
        }
        let generation = self.client.get_change_pack(pack).await?.generation;
        self.client
            .command(Command::AbandonChangePack {
                pack,
                expected_generation: generation,
            })
            .await?;
        result?;
        event(&self.db, "materialized", label, &written.len().to_string())?;
        Ok(json!({"execution":execution,"provenance_pack":pack,"written":written}))
    }

    async fn materialize(
        &self,
        label: &str,
        desired: Desired,
        discard: &[String],
        apply: bool,
    ) -> Result<Value> {
        let plan = self.materialization_plan(&desired, discard).await?;
        let blocked: Vec<&Value> = plan
            .iter()
            .filter(|step| step["action"] == "blocked_uncaptured_changes")
            .collect();
        if !apply || !blocked.is_empty() {
            return Ok(json!({"applied":false,"plan":plan,
            "blocked":blocked.iter().map(|step| step["path"].clone()).collect::<Vec<_>>(),
            "note": if blocked.is_empty() {
                "review the plan, then rerun with --apply"
            } else {
                "local files hold uncaptured changes; capture them, or name each with --discard to back it up and overwrite"
            }}));
        }
        let mut result = self.apply_materialization(label, &desired, &plan).await?;
        result["applied"] = json!(true);
        result["plan"] = json!(plan);
        Ok(result)
    }

    pub async fn materialize_baseline(
        &self,
        id_or_alias: &str,
        discard: &[String],
        apply: bool,
        activate: bool,
    ) -> Result<Value> {
        let (id, desired) = self.baseline_files(id_or_alias).await?;
        let mut result = self
            .materialize(&format!("baseline {id}"), desired, discard, apply)
            .await?;
        if apply && result["applied"] == true && activate {
            result["active_baseline"] = json!(self.activate_baseline(&id).await?);
        }
        result["baseline"] = json!(id);
        Ok(result)
    }

    /// Writes one file's captured content from a pack (candidate or promoted).
    pub async fn materialize_resource(
        &self,
        pack_id: &str,
        path: &str,
        discard: bool,
        apply: bool,
    ) -> Result<Value> {
        crate::validate_locator(path)?;
        let pack = self.pack(pack_id).await?;
        let effect = pack
            .candidate_effects
            .iter()
            .rev()
            .find(|effect| {
                crate::resources::is_file_effect(&effect.kind) && effect.target.locator == path
            })
            .ok_or_else(|| invalid(format!("pack {pack_id} does not change {path}")))?;
        let content = match effect.kind.as_str() {
            crate::resources::DELETE => None,
            _ => Some(Self::snapshot_content(effect)?),
        };
        let desired = Desired::from([(path.to_owned(), content)]);
        let discard = if discard {
            vec![path.to_owned()]
        } else {
            vec![]
        };
        self.materialize(&format!("{path} from {pack_id}"), desired, &discard, apply)
            .await
    }
}

fn digest_of_file(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_dir() => {
            Err(invalid(format!(
                "{} is not a regular file; refusing to replace it",
                path.display()
            )))
        }
        Ok(_) => Ok(Some(sha256(&fs::read(path)?).to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Temp file in the same directory, then rename, so a crash never leaves a torn file.
/// Parent components must be real directories inside the Project (no symlink escape).
fn write_atomically(root: &Path, locator: &str, content: &[u8]) -> Result<()> {
    let mut current = root.to_path_buf();
    let parts: Vec<&str> = locator.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(invalid(format!("{} is not a directory", current.display()))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&current)?,
            Err(error) => return Err(error.into()),
        }
    }
    let target = root.join(locator);
    let temp = current.join(format!(".calve-materialize-{}", uuid::Uuid::now_v7()));
    fs::write(&temp, content)?;
    if let Err(error) = fs::rename(&temp, &target) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    Ok(())
}
