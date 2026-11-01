//! Safe materialization of accepted file state into the working tree (PLAN §27.6).
//!
//! Local content that matches no snapshot Calve knows about is uncaptured work. It blocks
//! materialization unless the user names that exact path with `--discard`; discarded content is
//! copied to `.calve/cache/discarded/` first. Writes happen inside an OpenAEVC execution whose
//! observations record every file, so the working-tree change has receipts and provenance.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use openaevc::crypto::sha256;
use openaevc::protocol::{
    Command, Digest, ExecutionRequest, PackSpec, ProviderDescriptor, Query, ResourceRef, WorkerInfo,
};
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::{Value, json};

use calve_api::responses::{
    MaterializeCompleted, MaterializeOperation, MaterializeRolledBack, MaterializeState, StepRef,
};

use crate::journal::Record;
use crate::wal::{self, Mutation, Outcome, Wal};
use crate::{Error, Project, Result, event};

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

/// Desired content per path; `None` means the path must not exist.
type Desired = BTreeMap<String, Option<Vec<u8>>>;

impl Project {
    /// Every snapshot digest this Project has recorded for each path, from any pack (the pack
    /// index, one query; never a per-pack OpenAEVC read).
    async fn known_snapshots(&self) -> Result<BTreeMap<String, BTreeSet<String>>> {
        self.file_domain().await?;
        self.refresh_pack_index().await?;
        let mut known: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut q = self.db.prepare(
            "SELECT f.path, f.digest FROM pack_files f WHERE f.digest IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM pack_commitments c
                             WHERE c.pack_id=f.pack AND c.state='replacement_pending')",
        )?;
        for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (path, digest) = row?;
            known.entry(path).or_default().insert(digest);
        }
        Ok(known)
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
        let d = self.file_domain().await?;
        // Member packs (promoted_digest ties packs to Baseline members) in creation order, by
        // the promoted-digest index rather than every pack.
        self.refresh_pack_index().await?;
        let member_packs: Vec<(String, String)> = {
            let mut q = self.db.prepare(
                "SELECT s.id, s.promoted_digest FROM pack_summaries s
                 JOIN pack_metadata m ON m.id=s.id
                 WHERE s.promoted_digest IN (SELECT value FROM json_each(?1))
                   AND NOT EXISTS (SELECT 1 FROM pack_commitments c
                                   WHERE c.pack_id=s.id AND c.state='replacement_pending')
                 ORDER BY m.created_at, m.id",
            )?;
            q.query_map([serde_json::to_string(&members)?], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<std::result::Result<_, _>>()?
        };
        for (id, digest) in member_packs {
            let promoted: Digest = digest
                .parse()
                .map_err(|_| invalid("invalid promoted digest"))?;
            self.client
                .query(Query::GetPromotedPack {
                    pack: None,
                    digest: Some(promoted),
                })
                .await?;
            for effect in self.pack(&id).await?.candidate_effects {
                if d.is_file_effect(&effect) {
                    crate::validate_locator(&effect.target.locator)?;
                    state.apply(&d, &effect)?;
                }
            }
        }
        let mut desired: Desired = Desired::new();
        for (path, content) in &state.files {
            desired.insert(path.clone(), Some(self.content_bytes(path, content).await?));
        }
        for path in state.removed {
            desired.entry(path).or_insert(None);
        }
        // Paths other accepted packs introduced are absent from this composition, so a faithful
        // switch removes them too (still only when they hold recorded content).
        // Every path accepted history wrote or removed (a full replay's files ∪ removed), from
        // the pack index without loading any content.
        self.refresh_pack_index().await?;
        let touched: Vec<String> = {
            let mut q = self.db.prepare(
                "SELECT f.path FROM pack_files f JOIN pack_summaries s ON s.id=f.pack
                 WHERE s.state='PROMOTED'
                 UNION SELECT f.from_path FROM pack_files f JOIN pack_summaries s ON s.id=f.pack
                 WHERE s.state='PROMOTED' AND f.from_path IS NOT NULL",
            )?;
            q.query_map([], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        for path in touched {
            desired.entry(path).or_insert(None);
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

    /// Paths the plan changes, refused before anything is journaled when the caller lacks the
    /// write action on any of them.
    async fn authorize_writes(&self, plan: &[Value]) -> Result<()> {
        let d = self.file_domain().await?;
        let principal = self.client.session().principal();
        for step in plan.iter().filter(|step| step["action"] != "unchanged") {
            let decision = self
                .client
                .query(Query::Authorize {
                    principal,
                    action: d.decl.write_action.clone(),
                    resource: Some(ResourceRef {
                        kind: d.decl.resource_kind.clone(),
                        locator: step["path"].as_str().unwrap_or_default().into(),
                        version: None,
                        extension: d.extension.clone(),
                    }),
                })
                .await?;
            if decision["allowed"] != true {
                return Err(invalid(format!("not authorized to write {}", step["path"])));
            }
        }
        Ok(())
    }

    /// Materialization operations that are not `Completed` or `RolledBack`.
    pub fn unfinished_materializations(&self) -> Result<Vec<MaterializeOperation>> {
        Ok(self
            .list_materializations()?
            .into_iter()
            .filter(|m| {
                !matches!(
                    m.state,
                    MaterializeState::Completed | MaterializeState::RolledBack
                )
            })
            .collect())
    }

    /// Every journaled materialization: op, label, state, unresolved conflicts.
    pub fn list_materializations(&self) -> Result<Vec<MaterializeOperation>> {
        let mut out = vec![];
        let Ok(rd) = fs::read_dir(wal::runs(&self.root)) else {
            return Ok(out);
        };
        let mut ops: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        ops.sort();
        for op in ops {
            let Ok((_, records)) = Wal::open(&self.root, &op) else {
                continue;
            };
            out.push(summary(&op, &records));
        }
        Ok(out)
    }

    /// Desired content for a recorded source (`{"baseline"}` or `{"resource", "pack"}`).
    async fn source_desired(&self, source: &Value) -> Result<Desired> {
        if let Some(b) = source["baseline"].as_str() {
            return Ok(self.baseline_files(b).await?.1);
        }
        let (pack, path) = (
            source["pack"].as_str().unwrap_or_default(),
            source["resource"].as_str().unwrap_or_default(),
        );
        self.resource_desired(pack, path).await
    }

    /// Runs `plan` through the materialization WAL (§14). Nothing is written unless every
    /// replace/delete can use atomic primitives or the caller passed `allow_unsafe_fs`.
    async fn apply_materialization(
        &self,
        label: &str,
        source: Value,
        plan: &[Value],
        allow_unsafe_fs: bool,
    ) -> Result<Value> {
        let unfinished = self.unfinished_materializations()?;
        if !unfinished.is_empty() {
            return Err(crate::detailed(
                "MATERIALIZE_CONFLICT",
                "an earlier materialization is unfinished; resume, resolve or roll it back first",
                json!({"reason": "unfinished_operation", "operations": unfinished}),
            ));
        }
        self.authorize_writes(plan).await?;
        let mutations: Vec<Mutation> = plan
            .iter()
            .filter(|s| s["action"] != "unchanged")
            .enumerate()
            .map(|(i, s)| Mutation {
                step: format!("f{}", i + 1),
                path: s["path"].as_str().unwrap_or_default().to_owned(),
                before: s["current"].as_str().map(str::to_owned),
                after: s["desired"]
                    .as_str()
                    .filter(|d| *d != "deleted")
                    .map(str::to_owned),
            })
            .collect();
        let prims = wal::primitives(&self.root);
        let unsafe_paths: Vec<&str> = mutations
            .iter()
            .filter(|m| m.before.is_some())
            .map(|m| m.path.as_str())
            .collect();
        if !prims.atomic() && !unsafe_paths.is_empty() && !allow_unsafe_fs {
            return Err(crate::detailed(
                "MATERIALIZE_CONFLICT",
                "this filesystem lacks atomic exchange/no-replace; replacing or deleting files could lose a concurrent write (rerun with --allow-unsafe-fs to accept that)",
                json!({"reason": "unsafe_fs", "primitives": prims.name(), "paths": unsafe_paths}),
            ));
        }
        let mut w = Wal::create(&self.root, json!({"project_id": self.identity.project_id}))?;
        w.j.append(
            "m.planned",
            json!({"label": label, "source": source, "mutations": mutations,
                "primitives": prims.name(), "allow_unsafe_fs": allow_unsafe_fs}),
        )
        .map_err(|e| crate::coded("RECOVERY_REQUIRED", e.to_string()))?;
        self.drive(w, vec![]).await.map(|r| {
            let mut r = serde_json::to_value(r).unwrap_or_default();
            if !prims.atomic() && allow_unsafe_fs {
                r["warning"] = json!("--allow-unsafe-fs: replaced and deleted files were preserved in backups, but a concurrent write in the final window is not detected");
            }
            r
        })
    }

    /// Drives an operation to `Completed`: settles an interrupted step, applies the rest, verifies
    /// the post-state, then records provenance. Stops at the first conflict.
    async fn drive(&self, mut w: Wal, records: Vec<Record>) -> Result<MaterializeCompleted> {
        let planned = records
            .iter()
            .find(|r| r.kind == "m.planned")
            .map(|r| r.body.clone())
            .or_else(|| {
                // A fresh journal: the planned record was just appended.
                Wal::open(&self.root, &w.op).ok().and_then(|(_, rs)| {
                    rs.into_iter()
                        .find(|r| r.kind == "m.planned")
                        .map(|r| r.body)
                })
            })
            .ok_or_else(|| {
                crate::coded("RECOVERY_REQUIRED", "materialization journal has no plan")
            })?;
        let mutations: Vec<Mutation> = serde_json::from_value(planned["mutations"].clone())?;
        let desired = self.source_desired(&planned["source"]).await?;
        let op = w.op.clone();
        let content = |m: &Mutation| -> Result<Option<Vec<u8>>> {
            let bytes = desired.get(&m.path).cloned().flatten();
            if bytes.as_deref().map(|b| sha256(b).to_string()) != m.after {
                return Err(crate::detailed(
                    "MATERIALIZE_CONFLICT",
                    format!(
                        "{}: the source no longer yields the planned content",
                        m.path
                    ),
                    json!({"reason": "source_changed", "op": op, "path": m.path}),
                ));
            }
            Ok(bytes)
        };
        let records = if records.is_empty() {
            Wal::open(&self.root, &w.op)?.1
        } else {
            records
        };
        let seen = wal::mutations(&records);
        let resolved: BTreeSet<String> = records
            .iter()
            .filter(|r| r.kind == "m.resolved")
            .filter_map(|r| r.body["step"].as_str().map(str::to_owned))
            .collect();
        let state = |s: &str| -> Option<Option<&'static str>> {
            seen.iter().find(|(m, _)| m.step == s).map(|(_, e)| *e)
        };
        for m in &mutations {
            let outcome = match state(&m.step) {
                Some(Some("done")) => continue,
                Some(Some(_)) if resolved.contains(&m.step) => continue,
                Some(Some(_)) => {
                    return Err(self.conflict_error(&w, m, "unresolved"));
                }
                Some(None) => w.reconcile(&records, m, content(m)?.as_deref())?,
                None => w.apply(m, content(m)?.as_deref())?,
            };
            if let Outcome::Conflicted(reason) = outcome {
                w.j.append("m.state", json!({"state": "Conflicted", "step": m.step}))
                    .map_err(|e| crate::coded("RECOVERY_REQUIRED", e.to_string()))?;
                return Err(self.conflict_error(&w, m, &reason));
            }
        }
        // Post-state: every planned path holds what the plan says (resolved ones as chosen).
        for m in mutations.iter().filter(|m| !resolved.contains(&m.step)) {
            let now = digest_of_file(&self.root.join(&m.path))?;
            if now != m.after {
                w.j.append("m.state", json!({"state": "Conflicted", "step": m.step}))
                    .map_err(|e| crate::coded("RECOVERY_REQUIRED", e.to_string()))?;
                return Err(self.conflict_error(&w, m, "post_verify"));
            }
        }
        if !records
            .iter()
            .any(|r| r.kind == "m.state" && r.body["state"] == "Completed")
        {
            w.j.append("m.state", json!({"state": "Completed"}))
                .map_err(|e| crate::coded("RECOVERY_REQUIRED", e.to_string()))?;
            crate::journal::fault("materialize.after_completed");
        }
        let label = planned["label"].as_str().unwrap_or_default().to_owned();
        let (execution, pack) = self
            .provenance(&mut w, &records, &label, &mutations)
            .await?;
        if planned["source"]["activate"] == true
            && let Some(b) = planned["source"]["baseline"].as_str()
        {
            self.activate_baseline(b).await?;
        }
        let written: Vec<String> = mutations.iter().map(|m| m.path.clone()).collect();
        event(&self.db, "materialized", &label, &written.len().to_string())?;
        Ok(MaterializeCompleted {
            op: w.op.clone(),
            state: MaterializeState::Completed,
            execution: execution.as_str().unwrap_or_default().to_owned(),
            provenance_pack: pack.as_str().unwrap_or_default().to_owned(),
            written,
            primitives: w.prims.name().to_owned(),
            resolved: None,
        })
    }

    fn conflict_error(&self, w: &Wal, m: &Mutation, reason: &str) -> Error {
        let artifacts = w.conflicts(&m.step);
        crate::detailed(
            "MATERIALIZE_CONFLICT",
            format!(
                "{}: {reason}; nothing was reversed. Inspect {} and run `calve materialize resolve {} --keep ours|theirs`",
                m.path,
                artifacts
                    .strip_prefix(&self.root)
                    .unwrap_or(&artifacts)
                    .display(),
                w.op
            ),
            json!({"reason": reason, "op": w.op, "step": m.step, "path": m.path,
                "artifacts": artifacts.strip_prefix(&self.root).unwrap_or(&artifacts)}),
        )
    }

    /// Provenance in an OpenAEVC execution, once per operation. An attempt interrupted before
    /// its ack is found by discovery (the `changepack.created` events after the journaled head,
    /// matched on `org.calve.materialize.op`) and abandoned; it is never blindly repeated.
    async fn provenance(
        &self,
        w: &mut Wal,
        records: &[Record],
        label: &str,
        mutations: &[Mutation],
    ) -> Result<(Value, Value)> {
        let jerr = |e: crate::journal::Error| crate::coded("RECOVERY_REQUIRED", e.to_string());
        if let Some(ack) = records.iter().rev().find(|r| r.kind == "p.ack") {
            return Ok((ack.body["execution"].clone(), ack.body["pack"].clone()));
        }
        let mut attempt = 1;
        if let Some(intent) = records.iter().rev().find(|r| r.kind == "p.intent") {
            let a = intent.body["attempt"].as_u64().unwrap_or(1);
            let tag = format!("{}:{a}", w.op);
            for e in self.events_after(intent.body["head"].as_u64().unwrap_or(0))? {
                if e.kind != "changepack.created" {
                    continue;
                }
                let Ok(id) =
                    serde_json::from_value::<openaevc::protocol::PackId>(e.body["pack"].clone())
                else {
                    continue;
                };
                let p = self.client.get_change_pack(id).await?;
                if p.metadata.get("org.calve.materialize.op") != Some(&json!(tag)) {
                    continue;
                }
                let executions = self.list_executions(Some(&id.to_string()), None).await?;
                if let Some(x) = executions
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|x| x["state"] == "SUCCEEDED")
                {
                    // The interrupted attempt finished: it is the provenance.
                    w.j.append(
                        "p.ack",
                        json!({"attempt": a, "pack": id, "execution": x["id"], "resolved_by": "discovery"}),
                    )
                    .map_err(jerr)?;
                    return Ok((x["id"].clone(), json!(id)));
                }
                for x in executions.as_array().into_iter().flatten() {
                    if matches!(
                        x["state"].as_str(),
                        Some("PENDING" | "STARTING" | "RUNNING")
                    ) && let Ok(exe) = serde_json::from_value(x["id"].clone())
                    {
                        let _ = self
                            .client
                            .command(Command::CancelExecution {
                                execution: exe,
                                reason: Some("interrupted materialization provenance".into()),
                            })
                            .await;
                    }
                }
                let p = self.client.get_change_pack(id).await?;
                if !matches!(p.state, openaevc::protocol::PackState::Abandoned) {
                    self.client
                        .command(Command::AbandonChangePack {
                            pack: id,
                            expected_generation: p.generation,
                        })
                        .await?;
                }
            }
            w.j.append("p.abandoned", json!({"attempt": a}))
                .map_err(jerr)?;
            attempt = a + 1;
        }
        let head = self.journal_head()?;
        w.j.append("p.intent", json!({"attempt": attempt, "head": head}))
            .map_err(jerr)?;
        crate::journal::fault("materialize.provenance.after_intent");
        let d = self.file_domain().await?;
        let principal = self.client.session().principal();
        // A dedicated pack carries the execution so the writes have OpenAEVC provenance; it is
        // abandoned afterwards because it proposes no candidate change.
        let pack = self
            .client
            .create_change_pack(PackSpec {
                metadata: [
                    ("org.calve.materialize".to_owned(), json!(label)),
                    (
                        "org.calve.materialize.op".to_owned(),
                        json!(format!("{}:{attempt}", w.op)),
                    ),
                ]
                .into(),
                ..PackSpec::default()
            })
            .await?;
        self.db.execute(
            "INSERT OR IGNORE INTO pack_metadata VALUES (?1,?2,NULL,?3)",
            rusqlite::params![
                pack.to_string(),
                format!("Materialize {label}"),
                crate::now()?
            ],
        )?;
        self.client
            .command(Command::RegisterProvider {
                provider: ProviderDescriptor {
                    id: d.provider(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    worker_kinds: vec![d.materialize_harness()],
                    harnesses: vec![d.materialize_harness()],
                    required_actions: vec![d.decl.write_action.clone()],
                    cancellation: true,
                    resumable: false,
                    heartbeat: false,
                    limits: BTreeMap::new(),
                    provenance_fields: vec![],
                    principal,
                },
            })
            .await?;
        let work_unit = self
            .client
            .add_work_unit(pack, 1, &d.materialize_harness())
            .await?;
        let generation = self.client.get_change_pack(pack).await?.generation;
        let (execution, lease) = self
            .client
            .start_execution(ExecutionRequest {
                pack,
                expected_generation: generation,
                work_unit,
                provider: d.provider(),
                harness: d.materialize_harness(),
                worker: Some(WorkerInfo {
                    id: "local".into(),
                    kind: d.materialize_harness(),
                    attributes: BTreeMap::new(),
                }),
                allowed_resources: vec![],
                allowed_effects: vec![],
                context: vec![],
                timeout_ms: 1_800_000,
                budget: BTreeMap::new(),
                max_attempts: 1,
                idempotency_key: format!("materialize:{}:{attempt}", w.op),
                retry_of: None,
            })
            .await?;
        let _keeper = crate::lease::LeaseKeeper::maybe(self.client.clone(), lease.clone());
        for m in mutations {
            let mut observation = json!({"op": w.op, "step": m.step, "path": m.path,
                "digest": m.after.clone().unwrap_or_else(|| "deleted".into())});
            // Canonical protocol JSON forbids null, so a created file has no `previous`.
            if let Some(b) = &m.before {
                observation["previous"] = json!(b);
                observation["backup"] = json!(
                    w.backup(&m.step)
                        .strip_prefix(&self.root)
                        .unwrap_or(&w.backup(&m.step))
                );
            }
            self.client
                .command(Command::AppendObservation {
                    execution,
                    lease: lease.id,
                    kind: format!("{}.materialized", d.extension),
                    payload: Some(observation),
                    blob: None,
                    related_resources: vec![ResourceRef {
                        kind: d.decl.resource_kind.clone(),
                        locator: m.path.clone(),
                        version: None,
                        extension: d.extension.clone(),
                    }],
                    related_effects: vec![],
                })
                .await?;
        }
        self.client.complete_execution(&lease).await?;
        let generation = self.client.get_change_pack(pack).await?.generation;
        self.client
            .command(Command::AbandonChangePack {
                pack,
                expected_generation: generation,
            })
            .await?;
        crate::journal::fault("materialize.provenance.before_ack");
        w.j.append(
            "p.ack",
            json!({"attempt": attempt, "pack": pack, "execution": execution}),
        )
        .map_err(jerr)?;
        Ok((json!(execution), json!(pack)))
    }

    /// Continues an interrupted operation (§14 reconciliation, then the remaining steps).
    pub async fn materialize_resume(&self, op: &str) -> Result<MaterializeCompleted> {
        let (w, records) = Wal::open(&self.root, op)?;
        self.drive(w, records).await
    }

    /// Resolves every unresolved conflict of `op` by keeping `ours` (the planned content) or
    /// `theirs` (the concurrent writer's displaced bytes, or what is there now), through the same
    /// WAL pattern, then continues the operation. Conflict artifacts are kept.
    pub async fn materialize_resolve(&self, op: &str, keep: &str) -> Result<MaterializeCompleted> {
        if !matches!(keep, "ours" | "theirs") {
            return Err(crate::coded("INVALID_ARGUMENT", "--keep is ours or theirs"));
        }
        let (mut w, records) = Wal::open(&self.root, op)?;
        let planned = records
            .iter()
            .find(|r| r.kind == "m.planned")
            .ok_or_else(|| {
                crate::coded("RECOVERY_REQUIRED", "materialization journal has no plan")
            })?
            .body
            .clone();
        let desired = self.source_desired(&planned["source"]).await?;
        let resolved: BTreeSet<String> = records
            .iter()
            .filter(|r| r.kind == "m.resolved")
            .filter_map(|r| r.body["step"].as_str().map(str::to_owned))
            .collect();
        let mut done = vec![];
        for (m, end) in wal::mutations(&records) {
            if end != Some("conflicted") || !m.step.starts_with('f') || resolved.contains(&m.step) {
                continue;
            }
            let artifacts = w.conflicts(&m.step);
            let chosen: Option<Option<Vec<u8>>> = match keep {
                "ours" => Some(desired.get(&m.path).cloned().flatten()),
                _ => match fs::read(artifacts.join("displaced")) {
                    Ok(b) => Some(Some(b)),
                    Err(_) => None, // theirs is what is there now
                },
            };
            if let Some(bytes) = chosen {
                let current = digest_of_file(&self.root.join(&m.path))?;
                let after = bytes.as_deref().map(|b| sha256(b).to_string());
                if current != after {
                    let x = Mutation {
                        step: format!("x{}", m.step),
                        path: m.path.clone(),
                        before: current,
                        after,
                    };
                    if let Outcome::Conflicted(reason) = w.apply(&x, bytes.as_deref())? {
                        return Err(self.conflict_error(&w, &x, &reason));
                    }
                }
            }
            w.j.append("m.resolved", json!({"step": m.step, "keep": keep}))
                .map_err(|e| crate::coded("RECOVERY_REQUIRED", e.to_string()))?;
            done.push(m.path);
        }
        let (w, records) = Wal::open(&self.root, op)?;
        let mut result = self.drive(w, records).await?;
        result.resolved = Some(done);
        Ok(result)
    }

    /// Reverses every completed step of `op`, newest first, each revalidated (path chain, current
    /// content, backup) and applied with the full WAL pattern. Unsafe reversals become conflicts
    /// with the current bytes kept; the others still run (each step is a distinct path).
    pub async fn materialize_rollback(&self, op: &str, yes: bool) -> Result<MaterializeRolledBack> {
        if !yes {
            return Err(crate::coded(
                "CONFIRMATION_REQUIRED",
                "rolling back rewrites working-tree files; rerun with --yes",
            ));
        }
        let (mut w, records) = Wal::open(&self.root, op)?;
        let forward: Vec<Mutation> = wal::mutations(&records)
            .into_iter()
            .filter(|(m, end)| *end == Some("done") && m.step.starts_with('f'))
            .map(|(m, _)| m)
            .collect();
        let reversed: BTreeSet<String> = wal::mutations(&records)
            .into_iter()
            .filter(|(m, end)| *end == Some("done") && m.step.starts_with('r'))
            .map(|(m, _)| m.step[1..].to_owned())
            .collect();
        let (mut ok, mut conflicts) = (vec![], vec![]);
        for m in forward.iter().rev().filter(|m| !reversed.contains(&m.step)) {
            match w.reverse(m)? {
                Outcome::Done => ok.push(m.path.clone()),
                Outcome::Conflicted(reason) => conflicts.push(json!({"path": m.path, "reason": reason,
                    "artifacts": w.conflicts(&format!("r{}", m.step)).strip_prefix(&self.root).unwrap_or(&w.conflicts("")).to_path_buf()})),
            }
        }
        let state = if conflicts.is_empty() {
            "RolledBack"
        } else {
            "Conflicted"
        };
        w.j.append("m.state", json!({"state": state, "rollback": true}))
            .map_err(|e| crate::coded("RECOVERY_REQUIRED", e.to_string()))?;
        if !conflicts.is_empty() {
            return Err(crate::detailed(
                "MATERIALIZE_CONFLICT",
                format!(
                    "{} reversal(s) were unsafe and were not applied; their current content is kept",
                    conflicts.len()
                ),
                json!({"reason": "rollback", "op": op, "reverted": ok, "conflicts": conflicts}),
            ));
        }
        Ok(MaterializeRolledBack {
            op: op.to_owned(),
            state: MaterializeState::RolledBack,
            reverted: ok,
        })
    }

    async fn materialize(
        &self,
        label: &str,
        source: Value,
        desired: Desired,
        discard: &[String],
        apply: bool,
        allow_unsafe_fs: bool,
    ) -> Result<Value> {
        let plan = self.materialization_plan(&desired, discard).await?;
        let blocked: Vec<&Value> = plan
            .iter()
            .filter(|step| step["action"] == "blocked_uncaptured_changes")
            .collect();
        if !apply || !blocked.is_empty() {
            return Ok(json!({"applied":false,"plan":plan,
            "code":(!blocked.is_empty()).then_some("UNSAFE_MATERIALIZATION"),
            "blocked":blocked.iter().map(|step| step["path"].clone()).collect::<Vec<_>>(),
            "note": if blocked.is_empty() {
                "review the plan, then rerun with --apply"
            } else {
                "local files hold uncaptured changes; capture them, or name each with --discard to back it up and overwrite"
            }}));
        }
        let mut result = self
            .apply_materialization(label, source, &plan, allow_unsafe_fs)
            .await?;
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
        allow_unsafe_fs: bool,
    ) -> Result<Value> {
        let (id, desired) = self.baseline_files(id_or_alias).await?;
        let source = json!({"baseline": id, "activate": activate});
        let mut result = self
            .materialize(
                &format!("baseline {id}"),
                source,
                desired,
                discard,
                apply,
                allow_unsafe_fs,
            )
            .await?;
        if result["applied"] == true && activate {
            result["active_baseline"] = json!(id);
        }
        result["baseline"] = json!(id);
        Ok(result)
    }

    async fn resource_desired(&self, pack_id: &str, path: &str) -> Result<Desired> {
        crate::validate_locator(path)?;
        let pack = self.pack(pack_id).await?;
        let d = self.file_domain().await?;
        let effect = pack
            .candidate_effects
            .iter()
            .rev()
            .find(|effect| d.is_file_effect(effect) && effect.target.locator == path)
            .ok_or_else(|| invalid(format!("pack {pack_id} does not change {path}")))?;
        let content = match d.op(&effect.kind) {
            Some(crate::domains::FileOp::Delete) => None,
            _ => {
                let c = crate::resources::effect_file_content(&d, effect).ok_or_else(|| {
                    crate::coded(
                        "CONTENT_CORRUPT",
                        format!("snapshot of {path} fails its digest"),
                    )
                })?;
                Some(self.content_bytes(path, &c).await?)
            }
        };
        Ok(Desired::from([(path.to_owned(), content)]))
    }

    /// Writes one file's captured content from a pack (candidate or promoted).
    pub async fn materialize_resource(
        &self,
        pack_id: &str,
        path: &str,
        discard: bool,
        apply: bool,
        allow_unsafe_fs: bool,
    ) -> Result<Value> {
        let desired = self.resource_desired(pack_id, path).await?;
        let discard = if discard {
            vec![path.to_owned()]
        } else {
            vec![]
        };
        let source = json!({"pack": pack_id, "resource": path});
        self.materialize(
            &format!("{path} from {pack_id}"),
            source,
            desired,
            &discard,
            apply,
            allow_unsafe_fs,
        )
        .await
    }
}

/// The summary of one journal.
fn summary(op: &str, records: &[Record]) -> MaterializeOperation {
    let label = records
        .iter()
        .find(|r| r.kind == "m.planned")
        .and_then(|r| r.body["label"].as_str().map(str::to_owned));
    let resolved: BTreeSet<&str> = records
        .iter()
        .filter(|r| r.kind == "m.resolved")
        .filter_map(|r| r.body["step"].as_str())
        .collect();
    let conflicts = wal::mutations(records)
        .into_iter()
        .filter(|(m, end)| *end == Some("conflicted") && !resolved.contains(m.step.as_str()))
        .map(|(m, _)| StepRef {
            step: m.step,
            path: m.path,
        })
        .collect();
    let state = match records
        .iter()
        .rev()
        .find(|r| r.kind == "m.state")
        .and_then(|r| r.body["state"].as_str())
    {
        // Completed only counts once provenance is recorded.
        Some("Completed") if records.iter().any(|r| r.kind == "p.ack") => {
            MaterializeState::Completed
        }
        Some("Conflicted") => MaterializeState::Conflicted,
        Some("RolledBack") => MaterializeState::RolledBack,
        _ => MaterializeState::Interrupted,
    };
    MaterializeOperation {
        op: op.to_owned(),
        label,
        state,
        conflicts,
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
