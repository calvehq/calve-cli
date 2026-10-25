//! Supersede saga (rev 10 §12, ADR 0011; N23): replace pack P by a new pack P' holding exactly
//! P's first `m` effects, across OpenAEVC, the product database and a journal.
//!
//! Steps (journal `.calve/run/supersede/<id>.journal`, every OpenAEVC command through the exact
//! envelope helper, [`Project::send_journaled`]):
//! S0 `Planned` (reference CCE/RSE of P's first m effects, generation, effect count, executions,
//! commitment version, journal head) → S1 `CaptureClosed` (active executions on P cancelled) →
//! S2 `ReplacementCreated` (P' with `calve.supersede_id`; product state `replacement_pending`,
//! hidden) → S3 `ReplayStarted` → S4 replay of each proposal not yet present in P' →
//! S5 `ReplayCompleted` → S6 `Verified` (P' RSE and CCE equal the reference, else
//! `SUPERSEDE_DIVERGED`) → S6b `Revalidated` (final re-read of P and P', else
//! `SUPERSEDE_CONFLICT`) → S7 `ProductRelinked` (compare-and-swap on P's commitment version) →
//! S8 `OriginalAbandoned` (expected generation; a refusal is `SUPERSEDE_CONFLICT`) → S9 `Done`.
//! Compensation: C1 abandons P' (a refusal is `RECOVERY_REQUIRED(supersede)`, both packs kept),
//! C2 undoes the relink with compare-and-swap, C3 `Conflicted`. P is abandoned last, so until S8
//! the user always keeps a usable pack, and P' is never active before S7.
//!
//! Plan delta (recorded in ADR 0011): effects appended to P by another client after S0 leave P'
//! equal to the reference, so they are caught at S6b (`SUPERSEDE_CONFLICT`), as the §12 step
//! table specifies, rather than at S6.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use openaevc::protocol::{
    AppliedEffect, ChangePack, Command, EffectProposal, ExecutionId, ExecutionRequest, Lease,
    PackId, PackSpec, PackState, ProviderDescriptor, ResourceSelector, WorkerInfo,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::capture::{applied_projection, proposal_projection};
use crate::envelope::Resolution;
use crate::journal::{Journal, Record};
use crate::{Error, Project, Result};

pub const DONE: &str = "Done";
const TERMINAL: &[&str] = &[DONE, "Conflicted", "RecoveryRequired"];

pub fn dir(root: &Path) -> PathBuf {
    root.join(".calve/run/supersede")
}

fn corrupt(e: impl std::fmt::Display) -> Error {
    crate::detailed(
        "RECOVERY_REQUIRED",
        format!("supersede journal: {e}"),
        json!({"reason": "journal_corrupt"}),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SagaSpool {
    pack: PackId,
    proposals: Vec<EffectProposal>,
    provider: ProviderDescriptor,
    harness: String,
    allowed_resources: Vec<ResourceSelector>,
    allowed_effects: Vec<String>,
}

/// Merged state records of a saga: the last `state` and every recorded value.
struct Saga {
    state: String,
    data: serde_json::Map<String, Value>,
    pending: Option<Value>,
}

fn read_saga(records: &[Record]) -> Saga {
    let mut saga = Saga {
        state: "Planned".into(),
        data: Default::default(),
        pending: None,
    };
    for r in records {
        match r.kind.as_str() {
            "state" => {
                if let Some(o) = r.body.as_object() {
                    for (k, v) in o {
                        saga.data.insert(k.clone(), v.clone());
                    }
                }
                if let Some(s) = r.body["state"].as_str() {
                    saga.state = s.to_owned();
                }
                saga.pending = None;
            }
            "intent" => saga.pending = Some(r.body.clone()),
            "ack" => saga.pending = None,
            _ => {}
        }
    }
    saga
}

/// `{pack: (saga, state)}` of sagas that have not finished.
pub fn pending(root: &Path) -> Result<BTreeMap<String, (String, String)>> {
    let mut out = BTreeMap::new();
    let Ok(rd) = fs::read_dir(dir(root)) else {
        return Ok(out);
    };
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "journal") {
            continue;
        }
        let opened = Journal::open(&path).map_err(corrupt)?;
        let saga = read_saga(&opened.records);
        if !TERMINAL.contains(&saga.state.as_str()) {
            let id = opened.journal.header["journal_id"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            let pack = opened.journal.header["binding"]["pack"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            out.insert(pack, (id, saga.state));
        }
    }
    Ok(out)
}

/// Every saga with its state (`supersede list`).
/// Whether the saga journal at `path` reached `Done`.
pub(crate) fn finished(path: &Path) -> bool {
    Journal::open(path).is_ok_and(|o| read_saga(&o.records).state == DONE)
}

/// `calve supersede list`, through its contract type (an unknown state is a corrupt journal).
pub fn list(root: &Path) -> Result<Vec<calve_api::responses::SupersedeSaga>> {
    let mut out: Vec<Value> = vec![];
    let Ok(rd) = fs::read_dir(dir(root)) else {
        return Ok(vec![]);
    };
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "journal") {
            continue;
        }
        let opened = Journal::open(&path).map_err(corrupt)?;
        let s = read_saga(&opened.records);
        out.push(json!({"saga": opened.journal.header["journal_id"], "pack": opened.journal.header["binding"]["pack"],
            "state": s.state, "replacement": s.data.get("replacement"), "outcome": s.data.get("outcome")}));
    }
    serde_json::from_value(Value::Array(out)).map_err(|e| corrupt(format!("supersede saga: {e}")))
}

/// File state (path → digest) of an effect list, the resource-state manifest (RSE, §12).
pub(crate) fn resource_state(
    d: Option<&crate::domains::FileDomain>,
    effects: &[AppliedEffect],
) -> String {
    let mut files: BTreeMap<String, Option<String>> = BTreeMap::new();
    for e in effects {
        let op = d.and_then(|d| d.op(&e.kind));
        match op {
            Some(crate::domains::FileOp::Delete) => {
                files.insert(e.target.locator.clone(), None);
            }
            Some(crate::domains::FileOp::Move) => {
                if let Some(from) = e.payload["from"].as_str() {
                    files.insert(from.to_owned(), None);
                }
                files.insert(
                    e.target.locator.clone(),
                    e.payload["digest"].as_str().map(str::to_owned),
                );
            }
            _ => {
                files.insert(
                    e.target.locator.clone(),
                    e.payload["digest"].as_str().map(str::to_owned),
                );
            }
        }
    }
    // Absent and deleted are the same resource state.
    files.retain(|_, digest| digest.is_some());
    crate::journal::sha256_hex(&crate::journal::jcs(&json!(files)))
}

/// Ordered candidate-content projection digest (CCE, §12).
fn cce(effects: &[AppliedEffect]) -> String {
    let p: Vec<String> = effects.iter().map(applied_projection).collect();
    crate::journal::sha256_hex(&crate::journal::jcs(&json!(p)))
}

fn cce_proposals(proposals: &[EffectProposal]) -> String {
    let p: Vec<String> = proposals.iter().map(proposal_projection).collect();
    crate::journal::sha256_hex(&crate::journal::jcs(&json!(p)))
}

impl Project {
    fn saga_paths(&self, id: &str) -> (PathBuf, PathBuf) {
        let d = dir(&self.root);
        (
            d.join(format!("{id}.journal")),
            d.join(format!("{id}.spool.json")),
        )
    }

    fn commitment(&self, pack: &str) -> Result<(String, i64)> {
        Ok(self
            .db
            .query_row(
                "SELECT state, commitment_version FROM pack_commitments WHERE pack_id=?1",
                [pack],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or_else(|_| ("active".into(), 0)))
    }

    async fn non_terminal_executions(&self, pack: &str) -> Result<Vec<ExecutionId>> {
        let all = self.list_executions(Some(pack), None).await?;
        Ok(all
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| {
                matches!(
                    e["state"].as_str(),
                    Some("PENDING" | "STARTING" | "RUNNING")
                )
            })
            .filter_map(|e| serde_json::from_value(e["id"].clone()).ok())
            .collect())
    }

    /// S0: plans the replacement of `pack` by its first `keep` effects.
    pub async fn supersede_pack(
        &self,
        pack: &str,
        keep: usize,
        capture: Option<&str>,
    ) -> Result<Value> {
        let p = self.pack(pack).await?;
        if p.state != PackState::Open {
            return Err(crate::coded(
                "OPENAEVC_OPERATION_REJECTED",
                format!(
                    "only an OPEN pack can be superseded; {pack} is {}",
                    p.state.as_str()
                ),
            ));
        }
        if keep > p.candidate_effects.len() {
            return Err(crate::coded(
                "INVALID_ARGUMENT",
                format!(
                    "--keep {keep} exceeds the pack's {} effects",
                    p.candidate_effects.len()
                ),
            ));
        }
        if let Some((saga, state)) = pending(&self.root)?.get(pack) {
            return Err(crate::detailed(
                "SUPERSEDE_CONFLICT",
                format!(
                    "{pack} is already being superseded by {saga} ({state}); resume it with `calve supersede resume {saga}`"
                ),
                json!({"saga": saga, "state": state}),
            ));
        }
        let d = self.file_domain().await?;
        let reference = &p.candidate_effects[..keep];
        if reference.iter().any(|e| !d.is_file_effect(e)) {
            return Err(crate::coded(
                "INVALID_ARGUMENT",
                "only file-domain effects can be replayed into a replacement pack; use `capture rollback --mode compensate`",
            ));
        }
        let proposals: Vec<EffectProposal> = reference
            .iter()
            .map(|e| EffectProposal {
                kind: e.kind.clone(),
                target: e.target.clone(),
                payload: e.payload.clone(),
                preconditions: e.preconditions.clone(),
                outputs: e.outputs.clone(),
            })
            .collect();
        let harness = format!("{}.supersede", d.extension);
        let spool = SagaSpool {
            pack: p.id,
            provider: ProviderDescriptor {
                id: format!("{}.supersede", d.provider()),
                version: "0.1.0".into(),
                worker_kinds: vec![harness.clone()],
                harnesses: vec![harness.clone()],
                required_actions: vec![d.decl.write_action.clone()],
                cancellation: true,
                resumable: false,
                heartbeat: false,
                limits: BTreeMap::new(),
                provenance_fields: vec![],
                principal: self.identity.created_by,
            },
            harness,
            allowed_resources: proposals
                .iter()
                .map(|p| ResourceSelector {
                    kind: p.target.kind.clone(),
                    locator_prefix: Some(p.target.locator.clone()),
                })
                .collect(),
            allowed_effects: {
                let mut k: Vec<String> = proposals.iter().map(|p| p.kind.clone()).collect();
                k.sort();
                k.dedup();
                k
            },
            proposals,
        };
        let id = format!("sup_{}", uuid::Uuid::now_v7());
        fs::create_dir_all(dir(&self.root))?;
        let (jp, sp) = self.saga_paths(&id);
        let bytes = serde_json::to_vec(&spool)?;
        let tmp = sp.with_extension("tmp");
        fs::write(&tmp, &bytes)?;
        crate::journal::sync_file(&tmp)?;
        fs::rename(&tmp, &sp)?;
        let (_, version) = self.commitment(pack)?;
        let mut j = Journal::create(
            &jp,
            "supersede",
            &id,
            json!({"project_id": self.identity.project_id, "namespace_id": self.identity.namespace_id,
                "genesis_hash": crate::continuity::binding(&self.db)?.map(|b| b.genesis_hash), "pack": pack}),
        )
        .map_err(corrupt)?;
        j.append(
            "state",
            json!({"state": "Planned", "pack": pack, "m": keep, "total": p.candidate_effects.len(),
                "generation_s0": p.generation, "reference_cce": cce(reference),
                "reference_rse": resource_state(Some(&d), reference), "commitment_version": version,
                "executions_s0": self.list_executions(Some(pack), None).await?.as_array().into_iter().flatten()
                    .map(|e| e["id"].clone()).collect::<Vec<_>>(),
                "head": self.journal_head()?, "spool_sha256": crate::journal::sha256_hex(&bytes),
                "capture_session": capture}),
        )
        .map_err(corrupt)?;
        crate::journal::fault("supersede.S0");
        drop(j);
        self.drive_supersede(&id).await
    }

    pub async fn resume_supersede(&self, id: &str) -> Result<Value> {
        self.drive_supersede(id).await
    }

    fn saga_state(j: &mut Journal, state: &str, extra: Value) -> Result<()> {
        let mut body = json!({"state": state});
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        j.append("state", body).map_err(corrupt)?;
        crate::journal::fault(&format!("supersede.{state}"));
        Ok(())
    }

    /// Replacement packs carrying this saga id, oldest first (FG8: event scan, metadata).
    async fn discover_replacements(&self, id: &str, head: u64) -> Result<Vec<ChangePack>> {
        let mut out = vec![];
        for e in self.events_after(head)? {
            if e.kind != "changepack.created" {
                continue;
            }
            for s in e.subjects.iter().filter(|s| s.starts_with("cpk_")) {
                if let Ok(p) = self.pack(s).await
                    && p.metadata.get("calve.supersede_id").and_then(Value::as_str) == Some(id)
                    && !out.iter().any(|x: &ChangePack| x.id == p.id)
                {
                    out.push(p);
                }
            }
        }
        Ok(out)
    }

    async fn settle_saga_intent(
        &self,
        j: &mut Journal,
        intent: &Value,
        saga: &Saga,
        spool: &SagaSpool,
    ) -> Result<()> {
        let step = intent["step"].as_str().unwrap_or_default().to_owned();
        if let Resolution::Replayed(outcome) = self.resolve_intent(intent)? {
            return Self::ack_resolved(j, &step, &outcome, "replay");
        }
        let id = j.header["journal_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let found: Option<Value> = if step == "create" {
            let head = saga.data.get("head").and_then(Value::as_u64).unwrap_or(0);
            self.discover_replacements(&id, head)
                .await?
                .first()
                .map(|p| json!({"id": p.id}))
        } else if let Some(exe) = step.strip_prefix("cancel.") {
            let s = self.execution(exe).await?;
            (!matches!(
                s["state"].as_str(),
                Some("PENDING" | "STARTING" | "RUNNING")
            ))
            .then(|| json!({"state": s["state"]}))
        } else if let Some(n) = step.strip_prefix("work_unit.") {
            let n: u64 = n.parse().unwrap_or(0);
            match saga.data.get("replacement").and_then(Value::as_str) {
                Some(r) => self
                    .pack(r)
                    .await?
                    .work_units
                    .iter()
                    .find(|w| {
                        w.spec.as_ref().is_some_and(|s| {
                            s["calve.supersede"] == id.as_str() && s["attempt"] == n
                        })
                    })
                    .map(|w| json!({"id": w.id})),
                None => None,
            }
        } else if let Some(rest) = step.strip_prefix("replay.") {
            let i: usize = rest
                .rsplit('.')
                .next()
                .and_then(|i| i.parse().ok())
                .unwrap_or(usize::MAX);
            match (
                saga.data.get("replacement").and_then(Value::as_str),
                spool.proposals.get(i),
            ) {
                (Some(r), Some(p)) => {
                    let want = proposal_projection(p);
                    self.pack(r)
                        .await?
                        .candidate_effects
                        .iter()
                        .any(|e| applied_projection(e) == want)
                        .then(|| json!({"state": "APPLIED"}))
                }
                _ => None,
            }
        } else if let Some(n) = step.strip_prefix("complete.") {
            let exe = saga
                .data
                .get(&format!("execution.{n}"))
                .and_then(Value::as_str);
            match exe {
                Some(exe) => (self.execution(exe).await?["state"] == "SUCCEEDED")
                    .then(|| json!({"state": "SUCCEEDED"})),
                None => None,
            }
        } else if step == "abandon_original"
            || step == "abandon_replacement"
            || step.starts_with("abandon_duplicate.")
        {
            let pack = match step.as_str() {
                "abandon_original" => saga
                    .data
                    .get("pack")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                "abandon_replacement" => saga
                    .data
                    .get("replacement")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                s => s.strip_prefix("abandon_duplicate.").map(str::to_owned),
            };
            match pack {
                Some(p) => (self.pack(&p).await?.state == PackState::Abandoned)
                    .then(|| json!({"state": "ABANDONED"})),
                None => None,
            }
        } else {
            None
        };
        let outcome = match found {
            Some(result) => json!({"receipt": {"result": result, "discovered": true}}),
            None => json!({"not_applied": true}),
        };
        j.append(
            "ack",
            json!({"step": step, "outcome": outcome, "resolved_by": "discovery"}),
        )
        .map_err(corrupt)?;
        Ok(())
    }

    fn acked(records: &[Record], step: &str) -> Option<Value> {
        records
            .iter()
            .rev()
            .find(|r| r.kind == "ack" && r.body["step"] == step)
            .and_then(|r| {
                r.body["outcome"]
                    .get("receipt")
                    .map(|x| x["result"].clone())
            })
    }

    async fn drive_supersede(&self, id: &str) -> Result<Value> {
        use openaevc_sdk::OpenAevcClient as _;
        let (jp, sp) = self.saga_paths(id);
        let opened = Journal::open(&jp).map_err(corrupt)?;
        let mut j = opened.journal;
        let mut saga = read_saga(&opened.records);
        let bytes = fs::read(&sp)?;
        if saga.data.get("spool_sha256").and_then(Value::as_str)
            != Some(&crate::journal::sha256_hex(&bytes))
        {
            return Err(corrupt("the spool does not match its journal"));
        }
        let spool: SagaSpool = serde_json::from_slice(&bytes)?;
        // The S7 relink is a product-database step (no envelope); its branch is idempotent.
        if let Some(intent) = saga.pending.clone().filter(|i| i["step"] != "relink") {
            self.settle_saga_intent(&mut j, &intent, &saga, &spool)
                .await?;
        }
        let pfx = "supersede";
        let pack_id = saga.data["pack"].as_str().unwrap_or_default().to_owned();
        loop {
            let records = Journal::open(&jp).map_err(corrupt)?.records;
            saga = read_saga(&records);
            match saga.state.as_str() {
                "Planned" => {
                    // S1: close capture / other executions on P (effects stay, F19); cancel first (FG9).
                    for exe in self.non_terminal_executions(&pack_id).await? {
                        let _ = self.send_journaled(
                            &mut j,
                            pfx,
                            &format!("cancel.{exe}"),
                            Command::CancelExecution {
                                execution: exe,
                                reason: Some(format!("superseded by {id}")),
                            },
                        )?;
                    }
                    if !self.non_terminal_executions(&pack_id).await?.is_empty() {
                        return Err(crate::detailed(
                            "SUPERSEDE_CONFLICT",
                            "an execution on the pack could not be cancelled",
                            json!({"saga": id}),
                        ));
                    }
                    let g = self.pack(&pack_id).await?.generation;
                    Self::saga_state(
                        &mut j,
                        "CaptureClosed",
                        json!({"generation_after_close": g}),
                    )?;
                }
                "CaptureClosed" => {
                    // S2: never create twice; a lost journal plus duplicates is compensated.
                    let head = saga.data.get("head").and_then(Value::as_u64).unwrap_or(0);
                    let mut existing = self.discover_replacements(id, head).await?;
                    if existing.is_empty() && Self::acked(&records, "create").is_none() {
                        let p = self.pack(&pack_id).await?;
                        let mut metadata = p.metadata.clone();
                        metadata.insert("calve.supersede_id".into(), json!(id));
                        metadata.insert("calve.replaces".into(), json!(pack_id));
                        let out = self.send_journaled(
                            &mut j,
                            pfx,
                            "create",
                            Command::CreateChangePack {
                                spec: PackSpec {
                                    intent: p.intent.clone(),
                                    required_policies: p.required_policies.clone(),
                                    metadata,
                                    ..PackSpec::default()
                                },
                            },
                        )?;
                        out.map_err(Error::from)?;
                        existing = self.discover_replacements(id, head).await?;
                    }
                    let Some(first) = existing.first().cloned() else {
                        return Err(corrupt("the replacement pack was not found"));
                    };
                    for dup in existing.iter().skip(1) {
                        let _ = self.send_journaled(
                            &mut j,
                            pfx,
                            &format!("abandon_duplicate.{}", dup.id),
                            Command::AbandonChangePack {
                                pack: dup.id,
                                expected_generation: dup.generation,
                            },
                        )?;
                    }
                    let title: String = self
                        .db
                        .query_row(
                            "SELECT title FROM pack_metadata WHERE id=?1",
                            [&pack_id],
                            |r| r.get(0),
                        )
                        .unwrap_or_else(|_| pack_id.clone());
                    self.db.execute(
                        "INSERT OR IGNORE INTO pack_metadata VALUES (?1,?2,NULL,?3)",
                        rusqlite::params![first.id.to_string(), title, crate::now()?],
                    )?;
                    self.db.execute(
                        "INSERT INTO pack_commitments(pack_id,state,commitment_version,supersede_id,replaces) VALUES (?1,'replacement_pending',0,?2,?3)
                         ON CONFLICT(pack_id) DO UPDATE SET state='replacement_pending', supersede_id=excluded.supersede_id, replaces=excluded.replaces",
                        rusqlite::params![first.id.to_string(), id, pack_id],
                    )?;
                    Self::saga_state(
                        &mut j,
                        "ReplacementCreated",
                        json!({"replacement": first.id,
                        "duplicates_compensated": existing.iter().skip(1).map(|p| p.id).collect::<Vec<_>>()}),
                    )?;
                }
                "ReplacementCreated" | "ReplayStarted" => {
                    let replacement = saga.data["replacement"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    self.client
                        .command(Command::RegisterProvider {
                            provider: spool.provider.clone(),
                        })
                        .await?;
                    // S3: work unit + execution for the current attempt.
                    let n = saga
                        .data
                        .get("attempt")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        + u64::from(
                            saga.state == "ReplacementCreated"
                                || saga.data.get("lost") == Some(&json!(true)),
                        );
                    let n = n.max(1);
                    let (exe, lease): (ExecutionId, Lease) = match (
                        saga.data
                            .get(&format!("execution.{n}"))
                            .and_then(|v| serde_json::from_value(v.clone()).ok()),
                        saga.data
                            .get(&format!("lease.{n}"))
                            .and_then(|v| serde_json::from_value(v.clone()).ok()),
                    ) {
                        (Some(e), Some(l)) if saga.data.get("lost") != Some(&json!(true)) => (e, l),
                        _ => {
                            let wu = match Self::acked(&records, &format!("work_unit.{n}")) {
                                Some(r) => r["id"].as_str().and_then(|s| s.parse().ok()),
                                None => {
                                    let g = self.pack(&replacement).await?.generation;
                                    let out = self.send_journaled(
                                        &mut j,
                                        pfx,
                                        &format!("work_unit.{n}"),
                                        Command::AddWorkUnit {
                                            pack: replacement
                                                .parse()
                                                .map_err(|_| corrupt("replacement id"))?,
                                            expected_generation: g,
                                            kind: spool.harness.clone(),
                                            spec: Some(
                                                json!({"calve.supersede": id, "attempt": n}),
                                            ),
                                            depends_on: vec![],
                                        },
                                    )?;
                                    out.map_err(Error::from)?
                                        .result
                                        .id
                                        .as_deref()
                                        .and_then(|s| s.parse().ok())
                                }
                            }
                            .ok_or_else(|| {
                                crate::coded("INTERNAL", "AddWorkUnit returned no id")
                            })?;
                            let g = self.pack(&replacement).await?.generation;
                            let out = self.send_journaled(
                                &mut j,
                                pfx,
                                &format!("start.{n}"),
                                Command::StartExecution {
                                    request: ExecutionRequest {
                                        pack: replacement
                                            .parse()
                                            .map_err(|_| corrupt("replacement id"))?,
                                        expected_generation: g,
                                        work_unit: wu,
                                        provider: spool.provider.id.clone(),
                                        harness: spool.harness.clone(),
                                        worker: Some(WorkerInfo {
                                            id: "local".into(),
                                            kind: spool.harness.clone(),
                                            attributes: Default::default(),
                                        }),
                                        allowed_resources: spool.allowed_resources.clone(),
                                        allowed_effects: spool.allowed_effects.clone(),
                                        context: vec![],
                                        timeout_ms: 1_800_000,
                                        budget: Default::default(),
                                        max_attempts: 8,
                                        idempotency_key: format!("{id}:replay:{n}"),
                                        retry_of: None,
                                    },
                                },
                            )?;
                            let r = out.map_err(Error::from)?;
                            let exe: ExecutionId = r
                                .result
                                .id
                                .as_deref()
                                .and_then(|s| s.parse().ok())
                                .ok_or_else(|| {
                                    crate::coded("INTERNAL", "StartExecution returned no id")
                                })?;
                            let lease = r
                                .result
                                .lease
                                .clone()
                                .ok_or_else(|| crate::coded("INTERNAL", "no lease"))?;
                            Self::saga_state(
                                &mut j,
                                "ReplayStarted",
                                json!({"attempt": n, "lost": false,
                                format!("execution.{n}"): exe, format!("lease.{n}"): lease}),
                            )?;
                            (exe, lease)
                        }
                    };
                    // S4: replay each proposal not yet in P'.
                    let present: Vec<String> = self
                        .pack(&replacement)
                        .await?
                        .candidate_effects
                        .iter()
                        .map(applied_projection)
                        .collect();
                    let mut lost = false;
                    for (i, p) in spool.proposals.iter().enumerate() {
                        if present.contains(&proposal_projection(p)) {
                            continue;
                        }
                        let out = self.send_journaled(
                            &mut j,
                            pfx,
                            &format!("replay.{n}.{i}"),
                            Command::SubmitEffectProposal {
                                execution: exe,
                                lease: lease.id,
                                effect: p.clone(),
                            },
                        )?;
                        match out {
                            Ok(r) if r.result.state.as_deref() == Some("APPLIED") => {}
                            Ok(_) => {
                                return self
                                    .compensate(
                                        &mut j,
                                        id,
                                        "SUPERSEDE_DIVERGED",
                                        json!({"refused_replay": i}),
                                    )
                                    .await;
                            }
                            Err(_) => {
                                lost = true;
                                break;
                            }
                        }
                    }
                    if lost {
                        Self::saga_state(&mut j, "ReplayStarted", json!({"lost": true}))?;
                        continue;
                    }
                    // S5.
                    let out = self.send_journaled(
                        &mut j,
                        pfx,
                        &format!("complete.{n}"),
                        Command::CompleteExecution {
                            execution: exe,
                            lease: lease.id,
                        },
                    )?;
                    if out.is_err()
                        && self.execution(&exe.to_string()).await?["state"] != "SUCCEEDED"
                    {
                        Self::saga_state(&mut j, "ReplayStarted", json!({"lost": true}))?;
                        continue;
                    }
                    let g = self.pack(&replacement).await?.generation;
                    Self::saga_state(
                        &mut j,
                        "ReplayCompleted",
                        json!({"replacement_generation": g}),
                    )?;
                }
                "ReplayCompleted" => {
                    // S6: P' equals the reference by resource state and by candidate content.
                    let replacement = saga.data["replacement"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    let p2 = self.pack(&replacement).await?;
                    let d = self.file_domain().await.ok();
                    let (got_rse, got_cce) = (
                        resource_state(d.as_ref(), &p2.candidate_effects),
                        cce(&p2.candidate_effects),
                    );
                    if Some(got_rse.as_str()) != saga.data["reference_rse"].as_str()
                        || Some(got_cce.as_str()) != saga.data["reference_cce"].as_str()
                        || cce_proposals(&spool.proposals) != got_cce
                    {
                        return self.compensate(&mut j, id, "SUPERSEDE_DIVERGED",
                            json!({"reference_rse": saga.data["reference_rse"], "replacement_rse": got_rse,
                                "reference_cce": saga.data["reference_cce"], "replacement_cce": got_cce})).await;
                    }
                    Self::saga_state(&mut j, "Verified", json!({}))?;
                }
                "Verified" => {
                    // S6b: final re-read immediately before relinking.
                    let p = self.pack(&pack_id).await?;
                    let replacement = saga.data["replacement"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    let p2 = self.pack(&replacement).await?;
                    let mut problems = vec![];
                    if p.state != PackState::Open {
                        problems.push(format!("{pack_id} is {}", p.state.as_str()));
                    }
                    if Some(p.generation) != saga.data["generation_after_close"].as_u64() {
                        problems.push(format!("{pack_id} generation moved to {}", p.generation));
                    }
                    if Some(p.candidate_effects.len() as u64) != saga.data["total"].as_u64() {
                        problems.push(format!(
                            "{pack_id} now has {} effects, {} at the start",
                            p.candidate_effects.len(),
                            saga.data["total"]
                        ));
                    }
                    let known: Vec<Value> = saga.data["executions_s0"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let now = self.list_executions(Some(&pack_id), None).await?;
                    if now
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|e| !known.contains(&e["id"]))
                    {
                        problems.push(format!(
                            "an execution was started on {pack_id} during the supersession"
                        ));
                    }
                    if cce(&p2.candidate_effects) != cce_proposals(&spool.proposals) {
                        problems.push(format!("{replacement} has effects other than the replay"));
                    }
                    if !problems.is_empty() {
                        return self
                            .compensate(
                                &mut j,
                                id,
                                "SUPERSEDE_CONFLICT",
                                json!({"revalidation": problems}),
                            )
                            .await;
                    }
                    Self::saga_state(&mut j, "Revalidated", json!({}))?;
                }
                "Revalidated" => {
                    // S7: one transaction, compare-and-swap on P's commitment version.
                    let replacement = saga.data["replacement"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    let (state, _) = self.commitment(&pack_id)?;
                    if state != "superseded" {
                        let v0 = saga.data["commitment_version"].as_i64().unwrap_or(0);
                        let before: Vec<String> = {
                            let mut st = self.db.prepare("SELECT task_id FROM task_links WHERE kind='pack' AND object_id=?1 ORDER BY task_id")?;
                            st.query_map([&pack_id], |r| r.get(0))?
                                .collect::<std::result::Result<_, _>>()?
                        };
                        let intent: Option<String> = self
                            .db
                            .query_row(
                                "SELECT intent_id FROM pack_metadata WHERE id=?1",
                                [&pack_id],
                                |r| r.get(0),
                            )
                            .unwrap_or(None);
                        j.append("intent", json!({"step": "relink", "before": {"tasks": before, "intent": intent}})).map_err(corrupt)?;
                        crate::journal::fault("supersede.S7.after_intent");
                        let tx = self.db.unchecked_transaction()?;
                        tx.execute(
                            "INSERT OR IGNORE INTO pack_commitments(pack_id) VALUES (?1)",
                            [&pack_id],
                        )?;
                        let swapped = tx.execute(
                            "UPDATE pack_commitments SET state='superseded', supersede_id=?2, commitment_version=commitment_version+1
                             WHERE pack_id=?1 AND commitment_version=?3 AND state='active'",
                            rusqlite::params![pack_id, id, v0],
                        )?;
                        if swapped == 0 {
                            drop(tx);
                            j.append("ack", json!({"step": "relink", "outcome": {"not_applied": true, "reason": "commitment version moved"}})).map_err(corrupt)?;
                            return self.compensate(&mut j, id, "SUPERSEDE_CONFLICT", json!({"reason": "the pack's product links changed during the supersession"})).await;
                        }
                        tx.execute(
                            "UPDATE task_links SET object_id=?2 WHERE kind='pack' AND object_id=?1",
                            [&pack_id, &replacement],
                        )?;
                        tx.execute(
                            "UPDATE pack_metadata SET intent_id=?2 WHERE id=?1",
                            rusqlite::params![replacement, intent],
                        )?;
                        tx.execute(
                            "UPDATE pack_commitments SET state='active' WHERE pack_id=?1",
                            [&replacement],
                        )?;
                        tx.commit()?;
                        let (_, vp) = self.commitment(&pack_id)?;
                        let (_, vp2) = self.commitment(&replacement)?;
                        j.append("ack", json!({"step": "relink", "outcome": {"receipt": {"result": {"version_p": vp, "version_p2": vp2}}}})).map_err(corrupt)?;
                        crate::journal::fault("supersede.S7.after_commit");
                    }
                    let (_, vp) = self.commitment(&pack_id)?;
                    let (_, vp2) = self.commitment(&replacement)?;
                    let before = records
                        .iter()
                        .rev()
                        .find(|r| r.kind == "intent" && r.body["step"] == "relink")
                        .map(|r| r.body["before"].clone())
                        .or_else(|| {
                            Journal::open(&jp).ok().and_then(|o| {
                                o.records
                                    .iter()
                                    .rev()
                                    .find(|r| r.kind == "intent" && r.body["step"] == "relink")
                                    .map(|r| r.body["before"].clone())
                            })
                        });
                    Self::saga_state(
                        &mut j,
                        "ProductRelinked",
                        json!({"version_p": vp, "version_p2": vp2, "before": before}),
                    )?;
                }
                "ProductRelinked" => {
                    // S8: P last, with the generation recorded after S1.
                    let g = saga.data["generation_after_close"].as_u64().unwrap_or(0);
                    if self.pack(&pack_id).await?.state != PackState::Abandoned {
                        let out = self.send_journaled(
                            &mut j,
                            pfx,
                            "abandon_original",
                            Command::AbandonChangePack {
                                pack: pack_id.parse().map_err(|_| corrupt("pack id"))?,
                                expected_generation: g,
                            },
                        )?;
                        if let Err(e) = out {
                            return self
                                .compensate(
                                    &mut j,
                                    id,
                                    "SUPERSEDE_CONFLICT",
                                    json!({"abandon_refused": e}),
                                )
                                .await;
                        }
                    }
                    Self::saga_state(&mut j, "OriginalAbandoned", json!({}))?;
                }
                "OriginalAbandoned" => {
                    let replacement = saga.data["replacement"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned();
                    crate::event(&self.db, "pack.superseded", &pack_id, &replacement)?;
                    if let Some(cap) = saga.data.get("capture_session").and_then(Value::as_str) {
                        self.mark_capture(
                            cap,
                            "Superseded",
                            json!({"saga": id, "replacement": replacement}),
                        )?;
                    }
                    Self::saga_state(&mut j, DONE, json!({"outcome": "superseded"}))?;
                }
                "Diverged" | "Conflict" => {
                    let code = if saga.data.get("code").and_then(Value::as_str)
                        == Some("SUPERSEDE_DIVERGED")
                    {
                        "SUPERSEDE_DIVERGED"
                    } else {
                        "SUPERSEDE_CONFLICT"
                    };
                    let detail = saga.data.get("detail").cloned().unwrap_or(Value::Null);
                    return self.compensate(&mut j, id, code, detail).await;
                }
                _ => break,
            }
        }
        self.saga_report(id)
    }

    fn saga_report(&self, id: &str) -> Result<Value> {
        let (jp, _) = self.saga_paths(id);
        let saga = read_saga(&Journal::open(&jp).map_err(corrupt)?.records);
        Ok(
            json!({"saga": id, "state": saga.state, "pack": saga.data.get("pack"),
            "replacement": saga.data.get("replacement"), "outcome": saga.data.get("outcome"),
            "duplicates_compensated": saga.data.get("duplicates_compensated")}),
        )
    }

    /// C1–C3: abandon P', undo a committed relink, end `Conflicted`; P is never touched.
    async fn compensate(
        &self,
        j: &mut Journal,
        id: &str,
        code: &'static str,
        detail: Value,
    ) -> Result<Value> {
        let (jp, _) = self.saga_paths(id);
        let saga = read_saga(&Journal::open(&jp).map_err(corrupt)?.records);
        if saga.state != "Diverged" && saga.state != "Conflict" {
            Self::saga_state(
                j,
                if code == "SUPERSEDE_DIVERGED" {
                    "Diverged"
                } else {
                    "Conflict"
                },
                json!({"code": code, "detail": detail}),
            )?;
        }
        let pack_id = saga.data["pack"].as_str().unwrap_or_default().to_owned();
        // C1.
        if let Some(r) = saga.data.get("replacement").and_then(Value::as_str) {
            for exe in self.non_terminal_executions(r).await? {
                let _ = self.send_journaled(
                    j,
                    "supersede",
                    &format!("cancel.{exe}"),
                    Command::CancelExecution {
                        execution: exe,
                        reason: Some(format!("supersede {id} compensated")),
                    },
                )?;
            }
            let p2 = self.pack(r).await?;
            if p2.state != PackState::Abandoned {
                let expected = saga
                    .data
                    .get("replacement_generation")
                    .and_then(Value::as_u64)
                    .unwrap_or(p2.generation);
                let out = self.send_journaled(
                    j,
                    "supersede",
                    "abandon_replacement",
                    Command::AbandonChangePack {
                        pack: p2.id,
                        expected_generation: expected,
                    },
                )?;
                if let Err(e) = out {
                    Self::saga_state(
                        j,
                        "RecoveryRequired",
                        json!({"outcome": "recovery_required", "c1_refused": e}),
                    )?;
                    return Err(crate::detailed(
                        "RECOVERY_REQUIRED",
                        format!(
                            "supersede {id}: {r} was changed by another client, so it was not abandoned; both packs are kept"
                        ),
                        json!({"reason": "supersede", "saga": id, "pack": pack_id, "replacement": r, "openaevc": e}),
                    ));
                }
            }
            // C2: undo a committed relink, compare-and-swap on both versions.
            if let (Some(vp), Some(before)) = (
                saga.data.get("version_p").and_then(Value::as_i64),
                saga.data.get("before"),
            ) {
                let tx = self.db.unchecked_transaction()?;
                let ok = tx.execute(
                    "UPDATE pack_commitments SET state='active', supersede_id=NULL WHERE pack_id=?1 AND commitment_version=?2",
                    rusqlite::params![pack_id, vp],
                )?;
                if ok == 0 {
                    drop(tx);
                    Self::saga_state(
                        j,
                        "RecoveryRequired",
                        json!({"outcome": "recovery_required", "c2": "version moved"}),
                    )?;
                    return Err(crate::detailed(
                        "RECOVERY_REQUIRED",
                        format!(
                            "supersede {id}: the relink could not be undone because the pack's product links changed again"
                        ),
                        json!({"reason": "supersede", "saga": id}),
                    ));
                }
                for task in before["tasks"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    tx.execute("UPDATE task_links SET object_id=?1 WHERE kind='pack' AND object_id=?2 AND task_id=?3", [&pack_id, r, task])?;
                }
                tx.commit()?;
            }
            self.db.execute(
                "UPDATE pack_commitments SET state='conflicted' WHERE pack_id=?1",
                [r],
            )?;
        }
        // C3.
        Self::saga_state(
            j,
            "Conflicted",
            json!({"outcome": "conflicted", "code": code}),
        )?;
        crate::event(&self.db, "pack.supersede_conflicted", &pack_id, code)?;
        Err(crate::detailed(
            code,
            format!("supersede {id} stopped; {pack_id} is unchanged and still OPEN"),
            json!({"saga": id, "detail": detail}),
        ))
    }
}
