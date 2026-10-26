//! Capture sessions (rev 10 §12, ADR 0011; N13).
//!
//! **Plan before mutate:** the CIC capture plan becomes a *spool* (`<id>.spool.json`: effect
//! proposals, observations, the execution request; written atomically and bound into the journal
//! by its SHA-256) before any OpenAEVC command. The spool holds the captured file content on
//! purpose; it is product data, not a diagnostic sink.
//!
//! **Journal** (`<id>.journal`, hash-chained, header binding `{project, namespace, genesis, pack}`):
//! every OpenAEVC command goes through [`Project::send_journaled`] (exact envelope intent → send →
//! ack). States: `Planned → Submitting(attempt) → Submitted → Done`, or `FailedSubmit` (the
//! extension rejected an effect), with `Superseded`/`Compensated` set by rollback.
//!
//! **Resume** (after a crash, LOST, CANCELLED or FAILED): an unacknowledged intent is replayed
//! byte-for-byte inside the replay window, otherwise discovered from OpenAEVC (work unit by its
//! `{calve.capture, attempt}` spec, effects by their candidate-content projection, observations by
//! event scan, completion by execution state). A dead attempt is followed by a new work unit and
//! execution keyed `<session>:<attempt>`; effects already present are never submitted twice.
//!
//! **Guard:** seal and promote are refused by Calve while a session on the pack is not terminal
//! (`CAPTURE_INCOMPLETE`); OpenAEVC refuses sealing while the capture execution is active.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use openaevc::protocol::{
    AppliedEffect, ChangePack, Command, EffectProposal, ExecutionId, ExecutionRequest, Lease,
    PackId, ProviderDescriptor, ResourceRef, ResourceSelector, WorkUnitId, WorkerInfo,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::envelope::Resolution;
use crate::journal::{Journal, Record};
use crate::{Error, Project, Result};

/// Terminal session states: nothing more happens on the pack because of this session.
pub const TERMINAL: &[&str] = &["Done", "Superseded", "Compensated", "Abandoned"];

const MAX_ATTEMPTS: u32 = 8;

/// `.calve/run/capture`.
pub fn dir(root: &Path) -> PathBuf {
    root.join(".calve/run/capture")
}

/// The attempt's execution can no longer accept work (lease lost, or it ended): a new attempt
/// may continue. Any other refusal is an error, never a silent new attempt.
fn attempt_over(e: &openaevc::protocol::ProtocolError) -> bool {
    use openaevc::protocol::ErrorCode;
    matches!(
        e.code,
        ErrorCode::ExecutionLost | ErrorCode::InvalidTransition
    )
}

fn corrupt(e: impl std::fmt::Display) -> Error {
    crate::detailed(
        "RECOVERY_REQUIRED",
        format!("capture journal: {e}"),
        json!({"reason": "journal_corrupt"}),
    )
}

/// The candidate-content projection (CCE, §12): what an effect proposes, without provenance.
pub(crate) fn projection(
    kind: &str,
    target: &ResourceRef,
    payload: &Value,
    pre: &[Value],
    out: &[ResourceRef],
) -> String {
    crate::journal::sha256_hex(&crate::journal::jcs(&json!({
        "kind": kind, "target": target, "payload": payload, "preconditions": pre, "outputs": out,
    })))
}

pub(crate) fn proposal_projection(p: &EffectProposal) -> String {
    projection(&p.kind, &p.target, &p.payload, &p.preconditions, &p.outputs)
}

pub(crate) fn applied_projection(e: &AppliedEffect) -> String {
    projection(&e.kind, &e.target, &e.payload, &e.preconditions, &e.outputs)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SpoolObservation {
    pub kind: String,
    pub payload: Value,
    pub related_resources: Vec<ResourceRef>,
    /// Paths whose session effects the observation relates to (relations, §6.5b).
    pub related_paths: Vec<String>,
}

/// A file over the inline limit: its chunk layout (bytes in `<id>.chunks/<hex>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SpoolChunked {
    /// Index of its proposal.
    pub index: usize,
    pub path: String,
    pub digest: String,
    pub size: u64,
    /// `(chunk digest, size)` in order.
    pub chunks: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Spool {
    /// Observation kind of uploaded chunks.
    #[serde(default)]
    pub chunk_kind: String,
    #[serde(default)]
    pub chunked: Vec<SpoolChunked>,
    pub pack: PackId,
    pub generation: u64,
    pub provider: ProviderDescriptor,
    pub harness: String,
    pub allowed_resources: Vec<ResourceSelector>,
    pub allowed_effects: Vec<String>,
    pub proposals: Vec<EffectProposal>,
    pub observations: Vec<SpoolObservation>,
    pub captured: Vec<Value>,
    pub refused: Vec<Value>,
    pub relations: Vec<Value>,
    pub events: Vec<(String, String)>,
    pub input_digest: String,
    pub output_digest: String,
    /// `execution retry` of a failed capture: the first attempt reuses its work unit.
    pub retry: Option<(WorkUnitId, ExecutionId)>,
}

/// `(attempt, work unit, execution, lease)`.
type Attempt = (u32, Option<WorkUnitId>, Option<ExecutionId>, Option<Lease>);

/// What the journal says so far.
#[derive(Default)]
struct Log {
    state: String,
    /// attempt → (work unit, execution, lease)
    attempts: Vec<Attempt>,
    /// Steps acknowledged as applied.
    applied: BTreeSet<String>,
    /// Result of each applied step.
    results: std::collections::BTreeMap<String, Value>,
    /// A trailing intent without ack.
    pending: Option<Value>,
}

fn read_log(records: &[Record]) -> Log {
    let mut log = Log {
        state: "Planned".into(),
        ..Log::default()
    };
    let mut intent: Option<Value> = None;
    for r in records {
        match r.kind.as_str() {
            "state" => {
                if let Some(s) = r.body["state"].as_str() {
                    log.state = s.to_owned();
                }
            }
            "intent" => intent = Some(r.body.clone()),
            "ack" => {
                intent = None;
                let step = r.body["step"].as_str().unwrap_or_default().to_owned();
                // Applied = a receipt (sent, replayed or discovered); refusals and
                // `not_applied` discoveries leave the step to be redone.
                let Some(result) = r.body["outcome"].get("receipt").map(|x| &x["result"]) else {
                    continue;
                };
                if let Some(n) = step.strip_prefix("work_unit.").and_then(|n| n.parse().ok()) {
                    let wu = result["id"].as_str().and_then(|s| s.parse().ok());
                    log.attempts.push((n, wu, None, None));
                } else if let Some(n) = step
                    .strip_prefix("start.")
                    .and_then(|n| n.parse::<u32>().ok())
                {
                    let exe = result["id"].as_str().and_then(|s| s.parse().ok());
                    if let Some(a) = log.attempts.iter_mut().find(|a| a.0 == n) {
                        a.2 = exe;
                        a.3 = serde_json::from_value(result["lease"].clone()).ok();
                    }
                }
                log.results.insert(step.clone(), result.clone());
                log.applied.insert(step);
            }
            _ => {}
        }
    }
    log.pending = intent;
    log
}

/// Non-terminal capture sessions on `pack` (the §12 guard).
pub fn incomplete_for_pack(root: &Path, pack: &str) -> Result<Vec<Value>> {
    let mut out = vec![];
    for (id, header, log) in sessions(root)? {
        if header["binding"]["pack"] == pack && !TERMINAL.contains(&log.state.as_str()) {
            out.push(json!({"session": id, "state": log.state}));
        }
    }
    Ok(out)
}

/// `(session, header, state)` of every capture session.
pub(crate) fn sessions_raw(root: &Path) -> Result<Vec<(String, Value, String)>> {
    Ok(sessions(root)?
        .into_iter()
        .map(|(id, h, log)| (id, h, log.state))
        .collect())
}

fn sessions(root: &Path) -> Result<Vec<(String, Value, Log)>> {
    let mut out = vec![];
    let Ok(rd) = fs::read_dir(dir(root)) else {
        return Ok(out);
    };
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "journal") {
            continue;
        }
        let opened = Journal::open(&path).map_err(corrupt)?;
        let id = opened.journal.header["journal_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        out.push((id, opened.journal.header.clone(), read_log(&opened.records)));
    }
    Ok(out)
}

/// Every capture session with its state (`capture list`).
/// `calve capture list`, through its contract type (an unknown state is a corrupt journal).
pub fn list(root: &Path) -> Result<Vec<calve_api::responses::CaptureSession>> {
    let rows: Vec<Value> = sessions(root)?
        .into_iter()
        .map(|(id, h, log)| json!({"session": id, "pack": h["binding"]["pack"], "state": log.state,
            "attempts": log.attempts.len(), "pending_intent": log.pending.as_ref().map(|i| i["step"].clone())}))
        .collect();
    serde_json::from_value(Value::Array(rows)).map_err(|e| corrupt(format!("capture session: {e}")))
}

impl Project {
    fn session_paths(&self, id: &str) -> (PathBuf, PathBuf) {
        let d = dir(&self.root);
        (
            d.join(format!("{id}.journal")),
            d.join(format!("{id}.spool.json")),
        )
    }

    fn load_spool(&self, id: &str, header_sha: &str) -> Result<Spool> {
        let (_, spool_path) = self.session_paths(id);
        let bytes = fs::read(&spool_path)?;
        if crate::journal::sha256_hex(&bytes) != header_sha {
            return Err(corrupt(format!(
                "{} does not match its journal",
                spool_path.display()
            )));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Writes the spool (and the bytes of chunked files) and the journal (state `Planned`), then
    /// drives the session.
    pub(crate) async fn run_capture(
        &self,
        spool: Spool,
        chunk_data: Vec<(String, Vec<u8>)>,
    ) -> Result<Value> {
        let id = format!("cap_{}", uuid::Uuid::now_v7());
        let d = dir(&self.root);
        crate::journal::private_dir(&d)?;
        let (journal_path, spool_path) = self.session_paths(&id);
        if !chunk_data.is_empty() {
            let cdir = d.join(format!("{id}.chunks"));
            fs::create_dir_all(&cdir)?;
            for (digest, content) in &chunk_data {
                let f = cdir.join(digest.trim_start_matches("sha256:"));
                fs::write(&f, content)?;
                crate::journal::sync_file(&f)?;
            }
        }
        let bytes = serde_json::to_vec(&spool)?;
        let tmp = spool_path.with_extension("tmp");
        fs::write(&tmp, &bytes)?;
        crate::journal::sync_file(&tmp)?;
        fs::rename(&tmp, &spool_path)?;
        let pack = self.pack(&spool.pack.to_string()).await?;
        let binding = crate::continuity::binding(&self.db)?;
        let mut j = Journal::create(
            &journal_path,
            "capture",
            &id,
            json!({"project_id": self.identity.project_id, "namespace_id": self.identity.namespace_id,
                "genesis_hash": binding.map(|b| b.genesis_hash), "pack": spool.pack}),
        )
        .map_err(corrupt)?;
        j.append(
            "state",
            json!({"state": "Planned", "spool_sha256": crate::journal::sha256_hex(&bytes),
                "generation": spool.generation, "n": spool.proposals.len(),
                "m": pack.candidate_effects.len(), "input_digest": spool.input_digest,
                "output_digest": spool.output_digest,
                "base_effects": pack.candidate_effects.iter().map(|e| e.id.to_string()).collect::<Vec<_>>()}),
        )
        .map_err(corrupt)?;
        crate::journal::fault("capture.planned");
        drop(j);
        self.drive_capture(&id).await
    }

    /// Records a terminal outcome decided elsewhere (rollback) on a capture session.
    pub(crate) fn mark_capture(&self, id: &str, state: &str, extra: Value) -> Result<()> {
        let (journal_path, _) = self.session_paths(id);
        let mut j = Journal::open(&journal_path).map_err(corrupt)?.journal;
        let mut body = json!({"state": state});
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        j.append("state", body).map_err(corrupt)?;
        Ok(())
    }

    /// Resumes a session (`capture resume`, recovery).
    pub async fn resume_capture(&self, id: &str) -> Result<Value> {
        self.drive_capture(id).await
    }

    async fn effects_of(&self, pack: &ChangePack, work_units: &[WorkUnitId]) -> Vec<AppliedEffect> {
        pack.candidate_effects
            .iter()
            .filter(|e| work_units.contains(&e.work_unit))
            .cloned()
            .collect()
    }

    /// Settles a trailing unacknowledged intent: replay, else discovery.
    async fn settle_capture_intent(
        &self,
        j: &mut Journal,
        intent: &Value,
        spool: &Spool,
        log: &Log,
    ) -> Result<()> {
        let step = intent["step"].as_str().unwrap_or_default().to_owned();
        if let Resolution::Replayed(outcome) = self.resolve_intent(intent)? {
            return Self::ack_resolved(j, &step, &outcome, "replay");
        }
        let pack = self.pack(&spool.pack.to_string()).await?;
        let wus: Vec<WorkUnitId> = log.attempts.iter().filter_map(|a| a.1).collect();
        let applied: Option<Value> = if let Some(n) = step.strip_prefix("work_unit.") {
            let n: u32 = n.parse().unwrap_or(0);
            pack.work_units
                .iter()
                .find(|w| {
                    w.spec.as_ref().is_some_and(|s| {
                        s["calve.capture"] == j.header["journal_id"] && s["attempt"] == n
                    })
                })
                .map(|w| json!({"id": w.id}))
        } else if let Some(rest) = step.strip_prefix("submit.") {
            let i: usize = rest
                .rsplit('.')
                .next()
                .and_then(|i| i.parse().ok())
                .unwrap_or(usize::MAX);
            let want = self
                .assemble(spool, &log.results)
                .await
                .ok()
                .and_then(|p| p.get(i).map(proposal_projection));
            let present = self
                .effects_of(&pack, &wus)
                .await
                .iter()
                .any(|e| Some(applied_projection(e)) == want);
            present.then(|| json!({"state": "APPLIED"}))
        } else if let Some(rest) = step.strip_prefix("observe.") {
            let (n, jdx) = rest.split_once('.').unwrap_or(("0", "0"));
            let n: u32 = n.parse().unwrap_or(0);
            let jdx: usize = jdx.parse().unwrap_or(usize::MAX);
            let exe = log.attempts.iter().find(|a| a.0 == n).and_then(|a| a.2);
            let want = spool.observations.get(jdx);
            let mut found = None;
            if let (Some(exe), Some(want)) = (exe, want) {
                for e in self.events_after(intent["head"].as_u64().unwrap_or(0))? {
                    if e.kind == "observation.appended"
                        && e.body["execution"] == json!(exe)
                        && e.body["kind"] == want.kind.as_str()
                        && let Ok(d) = serde_json::from_value(e.body["digest"].clone())
                    {
                        let o = self.object_json(d).await?;
                        if o["envelope"]["body"]["payload"] == want.payload {
                            found = Some(json!({"digest": d}));
                        }
                    }
                }
            }
            found
        } else if let Some(rest) = step.strip_prefix("chunk.") {
            let (i, k) = rest.split_once('.').unwrap_or(("", ""));
            let want = spool
                .chunked
                .iter()
                .find(|c| c.index.to_string() == i)
                .and_then(|c| {
                    let k: usize = k.parse().ok()?;
                    let (cd, size) = c.chunks.get(k)?;
                    Some(json!({"file_digest": c.digest, "index": k, "chunk_digest": cd, "size": size}))
                });
            let mut found = None;
            if let Some(want) = want {
                for e in self.events_after(intent["head"].as_u64().unwrap_or(0))? {
                    if e.kind == "observation.appended"
                        && e.body["kind"] == spool.chunk_kind.as_str()
                        && let Ok(d) = serde_json::from_value(e.body["digest"].clone())
                        && self.object_json(d).await?["envelope"]["body"]["payload"] == want
                    {
                        found = Some(json!({"digest": d}));
                    }
                }
            }
            found
        } else if step.starts_with("complete.") || step.starts_with("fail.") {
            let n: u32 = step
                .split('.')
                .nth(1)
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let want = if step.starts_with("complete.") {
                "SUCCEEDED"
            } else {
                "FAILED"
            };
            match log.attempts.iter().find(|a| a.0 == n).and_then(|a| a.2) {
                Some(exe) => (self.execution(&exe.to_string()).await?["state"] == want)
                    .then(|| json!({"state": want})),
                None => None,
            }
        } else {
            // start.<n>: StartExecution is idempotent by its key, so resending is safe.
            None
        };
        let outcome = match applied {
            Some(result) => {
                json!({"receipt": {"receipt": null, "request_id": null, "result": result, "discovered": true}})
            }
            None => json!({"not_applied": true}),
        };
        j.append(
            "ack",
            json!({"step": step, "outcome": outcome, "resolved_by": "discovery"}),
        )
        .map_err(corrupt)?;
        Ok(())
    }

    async fn object_json(&self, digest: openaevc::protocol::Digest) -> Result<Value> {
        use openaevc_sdk::OpenAevcClient as _;
        Ok(self
            .client
            .query(openaevc::protocol::Query::GetObject { digest })
            .await?)
    }

    async fn drive_capture(&self, id: &str) -> Result<Value> {
        use openaevc_sdk::OpenAevcClient as _;
        let (journal_path, _) = self.session_paths(id);
        let opened = Journal::open(&journal_path).map_err(corrupt)?;
        let mut j = opened.journal;
        let planned = opened
            .records
            .iter()
            .find(|r| r.kind == "state" && r.body["state"] == "Planned")
            .map(|r| r.body.clone())
            .ok_or_else(|| corrupt("no Planned record"))?;
        let spool = self.load_spool(id, planned["spool_sha256"].as_str().unwrap_or_default())?;
        let pfx = "capture";
        let mut log = read_log(&opened.records);
        if let Some(intent) = log.pending.clone() {
            self.settle_capture_intent(&mut j, &intent, &spool, &log)
                .await?;
            let opened = Journal::open(&journal_path).map_err(corrupt)?;
            j = opened.journal;
            log = read_log(&opened.records);
        }
        if TERMINAL.contains(&log.state.as_str()) || log.state == "FailedSubmit" {
            return self.capture_report(id, &spool, &log).await;
        }
        self.client
            .command(Command::RegisterProvider {
                provider: spool.provider.clone(),
            })
            .await?;
        'attempts: loop {
            let pack = self.pack(&spool.pack.to_string()).await?;
            // The candidate changed under the session (effects it did not produce appeared or
            // went away since the plan): nothing more is submitted (CAPTURE_DIVERGED).
            if let Some(base) = planned["base_effects"].as_array() {
                let own: BTreeSet<WorkUnitId> = log.attempts.iter().filter_map(|a| a.1).collect();
                let foreign: Vec<&AppliedEffect> = pack
                    .candidate_effects
                    .iter()
                    .filter(|e| !own.contains(&e.work_unit))
                    .collect();
                let base: Vec<&str> = base.iter().filter_map(Value::as_str).collect();
                let now: Vec<String> = foreign.iter().map(|e| e.id.to_string()).collect();
                if now.iter().map(String::as_str).ne(base.iter().copied()) {
                    let paths: BTreeSet<&str> = foreign
                        .iter()
                        .filter(|e| !base.contains(&e.id.to_string().as_str()))
                        .map(|e| e.target.locator.as_str())
                        .collect();
                    j.append("state", json!({"state": "Diverged", "paths": paths}))
                        .map_err(corrupt)?;
                    return Err(crate::detailed(
                        "CAPTURE_DIVERGED",
                        format!(
                            "the pack changed under capture {id} (other effects on {} path(s)); roll it back with `calve capture rollback {id}` and capture again",
                            paths.len()
                        ),
                        json!({"session": id, "pack": spool.pack, "paths": paths}),
                    ));
                }
            }
            // The live attempt, if its execution can still accept effects.
            let mut live = None;
            if let Some((n, Some(wu), Some(exe), Some(lease))) = log.attempts.last().cloned() {
                let state = self.execution(&exe.to_string()).await?["state"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                match state.as_str() {
                    "SUCCEEDED" => break 'attempts,
                    "RUNNING" | "STARTING" | "PENDING" => live = Some((n, wu, exe, lease)),
                    // Effects of an execution that did not succeed can never be promoted, so a
                    // new attempt would only add to an unpromotable candidate.
                    _ if !self.effects_of(&pack, &[wu]).await.is_empty() => {
                        let shown = self.execution(&exe.to_string()).await?;
                        j.append(
                            "state",
                            json!({"state": "Lost", "attempt": n, "execution": exe, "execution_state": state}),
                        )
                        .map_err(corrupt)?;
                        return Err(crate::detailed(
                            "CAPTURE_INCOMPLETE",
                            format!(
                                "attempt {n} of capture {id} ended {state} after applying effects, which cannot be promoted; roll the capture back with `calve capture rollback {id}`"
                            ),
                            json!({"session": id, "attempt": n, "execution": exe, "execution_state": state,
                                "failure": shown["failure"], "lease": shown["lease"],
                                "observed_at": jiff::Timestamp::now().to_string()}),
                        ));
                    }
                    _ => {}
                }
            }
            let (n, _wu, exe, lease) = match live {
                Some(l) => l,
                None => {
                    // An attempt whose work unit exists but whose start was not acknowledged
                    // restarts with the same idempotency key (OpenAEVC returns the same
                    // execution); otherwise a new attempt.
                    let resume = match log.attempts.last() {
                        Some((n, Some(wu), None, _)) => Some((*n, *wu)),
                        _ => None,
                    };
                    let n =
                        resume.map_or_else(|| log.attempts.last().map_or(1, |a| a.0 + 1), |r| r.0);
                    if n > MAX_ATTEMPTS {
                        return Err(crate::detailed(
                            "CAPTURE_INCOMPLETE",
                            format!(
                                "capture {id} failed after {MAX_ATTEMPTS} attempts; roll it back with `calve capture rollback {id}`"
                            ),
                            json!({"session": id}),
                        ));
                    }
                    // OpenAEVC's `retry_of` names an earlier execution of the *same* work unit; a
                    // new attempt has its own work unit and starts fresh.
                    let previous_of = |wu: WorkUnitId| {
                        log.attempts
                            .iter()
                            .rev()
                            .find(|a| a.0 < n && a.1 == Some(wu))
                            .and_then(|a| a.2)
                    };
                    let (wu, retry_of) = match (resume, n, spool.retry) {
                        (Some((_, wu)), _, _) => (
                            wu,
                            previous_of(wu).or(spool.retry.filter(|r| r.0 == wu).map(|r| r.1)),
                        ),
                        (None, 1, Some((wu, exe))) => (wu, Some(exe)),
                        _ => {
                            let step = format!("work_unit.{n}");
                            let generation = self.pack(&spool.pack.to_string()).await?.generation;
                            let out = self.send_journaled(
                                &mut j,
                                pfx,
                                &step,
                                Command::AddWorkUnit {
                                    pack: spool.pack,
                                    expected_generation: generation,
                                    kind: spool.harness.clone(),
                                    spec: Some(json!({"calve.capture": id, "attempt": n})),
                                    depends_on: vec![],
                                },
                            )?;
                            let r = out.map_err(Error::from)?;
                            let wu = r
                                .result
                                .id
                                .as_deref()
                                .and_then(|s| s.parse().ok())
                                .ok_or_else(|| {
                                    crate::coded("INTERNAL", "AddWorkUnit returned no id")
                                })?;
                            (wu, None)
                        }
                    };
                    if resume.is_none() && n == 1 && spool.retry.is_some() {
                        j.append("ack", json!({"step": "work_unit.1", "outcome": {"receipt": {"receipt": null, "request_id": null, "result": {"id": wu}}}, "resolved_by": "retry"})).map_err(corrupt)?;
                    }
                    let generation = self.pack(&spool.pack.to_string()).await?.generation;
                    let request = ExecutionRequest {
                        pack: spool.pack,
                        expected_generation: generation,
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
                        max_attempts: MAX_ATTEMPTS,
                        idempotency_key: format!("{id}:{n}"),
                        retry_of,
                    };
                    let out = self.send_journaled(
                        &mut j,
                        pfx,
                        &format!("start.{n}"),
                        Command::StartExecution { request },
                    )?;
                    let r = out.map_err(Error::from)?;
                    let exe: ExecutionId = r
                        .result
                        .id
                        .as_deref()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| crate::coded("INTERNAL", "StartExecution returned no id"))?;
                    let lease = r
                        .result
                        .lease
                        .clone()
                        .ok_or_else(|| crate::coded("INTERNAL", "no lease"))?;
                    j.append("state", json!({"state": "Submitting", "attempt": n, "work_unit": wu, "execution": exe}))
                        .map_err(corrupt)?;
                    log = read_log(&Journal::open(&journal_path).map_err(corrupt)?.records);
                    (n, wu, exe, lease)
                }
            };
            let _keeper = crate::lease::LeaseKeeper::maybe(self.client.clone(), lease.clone());
            // Chunks first (they outlive a lost attempt: the blobs stay indexed).
            if self
                .upload_chunks(&mut j, &spool, exe, &lease, &log)
                .await?
            {
                log = read_log(&Journal::open(&journal_path).map_err(corrupt)?.records);
                continue 'attempts;
            }
            log = read_log(&Journal::open(&journal_path).map_err(corrupt)?.records);
            let proposals = self.assemble(&spool, &log.results).await?;
            let wus: Vec<WorkUnitId> = log.attempts.iter().filter_map(|a| a.1).collect();
            let present: BTreeSet<String> = self
                .effects_of(&pack, &wus)
                .await
                .iter()
                .map(applied_projection)
                .collect();
            for (i, proposal) in proposals.iter().enumerate() {
                if present.contains(&proposal_projection(proposal)) {
                    continue;
                }
                let alive = self
                    .client
                    .command(Command::HeartbeatExecution {
                        execution: exe,
                        lease: lease.id,
                        generation: lease.generation,
                    })
                    .await;
                if let Err(e) = alive {
                    if !attempt_over(&e) {
                        return Err(e.into());
                    }
                    log = read_log(&Journal::open(&journal_path).map_err(corrupt)?.records);
                    continue 'attempts;
                }
                let out = self.send_journaled(
                    &mut j,
                    pfx,
                    &format!("submit.{n}.{i}"),
                    Command::SubmitEffectProposal {
                        execution: exe,
                        lease: lease.id,
                        effect: proposal.clone(),
                    },
                )?;
                match out {
                    Ok(r) if r.result.state.as_deref() == Some("APPLIED") => {}
                    Ok(_) => {
                        let _ = self.send_journaled(
                            &mut j,
                            pfx,
                            &format!("fail.{n}"),
                            Command::FailExecution {
                                execution: exe,
                                lease: lease.id,
                                reason: "extension rejected file change".into(),
                            },
                        )?;
                        j.append("state", json!({"state": "FailedSubmit", "index": i}))
                            .map_err(corrupt)?;
                        return Err(crate::detailed(
                            "CAPTURE_REFUSED",
                            format!(
                                "{} rejected the change to {}; roll the capture back with `calve capture rollback {id}`",
                                proposal.target.extension, proposal.target.locator
                            ),
                            json!({"session": id, "path": proposal.target.locator}),
                        ));
                    }
                    Err(e) if attempt_over(&e) => {
                        // Lease lost or execution no longer running: the loop decides whether a
                        // new attempt may continue.
                        log = read_log(&Journal::open(&journal_path).map_err(corrupt)?.records);
                        continue 'attempts;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            // Observations (relations reference this session's effects by path).
            let pack = self.pack(&spool.pack.to_string()).await?;
            let effects = self.effects_of(&pack, &wus).await;
            for (jdx, o) in spool.observations.iter().enumerate() {
                let step = format!("observe.{n}.{jdx}");
                if log.applied.contains(&step) {
                    continue;
                }
                let related_effects = o
                    .related_paths
                    .iter()
                    .filter_map(|p| {
                        effects
                            .iter()
                            .rev()
                            .find(|e| e.target.locator == *p)
                            .map(|e| e.id)
                    })
                    .collect();
                let out = self.send_journaled(
                    &mut j,
                    pfx,
                    &step,
                    Command::AppendObservation {
                        execution: exe,
                        lease: lease.id,
                        kind: o.kind.clone(),
                        payload: Some(o.payload.clone()),
                        blob: None,
                        related_resources: o.related_resources.clone(),
                        related_effects,
                    },
                )?;
                if let Err(e) = out {
                    if !attempt_over(&e) {
                        return Err(e.into());
                    }
                    log = read_log(&Journal::open(&journal_path).map_err(corrupt)?.records);
                    continue 'attempts;
                }
            }
            let out = self.send_journaled(
                &mut j,
                pfx,
                &format!("complete.{n}"),
                Command::CompleteExecution {
                    execution: exe,
                    lease: lease.id,
                },
            )?;
            if let Err(e) = out {
                if !attempt_over(&e) {
                    return Err(e.into());
                }
                log = read_log(&Journal::open(&journal_path).map_err(corrupt)?.records);
                continue 'attempts;
            }
            break;
        }
        j.append("state", json!({"state": "Submitted"}))
            .map_err(corrupt)?;
        crate::journal::fault("capture.submitted");
        for (path, digest) in &spool.events {
            crate::event(&self.db, "file.captured", path, digest)?;
        }
        j.append("state", json!({"state": "Done"}))
            .map_err(corrupt)?;
        let log = read_log(&Journal::open(&journal_path).map_err(corrupt)?.records);
        self.capture_report(id, &spool, &log).await
    }

    async fn capture_report(&self, id: &str, spool: &Spool, log: &Log) -> Result<Value> {
        let last = log.attempts.last();
        let generation = self.pack(&spool.pack.to_string()).await?.generation;
        Ok(
            json!({"session": id, "state": log.state, "generation": generation,
            "execution": last.and_then(|a| a.2), "work_unit": last.and_then(|a| a.1),
            "attempts": log.attempts.len(),
            "captured": spool.captured, "unchanged": [], "refused": spool.refused,
            "relations": spool.relations}),
        )
    }
}

impl Project {
    /// Rolls a capture session back (§12). `supersede` (default) replaces the pack by one holding
    /// its pre-capture effects; `compensate` appends effects restoring the pre-capture resource
    /// state to the same pack (RSE holds; CCE does not, and the result says so).
    pub async fn rollback_capture(&self, id: &str, mode: &str) -> Result<Value> {
        let (journal_path, _) = self.session_paths(id);
        let opened = Journal::open(&journal_path).map_err(corrupt)?;
        let log = read_log(&opened.records);
        if TERMINAL.contains(&log.state.as_str()) {
            return Err(crate::coded(
                "INVALID_ARGUMENT",
                format!("capture {id} is already {}", log.state),
            ));
        }
        let planned = opened
            .records
            .iter()
            .find(|r| r.kind == "state" && r.body["state"] == "Planned")
            .map(|r| r.body.clone())
            .ok_or_else(|| corrupt("no Planned record"))?;
        let m = planned["m"].as_u64().unwrap_or(0) as usize;
        let pack = opened.journal.header["binding"]["pack"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        match mode {
            "supersede" => self.supersede_pack(&pack, m, Some(id)).await,
            "compensate" => {
                let spool =
                    self.load_spool(id, planned["spool_sha256"].as_str().unwrap_or_default())?;
                // Close the capture execution first (effects stay, F19).
                for exe in log.attempts.iter().filter_map(|a| a.2) {
                    let s = self.execution(&exe.to_string()).await?;
                    if matches!(
                        s["state"].as_str(),
                        Some("PENDING" | "STARTING" | "RUNNING")
                    ) {
                        let mut j = Journal::open(&journal_path).map_err(corrupt)?.journal;
                        let _ = self.send_journaled(
                            &mut j,
                            "capture",
                            &format!("cancel.{exe}"),
                            Command::CancelExecution {
                                execution: exe,
                                reason: Some("capture rolled back (compensate)".into()),
                            },
                        )?;
                    }
                }
                let p = self.pack(&pack).await?;
                let d = self.file_domain().await?;
                let pre = &p.candidate_effects[..m.min(p.candidate_effects.len())];
                let touched: BTreeSet<String> = p.candidate_effects[pre.len()..]
                    .iter()
                    .filter(|e| d.is_file_effect(e))
                    .map(|e| e.target.locator.clone())
                    .collect();
                let mut proposals = vec![];
                for path in &touched {
                    let before = pre.iter().rev().find(|e| e.target.locator == *path);
                    let now = p
                        .candidate_effects
                        .iter()
                        .rev()
                        .find(|e| e.target.locator == *path);
                    match (before, now) {
                        (Some(b), _) if d.op(&b.kind) != Some(crate::domains::FileOp::Delete) => {
                            proposals.push(EffectProposal {
                                kind: b.kind.clone(),
                                target: b.target.clone(),
                                payload: b.payload.clone(),
                                preconditions: vec![],
                                outputs: vec![],
                            })
                        }
                        (_, Some(n)) if d.op(&n.kind) != Some(crate::domains::FileOp::Delete) => {
                            proposals.push(EffectProposal {
                                kind: d.decl.delete.clone(),
                                target: n.target.clone(),
                                payload: json!({"previous_digest": n.payload["digest"]}),
                                preconditions: vec![],
                                outputs: vec![],
                            })
                        }
                        _ => {}
                    }
                }
                let comp = Spool {
                    chunk_kind: String::new(),
                    chunked: vec![],
                    pack: p.id,
                    generation: p.generation,
                    provider: spool.provider.clone(),
                    harness: spool.harness.clone(),
                    allowed_resources: proposals
                        .iter()
                        .map(|x| ResourceSelector {
                            kind: x.target.kind.clone(),
                            locator_prefix: Some(x.target.locator.clone()),
                        })
                        .collect(),
                    allowed_effects: [
                        Some(d.decl.put.clone()),
                        Some(d.decl.delete.clone()),
                        d.decl.put_chunked.clone(),
                    ]
                    .into_iter()
                    .flatten()
                    .collect(),
                    captured: proposals
                        .iter()
                        .map(|x| json!({"path": x.target.locator, "change": "compensation"}))
                        .collect(),
                    proposals,
                    observations: vec![SpoolObservation {
                        kind: format!("{}.capture-compensation", d.extension),
                        payload: json!({"compensates": id}),
                        related_resources: vec![],
                        related_paths: vec![],
                    }],
                    refused: vec![],
                    relations: vec![],
                    events: vec![],
                    input_digest: String::new(),
                    output_digest: String::new(),
                    retry: None,
                };
                let report = self.run_capture(comp, vec![]).await?;
                let after = self.pack(&pack).await?;
                let pre_state: Vec<_> = after.candidate_effects[..pre.len()].to_vec();
                let rse_holds =
                    crate::supersede::resource_state(Some(&d), &after.candidate_effects)
                        == crate::supersede::resource_state(Some(&d), &pre_state);
                self.mark_capture(id, "Compensated", json!({"compensation_session": report["session"], "rse_holds": rse_holds, "cce_holds": false}))?;
                Ok(
                    json!({"session": id, "mode": "compensate", "compensation_session": report["session"],
                    "rse_holds": rse_holds, "cce_holds": false,
                    "note": "the pack's effects now include the capture and its compensation, so candidate content differs from the pre-capture candidate (CCE); its resource state equals it (RSE)"}),
                )
            }
            other => Err(crate::coded(
                "INVALID_ARGUMENT",
                format!("--mode {other}: use supersede or compensate"),
            )),
        }
    }
}

impl Project {
    /// Uploads every chunk not yet acknowledged as a Blob observation of the current execution.
    /// Returns `true` when the attempt was lost (a new attempt continues).
    async fn upload_chunks(
        &self,
        j: &mut Journal,
        spool: &Spool,
        exe: ExecutionId,
        lease: &Lease,
        log: &Log,
    ) -> Result<bool> {
        let id = j.header["journal_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        for c in &spool.chunked {
            let bytes = fs::read(
                dir(&self.root)
                    .join(format!("{id}.chunks"))
                    .join(c.digest.trim_start_matches("sha256:")),
            )?;
            let mut offset = 0usize;
            for (k, (cd, size)) in c.chunks.iter().enumerate() {
                let slice = &bytes[offset..offset + *size as usize];
                offset += *size as usize;
                let step = format!("chunk.{}.{k}", c.index);
                if log.applied.contains(&step) {
                    continue;
                }
                // Renew the lease before each upload: a large file is many chunks.
                use openaevc_sdk::OpenAevcClient as _;
                if let Err(e) = self
                    .client
                    .command(Command::HeartbeatExecution {
                        execution: exe,
                        lease: lease.id,
                        generation: lease.generation,
                    })
                    .await
                {
                    if attempt_over(&e) {
                        return Ok(true);
                    }
                    return Err(e.into());
                }
                let out = self.send_journaled(j, "capture", &step, Command::AppendObservation {
                    execution: exe,
                    lease: lease.id,
                    kind: spool.chunk_kind.clone(),
                    payload: Some(json!({"file_digest": c.digest, "index": k, "chunk_digest": cd, "size": size})),
                    blob: Some(openaevc::protocol::Blob {
                        media_type: "application/octet-stream".into(),
                        data: slice.to_vec(),
                    }),
                    related_resources: vec![],
                    related_effects: vec![],
                })?;
                match out {
                    Err(e) if attempt_over(&e) => return Ok(true),
                    Err(e) => return Err(e.into()),
                    Ok(_) => {}
                }
            }
        }
        Ok(false)
    }

    /// The proposals with each chunked payload filled from the uploaded, read-back-verified
    /// chunk blobs (§13 step 2).
    async fn assemble(
        &self,
        spool: &Spool,
        results: &std::collections::BTreeMap<String, Value>,
    ) -> Result<Vec<EffectProposal>> {
        let mut proposals = spool.proposals.clone();
        for c in &spool.chunked {
            let mut chunks = vec![];
            for (k, (cd, size)) in c.chunks.iter().enumerate() {
                let obs: openaevc::protocol::Digest = results
                    .get(&format!("chunk.{}.{k}", c.index))
                    .and_then(|r| r["digest"].as_str())
                    .and_then(|d| d.parse().ok())
                    .ok_or_else(|| {
                        crate::coded(
                            "CAPTURE_INCOMPLETE",
                            format!("{}: chunk {k} is not uploaded", c.path),
                        )
                    })?;
                let blob = self.object_json(obs).await?["envelope"]["body"]["blob"].clone();
                let blob_digest: openaevc::protocol::Digest = serde_json::from_value(blob)
                    .map_err(|_| {
                        crate::coded(
                            "CONTENT_CORRUPT",
                            format!("{}: chunk {k} has no blob", c.path),
                        )
                    })?;
                chunks.push(json!({"blob_digest": blob_digest, "digest": cd, "size": size}));
            }
            let mut p = proposals[c.index].payload.clone();
            p["chunks"] = json!(chunks);
            // Read back and verify every chunk and the whole file before proposing it.
            self.chunked_bytes(&c.path, &p).await?;
            proposals[c.index].payload = p;
        }
        Ok(proposals)
    }
}
