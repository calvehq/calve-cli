//! Presentation-neutral read models for the console (PLAN §19, console-ux §63). Every field is
//! read from OpenAEVC queries/events or Calve product metadata. Nothing here decides protocol
//! eligibility: available actions mirror the pack state machine OpenAEVC enforces, and
//! explanations quote OpenAEVC policy decisions and verification results.

use std::collections::{BTreeMap, BTreeSet};

use openaevc::protocol::{Digest, Event, Query, b64};
use openaevc_sdk::OpenAevcClient;
use serde_json::{Value, json};

use crate::{Error, Project, Result};

/// Diff lines returned for one file; the console windows this further.
const MAX_DIFF_LINES: usize = 20_000;

/// Calve pack metadata: title, linked intent, creation time.
type PackMeta = (String, Option<String>, u64);

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

/// Stable action descriptor the console turns back into a typed request by parsing `args`
/// with the CLI grammar (structured, never through a shell).
fn action(id: &str, label: &str, key: &str, destructive: bool, args: Vec<String>) -> Value {
    json!({"id":id,"label":label,"key":key,"destructive":destructive,"args":args})
}

fn unavailable(id: &str, label: &str, reason: &str) -> Value {
    json!({"id":id,"label":label,"reason":reason})
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn content(effect: &openaevc::protocol::AppliedEffect) -> Option<Vec<u8>> {
    b64::decode(effect.payload["content"].as_str()?).ok()
}

/// Unified-diff lines between two file versions, with 3 lines of context.
pub fn diff_lines(old: &[u8], new: &[u8]) -> Value {
    let (Ok(old), Ok(new)) = (std::str::from_utf8(old), std::str::from_utf8(new)) else {
        return json!({"binary":true,"old_size":old.len(),"new_size":new.len()});
    };
    let diff = similar::TextDiff::from_lines(old, new);
    let mut lines = Vec::new();
    let (mut added, mut removed) = (0usize, 0usize);
    let mut truncated = false;
    for group in diff.grouped_ops(3) {
        if lines.len() >= MAX_DIFF_LINES {
            truncated = true;
            break;
        }
        let first = &group[0];
        lines.push(json!({"kind":"hunk","text":format!("@@ -{} +{} @@", first.old_range().start + 1, first.new_range().start + 1)}));
        for op in group {
            for change in diff.iter_changes(&op) {
                let kind = match change.tag() {
                    similar::ChangeTag::Equal => "context",
                    similar::ChangeTag::Insert => {
                        added += 1;
                        "add"
                    }
                    similar::ChangeTag::Delete => {
                        removed += 1;
                        "delete"
                    }
                };
                if lines.len() < MAX_DIFF_LINES {
                    lines.push(json!({"kind":kind,"old":change.old_index().map(|i| i + 1),
                        "new":change.new_index().map(|i| i + 1),
                        "text":change.value().trim_end_matches(['\n', '\r'])}));
                } else {
                    truncated = true;
                }
            }
        }
    }
    json!({"binary":false,"added":added,"removed":removed,"lines":lines,"truncated":truncated})
}

impl Project {
    async fn all_events(&self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        self.scan_protocol_events(0, |event| {
            events.push(event);
            Ok(())
        })
        .await?;
        Ok(events)
    }

    fn pack_titles(&self) -> Result<BTreeMap<String, PackMeta>> {
        let mut stmt = self
            .db
            .prepare("SELECT id,title,intent_id,created_at FROM pack_metadata")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?, r.get(3)?)))
            })?
            .collect::<std::result::Result<BTreeMap<_, _>, _>>()?;
        Ok(rows)
    }

    /// ChangePack rows with the columns the list screen shows.
    pub async fn view_packs(&self) -> Result<Value> {
        // The pack index already carries every column the list shows.
        Ok(json!(self.list_packs().await?))
    }

    /// One file's change against accepted state before this pack: the old side is the
    /// accepted content (of the rename source, for renames), the new side the candidate.
    fn file_diff(
        d: &crate::domains::FileDomain,
        before: &crate::resources::FileState,
        effect: &openaevc::protocol::AppliedEffect,
    ) -> Value {
        use crate::domains::FileOp;
        let path = effect.target.locator.as_str();
        let (status, old_path) = match d.op(&effect.kind) {
            Some(FileOp::Delete) => ("deleted", path),
            Some(FileOp::Move) => ("renamed", effect.payload["from"].as_str().unwrap_or(path)),
            _ if before.files.contains_key(path) => ("modified", path),
            _ => ("added", path),
        };
        // Diffs are inline-only (≤ 1 MiB per side); chunked content shows digests, not lines.
        let old = before
            .files
            .get(old_path)
            .and_then(|c| c.inline())
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let new = content(effect).unwrap_or_default();
        let mut diff = diff_lines(&old, &new);
        diff["path"] = json!(path);
        diff["status"] = json!(status);
        if status == "renamed" {
            diff["from"] = json!(old_path);
        }
        diff["digest"] = effect.payload["digest"].clone();
        diff["size"] = effect.payload["size"].clone();
        diff
    }

    /// One file's change in a pack against previously accepted content.
    pub async fn view_pack_diff(&self, pack_id: &str, path: &str) -> Result<Value> {
        let pack = self.pack(pack_id).await?;
        let d = self.file_domain().await?;
        let effect = pack
            .candidate_effects
            .iter()
            .rev()
            .find(|e| d.is_file_effect(e) && e.target.locator == path)
            .ok_or_else(|| invalid(format!("{path} is not part of this pack")))?;
        let before = self.accepted_state(Some(&pack.id.to_string())).await?;
        Ok(Self::file_diff(&d, &before, effect))
    }

    /// Everything the ChangePack workstation needs in one read.
    pub async fn view_pack(&self, pack_id: &str) -> Result<Value> {
        let pack = self.pack(pack_id).await?;
        let id = pack.id.to_string();
        let titles = self.pack_titles()?;
        let (title, intent_id, _) = titles.get(&id).cloned().unwrap_or_default();
        let intent = match &intent_id {
            Some(intent) => self.intent(intent).ok(),
            None => None,
        };
        // Files and change size against accepted history.
        let mut latest: BTreeMap<String, &openaevc::protocol::AppliedEffect> = BTreeMap::new();
        for effect in &pack.candidate_effects {
            latest.insert(effect.target.locator.clone(), effect);
        }
        let before = self.accepted_state(Some(&id)).await?;
        let domain = self.file_domain().await.ok();
        let mut files = Vec::new();
        let (mut added, mut removed) = (0u64, 0u64);
        for (path, effect) in &latest {
            let Some(d) = domain.as_ref().filter(|d| d.is_file_effect(effect)) else {
                files.push(json!({"path":path,"kind":effect.target.kind,"status":"changed","effect":effect.kind}));
                continue;
            };
            let diff = Self::file_diff(d, &before, effect);
            added += diff["added"].as_u64().unwrap_or(0);
            removed += diff["removed"].as_u64().unwrap_or(0);
            let mut row = json!({"path":path,"kind":effect.target.kind,"status":diff["status"],
                "added":diff["added"],"removed":diff["removed"],"binary":diff["binary"],
                "digest":effect.payload["digest"],"size":effect.payload["size"]});
            if let Some(from) = diff.get("from") {
                row["from"] = from.clone();
            }
            files.push(row);
        }
        // Authoritative results recorded by OpenAEVC for this pack.
        let events: Vec<Event> = self
            .all_events()
            .await?
            .into_iter()
            .filter(|event| event.subjects.contains(&id))
            .collect();
        let mut verifications = Vec::new();
        let mut evaluations = Vec::new();
        let mut latest_decision: Option<(u64, Digest, String)> = None;
        for event in &events {
            match event.kind.as_str() {
                "verification.completed" => {
                    if let Ok(digest) =
                        serde_json::from_value::<Digest>(event.body["verification"].clone())
                    {
                        let result = self.client.query(Query::GetVerification { digest }).await?;
                        let body = &result["envelope"]["body"];
                        verifications.push(json!({"digest":digest,"verifier":body["verifier"],
                            "status":body["status"],"generation":body["generation"],
                            "findings":body["findings"],"evidence":body["evidence"],
                            "at":event.timestamp.to_string(),
                            "current": body["generation"] == pack.generation}));
                    }
                }
                "evaluation.completed" => {
                    evaluations.push(json!({"digest":event.body["evaluation"],"evaluator":event.body["evaluator"],
                        "verdict":event.body["verdict"],"generation":event.body["generation"],
                        "at":event.timestamp.to_string()}));
                }
                "qualification.evaluated" => {
                    if let (Some(generation), Ok(decision)) = (
                        event.body["generation"].as_u64(),
                        serde_json::from_value::<Digest>(event.body["decision"].clone()),
                    ) {
                        latest_decision = Some((
                            generation,
                            decision,
                            event.body["outcome"].as_str().unwrap_or("").to_owned(),
                        ));
                    }
                }
                _ => {}
            }
        }
        let evidence = self.list_evidence(&id, None, 100, false).await?;
        self.refresh_pack_index().await?;
        let reviews = self.reviews(&id).await?;
        // Receipts are joined through the requests that produced this pack's events.
        let requests: BTreeSet<String> = events
            .iter()
            .filter_map(|event| event.request_id.map(|r| r.to_string()))
            .collect();
        let mut receipts = Vec::new();
        let mut after = None;
        loop {
            let page = self.list_receipts(after, 100).await?;
            for item in page["items"].as_array().into_iter().flatten() {
                if item["receipt"]["request_id"]
                    .as_str()
                    .is_some_and(|r| requests.contains(r))
                {
                    receipts.push(
                        json!({"digest":item["digest"],"command":item["receipt"]["command"],
                        "caller":item["receipt"]["caller"],"at":item["receipt"]["completed_at"],
                        "result":item["receipt"]["result"]}),
                    );
                }
            }
            match page["next"].as_str() {
                Some(next) => {
                    after = Some(next.parse().map_err(|_| invalid("bad receipt cursor"))?)
                }
                None => break,
            }
        }
        let history: Vec<Value> = events
            .iter()
            .rev()
            .take(200)
            .map(|event| {
                json!({"sequence":event.sequence,"kind":event.kind,"actor":event.actor,
                "at":event.timestamp.to_string(),"body":event.body})
            })
            .collect();
        let dependencies: Vec<Value> = events
            .iter()
            .filter(|event| event.kind == "dependency.added" || event.kind == "dependency.removed")
            .map(|event| json!({"kind":event.kind,"from":event.body["from"],"to":event.body["to"],"edge":event.body["kind"]}))
            .collect();
        let requires_review = self.pack_requires_review(&pack).await?;
        let explain = self
            .explain_pack(
                &pack,
                requires_review,
                &verifications,
                &reviews,
                latest_decision.as_ref(),
            )
            .await?;
        let (available, blocked) = pack_actions(&pack, &explain);
        Ok(json!({
            "id":id,"title":title,"state":pack.state.as_str(),"generation":pack.generation,
            "created_at":pack.created_at.to_string(),"updated_at":pack.updated_at.to_string(),
            "created_by":pack.created_by,"intent":intent,"revision":pack.revision,
            "candidate":pack.sealed.as_ref().map(|s| s.candidate),
            "promoted":pack.promotion.as_ref().map(|p| p.promoted_pack),
            "quarantine":pack.quarantine,"requires_review":requires_review,
            "summary":{"files":files.len(),"added":added,"removed":removed},
            "files":files,"verifications":verifications,"evaluations":evaluations,
            "evidence":evidence,"reviews":reviews,"receipts":receipts,"events":history,
            "dependencies":dependencies,"explain":explain,
            "actions":available,"unavailable_actions":blocked,
            "raw":serde_json::to_value(&pack)?,
        }))
    }

    /// What promotion needs, quoted from OpenAEVC: the pack's required policies, the latest
    /// verification per verifier, recorded reviews, and the latest policy decision.
    async fn explain_pack(
        &self,
        pack: &openaevc::protocol::ChangePack,
        requires_review: bool,
        verifications: &[Value],
        reviews: &[Value],
        decision: Option<&(u64, Digest, String)>,
    ) -> Result<Value> {
        let mut satisfied = Vec::new();
        let mut missing = Vec::new();
        let state = pack.state.as_str();
        if state == "OPEN" {
            missing.push(json!({"condition":"sealed candidate","detail":"seal the pack to fix its candidate"}));
        } else {
            satisfied.push(json!({"condition":"sealed candidate","detail":pack.sealed.as_ref().map(|s| s.candidate.to_string())}));
        }
        let latest: BTreeMap<String, &Value> = verifications
            .iter()
            .filter(|v| v["current"] == true)
            .map(|v| (v["verifier"].as_str().unwrap_or("").to_owned(), v))
            .collect();
        for digest in &pack.required_policies {
            let object = self
                .client
                .query(Query::GetObject { digest: *digest })
                .await?;
            let body = &object["envelope"]["body"];
            let name = body["name"].as_str().unwrap_or("policy").to_owned();
            for rule in body["rules"].as_array().into_iter().flatten() {
                let mut conditions = Vec::new();
                verifier_conditions(&rule["expr"], &mut conditions);
                for (kind, status) in conditions {
                    let condition = format!("{kind} is {status}");
                    match latest.get(&kind) {
                        Some(result) if result["status"] == status.as_str() => {
                            satisfied.push(json!({"condition":condition,"policy":name}))
                        }
                        Some(result) => missing.push(json!({"condition":condition,"policy":name,
                            "detail":format!("latest result is {}", result["status"].as_str().unwrap_or("?"))})),
                        None => missing.push(json!({"condition":condition,"policy":name,
                            "detail":"not run for this generation"})),
                    }
                }
            }
        }
        if requires_review {
            let forbid_self = self.self_review_forbidden(&pack.id.to_string())?;
            let creator = pack.created_by.to_string();
            let current: Vec<&Value> = reviews
                .iter()
                .filter(|r| r["stale"] == false)
                .filter(|r| {
                    !(forbid_self
                        && r["reviewer"] == creator.as_str()
                        && r["decision"] == "APPROVE")
                })
                .collect();
            if forbid_self {
                satisfied.push(json!({"condition":"self-review forbidden","detail":"approvals must come from another identity"}));
            }
            let approved = current.iter().any(|r| r["decision"] == "APPROVE");
            let rejected = current.iter().any(|r| r["decision"] == "REJECT");
            if rejected {
                missing.push(json!({"condition":"no rejection","detail":"a current review rejected this candidate"}));
            } else if approved {
                satisfied.push(json!({"condition":"approved review"}));
            } else {
                missing.push(json!({"condition":"approved review","detail":"no approval for the current candidate"}));
            }
        }
        let decision_view = match decision {
            Some((generation, digest, outcome)) if *generation == pack.generation => {
                let object = self
                    .client
                    .query(Query::GetPolicyDecision { digest: *digest })
                    .await?;
                let rules = object["envelope"]["body"]["rules"].clone();
                Some(json!({"digest":digest,"outcome":outcome,"rules":rules}))
            }
            _ => None,
        };
        let next = match state {
            "OPEN" => Some("seal"),
            "SEALED" if missing.is_empty() => Some("qualify"),
            "SEALED" => None,
            "QUALIFIED" => Some("promote"),
            "QUARANTINED" => Some("release"),
            _ => None,
        };
        Ok(
            json!({"state":state,"satisfied":satisfied,"missing":missing,
            "decision":decision_view,"next":next,
            "source":"OpenAEVC policies, verification results and policy decisions"}),
        )
    }

    /// Needs-attention, active work and recent activity for the landing screen.
    pub async fn view_overview(&self) -> Result<Value> {
        let mut attention = Vec::new();
        let rank = |kind: &str| match kind {
            "failure" => 0,
            "blocked" => 1,
            "review" => 2,
            "stale" => 3,
            "running" => 4,
            _ => 5,
        };
        for item in self.inbox(false).await? {
            if item["needs_attention"] != true {
                continue;
            }
            let kind = match item["kind"].as_str() {
                Some("execution") => "failure",
                Some("stale_review") => "stale",
                _ => "warning",
            };
            attention.push(
                json!({"kind":kind,"subject":item["subject"],"subject_kind":item["kind"],
                "message":item["summary"],"at":item["last_seen"],"source_key":item["source_key"]}),
            );
        }
        let tasks = self.tasks_with_protocol().await?;
        for task in tasks.iter().filter(|t| t["state"] == "BLOCKED") {
            attention.push(
                json!({"kind":"blocked","subject":task["id"],"subject_kind":"task",
                "message":format!("{} is blocked", task["title"].as_str().unwrap_or("task")),
                "at":task["updated_at"]}),
            );
        }
        let packs = self.view_packs().await?;
        for pack in packs.as_array().into_iter().flatten() {
            if pack["state"] == "SEALED" {
                attention.push(json!({"kind":"review","subject":pack["id"],"subject_kind":"pack",
                    "message":format!("{} awaits verification and review", pack["title"].as_str().unwrap_or("pack")),
                    "at":pack["updated_at"]}));
            }
        }
        let executions = self.list_executions(None, None).await?;
        for execution in executions.as_array().into_iter().flatten() {
            if matches!(
                execution["state"].as_str(),
                Some("RUNNING" | "STARTING" | "ADMITTED")
            ) {
                attention.push(json!({"kind":"running","subject":execution["id"],"subject_kind":"execution",
                    "message":format!("{} running", execution["harness"].as_str().unwrap_or("execution")),
                    "at":execution["started_at"]}));
            }
        }
        attention.sort_by_key(|item| rank(item["kind"].as_str().unwrap_or("")));
        let intents = self.list_intents()?;
        let mut work = Vec::new();
        for intent in intents.iter().filter(|i| i["state"] == "OPEN") {
            let own: Vec<&Value> = tasks
                .iter()
                .filter(|t| t["intent_id"] == intent["id"])
                .collect();
            let done = own.iter().filter(|t| t["state"] == "COMPLETE").count();
            let own_packs: Vec<&Value> = packs
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| p["intent"] == intent["id"])
                .collect();
            // Display-only rollup of authoritative child states.
            let state = if own.iter().any(|t| t["state"] == "BLOCKED") {
                "BLOCKED"
            } else if own.iter().any(|t| t["state"] == "IN_PROGRESS") {
                "RUNNING"
            } else if own_packs
                .iter()
                .any(|p| matches!(p["state"].as_str(), Some("SEALED" | "QUALIFIED")))
            {
                "REVIEW"
            } else if !own.is_empty() && done == own.len() {
                "COMPLETE"
            } else {
                "OPEN"
            };
            work.push(json!({"id":intent["id"],"title":intent["title"],"tasks_done":done,
                "tasks_total":own.len(),"packs":own_packs.len(),"state":state,"updated_at":intent["updated_at"]}));
        }
        // Liveness chatter is not "activity" a person needs on the landing screen.
        let activity: Vec<Value> = self
            .activity(60)
            .await?
            .into_iter()
            .filter(|row| {
                !matches!(
                    row["kind"].as_str(),
                    Some(
                        "execution.heartbeat"
                            | "execution.starting"
                            | "execution.admitted"
                            | "execution.running"
                            | "observation.appended"
                            | "provider.registered"
                            | "workunit.added"
                    )
                )
            })
            .take(12)
            .collect();
        Ok(
            json!({"project":{"id":self.identity.project_id,"name":self.display_name},
            "needs_attention":attention,"active_work":work,"recent_activity":activity,
            "counts":{"packs":packs.as_array().map_or(0, Vec::len),"intents":work.len(),
                "baselines":self.list_baselines().await?.len()}}),
        )
    }

    /// Tasks, their dependencies and produced packs as one graph.
    pub async fn view_change_graph(&self, intent: Option<&str>) -> Result<Value> {
        let tasks = self.tasks_with_protocol().await?;
        let packs = self.view_packs().await?;
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut pack_ids = BTreeSet::new();
        for task in tasks
            .iter()
            .filter(|t| intent.is_none_or(|i| t["intent_id"] == i))
        {
            nodes.push(
                json!({"id":task["id"],"kind":"task","label":task["title"],"state":task["state"],
                "intent":task["intent_id"],"assignee":task["assignee"]}),
            );
            for dependency in task["depends_on"].as_array().into_iter().flatten() {
                edges.push(json!({"from":dependency,"to":task["id"],"kind":"depends_on"}));
            }
            for pack in task["linked_packs"].as_array().into_iter().flatten() {
                edges.push(json!({"from":task["id"],"to":pack,"kind":"produces"}));
                pack_ids.insert(pack.as_str().unwrap_or_default().to_owned());
            }
        }
        for pack in packs.as_array().into_iter().flatten() {
            let id = pack["id"].as_str().unwrap_or_default();
            if pack_ids.contains(id) || intent.is_some_and(|i| pack["intent"] == i) {
                nodes.push(
                    json!({"id":id,"kind":"pack","label":pack["title"],"state":pack["state"]}),
                );
            }
        }
        Ok(json!({"intent":intent,"nodes":nodes,"edges":edges}))
    }

    /// Baseline members, composition edges and validation for the Baseline detail screen.
    pub async fn view_baseline(&self, id_or_alias: &str) -> Result<Value> {
        let baseline = self.baseline_typed(id_or_alias).await?;
        let validation = self.validate_baseline(id_or_alias).await?;
        let packs = self.view_packs().await?;
        let by_digest: BTreeMap<String, &Value> = packs
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|p| p["promoted_digest"].as_str().map(|d| (d.to_owned(), p)))
            .collect();
        let heads: BTreeSet<String> = baseline.heads.iter().map(ToString::to_string).collect();
        let members: Vec<Value> = baseline
            .members
            .iter()
            .map(|digest| {
                let pack = by_digest.get(&digest.to_string());
                json!({"digest":digest,"pack":pack.map(|p| p["id"].clone()),
                    "title":pack.map(|p| p["title"].clone()),"state":pack.map(|p| p["state"].clone()),
                    "head":heads.contains(&digest.to_string())})
            })
            .collect();
        let aliases: Vec<Value> = self
            .list_baseline_aliases()?
            .into_iter()
            .filter(|alias| alias["baseline_id"] == baseline.id.to_string())
            .collect();
        let label = self.baseline_label(&baseline);
        Ok(json!({"id":baseline.id,"label":label,"members":members,
            "edges":serde_json::to_value(&baseline.edges)?,"heads":baseline.heads,
            "validation":validation,"aliases":aliases,
            "active": self.active_baseline()? == Some(baseline.id.to_string()),
            "raw":serde_json::to_value(&baseline)?}))
    }

    /// Execution record, its journal events, resolved observations and produced effects.
    pub async fn view_execution(&self, id: &str) -> Result<Value> {
        let logs = self.execution_logs(id).await?;
        let execution = self.execution(id).await?;
        let mut observations = Vec::new();
        let mut output = Vec::new();
        for event in logs["events"].as_array().into_iter().flatten() {
            if event["kind"] != "observation.appended" {
                continue;
            }
            let Ok(digest) = serde_json::from_value::<Digest>(event["body"]["digest"].clone())
            else {
                continue;
            };
            let object = self.client.query(Query::GetObject { digest }).await?;
            let body = object["envelope"]["body"].clone();
            // Harness logs arrive as `{"lines":[{"stream","text"}]}` batches.
            for line in body["payload"]["lines"].as_array().into_iter().flatten() {
                output.push(
                    json!({"stream":line["stream"],"text":line["text"],"at":body["observed_at"]}),
                );
            }
            observations.push(
                json!({"digest":digest,"kind":body["kind"],"at":body["observed_at"],
                "payload":body["payload"],"resources":body["related_resources"]}),
            );
        }
        let effects: Vec<Value> = match execution["pack"].as_str() {
            Some(pack) => self
                .pack(pack)
                .await?
                .candidate_effects
                .iter()
                .filter(|effect| {
                    serde_json::to_value(&effect.provenance)
                        .is_ok_and(|p| crate::value_contains_exact(&p, id))
                })
                .map(|effect| {
                    json!({"kind":effect.kind,"target":effect.target.locator,
                    "digest":effect.payload["digest"]})
                })
                .collect(),
            None => vec![],
        };
        Ok(
            json!({"execution":execution,"events":logs["events"],"observations":observations,
            "output":output,"effects":effects}),
        )
    }

    /// Current change cursor: the newest protocol event sequence and product event sequence.
    async fn change_cursor(&self, protocol_after: u64) -> Result<(u64, i64)> {
        let mut head = protocol_after;
        loop {
            let page: Vec<Event> = serde_json::from_value(
                self.client
                    .query(Query::ListEvents {
                        after: head,
                        limit: Some(1000),
                        kinds: vec![],
                    })
                    .await?,
            )?;
            match page.last() {
                Some(event) if page.len() == 1000 => head = event.sequence,
                Some(event) => break Ok((event.sequence, self.product_cursor()?)),
                None => break Ok((head, self.product_cursor()?)),
            }
        }
    }

    fn product_cursor(&self) -> Result<i64> {
        Ok(self
            .db
            .query_row("SELECT COALESCE(MAX(seq),0) FROM product_events", [], |r| {
                r.get(0)
            })?)
    }

    /// Waits (up to `wait_ms`, at most 60 s) until either journal moves past the cursor.
    pub async fn view_changes(&self, protocol: u64, product: i64, wait_ms: u64) -> Result<Value> {
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms.min(60_000));
        loop {
            let (head, product_head) = self.change_cursor(protocol).await?;
            let changed = head > protocol || product_head > product;
            if changed || tokio::time::Instant::now() >= deadline {
                return Ok(json!({"protocol":head,"product":product_head,"changed":changed}));
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    /// Evidence across every pack, with the pack each item is attached to.
    pub async fn view_evidence(&self) -> Result<Value> {
        let mut rows = Vec::new();
        for pack in self.list_packs().await? {
            let id = pack["id"].as_str().unwrap_or_default();
            let page = self.list_evidence(id, None, 100, false).await?;
            for item in page["items"].as_array().into_iter().flatten() {
                let mut row = item.clone();
                row["pack"] = json!(id);
                row["pack_title"] = pack["title"].clone();
                rows.push(row);
            }
        }
        Ok(json!(rows))
    }
}

/// Verifier conditions a policy expression requires, in positive positions only.
fn verifier_conditions(expr: &Value, out: &mut Vec<(String, String)>) {
    if let Some(condition) = expr.get("verifier")
        && let (Some(kind), Some(status)) =
            (condition["kind"].as_str(), condition["status"].as_str())
    {
        out.push((kind.to_owned(), status.to_owned()));
    }
    for key in ["all", "any"] {
        for child in expr[key].as_array().into_iter().flatten() {
            verifier_conditions(child, out);
        }
    }
}

/// Transitions OpenAEVC defines for each pack state; OpenAEVC still enforces each one.
fn pack_actions(
    pack: &openaevc::protocol::ChangePack,
    explain: &Value,
) -> (Vec<Value>, Vec<Value>) {
    let id = pack.id.to_string();
    let generation = pack.generation.to_string();
    let with_gen = |verb: &[&str]| {
        let mut parts = vec!["pack"];
        parts.extend_from_slice(verb);
        parts.extend([id.as_str(), "--generation", generation.as_str()]);
        args(&parts)
    };
    let missing: Vec<String> = explain["missing"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["condition"].as_str().map(str::to_owned))
        .collect();
    let mut available = Vec::new();
    let mut blocked = Vec::new();
    match pack.state.as_str() {
        "OPEN" => {
            available.push(action(
                "seal",
                "Seal candidate",
                "s",
                false,
                with_gen(&["seal"]),
            ));
            available.push(action(
                "abandon",
                "Abandon",
                "A",
                true,
                with_gen(&["abandon"]),
            ));
            blocked.push(unavailable(
                "promote",
                "Promote",
                "pack is OPEN; seal and qualify it first",
            ));
        }
        "SEALED" => {
            available.push(action(
                "verify",
                "Run snapshot verification",
                "v",
                false,
                with_gen(&["verify"]),
            ));
            available.push(action(
                "check",
                "Run language checks",
                "c",
                false,
                with_gen(&["check"]),
            ));
            available.push(action(
                "evaluate",
                "Evaluate change size",
                "e",
                false,
                with_gen(&["evaluate"]),
            ));
            available.push(action(
                "approve",
                "Approve",
                "r",
                false,
                with_gen(&["approve"]),
            ));
            available.push(action("reject", "Reject", "R", true, with_gen(&["reject"])));
            available.push(action(
                "qualify",
                "Refresh qualification",
                "q",
                false,
                with_gen(&["qualify"]),
            ));
            available.push(action(
                "reopen",
                "Reopen (new generation)",
                "o",
                true,
                with_gen(&["reopen"]),
            ));
            available.push(action(
                "abandon",
                "Abandon",
                "A",
                true,
                with_gen(&["abandon"]),
            ));
            let reason = if missing.is_empty() {
                "qualification has not allowed promotion yet".to_owned()
            } else {
                format!("missing: {}", missing.join(", "))
            };
            blocked.push(unavailable("promote", "Promote", &reason));
        }
        "QUALIFIED" => {
            available.push(action(
                "promote",
                "Promote",
                "p",
                true,
                with_gen(&["promote"]),
            ));
            available.push(action(
                "reopen",
                "Reopen (new generation)",
                "o",
                true,
                with_gen(&["reopen"]),
            ));
            available.push(action(
                "abandon",
                "Abandon",
                "A",
                true,
                with_gen(&["abandon"]),
            ));
        }
        "QUARANTINED" => {
            available.push(action(
                "release",
                "Release quarantine",
                "u",
                false,
                args(&["pack", "release-quarantine", &id]),
            ));
            blocked.push(unavailable("promote", "Promote", "pack is quarantined"));
        }
        "PROMOTED" => {
            blocked.push(unavailable(
                "reopen",
                "Reopen",
                "promoted history is immutable; create a revision instead",
            ));
        }
        _ => {}
    }
    if !matches!(
        pack.state.as_str(),
        "PROMOTED" | "ABANDONED" | "QUARANTINED"
    ) {
        available.push(action(
            "quarantine",
            "Quarantine",
            "Q",
            true,
            args(&["pack", "quarantine", &id, "--reason"]),
        ));
    }
    (available, blocked)
}

#[cfg(test)]
mod tests {
    use super::diff_lines;

    #[test]
    fn diff_counts_and_marks_binary() {
        let diff = diff_lines(b"a\nb\nc\n", b"a\nB\nc\nd\n");
        assert_eq!(diff["added"], 2);
        assert_eq!(diff["removed"], 1);
        assert_eq!(diff["lines"][0]["kind"], "hunk");
        assert_eq!(diff_lines(&[0xff, 0], b"x")["binary"], true);
    }
}
