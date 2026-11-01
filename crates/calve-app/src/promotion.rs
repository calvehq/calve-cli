//! Seal and promotion workflow (PLAN §21.5, §26; P11).
//!
//! Preflight reports authoritative OpenAEVC state before the command; it never decides legality
//! (OpenAEVC does). Promotion takes the expected generation and, optionally, the expected
//! candidate digest (`STALE_VIEW` if the sealed candidate changed); a retry of a generation that
//! is already promoted returns the existing promotion instead of attempting a second one. The
//! result names the promoted pack, the PromotionRecord, the receipt and Baseline follow-ups; a
//! refusal keeps OpenAEVC's structured error and the preflight in `detail`.
use openaevc::protocol::{ChangePack, Command, Digest, PackState, Query};
use openaevc_sdk::OpenAevcClient;
use serde_json::{Value, json};

use crate::{Error, Project, Result};

impl Project {
    async fn can(&self, action: &str) -> Result<bool> {
        let decision = self
            .client
            .query(Query::Authorize {
                principal: self.client.session().principal(),
                action: action.into(),
                resource: None,
            })
            .await?;
        Ok(decision["allowed"] == true)
    }

    async fn object_body(&self, digest: Digest) -> Result<Value> {
        let v = self.client.query(Query::GetObject { digest }).await?;
        Ok(v["envelope"]["body"].clone())
    }

    async fn policy_names(&self, pack: &ChangePack) -> Result<Vec<Value>> {
        let mut out = vec![];
        for d in &pack.required_policies {
            let body = self.object_body(*d).await?;
            out.push(json!({"digest": d, "name": body["name"]}));
        }
        Ok(out)
    }

    /// Non-terminal executions on the pack.
    async fn active_executions(&self, pack: &ChangePack) -> Result<Vec<Value>> {
        let all = self
            .list_executions(Some(&pack.id.to_string()), None)
            .await?;
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
            .map(|e| json!({"id": e["id"], "state": e["state"]}))
            .collect())
    }

    /// Tasks linked to the pack whose dependencies are not complete.
    fn unresolved_task_dependencies(&self, pack: &ChangePack) -> Result<Vec<Value>> {
        let mut stmt = self.db.prepare(
            "SELECT l.task_id, d.depends_on_id, t.state FROM task_links l
             JOIN task_dependencies d ON d.task_id = l.task_id
             JOIN tasks t ON t.id = d.depends_on_id
             WHERE l.kind='pack' AND l.object_id=?1 AND t.state != 'COMPLETE'",
        )?;
        let rows = stmt.query_map([pack.id.to_string()], |r| {
            Ok(
                json!({"task": r.get::<_, String>(0)?, "blocked_by": r.get::<_, String>(1)?,
                "blocker_state": r.get::<_, String>(2)?}),
            )
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Extension bindings of the pack that are not registered in the Namespace.
    async fn missing_extensions(&self, pack: &ChangePack) -> Result<Vec<String>> {
        let listed = self.list_extensions().await?;
        let active: Vec<&str> = listed
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| e["active"] == true)
            .filter_map(|e| e["id"].as_str())
            .collect();
        Ok(pack
            .extension_bindings
            .iter()
            .filter(|b| !active.contains(&b.as_str()))
            .cloned()
            .collect())
    }

    /// §21.5: what sealing would capture and what stands in its way.
    pub async fn seal_preflight(&self, id: &str, generation: u64) -> Result<Value> {
        let pack = self.pack(id).await?;
        let d = self.file_domain().await.ok();
        let mut changes = std::collections::BTreeMap::<String, u64>::new();
        for e in &pack.candidate_effects {
            let label = d
                .as_ref()
                .and_then(|d| crate::resources::change_label(d, &e.kind))
                .unwrap_or("other");
            *changes.entry(label.into()).or_default() += 1;
        }
        let active = self.active_executions(&pack).await?;
        let deps = self.unresolved_task_dependencies(&pack)?;
        let missing = self.missing_extensions(&pack).await?;
        let capture = self.incomplete_captures(&pack)?;
        let mut blockers = vec![];
        if pack.generation != generation {
            blockers.push(json!({"code": "STALE_VIEW", "message": format!("current generation is {}", pack.generation)}));
        }
        if pack.state != PackState::Open {
            blockers.push(json!({"code": "OPENAEVC_OPERATION_REJECTED", "message": format!("the pack is {}", pack.state.as_str())}));
        }
        if !active.is_empty() {
            blockers.push(json!({"code": "OPENAEVC_OPERATION_REJECTED", "message": "executions are still active on the pack"}));
        }
        if !capture.is_empty() {
            blockers.push(json!({"code": "CAPTURE_INCOMPLETE", "message": "a capture session has not finished"}));
        }
        Ok(json!({
            "pack": pack.id, "generation": pack.generation, "state": pack.state.as_str(),
            "candidate": {"effects": pack.candidate_effects.len(), "changes": changes},
            "unresolved_task_dependencies": deps,
            "missing_extensions": missing,
            "active_executions": active,
            "incomplete_captures": capture,
            "policies": self.policy_names(&pack).await?,
            "can_seal": self.can("changepack.seal").await?,
            "blockers": blockers,
            "note": "OpenAEVC decides whether sealing is legal; this is what Calve can see beforehand",
        }))
    }

    /// §26.1: authoritative state before promotion.
    pub async fn promote_preflight(&self, id: &str, generation: u64) -> Result<Value> {
        let pack = self.pack(id).await?;
        let candidate = pack.sealed.as_ref().map(|s| s.candidate);
        let qualification = match &pack.qualification {
            Some(q) => {
                let decision = self.object_body(q.decision).await?;
                json!({"generation": q.generation, "candidate": q.candidate, "decision": q.decision,
                    "outcome": decision["outcome"], "rules": decision["rules"],
                    "current": q.generation == pack.generation && Some(q.candidate) == candidate})
            }
            None => Value::Null,
        };
        let reviews = self.reviews(id).await?;
        let requires_review = self.pack_requires_review(&pack).await?;
        let current_approvals = reviews
            .iter()
            .filter(|r| r["decision"] == "APPROVE" && r["stale"] == false)
            .count();
        let mut blockers = vec![];
        if pack.generation != generation {
            blockers.push(json!({"code": "STALE_VIEW", "message": format!("current generation is {}", pack.generation)}));
        }
        if pack.quarantine.is_some() {
            blockers.push(json!({"code": "OPENAEVC_OPERATION_REJECTED", "message": "the pack is quarantined"}));
        }
        if !matches!(pack.state, PackState::Qualified | PackState::Promoted) {
            blockers.push(json!({"code": "OPENAEVC_OPERATION_REJECTED",
                "message": format!("the pack is {}, not QUALIFIED; run `pack qualify`", pack.state.as_str())}));
        }
        if requires_review && current_approvals == 0 {
            let stale = reviews.iter().any(|r| r["stale"] == true);
            blockers.push(json!({"code": if stale { "REVIEW_STALE" } else { "OPENAEVC_OPERATION_REJECTED" },
                "message": if stale { "every approval is for an earlier candidate" } else { "the pack requires an approving review" }}));
        }
        let capture = self.incomplete_captures(&pack)?;
        if !capture.is_empty() {
            blockers.push(json!({"code": "CAPTURE_INCOMPLETE", "message": "a capture session has not finished"}));
        }
        let can = self.can("changepack.promote").await?;
        if !can {
            blockers.push(json!({"code": "CAPABILITY_DENIED", "message": "this principal may not promote (changepack.promote)"}));
        }
        Ok(json!({
            "pack": pack.id, "generation": pack.generation, "state": pack.state.as_str(),
            "candidate": candidate,
            "qualification": qualification,
            "policies": self.policy_names(&pack).await?,
            "reviews": {"required": requires_review, "current_approvals": current_approvals, "all": reviews},
            "quarantine": pack.quarantine,
            "dependencies": pack.revision.as_ref().map(|r| json!({"relation": r.relation, "targets": r.targets})),
            "extension_bindings": pack.extension_bindings,
            "capability": {"action": "changepack.promote", "allowed": can},
            "promotion": pack.promotion,
            "blockers": blockers,
            "ready": blockers.is_empty() && pack.state == PackState::Qualified,
        }))
    }

    /// §26.2–26.4.
    pub async fn promote_checked(
        &self,
        id: &str,
        generation: u64,
        expected_candidate: Option<Digest>,
    ) -> Result<Value> {
        let pack = self.pack(id).await?;
        if let Some(expected) = expected_candidate
            && pack.sealed.as_ref().map(|s| s.candidate) != Some(expected)
        {
            return Err(crate::detailed(
                "STALE_VIEW",
                "the sealed candidate is not the one you expected; review it again",
                json!({"expected": expected, "current": pack.sealed.as_ref().map(|s| s.candidate)}),
            ));
        }
        let capture = self.incomplete_captures(&pack)?;
        if !capture.is_empty() {
            return Err(crate::detailed(
                "CAPTURE_INCOMPLETE",
                "a capture session on this pack has not finished; resume or roll it back first",
                json!({"captures": capture}),
            ));
        }
        // Idempotent: the generation is already promoted → the same promotion, never a second.
        if pack.state == PackState::Promoted
            && pack.generation == generation
            && let Some(p) = &pack.promotion
        {
            return self
                .promotion_result(&pack, p.promoted_pack, p.promotion_record, None, true)
                .await;
        }
        let receipt = match self
            .client
            .command(Command::PromoteChangePack {
                pack: pack.id,
                generation,
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let preflight = self
                    .promote_preflight(id, generation)
                    .await
                    .unwrap_or(Value::Null);
                let stale_review = preflight["blockers"]
                    .as_array()
                    .is_some_and(|b| b.iter().any(|b| b["code"] == "REVIEW_STALE"));
                let code = if stale_review {
                    "REVIEW_STALE"
                } else {
                    calve_api::errors::openaevc_code(e.code.as_str())
                };
                return Err(Error::Detailed {
                    code,
                    message: format!("promotion refused by OpenAEVC: {}", e.message),
                    detail: json!({"openaevc": e, "preflight": preflight}),
                });
            }
        };
        crate::event(&self.db, "pack.promoted", id, &generation.to_string())?;
        let promoted = self.pack(id).await?;
        let p = promoted
            .promotion
            .clone()
            .ok_or_else(|| crate::coded("INTERNAL", "promotion returned no record"))?;
        self.promotion_result(
            &promoted,
            p.promoted_pack,
            p.promotion_record,
            Some(receipt.receipt),
            false,
        )
        .await
    }

    async fn promotion_result(
        &self,
        pack: &ChangePack,
        promoted: Digest,
        record: Digest,
        receipt: Option<Digest>,
        already: bool,
    ) -> Result<Value> {
        let record_body = self.object_body(record).await?;
        let active = self.active_baseline()?;
        let mut follow_up = vec![];
        if let Some(a) = &active {
            follow_up.push(format!(
                "calve baseline derive {a} \"<label>\" --add {promoted}"
            ));
            if let Some(rev) = &pack.revision
                && rev.relation == openaevc::protocol::RevisionRelation::Supersedes
            {
                follow_up.push(format!(
                    "calve baseline derive {a} \"<label>\" --replace-with {promoted}"
                ));
            }
        }
        follow_up.push(format!("calve baseline create \"<label>\" {promoted}"));
        Ok(json!({
            "pack": pack.id, "generation": pack.generation,
            "promoted_digest": promoted,
            "promotion_record": {"digest": record, "record": record_body},
            "receipt": receipt,
            "already_promoted": already,
            "active_baseline": active,
            "follow_up": follow_up,
        }))
    }

    /// Capture sessions on the pack that are not terminal (§12 guard; filled by capture.rs).
    pub(crate) fn incomplete_captures(&self, pack: &ChangePack) -> Result<Vec<Value>> {
        crate::capture::incomplete_for_pack(&self.root, &pack.id.to_string())
    }
}
