//! Project operations for the general-project domain. General resources are not files: their
//! current value is whatever the newest promoted effect in accepted history says.

use std::collections::BTreeMap;

use openaevc::protocol::{
    Command, EffectProposal, ExecutionRequest, PackState, ProviderDescriptor, ResourceRef,
    ResourceSelector, WorkerInfo,
};
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::{Value, json};

use crate::general::{self, HARNESS, ID, PROVIDER, WRITE_ACTION};
use crate::{Error, Project, Result, event};

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

/// `kind:name` as typed by users, e.g. `note:plan`.
pub fn parse_ref(reference: &str) -> Result<(&'static str, String)> {
    let (short, name) = reference
        .split_once(':')
        .ok_or_else(|| invalid(format!("{reference:?} must be kind:name, e.g. note:plan")))?;
    let kind = general::resource_kind(short)
        .ok_or_else(|| invalid(format!("unknown general resource kind {short}")))?;
    Ok((kind, name.to_owned()))
}

impl Project {
    /// Records general-resource effects in one execution, as OpenAEVC promotion requires.
    pub async fn edit_general(
        &self,
        pack_id: &str,
        generation: u64,
        sets: &[(String, Value)],
        removes: &[String],
    ) -> Result<Value> {
        let mut effects = Vec::new();
        for (reference, value) in sets {
            let (kind, name) = parse_ref(reference)?;
            let short = general::short_kind(kind).expect("known kind");
            effects.push(EffectProposal {
                kind: general::set_effect(short).expect("known kind"),
                target: ResourceRef {
                    kind: kind.into(),
                    locator: name,
                    version: None,
                    extension: ID.into(),
                },
                payload: value.clone(),
                preconditions: vec![],
                outputs: vec![],
            });
        }
        for reference in removes {
            let (kind, name) = parse_ref(reference)?;
            let short = general::short_kind(kind).expect("known kind");
            effects.push(EffectProposal {
                kind: general::remove_effect(short).expect("known kind"),
                target: ResourceRef {
                    kind: kind.into(),
                    locator: name,
                    version: None,
                    extension: ID.into(),
                },
                payload: json!({}),
                preconditions: vec![],
                outputs: vec![],
            });
        }
        if effects.is_empty() {
            return Err(invalid("nothing to change; pass --set or --remove"));
        }
        for effect in &effects {
            general::validate(effect).map_err(|reason| {
                invalid(format!(
                    "{}:{}: {reason}",
                    general::short_kind(&effect.target.kind).unwrap_or("?"),
                    effect.target.locator
                ))
            })?;
        }
        let pack = self.pack(pack_id).await?;
        if pack.state != PackState::Open || pack.generation != generation {
            return Err(invalid(format!(
                "pack must be OPEN at generation {generation}"
            )));
        }
        if !pack.candidate_effects.is_empty() {
            return Err(invalid(
                "pack already has effects; OpenAEVC promotes one generation's effects, so edit in a new pack",
            ));
        }
        let active = self.list_extensions().await?;
        if !active
            .as_array()
            .into_iter()
            .flatten()
            .any(|e| e["id"] == ID && e["active"] == true)
        {
            return Err(invalid(format!(
                "enable {ID} before editing general resources"
            )));
        }
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
                    principal: self.identity.created_by,
                },
            })
            .await?;
        let work_unit = self
            .client
            .add_work_unit(pack.id, pack.generation, HARNESS)
            .await?;
        let generation = self.pack(pack_id).await?.generation;
        let mut selectors: Vec<ResourceSelector> = effects
            .iter()
            .map(|effect| ResourceSelector {
                kind: effect.target.kind.clone(),
                locator_prefix: Some(effect.target.locator.clone()),
            })
            .collect();
        selectors.dedup_by(|a, b| a.kind == b.kind && a.locator_prefix == b.locator_prefix);
        let mut allowed_effects: Vec<String> =
            effects.iter().map(|effect| effect.kind.clone()).collect();
        allowed_effects.sort();
        allowed_effects.dedup();
        let (execution, lease) = self
            .client
            .start_execution(ExecutionRequest {
                pack: pack.id,
                expected_generation: generation,
                work_unit,
                provider: PROVIDER.into(),
                harness: HARNESS.into(),
                worker: Some(WorkerInfo {
                    id: "local".into(),
                    kind: HARNESS.into(),
                    attributes: BTreeMap::new(),
                }),
                allowed_resources: selectors,
                allowed_effects,
                context: vec![],
                timeout_ms: 600_000,
                budget: BTreeMap::new(),
                max_attempts: 1,
                idempotency_key: uuid::Uuid::now_v7().to_string(),
                retry_of: None,
            })
            .await?;
        let mut applied = Vec::new();
        for effect in effects {
            let label = format!(
                "{}:{}",
                general::short_kind(&effect.target.kind).unwrap_or("?"),
                effect.target.locator
            );
            match self.client.submit_effect(&lease, effect).await {
                Ok(true) => applied.push(label),
                outcome => {
                    let reason = match outcome {
                        Err(error) => error.message,
                        _ => format!("general extension rejected {label}"),
                    };
                    self.client
                        .command(Command::FailExecution {
                            execution,
                            lease: lease.id,
                            reason: reason.clone(),
                        })
                        .await?;
                    return Err(invalid(reason));
                }
            }
        }
        self.client.complete_execution(&lease).await?;
        event(&self.db, "general.edited", pack_id, &applied.join(","))?;
        Ok(
            json!({"pack":pack.id,"generation":self.pack(pack_id).await?.generation,
            "execution":execution,"applied":applied}),
        )
    }

    /// Current general resources: newest promoted effect per resource, in pack order, limited
    /// to the active Baseline's members when one is active.
    pub async fn general_resources(&self) -> Result<Vec<Value>> {
        let members: Option<Vec<String>> = match self.active_baseline()? {
            Some(id) => Some(
                self.baseline_typed(&id)
                    .await?
                    .members
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            ),
            None => None,
        };
        let mut state: BTreeMap<(String, String), Value> = BTreeMap::new();
        for summary in self.list_packs().await? {
            let Some(id) = summary["id"].as_str() else {
                continue;
            };
            if summary["state"] != "PROMOTED" {
                continue;
            }
            if let Some(members) = &members
                && !members
                    .iter()
                    .any(|member| Some(member.as_str()) == summary["promoted_digest"].as_str())
            {
                continue;
            }
            for effect in self.pack(id).await?.candidate_effects {
                if effect.target.extension != ID {
                    continue;
                }
                let key = (effect.target.kind.clone(), effect.target.locator.clone());
                let proposal = EffectProposal {
                    kind: effect.kind.clone(),
                    target: effect.target.clone(),
                    payload: effect.payload.clone(),
                    preconditions: vec![],
                    outputs: vec![],
                };
                match general::validate(&proposal) {
                    Ok(Some(value)) => {
                        state.insert(
                            key,
                            json!({"kind":general::short_kind(&effect.target.kind),
                            "name":effect.target.locator,"value":value,"pack":id}),
                        );
                    }
                    Ok(None) => {
                        state.remove(&key);
                    }
                    Err(_) => {}
                }
            }
        }
        Ok(state.into_values().collect())
    }

    pub async fn general_resource(&self, reference: &str) -> Result<Value> {
        let (kind, name) = parse_ref(reference)?;
        let short = general::short_kind(kind);
        self.general_resources()
            .await?
            .into_iter()
            .find(|item| item["kind"] == json!(short) && item["name"] == name)
            .ok_or_else(|| invalid(format!("{reference} has no accepted value")))
    }
}
