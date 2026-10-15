//! Non-file resources (`resource set kind:name=JSON`). Their kinds, effects and write action come
//! from the signed `resources` declarations of the enabled packages; the owning extension
//! validates each effect when OpenAEVC applies it. The current value of a resource is the
//! extension's apply outcome of the newest promoted effect.

use std::collections::BTreeMap;

use calve_integration_contract::metadata::ResourceDecl;
use openaevc::protocol::{
    Command, EffectProposal, ExecutionRequest, PackState, ProviderDescriptor, ResourceRef,
    ResourceSelector, WorkerInfo,
};
use openaevc_sdk::{OpenAevcClient, TypedClient};
use serde_json::{Value, json};

use crate::{Error, Project, Result, event};

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

impl Project {
    /// `kind:name` as typed by users (e.g. `note:plan`) → (extension, declaration, name).
    async fn parse_ref(&self, reference: &str) -> Result<(String, ResourceDecl, String)> {
        let (short, name) = reference
            .split_once(':')
            .ok_or_else(|| invalid(format!("{reference:?} must be kind:name, e.g. note:plan")))?;
        let mut found: Vec<(String, ResourceDecl)> = self
            .resource_domains()
            .await?
            .into_iter()
            .filter(|(_, d)| d.short == short)
            .collect();
        match found.len() {
            1 => {
                let (ext, d) = found.remove(0);
                Ok((ext, d, name.to_owned()))
            }
            0 => Err(invalid(format!(
                "unknown resource kind {short}: no enabled extension declares it"
            ))),
            _ => Err(invalid(format!(
                "resource kind {short} is declared by several enabled extensions"
            ))),
        }
    }

    /// Records resource effects in one execution, as OpenAEVC promotion requires.
    pub async fn edit_general(
        &self,
        pack_id: &str,
        generation: u64,
        sets: &[(String, Value)],
        removes: &[String],
    ) -> Result<Value> {
        let mut effects = Vec::new();
        let mut owner: Option<(String, String)> = None;
        let mut labels = BTreeMap::new();
        let refs = sets
            .iter()
            .map(|(r, v)| (r, Some(v)))
            .chain(removes.iter().map(|r| (r, None)));
        for (reference, value) in refs {
            let (ext, d, name) = self.parse_ref(reference).await?;
            if owner.as_ref().is_some_and(|(e, _)| *e != ext) {
                return Err(invalid(
                    "one edit changes resources of one extension; split it into separate packs",
                ));
            }
            owner.get_or_insert((ext.clone(), d.write_action.clone()));
            labels.insert((d.kind.clone(), name.clone()), d.short.clone());
            effects.push(EffectProposal {
                kind: if value.is_some() {
                    d.set.clone()
                } else {
                    d.remove.clone()
                },
                target: ResourceRef {
                    kind: d.kind.clone(),
                    locator: name,
                    version: None,
                    extension: ext,
                },
                payload: value.cloned().unwrap_or_else(|| json!({})),
                preconditions: vec![],
                outputs: vec![],
            });
        }
        let Some((extension, write_action)) = owner else {
            return Err(invalid("nothing to change; pass --set or --remove"));
        };
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
        let (harness, provider) = (format!("{extension}.edit"), format!("{extension}.local"));
        self.client
            .command(Command::RegisterProvider {
                provider: ProviderDescriptor {
                    id: provider.clone(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    worker_kinds: vec![harness.clone()],
                    harnesses: vec![harness.clone()],
                    required_actions: vec![write_action],
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
            .add_work_unit(pack.id, pack.generation, &harness)
            .await?;
        let generation = self.pack(pack_id).await?.generation;
        let mut selectors: Vec<ResourceSelector> = effects
            .iter()
            .map(|e| ResourceSelector {
                kind: e.target.kind.clone(),
                locator_prefix: Some(e.target.locator.clone()),
            })
            .collect();
        selectors.dedup_by(|a, b| a.kind == b.kind && a.locator_prefix == b.locator_prefix);
        let mut allowed_effects: Vec<String> = effects.iter().map(|e| e.kind.clone()).collect();
        allowed_effects.sort();
        allowed_effects.dedup();
        let (execution, lease) = self
            .client
            .start_execution(ExecutionRequest {
                pack: pack.id,
                expected_generation: generation,
                work_unit,
                provider,
                harness: harness.clone(),
                worker: Some(WorkerInfo {
                    id: "local".into(),
                    kind: harness,
                    attributes: BTreeMap::new(),
                }),
                allowed_resources: selectors,
                allowed_effects,
                context: vec![],
                timeout_ms: 600_000,
                budget: BTreeMap::new(),
                max_attempts: 1,
                idempotency_key: crate::app::idempotency_key("general"),
                retry_of: None,
            })
            .await?;
        let mut applied = Vec::new();
        for effect in effects {
            let label = format!(
                "{}:{}",
                labels[&(effect.target.kind.clone(), effect.target.locator.clone())],
                effect.target.locator
            );
            match self.client.submit_effect(&lease, effect).await {
                Ok(true) => applied.push(label),
                outcome => {
                    let reason = match outcome {
                        Err(error) => error.message,
                        _ => format!("{extension} rejected {label}"),
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

    /// Current resources: newest promoted effect per resource, in pack order, limited to the
    /// active Baseline's members when one is active. The value is the extension's apply
    /// outcome (`{"value": …}`); a remove effect clears it.
    pub async fn general_resources(&self) -> Result<Vec<Value>> {
        let decls: BTreeMap<(String, String), ResourceDecl> = self
            .resource_domains()
            .await?
            .into_iter()
            .map(|(ext, d)| ((ext, d.kind.clone()), d))
            .collect();
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
                    .any(|m| Some(m.as_str()) == summary["promoted_digest"].as_str())
            {
                continue;
            }
            for effect in self.pack(id).await?.candidate_effects {
                let Some(d) =
                    decls.get(&(effect.target.extension.clone(), effect.target.kind.clone()))
                else {
                    continue;
                };
                let key = (effect.target.kind.clone(), effect.target.locator.clone());
                if effect.kind == d.remove {
                    state.remove(&key);
                } else if effect.kind == d.set {
                    let value = effect
                        .outcome
                        .get("value")
                        .cloned()
                        .unwrap_or_else(|| effect.payload.clone());
                    state.insert(key, json!({"kind":d.short,"name":effect.target.locator,"value":value,"pack":id}));
                }
            }
        }
        Ok(state.into_values().collect())
    }

    pub async fn general_resource(&self, reference: &str) -> Result<Value> {
        let (_, d, name) = self.parse_ref(reference).await?;
        self.general_resources()
            .await?
            .into_iter()
            .find(|item| item["kind"] == json!(d.short) && item["name"] == name)
            .ok_or_else(|| invalid(format!("{reference} has no accepted value")))
    }
}
