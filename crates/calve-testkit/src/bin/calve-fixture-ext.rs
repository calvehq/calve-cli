//! Fixture native OpenAEVC extension (`org.example.toy`, rev 10 §20 "host tests use fixture
//! extensions"). It owns a toy file resource with the host-generic content payload, so Calve's
//! host paths (install, register, capture, verify, materialize) are tested without any
//! first-party domain. Test-only; never shipped.
#![forbid(unsafe_code)]

use openaevc::crypto::sha256;
use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve};
use openaevc::extension::wire::{ApplyOutput, Operation, ValidateOutput, VerifyOutput, WireError};
use openaevc::protocol::*;
use serde_json::{Value, json};

const ID: &str = "org.example.toy";
const RESOURCE: &str = "org.example.toy.file";
const PUT: &str = "org.example.toy.put";
const DELETE: &str = "org.example.toy.delete";
const VERIFIER: &str = "org.example.toy.verify";
const WRITE: &str = "org.example.toy.write";

/// `{digest, size, content}` (put) or `{previous_digest}` (delete): Calve's host-generic file
/// content payload.
fn inspect(e: &EffectProposal) -> Result<Option<Digest>, String> {
    if e.target.kind != RESOURCE
        || e.target.extension != ID
        || ![PUT, DELETE].contains(&e.kind.as_str())
    {
        return Err("not a toy file effect".into());
    }
    let p = e.payload.as_object().ok_or("payload must be an object")?;
    if e.kind == DELETE {
        p.get("previous_digest")
            .and_then(Value::as_str)
            .ok_or("previous_digest")?
            .parse::<Digest>()
            .map_err(|_| "digest")?;
        return Ok(None);
    }
    let d: Digest = p
        .get("digest")
        .and_then(Value::as_str)
        .ok_or("digest")?
        .parse()
        .map_err(|_| "digest")?;
    let c = b64::decode(p.get("content").and_then(Value::as_str).ok_or("content")?)
        .map_err(|_| "base64")?;
    if sha256(&c) != d || p.get("size").and_then(Value::as_u64) != Some(c.len() as u64) {
        return Err("content does not match digest or size".into());
    }
    Ok(Some(d))
}

struct Toy;

impl Extension for Toy {
    fn manifest(&self) -> ExtensionManifest {
        ExtensionManifest {
            id: ID.into(),
            version: "0.1.0".into(),
            protocol: SUPPORTED_PROTOCOL,
            contract: SUPPORTED_CONTRACT,
            publisher: None,
            artifact_digest: self_artifact_digest(),
            resource_kinds: vec![ResourceKindDecl {
                kind: RESOURCE.into(),
                description: Some("toy file".into()),
            }],
            effect_kinds: [PUT, DELETE]
                .map(|k| EffectKindDecl {
                    kind: k.into(),
                    resource_kind: RESOURCE.into(),
                    required_actions: vec![WRITE.into()],
                })
                .to_vec(),
            verifier_kinds: vec![VERIFIER.into()],
            evaluator_kinds: vec![],
            composition_validators: vec![],
            host_capabilities: vec![],
            schemas: Default::default(),
            execution_modes: vec!["subprocess".into()],
            entrypoint: Entrypoint {
                command: "calve-fixture-ext".into(),
                args: vec![],
            },
        }
    }

    fn handle(
        &mut self,
        operation: Operation,
        _: &mut HostContext<'_>,
    ) -> Result<Value, WireError> {
        let enc = |v: Result<Value, serde_json::Error>| {
            v.map_err(|e| WireError::new("encode", e.to_string()))
        };
        match operation {
            Operation::ValidateEffect { effect, .. } => {
                let r = inspect(&effect);
                enc(serde_json::to_value(ValidateOutput {
                    valid: r.is_ok(),
                    reason: r.err(),
                }))
            }
            Operation::ApplyEffect { effect, .. } => {
                let d = inspect(&effect).map_err(|e| WireError::new("invalid_effect", e))?;
                enc(serde_json::to_value(ApplyOutput {
                    outcome: d.map_or(json!({"deleted": true}), |d| json!({"digest": d})),
                }))
            }
            Operation::Verify { kind, effects, .. } if kind == VERIFIER => {
                let bad = effects.iter().filter(|e| {
                    let p = EffectProposal {
                        kind: e.kind.clone(),
                        target: e.target.clone(),
                        payload: e.payload.clone(),
                        preconditions: vec![],
                        outputs: vec![],
                    };
                    inspect(&p).is_err()
                });
                let status = if bad.count() > 0 {
                    VerificationStatus::Fail
                } else if effects.is_empty() {
                    VerificationStatus::Inconclusive
                } else {
                    VerificationStatus::Pass
                };
                enc(serde_json::to_value(VerifyOutput {
                    status,
                    findings: vec![],
                    facts: Default::default(),
                }))
            }
            other => Err(WireError::new(
                "unsupported",
                format!("{} is not supported", other.name()),
            )),
        }
    }
}

fn main() -> std::process::ExitCode {
    serve(Toy)
}
