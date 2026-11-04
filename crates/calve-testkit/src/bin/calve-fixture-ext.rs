//! Fixture native OpenAEVC extension (`org.example.toy`, rev 10 §20 "host tests use fixture
//! extensions"). It owns a toy file resource with the host-generic content payload, so Calve's
//! host paths (install, register, capture, verify, materialize) are tested without any
//! first-party domain. Test-only; never shipped.
#![forbid(unsafe_code)]

use openaevc::crypto::sha256;
use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve};
use openaevc::extension::wire::{
    ApplyOutput, EvaluateOutput, HostCall, Operation, ValidateOutput, VerifyOutput, WireError,
};
use openaevc::protocol::*;
use serde_json::{Value, json};

const ID: &str = "org.example.toy";
const RESOURCE: &str = "org.example.toy.file";
const PUT: &str = "org.example.toy.put";
const DELETE: &str = "org.example.toy.delete";
const PUT_CHUNKED: &str = "org.example.toy.put-chunked";
const VERIFIER: &str = "org.example.toy.verify";
const CHECKS: &str = "org.example.toy.checks";
const SIZE: &str = "org.example.toy.size";
const NOTE: &str = "org.example.toy.note";
const NOTE_SET: &str = "org.example.toy.note.set";
const NOTE_REMOVE: &str = "org.example.toy.note.remove";
const WRITE: &str = "org.example.toy.write";

/// A note is `{"text": string}`; removal has an empty payload.
fn note(e: &EffectProposal) -> Result<Option<Value>, String> {
    if e.target.kind != NOTE || e.target.extension != ID {
        return Err("not a toy note".into());
    }
    let p = e.payload.as_object().ok_or("payload must be an object")?;
    if e.kind == NOTE_REMOVE {
        return if p.is_empty() {
            Ok(None)
        } else {
            Err("remove takes no payload".into())
        };
    }
    match (p.len(), p.get("text").and_then(Value::as_str)) {
        (1, Some(t)) => Ok(Some(json!({"text": t}))),
        _ => Err("a note is {\"text\": string}".into()),
    }
}

/// `{digest, size, content}` (put) or `{previous_digest}` (delete): Calve's host-generic file
/// content payload.
fn inspect(e: &EffectProposal) -> Result<Option<Digest>, String> {
    if e.target.kind != RESOURCE
        || e.target.extension != ID
        || ![PUT, DELETE, PUT_CHUNKED].contains(&e.kind.as_str())
    {
        return Err("not a toy file effect".into());
    }
    if e.kind == PUT_CHUNKED {
        let (d, _) = calve_integration_contract::content::validate_chunked(&e.payload)?;
        return Ok(Some(d.parse().map_err(|_| "digest")?));
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
            resource_kinds: vec![
                ResourceKindDecl {
                    kind: RESOURCE.into(),
                    description: Some("toy file".into()),
                },
                ResourceKindDecl {
                    kind: NOTE.into(),
                    description: Some("toy note".into()),
                },
            ],
            effect_kinds: [
                (PUT, RESOURCE),
                (DELETE, RESOURCE),
                (PUT_CHUNKED, RESOURCE),
                (NOTE_SET, NOTE),
                (NOTE_REMOVE, NOTE),
            ]
            .map(|(k, r)| EffectKindDecl {
                kind: k.into(),
                resource_kind: r.into(),
                required_actions: vec![WRITE.into()],
            })
            .to_vec(),
            verifier_kinds: vec![VERIFIER.into(), CHECKS.into()],
            evaluator_kinds: vec![SIZE.into()],
            composition_validators: vec![],
            // Scenario G's probe; nothing else calls the host.
            host_capabilities: vec![HostCapability::ProcessExecute],
            // Installed under a name ending in `-unbound`, the fixture declares no reference
            // schema (N68: a package that ships one anyway must be refused).
            schemas: if unbound() {
                Default::default()
            } else {
                [(
                    calve_integration_contract::refs::SCHEMA.to_owned(),
                    sha256(calve_testkit::TOY_REFS.as_bytes()),
                )]
                .into()
            },
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
        host: &mut HostContext<'_>,
    ) -> Result<Value, WireError> {
        let enc = |v: Result<Value, serde_json::Error>| {
            v.map_err(|e| WireError::new("encode", e.to_string()))
        };
        match operation {
            Operation::ValidateEffect { effect, .. } if effect.target.kind == NOTE => {
                let r = note(&effect);
                enc(serde_json::to_value(ValidateOutput {
                    valid: r.is_ok(),
                    reason: r.err(),
                }))
            }
            Operation::ApplyEffect { effect, .. } if effect.target.kind == NOTE => {
                let v = note(&effect).map_err(|e| WireError::new("invalid_effect", e))?;
                enc(serde_json::to_value(ApplyOutput {
                    outcome: v.map_or(json!({"removed": true}), |v| json!({"value": v})),
                }))
            }
            Operation::Verify { kind, evidence, .. } if kind == CHECKS => {
                // Calve's check-result evidence: all exit 0 → pass; any failure → fail; a missing
                // tool → inconclusive (never a pass).
                let mut status = if evidence.is_empty() {
                    VerificationStatus::Inconclusive
                } else {
                    VerificationStatus::Pass
                };
                for e in &evidence {
                    let v: Value = serde_json::from_slice(&e.data)
                        .map_err(|e| WireError::new("invalid_evidence", e.to_string()))?;
                    if v["tool_available"] == false && status == VerificationStatus::Pass {
                        status = VerificationStatus::Inconclusive;
                    } else if v["tool_available"] == true && v["exit_code"] != 0 {
                        status = VerificationStatus::Fail;
                    }
                }
                enc(serde_json::to_value(VerifyOutput {
                    status,
                    findings: vec![],
                    facts: Default::default(),
                }))
            }
            Operation::Evaluate {
                kind,
                config,
                effects,
                ..
            } if kind == SIZE => {
                let limit =
                    |k: &str, d: u64| config.as_ref().and_then(|c| c[k].as_u64()).unwrap_or(d);
                let files: Vec<_> = effects
                    .iter()
                    .filter(|e| e.target.kind == RESOURCE)
                    .collect();
                let bytes: u64 = files
                    .iter()
                    .map(|e| e.payload["size"].as_u64().unwrap_or(0))
                    .sum();
                let n = files.len() as u64;
                let verdict = if n == 0 {
                    EvaluationVerdict::Unknown
                } else if n > limit("warn_after_files", 16)
                    || bytes > limit("warn_after_bytes", 256 * 1024)
                {
                    EvaluationVerdict::Warn
                } else {
                    EvaluationVerdict::Allow
                };
                let metrics = [
                    ("org.example.toy.changed_files".to_owned(), n as i64),
                    ("org.example.toy.changed_bytes".to_owned(), bytes as i64),
                ]
                .into();
                enc(serde_json::to_value(EvaluateOutput {
                    verdict,
                    metrics,
                    facts: Default::default(),
                }))
            }
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
            Operation::Verify {
                kind,
                effects,
                config,
                ..
            } if kind == VERIFIER => {
                // §57 Scenario G: verifying `process-probe.toy` needs a `process.execute` host
                // call; without the grant OpenAEVC denies it and fails the operation closed.
                if effects
                    .iter()
                    .any(|e| e.target.locator == "process-probe.toy")
                {
                    host.call(HostCall::ProcessExecute {
                        program: "true".into(),
                        args: vec![],
                        timeout_ms: 5000,
                    })?;
                }
                // Every file effect valid; with `{path, digest}` config, the newest effect at that
                // path must establish that digest.
                let mut findings = vec![];
                for e in effects.iter().filter(|e| e.target.kind == RESOURCE) {
                    let p = EffectProposal {
                        kind: e.kind.clone(),
                        target: e.target.clone(),
                        payload: e.payload.clone(),
                        preconditions: vec![],
                        outputs: vec![],
                    };
                    if let Err(m) = inspect(&p) {
                        findings.push(Finding {
                            code: "org.example.toy.invalid".into(),
                            message: m,
                            resource: Some(e.target.clone()),
                        });
                    }
                }
                // Residual-risk probe (ADR 0005): with path `t2-escape`, write outside the
                // install directory. It succeeds: T2 native code is not OS-confined.
                if let Some(c) = config.as_ref().filter(|c| c["path"] == "t2-escape") {
                    let hex = c["digest"]
                        .as_str()
                        .unwrap_or_default()
                        .trim_start_matches("sha256:");
                    let _ = std::fs::write(format!("/tmp/calve-t2-escape-{hex}"), b"escaped");
                }
                if let Some(c) = config.as_ref().filter(|c| c.get("path").is_some()) {
                    let newest = effects
                        .iter()
                        .rev()
                        .find(|e| e.target.locator == c["path"].as_str().unwrap_or_default());
                    if newest.map(|e| &e.payload["digest"]) != Some(&c["digest"]) {
                        findings.push(Finding {
                            code: "org.example.toy.digest_mismatch".into(),
                            message: "digest differs".into(),
                            resource: None,
                        });
                    }
                }
                let status = if !findings.is_empty() {
                    VerificationStatus::Fail
                } else if effects.is_empty() {
                    VerificationStatus::Inconclusive
                } else {
                    VerificationStatus::Pass
                };
                enc(serde_json::to_value(VerifyOutput {
                    status,
                    findings,
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

fn unbound() -> bool {
    std::env::args_os()
        .next()
        .map(std::path::PathBuf::from)
        .and_then(|p| {
            p.file_stem()
                .map(|s| s.to_string_lossy().ends_with("-unbound"))
        })
        .unwrap_or(false)
}

fn main() -> std::process::ExitCode {
    serve(Toy)
}
