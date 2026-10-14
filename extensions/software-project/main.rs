//! First-party software resource extension. An effect records an exact file snapshot; applying
//! it to a candidate does not write the working tree.
#![forbid(unsafe_code)]

use std::path::{Component, Path};

use openaevc::crypto::sha256;
use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve};
use openaevc::extension::wire::{
    ApplyOutput, EvaluateOutput, Operation, ValidateOutput, VerifyOutput, WireError,
};
use openaevc::protocol::*;
use serde_json::{Value, json};

const ID: &str = "org.calve.software";
const RESOURCE: &str = "org.calve.software.file";
const EFFECT: &str = "org.calve.software.snapshot";
const DELETE: &str = "org.calve.software.delete";
const RENAME: &str = "org.calve.software.rename";
const VERIFIER: &str = "org.calve.software.snapshot.verify";
const EVALUATOR: &str = "org.calve.software.change-size";
const MAX_CONTENT: usize = 1024 * 1024;

struct Software;

fn locator_ok(locator: &str) -> Result<(), String> {
    let path = Path::new(locator);
    if locator.contains('\\')
        || path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || path
            .components()
            .next()
            .is_some_and(|part| part.as_os_str() == ".calve")
    {
        return Err("file locator must be a relative path outside .calve".into());
    }
    Ok(())
}

/// Validates any software file effect. Returns the content digest and size it establishes;
/// a deletion establishes no content and reports size 0.
fn inspect(effect: &EffectProposal) -> Result<(Option<Digest>, usize), String> {
    if ![EFFECT, DELETE, RENAME].contains(&effect.kind.as_str())
        || effect.target.kind != RESOURCE
        || effect.target.extension != ID
    {
        return Err("effect must target a Calve software file".into());
    }
    locator_ok(&effect.target.locator)?;
    if !effect.preconditions.is_empty() || !effect.outputs.is_empty() {
        return Err("software effects do not use preconditions or outputs".into());
    }
    let payload = effect
        .payload
        .as_object()
        .ok_or("payload must be an object")?;
    if effect.kind == DELETE {
        if payload.len() != 1 {
            return Err("delete payload needs only previous_digest".into());
        }
        payload
            .get("previous_digest")
            .and_then(Value::as_str)
            .ok_or("missing previous_digest")?
            .parse::<Digest>()
            .map_err(|_| "invalid previous_digest")?;
        return Ok((None, 0));
    }
    let expected_keys = if effect.kind == RENAME { 4 } else { 3 };
    if payload.len() != expected_keys {
        return Err("payload needs digest, size and content (and from, for renames)".into());
    }
    if effect.kind == RENAME {
        let from = payload
            .get("from")
            .and_then(Value::as_str)
            .ok_or("missing from")?;
        locator_ok(from)?;
        if from == effect.target.locator {
            return Err("rename must change the path".into());
        }
    }
    let expected: Digest = payload
        .get("digest")
        .and_then(Value::as_str)
        .ok_or("missing digest")?
        .parse()
        .map_err(|_| "invalid digest")?;
    let size = payload
        .get("size")
        .and_then(Value::as_u64)
        .ok_or("missing size")?
        .try_into()
        .map_err(|_| "invalid size")?;
    let encoded = payload
        .get("content")
        .and_then(Value::as_str)
        .ok_or("missing content")?;
    if encoded.len() > (MAX_CONTENT * 4 / 3 + 8) {
        return Err("file exceeds 1 MiB capture limit".into());
    }
    let content = b64::decode(encoded).map_err(|_| "invalid base64 content")?;
    if content.len() != size || content.len() > MAX_CONTENT || sha256(&content) != expected {
        return Err("content does not match digest or size".into());
    }
    Ok((Some(expected), size))
}

impl Extension for Software {
    fn manifest(&self) -> ExtensionManifest {
        ExtensionManifest {
            id: ID.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol: SUPPORTED_PROTOCOL,
            contract: SUPPORTED_CONTRACT,
            publisher: None,
            artifact_digest: self_artifact_digest(),
            resource_kinds: vec![ResourceKindDecl {
                kind: RESOURCE.into(),
                description: Some("Project file snapshot".into()),
            }],
            effect_kinds: [EFFECT, DELETE, RENAME]
                .iter()
                .map(|kind| EffectKindDecl {
                    kind: (*kind).into(),
                    resource_kind: RESOURCE.into(),
                    required_actions: vec!["org.calve.software.write".into()],
                })
                .collect(),
            verifier_kinds: vec![VERIFIER.into()],
            evaluator_kinds: vec![EVALUATOR.into()],
            composition_validators: vec![],
            host_capabilities: vec![],
            schemas: Default::default(),
            execution_modes: vec!["subprocess".into()],
            entrypoint: Entrypoint {
                command: "calve_ext_software".into(),
                args: vec![],
            },
        }
    }

    fn handle(
        &mut self,
        operation: Operation,
        _host: &mut HostContext<'_>,
    ) -> Result<Value, WireError> {
        match operation {
            Operation::ValidateEffect { effect, .. } => {
                let result = inspect(&effect);
                serde_json::to_value(ValidateOutput {
                    valid: result.is_ok(),
                    reason: result.err(),
                })
                .map_err(|e| WireError::new("encode", e.to_string()))
            }
            Operation::ApplyEffect { effect, .. } => {
                let (digest, size) =
                    inspect(&effect).map_err(|e| WireError::new("invalid_effect", e))?;
                let outcome = match digest {
                    Some(digest) => json!({"digest":digest,"size":size}),
                    None => json!({"deleted":true}),
                };
                serde_json::to_value(ApplyOutput { outcome })
                    .map_err(|e| WireError::new("encode", e.to_string()))
            }
            Operation::Verify {
                kind,
                config,
                effects,
                ..
            } if kind == VERIFIER => {
                let config = config.unwrap_or_else(|| json!({}));
                let object = config
                    .as_object()
                    .ok_or_else(|| WireError::new("invalid_config", "config must be an object"))?;
                if object.keys().any(|key| key != "path" && key != "digest")
                    || object.contains_key("path") != object.contains_key("digest")
                {
                    return Err(WireError::new(
                        "invalid_config",
                        "provide both path and digest, or neither",
                    ));
                }
                let expected = if let Some(path) = object.get("path") {
                    let path = path
                        .as_str()
                        .ok_or_else(|| WireError::new("invalid_config", "path must be a string"))?;
                    let digest: Digest = object["digest"]
                        .as_str()
                        .ok_or_else(|| WireError::new("invalid_config", "digest must be a string"))?
                        .parse()
                        .map_err(|_| WireError::new("invalid_config", "invalid digest"))?;
                    Some((path, digest))
                } else {
                    None
                };
                let mut checked = 0;
                let mut found_expected = false;
                let mut findings = Vec::new();
                for effect in effects
                    .iter()
                    .rev()
                    .filter(|effect| [EFFECT, DELETE, RENAME].contains(&effect.kind.as_str()))
                {
                    checked += 1;
                    let proposal = EffectProposal {
                        kind: effect.kind.clone(),
                        target: effect.target.clone(),
                        payload: effect.payload.clone(),
                        preconditions: effect.preconditions.clone(),
                        outputs: effect.outputs.clone(),
                    };
                    match inspect(&proposal) {
                        Ok((digest, _)) => {
                            if let Some((path, expected_digest)) = expected.as_ref()
                                && effect.target.locator == *path
                                && !found_expected
                            {
                                found_expected = true;
                                if digest != Some(*expected_digest) {
                                    findings.push(Finding {
                                        code: "org.calve.software.digest_mismatch".into(),
                                        message: format!(
                                            "{path} has digest {}, expected {expected_digest}",
                                            digest
                                                .map_or("<deleted>".to_owned(), |d| d.to_string())
                                        ),
                                        resource: Some(effect.target.clone()),
                                    });
                                }
                            }
                        }
                        Err(message) => findings.push(Finding {
                            code: "org.calve.software.invalid_snapshot".into(),
                            message,
                            resource: Some(effect.target.clone()),
                        }),
                    }
                }
                if let Some((path, _)) = expected.as_ref()
                    && !found_expected
                {
                    findings.push(Finding {
                        code: "org.calve.software.snapshot_missing".into(),
                        message: format!("no snapshot of {path} in candidate"),
                        resource: None,
                    });
                }
                let status = if !findings.is_empty() {
                    VerificationStatus::Fail
                } else if checked == 0 {
                    VerificationStatus::Inconclusive
                } else {
                    VerificationStatus::Pass
                };
                serde_json::to_value(VerifyOutput {
                    status,
                    findings,
                    facts: Default::default(),
                })
                .map_err(|e| WireError::new("encode", e.to_string()))
            }
            Operation::Evaluate {
                kind,
                config,
                effects,
                ..
            } if kind == EVALUATOR => {
                let config = config.unwrap_or_else(|| json!({}));
                let object = config
                    .as_object()
                    .ok_or_else(|| WireError::new("invalid_config", "config must be an object"))?;
                if object
                    .keys()
                    .any(|key| key != "warn_after_bytes" && key != "warn_after_files")
                {
                    return Err(WireError::new(
                        "invalid_config",
                        "unknown change-size option",
                    ));
                }
                let threshold = |key: &str, default: u64| -> Result<u64, WireError> {
                    object
                        .get(key)
                        .map(|value| {
                            value.as_u64().ok_or_else(|| {
                                WireError::new(
                                    "invalid_config",
                                    format!("{key} must be a nonnegative integer"),
                                )
                            })
                        })
                        .transpose()
                        .map(|value| value.unwrap_or(default))
                };
                let warn_after_bytes = threshold("warn_after_bytes", 256 * 1024)?;
                let warn_after_files = threshold("warn_after_files", 16)?;
                let mut files = 0u64;
                let mut bytes = 0u64;
                for effect in effects
                    .iter()
                    .filter(|effect| [EFFECT, DELETE, RENAME].contains(&effect.kind.as_str()))
                {
                    let proposal = EffectProposal {
                        kind: effect.kind.clone(),
                        target: effect.target.clone(),
                        payload: effect.payload.clone(),
                        preconditions: effect.preconditions.clone(),
                        outputs: effect.outputs.clone(),
                    };
                    let (_, size) = inspect(&proposal)
                        .map_err(|error| WireError::new("invalid_effect", error))?;
                    files += 1;
                    bytes = bytes
                        .checked_add(size as u64)
                        .ok_or_else(|| WireError::new("overflow", "change size overflow"))?;
                }
                let verdict = if files == 0 {
                    EvaluationVerdict::Unknown
                } else if files > warn_after_files || bytes > warn_after_bytes {
                    EvaluationVerdict::Warn
                } else {
                    EvaluationVerdict::Allow
                };
                serde_json::to_value(EvaluateOutput {
                    verdict,
                    metrics: [
                        ("org.calve.software.changed_files".into(), files as i64),
                        ("org.calve.software.changed_bytes".into(), bytes as i64),
                    ]
                    .into(),
                    facts: Default::default(),
                })
                .map_err(|e| WireError::new("encode", e.to_string()))
            }
            other => Err(WireError::new(
                "unsupported",
                format!("{} is not supported", other.name()),
            )),
        }
    }
}

fn main() -> std::process::ExitCode {
    serve(Software)
}
