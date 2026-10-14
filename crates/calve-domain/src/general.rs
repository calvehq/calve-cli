//! First-party `general-project` domain (`org.calve.general`): structured notes, checklists,
//! key/value records and external artifact references. Compiled into both the extension
//! binary and the Calve library, so it only depends on OpenAEVC contract crates.

use openaevc::protocol::EffectProposal;
use serde_json::{Map, Value, json};

pub const ID: &str = "org.calve.general";
pub const HARNESS: &str = "org.calve.general.edit";
pub const PROVIDER: &str = "org.calve.general.local";
pub const WRITE_ACTION: &str = "org.calve.general.write";
const MAX_TEXT: usize = 64 * 1024;
const MAX_ITEMS: usize = 500;

/// (short kind, resource kind, effect kinds)
pub const KINDS: &[(&str, &str, &[&str])] = &[
    (
        "note",
        "org.calve.general.note",
        &[
            "org.calve.general.note.set",
            "org.calve.general.note.remove",
        ],
    ),
    (
        "checklist",
        "org.calve.general.checklist",
        &[
            "org.calve.general.checklist.set",
            "org.calve.general.checklist.remove",
        ],
    ),
    (
        "record",
        "org.calve.general.record",
        &[
            "org.calve.general.record.set",
            "org.calve.general.record.remove",
        ],
    ),
    (
        "artifact",
        "org.calve.general.artifact",
        &[
            "org.calve.general.artifact.attach",
            "org.calve.general.artifact.detach",
        ],
    ),
];

pub fn resource_kind(short: &str) -> Option<&'static str> {
    KINDS
        .iter()
        .find(|(name, _, _)| *name == short)
        .map(|(_, kind, _)| *kind)
}

pub fn short_kind(resource: &str) -> Option<&'static str> {
    KINDS
        .iter()
        .find(|(_, kind, _)| *kind == resource)
        .map(|(name, _, _)| *name)
}

/// Effect kinds are bound to one resource kind each: `[set, remove]`.
fn effects(short: &str) -> Option<&'static [&'static str]> {
    KINDS
        .iter()
        .find(|(name, _, _)| *name == short)
        .map(|(_, _, effects)| *effects)
}

pub fn set_effect(short: &str) -> Option<String> {
    effects(short).map(|kinds| kinds[0].to_owned())
}

pub fn remove_effect(short: &str) -> Option<String> {
    effects(short).map(|kinds| kinds[1].to_owned())
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/'))
        && !name.starts_with(['/', '.'])
        && !name.contains("//")
        && !name.split('/').any(|part| part == ".." || part.is_empty())
}

fn text(value: &Value, field: &str) -> Result<String, String> {
    let text = value[field]
        .as_str()
        .ok_or_else(|| format!("{field} must be a string"))?;
    if text.len() > MAX_TEXT {
        return Err(format!("{field} exceeds 64 KiB"));
    }
    Ok(text.to_owned())
}

fn only_keys(payload: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    match payload.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(format!("unexpected field {key}")),
        None => Ok(()),
    }
}

/// Validates an effect and returns the resource value it establishes (`None` for removal).
pub fn validate(effect: &EffectProposal) -> Result<Option<Value>, String> {
    let Some(short) = short_kind(&effect.target.kind) else {
        return Err("unknown general resource kind".into());
    };
    if effect.target.extension != ID || !name_ok(&effect.target.locator) {
        return Err("general resources need a name of letters, digits, '-', '_', '.', '/'".into());
    }
    if !effect.preconditions.is_empty() || !effect.outputs.is_empty() {
        return Err("general effects do not use preconditions or outputs".into());
    }
    let payload = effect
        .payload
        .as_object()
        .ok_or("payload must be an object")?;
    if Some(effect.kind.clone()) == remove_effect(short) {
        only_keys(payload, &[])?;
        return Ok(None);
    }
    if Some(effect.kind.clone()) != set_effect(short) {
        return Err(format!(
            "{} does not apply to {short} resources",
            effect.kind
        ));
    }
    let value = &effect.payload;
    let normalized = match short {
        "note" => {
            only_keys(payload, &["text"])?;
            json!({"text":text(value, "text")?})
        }
        "checklist" => {
            only_keys(payload, &["items"])?;
            let items = value["items"].as_array().ok_or("items must be an array")?;
            if items.len() > MAX_ITEMS {
                return Err("checklist exceeds 500 items".into());
            }
            let mut out = Vec::new();
            for item in items {
                let object = item.as_object().ok_or("checklist items must be objects")?;
                only_keys(object, &["text", "done"])?;
                let done = item["done"].as_bool().ok_or("done must be a boolean")?;
                out.push(json!({"text":text(item, "text")?,"done":done}));
            }
            json!({"items":out})
        }
        "record" => {
            only_keys(payload, &["fields"])?;
            let fields = value["fields"]
                .as_object()
                .ok_or("fields must be an object")?;
            if fields.len() > MAX_ITEMS {
                return Err("record exceeds 500 fields".into());
            }
            // Canonical protocol JSON has no floats or nulls, so values are strings, integers or
            // booleans.
            for (key, field) in fields {
                let scalar =
                    field.is_string() || field.is_boolean() || field.is_i64() || field.is_u64();
                if !name_ok(key) || !scalar {
                    return Err(format!(
                        "field {key} must have a simple name and a scalar value (string, integer or boolean)"
                    ));
                }
            }
            json!({"fields":fields})
        }
        "artifact" => {
            only_keys(payload, &["uri", "digest", "media_type"])?;
            let uri = text(value, "uri")?;
            if uri.is_empty() || uri.chars().any(char::is_control) {
                return Err("uri must be printable".into());
            }
            let mut artifact = json!({"uri":uri});
            for field in ["digest", "media_type"] {
                if value.get(field).is_some() {
                    artifact[field] = json!(text(value, field)?);
                }
            }
            artifact
        }
        _ => unreachable!(),
    };
    Ok(Some(normalized))
}

pub fn serve() -> std::process::ExitCode {
    use openaevc::extension::server::{Extension, HostContext, self_artifact_digest, serve};
    use openaevc::extension::wire::{ApplyOutput, Operation, ValidateOutput, WireError};
    use openaevc::protocol::{
        EffectKindDecl, Entrypoint, ExtensionManifest, ResourceKindDecl, SUPPORTED_CONTRACT,
        SUPPORTED_PROTOCOL,
    };

    struct General;

    impl Extension for General {
        fn manifest(&self) -> ExtensionManifest {
            ExtensionManifest {
                id: ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                protocol: SUPPORTED_PROTOCOL,
                contract: SUPPORTED_CONTRACT,
                publisher: None,
                artifact_digest: self_artifact_digest(),
                resource_kinds: KINDS
                    .iter()
                    .map(|(short, kind, _)| ResourceKindDecl {
                        kind: (*kind).into(),
                        description: Some(format!("General project {short}")),
                    })
                    .collect(),
                effect_kinds: KINDS
                    .iter()
                    .flat_map(|(_, kind, effects)| {
                        effects.iter().map(move |effect| EffectKindDecl {
                            kind: (*effect).into(),
                            resource_kind: (*kind).into(),
                            required_actions: vec![WRITE_ACTION.into()],
                        })
                    })
                    .collect(),
                verifier_kinds: vec![],
                evaluator_kinds: vec![],
                composition_validators: vec![],
                host_capabilities: vec![],
                schemas: Default::default(),
                execution_modes: vec!["subprocess".into()],
                entrypoint: Entrypoint {
                    command: "calve_ext_general".into(),
                    args: vec![],
                },
            }
        }

        fn handle(
            &mut self,
            operation: Operation,
            _: &mut HostContext<'_>,
        ) -> Result<Value, WireError> {
            let encode = |value: Result<Value, serde_json::Error>| {
                value.map_err(|e| WireError::new("encode", e.to_string()))
            };
            match operation {
                Operation::ValidateEffect { effect, .. } => {
                    let result = validate(&effect);
                    encode(serde_json::to_value(ValidateOutput {
                        valid: result.is_ok(),
                        reason: result.err(),
                    }))
                }
                Operation::ApplyEffect { effect, .. } => {
                    let value =
                        validate(&effect).map_err(|e| WireError::new("invalid_effect", e))?;
                    // Canonical protocol JSON has no null, so removal is its own outcome shape.
                    let outcome = match value {
                        Some(value) => json!({"value":value}),
                        None => json!({"removed":true}),
                    };
                    encode(serde_json::to_value(ApplyOutput { outcome }))
                }
                other => Err(WireError::new(
                    "unsupported",
                    format!("{} is not supported", other.name()),
                )),
            }
        }
    }

    serve(General)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaevc::protocol::ResourceRef;

    fn effect(kind: &str, resource: &str, locator: &str, payload: Value) -> EffectProposal {
        EffectProposal {
            kind: kind.into(),
            target: ResourceRef {
                kind: resource.into(),
                locator: locator.into(),
                version: None,
                extension: ID.into(),
            },
            payload,
            preconditions: vec![],
            outputs: vec![],
        }
    }

    #[test]
    fn validates_each_kind() {
        let note = effect(
            "org.calve.general.note.set",
            "org.calve.general.note",
            "plan",
            json!({"text":"hi"}),
        );
        assert!(validate(&note).is_ok());
        let list = effect(
            "org.calve.general.checklist.set",
            "org.calve.general.checklist",
            "launch",
            json!({"items":[{"text":"a","done":true}]}),
        );
        assert!(validate(&list).is_ok());
        let nested = effect(
            "org.calve.general.record.set",
            "org.calve.general.record",
            "r",
            json!({"fields":{"a":{"b":1}}}),
        );
        assert!(validate(&nested).is_err());
        let escape = effect(
            "org.calve.general.note.set",
            "org.calve.general.note",
            "../x",
            json!({"text":""}),
        );
        assert!(validate(&escape).is_err());
        let wrong = effect(
            "org.calve.general.note.set",
            "org.calve.general.record",
            "r",
            json!({"text":""}),
        );
        assert!(validate(&wrong).is_err());
        let removal = effect(
            "org.calve.general.artifact.detach",
            "org.calve.general.artifact",
            "spec",
            json!({}),
        );
        assert_eq!(validate(&removal), Ok(None));
    }
}
