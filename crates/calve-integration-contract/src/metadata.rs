//! `calve-integration.json` (schema `calve.integration/1`, rev 10 §8), the relation payload
//! schema subset, and the relate fatality policy (§6.5b).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::hello::{Capabilities, CicRange, Declared};

pub const SCHEMA_PREFIX: &str = "calve.integration/";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detect {
    pub markers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptionalPolicy {
    OmitOnFailure,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationDecl {
    pub kind: String,
    pub required: bool,
    pub schema: Value,
}

/// A file domain (capture, verification, materialization). Effects carry the host-generic file
/// payload `calve.file/1`: `put` = `{digest, size, content}` (content base64), `delete` =
/// `{previous_digest}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesDecl {
    pub resource_kind: String,
    pub put: String,
    pub delete: String,
    /// Content stored as chunk Blobs (`{digest, size, chunks: [{blob_digest, digest, size}]}`),
    /// for files over the inline limit (rev 10 §13). Without it larger files are refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub put_chunked: Option<String>,
    /// Effect kinds still accepted in recorded history but never emitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<String>,
    pub write_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluator: Option<String>,
    /// File names whose text the host passes to `classify` as ignore sources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_files: Vec<String>,
}

/// A non-file resource kind edited with `resource set` (`<short>:<name>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDecl {
    pub short: String,
    pub kind: String,
    pub set: String,
    pub remove: String,
    pub write_action: String,
}

/// Language checks: the verifier that judges Calve's `org.calve.check-result/v1` evidence;
/// detection and the check plan come from the `detect` and `check_plan` ops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChecksDecl {
    pub verifier: String,
}

/// Unknown keys are kept in `extra` and ignored (forward compatibility within a schema major).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub abi: u32,
    pub capabilities: Capabilities,
    pub cic: Vec<CicRange>,
    pub detect: Detect,
    pub display_name: String,
    pub extension_id: String,
    pub ops: Vec<String>,
    pub optional_relations: OptionalPolicy,
    pub relations: Vec<RelationDecl>,
    pub schema: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<FilesDecl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceDecl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<ChecksDecl>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Metadata {
    /// `N` of `calve.integration/N`.
    pub fn schema_number(&self) -> Option<u32> {
        self.schema.strip_prefix(SCHEMA_PREFIX)?.parse().ok()
    }

    pub fn declared(&self) -> Declared {
        Declared {
            abi: self.abi,
            cic: self.cic.clone(),
            capabilities: self.capabilities.clone(),
            schema: self.schema_number().unwrap_or(0),
        }
    }

    /// Structural rules checked at install (gate 2): kinds prefixed with the extension id and
    /// unique, schemas inside the supported subset, `relate.v1` declared required when any
    /// relation kind is required.
    pub fn validate(&self) -> Result<(), String> {
        self.schema_number()
            .ok_or("schema is not calve.integration/N")?;
        let mut kinds = std::collections::BTreeSet::new();
        for r in &self.relations {
            if !r.kind.starts_with(&format!("{}.", self.extension_id)) {
                return Err(format!(
                    "relation kind {} not prefixed with {}",
                    r.kind, self.extension_id
                ));
            }
            if !kinds.insert(&r.kind) {
                return Err(format!("duplicate relation kind {}", r.kind));
            }
            check_schema(&r.schema)?;
        }
        let own = |k: &str| k.starts_with(&format!("{}.", self.extension_id));
        let caps = |c: &str| self.capabilities.required.iter().any(|x| x == c);
        if let Some(f) = &self.files {
            let kinds = [&f.resource_kind, &f.put, &f.delete, &f.write_action];
            if !kinds
                .into_iter()
                .chain(&f.history)
                .chain(&f.put_chunked)
                .chain(&f.verifier)
                .chain(&f.evaluator)
                .all(|k| own(k))
            {
                return Err("files kinds must be prefixed with the extension id".into());
            }
            if !caps("capture.v1") || !caps("classify.v1") {
                return Err("a files declaration requires capture.v1 and classify.v1".into());
            }
            if f.ignore_files
                .iter()
                .any(|n| n.is_empty() || n.contains(['/', '\\', '\0']) || n == "." || n == "..")
            {
                return Err("ignore_files must be plain file names".into());
            }
        }
        let mut shorts = std::collections::BTreeSet::new();
        for r in &self.resources {
            if ![&r.kind, &r.set, &r.remove, &r.write_action]
                .into_iter()
                .all(|k| own(k))
            {
                return Err(format!(
                    "resource {} kinds must be prefixed with the extension id",
                    r.short
                ));
            }
            if r.short.is_empty()
                || !r.short.bytes().all(|b| b.is_ascii_lowercase())
                || !shorts.insert(&r.short)
            {
                return Err(format!(
                    "resource short name {:?} must be unique lowercase letters",
                    r.short
                ));
            }
        }
        if let Some(c) = &self.checks
            && (!own(&c.verifier) || !caps("detect.v1") || !caps("check_plan.v1"))
        {
            return Err("checks need an own verifier kind and detect.v1 + check_plan.v1".into());
        }
        if self.relations.iter().any(|r| r.required)
            && !self.capabilities.required.iter().any(|c| c == "relate.v1")
        {
            return Err("a required relation kind implies required capability relate.v1".into());
        }
        Ok(())
    }
}

/// The payload schema subset: `{"type":"object","properties":{k:{"type":"string"|"integer"|
/// "boolean"}},"required":[…],"additionalProperties":false}`. Anything else is refused at
/// install, so a payload is never validated against a schema the host does not understand.
pub fn check_schema(schema: &Value) -> Result<(), String> {
    let o = schema.as_object().ok_or("schema must be an object")?;
    for k in o.keys() {
        if !["type", "properties", "required", "additionalProperties"].contains(&k.as_str()) {
            return Err(format!("unsupported schema keyword {k}"));
        }
    }
    if o.get("type") != Some(&Value::from("object"))
        || o.get("additionalProperties") != Some(&Value::Bool(false))
    {
        return Err("schema must be a closed object".into());
    }
    let props = o
        .get("properties")
        .and_then(Value::as_object)
        .ok_or("properties required")?;
    for (k, p) in props {
        let t = p
            .as_object()
            .filter(|p| p.len() == 1)
            .and_then(|p| p.get("type"))
            .and_then(Value::as_str);
        if !matches!(t, Some("string" | "integer" | "boolean")) {
            return Err(format!(
                "property {k}: only {{\"type\": string|integer|boolean}}"
            ));
        }
    }
    for r in o
        .get("required")
        .and_then(Value::as_array)
        .ok_or("required list missing")?
    {
        let r = r.as_str().ok_or("required entries are strings")?;
        if !props.contains_key(r) {
            return Err(format!("required {r} not in properties"));
        }
    }
    Ok(())
}

pub fn validate_payload(schema: &Value, payload: &Value) -> Result<(), String> {
    check_schema(schema)?;
    let props = schema["properties"].as_object().expect("checked");
    let obj = payload.as_object().ok_or("payload must be an object")?;
    for (k, v) in obj {
        let ty = props
            .get(k)
            .ok_or_else(|| format!("unexpected field {k}"))?["type"]
            .as_str()
            .expect("checked");
        let ok = match ty {
            "string" => v.is_string(),
            "integer" => v.is_i64() || v.is_u64(),
            _ => v.is_boolean(),
        };
        if !ok {
            return Err(format!("field {k} is not {ty}"));
        }
    }
    for r in schema["required"].as_array().expect("checked") {
        if !obj.contains_key(r.as_str().expect("checked")) {
            return Err(format!("missing field {r}"));
        }
    }
    Ok(())
}

/// How a relate session ended, as seen by the fatality policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// `Finished` and verified; per-kind outcomes.
    Finished(Vec<(String, crate::wire::KindStatus)>),
    /// Any session-level failure (trap, ABI violation, deadline, OOM, cancel, guest error).
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelateFatal {
    /// A session failure while a required kind is declared → `RELATION_FAILED`.
    Failed(String),
    /// A required kind refused → `RELATION_REFUSED`.
    Refused(String),
    /// Optional failure with policy `fail`.
    OptionalFailed(String),
}

/// One audited omission (`relations_omitted[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Omission {
    pub kind: String,
    pub reason: String,
    pub session_failed: bool,
}

/// §6.5b fatality, decided before any effect submission. `Ok` lists the omitted kinds.
pub fn relate_outcome(meta: &Metadata, end: &SessionEnd) -> Result<Vec<Omission>, RelateFatal> {
    let mut omitted = Vec::new();
    match end {
        SessionEnd::Failed(reason) => {
            if let Some(r) = meta.relations.iter().find(|r| r.required) {
                return Err(RelateFatal::Failed(format!("{}: {reason}", r.kind)));
            }
            for r in &meta.relations {
                omitted.push(Omission {
                    kind: r.kind.clone(),
                    reason: reason.clone(),
                    session_failed: true,
                });
            }
        }
        SessionEnd::Finished(kinds) => {
            for (kind, status) in kinds {
                let crate::wire::KindStatus::Refused(reason) = status else {
                    continue;
                };
                let decl = meta.relations.iter().find(|d| &d.kind == kind);
                if decl.is_none_or(|d| d.required) {
                    return Err(RelateFatal::Refused(format!("{kind}: {reason}")));
                }
                omitted.push(Omission {
                    kind: kind.clone(),
                    reason: reason.clone(),
                    session_failed: false,
                });
            }
        }
    }
    if !omitted.is_empty() && meta.optional_relations == OptionalPolicy::Fail {
        return Err(RelateFatal::OptionalFailed(omitted[0].kind.clone()));
    }
    Ok(omitted)
}
