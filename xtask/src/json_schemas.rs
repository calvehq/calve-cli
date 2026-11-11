//! `json-schemas [--write]`: per-command JSON Schemas of `--json` output (PLAN §17, ADR 0020).
//!
//! The CLI end-to-end suites run with `CALVE_JSON_RECORD` set, so every `data` the CLI printed is
//! recorded per command. `--check` (default) validates every recorded output against
//! `docs/reference/json/v1/<command>.json` and fails on any non-additive change (a removed
//! required field, a changed type) or on a command without a schema. `--write` first runs the
//! same check, then adds schemas for new commands and new optional properties (never widening a
//! type or touching `required`), and regenerates `calve-api/src/json_commands.rs`.
//!
//! Schemas use a small JSON Schema subset: `type`, `properties`, `required`, `items`,
//! `additionalProperties` (for maps with data-derived keys).
//!
//! Typed commands (`calve_api::responses::typed`) are different: their response type is the
//! contract. Their schema is generated from the type (so optional fields, nullability and every
//! variant come from it, not from what tests printed), `--check` fails when the file differs
//! from the type, and every recorded output must deserialize into the type with no unknown field.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::{Map, Value, json};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Keys that come from data (ids, digests, paths, platform triples), not from the format.
fn data_key(k: &str) -> bool {
    k.len() > 32
        || k.contains([':', '/', '.', '-', ' ', '@'])
        || k.bytes().any(|b| b.is_ascii_uppercase())
        || (k.len() > 12 && k.contains('_') && k.bytes().filter(u8::is_ascii_digit).count() >= 4)
}

pub fn infer(samples: &[&Value]) -> Value {
    let mut kinds: BTreeSet<&str> = samples.iter().map(|v| kind(v)).collect();
    if kinds.contains("number") {
        kinds.remove("integer");
    }
    let mut schema = Map::new();
    let types: Vec<Value> = kinds.iter().map(|k| json!(k)).collect();
    schema.insert(
        "type".into(),
        if types.len() == 1 {
            types[0].clone()
        } else {
            Value::Array(types)
        },
    );
    let objects: Vec<&Map<String, Value>> = samples.iter().filter_map(|v| v.as_object()).collect();
    if !objects.is_empty() {
        let keys: BTreeSet<&String> = objects.iter().flat_map(|o| o.keys()).collect();
        if !keys.is_empty() && keys.iter().all(|k| data_key(k)) {
            let values: Vec<&Value> = objects.iter().flat_map(|o| o.values()).collect();
            schema.insert("additionalProperties".into(), infer(&values));
        } else {
            let mut props = Map::new();
            let mut required = vec![];
            for k in keys {
                let vals: Vec<&Value> = objects.iter().filter_map(|o| o.get(k)).collect();
                if vals.len() == objects.len() {
                    required.push(json!(k));
                }
                props.insert(k.clone(), infer(&vals));
            }
            schema.insert("properties".into(), Value::Object(props));
            schema.insert("required".into(), Value::Array(required));
        }
    }
    let items: Vec<&Value> = samples
        .iter()
        .filter_map(|v| v.as_array())
        .flatten()
        .collect();
    if samples.iter().any(|v| v.is_array()) {
        schema.insert(
            "items".into(),
            if items.is_empty() {
                json!({})
            } else {
                infer(&items)
            },
        );
    }
    Value::Object(schema)
}

/// Problems of `v` against `schema` (empty = valid), with JSON-pointer-like paths.
pub fn validate(schema: &Value, v: &Value, path: &str, out: &mut Vec<String>) {
    let Some(s) = schema.as_object() else { return };
    if let Some(t) = s.get("type") {
        let allowed: Vec<&str> = match t {
            Value::String(t) => vec![t.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        let k = kind(v);
        let ok = allowed.contains(&k) || (k == "integer" && allowed.contains(&"number"));
        if !ok {
            out.push(format!("{path}: {k}, schema allows {allowed:?}"));
            return;
        }
    }
    if let Some(o) = v.as_object() {
        if let Some(req) = s.get("required").and_then(Value::as_array) {
            for r in req.iter().filter_map(Value::as_str) {
                if !o.contains_key(r) {
                    out.push(format!("{path}: required field {r:?} is missing"));
                }
            }
        }
        let props = s.get("properties").and_then(Value::as_object);
        for (k, val) in o {
            match (props.and_then(|p| p.get(k)), s.get("additionalProperties")) {
                (Some(ps), _) => validate(ps, val, &format!("{path}/{k}"), out),
                (None, Some(ap)) => validate(ap, val, &format!("{path}/{k}"), out),
                (None, None) => {}
            }
        }
    }
    if let (Some(a), Some(items)) = (v.as_array(), s.get("items")) {
        for (i, x) in a.iter().enumerate() {
            validate(items, x, &format!("{path}/{i}"), out);
        }
    }
}

/// Adds what `new` knows and `old` does not: properties (optional) and empty `items`/maps.
/// Types and `required` of `old` never change.
pub fn merge(old: &Value, new: &Value) -> Value {
    let (Some(o), Some(n)) = (old.as_object(), new.as_object()) else {
        return old.clone();
    };
    let mut out = o.clone();
    if let (Some(op), Some(np)) = (
        o.get("properties").and_then(Value::as_object),
        n.get("properties").and_then(Value::as_object),
    ) {
        let mut props = op.clone();
        for (k, ns) in np {
            let merged = match op.get(k) {
                Some(os) => merge(os, ns),
                None => ns.clone(),
            };
            props.insert(k.clone(), merged);
        }
        out.insert("properties".into(), Value::Object(props));
    } else if o.get("properties").is_none()
        && o.get("additionalProperties").is_none()
        && let Some(np) = n.get("properties")
    {
        // An object first seen empty: its properties are all new, so optional.
        out.insert("properties".into(), np.clone());
        out.insert("required".into(), json!([]));
    }
    for key in ["items", "additionalProperties"] {
        match (o.get(key), n.get(key)) {
            (Some(os), Some(ns)) if os.as_object().is_some_and(Map::is_empty) => {
                out.insert(key.into(), ns.clone());
            }
            (Some(os), Some(ns)) => {
                out.insert(key.into(), merge(os, ns));
            }
            _ => {}
        }
    }
    Value::Object(out)
}

fn record(root: &Path, dir: &Path) -> Result {
    // The extension tests read the `fixture_ext` example, which `cargo test --tests` never
    // builds (a full `cargo test` does, which hid this on machines that had run one).
    let built = std::process::Command::new(env!("CARGO"))
        .current_dir(root)
        .args(["build", "--locked", "-p", "calve", "--examples"])
        .status()?;
    if !built.success() {
        return Err("building the calve examples failed".into());
    }
    let mut cmd = std::process::Command::new(env!("CARGO"));
    cmd.current_dir(root).env("CALVE_JSON_RECORD", dir).args([
        "test",
        "--locked",
        "-p",
        "calve",
        "--tests",
        "--no-fail-fast",
    ]);
    let status = cmd.status()?;
    if !status.success() {
        return Err("the recorded test run failed".into());
    }
    Ok(())
}

fn samples(dir: &Path) -> Result<BTreeMap<String, Vec<Value>>> {
    let mut out: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some((command, _)) = name.split_once('@') else {
            continue;
        };
        let value =
            serde_json::from_str(&fs::read_to_string(&p)?).map_err(|e| format!("{name}: {e}"))?;
        out.entry(command.replace('.', " "))
            .or_default()
            .push(value);
    }
    Ok(out)
}

/// `from`: reuse the recordings of an earlier run instead of running the suites again.
pub fn run(root: &Path, write: bool, from: Option<&Path>) -> Result {
    let schemas = root.join("docs/reference/json/v1");
    fs::create_dir_all(&schemas)?;
    let recorded = match from {
        Some(dir) => samples(dir)?,
        None => {
            let tmp =
                std::env::temp_dir().join(format!("calve-json-record-{}", std::process::id()));
            let _ = fs::remove_dir_all(&tmp);
            fs::create_dir_all(&tmp)?;
            record(root, &tmp)?;
            // Kept, so a schema correction can be rechecked with `--from` (no rerun).
            eprintln!("recordings in {}", tmp.display());
            samples(&tmp)?
        }
    };
    let mut problems = vec![];
    let mut missing = vec![];
    let typed: BTreeMap<&str, (Value, calve_api::responses::Check)> = calve_api::responses::typed()
        .into_iter()
        .map(|(c, s, f)| (c, (s, f)))
        .collect();
    let typed_doc = |command: &str, schema: &Value| {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": format!("calve {command} --json"),
            "description": "The `data` of the v1 envelope {\"api_version\":\"1\",\"command\",\"data\"}, generated from its response type (calve-api `responses`).",
            "schema": schema,
        })
    };
    for (command, values) in &recorded {
        if let Some((schema, check)) = typed.get(command.as_str()) {
            for v in values {
                if let Err(e) = check(v) {
                    problems.push(format!(
                        "{command}: output does not match its response type: {e}"
                    ));
                }
            }
            let file = schemas.join(calve_api::json::schema_file(command));
            let current = fs::read_to_string(&file)
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok());
            if !write && current.as_ref() != Some(&typed_doc(command, schema)) {
                missing.push(format!("{command} (typed schema out of date)"));
            }
            continue;
        }
        let file = schemas.join(calve_api::json::schema_file(command));
        let Ok(text) = fs::read_to_string(&file) else {
            missing.push(command.clone());
            continue;
        };
        let schema: Value = serde_json::from_str(&text)?;
        for v in values {
            let mut out = vec![];
            validate(&schema["schema"], v, "", &mut out);
            problems.extend(out.into_iter().map(|p| format!("{command}: {p}")));
        }
    }
    if !problems.is_empty() {
        problems.sort();
        problems.dedup();
        return Err(format!(
            "non-additive --json changes (a v1 breaking change needs v2 schemas, ADR 0020):\n  {}",
            problems.join("\n  ")
        )
        .into());
    }
    let declared: BTreeSet<String> = fs::read_dir(&schemas)?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".json").map(|c| c.replace('.', " ")))
        .collect();
    if !write {
        if !missing.is_empty() {
            return Err(format!(
                "commands without a JSON schema: {missing:?}; run `cargo xtask json-schemas --write`"
            )
            .into());
        }
        let listed: BTreeSet<String> = calve_api::json::COMMANDS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        if listed != declared {
            return Err(
                "calve-api json_commands.rs differs from the schema files; run --write".into(),
            );
        }
        println!(
            "{} commands: every recorded --json output matches its v1 schema",
            recorded.len()
        );
        return Ok(());
    }
    let mut all = declared;
    for (command, (schema, _)) in &typed {
        let file = schemas.join(calve_api::json::schema_file(command));
        fs::write(
            &file,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&typed_doc(command, schema))?
            ),
        )?;
        all.insert((*command).to_owned());
    }
    for (command, values) in recorded
        .iter()
        .filter(|(c, _)| !typed.contains_key(c.as_str()))
    {
        let refs: Vec<&Value> = values.iter().collect();
        let inferred = infer(&refs);
        let file = schemas.join(calve_api::json::schema_file(command));
        let schema = match fs::read_to_string(&file) {
            Ok(text) => merge(&serde_json::from_str::<Value>(&text)?["schema"], &inferred),
            Err(_) => inferred,
        };
        let doc = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": format!("calve {command} --json"),
            "description": "The `data` of the v1 envelope {\"api_version\":\"1\",\"command\",\"data\"}. Additional properties may appear within v1.",
            "schema": schema,
        });
        fs::write(&file, format!("{}\n", serde_json::to_string_pretty(&doc)?))?;
        all.insert(command.clone());
    }
    let list: Vec<String> = all.iter().map(|c| format!("    {c:?},\n")).collect();
    fs::write(
        root.join("crates/calve-api/src/json_commands.rs"),
        format!(
            "// Generated by `cargo xtask json-schemas --write`; do not edit.\npub const COMMANDS: &[&str] = &[\n{}];\n",
            list.concat()
        ),
    )?;
    println!("{} schemas in {}", all.len(), schemas.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inferred_schemas_accept_their_samples_and_catch_breaking_changes() {
        let a = json!({"id": "cpk_1", "n": 1, "tags": ["x"], "digests": {"sha256:ab": 1}});
        let b = json!({"id": "cpk_2", "n": 2, "tags": [], "extra": null, "digests": {}});
        let s = infer(&[&a, &b]);
        for v in [&a, &b] {
            let mut out = vec![];
            validate(&s, v, "", &mut out);
            assert!(out.is_empty(), "{out:?}");
        }
        assert!(
            s["properties"]["digests"]
                .get("additionalProperties")
                .is_some()
        );
        // Additive: a new field passes. Breaking: a removed required field or a type change.
        let mut out = vec![];
        validate(
            &s,
            &json!({"id": "x", "n": 1, "tags": [], "digests": {}, "new": 1}),
            "",
            &mut out,
        );
        assert!(out.is_empty(), "{out:?}");
        validate(
            &s,
            &json!({"n": 1, "tags": [], "digests": {}}),
            "",
            &mut out,
        );
        validate(
            &s,
            &json!({"id": 5, "n": 1, "tags": [], "digests": {}}),
            "",
            &mut out,
        );
        assert_eq!(out.len(), 2, "{out:?}");
        // Merging adds optional properties only.
        let m = merge(
            &s,
            &infer(&[&json!({"id": "y", "n": 3, "tags": [], "digests": {}, "new": true})]),
        );
        assert!(m["properties"].get("new").is_some());
        assert_eq!(m["required"], s["required"]);
    }
}
