//! Local observability (PLAN §45): rolling structured logs, metrics derived from them, and
//! redacted diagnostic bundles. Nothing leaves the machine.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::registry::default_data_root;
use crate::{Error, Result};

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const KEEP_LOGS: usize = 3;

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

fn log_path() -> Option<PathBuf> {
    default_data_root()
        .ok()
        .map(|root| root.join("logs/calve.jsonl"))
}

/// Appends one structured record; logging never fails the operation it describes.
pub fn record(kind: &str, fields: Value) {
    let Some(path) = log_path() else { return };
    let _ = (|| -> std::io::Result<()> {
        let dir = path.parent().expect("log dir");
        fs::create_dir_all(dir)?;
        if fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > MAX_LOG_BYTES {
            for index in (1..KEEP_LOGS).rev() {
                let _ = fs::rename(
                    dir.join(format!("calve.{index}.jsonl")),
                    dir.join(format!("calve.{}.jsonl", index + 1)),
                );
            }
            fs::rename(&path, dir.join("calve.1.jsonl"))?;
        }
        let mut line = json!({"ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64), "kind": kind});
        if let (Some(target), Some(source)) = (line.as_object_mut(), fields.as_object()) {
            target.extend(source.clone());
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        writeln!(options.open(&path)?, "{line}")
    })();
}

fn recent(limit: usize) -> Vec<Value> {
    let Some(path) = log_path() else {
        return vec![];
    };
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(limit)..]
        .iter()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Latency and error counts per action over the most recent requests.
pub fn metrics(project_id: Option<&str>) -> Value {
    let mut by_action: std::collections::BTreeMap<String, Vec<(u64, bool)>> = Default::default();
    for entry in recent(5000).into_iter().filter(|e| e["kind"] == "request") {
        if project_id.is_some_and(|id| entry["project"].as_str().is_some_and(|p| p != id)) {
            continue;
        }
        by_action
            .entry(entry["action"].as_str().unwrap_or("?").to_owned())
            .or_default()
            .push((
                entry["duration_ms"].as_u64().unwrap_or(0),
                entry["outcome"] != "ok",
            ));
    }
    let actions: Vec<Value> = by_action
        .into_iter()
        .map(|(action, mut samples)| {
            let errors = samples.iter().filter(|(_, e)| *e).count();
            samples.sort_by_key(|(ms, _)| *ms);
            let pick = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize].0;
            json!({"action":action,"count":samples.len(),"errors":errors,
                "p50_ms":pick(0.5),"p95_ms":pick(0.95),"max_ms":samples.last().map_or(0, |s| s.0)})
        })
        .collect();
    json!({"window":"last 5000 requests","actions":actions})
}

/// Replaces secret-looking values so bundles can be shared.
fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                let lower = key.to_lowercase();
                if ["secret", "token", "password", "seed", "key"]
                    .iter()
                    .any(|word| lower.contains(word))
                    && !entry.is_object()
                    && !entry.is_array()
                {
                    *entry = json!("<redacted>");
                } else {
                    redact(entry);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact),
        _ => {}
    }
}

/// Writes a diagnostic bundle directory, or with `create = false` lists what it would write.
/// Resource contents, keys and product data are never included.
pub fn bundle(target: &Path, parts: Vec<(&str, Value)>, create: bool) -> Result<Value> {
    let files: Vec<String> = parts
        .iter()
        .map(|(name, _)| format!("{name}.json"))
        .chain(["logs.jsonl".to_owned()])
        .collect();
    if !create {
        return Ok(json!({"would_write":target,"files":files,
            "note":"secret-looking values are redacted; resource contents and keys are never included; rerun with --yes to create"}));
    }
    if target.exists() {
        return Err(invalid(format!("{} already exists", target.display())));
    }
    fs::create_dir_all(target)?;
    for (name, mut value) in parts {
        redact(&mut value);
        fs::write(
            target.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&value)?,
        )?;
    }
    let mut logs = String::new();
    for mut entry in recent(2000) {
        redact(&mut entry);
        logs.push_str(&entry.to_string());
        logs.push('\n');
    }
    fs::write(target.join("logs.jsonl"), logs)?;
    Ok(json!({"written":target,"files":files}))
}

#[cfg(test)]
mod tests {
    use super::redact;
    use serde_json::json;

    #[test]
    fn secrets_are_redacted_recursively() {
        let mut value =
            json!({"secrets":{"API_TOKEN":"env:X"},"list":[{"password":"p"}],"name":"ok"});
        redact(&mut value);
        assert_eq!(value["secrets"]["API_TOKEN"], "<redacted>");
        assert_eq!(value["list"][0]["password"], "<redacted>");
        assert_eq!(value["name"], "ok");
    }
}
