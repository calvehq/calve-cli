//! Human output (PLAN §17.1): lists are tables with per-command columns, records are aligned
//! fields with nested values indented, never raw JSON. Every string is sanitized: terminal
//! control sequences from untrusted data (file names, logs, extension text) are shown escaped
//! (§42.2). Machine output is `--json` (src/main.rs).

use std::fmt::Write as _;

use calve_api::Fault;
use serde_json::Value;

/// Preferred table columns per list command; other lists use [`DEFAULT_COLUMNS`] order.
const COLUMNS: &[(&str, &[&str])] = &[
    (
        "pack list",
        &["id", "title", "state", "generation", "intent"],
    ),
    (
        "revision list",
        &["id", "title", "state", "generation", "relation"],
    ),
    ("intent list", &["id", "title", "state", "priority"]),
    ("task list", &["id", "title", "state", "intent", "assignee"]),
    (
        "baseline list",
        &["id", "name", "state", "packs", "created_at"],
    ),
    (
        "execution list",
        &["id", "state", "harness", "provider", "task"],
    ),
    ("extension list", &["id", "version", "active", "kind"]),
    ("extension search", &["id", "catalog"]),
    (
        "extension catalog list",
        &["name", "state", "url", "root_version"],
    ),
    (
        "workspace list",
        &["id", "name", "selected", "default_project_id"],
    ),
    ("project list", &["project_id", "name", "path"]),
    ("provider list", &["id", "kind", "enabled", "scope"]),
    ("harness list", &["id", "provider", "kind"]),
    ("inbox list", &["source_key", "kind", "title", "state"]),
    ("activity", &["time", "actor", "kind", "subject"]),
    ("receipt list", &["digest", "kind", "subject"]),
    ("evidence list", &["digest", "kind", "media_type"]),
];

const DEFAULT_COLUMNS: &[&str] = &[
    "id",
    "name",
    "title",
    "kind",
    "state",
    "status",
    "version",
    "generation",
];
const MAX_COLUMNS: usize = 6;
const MAX_CELL: usize = 48;

/// Escapes control characters (incl. ESC, so no terminal sequence survives) and bidi
/// overrides; keeps newlines and tabs only where `multiline`.
pub fn sanitize(text: &str, multiline: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let bidi = matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        if (multiline && (c == '\n' || c == '\t')) || !(c.is_control() || bidi) {
            out.push(c);
        } else {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        }
    }
    out
}

fn scalar(v: &Value) -> Option<String> {
    Some(match v {
        Value::Null => "—".into(),
        Value::Bool(b) => if *b { "yes" } else { "no" }.into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => sanitize(s, false),
        _ => return None,
    })
}

fn cell(v: &Value) -> String {
    let text = match v {
        Value::Array(a) if a.iter().all(|x| scalar(x).is_some()) => {
            a.iter().filter_map(scalar).collect::<Vec<_>>().join(", ")
        }
        Value::Array(a) => format!("{} items", a.len()),
        Value::Object(o) => format!("{} fields", o.len()),
        v => scalar(v).unwrap_or_default(),
    };
    if text.chars().count() > MAX_CELL {
        let cut: String = text.chars().take(MAX_CELL - 1).collect();
        format!("{cut}…")
    } else {
        text
    }
}

fn label(key: &str) -> String {
    let mut s = key.replace('_', " ");
    if let Some(first) = s.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    s
}

fn table(out: &mut String, rows: &[Value], preferred: &[&str], indent: usize) {
    let mut cols: Vec<String> = vec![];
    let present = |k: &str| rows.iter().any(|r| r.get(k).is_some());
    for k in preferred.iter().chain(DEFAULT_COLUMNS) {
        if cols.len() < MAX_COLUMNS && !cols.iter().any(|c| c == k) && present(k) {
            cols.push((*k).to_owned());
        }
    }
    if let Some(first) = rows.first().and_then(Value::as_object) {
        for (k, v) in first {
            if cols.len() < MAX_COLUMNS && !cols.contains(k) && scalar(v).is_some() {
                cols.push(k.clone());
            }
        }
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            cols.iter()
                .map(|c| r.get(c).map(cell).unwrap_or_default())
                .collect()
        })
        .collect();
    let header: Vec<String> = cols
        .iter()
        .map(|c| c.to_uppercase().replace('_', " "))
        .collect();
    let widths: Vec<usize> = (0..cols.len())
        .map(|i| {
            cells
                .iter()
                .map(|r| r[i].chars().count())
                .chain([header[i].chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    for row in std::iter::once(&header).chain(&cells) {
        let line: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(c, w)| format!("{c:<w$}", w = *w))
            .collect();
        let _ = writeln!(out, "{}{}", " ".repeat(indent), line.join("  ").trim_end());
    }
}

fn record(out: &mut String, obj: &serde_json::Map<String, Value>, indent: usize) {
    let width = obj
        .keys()
        .map(|k| label(k).chars().count())
        .max()
        .unwrap_or(0)
        + 1;
    let pad = " ".repeat(indent);
    for (k, v) in obj {
        let name = format!("{}:", label(k));
        match v {
            Value::Object(o) if o.is_empty() => {
                let _ = writeln!(out, "{pad}{name:<width$} —");
            }
            Value::Object(o) => {
                let _ = writeln!(out, "{pad}{name}");
                record(out, o, indent + 2);
            }
            Value::Array(a) if a.is_empty() => {
                let _ = writeln!(out, "{pad}{name:<width$} none");
            }
            Value::Array(a) if a.iter().all(Value::is_object) => {
                let _ = writeln!(out, "{pad}{name}");
                table(out, a, &[], indent + 2);
            }
            Value::String(s) if s.contains('\n') => {
                let _ = writeln!(out, "{pad}{name}");
                for line in sanitize(s, true).lines() {
                    let _ = writeln!(out, "{pad}  {line}");
                }
            }
            v => {
                let _ = writeln!(out, "{pad}{name:<width$} {}", cell(v));
            }
        }
    }
}

/// Renders a successful result of `calve <key>` for a terminal or a pipe.
pub fn human(key: &str, value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::String(s) => {
            let _ = writeln!(out, "{}", sanitize(s, true));
        }
        Value::Array(a) if a.is_empty() => out.push_str("No items.\n"),
        Value::Array(a) if a.iter().all(Value::is_object) => {
            let preferred = COLUMNS
                .iter()
                .find(|(k, _)| *k == key)
                .map_or(&[][..], |(_, c)| *c);
            table(&mut out, a, preferred, 0);
        }
        Value::Array(a) => {
            for v in a {
                let _ = writeln!(out, "{}", cell(v));
            }
        }
        Value::Object(o) => record(&mut out, o, 0),
        v => {
            let _ = writeln!(out, "{}", cell(v));
        }
    }
    out
}

/// `calve: CODE: message`, then the OpenAEVC cause when there is one.
pub fn error(f: &Fault) -> String {
    let mut out = format!("calve: {}: {}\n", f.code, sanitize(&f.message, true));
    if let Some(o) = f.detail.as_ref().and_then(|d| d.get("openaevc")) {
        let _ = writeln!(
            out,
            "  OpenAEVC {}: {}",
            o["code"].as_str().unwrap_or("?"),
            sanitize(o["message"].as_str().unwrap_or(""), true)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lists_are_tables_and_records_never_raw_json() {
        let list = json!([{"id": "cpk_1", "title": "Fix", "state": "OPEN", "generation": 2, "extra": {"a": 1}}]);
        let t = human("pack list", &list);
        assert!(t.starts_with("ID"), "{t}");
        assert!(
            t.contains("cpk_1") && t.contains("OPEN") && !t.contains('{'),
            "{t}"
        );
        let rec = json!({"id": "x", "nested": {"a": 1}, "items": [{"k": "v"}], "tags": ["a", "b"], "none": null});
        let r = human("pack show", &rec);
        assert!(
            !r.contains('{') && r.contains("  A:") && r.contains("a, b") && r.contains("—"),
            "{r}"
        );
    }

    #[test]
    fn terminal_sequences_are_escaped() {
        let s = human("x", &json!({"name": "evil\u{1b}[2J\u{202e}txt"}));
        assert!(
            !s.contains('\u{1b}') && !s.contains('\u{202e}') && s.contains("\\u{1b}"),
            "{s}"
        );
    }
}
