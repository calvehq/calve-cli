//! Capture sessions (rev 10 §12, ADR 0011): journaled, resumable capture executions with a
//! Calve guard on seal/promote while a session is not terminal.
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::Result;

/// Terminal session states: nothing more happens on the pack because of this session.
pub const TERMINAL: &[&str] = &["Done", "Superseded", "Compensated", "Abandoned"];

/// `.calve/run/capture`.
pub fn dir(root: &Path) -> std::path::PathBuf {
    root.join(".calve/run/capture")
}

/// Non-terminal capture sessions on `pack` (the §12 guard).
pub fn incomplete_for_pack(root: &Path, pack: &str) -> Result<Vec<Value>> {
    let mut out = vec![];
    let Ok(rd) = fs::read_dir(dir(root)) else {
        return Ok(out);
    };
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "journal") {
            continue;
        }
        let opened = crate::journal::Journal::open(&path)
            .map_err(|e| crate::coded("RECOVERY_REQUIRED", format!("{}: {e}", path.display())))?;
        if opened.journal.header["binding"]["pack"] != pack {
            continue;
        }
        let state = opened
            .records
            .iter()
            .rev()
            .find_map(|r| r.body.get("state").and_then(Value::as_str))
            .unwrap_or("Planned")
            .to_owned();
        if !TERMINAL.contains(&state.as_str()) {
            out.push(json!({"session": opened.journal.header["journal_id"], "state": state}));
        }
    }
    Ok(out)
}
