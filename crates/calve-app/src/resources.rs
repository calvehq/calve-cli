//! Read-only software resource views. `.calve` and symlink targets are never traversed.

use std::fs;
use std::path::{Component, Path};

use openaevc_crypto::sha256;
use openaevc_protocol::{Digest, PackState, b64};
use serde::Serialize;
use serde_json::{Value, json};

use crate::ignore::IgnoreRules;
use crate::{Error, Project, Result};

const MAX_SCAN_ENTRIES: usize = 10_000;
const MAX_SCAN_DEPTH: usize = 32;
const MAX_HASH_BYTES: u64 = 1024 * 1024;
const MAX_DIFF_LINES: usize = 200;
const MAX_TREE_FILES: usize = 64;
const MAX_TREE_BYTES: u64 = 16 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

#[derive(Serialize)]
struct ResourceSummary {
    path: String,
    kind: &'static str,
    size: Option<u64>,
    digest: Option<Digest>,
    captureable: bool,
}

fn relative_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn scan_dir(
    root: &Path,
    relative: &Path,
    depth: usize,
    rules: &IgnoreRules,
    out: &mut Vec<ResourceSummary>,
) -> Result<()> {
    if depth > MAX_SCAN_DEPTH {
        return Err(invalid("resource scan exceeds maximum depth"));
    }
    let mut entries =
        fs::read_dir(root.join(relative))?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if out.len() >= MAX_SCAN_ENTRIES {
            return Err(invalid("resource scan exceeds 10,000 entries"));
        }
        let path = relative.join(entry.file_name());
        if path
            .components()
            .next()
            .is_some_and(|part| part.as_os_str() == ".calve")
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if rules.ignored(&relative_path(&path), metadata.is_dir()) {
            continue;
        }
        if metadata.file_type().is_symlink() {
            out.push(ResourceSummary {
                path: relative_path(&path),
                kind: "symlink",
                size: None,
                digest: None,
                captureable: false,
            });
        } else if metadata.is_dir() {
            scan_dir(root, &path, depth + 1, rules, out)?;
        } else if metadata.is_file() {
            let digest = if metadata.len() <= MAX_HASH_BYTES {
                let bytes = fs::read(entry.path())?;
                (bytes.len() as u64 <= MAX_HASH_BYTES).then(|| sha256(&bytes))
            } else {
                None
            };
            out.push(ResourceSummary {
                path: relative_path(&path),
                kind: "file",
                size: Some(metadata.len()),
                digest,
                captureable: digest.is_some(),
            });
        }
    }
    Ok(())
}

fn line_changes(before: &str, after: &str) -> Option<Vec<Value>> {
    let a: Vec<&str> = before.split_inclusive('\n').collect();
    let b: Vec<&str> = after.split_inclusive('\n').collect();
    if a.len() > MAX_DIFF_LINES || b.len() > MAX_DIFF_LINES {
        return None;
    }
    let mut dp = vec![vec![0u16; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut changes = Vec::new();
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            changes.push(json!({"kind":"context","old_line":i+1,"new_line":j+1,"text":a[i]}));
            i += 1;
            j += 1;
        } else if i < a.len() && (j == b.len() || dp[i + 1][j] >= dp[i][j + 1]) {
            changes.push(json!({"kind":"remove","old_line":i+1,"text":a[i]}));
            i += 1;
        } else {
            changes.push(json!({"kind":"add","new_line":j+1,"text":b[j]}));
            j += 1;
        }
    }
    Some(changes)
}

pub(crate) const SNAPSHOT: &str = "org.calve.software.snapshot";
pub(crate) const DELETE: &str = "org.calve.software.delete";
pub(crate) const RENAME: &str = "org.calve.software.rename";

pub(crate) fn is_file_effect(kind: &str) -> bool {
    kind == SNAPSHOT || kind == DELETE || kind == RENAME
}

/// Content carried by a snapshot or rename effect, checked against its digest.
pub(crate) fn effect_content(effect: &openaevc_protocol::AppliedEffect) -> Option<Vec<u8>> {
    let content = b64::decode(effect.payload["content"].as_str()?).ok()?;
    (effect.payload["digest"].as_str() == Some(&sha256(&content).to_string())).then_some(content)
}

/// File state produced by applying software effects in order. `removed` remembers paths a
/// delete or rename took away, so materialization can remove them locally.
#[derive(Debug, Clone, Default)]
pub(crate) struct FileState {
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
    pub removed: std::collections::BTreeSet<String>,
}

impl FileState {
    pub fn apply(&mut self, effect: &openaevc_protocol::AppliedEffect) -> Result<()> {
        let path = effect.target.locator.clone();
        match effect.kind.as_str() {
            SNAPSHOT => {
                let content = effect_content(effect)
                    .ok_or_else(|| invalid(format!("snapshot of {path} fails its digest")))?;
                self.removed.remove(&path);
                self.files.insert(path, content);
            }
            DELETE => {
                self.files.remove(&path);
                self.removed.insert(path);
            }
            RENAME => {
                let content = effect_content(effect)
                    .ok_or_else(|| invalid(format!("rename to {path} fails its digest")))?;
                let from = effect.payload["from"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                self.files.remove(&from);
                self.removed.insert(from);
                self.removed.remove(&path);
                self.files.insert(path, content);
            }
            _ => {}
        }
        Ok(())
    }
}

impl Project {
    /// Accepted file state: promoted packs in creation order, stopping before `until` when
    /// given, and limited to the active Baseline's members when `baseline_only`.
    pub(crate) async fn accepted_state(&self, until: Option<&str>) -> Result<FileState> {
        let mut state = FileState::default();
        for summary in self.list_packs().await? {
            let id = summary["id"].as_str().unwrap_or_default();
            if Some(id) == until {
                break;
            }
            if summary["state"] != "PROMOTED" {
                continue;
            }
            for effect in self
                .pack(id)
                .await?
                .candidate_effects
                .iter()
                .filter(|e| is_file_effect(&e.kind))
            {
                state.apply(effect)?;
            }
        }
        Ok(state)
    }

    /// Path -> digest after applying file changes from the pack index, in pack creation order.
    /// `promoted_only` limits it to accepted history. No effect content is loaded.
    pub(crate) async fn indexed_digests(
        &self,
        promoted_only: bool,
    ) -> Result<std::collections::BTreeMap<String, Digest>> {
        self.refresh_pack_index().await?;
        let mut stmt = self.db.prepare(
            "SELECT f.path,f.change,f.digest,f.from_path FROM pack_files f
             JOIN pack_metadata m ON m.id=f.pack JOIN pack_summaries s ON s.id=f.pack
             WHERE (?1 = 0 OR s.state='PROMOTED') ORDER BY m.created_at,m.id,f.position",
        )?;
        let rows = stmt.query_map([promoted_only], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?;
        let mut state = std::collections::BTreeMap::new();
        for row in rows {
            let (path, change, digest, from) = row?;
            match change.as_str() {
                "delete" => {
                    state.remove(&path);
                }
                "rename" => {
                    if let Some(from) = from {
                        state.remove(&from);
                    }
                    if let Some(digest) = digest.and_then(|d| d.parse().ok()) {
                        state.insert(path, digest);
                    }
                }
                _ => {
                    if let Some(digest) = digest.and_then(|d| d.parse().ok()) {
                        state.insert(path, digest);
                    }
                }
            }
        }
        Ok(state)
    }

    /// Compares present files under `scope` with accepted state: changed or new files become
    /// snapshots, accepted files that are gone become deletes, and a delete whose content
    /// reappears at a new path becomes a rename. Unchanged files are left out.
    pub(crate) async fn file_changes(
        &self,
        scope: &str,
        present: Vec<(String, Vec<u8>)>,
    ) -> Result<Vec<crate::FileChange>> {
        use crate::FileChange;
        let accepted = self.indexed_digests(true).await?;
        let rules = IgnoreRules::load(&self.root)?;
        let in_scope = |path: &str| {
            scope.is_empty() || path == scope || path.starts_with(&format!("{scope}/"))
        };
        let present_paths: std::collections::BTreeSet<&str> =
            present.iter().map(|(p, _)| p.as_str()).collect();
        let mut deleted: Vec<(String, Digest)> = accepted
            .iter()
            .filter(|(path, _)| {
                in_scope(path)
                    && !present_paths.contains(path.as_str())
                    && !rules.ignored(path, false)
            })
            .map(|(path, digest)| (path.clone(), *digest))
            .collect();
        let mut changes = Vec::new();
        for (path, content) in present {
            let digest = sha256(&content);
            if accepted.get(&path) == Some(&digest) {
                continue;
            }
            let is_new = !accepted.contains_key(&path);
            match deleted
                .iter()
                .position(|(_, previous)| is_new && *previous == digest)
            {
                Some(index) => {
                    let (from, _) = deleted.remove(index);
                    changes.push(FileChange::Rename {
                        from,
                        to: path,
                        content,
                    });
                }
                None => changes.push(FileChange::Snapshot(path, content)),
            }
        }
        changes.extend(
            deleted
                .into_iter()
                .map(|(path, previous)| FileChange::Delete { path, previous }),
        );
        Ok(changes)
    }
}

impl Project {
    pub fn list_resources(&self) -> Result<Value> {
        let mut entries = Vec::new();
        let rules = IgnoreRules::load(&self.root)?;
        scan_dir(&self.root, Path::new(""), 0, &rules, &mut entries)?;
        Ok(json!(entries))
    }

    /// Captures every discoverable regular file below a directory, one protocol execution per file.
    pub async fn capture_tree(
        &self,
        pack_id: &str,
        expected_generation: u64,
        directory: &Path,
    ) -> Result<Value> {
        let root_requested = directory == Path::new(".") || directory.as_os_str().is_empty();
        let directory_text = directory
            .to_str()
            .ok_or_else(|| invalid("capture tree path must be UTF-8"))?;
        if !root_requested
            && ((cfg!(unix) && directory_text.contains('\\'))
                || directory
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
                || directory
                    .components()
                    .next()
                    .is_some_and(|part| part.as_os_str() == ".calve"))
        {
            return Err(invalid(
                "capture tree needs a relative directory outside .calve",
            ));
        }
        let relative = if root_requested {
            Path::new("")
        } else {
            directory
        };
        let mut current = self.root.clone();
        for part in relative.components() {
            current.push(part);
            if fs::symlink_metadata(&current)?.file_type().is_symlink() {
                return Err(invalid("capture tree path may not contain a symlink"));
            }
        }
        if !fs::metadata(&current)?.is_dir() {
            return Err(invalid("capture tree needs an existing directory"));
        }
        let pack = self.pack(pack_id).await?;
        if pack.state != PackState::Open || pack.generation != expected_generation {
            return Err(invalid(format!(
                "pack must be OPEN at generation {expected_generation}"
            )));
        }
        let rules = IgnoreRules::load(&self.root)?;
        if !root_requested && rules.ignored(&relative_path(relative), true) {
            return Err(invalid("capture tree directory is ignored"));
        }
        let mut entries = Vec::new();
        scan_dir(&self.root, relative, 0, &rules, &mut entries)?;
        let files: Vec<_> = entries
            .into_iter()
            .filter(|entry| entry.kind == "file")
            .collect();
        if files.len() > MAX_TREE_FILES {
            return Err(invalid(
                "capture tree exceeds 64 files; choose a smaller directory",
            ));
        }
        let total = files
            .iter()
            .try_fold(0u64, |sum, entry| sum.checked_add(entry.size.unwrap_or(0)))
            .ok_or_else(|| invalid("capture tree exceeds size limit"))?;
        if files.iter().any(|entry| !entry.captureable) || total > MAX_TREE_BYTES {
            return Err(invalid(
                "capture tree needs files of at most 1 MiB each and 16 MiB total",
            ));
        }
        let snapshots = files
            .iter()
            .map(|entry| self.read_capture_file(Path::new(&entry.path)))
            .collect::<Result<Vec<_>>>()?;
        let changes = self
            .file_changes(&relative_path(relative), snapshots)
            .await?;
        let batch = self
            .capture_snapshots_attempt(pack_id, expected_generation, changes, None)
            .await?;
        Ok(
            json!({"directory":relative_path(relative),"generation":batch["generation"],
            "execution":batch["execution"],"work_unit":batch["work_unit"],
            "captured":batch["captured"],"unchanged":batch["unchanged"]}),
        )
    }

    pub fn show_resource(&self, path: &Path) -> Result<Value> {
        let (locator, content) = self.read_capture_file(path)?;
        let digest = sha256(&content);
        let text = std::str::from_utf8(&content).ok();
        Ok(
            json!({"path":locator,"kind":"file","extension":"org.calve.software","digest":digest,"size":content.len(),"text":text,"content_base64":b64::encode(&content)}),
        )
    }

    pub async fn diff_resource(&self, pack_id: &str, path: &Path) -> Result<Value> {
        if path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(invalid("resource path must be relative"));
        }
        let locator = relative_path(path);
        let pack = self.pack(pack_id).await?;
        let captured = pack
            .candidate_effects
            .iter()
            .rev()
            .find(|effect| is_file_effect(&effect.kind) && effect.target.locator == locator);
        let current = match self.read_capture_file(path) {
            Ok((_, content)) => Some(content),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let Some(effect) = captured else {
            return Ok(
                json!({"path":locator,"pack":pack_id,"state":"not_captured","current_digest":current.as_ref().map(|bytes| sha256(bytes))}),
            );
        };
        if effect.kind == DELETE {
            let state = if current.is_some() {
                "recreated_locally"
            } else {
                "deleted"
            };
            return Ok(
                json!({"path":locator,"pack":pack_id,"state":state,"captured":"deleted",
                "current_digest":current.as_ref().map(|bytes| sha256(bytes))}),
            );
        }
        let old = b64::decode(
            effect.payload["content"]
                .as_str()
                .ok_or_else(|| invalid("invalid captured content"))?,
        )
        .map_err(|_| invalid("invalid captured content"))?;
        let old_digest = sha256(&old);
        let current_digest = current.as_ref().map(|bytes| sha256(bytes));
        let changes = if let Some(current) = current
            .as_ref()
            .filter(|bytes| old.len() <= 64 * 1024 && bytes.len() <= 64 * 1024)
        {
            match (std::str::from_utf8(&old), std::str::from_utf8(current)) {
                (Ok(before), Ok(after)) => line_changes(before, after),
                _ => None,
            }
        } else {
            None
        };
        let state = match current_digest {
            None => "deleted",
            Some(digest) if digest == old_digest => "unchanged",
            Some(_) => "modified",
        };
        Ok(
            json!({"path":locator,"pack":pack_id,"state":state,"captured_digest":old_digest,"current_digest":current_digest,"changes":changes}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::line_changes;

    #[test]
    fn line_diff_reports_changed_line() {
        let changes = line_changes("a\nb\n", "a\nc\n").unwrap();
        assert_eq!(changes[1]["kind"], "remove");
        assert_eq!(changes[2]["kind"], "add");
    }
}
