//! File resources on the host side (rev 10 §4, §6.4–§6.5): accepted state replayed from the
//! file domain's effects, classified scans (the extension's `classify` decides what is
//! ignored), capture planning through the CIC `capture` + `relate` sessions over manifests, and
//! read-only views. Ignore rules, rename pairing and diffs are extension semantics; `.calve` and
//! symlinks are never traversed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use calve_integration_contract::driver::{Driver, Session};
use calve_integration_contract::metadata::{SessionEnd, relate_outcome};
use calve_integration_contract::session::Relation;
use calve_integration_contract::wire::{
    ClassifyEntry, ClassifyOut, DiffOut, Entry, EntryKind, validate_classify,
};
use openaevc::crypto::sha256;
use openaevc::protocol::{AppliedEffect, Digest, PackState, b64};
use serde_json::{Value, json};

use crate::domains::{FileDomain, FileOp, cic_error, open_session};
use crate::integration::SessionLimits;
use crate::manifests::Manifest;
use crate::workspace_io::Workspace;
use crate::{Error, FileChange, Project, Result};

const MAX_SCAN_ENTRIES: usize = 10_000;
const MAX_SCAN_DEPTH: usize = 32;
/// Inline content limit per file (the approved over-limit refusal until chunked content, M4).
pub(crate) const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;
const MAX_TREE_FILES: usize = 64;
const MAX_TREE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_IGNORE_SOURCE: u64 = 64 * 1024;

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

fn io_err(e: crate::workspace_io::IoError) -> Error {
    invalid(e.to_string())
}

/// Content carried by a put/move effect, checked against its digest.
pub(crate) fn effect_content(effect: &AppliedEffect) -> Option<Vec<u8>> {
    let content = b64::decode(effect.payload["content"].as_str()?).ok()?;
    (effect.payload["digest"].as_str() == Some(&sha256(&content).to_string())).then_some(content)
}

/// File state produced by applying file-domain effects in order. `removed` remembers paths a
/// delete or move took away, so materialization can remove them locally.
#[derive(Debug, Clone, Default)]
pub(crate) struct FileState {
    pub files: BTreeMap<String, Vec<u8>>,
    pub removed: BTreeSet<String>,
}

impl FileState {
    pub fn apply(&mut self, d: &FileDomain, effect: &AppliedEffect) -> Result<()> {
        if !d.is_file_effect(effect) {
            return Ok(());
        }
        let path = effect.target.locator.clone();
        match d.op(&effect.kind) {
            Some(FileOp::Put) => {
                let content = effect_content(effect)
                    .ok_or_else(|| invalid(format!("snapshot of {path} fails its digest")))?;
                self.removed.remove(&path);
                self.files.insert(path, content);
            }
            Some(FileOp::Delete) => {
                self.files.remove(&path);
                self.removed.insert(path);
            }
            Some(FileOp::Move) => {
                let content = effect_content(effect)
                    .ok_or_else(|| invalid(format!("move to {path} fails its digest")))?;
                let from = effect.payload["from"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                self.files.remove(&from);
                self.removed.insert(from);
                self.removed.remove(&path);
                self.files.insert(path, content);
            }
            None => {}
        }
        Ok(())
    }
}

/// The index label of a file effect (`pack_files.change`).
pub(crate) fn change_label(d: &FileDomain, kind: &str) -> Option<&'static str> {
    Some(match d.op(kind)? {
        FileOp::Put => "snapshot",
        FileOp::Delete => "delete",
        FileOp::Move => "rename",
    })
}

pub(crate) fn relative_locator(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid("path must be UTF-8"))?
        .replace('\\', "/");
    if path
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(invalid("path must be relative, without '.' or '..'"));
    }
    crate::workspace_io::validate_locator(&text).map_err(io_err)?;
    Ok(text)
}

/// The declared ignore-source files that apply to entries of `dir` (it and its ancestors).
fn ignore_sources(
    ws: &Workspace,
    d: &FileDomain,
    dir: &str,
    cache: &mut BTreeMap<String, BTreeMap<String, String>>,
) -> Result<BTreeMap<String, String>> {
    if let Some(s) = cache.get(dir) {
        return Ok(s.clone());
    }
    let mut out = match dir.rsplit_once('/') {
        Some((parent, _)) => ignore_sources(ws, d, parent, cache)?,
        None if !dir.is_empty() => ignore_sources(ws, d, "", cache)?,
        None => BTreeMap::new(),
    };
    for name in &d.decl.ignore_files {
        let loc = if dir.is_empty() {
            name.clone()
        } else {
            format!("{dir}/{name}")
        };
        if ws.exists(&loc) {
            match ws.read(&loc, MAX_IGNORE_SOURCE) {
                Ok(b) => {
                    out.insert(
                        loc,
                        String::from_utf8(b)
                            .map_err(|_| invalid(format!("{name} must be UTF-8")))?,
                    );
                }
                Err(e) => return Err(invalid(format!("{name}: {e}"))),
            }
        }
    }
    cache.insert(dir.to_owned(), out.clone());
    Ok(out)
}

/// Names of the Workspace root's files, for marker-dependent ignore defaults.
// ponytail: the first MAX_MARKERS names in listing order; a root with more files may miss a
// marker, filter by declared markers if that ever matters.
pub(crate) fn root_markers(ws: &Workspace) -> Result<Vec<String>> {
    Ok(ws
        .list_dir("")
        .map_err(io_err)?
        .into_iter()
        .filter(|(_, kind, _)| *kind == EntryKind::File)
        .map(|(name, _, _)| name)
        .take(calve_integration_contract::wire::MAX_MARKERS)
        .collect())
}

/// One `classify` request (exact cardinality and path validation).
fn classify(
    s: &mut Session<Box<dyn Driver>>,
    entries: Vec<ClassifyEntry>,
    sources: BTreeMap<String, String>,
    markers: &[String],
) -> Result<Vec<(ClassifyEntry, bool, Option<String>)>> {
    if entries.is_empty() {
        return Ok(vec![]);
    }
    let got: ClassifyOut = serde_json::from_value(
        s.request(
            "classify",
            json!({"entries": entries, "ignore_sources": sources, "markers": markers}),
        )
        .map_err(cic_error)?,
    )
    .map_err(|e| invalid(format!("ABI_VIOLATION: classify: {e}")))?;
    validate_classify(&entries, &got.decisions)
        .map_err(|e| invalid(format!("ABI_VIOLATION: classify: {e}")))?;
    Ok(entries
        .into_iter()
        .zip(got.decisions)
        .map(|(e, d)| (e, d.ignored, d.rule))
        .collect())
}

/// A classified scan from `start` (`""` = root): directory by directory the extension decides
/// what is ignored; only kept directories are descended and only kept files hashed. Returns
/// files (with digest and size) and the symlinks seen.
pub(crate) fn scan(
    ws: &Workspace,
    d: &FileDomain,
    s: &mut Session<Box<dyn Driver>>,
    start: &str,
    max_entries: usize,
) -> Result<(Vec<Entry>, Vec<String>)> {
    let mut cache = BTreeMap::new();
    let markers = root_markers(ws)?;
    let (mut files, mut links) = (vec![], vec![]);
    let mut stack = vec![(start.to_owned(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_SCAN_DEPTH {
            return Err(invalid("resource scan exceeds maximum depth"));
        }
        let listed = ws.list_dir(&dir).map_err(io_err)?;
        let entries: Vec<ClassifyEntry> = listed
            .iter()
            .map(|(name, kind, size)| ClassifyEntry {
                path: if dir.is_empty() {
                    name.clone()
                } else {
                    format!("{dir}/{name}")
                },
                kind: *kind,
                size: (*kind == EntryKind::File).then_some(*size),
            })
            .collect();
        let sources = ignore_sources(ws, d, &dir, &mut cache)?;
        for (e, ignored, _) in classify(s, entries, sources, &markers)? {
            if ignored {
                continue;
            }
            if files.len() + links.len() >= max_entries {
                return Err(invalid(format!(
                    "resource scan exceeds {max_entries} entries"
                )));
            }
            match e.kind {
                EntryKind::Dir => stack.push((e.path, depth + 1)),
                EntryKind::Symlink => links.push(e.path),
                EntryKind::File => files.push(ws.hash(&e.path).map_err(io_err)?),
            }
        }
    }
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    links.sort();
    Ok((files, links))
}

/// Host-structural manifest entry for capture: path, kind and digest only, so "unchanged" is
/// exactly "same content" (size and mode are not recorded by file effects).
fn capture_entry(path: &str, digest_hex: &str) -> Entry {
    Entry {
        path: path.to_owned(),
        kind: EntryKind::File,
        digest: Some(digest_hex.to_owned()),
        size: None,
        mode: None,
        target: None,
    }
}

/// What a capture would submit: changes in path order, refusals, and verified relations.
#[derive(Debug, Default)]
pub(crate) struct CapturePlan {
    pub changes: Vec<FileChange>,
    pub refused: Vec<(String, String)>,
    pub relations: Vec<Relation>,
    /// op_index → path, for relation members.
    pub op_paths: Vec<String>,
    pub omitted: Vec<Value>,
    pub input_digest: String,
    pub output_digest: String,
}

impl Project {
    fn workspace(&self) -> Result<Workspace> {
        Workspace::open(&self.root).map_err(io_err)
    }

    fn run_dir(&self) -> std::path::PathBuf {
        self.root.join(".calve/run")
    }

    /// Accepted file state: promoted packs in creation order, stopping before `until`.
    pub(crate) async fn accepted_state(&self, until: Option<&str>) -> Result<FileState> {
        let mut state = FileState::default();
        let Ok(d) = self.file_domain().await else {
            return Ok(state);
        };
        for summary in self.list_packs().await? {
            let id = summary["id"].as_str().unwrap_or_default();
            if Some(id) == until {
                break;
            }
            if summary["state"] != "PROMOTED" {
                continue;
            }
            for effect in &self.pack(id).await?.candidate_effects {
                state.apply(&d, effect)?;
            }
        }
        Ok(state)
    }

    /// Path → digest after applying file changes from the pack index, in pack creation order.
    /// `promoted_only` limits it to accepted history. No effect content is loaded.
    pub(crate) async fn indexed_digests(
        &self,
        promoted_only: bool,
    ) -> Result<BTreeMap<String, Digest>> {
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
        let mut state = BTreeMap::new();
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

    /// Plans a capture (§6.5): `work` and `base` entries become sorted manifests; the file
    /// extension's `capture` session decides one op per path, and its `relate` session (when
    /// declared) derives relations, verified before anything is submitted. Content is read and
    /// re-checked against the scanned digest when an effect is built.
    pub(crate) async fn plan_capture(
        &self,
        d: &FileDomain,
        work: Vec<Entry>,
        base: Vec<Entry>,
        accepted: &BTreeMap<String, Digest>,
    ) -> Result<CapturePlan> {
        let cache = self.root.join(".calve/cache/manifests");
        let run = self.run_dir();
        let to_err = |e: crate::manifests::ManifestError| invalid(e.to_string());
        let mb = Manifest::from_entries(&base, &cache, &run).map_err(to_err)?;
        let mw = Manifest::from_entries(&work, &cache, &run).map_err(to_err)?;
        let limits = SessionLimits::default();
        let mut s = open_session(&d.record)?;
        let cap = crate::integration::capture(&mut s, &mb, &mw, json!({}), &run, &limits)
            .map_err(cic_error)?;
        let ws = self.workspace()?;
        let mut plan = CapturePlan {
            input_digest: cap.out.input_digest.clone(),
            output_digest: cap.out.output_digest.clone(),
            ..Default::default()
        };
        let digests: BTreeMap<&str, &str> = work
            .iter()
            .map(|e| (e.path.as_str(), e.digest.as_deref().unwrap_or_default()))
            .collect();
        for op in cap.spool.ops().map_err(cic_error)? {
            let op = op.map_err(cic_error)?;
            let path = op["path"].as_str().unwrap_or_default().to_owned();
            plan.op_paths.push(path.clone());
            match op["op"].as_str() {
                Some("add" | "modify") => {
                    let content = ws.read(&path, MAX_CAPTURE_BYTES).map_err(|e| match e {
                        crate::workspace_io::IoError::TooLarge(_) => invalid(format!(
                            "FILE_TOO_LARGE: {path} exceeds the 1 MiB capture limit"
                        )),
                        other => io_err(other),
                    })?;
                    if Some(sha256(&content).hex().as_str()) != digests.get(path.as_str()).copied()
                    {
                        return Err(invalid(format!(
                            "UNSTABLE_FILE: {path} changed during capture; retry"
                        )));
                    }
                    plan.changes.push(FileChange::Put(path, content));
                }
                Some("delete") => {
                    let previous = *accepted.get(&path).ok_or_else(|| {
                        invalid(format!("{path}: delete without accepted content"))
                    })?;
                    plan.changes.push(FileChange::Delete { path, previous });
                }
                Some("refuse") => plan
                    .refused
                    .push((path, op["reason"].as_str().unwrap_or_default().to_owned())),
                _ => {}
            }
        }
        // Relations: a separate session over the finished op stream; fatality decided before
        // any submission (§6.5b).
        let meta = d.record.metadata.as_ref().expect("cic package");
        if !meta.relations.is_empty() && s.negotiated.capabilities.contains("relate.v1") {
            let end = match open_session(&d.record).and_then(|mut r| {
                crate::integration::relate(&mut r, meta, &cap, json!({}), &run, &limits)
                    .map_err(cic_error)
            }) {
                Ok(out) => {
                    plan.relations = out.relations;
                    SessionEnd::Finished(
                        out.kinds.into_iter().map(|k| (k.kind, k.status)).collect(),
                    )
                }
                Err(e) => SessionEnd::Failed(e.to_string()),
            };
            match relate_outcome(meta, &end) {
                Ok(omitted) => {
                    plan.omitted = omitted.into_iter().map(|o| json!({"kind": o.kind, "reason": o.reason, "session_failed": o.session_failed})).collect();
                    if matches!(end, SessionEnd::Failed(_)) {
                        plan.relations.clear();
                    }
                }
                Err(e) => return Err(invalid(format!("RELATION_FAILED: {e:?}"))),
            }
        }
        Ok(plan)
    }

    /// Capture plan for explicit paths: present files (even if ignored) and accepted paths that
    /// are gone.
    pub(crate) async fn plan_paths(&self, d: &FileDomain, paths: &[String]) -> Result<CapturePlan> {
        let accepted = self.indexed_digests(true).await?;
        let ws = self.workspace()?;
        let (mut work, mut base) = (vec![], vec![]);
        for p in paths {
            if ws.exists(p) {
                let e = ws.hash(p).map_err(io_err)?;
                work.push(capture_entry(p, e.digest.as_deref().unwrap_or_default()));
            } else if !accepted.contains_key(p) {
                return Err(invalid(format!(
                    "{p} does not exist and was never accepted"
                )));
            }
            if let Some(digest) = accepted.get(p) {
                base.push(capture_entry(p, &digest.hex()));
            }
        }
        self.plan_capture(d, work, base, &accepted).await
    }

    /// Capture plan for a directory: a classified scan of `scope` against the accepted files
    /// in it (accepted paths the extension now ignores are not deleted).
    pub(crate) async fn plan_tree(
        &self,
        d: &FileDomain,
        scope: &str,
    ) -> Result<(CapturePlan, Vec<Entry>)> {
        let accepted = self.indexed_digests(true).await?;
        let ws = self.workspace()?;
        let mut s = open_session(&d.record)?;
        let (files, _) = scan(&ws, d, &mut s, scope, MAX_SCAN_ENTRIES)?;
        let in_scope =
            |p: &str| scope.is_empty() || p == scope || p.starts_with(&format!("{scope}/"));
        let present: BTreeSet<&str> = files.iter().map(|e| e.path.as_str()).collect();
        let gone: Vec<ClassifyEntry> = accepted
            .keys()
            .filter(|p| in_scope(p) && !present.contains(p.as_str()))
            .map(|p| ClassifyEntry {
                path: p.clone(),
                kind: EntryKind::File,
                size: None,
            })
            .collect();
        let mut base: Vec<Entry> = accepted
            .iter()
            .filter(|(p, _)| present.contains(p.as_str()))
            .map(|(p, d)| capture_entry(p, &d.hex()))
            .collect();
        let mut cache = BTreeMap::new();
        let markers = root_markers(&ws)?;
        for e in gone {
            let dir = e.path.rsplit_once('/').map_or("", |(d, _)| d).to_owned();
            let sources = ignore_sources(&ws, d, &dir, &mut cache)?;
            for (e, ignored, _) in classify(&mut s, vec![e], sources, &markers)? {
                if !ignored {
                    base.push(capture_entry(&e.path, &accepted[&e.path].hex()));
                }
            }
        }
        let work: Vec<Entry> = files
            .iter()
            .map(|e| capture_entry(&e.path, e.digest.as_deref().unwrap_or_default()))
            .collect();
        Ok((self.plan_capture(d, work, base, &accepted).await?, files))
    }

    pub async fn list_resources(&self) -> Result<Value> {
        let d = self.file_domain().await?;
        self.list_resources_sync(&d)
    }

    pub(crate) fn list_resources_sync(&self, d: &FileDomain) -> Result<Value> {
        let ws = self.workspace()?;
        let mut s = open_session(&d.record)?;
        let (files, links) = scan(&ws, d, &mut s, "", MAX_SCAN_ENTRIES)?;
        let mut out: Vec<Value> = files
            .iter()
            .map(|e| {
                let size = e.size.unwrap_or(0);
                json!({"path": e.path, "kind": "file", "size": size,
                    "digest": (size <= MAX_CAPTURE_BYTES).then(|| format!("sha256:{}", e.digest.as_deref().unwrap_or_default())),
                    "captureable": size <= MAX_CAPTURE_BYTES})
            })
            .collect();
        out.extend(links.iter().map(|p| json!({"path": p, "kind": "symlink", "size": null, "digest": null, "captureable": false})));
        out.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        Ok(json!(out))
    }

    /// Captures every kept file below a directory and the deletions inside it, in one
    /// execution, as planned by the file extension.
    pub async fn capture_tree(
        &self,
        pack_id: &str,
        expected_generation: u64,
        directory: &Path,
    ) -> Result<Value> {
        let root_requested = directory == Path::new(".") || directory.as_os_str().is_empty();
        let scope = if root_requested {
            String::new()
        } else {
            relative_locator(directory)?
        };
        let ws = self.workspace()?;
        if !root_requested && ws.list_dir(&scope).is_err() {
            return Err(invalid(
                "capture tree needs an existing directory (no symlinks on the path)",
            ));
        }
        let pack = self.pack(pack_id).await?;
        if pack.state != PackState::Open || pack.generation != expected_generation {
            return Err(invalid(format!(
                "pack must be OPEN at generation {expected_generation}"
            )));
        }
        let d = self.file_domain().await?;
        if !scope.is_empty()
            && self
                .classify_paths(&d, &[format!("{scope}/")])?
                .first()
                .is_some_and(|(_, ignored, _)| *ignored)
        {
            return Err(invalid("capture tree directory is ignored"));
        }
        let (plan, files) = self.plan_tree(&d, &scope).await?;
        if files.len() > MAX_TREE_FILES {
            return Err(invalid(
                "capture tree exceeds 64 files; choose a smaller directory",
            ));
        }
        let total = files
            .iter()
            .try_fold(0u64, |sum, e| sum.checked_add(e.size.unwrap_or(0)))
            .ok_or_else(|| invalid("capture tree exceeds size limit"))?;
        if files
            .iter()
            .any(|e| e.size.unwrap_or(0) > MAX_CAPTURE_BYTES)
            || total > MAX_TREE_BYTES
        {
            return Err(invalid(
                "FILE_TOO_LARGE: capture tree needs files of at most 1 MiB each and 16 MiB total",
            ));
        }
        let batch = self
            .submit_capture(pack_id, expected_generation, &d, plan, None)
            .await?;
        Ok(
            json!({"directory": scope, "generation": batch["generation"], "execution": batch["execution"],
            "work_unit": batch["work_unit"], "captured": batch["captured"], "unchanged": batch["unchanged"],
            "refused": batch["refused"], "relations": batch["relations"]}),
        )
    }

    pub async fn show_resource(&self, path: &Path) -> Result<Value> {
        let locator = relative_locator(path)?;
        let d = self.file_domain().await?;
        let content = self
            .workspace()?
            .read(&locator, MAX_CAPTURE_BYTES)
            .map_err(io_err)?;
        let text = std::str::from_utf8(&content).ok();
        Ok(
            json!({"path": locator, "kind": "file", "extension": d.extension, "digest": sha256(&content),
            "size": content.len(), "text": text, "content_base64": b64::encode(&content)}),
        )
    }

    pub async fn diff_resource(&self, pack_id: &str, path: &Path) -> Result<Value> {
        let locator = relative_locator(path)?;
        let d = self.file_domain().await?;
        let pack = self.pack(pack_id).await?;
        let captured = pack
            .candidate_effects
            .iter()
            .rev()
            .find(|e| d.is_file_effect(e) && e.target.locator == locator);
        let current = match self.workspace()?.read(&locator, MAX_CAPTURE_BYTES) {
            Ok(b) => Some(b),
            Err(crate::workspace_io::IoError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound =>
            {
                None
            }
            Err(e) => return Err(io_err(e)),
        };
        let Some(effect) = captured else {
            return Ok(
                json!({"path": locator, "pack": pack_id, "state": "not_captured", "current_digest": current.as_ref().map(|b| sha256(b))}),
            );
        };
        if d.op(&effect.kind) == Some(FileOp::Delete) {
            let state = if current.is_some() {
                "recreated_locally"
            } else {
                "deleted"
            };
            return Ok(
                json!({"path": locator, "pack": pack_id, "state": state, "captured": "deleted",
                "current_digest": current.as_ref().map(|b| sha256(b))}),
            );
        }
        let old = effect_content(effect).ok_or_else(|| invalid("invalid captured content"))?;
        let old_digest = sha256(&old);
        let current_digest = current.as_ref().map(|b| sha256(b));
        // Line changes come from the extension's `diff` op (content inline, ≤ 1 MiB a side).
        let changes = match &current {
            Some(cur) if current_digest != Some(old_digest) => {
                let out: DiffOut = serde_json::from_value(crate::domains::request(&d.record, "diff",
                    json!({"path": locator, "before": b64::encode(&old), "after": b64::encode(cur), "context": 3}))?)
                    .map_err(|e| invalid(format!("ABI_VIOLATION: diff: {e}")))?;
                match out {
                    DiffOut::Hunks { hunks } => Some(serde_json::to_value(hunks)?),
                    DiffOut::Binary | DiffOut::TooLarge => None,
                }
            }
            _ => None,
        };
        let state = match current_digest {
            None => "deleted",
            Some(digest) if digest == old_digest => "unchanged",
            Some(_) => "modified",
        };
        Ok(
            json!({"path": locator, "pack": pack_id, "state": state, "captured_digest": old_digest, "current_digest": current_digest, "changes": changes}),
        )
    }
}

impl Project {
    /// `(path, ignored, rule)` for each path, as the file extension classifies it now.
    pub(crate) fn classify_paths(
        &self,
        d: &FileDomain,
        paths: &[String],
    ) -> Result<Vec<(String, bool, Option<String>)>> {
        if paths.is_empty() {
            return Ok(vec![]);
        }
        let ws = self.workspace()?;
        let mut s = open_session(&d.record)?;
        let mut cache = BTreeMap::new();
        let markers = root_markers(&ws)?;
        let mut out = vec![];
        for p in paths {
            let dir = p.rsplit_once('/').map_or("", |(d, _)| d).to_owned();
            let kind = if p.ends_with('/') {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            let path = p.trim_end_matches('/').to_owned();
            let sources = ignore_sources(&ws, d, &dir, &mut cache)?;
            for (e, ignored, rule) in classify(
                &mut s,
                vec![ClassifyEntry {
                    path,
                    kind,
                    size: None,
                }],
                sources,
                &markers,
            )? {
                out.push((e.path, ignored, rule));
            }
        }
        Ok(out)
    }

    /// `calve ignore check`: the file extension's decision and the rule that made it.
    pub async fn check_ignore(&self, path: &Path) -> Result<Value> {
        let text = path
            .to_str()
            .ok_or_else(|| invalid("ignore check path must be UTF-8"))?
            .replace('\\', "/");
        let bare = text.trim_end_matches('/');
        if bare == ".calve" || bare.starts_with(".calve/") {
            return Ok(
                json!({"path": text, "ignored": true, "source": "hard safety", "pattern": ".calve/"}),
            );
        }
        relative_locator(Path::new(bare))?;
        let d = self.file_domain().await?;
        let is_dir = text.ends_with('/') || self.root.join(bare).is_dir();
        let probe = if is_dir {
            format!("{bare}/")
        } else {
            bare.to_owned()
        };
        let (path, ignored, rule) = self.classify_paths(&d, &[probe])?.remove(0);
        Ok(
            json!({"path": path, "ignored": ignored, "source": rule.as_ref().map(|_| d.extension.clone()), "rule": rule}),
        )
    }
}
