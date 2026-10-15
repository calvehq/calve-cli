//! Product operations that sit beside the change workflow: inbox state, pack metadata, execution
//! retry/logs, resource history, ignore-rule editing, receipts, maintenance and recovery.

use std::fs;
use std::path::{Component, Path};

use openaevc::protocol::{Digest, Event, ExecutionId, Query, WorkUnitId};
use openaevc_sdk::OpenAevcClient;
use rusqlite::params;
use serde_json::{Value, json};

use crate::{Error, Project, Result, event, now, value_contains_exact};

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

fn ignore_pattern(pattern: &str) -> Result<&str> {
    let pattern = pattern.trim_end_matches(['\r', '\n']);
    if pattern.trim().is_empty() || pattern.contains(['\n', '\r']) {
        return Err(invalid("ignore pattern must be one non-empty line"));
    }
    Ok(pattern)
}

impl Project {
    pub async fn inbox_item(&self, key: &str) -> Result<Value> {
        self.inbox(true)
            .await?
            .into_iter()
            .find(|item| item["source_key"] == key)
            .ok_or_else(|| invalid(format!("no inbox item {key}")))
    }

    /// Removes the acknowledgement so the item needs attention again while it is still active.
    pub async fn unacknowledge_inbox_item(&self, key: &str) -> Result<()> {
        self.refresh_inbox().await?;
        let changed = self.db.execute(
            "UPDATE inbox_items SET acknowledged_at=NULL WHERE source_key=?1 AND resolved_at IS NULL",
            [key],
        )?;
        if changed == 0 {
            return Err(invalid(format!("no active inbox item {key}")));
        }
        event(&self.db, "inbox.item.updated", key, "unacknowledge")
    }

    /// Drops only Calve's attention projection for resolved items; protocol history is untouched.
    pub async fn clear_resolved_inbox(&self) -> Result<Value> {
        self.refresh_inbox().await?;
        let cleared = self
            .db
            .execute("DELETE FROM inbox_items WHERE resolved_at IS NOT NULL", [])?;
        event(&self.db, "inbox.cleared", "resolved", &cleared.to_string())?;
        Ok(json!({"cleared":cleared}))
    }

    pub async fn edit_pack_title(&self, id: &str, title: &str) -> Result<Value> {
        let title = title.trim();
        if title.is_empty() || title.len() > 200 || title.chars().any(char::is_control) {
            return Err(invalid("pack title must be 1–200 printable characters"));
        }
        let pack = self.pack(id).await?;
        let changed = self.db.execute(
            "UPDATE pack_metadata SET title=?1 WHERE id=?2",
            params![title, pack.id.to_string()],
        )?;
        if changed == 0 {
            return Err(invalid("pack has no Calve metadata"));
        }
        event(&self.db, "pack.renamed", &pack.id.to_string(), title)?;
        Ok(json!({"id":pack.id,"title":title}))
    }

    /// Summarizes every captured resource of a pack against the current working copy.
    pub async fn diff_pack(&self, id: &str) -> Result<Value> {
        let pack = self.pack(id).await?;
        let d = self.file_domain().await?;
        let mut locators: Vec<String> = pack
            .candidate_effects
            .iter()
            .filter(|effect| d.is_file_effect(effect))
            .map(|effect| effect.target.locator.clone())
            .collect();
        locators.sort();
        locators.dedup();
        let mut files = Vec::new();
        for locator in locators {
            let mut diff = self.diff_resource(id, Path::new(&locator)).await?;
            if let Some(map) = diff.as_object_mut() {
                map.remove("changes");
            }
            files.push(diff);
        }
        Ok(json!({"pack":pack.id,"generation":pack.generation,"files":files}))
    }

    /// Requests the protocol successor of a failed Calve capture attempt. The failed record stays.
    pub async fn retry_execution(
        &self,
        config: &crate::config::EffectiveConfig,
        id: &str,
    ) -> Result<Value> {
        let previous = self.execution(id).await?;
        if let Some(harness) = previous["harness"]
            .as_str()
            .and_then(|name| name.strip_prefix("org.calve.harness."))
        {
            if !matches!(
                previous["state"].as_str(),
                Some("FAILED" | "LOST" | "CANCELLED")
            ) {
                return Err(invalid(
                    "only FAILED, LOST or CANCELLED executions can be retried",
                ));
            }
            let execution: ExecutionId = serde_json::from_value(previous["id"].clone())?;
            let work_unit: WorkUnitId = serde_json::from_value(previous["work_unit"].clone())?;
            let pack = previous["pack"].as_str().unwrap_or_default().to_owned();
            let generation = self.pack(&pack).await?.generation;
            let mut result = self
                .start_harness_execution(
                    config,
                    &pack,
                    generation,
                    harness,
                    None,
                    Some((work_unit, execution)),
                )
                .await?;
            result["retry_of"] = json!(execution);
            return Ok(result);
        }
        let d = self.file_domain().await?;
        if previous["harness"] != d.capture_harness().as_str() {
            return Err(invalid(format!(
                "no local harness can retry {} executions",
                previous["harness"].as_str().unwrap_or("unknown")
            )));
        }
        if !matches!(
            previous["state"].as_str(),
            Some("FAILED" | "LOST" | "CANCELLED")
        ) {
            return Err(invalid(
                "only FAILED, LOST or CANCELLED executions can be retried",
            ));
        }
        let execution: ExecutionId = serde_json::from_value(previous["id"].clone())?;
        let work_unit: WorkUnitId = serde_json::from_value(previous["work_unit"].clone())?;
        let pack = previous["pack"]
            .as_str()
            .ok_or_else(|| invalid("execution has no pack"))?
            .to_owned();
        // The successor re-plans exactly the failed attempt's paths through the extension.
        let paths: Vec<String> = previous["allowed_resources"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|selector| selector["locator_prefix"].as_str().map(str::to_owned))
            .collect();
        let accepted = self.indexed_digests(true).await?;
        let ws =
            crate::workspace_io::Workspace::open(&self.root).map_err(|e| invalid(e.to_string()))?;
        let paths: Vec<String> = paths
            .into_iter()
            .filter(|p| ws.exists(p) || accepted.contains_key(p))
            .collect();
        let plan = self.plan_paths(&d, &paths).await?;
        let generation = self.pack(&pack).await?.generation;
        let mut result = self
            .submit_capture(&pack, generation, &d, plan, Some((work_unit, execution)))
            .await?;
        result["retry_of"] = json!(execution);
        Ok(result)
    }

    /// Protocol journal events that mention the execution, in sequence order.
    pub async fn execution_logs(&self, id: &str) -> Result<Value> {
        let execution = self.execution(id).await?;
        let id = execution["id"].as_str().unwrap_or(id).to_owned();
        let mut events: Vec<Event> = Vec::new();
        self.scan_protocol_events(0, |item| {
            if value_contains_exact(&serde_json::to_value(&item)?, &id) {
                events.push(item);
            }
            Ok(())
        })
        .await?;
        Ok(json!({"execution":id,"state":execution["state"],"events":events}))
    }

    /// Every captured snapshot of one resource across packs, oldest pack first.
    pub async fn resource_history(&self, path: &Path) -> Result<Value> {
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(invalid("resource path must be relative"));
        }
        let locator = path.to_string_lossy().replace('\\', "/");
        let d = self.file_domain().await?;
        let mut history = Vec::new();
        for summary in self.list_packs().await? {
            let Some(id) = summary["id"].as_str() else {
                continue;
            };
            let pack = self.pack(id).await?;
            let touches = |effect: &&openaevc::protocol::AppliedEffect| {
                d.is_file_effect(effect)
                    && (effect.target.locator == locator
                        || effect.payload["from"] == locator.as_str())
            };
            if let Some(effect) = pack.candidate_effects.iter().rev().find(touches) {
                use crate::domains::FileOp;
                let change = match d.op(&effect.kind) {
                    Some(FileOp::Delete) => "deleted",
                    Some(FileOp::Move) if effect.target.locator == locator => "renamed_here",
                    Some(FileOp::Move) => "renamed_away",
                    _ => "snapshot",
                };
                history.push(json!({"pack":pack.id,"title":summary["title"],"state":pack.state,
                    "generation":pack.generation,"change":change,"digest":effect.payload["digest"],
                    "size":effect.payload["size"],"from":effect.payload.get("from"),"to":effect.target.locator}));
            }
        }
        Ok(json!({"path":locator,"history":history}))
    }

    /// Resource scan plus which files differ from the newest capture of each path.
    pub async fn scan_resources(&self) -> Result<Value> {
        let resources = self.list_resources().await?;
        // Newest captured state across every pack, promoted or not, from the pack index.
        let latest = self.indexed_digests(false).await?;
        let mut uncaptured = Vec::new();
        let mut present = std::collections::BTreeSet::new();
        for item in resources.as_array().into_iter().flatten() {
            let path = item["path"].as_str().unwrap_or_default();
            present.insert(path.to_owned());
            let captured = latest.get(path).map(|d| json!(d));
            if item["kind"] == "file" && captured.as_ref() != Some(&item["digest"]) {
                uncaptured.push(json!({"path":path,"digest":item["digest"],
                    "state": if captured.is_some() {"modified"} else {"new"}}));
            }
        }
        let gone: Vec<String> = latest
            .keys()
            .filter(|p| !present.contains(*p))
            .cloned()
            .collect();
        let d = self.file_domain().await?;
        for (path, ignored, _) in self.classify_paths(&d, &gone)? {
            if !ignored {
                uncaptured.push(json!({"path":path,"state":"deleted"}));
            }
        }
        Ok(json!({"resources":resources,"uncaptured":uncaptured}))
    }

    /// The file extension's root ignore file (`ignore_files[0]` of its declaration).
    async fn ignore_file(&self) -> Result<(crate::domains::FileDomain, String)> {
        let d = self.file_domain().await?;
        let name = d
            .decl
            .ignore_files
            .first()
            .cloned()
            .ok_or_else(|| invalid(format!("{} declares no ignore file", d.extension)))?;
        Ok((d, name))
    }

    /// Effective rules: Calve's hard safety rule, then each line of the declared root ignore
    /// file. Built-in defaults are applied by the file extension (`classify`).
    pub async fn list_ignore(&self) -> Result<Value> {
        let (d, name) = self.ignore_file().await?;
        let mut out =
            vec![json!({"pattern":".calve/","source":"hard safety","line":null,"ignored":true})];
        let text = fs::read_to_string(self.root.join(&name)).unwrap_or_default();
        for (n, line) in text.lines().enumerate() {
            if !line.trim().is_empty() && !line.starts_with('#') {
                out.push(json!({"pattern":line,"source":name,"line":n + 1,"ignored":!line.starts_with('!')}));
            }
        }
        out.push(json!({"pattern":null,"source":format!("defaults of {}", d.extension),"line":null,"ignored":true,
            "note":"built-in defaults are decided by the extension; check a path with `calve ignore check`"}));
        Ok(json!(out))
    }

    pub async fn add_ignore(&self, pattern: &str) -> Result<Value> {
        let pattern = ignore_pattern(pattern)?;
        let (d, name) = self.ignore_file().await?;
        let mut contents = match fs::read_to_string(self.root.join(&name)) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        if contents.lines().any(|line| line == pattern) {
            return Ok(json!({"pattern":pattern,"added":false}));
        }
        if !contents.is_empty() && !contents.ends_with('\n') {
            contents.push('\n');
        }
        contents.push_str(pattern);
        contents.push('\n');
        self.write_ignore(&d, &name, &contents)?;
        Ok(json!({"pattern":pattern,"added":true}))
    }

    pub async fn remove_ignore(&self, pattern: &str) -> Result<Value> {
        let pattern = ignore_pattern(pattern)?;
        let (d, name) = self.ignore_file().await?;
        let contents = fs::read_to_string(self.root.join(&name))?;
        let kept: Vec<&str> = contents.lines().filter(|line| *line != pattern).collect();
        if kept.len() == contents.lines().count() {
            return Err(invalid(format!("pattern {pattern:?} is not in {name}")));
        }
        let mut text = kept.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        self.write_ignore(&d, &name, &text)?;
        Ok(json!({"pattern":pattern,"removed":true}))
    }

    /// The extension validates the new rules (a `classify` with them as the root source) before
    /// the file is replaced, so a bad edit never lands on disk.
    fn write_ignore(
        &self,
        d: &crate::domains::FileDomain,
        name: &str,
        contents: &str,
    ) -> Result<()> {
        if contents.len() > 64 * 1024 {
            return Err(invalid(format!("{name} must stay at most 64 KiB")));
        }
        let mut s = crate::domains::open_session(&d.record)?;
        s.request("classify", json!({"entries":[{"path":"probe","kind":"file","size":0}],"ignore_sources":{name:contents}}))
            .map_err(|e| invalid(format!("{name} rejected by {}: {e}", d.extension)))?;
        let staged = self.root.join(".calve/tmp-ignore");
        fs::write(&staged, contents)?;
        crate::workspace_io::rename_durable(&staged, &self.root.join(name))?;
        event(&self.db, "ignore.updated", name, "")
    }

    /// OpenAEVC digest-verifies objects on read; this also checks the receipt's references.
    pub async fn verify_receipt(&self, digest: Digest) -> Result<Value> {
        let object = self.receipt(digest).await?;
        let body = &object["envelope"]["body"];
        let mut problems = Vec::new();
        if object["envelope"]["namespace"] != json!(self.identity.namespace_id) {
            problems.push("receipt belongs to another Namespace".to_owned());
        }
        match (body["first_seq"].as_u64(), body["last_seq"].as_u64()) {
            (Some(first), Some(last)) if first <= last && first > 0 => {
                let span = u32::try_from(last - first + 1)
                    .unwrap_or(u32::MAX)
                    .min(1000);
                let events: Vec<Event> = serde_json::from_value(
                    self.client
                        .query(Query::ListEvents {
                            after: first - 1,
                            limit: Some(span),
                            kinds: vec![],
                        })
                        .await?,
                )?;
                if events.first().map(|e| e.sequence) != Some(first) || events.len() as u32 != span
                {
                    problems.push(format!("journal events {first}..={last} are incomplete"));
                }
            }
            // Receipts without journal events (e.g. idempotent replays) carry an empty range.
            (Some(first), Some(last)) if first > last || first == 0 => {}
            _ => problems.push("receipt has no event range".into()),
        }
        Ok(
            json!({"digest":digest,"valid":problems.is_empty(),"digest_verified":true,"problems":problems}),
        )
    }

    /// Product-database checks that need no OpenAEVC runtime access.
    pub fn check_product_db(&self) -> Result<Value> {
        let integrity: String = self
            .db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        let foreign: i64 =
            self.db
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get(0)
                })?;
        Ok(
            json!({"integrity":integrity,"foreign_key_violations":foreign,
            "ok": integrity == "ok" && foreign == 0}),
        )
    }

    pub fn compact_product_db(&self) -> Result<Value> {
        self.db
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")?;
        event(&self.db, "maintenance.compacted", "product.sqlite3", "")?;
        Ok(json!({"compacted":"product.sqlite3"}))
    }

    /// The inbox is the only derived projection Calve persists; it is rebuilt from sources.
    pub async fn rebuild_projections(&self) -> Result<Value> {
        self.reset_pack_index()?;
        self.refresh_pack_index().await?;
        self.db
            .execute("DELETE FROM inbox_items WHERE resolved_at IS NOT NULL", [])?;
        self.refresh_inbox().await?;
        let active: i64 = self
            .db
            .query_row("SELECT count(*) FROM inbox_items", [], |row| row.get(0))?;
        event(&self.db, "maintenance.projections_rebuilt", "inbox", "")?;
        Ok(json!({"rebuilt":["packs","inbox"],"active_items":active,"at":now()?}))
    }

    pub async fn extension_info(&self, id: &str) -> Result<Value> {
        let listed = self.list_extensions().await?;
        let entry = listed
            .as_array()
            .into_iter()
            .flatten()
            .find(|item| item["id"] == id)
            .cloned()
            .ok_or_else(|| invalid(format!("extension {id} is not registered")))?;
        let digest: Digest = serde_json::from_value(entry["manifest"].clone())?;
        let manifest = self.client.query(Query::GetObject { digest }).await?;
        Ok(json!({"extension":entry,"manifest":manifest["envelope"]["body"]}))
    }

    /// The permission surface a user reviews: host capabilities plus declared kinds.
    pub async fn extension_permissions(&self, id: &str) -> Result<Value> {
        let info = self.extension_info(id).await?;
        let manifest = &info["manifest"];
        Ok(
            json!({"id":id,"granted_host_capabilities":info["extension"]["granted_host_capabilities"],
            "requested_host_capabilities":manifest["host_capabilities"],
            "resource_kinds":manifest["resource_kinds"],"effect_kinds":manifest["effect_kinds"]}),
        )
    }

    pub async fn disable_extension(&self, id: &str) -> Result<Value> {
        self.extension_info(id).await?;
        self.release_extension_usage(id).await?;
        let receipt = self
            .client
            .command(openaevc::protocol::Command::UnregisterExtension {
                extension: id.into(),
            })
            .await?;
        event(&self.db, "extension.disabled", id, "")?;
        Ok(serde_json::to_value(receipt)?)
    }

    pub async fn extension_health(&self) -> Result<Value> {
        let mut report = Vec::new();
        for entry in self
            .list_extensions()
            .await?
            .as_array()
            .into_iter()
            .flatten()
        {
            let manifest = serde_json::from_value::<Digest>(entry["manifest"].clone())
                .map_err(Error::from)
                .map(|digest| Query::GetObject { digest });
            let problem = match manifest {
                Ok(query) => self.client.query(query).await.err().map(|e| e.message),
                Err(error) => Some(error.to_string()),
            };
            report.push(json!({"id":entry["id"],"active":entry["active"],
                "healthy": entry["active"] == true && problem.is_none(),"problem":problem}));
        }
        Ok(json!(report))
    }

    /// `store` comes from [`verify_store`], which must run before the Project runtime opens.
    pub fn maintenance_check(&self, store: Value) -> Result<Value> {
        let product = self.check_product_db()?;
        let recovery = recovery_plan(&self.root)?;
        Ok(
            json!({"ok":product["ok"] == true && store["ok"] == true && recovery.is_empty(),
            "product_db":product,"store":store,"recovery_actions":recovery}),
        )
    }
}

/// Leftovers that are provably disposable: staging from interrupted init/ignore edits.
/// Recovery never touches OpenAEVC state or the product database.
pub fn recovery_plan(root: &Path) -> Result<Vec<Value>> {
    let mut actions = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let stale = entry
            .metadata()?
            .modified()?
            .elapsed()
            .is_ok_and(|age| age.as_secs() > 600);
        if name.starts_with(".calve-init-") && entry.file_type()?.is_dir() && stale {
            actions.push(json!({"action":"remove_staging_dir","path":entry.path(),
                "reason":"left by an interrupted calve init"}));
        }
    }
    actions.extend(crate::adopt::adoption_leftovers(root)?);
    // Interrupted package installs/retirements (machine-level journals, §9.4).
    if let Ok(paths) = crate::extensions::machine_paths()
        && let Ok(rd) = fs::read_dir(paths.data.join("run/install"))
    {
        let n = rd
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|x| x == "journal" || x == "retire")
            })
            .count();
        if n > 0 {
            actions.push(json!({"action":"reconcile_install_journals","count":n,
                "reason":"package install interrupted; staging is removed or the install completed"}));
        }
    }
    let staged = root.join(".calve/tmp-ignore");
    if staged.is_file() {
        actions.push(json!({"action":"remove_file","path":staged,
            "reason":"left by an interrupted ignore edit"}));
    }
    Ok(actions)
}

pub fn recovery_apply(root: &Path) -> Result<Value> {
    let actions = recovery_plan(root)?;
    for action in &actions {
        let path = Path::new(action["path"].as_str().unwrap_or_default());
        match action["action"].as_str() {
            Some("remove_staging_dir") => fs::remove_dir_all(path)?,
            Some("remove_file") => fs::remove_file(path)?,
            Some("reconcile_install_journals") => {
                crate::extensions::recover_installs()?;
            }
            Some("restore_adoption_source") => {
                let state = root.join(".calve");
                if state.exists() {
                    fs::remove_dir_all(&state)?;
                }
                fs::rename(path, state)?;
            }
            _ => {}
        }
    }
    crate::observe::record("recovery", json!({"root":root,"actions":actions}));
    Ok(json!({"applied":actions}))
}

/// OpenAEVC admits one runtime per data root, so these run while no Project is open.
fn open_store(root: &Path) -> Result<openaevc::store::SqliteStore> {
    Ok(openaevc::store::SqliteStore::open(
        &root.join(".calve/openaevc"),
        openaevc::store::SqliteOptions::default(),
    )?)
}

pub fn verify_store(root: &Path) -> Result<Value> {
    use openaevc::store::Store;
    let report = open_store(root)?.verify_integrity()?;
    Ok(
        json!({"ok":report.ok(),"problems":report.problems,"namespaces":report.namespaces,
        "events":report.events,"objects":report.objects}),
    )
}

/// Delegates collection to OpenAEVC, which never removes indexed (accepted) objects.
pub fn collect_garbage(root: &Path, grace_secs: u64, dry_run: bool) -> Result<Value> {
    if dry_run {
        return Ok(json!({"dry_run":true,"grace_secs":grace_secs,
            "plan":"OpenAEVC removes unindexed objects and orphan CAS files older than the grace period; indexed history is never removed"}));
    }
    let report = open_store(root)?.collect_garbage(std::time::Duration::from_secs(grace_secs))?;
    Ok(json!({"dry_run":false,"scanned":report.scanned,"removed":report.removed}))
}
