//! Product operations that sit beside the change workflow: inbox state, pack metadata, execution
//! retry/logs, resource history, ignore-rule editing, receipts, maintenance and recovery.

use std::fs;
use std::path::{Component, Path};

use openaevc_protocol::{Digest, Event, ExecutionId, Query, WorkUnitId};
use openaevc_sdk::OpenAevcClient;
use rusqlite::params;
use serde_json::{Value, json};

use crate::ignore::IgnoreRules;
use crate::{Error, Project, Result, event, now, value_contains_exact};

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

const CAPTURE_HARNESS: &str = "org.calve.software.capture";

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
        let mut locators: Vec<String> = pack
            .candidate_effects
            .iter()
            .filter(|effect| crate::resources::is_file_effect(&effect.kind))
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
        if previous["harness"] != CAPTURE_HARNESS {
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
        let mut files = Vec::new();
        for selector in previous["allowed_resources"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let locator = selector["locator_prefix"]
                .as_str()
                .ok_or_else(|| invalid("capture scope has no file locator"))?;
            files.push(match self.read_capture_file(Path::new(locator)) {
                Ok((path, content)) => crate::FileChange::Snapshot(path, content),
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    match self.indexed_digests(true).await?.get(locator).copied() {
                        Some(previous) => crate::FileChange::Delete {
                            path: locator.to_owned(),
                            previous,
                        },
                        // The other half of a rename; its partner carries the content.
                        None => continue,
                    }
                }
                Err(error) => return Err(error),
            });
        }
        let generation = self.pack(&pack).await?.generation;
        let mut result = self
            .capture_snapshots_attempt(&pack, generation, files, Some((work_unit, execution)))
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
        let mut history = Vec::new();
        for summary in self.list_packs().await? {
            let Some(id) = summary["id"].as_str() else {
                continue;
            };
            let pack = self.pack(id).await?;
            let touches = |effect: &&openaevc_protocol::AppliedEffect| {
                crate::resources::is_file_effect(&effect.kind)
                    && (effect.target.locator == locator
                        || effect.payload["from"] == locator.as_str())
            };
            if let Some(effect) = pack.candidate_effects.iter().rev().find(touches) {
                let change = match effect.kind.as_str() {
                    crate::resources::DELETE => "deleted",
                    crate::resources::RENAME if effect.target.locator == locator => "renamed_here",
                    crate::resources::RENAME => "renamed_away",
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
        let resources = self.list_resources()?;
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
        let rules = crate::ignore::IgnoreRules::load(&self.root)?;
        for path in latest
            .keys()
            .filter(|p| !present.contains(*p) && !rules.ignored(p, false))
        {
            uncaptured.push(json!({"path":path,"state":"deleted"}));
        }
        Ok(json!({"resources":resources,"uncaptured":uncaptured}))
    }

    pub fn list_ignore(&self) -> Result<Value> {
        Ok(json!(IgnoreRules::load(&self.root)?.describe()))
    }

    pub fn add_ignore(&self, pattern: &str) -> Result<Value> {
        let pattern = ignore_pattern(pattern)?;
        let path = self.root.join(".calveignore");
        let mut contents = match fs::read_to_string(&path) {
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
        self.write_ignore(&contents)?;
        Ok(json!({"pattern":pattern,"added":true}))
    }

    pub fn remove_ignore(&self, pattern: &str) -> Result<Value> {
        let pattern = ignore_pattern(pattern)?;
        let path = self.root.join(".calveignore");
        let contents = fs::read_to_string(&path)?;
        let kept: Vec<&str> = contents.lines().filter(|line| *line != pattern).collect();
        let removed = kept.len() != contents.lines().count();
        if !removed {
            return Err(invalid(format!(
                "pattern {pattern:?} is not in .calveignore"
            )));
        }
        let mut text = kept.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        self.write_ignore(&text)?;
        Ok(json!({"pattern":pattern,"removed":true}))
    }

    /// Validates rules before replacing the file so a bad edit never lands on disk.
    fn write_ignore(&self, contents: &str) -> Result<()> {
        let path = self.root.join(".calveignore");
        let staged = self.root.join(".calve/tmp-calveignore");
        fs::write(&staged, contents)?;
        IgnoreRules::parse(contents)?;
        fs::rename(&staged, &path)?;
        event(&self.db, "ignore.updated", ".calveignore", "")
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
            .command(openaevc_protocol::Command::UnregisterExtension {
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
    actions.extend(crate::extensions::staging_leftovers());
    let staged = root.join(".calve/tmp-calveignore");
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
fn open_store(root: &Path) -> Result<openaevc_store::SqliteStore> {
    Ok(openaevc_store::SqliteStore::open(
        &root.join(".calve/openaevc"),
        openaevc_store::SqliteOptions::default(),
    )?)
}

pub fn verify_store(root: &Path) -> Result<Value> {
    use openaevc_store::Store;
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
