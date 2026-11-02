//! Application use cases behind the versioned API; the CLI, daemon and console all call
//! [`execute`].

use std::path::PathBuf;
use std::{fs::OpenOptions, path::Path};

use openaevc::protocol::{Digest, ResourceRef, RevisionRelation};
use openaevc_sdk::OpenAevcClient;
use serde_json::{Value, json};

pub use calve_api::*;

use crate::compatibility;
use crate::config::{ConfigPaths, Scope};
use crate::registry::Registry;
use crate::{Error, Project, Result};

tokio::task_local! {
    /// The Calve request being served: `(request_id, correlation_id, OpenAEVC calls so far,
    /// acting principal)`.
    static REQUEST: (
        uuid::Uuid,
        Option<uuid::Uuid>,
        std::cell::Cell<u32>,
        std::cell::RefCell<Option<String>>,
    );
}

/// The OpenAEVC idempotency key of the next state-changing call in this request (§45.2):
/// `calve:<request id>:<purpose>:<n>`. A retried request (same id) reproduces the same keys, so
/// OpenAEVC deduplicates it; outside a request a fresh key is used.
pub(crate) fn idempotency_key(purpose: &str) -> String {
    REQUEST
        .try_with(|(id, _, n, _)| {
            let k = n.get();
            n.set(k + 1);
            format!("calve:{id}:{purpose}:{k}")
        })
        .unwrap_or_else(|_| uuid::Uuid::now_v7().to_string())
}

fn parse_digests(values: &[String]) -> Result<Vec<Digest>> {
    values
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|_| crate::coded("INVALID_ARGUMENT", format!("invalid digest {s}")))
        })
        .collect()
}

/// `FROM:TO` (FROM requires TO) or `FROM:TO:orders-after` with promoted-pack digests (each
/// `sha256:<hex>`, so the separator is the third `:`-field boundary).
fn parse_edges(values: &[String]) -> Result<Vec<openaevc::protocol::CompositionEdge>> {
    use openaevc::protocol::{CompositionEdge, CompositionEdgeKind};
    values
        .iter()
        .map(|v| {
            let parts: Vec<&str> = v.split(':').collect();
            let (from, to, kind) = match parts.as_slice() {
                [a, b, c, d] => (format!("{a}:{b}"), format!("{c}:{d}"), "requires"),
                [a, b, c, d, k] => (format!("{a}:{b}"), format!("{c}:{d}"), *k),
                _ => {
                    return Err(crate::coded(
                        "INVALID_ARGUMENT",
                        format!("edge {v} must be FROM:TO[:requires|orders-after]"),
                    ));
                }
            };
            let kind = match kind {
                "requires" => CompositionEdgeKind::Requires,
                "orders-after" => CompositionEdgeKind::OrdersAfter,
                k => {
                    return Err(crate::coded(
                        "INVALID_ARGUMENT",
                        format!("edge kind {k} must be requires or orders-after"),
                    ));
                }
            };
            Ok(CompositionEdge {
                from: parse_digests(&[from])?[0],
                to: parse_digests(&[to])?[0],
                kind,
                relation: None,
            })
        })
        .collect()
}

/// Records the principal acting in this request (product activity carries it, §30.2).
pub(crate) fn set_actor(principal: String) {
    let _ = REQUEST.try_with(|(.., actor)| *actor.borrow_mut() = Some(principal));
}

/// The acting principal of the current request, if any.
pub(crate) fn current_actor() -> Option<String> {
    REQUEST
        .try_with(|(.., actor)| actor.borrow().clone())
        .ok()
        .flatten()
}

/// `(extension, dotted capability)` of an OpenAEVC host-call denial: its extension error has code
/// `denied` and ends with the capability's variant name (`ProcessExecute` → `process.execute`).
fn denied_capability(error: &openaevc::protocol::ProtocolError) -> Option<(String, String)> {
    let info = error
        .extension_error
        .as_ref()
        .filter(|e| e.code == "denied")?;
    let variant = info.message.rsplit(": ").next()?;
    let mut dotted = String::new();
    for c in variant.chars() {
        if c.is_ascii_uppercase() && !dotted.is_empty() {
            dotted.push('.');
        }
        dotted.push(c.to_ascii_lowercase());
    }
    Some((info.extension_id.clone(), dotted))
}

/// Maps product errors onto the stable codes of [`calve_api::errors`] (§41). OpenAEVC errors keep
/// their structured form in `detail.openaevc`; every message and detail is redacted against the
/// secrets registered in this process (§16.1).
pub fn fault(error: Error) -> Fault {
    use calve_api::errors::{openaevc_code, split_code};
    let (code, message, retryable, detail): (&str, String, bool, Option<Value>) = match error {
        // A host call the extension holds no grant for: not a transient failure, and the user
        // can act on it (§57 G). OpenAEVC's own error stays in the detail.
        Error::Protocol(protocol) if denied_capability(&protocol).is_some() => {
            let (extension, capability) = denied_capability(&protocol).expect("checked");
            (
                "CAPABILITY_DENIED",
                format!(
                    "extension {extension} lacks the host capability {capability}, so OpenAEVC denied the operation; grant it with `calve extension grant {extension} {capability}`"
                ),
                false,
                Some(
                    json!({"openaevc": &*protocol, "extension": extension, "capability": capability}),
                ),
            )
        }
        Error::Protocol(protocol) => (
            openaevc_code(protocol.code.as_str()),
            protocol.message.clone(),
            protocol.retryable,
            Some(json!({"openaevc": &*protocol})),
        ),
        Error::Message(message) => match split_code(&message) {
            Some((code, rest)) => (code, rest.to_owned(), false, None),
            None => ("PRODUCT_ERROR", message, false, None),
        },
        Error::Detailed {
            code,
            message,
            detail,
        } => (code, message, code == "PROJECT_LOCKED", Some(detail)),
        Error::Busy(message) => ("PROJECT_LOCKED", message, true, None),
        Error::Io(error) => ("IO_ERROR", error.to_string(), false, None),
        Error::Database(error) => match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                ("PROJECT_LOCKED", error.to_string(), true, None)
            }
            Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase) => {
                ("CORRUPT_PRODUCT_STATE", error.to_string(), false, None)
            }
            _ => ("INTERNAL", error.to_string(), false, None),
        },
        Error::TomlRead(error) => ("INVALID_CONFIGURATION", error.to_string(), false, None),
        Error::TomlWrite(error) => ("INTERNAL", error.to_string(), false, None),
        Error::Json(error) => ("INTERNAL", error.to_string(), false, None),
    };
    let redact = crate::redact::active();
    Fault {
        code: code.into(),
        message: redact.text(&message),
        retryable,
        detail: detail
            .map(|d| serde_json::from_str(&redact.text(&d.to_string())).unwrap_or(Value::Null)),
    }
}

fn workspace_command(registry: &mut Registry, command: WorkspaceCommand) -> Result<Value> {
    Ok(match command {
        WorkspaceCommand::List => json!(registry.list()?),
        WorkspaceCommand::Show { workspace } => json!(match workspace {
            Some(name) => registry.show(&name)?,
            None => registry.selected()?,
        }),
        WorkspaceCommand::Create { name } => json!(registry.create(&name)?),
        WorkspaceCommand::Rename { workspace, name } => json!(registry.rename(&workspace, &name)?),
        WorkspaceCommand::Select { workspace } => json!(registry.select(&workspace)?),
        WorkspaceCommand::AddProject { workspace, project } => {
            json!(registry.add_project(&workspace, &project)?)
        }
        WorkspaceCommand::RemoveProject { workspace, project } => {
            json!(registry.remove_project(&workspace, &project)?)
        }
        WorkspaceCommand::SetDefaultProject { workspace, project } => {
            json!(registry.set_default_project(&workspace, &project)?)
        }
        WorkspaceCommand::Delete {
            workspace, force, ..
        } => {
            registry.delete(&workspace, force)?;
            json!({"deleted":workspace})
        }
    })
}

fn project_command(
    registry: &mut Registry,
    command: ProjectCommand,
    workspace: Option<&str>,
) -> Result<Value> {
    Ok(match command {
        ProjectCommand::List => json!(registry.projects()?),
        ProjectCommand::Show { project } => json!(registry.project(&project)?),
        ProjectCommand::AuthorityExport { .. } | ProjectCommand::AuthorityImport { .. } => {
            unreachable!("handled before a registry command")
        }
        ProjectCommand::Register { path } => {
            let project = Project::peek(&path)?;
            json!(registry.register_project(&project, workspace)?)
        }
        ProjectCommand::Unregister { project, .. } => {
            registry.unregister(&project)?;
            json!({"unregistered":project})
        }
        ProjectCommand::Relocate { project, path } => json!(registry.relocate(&project, &path)?),
        ProjectCommand::AdoptCopy { .. } => unreachable!("adopt-copy is dispatched asynchronously"),
        ProjectCommand::Rename { project, name } => {
            let entry = registry.project(&project)?;
            let _writer = project_writer(&entry.path)?;
            evict_project(&entry.path);
            let mut opened = Project::open(&entry.path)?;
            registry.ensure_project_path(&opened.identity, &opened.root)?;
            let previous = entry.name;
            registry.rename_project(&entry.project_id, &name)?;
            if let Err(error) = opened.rename(&name) {
                let _ = registry.rename_project(&entry.project_id, &previous);
                return Err(error);
            }
            json!(registry.project(&entry.project_id)?)
        }
        ProjectCommand::Identity { project } => {
            let entry = registry.project(&project)?;
            json!(Project::peek(&entry.path)?.identity)
        }
        ProjectCommand::Health { project } => project_health(registry, &project)?,
    })
}

/// §29.4: per-Project attention counts of the selected Workspace, from each product DB opened
/// read-only (the counts are as of that Project's last Inbox refresh).
fn inbox_summary(registry: &Registry) -> Result<Value> {
    use calve_api::responses::{InboxCounts, InboxSummary, InboxSummaryProject};
    let now = crate::now()?;
    let mut projects = vec![];
    for p in registry.selected()?.projects {
        let db = p.path.join(".calve/product.sqlite3");
        let counts = rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .and_then(|c| {
                c.query_row(
                    "SELECT count(*), coalesce(sum(severity='danger'),0), max(last_seen) FROM inbox_items
                     WHERE resolved_at IS NULL AND acknowledged_at IS NULL
                     AND (snoozed_until IS NULL OR snoozed_until <= ?1)",
                    [now],
                    |r| Ok(InboxCounts { attention: r.get(0)?, danger: r.get(1)?, as_of: r.get(2)? }),
                )
            });
        let (inbox, error) = match counts {
            Ok(c) => (Some(c), None),
            Err(e) => (None, Some(e.to_string())),
        };
        projects.push(InboxSummaryProject {
            project_id: p.project_id,
            name: p.name,
            path: p.path.display().to_string(),
            inbox,
            error,
        });
    }
    Ok(json!(InboxSummary { projects }))
}

pub(crate) fn project_health(registry: &Registry, identifier: &str) -> Result<Value> {
    let supplied = Path::new(identifier);
    let entry = if supplied.exists() {
        match Project::peek(supplied) {
            Ok(candidate) => {
                let registered = registry.project(&candidate.identity.project_id).ok();
                return Ok(match registered {
                    Some(entry) => health_at_registered_path(registry, entry, candidate),
                    None => {
                        json!({"status":"unregistered","project_id":candidate.identity.project_id,
                        "namespace_id":candidate.identity.namespace_id,"candidate_path":candidate.root,
                        "findings":[{"code":"UNREGISTERED","message":"Project is not registered in a Workspace"}]})
                    }
                });
            }
            Err(error) => {
                return Ok(json!({"status":"invalid_project","candidate_path":supplied,
                    "findings":[{"code":"PROJECT_OPEN_FAILED","message":error.to_string()}]}));
            }
        }
    } else {
        registry.project(identifier)?
    };
    if !entry.path.exists() {
        return Ok(
            json!({"status":"missing_path","project_id":entry.project_id,
            "namespace_id":entry.namespace_id,"registered_path":entry.path,
            "findings":[{"code":"REGISTERED_PATH_MISSING","message":"Registered Project path does not exist; relocate the Project if it was moved"}]}),
        );
    }
    match Project::peek(&entry.path) {
        Ok(candidate) => Ok(health_at_registered_path(registry, entry, candidate)),
        Err(error) => Ok(
            json!({"status":"invalid_project","project_id":entry.project_id,
            "registered_path":entry.path,"findings":[{"code":"PROJECT_OPEN_FAILED","message":error.to_string()}]}),
        ),
    }
}

fn health_at_registered_path(
    registry: &Registry,
    entry: crate::registry::ProjectEntry,
    candidate: crate::ProjectInfo,
) -> Value {
    let same_identity = entry.project_id == candidate.identity.project_id
        && entry.namespace_id == candidate.identity.namespace_id.to_string();
    let same_path = entry.path == candidate.root;
    let status = if !same_identity
        || registry
            .ensure_project_path(&candidate.identity, &candidate.root)
            .is_err()
            && same_path
    {
        "identity_conflict"
    } else if !same_path && entry.path.exists() {
        "duplicate_copy"
    } else if !same_path {
        "relocation_needed"
    } else if entry.name != candidate.display_name {
        "name_out_of_sync"
    } else {
        "healthy"
    };
    let findings = match status {
        "identity_conflict" => vec![
            json!({"code":"IDENTITY_CONFLICT","message":"Project identity or Namespace does not match its registration"}),
        ],
        "duplicate_copy" => vec![
            json!({"code":"DUPLICATE_COPY","message":"Another live path is registered with this Project identity; writes to this copy are blocked"}),
        ],
        "relocation_needed" => vec![
            json!({"code":"RELOCATION_NEEDED","message":"Registered path is missing; run project relocate after confirming this is the moved Project"}),
        ],
        "name_out_of_sync" => vec![
            json!({"code":"NAME_OUT_OF_SYNC","message":"Registry and Project display names differ; run project rename to reconcile them"}),
        ],
        _ => vec![],
    };
    json!({"status":status,"project_id":candidate.identity.project_id,
        "namespace_id":candidate.identity.namespace_id,"registered_path":entry.path,
        "candidate_path":candidate.root,"name":candidate.display_name,"findings":findings})
}

/// Every project-scoped command takes the writer lock, except cancel; queries never do.
fn mutates_project(command: &Action) -> bool {
    command.kind() == OperationKind::Command
}

/// A run holds the writer lock until it ends, so cancelling it cannot wait for that lock. Cancel
/// is a single OpenAEVC command, serialized by OpenAEVC, with no Calve state to protect.
fn takes_writer_lock(command: &Action) -> bool {
    mutates_project(command)
        && !matches!(
            command,
            Action::Execution {
                command: ExecutionCommand::Cancel { .. }
                    | ExecutionCommand::Start { .. }
                    | ExecutionCommand::Retry { .. }
            }
        )
}

/// The part of the working tree a command touches, when it must not race a run changing it.
fn tree_scope(action: &Action) -> Option<(&'static str, Vec<String>)> {
    let path = |p: &std::path::Path| p.to_string_lossy().replace('\\', "/");
    match action {
        Action::Baseline {
            command: BaselineCommand::Materialize { apply: true, .. },
        }
        | Action::Materialize { .. } => Some(("materialization", vec![])),
        Action::Resource {
            command:
                ResourceCommand::Materialize {
                    path: p,
                    apply: true,
                    ..
                },
        } => Some(("materialization", vec![p.clone()])),
        Action::Pack {
            command: PackCommand::Lifecycle(LifecycleCommand::Capture { path: p, .. }),
        }
        | Action::Revision {
            command: RevisionCommand::Lifecycle(LifecycleCommand::Capture { path: p, .. }),
        } => Some(("this capture", vec![path(p)])),
        Action::Pack {
            command: PackCommand::CaptureTree { .. },
        } => Some(("this capture", vec![])),
        _ => None,
    }
}

/// Waits briefly for the writer lock: runs and commands now hold it for short sections.
pub(crate) async fn project_writer_wait(
    root: &Path,
    wait: std::time::Duration,
) -> Result<std::fs::File> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match project_writer(root) {
            Err(crate::Error::Detailed {
                code: "PROJECT_LOCKED",
                ..
            }) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            other => return other,
        }
    }
}

fn resolve_project_path(
    registry: &Registry,
    requested: Option<PathBuf>,
    workspace: Option<&str>,
) -> Result<PathBuf> {
    if let Some(value) = requested {
        if value.exists() {
            return Ok(value);
        }
        return Ok(registry.project(&value.to_string_lossy())?.path);
    }
    let cwd = std::env::current_dir()?;
    if Project::discover(&cwd).is_ok() {
        return Ok(cwd);
    }
    let selected = match workspace {
        Some(name) => registry.show(name)?,
        None => registry.selected()?,
    };
    let id = selected.workspace.default_project_id.ok_or_else(|| {
        crate::coded(
            "PROJECT_NOT_FOUND",
            "no project found and this workspace has no default project",
        )
    })?;
    Ok(registry.project(&id)?.path)
}

fn config_command(
    registry: &Registry,
    command: ConfigCommand,
    requested: Option<PathBuf>,
    workspace: Option<&str>,
    override_file: Option<PathBuf>,
) -> Result<Value> {
    let view = match workspace {
        Some(name) => registry.show(name)?,
        None => registry.selected()?,
    };
    let project_root = if requested.is_some() {
        Some(Project::discover(&resolve_project_path(
            registry, requested, workspace,
        )?)?)
    } else {
        resolve_project_path(registry, None, workspace)
            .ok()
            .and_then(|path| Project::discover(&path).ok())
    };
    let paths =
        ConfigPaths::for_context(&view.workspace.id, project_root.as_deref(), override_file)?;
    let ensure_project_write = || -> Result<()> {
        let root = project_root
            .as_deref()
            .ok_or_else(|| Error::Message("project scope requires a Project".into()))?;
        let project = Project::peek(root)?;
        registry.ensure_project_path(&project.identity, &project.root)
    };
    let mut _writer = None;
    Ok(match command {
        ConfigCommand::List => json!(paths.load()?),
        ConfigCommand::Get { key } => paths.get(&key)?,
        ConfigCommand::Set { key, value, scope } => {
            let scope: Scope = scope.parse()?;
            if scope == Scope::Project {
                ensure_project_write()?;
                _writer = Some(project_writer(
                    project_root.as_deref().expect("checked project root"),
                )?);
            }
            paths.set(scope, &key, &value)?;
            json!({"key":key,"value":paths.get(&key)?,"scope":scope.to_string()})
        }
        ConfigCommand::Unset { key, scope } => {
            let scope: Scope = scope.parse()?;
            if scope == Scope::Project {
                ensure_project_write()?;
                _writer = Some(project_writer(
                    project_root.as_deref().expect("checked project root"),
                )?);
            }
            paths.unset(scope, &key)?;
            json!({"unset":key,"scope":scope.to_string()})
        }
        ConfigCommand::Validate => {
            let effective = paths.load()?;
            json!({"valid":true,"warnings":effective.warnings,"sources":effective.sources})
        }
        ConfigCommand::Approve => {
            let path = paths.project.clone().ok_or_else(|| {
                crate::coded("PROJECT_NOT_FOUND", "no Project configuration here")
            })?;
            let digest = crate::authority::approve_config(&path)?;
            json!({"approved": digest, "path": path})
        }
        ConfigCommand::EditPath { scope } => {
            let scope: Scope = scope.parse()?;
            json!({"path":paths.path(scope)?})
        }
    })
}

/// Package-cache and catalog commands are machine-wide; `list` is too unless it asks for a
/// Project's registrations.
fn extension_is_global(command: &ExtensionCommand, has_project: bool) -> bool {
    match command {
        ExtensionCommand::List { installed } => *installed || !has_project,
        ExtensionCommand::Catalog { .. }
        | ExtensionCommand::Search { .. }
        | ExtensionCommand::Install { .. }
        | ExtensionCommand::SwitchPublisher { .. }
        | ExtensionCommand::Uninstall { .. } => true,
        _ => false,
    }
}

/// Config paths for the selected Workspace and, when one resolves, the current Project.
fn context_config(
    registry: &Registry,
    requested: Option<PathBuf>,
    workspace: Option<&str>,
    override_file: Option<PathBuf>,
) -> Result<ConfigPaths> {
    let view = match workspace {
        Some(name) => registry.show(name)?,
        None => registry.selected()?,
    };
    let root = if requested.is_some() {
        Some(Project::discover(&resolve_project_path(
            registry, requested, workspace,
        )?)?)
    } else {
        resolve_project_path(registry, None, workspace)
            .ok()
            .and_then(|path| Project::discover(&path).ok())
    };
    ConfigPaths::for_context(&view.workspace.id, root.as_deref(), override_file)
}

fn provider_command(
    registry: &Registry,
    command: ProviderCommand,
    requested: Option<PathBuf>,
    workspace: Option<&str>,
    override_file: Option<PathBuf>,
) -> Result<Value> {
    use crate::config::{ProviderKind, ProviderProfile};
    use crate::providers;
    let paths = context_config(registry, requested, workspace, override_file)?;
    let config = paths.load()?;
    let existing = |id: &str| -> Result<ProviderProfile> {
        config.providers.get(id).cloned().ok_or_else(|| {
            crate::coded(
                "PROVIDER_UNAVAILABLE",
                format!("provider {id} is not configured"),
            )
        })
    };
    let apply = |profile: &mut ProviderProfile, fields: ProviderFields| -> Result<()> {
        if let Some(kind) = fields.kind {
            profile.kind = if kind == "stdio-agent" {
                ProviderKind::StdioAgent
            } else {
                ProviderKind::LocalProcess
            };
        }
        if fields.name.is_some() {
            profile.name = fields.name;
        }
        if fields.executable.is_some() {
            profile.executable = fields.executable;
        }
        if !fields.args.is_empty() {
            profile.args = fields.args;
        }
        if !fields.env.is_empty() {
            profile.env = fields.env;
        }
        if !fields.secrets.is_empty() {
            profile.secrets.clear();
            for pair in fields.secrets {
                let (name, reference) = pair.split_once('=').ok_or_else(|| {
                    Error::Message(format!("secret {pair:?} must be NAME=REFERENCE"))
                })?;
                profile.secrets.insert(name.into(), reference.into());
            }
        }
        if fields.default_harness.is_some() {
            profile.default_harness = fields.default_harness;
        }
        if fields.timeout_ms.is_some() {
            profile.timeout_ms = fields.timeout_ms;
        }
        if fields.memory_limit_bytes.is_some()
            || fields.cpu_limit_seconds.is_some()
            || fields.process_limit.is_some()
        {
            let limits = profile.limits.get_or_insert_with(Default::default);
            limits.memory_bytes = fields.memory_limit_bytes.or(limits.memory_bytes);
            limits.cpu_seconds = fields.cpu_limit_seconds.or(limits.cpu_seconds);
            limits.processes = fields.process_limit.or(limits.processes);
        }
        if fields.max_output_bytes.is_some() {
            profile.max_output_bytes = fields.max_output_bytes;
        }
        if !fields.projects.is_empty() {
            profile.projects = fields.projects;
        }
        Ok(())
    };
    let set_enabled = |id: &str, enabled: bool| -> Result<Value> {
        let mut profile = existing(id)?;
        profile.enabled = enabled;
        providers::put_provider(&paths, None, id, profile)?;
        Ok(json!({"id":id,"enabled":enabled}))
    };
    match command {
        ProviderCommand::List => Ok(providers::list_providers(&config)),
        ProviderCommand::Show { id } => providers::show_provider(&config, &id),
        ProviderCommand::Test { id } => providers::test_provider(&config, &id),
        ProviderCommand::Add { id, fields, scope } => {
            if config.providers.contains_key(&id) {
                return Err(Error::Message(format!(
                    "provider {id} already exists; use provider edit"
                )));
            }
            let kind = fields
                .kind
                .clone()
                .ok_or_else(|| Error::Message("provider add requires --kind".into()))?;
            let mut profile = ProviderProfile {
                name: None,
                kind: if kind == "stdio-agent" {
                    ProviderKind::StdioAgent
                } else {
                    ProviderKind::LocalProcess
                },
                enabled: true,
                executable: None,
                args: vec![],
                env: vec![],
                secrets: Default::default(),
                default_harness: None,
                timeout_ms: None,
                max_output_bytes: None,
                projects: vec![],
                limits: None,
            };
            apply(&mut profile, fields)?;
            providers::put_provider(&paths, Some(scope.parse()?), &id, profile)
        }
        ProviderCommand::Edit { id, fields } => {
            let mut profile = existing(&id)?;
            apply(&mut profile, fields)?;
            providers::put_provider(&paths, None, &id, profile)
        }
        ProviderCommand::Enable { id } => set_enabled(&id, true),
        ProviderCommand::Disable { id } => set_enabled(&id, false),
        ProviderCommand::Remove { id, .. } => {
            let scope = paths.provider_scope(&id)?;
            paths.remove_provider(scope, &id)?;
            Ok(json!({"removed":id,"scope":scope.to_string()}))
        }
    }
}

thread_local! {
    /// Daemon mode keeps one open Project, and so one OpenAEVC runtime, per root (PLAN §11.1),
    /// letting queries proceed while a long execution runs. Embedded mode opens per request.
    static PROJECTS: std::cell::RefCell<Option<std::collections::HashMap<PathBuf, std::rc::Rc<Project>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Called once by the daemon on its request thread.
pub fn enable_project_cache() {
    PROJECTS.with(|cache| *cache.borrow_mut() = Some(std::collections::HashMap::new()));
}

/// Commands open as writers (migration, checkpoint); queries as readers (§46.4). A cached
/// Project was opened by whichever came first; a reader-opened one is current (it refused to
/// open otherwise), so commands may share it.
fn open_project(root: &Path, writer: bool) -> Result<std::rc::Rc<Project>> {
    crate::journal::fault("daemon.open_project");
    let open = |root: &Path| {
        if writer {
            Project::open(root)
        } else {
            Project::open_reader(root)
        }
    };
    PROJECTS.with(|cell| {
        let mut cache = cell.borrow_mut();
        let Some(map) = cache.as_mut() else {
            return Ok(std::rc::Rc::new(open(root)?));
        };
        if let Some(project) = map.get(root) {
            if root.join(".calve/project.toml").is_file() {
                return Ok(project.clone());
            }
            map.remove(root);
        }
        let project = std::rc::Rc::new(open(root)?);
        map.insert(root.to_path_buf(), project.clone());
        Ok(project)
    })
}

/// Releases the cached runtime so an exclusive operation can open the data root.
/// Closes the cached runtime unless a request still uses it; false if one does, because evicting
/// it then would leave the store locked and every later request unable to open the Project.
fn release_project(root: &Path) -> bool {
    PROJECTS.with(|cell| {
        let mut cache = cell.borrow_mut();
        let Some(map) = cache.as_mut() else {
            return true;
        };
        if map
            .get(root)
            .is_some_and(|p| std::rc::Rc::strong_count(p) > 1)
        {
            return false;
        }
        map.remove(root);
        true
    })
}

/// The daemon's periodic maintenance: OpenAEVC expires leases on a tick or a command, so without
/// this a daemon restarted under a dead run would keep reporting it RUNNING.
pub fn tick_projects() {
    PROJECTS.with(|cell| {
        for project in cell.borrow().iter().flat_map(|map| map.values()) {
            project.tick();
        }
    });
}

pub fn evict_project(root: &Path) {
    PROJECTS.with(|cell| {
        if let Some(map) = cell.borrow_mut().as_mut() {
            map.remove(root);
        }
    });
}

/// The single-writer lock (§40.1, §40.3). Liveness is the OS lock itself (released when the
/// owner exits or crashes); the owner record `{pid, nonce, session, host, started}` names who
/// holds it, and its nonce distinguishes a reused PID from the original owner.
pub(crate) fn project_writer(root: &Path) -> Result<std::fs::File> {
    use std::io::{Read as _, Seek as _, Write as _};
    let lock = root.join(".calve/writer.lock");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock)?;
    if let Err(error) = file.try_lock() {
        return Err(match error {
            std::fs::TryLockError::WouldBlock => {
                let mut owner = String::new();
                let _ = file.read_to_string(&mut owner);
                let owner: Value = serde_json::from_str(&owner).unwrap_or(Value::Null);
                crate::detailed(
                    "PROJECT_LOCKED",
                    format!(
                        "{} is being changed by pid {} (session {}, since {}); retry when it finishes",
                        root.display(),
                        owner["pid"],
                        owner["session"].as_str().unwrap_or("?"),
                        owner["started"].as_str().unwrap_or("?")
                    ),
                    json!({"owner": owner, "lock": lock}),
                )
            }
            std::fs::TryLockError::Error(error) => Error::Io(error),
        });
    }
    let owner = json!({"pid": std::process::id(), "nonce": uuid::Uuid::now_v7(),
        "session": session_id(), "host": hostname(), "started": crate::now()?});
    file.set_len(0)?;
    file.rewind()?;
    file.write_all(owner.to_string().as_bytes())?;
    Ok(file)
}

/// This process's session id (one per process).
fn session_id() -> &'static str {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| format!("ses_{}", uuid::Uuid::now_v7()))
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_owned()))
        .unwrap_or_default()
}

/// The writer lock's state for `recover inspect`: held (live owner) or free (last owner, if a
/// previous holder crashed or exited), without taking or modifying it.
pub(crate) fn writer_lock_state(root: &Path) -> Value {
    let lock = root.join(".calve/writer.lock");
    let Ok(file) = OpenOptions::new().read(true).open(&lock) else {
        return json!({"state": "absent"});
    };
    let owner: Value = std::fs::read_to_string(&lock)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    match file.try_lock_shared() {
        Ok(()) => {
            let _ = file.unlock();
            json!({"state": "free", "last_owner": owner})
        }
        Err(_) => json!({"state": "held", "owner": owner}),
    }
}

/// Executes one typed request. The envelope always returns a correlated response, including
/// validation and protocol failures, so it can be carried over a local IPC connection unchanged.
/// `pack.seal`-style name of an action, derived from its serialized shape.
pub fn action_name(action: &Action) -> String {
    let mut parts = Vec::new();
    let mut value = serde_json::to_value(action).unwrap_or(Value::Null);
    loop {
        match value {
            Value::String(name) => {
                parts.push(name.to_lowercase());
                break;
            }
            Value::Object(map) if !map.is_empty() => {
                let (key, inner) = map.into_iter().next().expect("non-empty");
                if key != "command" && key != "view" && key != "options" && key != "filter" {
                    parts.push(key.to_lowercase());
                }
                value = match inner {
                    Value::Object(fields) => fields
                        .get("command")
                        .or_else(|| fields.get("view"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    other => other,
                };
            }
            _ => break,
        }
    }
    parts.join(".")
}

pub async fn execute(request: Request) -> Response {
    let started = std::time::Instant::now();
    let name = action_name(&request.action);
    let project = request.scope.project.clone();
    let response = execute_inner(request).await;
    let (outcome, code) = match &response.outcome {
        Outcome::Ok { .. } => ("ok", None),
        Outcome::Error { error } => ("error", Some(error.code.clone())),
    };
    crate::observe::record(
        "request",
        json!({"request_id":response.request_id,"correlation_id":response.correlation_id,
            "action":name,"project":project,"duration_ms":started.elapsed().as_millis() as u64,
            "outcome":outcome,"code":code}),
    );
    response
}

async fn execute_inner(request: Request) -> Response {
    let request_id = request.request_id;
    let correlation_id = request.correlation_id;
    let outcome = if request.api_version != API_VERSION {
        Outcome::Error {
            error: Fault {
                code: "UNSUPPORTED_API_VERSION".into(),
                message: format!(
                    "API version {} is unsupported; expected {API_VERSION}",
                    request.api_version
                ),
                retryable: false,
                detail: None,
            },
        }
    } else if request.payload_version != PAYLOAD_VERSION {
        Outcome::Error {
            error: Fault {
                code: "UNSUPPORTED_PAYLOAD_VERSION".into(),
                message: format!(
                    "payload version {} is unsupported; expected {PAYLOAD_VERSION}",
                    request.payload_version
                ),
                retryable: false,
                detail: None,
            },
        }
    } else if request.operation_kind != request.action.kind() {
        Outcome::Error {
            error: Fault {
                code: "INVALID_OPERATION_KIND".into(),
                message: "operation kind does not match action".into(),
                retryable: false,
                detail: None,
            },
        }
    } else if let Some(consequence) = request.action.confirmation() {
        // Destructive commands need `--yes` (the CLI asks on a terminal and resends).
        Outcome::Error {
            error: Fault {
                code: "CONFIRMATION_REQUIRED".into(),
                message: format!("{consequence} Confirm with --yes."),
                retryable: false,
                detail: None,
            },
        }
    } else {
        match REQUEST
            .scope(
                (
                    request_id,
                    correlation_id,
                    std::cell::Cell::new(0),
                    std::cell::RefCell::new(None),
                ),
                dispatch(request),
            )
            .await
        {
            Ok(value) => Outcome::Ok { value },
            Err(error) => Outcome::Error {
                error: fault(error),
            },
        }
    };
    Response {
        api_version: API_VERSION,
        request_id,
        correlation_id,
        outcome,
    }
}

async fn dispatch(request: Request) -> Result<Value> {
    let Request {
        actor: Actor::LocalUser,
        scope,
        action,
        ..
    } = request;
    if matches!(action, Action::Version) {
        return Ok(json!({
            "calve": env!("CARGO_PKG_VERSION"),
            "openaevc_crate_version": compatibility::OPENAEVC_CRATE_VERSION,
            "openaevc_tag": compatibility::OPENAEVC_TAG,
            "openaevc_revision": compatibility::OPENAEVC_REVISION,
            "protocol": openaevc::protocol::PROTOCOL_VERSION.to_string(),
            "api_version": API_VERSION,
        }));
    }
    if matches!(action, Action::Daemon { .. } | Action::Console) {
        return Err(Error::Message(
            "console and daemon lifecycle are frontend actions".into(),
        ));
    }
    let mut registry = Registry::open_default()?;
    let workspace = scope.workspace.as_deref();
    let action = match action {
        Action::Version => unreachable!(),
        Action::Init {
            path,
            name,
            no_register,
            nested,
        } => {
            let target = path.or(scope.project).unwrap_or(std::env::current_dir()?);
            if target.exists() {
                registry.assert_path_available(&std::fs::canonicalize(&target)?)?;
            }
            let project = Project::init_with(&target, name.as_deref(), nested).await?;
            if !no_register {
                registry.register_project(&project.info(), workspace)?;
            }
            return init_report(&project, !no_register);
        }
        Action::Workspace { command } => return workspace_command(&mut registry, command),
        Action::Inbox {
            command: InboxCommand::Summary,
        } => return inbox_summary(&registry),
        Action::Project {
            command: ProjectCommand::AuthorityExport { project, file, yes },
        } => {
            if !yes {
                return Err(crate::coded(
                    "CONFIRMATION_REQUIRED",
                    "the exported file can act as this Project; confirm with --yes",
                ));
            }
            let entry = registry.project(&project).ok().map(|e| e.path);
            let root = entry.unwrap_or_else(|| PathBuf::from(&project));
            return crate::authority::export(&Project::discover(&root)?, &file);
        }
        Action::Project {
            command: ProjectCommand::AuthorityImport { path, file },
        } => return crate::authority::import(&Project::discover(&path)?, &file),
        Action::Project {
            command: ProjectCommand::AdoptCopy { path, name },
        } => {
            let (project, mut summary) = crate::adopt::adopt_copy(&path, name.as_deref()).await?;
            summary["registration"] = json!(registry.register_project(&project.info(), workspace)?);
            return Ok(summary);
        }
        Action::Project { command } => return project_command(&mut registry, command, workspace),
        Action::Extension { command } if extension_is_global(&command, scope.project.is_some()) => {
            use crate::extensions;
            use calve_api::CatalogCommand;
            return match command {
                ExtensionCommand::List { .. } => extensions::list_installed(),
                ExtensionCommand::Catalog { command } => match command {
                    CatalogCommand::Add {
                        name,
                        url,
                        root,
                        root_digest,
                    } => extensions::catalog_add(&name, &url, &root, &root_digest),
                    CatalogCommand::List => extensions::catalog_list(),
                    CatalogCommand::Refresh { name } => {
                        extensions::catalog_refresh(name.as_deref())
                    }
                    CatalogCommand::Reset {
                        name,
                        root,
                        root_digest,
                        yes,
                        i_understand_rollback_risk,
                    } => {
                        if !(yes && i_understand_rollback_risk) {
                            return Err(crate::Error::Message(
                                "a catalog reset lowers rollback protection; confirm with --yes --i-understand-rollback-risk".into(),
                            ));
                        }
                        extensions::catalog_reset(&name, &root, &root_digest)
                    }
                    CatalogCommand::Remove { name, .. } => extensions::catalog_remove(&name),
                },
                ExtensionCommand::Search { query } => extensions::search(query.as_deref()),
                ExtensionCommand::Install {
                    id,
                    version,
                    catalog,
                    acknowledge_native,
                } => extensions::install_package(
                    &id,
                    version.as_deref(),
                    catalog.as_deref(),
                    acknowledge_native,
                ),
                ExtensionCommand::SwitchPublisher {
                    id,
                    catalog,
                    yes,
                    acknowledge_native,
                } => {
                    if !yes {
                        return Err(crate::Error::Message(format!(
                            "switching the publisher of {id} trusts a different catalog for it; confirm with --yes"
                        )));
                    }
                    extensions::switch_publisher(&id, &catalog, acknowledge_native)
                }
                ExtensionCommand::Uninstall { id, version, .. } => {
                    extensions::uninstall(&id, version.as_deref())
                }
                _ => unreachable!(),
            };
        }
        Action::Provider { command } => {
            return provider_command(
                &registry,
                command,
                scope.project,
                workspace,
                scope.config_file,
            );
        }
        Action::Harness { command } => {
            let paths = context_config(&registry, scope.project, workspace, scope.config_file)?;
            let config = paths.load()?;
            return match command {
                HarnessCommand::List => Ok(crate::providers::list_harnesses(&config)),
                HarnessCommand::Show { id } => crate::providers::show_harness(&config, &id),
                HarnessCommand::Test { id } => crate::providers::test_harness(&config, &id),
            };
        }
        Action::Config { command } => {
            return config_command(
                &registry,
                command,
                scope.project,
                workspace,
                scope.config_file,
            );
        }
        action => action,
    };
    let path = resolve_project_path(&registry, scope.project, workspace)?;
    let root = match (Project::discover(&path), &action) {
        (Ok(root), _) => root,
        // An interrupted adoption can leave no `.calve`; recovery still needs to reach it.
        (Err(_), Action::Recover { .. }) if path.is_dir() => std::fs::canonicalize(&path)?,
        (Err(error), _) => return Err(error),
    };
    if mutates_project(&action)
        && !matches!(action, Action::Recover { .. })
        && root.join(".calve/project.toml").is_file()
    {
        crate::authority::ensure_instance(&root)?;
    }
    let _writer = if takes_writer_lock(&action) && root.join(".calve").is_dir() {
        Some(project_writer_wait(&root, std::time::Duration::from_secs(5)).await?)
    } else {
        None
    };
    if let Action::Recover { command } = &action {
        return recover(&root, command).await;
    }
    // Store maintenance needs the runtime closed (one runtime per data root), and must not close
    // one a running request depends on.
    let store_free = match action {
        Action::Maintenance {
            command:
                MaintenanceCommand::VerifyStore
                | MaintenanceCommand::Gc { .. }
                | MaintenanceCommand::Check,
        } => release_project(&root),
        _ => true,
    };
    let busy = || {
        crate::Error::Busy(format!(
            "{} is in use by a running request, and this needs the OpenAEVC store alone; retry when it ends",
            root.display()
        ))
    };
    let store_report = match &action {
        Action::Maintenance {
            command: MaintenanceCommand::VerifyStore,
        } => {
            if !store_free {
                return Err(busy());
            }
            return crate::ops::verify_store(&root);
        }
        Action::Maintenance {
            command:
                MaintenanceCommand::Gc {
                    dry_run,
                    grace_secs,
                    conflicts,
                    older_than_secs,
                    ..
                },
        } => {
            let o = crate::gc::Options {
                grace: std::time::Duration::from_secs(*grace_secs),
                conflicts: conflicts.then(|| std::time::Duration::from_secs(*older_than_secs)),
            };
            if *dry_run {
                return crate::gc::dry_run(&root, &o);
            }
            if !store_free {
                return Err(busy());
            }
            return crate::gc::collect(&root, &o, &|| {
                crate::ops::collect_protocol_garbage(&root, o.grace)
            });
        }
        Action::Maintenance {
            command: MaintenanceCommand::Check,
        } => Some(if store_free {
            crate::ops::verify_store(&root)?
        } else {
            // The console's change feed holds the runtime almost constantly, so a check still
            // reports the rest. `ok` is false because the store was not verified.
            json!({"ok":false,"state":"in_use","problems":["the OpenAEVC store was not verified: a running request is using it"],
                "namespaces":0,"events":0,"objects":0})
        }),
        _ => None,
    };
    let project_handle = open_project(&root, takes_writer_lock(&action))?;
    // A request acting as a local identity gets its own session on the shared runtime.
    let acting = match scope.actor.as_deref() {
        Some(name) => Some(project_handle.acting_as(name)?),
        None => None,
    };
    let project: &Project = acting.as_ref().unwrap_or(&project_handle);
    set_actor(project.client.session().principal().to_string());
    let workspace_id = match workspace {
        Some(name) => registry.show(name)?.workspace.id,
        None => registry.selected()?.workspace.id,
    };
    let settings =
        ConfigPaths::for_context(&workspace_id, Some(&project.root), scope.config_file)?.load()?;
    if mutates_project(&action) {
        registry.ensure_project_path(&project.identity, &project.root)?;
        compatibility::query(&project.client).await?;
        if let Some((what, paths)) = tree_scope(&action) {
            project.refuse_if_claimed(what, &paths).await?;
        }
    }
    match action {
        Action::Version
        | Action::Init { .. }
        | Action::Workspace { .. }
        | Action::Project { .. }
        | Action::Config { .. }
        | Action::Provider { .. }
        | Action::Harness { .. } => unreachable!(),
        Action::Status => project.status(Some(&settings)).await,
        Action::Intent { command } => match command {
            IntentCommand::Create {
                title,
                description,
                tags,
                actors,
                graph_node,
            } => Ok(
                json!({"id":project.create_intent_with_references(&title,description.as_deref(),&tags,&actors,graph_node.as_deref()).await?}),
            ),
            IntentCommand::List { after, limit } => {
                Ok(json!(project.list_intents_page(after.as_deref(), limit)?))
            }
            IntentCommand::Show { id } => project.intent_with_packs(&id).await,
            IntentCommand::Edit {
                id,
                title,
                description,
                tags,
                clear_tags,
                actors,
                clear_actors,
                graph_node,
                clear_graph_node,
            } => {
                let tags = if clear_tags {
                    Some(Vec::new())
                } else if tags.is_empty() {
                    None
                } else {
                    Some(tags)
                };
                let actors = if clear_actors {
                    Some(Vec::new())
                } else if actors.is_empty() {
                    None
                } else {
                    Some(actors)
                };
                let graph_node = if clear_graph_node {
                    Some(None)
                } else {
                    graph_node.as_deref().map(Some)
                };
                project
                    .update_intent_with_references(
                        &id,
                        title.as_deref(),
                        description.as_deref(),
                        tags.as_deref(),
                        actors.as_deref(),
                        graph_node,
                    )
                    .await?;
                project.intent_with_packs(&id).await
            }
            IntentCommand::Close { id, cancelled } => {
                project.set_intent_state(&id, if cancelled { "CANCELLED" } else { "COMPLETED" })?;
                project.intent_with_packs(&id).await
            }
            IntentCommand::Reopen { id } => {
                project.set_intent_state(&id, "OPEN")?;
                project.intent_with_packs(&id).await
            }
            IntentCommand::LinkPack { intent, pack } => {
                let generation = project.pack(&pack).await?.generation;
                project.set_pack_intent(&pack, generation, &intent).await?;
                Ok(json!(project.pack(&pack).await?))
            }
            IntentCommand::UnlinkPack { intent, pack } => {
                let generation = project.pack(&pack).await?.generation;
                project
                    .unlink_pack_intent(&pack, generation, &intent)
                    .await?;
                Ok(json!(project.pack(&pack).await?))
            }
        },
        Action::Task { command } => match command {
            TaskCommand::Create {
                intent,
                title,
                description,
                priority,
                assignee,
            } => Ok(
                json!({"id":project.create_task_with_metadata(&intent,&title,description.as_deref(),&priority,assignee.as_deref())?}),
            ),
            TaskCommand::List => Ok(json!(project.tasks_with_protocol().await?)),
            TaskCommand::Show { id } => project.task_with_protocol(&id).await,
            TaskCommand::Update {
                id,
                title,
                description,
                priority,
                assignee,
            } => {
                project.update_task(
                    &id,
                    title.as_deref(),
                    description.as_deref(),
                    priority.as_deref(),
                    assignee.as_deref(),
                )?;
                Ok(json!({"updated":id}))
            }
            TaskCommand::Complete { id } => {
                project.complete_task(&id)?;
                Ok(json!({"completed":id}))
            }
            TaskCommand::Start { id } => {
                project.start_task(&id)?;
                project.task_with_protocol(&id).await
            }
            TaskCommand::Block { id, reason } => {
                project.block_task(&id, &reason)?;
                project.task_with_protocol(&id).await
            }
            TaskCommand::Unblock { id } => {
                project.unblock_task(&id)?;
                project.task_with_protocol(&id).await
            }
            TaskCommand::Reopen { id } => {
                project.reopen_task(&id)?;
                project.task_with_protocol(&id).await
            }
            TaskCommand::LinkPack { id, pack } => {
                project.link_task_pack(&id, &pack).await?;
                project.task_with_protocol(&id).await
            }
            TaskCommand::LinkExecution { id, execution } => {
                project.link_task_execution(&id, &execution).await?;
                project.task_with_protocol(&id).await
            }
            TaskCommand::LinkWorkUnit { id, work_unit } => {
                project.link_task_work_unit(&id, &work_unit).await?;
                project.task_with_protocol(&id).await
            }
            TaskCommand::Assign { id, assignee } => {
                project.update_task(&id, None, None, None, Some(&assignee))?;
                project.task_with_protocol(&id).await
            }
            TaskCommand::Depend { id, on } => {
                project.add_task_dependency(&id, &on)?;
                Ok(json!({"task_id":id,"depends_on":on}))
            }
            TaskCommand::Undepend { id, on } => {
                project.remove_task_dependency(&id, &on)?;
                Ok(json!({"task_id":id,"removed_dependency":on}))
            }
        },
        Action::Inbox { command } => match command {
            InboxCommand::List { all } => Ok(json!(project.inbox(all).await?)),
            InboxCommand::Summary => unreachable!("handled before a Project opens"),
            InboxCommand::Show { source_key } => project.inbox_item(&source_key).await,
            InboxCommand::Unack { source_keys } => {
                for key in &source_keys {
                    project.unacknowledge_inbox_item(key).await?;
                }
                Ok(json!({"unacknowledged":source_keys}))
            }
            InboxCommand::ClearResolved { .. } => project.clear_resolved_inbox().await,
            InboxCommand::Read { source_key } => {
                project.update_inbox_item(&source_key, "read", None).await?;
                Ok(json!({"read":source_key}))
            }
            InboxCommand::Acknowledge { source_keys } => {
                for key in &source_keys {
                    project.update_inbox_item(key, "acknowledge", None).await?;
                }
                Ok(json!({"acknowledged":source_keys}))
            }
            InboxCommand::Snooze { source_key, until } => {
                project
                    .update_inbox_item(&source_key, "snooze", Some(until))
                    .await?;
                Ok(json!({"snoozed":source_key,"until":until}))
            }
            InboxCommand::Unsnooze { source_key } => {
                project
                    .update_inbox_item(&source_key, "unsnooze", None)
                    .await?;
                Ok(json!({"unsnoozed":source_key}))
            }
        },
        Action::Pack { command } => match command {
            PackCommand::Create {
                title,
                intent,
                require_snapshot_verification,
                require_review,
                require_checks,
                forbid_self_review,
            } => {
                let id = project
                    .create_pack_with_policies(
                        &title,
                        intent.as_deref(),
                        require_snapshot_verification,
                        require_review,
                        &require_checks,
                    )
                    .await?;
                if forbid_self_review {
                    project.forbid_self_review(&id.to_string())?;
                }
                Ok(json!({"id":id,"generation":1}))
            }
            PackCommand::List { after, limit } => Ok(json!(
                project.list_packs_page(after.as_deref(), limit).await?
            )),
            PackCommand::Show { id } => Ok(serde_json::to_value(project.pack(&id).await?)?),
            PackCommand::SetIntent {
                id,
                intent,
                generation,
            } => project.set_pack_intent(&id, generation, &intent).await,
            PackCommand::Edit { id, title } => project.edit_pack_title(&id, &title).await,
            PackCommand::CaptureTree {
                id,
                directory,
                generation,
                preview,
                accept_deletions,
            } => {
                project
                    .capture_tree(&id, generation, &directory, preview, accept_deletions)
                    .await
            }
            PackCommand::Lifecycle(command) => lifecycle(project, &settings, command).await,
            PackCommand::Qualify { id, generation } => project.qualify(&id, generation).await,
            PackCommand::Reopen { id, generation } => project.reopen(&id, generation).await,
            PackCommand::Quarantine { id, reason } => project.quarantine_pack(&id, &reason).await,
            PackCommand::Release { id } => project.release_quarantine(&id).await,
            PackCommand::Abandon { id, generation, .. } => {
                project.abandon_pack(&id, generation).await
            }
        },
        Action::Revision { command } => match command {
            RevisionCommand::Create {
                title,
                of,
                relation,
                intent,
                require_review,
            } => {
                let targets = of
                    .iter()
                    .map(|text| {
                        text.parse::<Digest>().map_err(|_| {
                            Error::Message(format!("invalid promoted-pack digest {text}"))
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let relation = match relation.as_str() {
                    "amends" => RevisionRelation::Amends,
                    "supersedes" => RevisionRelation::Supersedes,
                    "reverts" => RevisionRelation::Reverts,
                    _ => return Err(Error::Message("invalid revision relation".into())),
                };
                let id = project
                    .create_revision_pack_with_requirements(
                        &title,
                        intent.as_deref(),
                        relation,
                        targets,
                        require_review,
                    )
                    .await?;
                Ok(json!({"id":id,"generation":1}))
            }
            RevisionCommand::List => Ok(json!(project.list_revisions().await?)),
            RevisionCommand::Show { id } => Ok(serde_json::to_value(project.revision(&id).await?)?),
            RevisionCommand::Lifecycle(command) => {
                let id = match &command {
                    LifecycleCommand::Capture { id, .. }
                    | LifecycleCommand::Diff { id, .. }
                    | LifecycleCommand::Verify { id, .. }
                    | LifecycleCommand::Evaluate { id, .. }
                    | LifecycleCommand::Seal { id, .. }
                    | LifecycleCommand::Check { id, .. }
                    | LifecycleCommand::Review { id }
                    | LifecycleCommand::Approve { id, .. }
                    | LifecycleCommand::Reject { id, .. }
                    | LifecycleCommand::Promote { id, .. } => id,
                };
                project.revision(id).await?;
                lifecycle(project, &settings, command).await
            }
        },
        Action::Capture { command } => match command {
            CaptureCommand::List => Ok(json!(crate::capture::list(&project.root)?)),
            CaptureCommand::Resume { session } => project.resume_capture(&session).await,
            CaptureCommand::Rollback { session, mode, .. } => {
                project.rollback_capture(&session, &mode).await
            }
        },
        Action::Materialize { command } => match command {
            MaterializeCommand::List => Ok(json!(project.list_materializations()?)),
            MaterializeCommand::Resume { op } => Ok(json!(project.materialize_resume(&op).await?)),
            MaterializeCommand::Resolve { op, keep } => {
                Ok(json!(project.materialize_resolve(&op, &keep).await?))
            }
            MaterializeCommand::Rollback { op, yes } => {
                Ok(json!(project.materialize_rollback(&op, yes).await?))
            }
        },
        Action::Supersede { command } => match command {
            SupersedeCommand::Start { pack, keep, .. } => {
                project.supersede_pack(&pack, keep, None).await
            }
            SupersedeCommand::List => Ok(json!(crate::supersede::list(&project.root)?)),
            SupersedeCommand::Resume { saga } => project.resume_supersede(&saga).await,
        },
        Action::Evidence { command } => match command {
            EvidenceCommand::Add {
                pack,
                generation,
                kind,
                file,
                media_type,
            } => {
                let path = if file.is_absolute() {
                    file
                } else {
                    project.root.join(file)
                };
                let path = std::fs::canonicalize(path)?;
                if path.starts_with(project.root.join(".calve")) {
                    return Err(Error::Message(
                        "project internal state cannot be evidence input".into(),
                    ));
                }
                if std::fs::metadata(&path)?.len() > 1024 * 1024 {
                    return Err(Error::Message("evidence payload exceeds 1 MiB".into()));
                }
                let digest = project
                    .register_evidence(&pack, generation, &kind, &media_type, std::fs::read(path)?)
                    .await?;
                Ok(json!({"digest":digest}))
            }
            EvidenceCommand::Show { digest } => project.evidence(digest).await,
            EvidenceCommand::List {
                pack,
                after,
                limit,
                current,
            } => project.list_evidence(&pack, after, limit, current).await,
        },
        Action::Receipt { command } => match command {
            ReceiptCommand::List { after, limit } => project.list_receipts(after, limit).await,
            ReceiptCommand::Show { digest } => project.receipt(digest).await,
            ReceiptCommand::Verify { digest } => project.verify_receipt(digest).await,
        },
        Action::Execution { command } => match command {
            ExecutionCommand::List { pack, state } => {
                let state = state.as_deref().map(|name| match name {
                    "pending" => openaevc::protocol::ExecutionState::Pending,
                    "admitted" => openaevc::protocol::ExecutionState::Admitted,
                    "starting" => openaevc::protocol::ExecutionState::Starting,
                    "running" => openaevc::protocol::ExecutionState::Running,
                    "succeeded" => openaevc::protocol::ExecutionState::Succeeded,
                    "failed" => openaevc::protocol::ExecutionState::Failed,
                    "cancelled" => openaevc::protocol::ExecutionState::Cancelled,
                    "lost" => openaevc::protocol::ExecutionState::Lost,
                    _ => unreachable!("clap validated execution state"),
                });
                project.list_executions(pack.as_deref(), state).await
            }
            ExecutionCommand::Show { id } => project.execution(&id).await,
            ExecutionCommand::Wait { id, timeout_ms } => {
                project.wait_execution(&id, timeout_ms).await
            }
            ExecutionCommand::Cancel { id, reason } => {
                project.cancel_execution(&id, reason.as_deref()).await
            }
            ExecutionCommand::Logs { id, after } => project.execution_logs(&id, after).await,
            ExecutionCommand::Retry { id } => project.retry_execution(&settings, &id).await,
            ExecutionCommand::Start {
                pack,
                harness,
                generation,
                task,
            } => {
                project
                    .start_harness_execution(
                        &settings,
                        &pack,
                        generation,
                        &harness,
                        task.as_deref(),
                        None,
                    )
                    .await
            }
        },
        Action::Extension { command } => match command {
            ExtensionCommand::List { .. } => project.list_extensions().await,
            ExtensionCommand::Catalog { .. }
            | ExtensionCommand::Search { .. }
            | ExtensionCommand::Install { .. }
            | ExtensionCommand::SwitchPublisher { .. }
            | ExtensionCommand::Uninstall { .. } => unreachable!("handled without a Project"),
            ExtensionCommand::Info { id } => project.extension_info(&id).await,
            ExtensionCommand::Disable { id } => project.disable_extension(&id).await,
            ExtensionCommand::Permissions { id } => project.extension_permissions(&id).await,
            ExtensionCommand::Health => project.extension_health().await,
            ExtensionCommand::Grant { id, capabilities } => {
                project.grant_extension(&id, &capabilities).await
            }
            ExtensionCommand::Revoke { id, capabilities } => {
                project.revoke_extension(&id, &capabilities).await
            }
            ExtensionCommand::Update {
                id,
                grants,
                acknowledge_native,
            } => {
                project
                    .update_extension(&id, &grants, acknowledge_native)
                    .await
            }
            ExtensionCommand::Enable {
                id,
                grants,
                acknowledge_native,
            } => {
                project
                    .enable_extension(&id, &grants, acknowledge_native)
                    .await
            }
        },
        Action::Resource { command } => match command {
            ResourceCommand::List { domain } if domain == "general" => {
                Ok(json!(project.general_resources().await?))
            }
            ResourceCommand::List { .. } => project.list_resources().await,
            ResourceCommand::Show { target } => {
                // `kind:name` is a declared resource (':' never appears in a file locator).
                if target.contains(':') {
                    project.general_resource(&target).await
                } else {
                    project.show_resource(Path::new(&target)).await
                }
            }
            ResourceCommand::Materialize {
                path,
                pack,
                discard,
                apply,
                allow_unsafe_fs,
            } => {
                project
                    .materialize_resource(&pack, &path, discard, apply, allow_unsafe_fs)
                    .await
            }
            ResourceCommand::Set {
                pack,
                generation,
                sets,
                removes,
            } => {
                let sets = sets
                    .iter()
                    .map(|item| {
                        let (reference, value) = item.split_once('=').ok_or_else(|| {
                            Error::Message(format!("{item:?} must be kind:name=JSON"))
                        })?;
                        Ok((reference.to_owned(), serde_json::from_str(value)?))
                    })
                    .collect::<Result<Vec<_>>>()?;
                project
                    .edit_general(&pack, generation, &sets, &removes)
                    .await
            }
            ResourceCommand::Diff { pack, path } => project.diff_resource(&pack, &path).await,
            ResourceCommand::Scan => project.scan_resources().await,
            ResourceCommand::History { path } => project.resource_history(&path).await,
        },
        Action::Ignore { command } => match command {
            IgnoreCommand::List => project.list_ignore().await,
            IgnoreCommand::Add { pattern } => project.add_ignore(&pattern).await,
            IgnoreCommand::Remove { pattern } => project.remove_ignore(&pattern).await,
            IgnoreCommand::Check { path } => project.check_ignore(&path).await,
        },
        Action::Review { command } => match command {
            ReviewCommand::Approve {
                pack,
                generation,
                reason,
            } => Ok(json!({"id":project.review(&pack,generation,"APPROVE",&reason).await?})),
            ReviewCommand::Reject {
                pack,
                generation,
                reason,
            } => Ok(json!({"id":project.review(&pack,generation,"REJECT",&reason).await?})),
            ReviewCommand::Comment {
                pack,
                generation,
                reason,
            } => Ok(json!({"id":project.review(&pack,generation,"COMMENT",&reason).await?})),
            ReviewCommand::List { pack } => {
                project.refresh_pack_index().await?;
                Ok(json!(project.reviews(&pack).await?))
            }
        },
        Action::Baseline { command } => match command {
            BaselineCommand::Create {
                label,
                members,
                edges,
            } => {
                let digests = parse_digests(&members)?;
                let edges = parse_edges(&edges)?;
                let (id, digest) = project
                    .create_baseline_with(&label, digests, edges, None)
                    .await?;
                Ok(json!({"id":id,"digest":digest}))
            }
            BaselineCommand::Derive {
                base,
                label,
                add,
                remove,
                replace,
                edges,
            } => {
                let (base_digest, base) = project.baseline_object(&base).await?;
                let (members, edges) = project
                    .derived_composition(
                        &base,
                        &parse_digests(&add)?,
                        &parse_digests(&remove)?,
                        &parse_digests(&replace)?,
                        &parse_edges(&edges)?,
                    )
                    .await?;
                let (id, digest) = project
                    .create_baseline_with(&label, members.clone(), edges, Some(base_digest))
                    .await?;
                Ok(json!({"id":id,"digest":digest,"derived_from":base_digest,"members":members}))
            }
            BaselineCommand::List => Ok(json!(project.list_baselines().await?)),
            BaselineCommand::Show { id } => project.baseline(&id).await,
            BaselineCommand::Validate { id } => project.validate_baseline(&id).await,
            BaselineCommand::Compare { left, right } => {
                project.compare_baselines(&left, &right).await
            }
            BaselineCommand::Graph { id } => project.baseline_graph(&id).await,
            BaselineCommand::Alias { command } => match command {
                BaselineAliasCommand::List => Ok(json!(project.list_baseline_aliases()?)),
                BaselineAliasCommand::Set { alias, baseline } => Ok(
                    json!({"alias":alias,"baseline_id":project.set_baseline_alias(&alias,&baseline).await?}),
                ),
                BaselineAliasCommand::Remove { alias } => {
                    project.remove_baseline_alias(&alias)?;
                    Ok(json!({"removed":alias}))
                }
            },
            BaselineCommand::Materialize {
                id,
                discard,
                apply,
                activate,
                allow_unsafe_fs,
            } => {
                project
                    .materialize_baseline(&id, &discard, apply, activate, allow_unsafe_fs)
                    .await
            }
            BaselineCommand::Activate { id } => {
                Ok(json!({"active_baseline":project.activate_baseline(&id).await?}))
            }
        },
        Action::Activity { filter } => Ok(json!(
            project
                .activity_with_filter(settings.page_size, &filter)
                .await?
        )),
        Action::Authority { command } => match command {
            AuthorityCommand::Principals => Ok(json!(project.authority_principals().await?)),
            AuthorityCommand::Grants => Ok(json!(project.authority_grants().await?)),
            AuthorityCommand::Show { id } => project.authority_show(&id).await,
            AuthorityCommand::Explain {
                action,
                principal,
                resource_kind,
                resource_locator,
                extension,
            } => {
                let resource = match (resource_kind, resource_locator, extension) {
                    (None, None, None) => None,
                    (Some(kind), Some(locator), Some(extension)) => Some(ResourceRef {
                        kind,
                        locator,
                        version: None,
                        extension,
                    }),
                    _ => {
                        return Err(Error::Message(
                            "resource explanation requires --resource-kind, --resource-locator, and --extension together".into(),
                        ));
                    }
                };
                project
                    .authority_explain(&action, principal.as_deref(), resource)
                    .await
            }
            AuthorityCommand::Grant { options } => project.authority_grant(&options).await,
            AuthorityCommand::Revoke { grant, reason, .. } => {
                project.authority_revoke(&grant, reason.as_deref()).await
            }
            AuthorityCommand::IdentityAdd {
                name,
                actions,
                days,
            } => project.add_identity(&name, &actions, days).await,
            AuthorityCommand::Identities => project.list_identities(),
            AuthorityCommand::IdentityRemove { name, .. } => project.remove_identity(&name).await,
        },
        Action::Doctor { bundle, yes } => {
            let namespace = project
                .client
                .query(openaevc::protocol::Query::GetNamespace {})
                .await?;
            let compatibility = compatibility::query(&project.client).await?;
            let product_db = project.check_product_db()?;
            let extensions = project.extension_health().await?;
            let recovery = crate::ops::recovery_plan(&project.root)?;
            let registration = registry.ensure_project_path(&project.identity, &project.root);
            let containment = crate::supervise::probe_containment();
            let mut findings = Vec::new();
            if containment["landlock"] == "none" || containment["namespace"] == false {
                findings.push(json!({"code":"WORKER_CONTAINMENT","message":format!(
                    "workers cannot be fully confined here: {containment}")}));
            }
            if product_db["ok"] != true {
                findings.push(json!({"code":"PRODUCT_DB","message":"product database integrity check failed",
                    "remedy":"calve maintenance check; restore .calve/product.sqlite3 from backup"}));
            }
            for item in extensions
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["healthy"] != true)
            {
                findings.push(json!({"code":"EXTENSION","message":format!("extension {} is unhealthy", item["id"]),
                    "remedy":format!("calve extension health; calve extension enable {}", item["id"].as_str().unwrap_or(""))}));
            }
            if !recovery.is_empty() {
                findings.push(json!({"code":"RECOVERY","message":format!("{} disposable leftover(s) found", recovery.len()),
                    "remedy":"calve recover plan"}));
            }
            if let Err(error) = &registration {
                findings.push(json!({"code":"REGISTRATION","message":error.to_string(),
                    "remedy":"calve project health <path>"}));
            }
            for warning in &settings.warnings {
                findings.push(
                    json!({"code":"CONFIG","message":warning,"remedy":"calve config validate"}),
                );
            }
            let metrics = crate::observe::metrics(project.root.to_str());
            let report = json!({"healthy":findings.is_empty(),"project_id":project.identity.project_id,
                "root":project.root,"namespace":namespace,"product_db":product_db,"containment":containment,
                "compatibility":compatibility,"extensions":extensions,"findings":findings,
                "metrics":metrics});
            match bundle {
                None => Ok(report),
                Some(target) => {
                    let config =
                        ConfigPaths::for_context(&workspace_id, Some(&project.root), None)?
                            .load()?;
                    crate::observe::bundle(
                        &target,
                        vec![
                            ("doctor", report),
                            (
                                "version",
                                json!({"calve":env!("CARGO_PKG_VERSION"),"openaevc_revision":compatibility::OPENAEVC_REVISION}),
                            ),
                            ("config", serde_json::to_value(&config)?),
                            ("status", project.status(Some(&config)).await?),
                            ("extensions-installed", crate::extensions::list_installed()?),
                            ("recovery", json!(crate::ops::recovery_plan(&project.root)?)),
                        ],
                        yes,
                    )
                }
            }
        }
        Action::Maintenance { command } => match command {
            MaintenanceCommand::Check => {
                project.maintenance_check(store_report.expect("store verified before open"))
            }
            MaintenanceCommand::Compact => project.compact_product_db(),
            MaintenanceCommand::RebuildProjections => project.rebuild_projections().await,
            MaintenanceCommand::VerifyStore | MaintenanceCommand::Gc { .. } => {
                unreachable!("store maintenance runs before the Project is opened")
            }
        },
        Action::Recover { .. } => unreachable!("recover runs before the Project is opened"),
        Action::View { view } => match view {
            ViewQuery::Overview => project.view_overview().await,
            ViewQuery::Packs {
                after,
                limit,
                state,
            } => {
                project
                    .view_packs(after.as_deref(), limit, state.as_deref())
                    .await
            }
            ViewQuery::Pack { id } => project.view_pack(&id).await,
            ViewQuery::PackDiff { id, path, context } => {
                project.view_pack_diff(&id, &path, context).await
            }
            ViewQuery::ChangeGraph { intent } => project.view_change_graph(intent.as_deref()).await,
            ViewQuery::Baseline { id } => project.view_baseline(&id).await,
            ViewQuery::Execution { id } => project.view_execution(&id).await,
            ViewQuery::Evidence { before, limit } => {
                project.view_evidence(before.as_deref(), limit).await
            }
            ViewQuery::Changes {
                protocol,
                product,
                wait_ms,
            } => project.view_changes(protocol, product, wait_ms).await,
        },
        Action::Console | Action::Daemon { .. } => Err(Error::Message(
            "console and daemon lifecycle are frontend actions".into(),
        )),
    }
}

async fn lifecycle(
    project: &Project,
    settings: &crate::config::EffectiveConfig,
    command: LifecycleCommand,
) -> Result<Value> {
    match command {
        LifecycleCommand::Check {
            id,
            generation,
            languages,
            only,
            approve_plan,
        } => {
            project
                .run_checks(settings, &id, generation, &languages, &only, &approve_plan)
                .await
        }
        LifecycleCommand::Capture {
            id,
            path,
            generation,
        } => project.capture_file(&id, generation, &path).await,
        LifecycleCommand::Diff { id, path: None } => project.diff_pack(&id).await,
        LifecycleCommand::Diff {
            id,
            path: Some(path),
        } => project.diff_resource(&id, &path).await,
        LifecycleCommand::Verify {
            id,
            generation,
            path,
            digest,
        } => {
            project
                .verify_snapshots(&id, generation, path.as_deref().zip(digest))
                .await
        }
        LifecycleCommand::Evaluate {
            id,
            generation,
            warn_after_bytes,
            warn_after_files,
        } => {
            project
                .evaluate_change_size(&id, generation, warn_after_bytes, warn_after_files)
                .await
        }
        LifecycleCommand::Seal {
            id,
            generation,
            preflight: true,
        } => project.seal_preflight(&id, generation).await,
        LifecycleCommand::Seal { id, generation, .. } => {
            Ok(json!({"candidate_digest":project.seal(&id,generation).await?}))
        }
        LifecycleCommand::Review { id } => {
            project.refresh_pack_index().await?;
            Ok(json!(project.reviews(&id).await?))
        }
        LifecycleCommand::Approve {
            id,
            generation,
            reason,
        } => Ok(json!({"id":project.review(&id,generation,"APPROVE",&reason).await?})),
        LifecycleCommand::Reject {
            id,
            generation,
            reason,
        } => Ok(json!({"id":project.review(&id,generation,"REJECT",&reason).await?})),
        LifecycleCommand::Promote {
            id,
            generation,
            preflight: true,
            ..
        } => project.promote_preflight(&id, generation).await,
        LifecycleCommand::Promote {
            id,
            generation,
            candidate,
            ..
        } => {
            let candidate = candidate
                .map(|c| parse_digests(&[c]))
                .transpose()?
                .map(|v| v[0]);
            project.promote_checked(&id, generation, candidate).await
        }
    }
}

/// What `init` found and what to do next. Extensions are recommended, never enabled or granted:
/// installed packages whose signed `detect.markers` appear at the root, plus a package that
/// declares a file domain when the Project has files.
fn init_report(project: &Project, registered: bool) -> Result<Value> {
    let root_names: Vec<String> = std::fs::read_dir(&project.root)?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n != ".calve")
        .collect();
    let mut recommended = Vec::new();
    for r in crate::catalog::install::installed(&crate::extensions::machine_paths()?)? {
        let Some(m) = &r.metadata else { continue };
        let detected = m.detect.markers.iter().any(|mk| root_names.contains(mk));
        let files = m.files.is_some() && !root_names.is_empty();
        if (detected || files || (root_names.is_empty() && !m.resources.is_empty()))
            && !recommended.contains(&r.id)
        {
            recommended.push(r.id.clone());
        }
    }
    let integrity = project.check_product_db()?;
    let mut next: Vec<String> = if recommended.is_empty() {
        vec![
            "calve extension catalog list".into(),
            "calve extension search".into(),
        ]
    } else {
        recommended
            .iter()
            .map(|id| format!("calve extension enable {id} --acknowledge-native"))
            .collect()
    };
    next.push("calve intent create \"<goal>\"".into());
    next.push("calve pack create \"<change>\"".into());
    Ok(
        json!({"project_id":project.identity.project_id,"namespace_id":project.identity.namespace_id,
        "root":project.root,"registered":registered,"integrity":integrity,
        "recommended_extensions":recommended,"next_actions":next}),
    )
}

/// Recovery must work when the Project cannot open: inspect and plan open nothing writable.
async fn recover(root: &Path, command: &RecoverCommand) -> Result<Value> {
    // Inspect reports a store in use, so a running request keeps its runtime; apply must not
    // change anything under one.
    if !release_project(root) && matches!(command, RecoverCommand::Apply { .. }) {
        return Err(crate::Error::Busy(format!(
            "{} is in use by a running request; retry recovery when it ends",
            root.display()
        )));
    }
    match command {
        RecoverCommand::Inspect => crate::recovery::inspect(root),
        RecoverCommand::Plan => Ok(
            json!({"root": root, "actions": crate::recovery::plan(root)?,
            "note": "recovery never edits OpenAEVC state; `--restore-backup` replaces only the product database, then reconciles it against OpenAEVC"}),
        ),
        RecoverCommand::Apply { yes: false, .. } => Err(crate::coded(
            "CONFIRMATION_REQUIRED",
            format!(
                "recover apply would perform {} action(s); rerun with --yes after reviewing `calve recover plan` (and `recover inspect` for backups)",
                crate::recovery::plan(root)?.len()
            ),
        )),
        RecoverCommand::Apply {
            yes: true,
            restore_backup: Some(file),
            ..
        } => crate::recovery::restore_and_reconcile(root, file).await,
        RecoverCommand::Apply {
            yes: true,
            rebuild_product: true,
            ..
        } => crate::recovery::rebuild_product(root).await,
        RecoverCommand::Apply { yes: true, .. } => crate::ops::recovery_apply(root),
    }
}
