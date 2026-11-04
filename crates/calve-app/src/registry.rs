//! Machine-local workspace and project organization. Protocol state stays in each Project.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;

use crate::{Error, Project, ProjectIdentity, Result};

const SCHEMA: &str = "
    CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
    INSERT INTO schema_migrations VALUES (1);
    CREATE TABLE workspaces (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        default_project_id TEXT
    );
    CREATE TABLE projects (
        project_id TEXT PRIMARY KEY,
        namespace_id TEXT NOT NULL,
        path TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        registered_at INTEGER NOT NULL
    );
    CREATE TABLE workspace_projects (
        workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
        position INTEGER NOT NULL,
        pinned INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (workspace_id, project_id)
    );
    CREATE TABLE registry_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE INDEX workspace_projects_order ON workspace_projects(workspace_id, position);
";

fn invalid(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system time before Unix epoch"))?
        .as_secs())
}

fn name_ok(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 100 && !name.chars().any(char::is_control)
}

/// The default registry location follows platform data-directory conventions.
/// Per-data-root runtime state (daemon socket and pid, spawn records): in the platform runtime
/// directory when there is one (`$XDG_RUNTIME_DIR/calve/<data root digest>/`, so each data root
/// has its own), otherwise the data directory itself. Contents do not outlive a reboot.
pub fn runtime_dir() -> Result<PathBuf> {
    let data = default_data_root()?;
    match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        Some(run) if cfg!(unix) && run.is_absolute() && run.is_dir() => {
            // Keyed by the (guarded) data root, so a test's runtime state never meets a real one.
            let key = crate::journal::sha256_hex(data.to_string_lossy().as_bytes());
            Ok(run.join("calve").join(&key[..16]))
        }
        _ => Ok(data),
    }
}

/// Debug builds under `cargo test`: `CALVE_TEST_GUARD` lists the roots tests may use, and the
/// temporary directory is always one. A real user's Calve state is outside them, so a test that
/// would reach it fails before anything is read or written. Release builds never check.
pub fn guard_test_root(path: PathBuf) -> Result<PathBuf> {
    if !cfg!(debug_assertions) {
        return Ok(path);
    }
    guard_with(
        path,
        std::env::var_os("CALVE_TEST_GUARD"),
        std::env::temp_dir(),
    )
}

fn guard_with(
    path: PathBuf,
    allowed: Option<std::ffi::OsString>,
    temp: PathBuf,
) -> Result<PathBuf> {
    let Some(allowed) = allowed else {
        return Ok(path);
    };
    let mut roots: Vec<PathBuf> = std::env::split_paths(&allowed).collect();
    roots.push(temp);
    // Compared after resolving symlinks, so a link inside a test root cannot lead out of it;
    // `..` is refused outright (it cannot be resolved below a missing directory).
    let inside = !path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
        && roots
            .iter()
            .filter(|r| !r.as_os_str().is_empty())
            .any(|r| resolved(&path).starts_with(resolved(r)));
    if inside {
        Ok(path)
    } else {
        Err(crate::coded(
            "INVALID_CONFIGURATION",
            format!(
                "test guard: {} is outside the test roots; a test must never touch a real user's Calve state",
                path.display()
            ),
        ))
    }
}

/// `path` with its deepest existing ancestor canonicalized (symlinks resolved).
fn resolved(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut at = path;
    loop {
        if let Ok(real) = at.canonicalize() {
            return rest.iter().rev().fold(real, |p, n| p.join(n));
        }
        match (at.parent(), at.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                at = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

pub fn default_data_root() -> Result<PathBuf> {
    guard_test_root(user_data_root()?)
}

fn user_data_root() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| invalid("HOME is not set"))?;
        return Ok(PathBuf::from(home).join("Library/Application Support/Calve"));
    }
    #[cfg(windows)]
    {
        let data = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .ok_or_else(|| invalid("LOCALAPPDATA or APPDATA is not set"))?;
        return Ok(PathBuf::from(data).join("Calve"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
            let path = PathBuf::from(data);
            if path.is_absolute() {
                return Ok(path.join("calve"));
            }
            return Err(invalid("XDG_DATA_HOME must be an absolute path"));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| invalid("HOME is not set"))?;
        Ok(PathBuf::from(home).join(".local/share/calve"))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub selected: bool,
    pub default_project_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectEntry {
    pub project_id: String,
    pub namespace_id: String,
    pub path: PathBuf,
    pub name: String,
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceView {
    #[serde(flatten)]
    pub workspace: Workspace,
    pub projects: Vec<ProjectEntry>,
}

pub struct Registry {
    db: Connection,
    pub root: PathBuf,
}

impl Registry {
    pub fn open_default() -> Result<Self> {
        Self::open_at(&default_data_root()?)
    }

    pub fn open_at(root: &Path) -> Result<Self> {
        crate::journal::private_dir(root)?;
        let root = fs::canonicalize(root)?;
        let mut db = Connection::open(root.join("workspace.sqlite3"))?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;")?;
        let version: u32 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        match version {
            0 => {
                let tx = db.transaction()?;
                tx.execute_batch(SCHEMA)?;
                tx.execute_batch("PRAGMA user_version=1")?;
                tx.commit()?;
                crate::observe::record(
                    "migration",
                    serde_json::json!({"database": "registry", "from": 0, "to": 1}),
                );
            }
            1 => {}
            _ => {
                return Err(crate::coded(
                    "MIGRATION_REQUIRED",
                    format!(
                        "registry schema version {version} is newer than this Calve supports (1); upgrade Calve"
                    ),
                ));
            }
        }
        let mut registry = Self { db, root };
        registry.ensure_default()?;
        Ok(registry)
    }

    fn ensure_default(&mut self) -> Result<()> {
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO workspaces(id,name,created_at) VALUES ('wsp_default','default',?1)",
            [now()?],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO registry_meta(key,value) VALUES ('selected_workspace','wsp_default')",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn selected_id(&self) -> Result<String> {
        Ok(self.db.query_row(
            "SELECT value FROM registry_meta WHERE key='selected_workspace'",
            [],
            |row| row.get(0),
        )?)
    }

    fn workspace_row(&self, identifier: &str) -> Result<(String, String, Option<String>)> {
        self.db
            .query_row(
                "SELECT id,name,default_project_id FROM workspaces WHERE id=?1 OR name=?1",
                [identifier],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| {
                crate::coded(
                    "WORKSPACE_NOT_FOUND",
                    format!("unknown workspace {identifier}"),
                )
            })
    }

    pub fn selected(&self) -> Result<WorkspaceView> {
        self.show(&self.selected_id()?)
    }

    pub fn list(&self) -> Result<Vec<Workspace>> {
        let selected = self.selected_id()?;
        let mut stmt = self
            .db
            .prepare("SELECT id,name,default_project_id FROM workspaces ORDER BY created_at,id")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .map(|(id, name, default_project_id)| Workspace {
                selected: id == selected,
                id,
                name,
                default_project_id,
            })
            .collect())
    }

    pub fn show(&self, identifier: &str) -> Result<WorkspaceView> {
        let (id, name, default_project_id) = self.workspace_row(identifier)?;
        let selected = id == self.selected_id()?;
        let mut stmt = self.db.prepare(
            "SELECT p.project_id,p.namespace_id,p.path,p.name,wp.pinned
             FROM workspace_projects wp JOIN projects p USING(project_id)
             WHERE wp.workspace_id=?1 ORDER BY wp.position,p.project_id",
        )?;
        let projects = stmt
            .query_map([&id], |row| {
                Ok(ProjectEntry {
                    project_id: row.get(0)?,
                    namespace_id: row.get(1)?,
                    path: PathBuf::from(row.get::<_, String>(2)?),
                    name: row.get(3)?,
                    pinned: row.get::<_, i64>(4)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(WorkspaceView {
            workspace: Workspace {
                id,
                name,
                selected,
                default_project_id,
            },
            projects,
        })
    }

    pub fn create(&mut self, name: &str) -> Result<Workspace> {
        if !name_ok(name) {
            return Err(invalid("workspace name must be 1–100 printable characters"));
        }
        if self.workspace_row(name).is_ok() {
            return Err(invalid(format!("workspace {name} already exists")));
        }
        let id = format!("wsp_{}", uuid::Uuid::now_v7());
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO workspaces(id,name,created_at) VALUES (?1,?2,?3)",
            params![id, name, now()?],
        )?;
        tx.commit()?;
        Ok(Workspace {
            id,
            name: name.to_owned(),
            selected: false,
            default_project_id: None,
        })
    }

    pub fn rename(&mut self, identifier: &str, name: &str) -> Result<Workspace> {
        if !name_ok(name) {
            return Err(invalid("workspace name must be 1–100 printable characters"));
        }
        let (id, _, default_project_id) = self.workspace_row(identifier)?;
        if id == "wsp_default" {
            return Err(invalid("the default workspace cannot be renamed"));
        }
        let selected = id == self.selected_id()?;
        self.db.execute(
            "UPDATE workspaces SET name=?1 WHERE id=?2",
            params![name, id],
        )?;
        Ok(Workspace {
            id,
            name: name.to_owned(),
            selected,
            default_project_id,
        })
    }

    pub fn select(&mut self, identifier: &str) -> Result<WorkspaceView> {
        let (id, _, _) = self.workspace_row(identifier)?;
        self.db.execute(
            "UPDATE registry_meta SET value=?1 WHERE key='selected_workspace'",
            [&id],
        )?;
        self.show(&id)
    }

    /// Deletes a Workspace; one that still lists Projects only with `force` (the Projects, their
    /// files and registrations stay).
    pub fn delete(&mut self, identifier: &str, force: bool) -> Result<()> {
        let (id, _, _) = self.workspace_row(identifier)?;
        if id == "wsp_default" {
            return Err(invalid("the default workspace cannot be deleted"));
        }
        let listed: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM workspace_projects WHERE workspace_id=?1",
            [&id],
            |row| row.get(0),
        )?;
        if listed > 0 && !force {
            return Err(crate::coded(
                "CONFIRMATION_REQUIRED",
                format!(
                    "Workspace {identifier} still lists {listed} Project(s); delete it anyway with --force (the Projects stay registered)"
                ),
            ));
        }
        let tx = self.db.transaction()?;
        tx.execute("UPDATE registry_meta SET value='wsp_default' WHERE key='selected_workspace' AND value=?1", [&id])?;
        tx.execute("DELETE FROM workspaces WHERE id=?1", [&id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn projects(&self) -> Result<Vec<ProjectEntry>> {
        let mut stmt = self.db.prepare("SELECT project_id,namespace_id,path,name FROM projects ORDER BY registered_at,project_id")?;
        let rows = stmt.query_map([], |row| {
            Ok(ProjectEntry {
                project_id: row.get(0)?,
                namespace_id: row.get(1)?,
                path: PathBuf::from(row.get::<_, String>(2)?),
                name: row.get(3)?,
                pinned: false,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn project(&self, identifier: &str) -> Result<ProjectEntry> {
        self.db.query_row(
            "SELECT project_id,namespace_id,path,name FROM projects WHERE project_id=?1 OR path=?1",
            [identifier], |row| Ok(ProjectEntry {
                project_id: row.get(0)?, namespace_id: row.get(1)?,
                path: PathBuf::from(row.get::<_,String>(2)?), name: row.get(3)?, pinned: false,
            }),
        ).optional()?.ok_or_else(|| crate::coded("PROJECT_NOT_FOUND", format!("unknown registered project {identifier}")))
    }

    pub fn rename_project(&self, identifier: &str, name: &str) -> Result<ProjectEntry> {
        let name = name.trim();
        if !name_ok(name) {
            return Err(invalid("project name must be 1–100 printable characters"));
        }
        let entry = self.project(identifier)?;
        self.db.execute(
            "UPDATE projects SET name=?1 WHERE project_id=?2",
            params![name, entry.project_id],
        )?;
        self.project(&entry.project_id)
    }

    pub fn assert_path_available(&self, path: &Path) -> Result<()> {
        if let Some(path_text) = path.to_str() {
            let existing: Option<String> = self
                .db
                .query_row(
                    "SELECT project_id FROM projects WHERE path=?1",
                    [path_text],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = existing {
                return Err(crate::coded(
                    "PROJECT_IDENTITY_CONFLICT",
                    format!("path is already registered to {id}"),
                ));
            }
        }
        Ok(())
    }

    pub fn ensure_project_path(&self, identity: &ProjectIdentity, path: &Path) -> Result<()> {
        let path_text = path.to_string_lossy();
        let at_path: Option<String> = self
            .db
            .query_row(
                "SELECT project_id FROM projects WHERE path=?1",
                [&*path_text],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(other) = at_path
            && other != identity.project_id
        {
            return Err(crate::coded(
                "PROJECT_IDENTITY_CONFLICT",
                format!(
                    "path {} is registered to another project ({other})",
                    path.display()
                ),
            ));
        }
        let registered: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT path,namespace_id FROM projects WHERE project_id=?1",
                [&identity.project_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((known, namespace)) = registered
            && (known != path_text || namespace != identity.namespace_id.to_string())
        {
            return Err(crate::coded(
                "PROJECT_IDENTITY_CONFLICT",
                format!(
                    "{} is registered at {}; writes to {} are blocked",
                    identity.project_id,
                    known,
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    fn add_membership(tx: &Transaction<'_>, workspace: &str, project_id: &str) -> Result<()> {
        let next: i64 = tx.query_row(
            "SELECT COALESCE(MAX(position),-1)+1 FROM workspace_projects WHERE workspace_id=?1",
            [workspace],
            |row| row.get(0),
        )?;
        tx.execute("INSERT OR IGNORE INTO workspace_projects(workspace_id,project_id,position) VALUES (?1,?2,?3)", params![workspace,project_id,next])?;
        tx.execute(
            "UPDATE workspaces SET default_project_id=COALESCE(default_project_id,?2) WHERE id=?1",
            params![workspace, project_id],
        )?;
        Ok(())
    }

    pub fn register_project(
        &mut self,
        project: &crate::ProjectInfo,
        workspace: Option<&str>,
    ) -> Result<ProjectEntry> {
        let path = project.root.to_string_lossy().into_owned();
        let id = &project.identity.project_id;
        let namespace = project.identity.namespace_id.to_string();
        let workspace_id = workspace
            .map(|name| self.workspace_row(name).map(|r| r.0))
            .transpose()?
            .unwrap_or(self.selected_id()?);
        self.ensure_project_path(&project.identity, &project.root)?;
        if let Ok(other) = self.project(&path)
            && other.project_id != *id
        {
            return Err(invalid(format!(
                "path already belongs to {}",
                other.project_id
            )));
        }
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO projects(project_id,namespace_id,path,name,registered_at) VALUES (?1,?2,?3,?4,?5)",
            params![id,namespace,path,project.display_name,now()?],
        )?;
        Self::add_membership(&tx, &workspace_id, id)?;
        tx.commit()?;
        self.project(id)
    }

    pub fn add_project(&mut self, workspace: &str, project_id: &str) -> Result<WorkspaceView> {
        let (workspace_id, _, _) = self.workspace_row(workspace)?;
        self.project(project_id)?;
        let tx = self.db.transaction()?;
        Self::add_membership(&tx, &workspace_id, project_id)?;
        tx.commit()?;
        self.show(&workspace_id)
    }

    pub fn remove_project(&mut self, workspace: &str, project_id: &str) -> Result<WorkspaceView> {
        let (workspace_id, _, _) = self.workspace_row(workspace)?;
        let tx = self.db.transaction()?;
        let count = tx.execute(
            "DELETE FROM workspace_projects WHERE workspace_id=?1 AND project_id=?2",
            params![workspace_id, project_id],
        )?;
        if count == 0 {
            return Err(invalid("project is not in that workspace"));
        }
        tx.execute(
            "UPDATE workspaces SET default_project_id=NULL WHERE id=?1 AND default_project_id=?2",
            params![workspace_id, project_id],
        )?;
        tx.commit()?;
        self.show(&workspace_id)
    }

    pub fn set_default_project(
        &mut self,
        workspace: &str,
        project_id: &str,
    ) -> Result<WorkspaceView> {
        let (workspace_id, _, _) = self.workspace_row(workspace)?;
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM workspace_projects WHERE workspace_id=?1 AND project_id=?2",
            params![workspace_id, project_id],
            |row| row.get(0),
        )?;
        if count == 0 {
            return Err(invalid("project is not in that workspace"));
        }
        self.db.execute(
            "UPDATE workspaces SET default_project_id=?2 WHERE id=?1",
            params![workspace_id, project_id],
        )?;
        self.show(&workspace_id)
    }

    pub fn relocate(&mut self, project_id: &str, new_path: &Path) -> Result<ProjectEntry> {
        let entry = self.project(project_id)?;
        if entry.path.exists() {
            return Err(invalid(
                "registered path still exists; relocation would register a live copy",
            ));
        }
        let project = Project::peek(new_path)?;
        if project.identity.project_id != entry.project_id
            || project.identity.namespace_id.to_string() != entry.namespace_id
        {
            return Err(invalid(
                "target ProjectId or Namespace does not match registration",
            ));
        }
        self.db.execute(
            "UPDATE projects SET path=?1 WHERE project_id=?2",
            params![project.root.to_string_lossy(), project_id],
        )?;
        crate::authority::bind(project_id, &project.root)?;
        self.project(project_id)
    }

    pub fn unregister(&mut self, project_id: &str) -> Result<()> {
        let entry = self.project(project_id)?;
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE workspaces SET default_project_id=NULL WHERE default_project_id=?1",
            [&entry.project_id],
        )?;
        tx.execute(
            "DELETE FROM projects WHERE project_id=?1",
            [&entry.project_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod guard_tests {
    use super::guard_with;
    use std::path::PathBuf;

    #[test]
    fn the_test_guard_admits_only_test_roots() {
        let temp = PathBuf::from("/tmp");
        let allowed = Some(std::env::join_paths(["/w/target"]).unwrap());
        let ok = |p: &str| guard_with(PathBuf::from(p), allowed.clone(), temp.clone()).is_ok();
        assert!(ok("/w/target/test-xdg/calve"));
        assert!(ok("/tmp/x/d/calve"));
        assert!(!ok("/home/u/.local/share/calve"));
        assert!(!ok("/w/targets/calve"), "a prefix of a name is not a root");
        assert!(
            guard_with(PathBuf::from("/home/u/x"), None, temp).is_ok(),
            "off without the guard"
        );
    }

    /// Neither a symlink inside a test root nor `..` leads out of it.
    #[cfg(unix)]
    #[test]
    fn the_test_guard_cannot_be_escaped_by_links_or_dot_dot() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let allowed = Some(root.path().as_os_str().to_owned());
        let temp = root.path().join("no-temp");
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        let ok = |p: PathBuf| guard_with(p, allowed.clone(), temp.clone()).is_ok();
        assert!(ok(root.path().join("d/calve")));
        assert!(
            !ok(root.path().join("link/calve")),
            "a link out of the root"
        );
        assert!(!ok(root.path().join("link")), "the link itself");
        assert!(!ok(root.path().join("missing/../../x")), "dot-dot");
        assert!(
            !ok(root.path().join("d/../calve")),
            "dot-dot even when it stays inside"
        );
    }
}
