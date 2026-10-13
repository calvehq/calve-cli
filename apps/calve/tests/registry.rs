use std::fs;
use std::path::Path;

use calve_app::Project;
use calve_app::registry::Registry;

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for item in fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        let destination = to.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_tree(&item.path(), &destination);
        } else {
            fs::copy(item.path(), destination).unwrap();
        }
    }
}

#[tokio::test]
async fn workspace_membership_does_not_duplicate_project_state() {
    let temp = tempfile::tempdir().unwrap();
    let project_path = temp.path().join("project");
    let project = Project::init(&project_path, Some("Shared")).await.unwrap();
    let id = project.identity.project_id.clone();
    let mut registry = Registry::open_at(&temp.path().join("data")).unwrap();
    registry.register_project(&project.info(), None).unwrap();
    let second = registry.create("team").unwrap();
    registry.add_project(&second.id, &id).unwrap();
    registry.set_default_project(&second.id, &id).unwrap();
    assert_eq!(registry.show("default").unwrap().projects.len(), 1);
    assert_eq!(registry.show("team").unwrap().projects.len(), 1);
    assert_eq!(
        registry
            .show("team")
            .unwrap()
            .workspace
            .default_project_id
            .as_deref(),
        Some(id.as_str())
    );
    registry.select("team").unwrap();
    drop(registry);
    let mut reopened = Registry::open_at(&temp.path().join("data")).unwrap();
    assert_eq!(reopened.selected().unwrap().workspace.id, second.id);
    reopened.delete("team").unwrap();
    assert_eq!(reopened.selected().unwrap().workspace.id, "wsp_default");
    assert_eq!(reopened.projects().unwrap().len(), 1);
    drop(project);
    assert_eq!(
        Project::open(&project_path).unwrap().identity.project_id,
        id
    );
}

#[tokio::test]
async fn copied_identity_is_blocked_until_original_is_relocated() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original");
    let copy = temp.path().join("copy");
    let project = Project::init(&original, None).await.unwrap();
    let id = project.identity.project_id.clone();
    let mut registry = Registry::open_at(&temp.path().join("data")).unwrap();
    registry.register_project(&project.info(), None).unwrap();
    drop(project);
    copy_tree(&original, &copy);
    let copied = Project::open(&copy).unwrap();
    assert!(
        registry
            .ensure_project_path(&copied.identity, &copied.root)
            .is_err()
    );
    assert!(registry.register_project(&copied.info(), None).is_err());
    assert!(registry.relocate(&id, &copy).is_err());
    drop(copied);
    fs::remove_dir_all(&copy).unwrap();
    fs::rename(&original, &copy).unwrap();
    let relocated = registry.relocate(&id, &copy).unwrap();
    assert_eq!(relocated.path, copy);
}

#[tokio::test]
async fn project_display_name_is_mutable_product_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("project");
    let mut project = Project::init(&path, Some("Original")).await.unwrap();
    let id = project.identity.project_id.clone();
    assert_eq!(project.identity.format_version, 2);
    assert!(project.identity.name.is_none());
    let identity_file = fs::read_to_string(path.join(".calve/project.toml")).unwrap();
    assert!(!identity_file.contains("name ="));
    let mut registry = Registry::open_at(&temp.path().join("data")).unwrap();
    registry.register_project(&project.info(), None).unwrap();
    let workspace = registry.create("secondary").unwrap();
    registry.add_project(&workspace.id, &id).unwrap();
    registry.rename_project(&id, "Updated").unwrap();
    project.rename("Updated").unwrap();
    assert!(project.rename("  ").is_err());
    assert!(registry.rename_project(&id, "  ").is_err());
    assert_eq!(registry.project(&id).unwrap().name, "Updated");
    assert_eq!(
        registry.show(&workspace.id).unwrap().projects[0].name,
        "Updated"
    );
    drop(project);
    assert_eq!(Project::open(&path).unwrap().display_name, "Updated");
    assert_eq!(
        fs::read_to_string(path.join(".calve/project.toml")).unwrap(),
        identity_file
    );
}

#[tokio::test]
async fn legacy_project_name_remains_readable_after_rename() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("project");
    let project = Project::init(&path, Some("Original")).await.unwrap();
    drop(project);
    let identity_path = path.join(".calve/project.toml");
    let mut identity: toml::Value =
        toml::from_str(&fs::read_to_string(&identity_path).unwrap()).unwrap();
    identity["format_version"] = toml::Value::Integer(1);
    identity
        .as_table_mut()
        .unwrap()
        .insert("name".into(), toml::Value::String("Original".into()));
    fs::write(&identity_path, toml::to_string(&identity).unwrap()).unwrap();
    let db = rusqlite::Connection::open(path.join(".calve/product.sqlite3")).unwrap();
    db.execute(
        "DELETE FROM preferences WHERE key='project.display_name'",
        [],
    )
    .unwrap();
    drop(db);
    let mut reopened = Project::open(&path).unwrap();
    assert_eq!(reopened.display_name, "Original");
    reopened.rename("Updated").unwrap();
    drop(reopened);
    let reopened = Project::open(&path).unwrap();
    assert_eq!(reopened.display_name, "Updated");
    assert_eq!(reopened.identity.name.as_deref(), Some("Original"));
}
