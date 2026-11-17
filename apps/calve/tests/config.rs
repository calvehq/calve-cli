use std::fs;

use calve_app::config::{ColorMode, ConfigPaths, Scope};

#[test]
fn precedence_and_unset_reveal_lower_scope() {
    let temp = tempfile::tempdir().unwrap();
    let paths = ConfigPaths {
        global: temp.path().join("config/global.toml"),
        workspace: temp.path().join("config/team.toml"),
        project: Some(temp.path().join("project/.calve/config.toml")),
        override_file: None,
    };
    paths.set(Scope::Global, "ui.color", "never").unwrap();
    paths.set(Scope::Global, "ui.page_size", "20").unwrap();
    paths.set(Scope::Workspace, "ui.page_size", "30").unwrap();
    paths.set(Scope::Project, "ui.page_size", "40").unwrap();
    let effective = paths.load().unwrap();
    assert_eq!(effective.color, ColorMode::Never);
    assert_eq!(effective.page_size, 40);
    paths.unset(Scope::Project, "ui.page_size").unwrap();
    assert_eq!(paths.load().unwrap().page_size, 30);
    let override_path = temp.path().join("override.toml");
    fs::write(&override_path, "format_version = 1\n[ui]\npage_size = 7\n").unwrap();
    let with_override = ConfigPaths {
        override_file: Some(override_path),
        ..paths
    };
    assert_eq!(with_override.load().unwrap().page_size, 7);
}

#[test]
fn secret_references_are_validated_and_extension_keys_survive_write() {
    let temp = tempfile::tempdir().unwrap();
    let global = temp.path().join("config.toml");
    fs::write(&global, "format_version = 1\nfuture_core = 4\n[integrations.\"org.example.tool\"]\nenabled = true\n").unwrap();
    let paths = ConfigPaths {
        global: global.clone(),
        workspace: temp.path().join("workspace.toml"),
        project: None,
        override_file: None,
    };
    assert!(
        paths
            .set(Scope::Global, "secrets.token", "literal-password")
            .is_err()
    );
    paths
        .set(Scope::Global, "secrets.token", "env:CALVE_TOKEN")
        .unwrap();
    paths.set(Scope::Global, "ui.color", "auto").unwrap();
    let text = fs::read_to_string(global).unwrap();
    assert!(text.contains("org.example.tool"));
    assert!(text.contains("future_core"));
    assert!(text.contains("env:CALVE_TOKEN"));
    let effective = paths.load().unwrap();
    assert_eq!(effective.secrets["token"], "env:CALVE_TOKEN");
    assert_eq!(effective.warnings.len(), 1);
}
