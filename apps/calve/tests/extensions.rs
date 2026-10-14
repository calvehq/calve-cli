use std::fs;
use std::path::{Path, PathBuf};

use calve_app::extensions::{CatalogBody, CatalogPackage, publish_catalog, rotate_root};
use calve_testkit::Env;
use openaevc::crypto::sha256;
use serde_json::json;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_calve"))
        .parent()
        .unwrap()
        .join("examples")
        .join(if cfg!(windows) {
            "fixture_ext.exe"
        } else {
            "fixture_ext"
        })
}

/// Writes a fixture artifact whose trailer sets its version and requested capabilities.
fn artifact(dir: &Path, version: &str, caps: &[&str]) -> CatalogPackage {
    let name = format!("fixture-{version}");
    let mut bytes = fs::read(fixture()).unwrap();
    bytes.extend(format!("\nCALVE-FIXTURE:{}", json!({"version":version,"caps":caps})).as_bytes());
    let path = dir.join(&name);
    fs::write(&path, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    CatalogPackage {
        id: "org.example.fixture".into(),
        version: version.into(),
        artifact: name,
        digest: sha256(&bytes),
        summary: Some("Fixture".into()),
    }
}

fn publish(dir: &Path, packages: Vec<CatalogPackage>, seeds: &[[u8; 32]]) {
    let body = CatalogBody {
        name: "example".into(),
        version: 0,
        expires: 0,
        packages,
    };
    fs::write(
        dir.join("targets.body.json"),
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    publish_catalog(dir, seeds, seeds.len(), 30).unwrap();
}

fn snapshot_roles(dir: &Path) -> Vec<(String, Vec<u8>)> {
    ["timestamp.json", "snapshot.json", "targets.json"]
        .iter()
        .map(|name| (name.to_string(), fs::read(dir.join(name)).unwrap()))
        .collect()
}

#[test]
fn signed_catalog_install_grant_update_rotate_and_uninstall() {
    let env = Env::new(env!("CARGO_BIN_EXE_calve"));
    let data = env.path();
    let catalog = data.join("catalog");
    fs::create_dir(&catalog).unwrap();
    let key = [9u8; 32];
    let v1 = artifact(&catalog, "1.0.0", &["clock.read"]);
    publish(&catalog, vec![v1.clone()], &[key]);
    let old_metadata = snapshot_roles(&catalog);
    let root_digest = sha256(&fs::read(catalog.join("root.json")).unwrap()).to_string();
    let c = catalog.to_str().unwrap();

    let wrong = env.fails(&[
        "extension",
        "catalog-trust",
        "example",
        c,
        "--root-digest",
        &sha256(b"other").to_string(),
    ]);
    assert!(wrong.contains("pinned digest"), "{wrong}");
    env.ok(&[
        "extension",
        "catalog-trust",
        "example",
        c,
        "--root-digest",
        &root_digest,
    ]);
    assert!(
        env.ok(&["extension", "catalogs"])
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "example" && c["valid"] == true)
    );
    assert_eq!(
        env.ok(&["extension", "search", "fixture"])["packages"][0]["version"],
        "1.0.0"
    );

    // Tampering with an artifact after signing is caught by the digest check.
    let honest = fs::read(catalog.join(&v1.artifact)).unwrap();
    fs::write(
        catalog.join(&v1.artifact),
        [honest.clone(), b"x".to_vec()].concat(),
    )
    .unwrap();
    assert!(
        env.fails(&["extension", "install", "org.example.fixture"])
            .contains("digest")
    );
    fs::write(catalog.join(&v1.artifact), &honest).unwrap();
    assert_eq!(
        env.ok(&["extension", "install", "org.example.fixture"])["requested_host_capabilities"],
        json!(["clock.read"])
    );

    let root = data.join("project");
    let p = root.to_str().unwrap();
    env.ok(&["init", p]);
    let enabled = env.ok(&["--project", p, "extension", "enable", "org.example.fixture"]);
    assert_eq!(enabled["ungranted_requests"], json!(["clock.read"]));
    assert!(
        env.fails(&[
            "--project",
            p,
            "extension",
            "grant",
            "org.example.fixture",
            "network.connect"
        ])
        .contains("does not request")
    );
    assert_eq!(
        env.ok(&[
            "--project",
            p,
            "extension",
            "grant",
            "org.example.fixture",
            "clock.read"
        ])["granted"],
        json!(["clock.read"])
    );
    assert!(
        env.fails(&["extension", "uninstall", "org.example.fixture"])
            .contains("enabled in Project")
    );

    // Root rotation: the new root is signed by old and new keys; later metadata uses the new key.
    let new_key = [7u8; 32];
    let v2 = artifact(&catalog, "1.1.0", &["clock.read", "network.connect"]);
    let body = CatalogBody {
        name: "example".into(),
        version: 0,
        expires: 0,
        packages: vec![v1.clone(), v2],
    };
    fs::write(
        catalog.join("targets.body.json"),
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    rotate_root(&catalog, &[key], &[new_key], 1, 30).unwrap();
    let held = env.ok(&["--project", p, "extension", "update", "org.example.fixture"]);
    assert_eq!(
        held["permission_widening"],
        json!(["network.connect"]),
        "{held}"
    );
    let updated = env.ok(&[
        "--project",
        p,
        "extension",
        "update",
        "org.example.fixture",
        "--grant",
        "network.connect",
    ]);
    assert_eq!(updated["version"], "1.1.0");
    let listed = env.ok(&["extension", "catalogs"]);
    let example = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "example")
        .unwrap();
    assert_eq!(example["versions"]["root"], 2, "{example}");

    // Metadata signed only by the retired key is refused.
    publish_catalog(&catalog, &[key], 1, 30).unwrap();
    let warnings = env.ok(&["extension", "search"])["warnings"].to_string();
    assert!(
        warnings.contains("signatures"),
        "retired key must not verify: {warnings}"
    );
    publish_catalog(&catalog, &[new_key], 1, 30).unwrap();

    // Restoring older timestamp/snapshot/targets is a rollback and is refused.
    for (name, bytes) in &old_metadata {
        fs::write(catalog.join(name), bytes).unwrap();
    }
    let warnings = env.ok(&["extension", "search"])["warnings"].to_string();
    assert!(
        warnings.contains("rollback") || warnings.contains("signatures"),
        "{warnings}"
    );

    env.ok(&[
        "--project",
        p,
        "extension",
        "revoke",
        "org.example.fixture",
        "network.connect",
    ]);
    env.ok(&[
        "--project",
        p,
        "extension",
        "disable",
        "org.example.fixture",
    ]);
    assert_eq!(
        env.ok(&["extension", "uninstall", "org.example.fixture"])["uninstalled"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}
