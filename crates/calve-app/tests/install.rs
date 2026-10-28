//! Package installation from signed catalogs (rev 10 §8, §9.3–§9.4): the trust, compatibility
//! and permission gates, publisher identity, revocation, immutability, crash convergence and
//! retirement — against the independent test publisher and the fixture extension.

use std::fs;

use calve_app::catalog::install::*;
use calve_testkit::tuf::{Package, Repo};

struct Machine {
    _t: tempfile::TempDir,
    paths: Paths,
}

impl Drop for Machine {
    fn drop(&mut self) {
        calve_testkit::make_writable(self._t.path());
    }
}

fn machine() -> Machine {
    let t = tempfile::tempdir().unwrap();
    let paths = Paths {
        data: t.path().join("data"),
        extension_dir: t.path().join("extensions"),
    };
    Machine { _t: t, paths }
}

fn native() -> Vec<u8> {
    fs::read(calve_testkit::fixture_ext()).unwrap()
}

fn toy(meta: Option<Vec<u8>>) -> Package<'static> {
    Package {
        id: "org.example.toy",
        version: "0.1.0",
        kind: "cic-capable",
        native: ("calve-fixture-ext", native()),
        cic: Some(calve_testkit::cic::guest("ref-rust")),
        metadata: Some(meta.unwrap_or_else(|| {
            fs::read(calve_testkit::cic::fixtures().join("toy-metadata.json")).unwrap()
        })),
        refs: Some(calve_testkit::TOY_REFS.as_bytes().to_vec()),
    }
}

fn catalog(m: &Machine, name: &str, r: &Repo) {
    let root = r.root_bytes(1);
    add_catalog(
        &m.paths,
        name,
        r.path().to_str().unwrap(),
        &root,
        &calve_testkit::tuf::sha(&root),
    )
    .unwrap();
}

fn installer(m: &Machine) -> Installer {
    Installer::new(m.paths.clone(), CicRunner::InProcess)
}

fn req(ack: bool) -> InstallRequest<'static> {
    InstallRequest {
        id: "org.example.toy",
        version: None,
        catalog: None,
        acknowledge_native: ack,
        switch_publisher: false,
    }
}

fn code(r: Result<PackageRecord>) -> &'static str {
    r.expect_err("expected a refusal").code
}

fn repo_with_toy() -> Repo {
    let mut r = Repo::new();
    r.add_package("targets", toy(None));
    r.publish();
    r
}

#[test]
fn installs_into_an_immutable_digest_path_and_is_idempotent() {
    let m = machine();
    let r = repo_with_toy();
    catalog(&m, "main", &r);
    let rec = installer(&m).install(&req(true)).unwrap();
    assert_eq!(
        (rec.id.as_str(), rec.version.as_str(), rec.kind.clone()),
        ("org.example.toy", "0.1.0", Kind::CicCapable)
    );
    assert_eq!(rec.digests["native"], calve_testkit::tuf::sha(&native()));
    assert_eq!(
        rec.entrypoint,
        format!(
            "org.example.toy/{}/calve-fixture-ext",
            rec.digests["native"]
        )
    );
    assert_eq!(rec.manifest.id, "org.example.toy");
    assert!(rec.native_acknowledged && rec.metadata.is_some());
    verify_installed(&m.paths, &rec).unwrap();
    let dir = m
        .paths
        .extension_dir
        .join("org.example.toy")
        .join(rec.native_digest());
    assert!(
        fs::metadata(dir.join("cic.wasm"))
            .unwrap()
            .permissions()
            .readonly(),
        "read-only after install"
    );
    assert_eq!(
        installer(&m).install(&req(true)).unwrap().digests,
        rec.digests,
        "idempotent"
    );
    assert_eq!(installed(&m.paths).unwrap().len(), 1);
    let left: Vec<_> = fs::read_dir(&m.paths.extension_dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with('.')
        })
        .collect();
    assert!(left.is_empty(), "no staging left");
}

#[test]
fn native_code_never_runs_without_the_t2_acknowledgment() {
    let m = machine();
    let r = repo_with_toy();
    catalog(&m, "main", &r);
    assert_eq!(
        code(installer(&m).install(&req(false))),
        "T2_ACKNOWLEDGMENT_REQUIRED"
    );
    assert!(installed(&m.paths).unwrap().is_empty());
}

#[test]
fn describe_must_equal_the_signed_metadata() {
    let m = machine();
    let mut meta: serde_json::Value = serde_json::from_slice(
        &fs::read(calve_testkit::cic::fixtures().join("toy-metadata.json")).unwrap(),
    )
    .unwrap();
    meta["display_name"] = "Not the guest".into();
    let mut r = Repo::new();
    r.add_package("targets", toy(Some(serde_json::to_vec(&meta).unwrap())));
    r.publish();
    catalog(&m, "main", &r);
    assert_eq!(code(installer(&m).install(&req(true))), "PACKAGE_INVALID");
}

#[test]
fn kind_rules_and_compatibility_gates() {
    // cic.wasm without metadata.
    let m = machine();
    let mut r = Repo::new();
    let mut p = toy(None);
    p.metadata = None;
    r.add_package("targets", p);
    r.publish();
    catalog(&m, "main", &r);
    assert_eq!(code(installer(&m).install(&req(true))), "PACKAGE_INVALID");
    // A required capability the host does not have.
    let m = machine();
    let mut meta: serde_json::Value = serde_json::from_slice(
        &fs::read(calve_testkit::cic::fixtures().join("toy-metadata.json")).unwrap(),
    )
    .unwrap();
    meta["capabilities"]["required"] = serde_json::json!(["capture.v1", "teleport.v9"]);
    let mut r = Repo::new();
    r.add_package("targets", toy(Some(serde_json::to_vec(&meta).unwrap())));
    r.publish();
    catalog(&m, "main", &r);
    assert_eq!(code(installer(&m).install(&req(true))), "INCOMPATIBLE_CIC");
    // No native build for this platform.
    let m = machine();
    let mut r = Repo::new();
    r.add_package("targets", toy(None));
    let idx = r.targets.get_mut("org.example.toy/package.json").unwrap();
    *idx = String::from_utf8(idx.clone())
        .unwrap()
        .replace(
            &calve_testkit::tuf::host_platform(),
            "riscv64gc-unknown-none-elf",
        )
        .into_bytes();
    r.publish();
    catalog(&m, "main", &r);
    assert_eq!(
        code(installer(&m).install(&req(true))),
        "EXTENSION_INCOMPATIBLE"
    );
}

#[test]
fn tampered_target_on_the_mirror_is_refused() {
    let m = machine();
    let r = repo_with_toy();
    catalog(&m, "main", &r);
    let digest = calve_testkit::tuf::sha(&calve_testkit::cic::guest("ref-rust"));
    let path = r
        .path()
        .join(format!("targets/org.example.toy/0.1.0/{digest}.cic.wasm"));
    let mut b = fs::read(&path).unwrap();
    b[100] ^= 1;
    fs::write(&path, b).unwrap();
    assert_eq!(code(installer(&m).install(&req(true))), "CATALOG_UNTRUSTED");
    assert!(installed(&m.paths).unwrap().is_empty());
}

#[test]
fn revoked_packages_are_refused() {
    let m = machine();
    let mut r = Repo::new();
    r.add_package("targets", toy(None));
    r.revoke("org.example.toy", Some("0.1.0"), "compromised build");
    r.publish();
    catalog(&m, "main", &r);
    assert_eq!(code(installer(&m).install(&req(true))), "EXTENSION_REVOKED");
}

#[test]
fn publisher_identity_id_policy_and_path_authorization() {
    // A delegated role signing an id outside its id policy.
    let m = machine();
    let mut r = Repo::new();
    r.delegate(
        "acme",
        "targets",
        &[
            "org.example.toy/*",
            "org.example.toy/*/*",
            "org.example.toy/*/*/*",
        ],
        false,
    );
    r.add_package("acme", toy(None));
    r.id_policy("acme", &["com.acme."]);
    r.publish();
    catalog(&m, "main", &r);
    assert_eq!(
        code(installer(&m).install(&req(true))),
        "PUBLISHER_NOT_AUTHORIZED"
    );
    // The same role with a matching policy installs and the record names the role.
    let m = machine();
    let mut r = Repo::new();
    r.delegate(
        "examples",
        "targets",
        &[
            "org.example.toy/*",
            "org.example.toy/*/*",
            "org.example.toy/*/*/*",
        ],
        false,
    );
    r.add_package("examples", toy(None));
    r.id_policy("examples", &["org.example."]);
    r.publish();
    catalog(&m, "main", &r);
    assert_eq!(installer(&m).install(&req(true)).unwrap().role, "examples");
    // A role whose paths do not cover the id: its listing is invisible to the verifier.
    let m = machine();
    let mut r = Repo::new();
    r.delegate(
        "evil",
        "targets",
        &["com.evil/*", "com.evil/*/*", "com.evil/*/*/*"],
        false,
    );
    r.add_package("evil", toy(None));
    r.id_policy("evil", &["org."]);
    r.publish();
    catalog(&m, "main", &r);
    assert_eq!(code(installer(&m).install(&req(true))), "NOT_FOUND");
}

#[test]
fn second_catalog_offering_a_pinned_id_needs_switch_publisher() {
    let m = machine();
    let (r1, r2) = (repo_with_toy(), repo_with_toy());
    catalog(&m, "first", &r1);
    catalog(&m, "second", &r2);
    assert_eq!(code(installer(&m).install(&req(true))), "AMBIGUOUS");
    let first = InstallRequest {
        catalog: Some("first"),
        ..req(true)
    };
    installer(&m).install(&first).unwrap();
    let second = InstallRequest {
        catalog: Some("second"),
        ..req(true)
    };
    assert_eq!(
        code(installer(&m).install(&second)),
        "PUBLISHER_NOT_AUTHORIZED"
    );
    let switched = InstallRequest {
        switch_publisher: true,
        ..second
    };
    assert_eq!(installer(&m).install(&switched).unwrap().catalog, "second");
}

#[test]
fn a_crash_at_every_install_step_converges() {
    for step in [
        InstallStep::Resolved,
        InstallStep::Downloaded,
        InstallStep::Validated,
        InstallStep::Installed,
        InstallStep::Recorded,
    ] {
        let m = machine();
        let r = repo_with_toy();
        catalog(&m, "main", &r);
        let mut i = installer(&m);
        i.fault = Some(step);
        assert_eq!(code(i.install(&req(true))), "CRASH_INJECTED");
        let recovered = installer(&m).recover().unwrap();
        assert_eq!(recovered.len(), 1, "{step:?}: one journal reconciled");
        let outcome = recovered[0]["outcome"].as_str().unwrap();
        let expect = if matches!(step, InstallStep::Installed | InstallStep::Recorded) {
            "installed"
        } else {
            "abandoned"
        };
        assert_eq!(outcome, expect, "{step:?}");
        let staging: Vec<_> = fs::read_dir(&m.paths.extension_dir)
            .into_iter()
            .flatten()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".staging")
            })
            .collect();
        assert!(staging.is_empty(), "{step:?}: staging removed");
        assert!(
            installer(&m).recover().unwrap().is_empty(),
            "{step:?}: idempotent"
        );
        let rec = installer(&m).install(&req(true)).unwrap();
        verify_installed(&m.paths, &rec).unwrap();
    }
}

#[test]
fn tampering_after_install_is_detected_and_retirement_respects_use() {
    let m = machine();
    let r = repo_with_toy();
    catalog(&m, "main", &r);
    let rec = installer(&m).install(&req(true)).unwrap();
    let dir = m
        .paths
        .extension_dir
        .join("org.example.toy")
        .join(rec.native_digest());
    let meta = dir.join("calve-integration.json");
    let mut perm = fs::metadata(&meta).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perm.set_readonly(false);
    fs::set_permissions(&meta, perm).unwrap();
    fs::write(&meta, b"{}").unwrap();
    assert_eq!(
        verify_installed(&m.paths, &rec).err().unwrap().code,
        "PACKAGE_TAMPERED"
    );
    assert_eq!(
        installer(&m).retire(&rec, |_| true).err().unwrap().code,
        "EXTENSION_IN_USE"
    );
    assert!(dir.exists(), "kept while in use");
    installer(&m).retire(&rec, |_| false).unwrap();
    assert!(!dir.exists(), "retired");
}

#[test]
fn catalog_names_and_ids_are_validated() {
    let m = machine();
    let r = repo_with_toy();
    let root = r.root_bytes(1);
    assert_eq!(
        add_catalog(
            &m.paths,
            "../x",
            "/tmp",
            &root,
            &calve_testkit::tuf::sha(&root)
        )
        .err()
        .unwrap()
        .code,
        "INVALID_INPUT"
    );
    assert!(
        add_catalog(
            &m.paths,
            "ok",
            r.path().to_str().unwrap(),
            &root,
            &"0".repeat(64)
        )
        .is_err(),
        "root digest pin"
    );
    for bad in ["toy", "Org.Example", "a..b", "a/b.c", "../evil.x"] {
        assert!(!valid_id(bad), "{bad}");
    }
}

/// Security review of 7b12d8e: a role name is chosen by its delegator, so a nested delegation
/// that reuses the name of a policy-authorized top-level role must not inherit its policy.
#[test]
fn nested_role_reusing_an_authorized_name_is_not_that_publisher() {
    let m = machine();
    let mut r = Repo::new();
    r.delegate("acme", "targets", &["*", "*/*", "*/*/*", "*/*/*/*"], false);
    r.delegate(
        "examples",
        "acme",
        &[
            "org.example.toy/*",
            "org.example.toy/*/*",
            "org.example.toy/*/*/*",
        ],
        false,
    );
    r.add_package("examples", toy(None));
    r.id_policy("acme", &["com.acme."]);
    r.id_policy("examples", &["org.example."]);
    r.publish();
    catalog(&m, "main", &r);
    let e = installer(&m)
        .install(&req(true))
        .expect_err("nested name must not match");
    assert_eq!(e.code, "PUBLISHER_NOT_AUTHORIZED", "{e}");
    assert!(e.message.contains("acme/examples"), "{e}");
}

/// Security review of ec59f58: a single role whose name contains `/` must not collide with a
/// delegation chain of the same text.
#[test]
fn slash_in_a_role_name_cannot_impersonate_a_chain() {
    let m = machine();
    let mut r = Repo::new();
    r.delegate(
        "acme/examples",
        "targets",
        &[
            "org.example.toy/*",
            "org.example.toy/*/*",
            "org.example.toy/*/*/*",
        ],
        false,
    );
    r.add_package("acme/examples", toy(None));
    r.id_policy("acme/examples", &["org.example."]);
    r.publish();
    catalog(&m, "main", &r);
    let e = installer(&m)
        .install(&req(true))
        .expect_err("policy for the chain, not the name");
    assert_eq!(e.code, "PUBLISHER_NOT_AUTHORIZED", "{e}");
    assert!(e.message.contains("acme%2Fexamples"), "{e}");
}

#[test]
fn an_interrupted_retirement_restores_the_package() {
    let m = machine();
    let r = repo_with_toy();
    catalog(&m, "main", &r);
    let rec = installer(&m).install(&req(true)).unwrap();
    let mut i = installer(&m);
    i.fault = Some(InstallStep::Retiring);
    assert_eq!(
        i.retire(&rec, |_| false).unwrap_err().code,
        "CRASH_INJECTED"
    );
    let out = installer(&m).recover().unwrap();
    assert_eq!(out[0]["outcome"], "restored");
    verify_installed(&m.paths, &rec).unwrap();
}

#[test]
fn native_builds_are_selected_by_exact_target_triple_and_digest() {
    // Two targets ship a binary with the same file name in the same version: distinct paths,
    // and the host's build is the one installed.
    let m = machine();
    let mut r = Repo::new();
    r.add_package("targets", toy(None));
    let other = if calve_testkit::tuf::host_platform() == "aarch64-apple-darwin" {
        "x86_64-unknown-linux-gnu"
    } else {
        "aarch64-apple-darwin"
    };
    r.add_native(
        "targets",
        "org.example.toy",
        "0.1.0",
        other,
        "calve-fixture-ext",
        b"another platform's executable".to_vec(),
    );
    r.publish();
    catalog(&m, "main", &r);
    let rec = installer(&m).install(&req(true)).unwrap();
    assert_eq!(rec.target, calve_testkit::tuf::host_platform());
    assert_eq!(rec.digests["native"], calve_testkit::tuf::sha(&native()));
    assert_eq!(rec.manifest.artifact_digest.hex(), rec.digests["native"]);

    // The package index's native digest must equal the TUF target hash.
    let m = machine();
    let mut r = repo_with_toy();
    let idx = r.targets.get_mut("org.example.toy/package.json").unwrap();
    *idx = String::from_utf8(idx.clone())
        .unwrap()
        .replace(&calve_testkit::tuf::sha(&native()), &"0".repeat(64))
        .into_bytes();
    r.publish();
    catalog(&m, "main", &r);
    assert_eq!(code(installer(&m).install(&req(true))), "PACKAGE_INVALID");
    assert!(installed(&m.paths).unwrap().is_empty());

    // An installed record of another target is never activated.
    let m = machine();
    let r = repo_with_toy();
    catalog(&m, "main", &r);
    let mut rec = installer(&m).install(&req(true)).unwrap();
    rec.target = other.into();
    assert_eq!(
        verify_installed(&m.paths, &rec).unwrap_err().code,
        "EXTENSION_INCOMPATIBLE"
    );
}

#[test]
fn the_registered_manifest_must_be_exactly_the_installed_one() {
    use calve_app::extensions::registration_matches;
    let m = machine();
    let r = repo_with_toy();
    catalog(&m, "main", &r);
    let rec = installer(&m).install(&req(true)).unwrap();
    let body = serde_json::to_value(&rec.manifest).unwrap();
    registration_matches(&rec, &body).unwrap();
    for (field, value) in [
        ("id", serde_json::json!("org.example.other")),
        ("version", serde_json::json!("0.1.1")),
        (
            "host_capabilities",
            if rec.manifest.host_capabilities.is_empty() {
                serde_json::json!(["process.execute"])
            } else {
                serde_json::json!([])
            },
        ),
        (
            "artifact_digest",
            serde_json::json!(format!("sha256:{}", "1".repeat(64))),
        ),
    ] {
        let mut b = body.clone();
        b[field] = value;
        assert!(registration_matches(&rec, &b).is_err(), "{field}");
    }
}
