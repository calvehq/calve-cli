//! OpenAEVC source identity, feature isolation and module-use rules (plan rev 11 §5, ADR 0003).
//! Pure functions over parsed manifests, the lockfile and source text, so every rule has a
//! negative fixture in the tests below.

use toml::Value;

pub const GIT: &str = "https://github.com/calvehq/openaevc.git";
/// The only OpenAEVC packages Calve may depend on (`openaevc-sdk` is git-only).
pub const PACKAGES: &[&str] = &["openaevc", "openaevc-sdk"];
/// Only this crate may enable OpenAEVC features or depend on the SDK (dev-dependencies excepted).
pub const RUNTIME_OWNER: &str = "calve-app";
/// Modules that need `store`/`runtime`/`transport`; only the runtime owner may name them.
pub const RESTRICTED_MODULES: &[&str] = &[
    "openaevc::store",
    "openaevc::runtime",
    "openaevc::transport",
];

/// `[workspace.dependencies]`: exactly `openaevc` and `openaevc-sdk`, both from the public
/// git source at `tag`, `version = "=0.1.0"`, default features off; no branch/rev/path/registry.
pub fn check_workspace_deps(deps: &toml::map::Map<String, Value>, tag: &str) -> Result<(), String> {
    for (name, value) in deps.iter().filter(|(n, _)| n.starts_with("openaevc")) {
        if !PACKAGES.contains(&name.as_str()) {
            return Err(format!(
                "{name}: only {PACKAGES:?} may be declared (single-crate OpenAEVC v0.1.0)"
            ));
        }
        let t = value
            .as_table()
            .ok_or_else(|| format!("{name} must be a table with git + tag"))?;
        let get = |k: &str| t.get(k).and_then(Value::as_str);
        if get("git") != Some(GIT) {
            return Err(format!(
                "{name}: git must be {GIT} (crates.io, ssh and forks are rejected)"
            ));
        }
        if get("tag") != Some(tag) {
            return Err(format!("{name}: tag must be {tag}"));
        }
        for forbidden in ["branch", "rev", "path", "registry"] {
            if t.contains_key(forbidden) {
                return Err(format!(
                    "{name}: `{forbidden}` is not allowed; pin the release tag"
                ));
            }
        }
        if get("version") != Some("=0.1.0") {
            return Err(format!("{name}: version must be \"=0.1.0\""));
        }
        if t.get("default-features").and_then(Value::as_bool) != Some(false) {
            return Err(format!("{name}: default-features must be false"));
        }
    }
    for p in PACKAGES {
        if !deps.contains_key(*p) {
            return Err(format!("{p} is not declared in [workspace.dependencies]"));
        }
    }
    Ok(())
}

/// Cargo.lock: exactly one package per OpenAEVC name, each resolved from `GIT?tag=<tag>#<rev>`,
/// and no other `openaevc*` package (e.g. leftovers of the pre-v0.1.0 crate split).
pub fn check_lock(lock: &Value, tag: &str, rev: &str) -> Result<(), String> {
    let want = format!("git+{GIT}?tag={tag}#{rev}");
    let packages = lock
        .get("package")
        .and_then(Value::as_array)
        .ok_or("Cargo.lock has no packages")?;
    let mut seen = Vec::new();
    for p in packages {
        let name = p.get("name").and_then(Value::as_str).unwrap_or_default();
        if !name.starts_with("openaevc") {
            continue;
        }
        if !PACKAGES.contains(&name) {
            return Err(format!(
                "Cargo.lock contains unexpected OpenAEVC package {name}"
            ));
        }
        let source = p.get("source").and_then(Value::as_str).unwrap_or("<none>");
        if source != want {
            return Err(format!("{name} resolves to {source}, expected {want}"));
        }
        seen.push(name);
    }
    seen.sort_unstable();
    if seen != PACKAGES {
        return Err(format!(
            "Cargo.lock must contain exactly one of each of {PACKAGES:?}, found {seen:?}"
        ));
    }
    Ok(())
}

/// A member manifest: OpenAEVC features and the SDK only in the runtime owner (dev-deps
/// excepted); no member-level OpenAEVC source overrides.
pub fn check_member(name: &str, manifest: &Value) -> Result<(), String> {
    for section in ["dependencies", "dev-dependencies"] {
        let Some(deps) = manifest.get(section).and_then(Value::as_table) else {
            continue;
        };
        for (dep, value) in deps.iter().filter(|(d, _)| d.starts_with("openaevc")) {
            if !PACKAGES.contains(&dep.as_str()) {
                return Err(format!(
                    "{name}: {dep} does not exist in OpenAEVC v0.1.0; use `openaevc`"
                ));
            }
            let t = value.as_table();
            if t.and_then(|t| t.get("workspace")).and_then(Value::as_bool) != Some(true) {
                return Err(format!(
                    "{name}: {dep} must be `workspace = true` (one pinned source)"
                ));
            }
            if section == "dependencies" && name != RUNTIME_OWNER {
                if dep == "openaevc-sdk" {
                    return Err(format!(
                        "{name}: openaevc-sdk is reserved for {RUNTIME_OWNER}"
                    ));
                }
                if t.and_then(|t| t.get("features"))
                    .and_then(Value::as_array)
                    .is_some_and(|f| !f.is_empty())
                {
                    return Err(format!(
                        "{name}: OpenAEVC features are reserved for {RUNTIME_OWNER}"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Source text of a crate other than the runtime owner must not name the feature-gated modules.
pub fn check_source(crate_name: &str, file: &str, source: &str) -> Result<(), String> {
    if crate_name == RUNTIME_OWNER {
        return Ok(());
    }
    for m in RESTRICTED_MODULES {
        if source.contains(m) {
            return Err(format!("{file}: {m} is reserved for {RUNTIME_OWNER}"));
        }
    }
    Ok(())
}

/// `cargo tree -e features -i openaevc` output of an isolated build must not enable
/// store/runtime/transport for a crate that does not depend on the runtime owner.
pub fn check_feature_tree(crate_name: &str, tree: &str) -> Result<(), String> {
    for f in ["store", "runtime", "transport", "full"] {
        if tree.contains(&format!("openaevc feature \"{f}\"")) {
            return Err(format!(
                "{crate_name}: isolated build enables openaevc feature {f}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: &str = "v0.1.0";
    const REV: &str = "5720d3ec15bee6c49630b2cec5a21afd357dedf8";

    fn ws(extra: &str) -> toml::map::Map<String, Value> {
        let src = format!(
            r#"openaevc = {{ git = "{GIT}", tag = "v0.1.0", version = "=0.1.0", default-features = false }}
openaevc-sdk = {{ git = "{GIT}", tag = "v0.1.0", version = "=0.1.0", default-features = false }}
{extra}"#
        );
        toml::from_str(&src).unwrap()
    }

    #[test]
    fn workspace_pin_positive_and_negatives() {
        check_workspace_deps(&ws(""), TAG).unwrap();
        let mut crates_io = ws("");
        crates_io.insert(
            "openaevc".into(),
            toml::from_str::<Value>("v = { version = \"0.1.0\" }").unwrap()["v"].clone(),
        );
        assert!(
            check_workspace_deps(&crates_io, TAG)
                .unwrap_err()
                .contains("git must be"),
            "crates.io openaevc"
        );
        let branch: toml::map::Map<String, Value> = toml::from_str(&format!(
            "openaevc = {{ git = \"{GIT}\", branch = \"main\", tag = \"v0.1.0\", version = \"=0.1.0\", default-features = false }}\nopenaevc-sdk = {{ git = \"{GIT}\", tag = \"v0.1.0\", version = \"=0.1.0\", default-features = false }}"
        ))
        .unwrap();
        assert!(
            check_workspace_deps(&branch, TAG)
                .unwrap_err()
                .contains("branch"),
            "branch = main"
        );
        let ssh: toml::map::Map<String, Value> = toml::from_str(
            "openaevc = { git = \"ssh://git@github.com/calvehq/openaevc.git\", tag = \"v0.1.0\", version = \"=0.1.0\", default-features = false }",
        )
        .unwrap();
        assert!(check_workspace_deps(&ssh, TAG).is_err(), "ssh source");
        let mut wrong_tag = ws("");
        wrong_tag["openaevc"]
            .as_table_mut()
            .unwrap()
            .insert("tag".into(), "v0.2.0".into());
        assert!(check_workspace_deps(&wrong_tag, TAG).is_err(), "other tag");
        let mut defaults = ws("");
        defaults["openaevc"]
            .as_table_mut()
            .unwrap()
            .remove("default-features");
        assert!(
            check_workspace_deps(&defaults, TAG).is_err(),
            "default features on"
        );
        let old = ws(&format!(
            "openaevc-protocol = {{ git = \"{GIT}\", tag = \"v0.1.0\" }}"
        ));
        assert!(
            check_workspace_deps(&old, TAG)
                .unwrap_err()
                .contains("only"),
            "pre-split crate"
        );
    }

    fn lock(entries: &[(&str, &str)]) -> Value {
        let mut s = String::from("version = 4\n");
        for (n, src) in entries {
            s += &format!("[[package]]\nname = \"{n}\"\nversion = \"0.1.0\"\nsource = \"{src}\"\n");
        }
        toml::from_str(&s).unwrap()
    }

    #[test]
    fn lock_identity_positive_and_negatives() {
        let good = format!("git+{GIT}?tag={TAG}#{REV}");
        check_lock(
            &lock(&[("openaevc", &good), ("openaevc-sdk", &good)]),
            TAG,
            REV,
        )
        .unwrap();
        let other_rev = format!("git+{GIT}?tag={TAG}#288b804fc2b7d178de9dd2de20d13e615aed02c8");
        assert!(
            check_lock(
                &lock(&[("openaevc", &other_rev), ("openaevc-sdk", &good)]),
                TAG,
                REV
            )
            .is_err(),
            "other commit"
        );
        let reg = "registry+https://github.com/rust-lang/crates.io-index";
        assert!(
            check_lock(
                &lock(&[("openaevc", reg), ("openaevc-sdk", &good)]),
                TAG,
                REV
            )
            .is_err(),
            "crates.io in lock"
        );
        assert!(
            check_lock(
                &lock(&[
                    ("openaevc", &good),
                    ("openaevc", reg),
                    ("openaevc-sdk", &good)
                ]),
                TAG,
                REV
            )
            .is_err(),
            "two openaevc packages"
        );
        assert!(
            check_lock(&lock(&[("openaevc", &good)]), TAG, REV).is_err(),
            "sdk missing"
        );
        assert!(
            check_lock(
                &lock(&[
                    ("openaevc", &good),
                    ("openaevc-sdk", &good),
                    ("openaevc-protocol", &good)
                ]),
                TAG,
                REV
            )
            .is_err(),
            "leftover split crate"
        );
    }

    fn member(deps: &str) -> Value {
        toml::from_str(&format!("[dependencies]\n{deps}")).unwrap()
    }

    #[test]
    fn member_feature_and_sdk_ownership() {
        check_member("calve-app", &member("openaevc = { workspace = true, features = [\"runtime\"] }\nopenaevc-sdk.workspace = true")).unwrap();
        check_member("calve-api", &member("openaevc.workspace = true")).unwrap();
        assert!(
            check_member(
                "calve-api",
                &member("openaevc = { workspace = true, features = [\"store\"] }")
            )
            .is_err(),
            "features outside calve-app"
        );
        assert!(
            check_member("calve-console", &member("openaevc-sdk.workspace = true")).is_err(),
            "sdk outside calve-app"
        );
        assert!(
            check_member("calve-api", &member("openaevc = { git = \"x\" }")).is_err(),
            "member-level source"
        );
        assert!(
            check_member("calve-api", &member("openaevc-protocol.workspace = true")).is_err(),
            "pre-split crate"
        );
        let dev: Value =
            toml::from_str("[dev-dependencies]\nopenaevc-sdk.workspace = true").unwrap();
        check_member("calve", &dev).unwrap();
    }

    #[test]
    fn restricted_modules_and_feature_tree() {
        check_source("calve-app", "lib.rs", "use openaevc::runtime::Runtime;").unwrap();
        check_source("calve-api", "lib.rs", "use openaevc::protocol::Digest;").unwrap();
        assert!(check_source("calve-api", "lib.rs", "use openaevc::store::SqliteStore;").is_err());
        assert!(check_source("calve-console", "x.rs", "openaevc::runtime::handlers").is_err());
        check_feature_tree(
            "calve-api",
            "openaevc v0.1.0\nopenaevc feature \"default\"\n",
        )
        .unwrap();
        assert!(check_feature_tree("calve-api", "openaevc feature \"runtime\"\n").is_err());
    }
}
