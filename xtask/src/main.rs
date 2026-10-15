//! Repository checks that should remain independent of Calve's runtime modules.
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

mod json_schemas;
mod openaevc_rules;

use calve_app::compatibility::{OPENAEVC_REVISION, OPENAEVC_TAG};

const USAGE: &str = "usage: cargo run --bin xtask -- check-architecture
       cargo run --bin xtask -- check-isolation
       cargo run --bin xtask -- cli-reference [--check]
       cargo run --bin xtask -- json-schemas [--write]
       cargo run --bin xtask -- dist [--target <triple>]
       cargo run --bin xtask -- sbom <output.json>";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("check-architecture") if args.len() == 1 => {
            check().map(|()| println!("architecture check passed"))
        }
        Some("check-isolation") if args.len() == 1 => check_isolation(),
        Some("dist") => dist(&args[1..]),
        Some("sbom") if args.len() == 2 => sbom(Path::new(&args[1])),
        Some("json-schemas") if args.len() <= 2 => json_schemas::run(
            &workspace_root(),
            args.get(1).map(String::as_str) == Some("--write"),
        ),
        Some("cli-reference") if args.len() <= 2 => {
            cli_reference(args.get(1).map(String::as_str) == Some("--check"))
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(error) = result {
        eprintln!("xtask failed: {error}");
        std::process::exit(1);
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn run(command: &mut std::process::Command) -> Result<(), Box<dyn std::error::Error>> {
    let status = command.status()?;
    if !status.success() {
        return Err(format!("{command:?} failed with {status}").into());
    }
    Ok(())
}

/// CycloneDX 1.5 SBOM of every locked dependency, derived from Cargo.lock.
fn sbom(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let lock: toml::Value = fs::read_to_string(workspace_root().join("Cargo.lock"))?.parse()?;
    let components: Vec<serde_json::Value> = lock["package"]
        .as_array()
        .ok_or("Cargo.lock has no packages")?
        .iter()
        .map(|package| {
            let name = package["name"].as_str().unwrap_or_default();
            let version = package["version"].as_str().unwrap_or_default();
            let field = |key: &str, default: &str| {
                package
                    .get(key)
                    .and_then(|v| v.as_str())
                    .unwrap_or(default)
                    .to_owned()
            };
            serde_json::json!({
                "type": "library",
                "name": name,
                "version": version,
                "purl": format!("pkg:cargo/{name}@{version}"),
                "properties": [
                    {"name": "cargo:source", "value": field("source", "workspace")},
                    {"name": "cargo:checksum", "value": field("checksum", "")},
                ],
            })
        })
        .collect();
    let count = components.len();
    let document = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "calve", "version": env!("CARGO_PKG_VERSION")}},
        "components": components,
    });
    fs::write(output, serde_json::to_vec_pretty(&document)?)?;
    println!("wrote {count} components to {}", output.display());
    Ok(())
}

/// Packs `files` under a top-level `name/` directory into a reproducible `.tar.gz`: sorted
/// entries, fixed mtime, numeric owner, and gzip without a timestamp.
fn archive(
    dist: &Path,
    name: &str,
    files: &[(PathBuf, String)],
    epoch: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = dist.join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    for (source, file) in files {
        fs::copy(source, dir.join(file))?;
    }
    let tar = std::process::Command::new("tar")
        .current_dir(dist)
        .args([
            "--sort=name",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            &format!("--mtime=@{epoch}"),
            "-cf",
            "-",
            name,
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let gzip = std::process::Command::new("gzip")
        .args(["-n", "-9"])
        .stdin(tar.stdout.ok_or("tar produced no output")?)
        .output()?;
    if !gzip.status.success() {
        return Err("gzip failed".into());
    }
    let path = dist.join(format!("{name}.tar.gz"));
    fs::write(&path, gzip.stdout)?;
    fs::remove_dir_all(&dir)?;
    Ok(path)
}

/// Builds release archives (core and extensions separately), a signed first-party catalog
/// snapshot when a seed is given, the SBOM and SHA256SUMS (PLAN §51).
fn dist(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut target: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--target" => target = iter.next().cloned(),
            other => return Err(format!("unknown dist argument {other}").into()),
        }
    }
    let root = workspace_root();
    let version = env!("CARGO_PKG_VERSION");
    let host = || {
        std::process::Command::new("rustc")
            .arg("-vV")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|text| {
                text.lines()
                    .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
            })
            .unwrap_or_else(|| "unknown".into())
    };
    let triple = target.clone().unwrap_or_else(host);
    let mut build = std::process::Command::new("cargo");
    build
        .current_dir(&root)
        .args(["build", "--release", "--locked", "-p", "calve"]);
    if let Some(target) = &target {
        build.args(["--target", target]);
    }
    run(&mut build)?;
    let bin_dir = match &target {
        Some(target) => root.join("target").join(target).join("release"),
        None => root.join("target/release"),
    };
    let exe = if triple.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let dist = root.join("dist");
    fs::create_dir_all(&dist)?;
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .or_else(|| {
            std::process::Command::new("git")
                .current_dir(&root)
                .args(["log", "-1", "--format=%ct"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "0".into());
    let docs = ["LICENSE", "NOTICE", "README.md"].map(|f| (root.join(f), f.to_owned()));
    let mut core: Vec<(PathBuf, String)> = ["calve", "calved"]
        .iter()
        .map(|b| (bin_dir.join(format!("{b}{exe}")), format!("{b}{exe}")))
        .collect();
    core.extend(docs.iter().cloned());
    let mut outputs = vec![archive(
        &dist,
        &format!("calve-{version}-{triple}"),
        &core,
        &epoch,
    )?];

    // Extensions ship from calve-extensions through the signed TUF catalog (plan §4); the core
    // archive carries no extension binaries.

    let sbom_path = dist.join(format!("calve-{version}.cdx.json"));
    sbom(&sbom_path)?;
    outputs.push(sbom_path);
    let mut sums = String::new();
    for output in &outputs {
        let digest = openaevc::crypto::sha256(&fs::read(output)?).to_string();
        let name = output.file_name().and_then(|n| n.to_str()).unwrap_or("");
        sums.push_str(&format!(
            "{}  {name}\n",
            digest.trim_start_matches("sha256:")
        ));
    }
    fs::write(dist.join(format!("SHA256SUMS-{triple}")), sums)?;
    for output in outputs {
        println!("{}", output.display());
    }
    Ok(())
}

/// Renders docs/reference/cli.md from the clap command tree so the reference never drifts.
fn cli_reference(check: bool) -> Result<(), Box<dyn std::error::Error>> {
    use clap::CommandFactory;
    #[derive(clap::Parser)]
    #[command(
        name = "calve",
        about = "See the whole change. Decide what becomes real."
    )]
    struct Cli {
        #[command(subcommand)]
        action: calve_api::Action,
    }
    fn walk(command: &clap::Command, path: &str, out: &mut String) {
        for sub in command.get_subcommands().filter(|s| !s.is_hide_set()) {
            let full = format!("{path} {}", sub.get_name());
            let args: Vec<String> = sub
                .get_arguments()
                .filter(|a| !a.is_hide_set() && a.get_id() != "help")
                .map(|a| {
                    let name = match a.get_long() {
                        Some(long) => format!("--{long}"),
                        None => format!("<{}>", a.get_id()),
                    };
                    let takes = a.get_long().is_some() && a.get_action().takes_values();
                    let shown = if takes {
                        format!("{name} <{}>", a.get_id())
                    } else {
                        name
                    };
                    if a.is_required_set() {
                        shown
                    } else {
                        format!("[{shown}]")
                    }
                })
                .collect();
            if sub.get_subcommands().next().is_none() {
                out.push_str(&format!(
                    "| `{}` | {} |\n",
                    format!("{full} {}", args.join(" ")).trim(),
                    sub.get_about().map(|a| a.to_string()).unwrap_or_default()
                ));
            }
            walk(sub, &full, out);
        }
    }
    let root = Cli::command();
    let mut body = String::from(
        "# CLI reference\n\nGenerated by `cargo run -p xtask -- cli-reference`; do not edit by hand.\n\nGlobal flags: `--project <path-or-id>`, `--workspace <name>`, `--as <identity>`, `--config <path>`, `--json`, `--quiet`, `--verbose`, `--no-color`, `--no-daemon-start`, `--direct`, `--endpoint <socket>`.\n",
    );
    for top in root
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
    {
        body.push_str(&format!(
            "\n## `calve {}`\n\n| Command | Description |\n|---|---|\n",
            top.get_name()
        ));
        if top.get_subcommands().next().is_none() {
            walk(
                &clap::Command::new("").subcommand(top.clone()),
                "calve",
                &mut body,
            );
        } else {
            walk(top, &format!("calve {}", top.get_name()), &mut body);
        }
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/reference/cli.md");
    if check {
        if fs::read_to_string(&path).ok().as_deref() != Some(body.as_str()) {
            return Err(
                "docs/reference/cli.md is out of date; run `cargo run -p xtask -- cli-reference`"
                    .into(),
            );
        }
        println!("cli reference is current");
    } else {
        fs::write(&path, body)?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

/// Allowed internal dependency edges (PLAN §10). Anything else fails CI.
const ALLOWED: &[(&str, &[&str])] = &[
    ("calve-integration-contract", &[]),
    ("calve-api", &[]),
    ("calve-ipc", &["calve-api"]),
    (
        "calve-app",
        &[
            "calve-api",
            "calve-integration-contract",
            "calve-testkit",
            "calve-win-sec",
        ],
    ),
    ("calve-client", &["calve-api", "calve-app", "calve-ipc"]),
    // The console reads read models through the client only (PLAN §10).
    ("calve-console", &["calve-api", "calve-client"]),
    ("calve-testkit", &["calve-integration-contract"]),
    // The single crate allowed `unsafe` (cfg(windows) FFI only).
    ("calve-win-sec", &[]),
    (
        "calve",
        &[
            "calve-api",
            "calve-app",
            "calve-client",
            "calve-console",
            "calve-integration-contract",
            "calve-ipc",
            "calve-testkit",
        ],
    ),
    ("xtask", &["calve-api", "calve-app"]),
];

/// Terminal crates belong to the console alone; product-store SQL stays in calve-app.
const RESTRICTED: &[(&str, &[&str])] = &[
    ("ratatui", &["calve-console"]),
    ("crossterm", &["calve-console"]),
    ("rusqlite", &["calve-app", "calve"]),
];

/// The contract crate's whole dependency set (plan §4): no `calve-*`, tokio or rusqlite.
const CONTRACT_DEPENDENCIES: &[&str] = &["serde", "serde_json", "sha2", "openaevc"];

fn check() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask has no workspace parent")?
        .to_path_buf();
    let manifest: toml::Value = fs::read_to_string(root.join("Cargo.toml"))?.parse()?;
    let dependencies = manifest["workspace"]["dependencies"]
        .as_table()
        .ok_or("workspace has no dependencies table")?;
    openaevc_rules::check_workspace_deps(dependencies, OPENAEVC_TAG)?;
    let lock: toml::Value = fs::read_to_string(root.join("Cargo.lock"))?.parse()?;
    openaevc_rules::check_lock(&lock, OPENAEVC_TAG, OPENAEVC_REVISION)?;
    for member in ["apps/calve", "xtask"]
        .into_iter()
        .map(PathBuf::from)
        .chain(
            fs::read_dir(root.join("crates"))?
                .map(|e| e.map(|e| PathBuf::from("crates").join(e.file_name())))
                .collect::<Result<Vec<_>, _>>()?,
        )
    {
        let package: toml::Value =
            fs::read_to_string(root.join(&member).join("Cargo.toml"))?.parse()?;
        let name = package["package"]["name"]
            .as_str()
            .ok_or("package without name")?;
        openaevc_rules::check_member(name, &package)?;
        // Plan §4.1: `unsafe` is forbidden everywhere (workspace lints) except calve-win-sec.
        let inherits = package
            .get("lints")
            .and_then(|l| l.get("workspace"))
            .and_then(toml::Value::as_bool)
            == Some(true);
        if name != "calve-win-sec" && !inherits {
            return Err(
                format!("{name} must use the workspace lints (unsafe_code = forbid)").into(),
            );
        }
        if name == "calve-integration-contract"
            && let Some(deps) = package.get("dependencies").and_then(toml::Value::as_table)
            && let Some(dep) = deps
                .keys()
                .find(|d| !CONTRACT_DEPENDENCIES.contains(&d.as_str()))
        {
            return Err(format!(
                "{name} may not depend on {dep} (allowed: {CONTRACT_DEPENDENCIES:?})"
            )
            .into());
        }
        let allowed = ALLOWED
            .iter()
            .find(|(crate_name, _)| *crate_name == name)
            .ok_or_else(|| format!("{name} is not listed in the architecture DAG"))?
            .1;
        for section in ["dependencies", "dev-dependencies"] {
            let Some(deps) = package.get(section).and_then(toml::Value::as_table) else {
                continue;
            };
            for dep in deps.keys() {
                if dep.starts_with("calve-") && !allowed.contains(&dep.as_str()) {
                    return Err(format!("{name} may not depend on {dep}").into());
                }
                if section == "dependencies"
                    && let Some((_, owners)) =
                        RESTRICTED.iter().find(|(crate_name, _)| crate_name == dep)
                    && !owners.contains(&name)
                {
                    return Err(format!("{name} may not depend on {dep}").into());
                }
            }
        }
        // ADR 0007: the TUF library is replaceable — only the adapter and the trust-state
        // module may name it.
        scan_verifier_use(&root.join(&member).join("src"))?;
        // xtask lists the forbidden strings itself.
        if name != "xtask" {
            scan_sources(&root.join(&member).join("src"))?;
            scan_openaevc_modules(name, &root.join(&member).join("src"))?;
        }
    }
    for dir in ["crates", "apps"] {
        scan_domain_literals(&root.join(dir))?;
    }
    scan_sources(&root.join("apps/calved"))?;
    Ok(())
}

/// First-party domain identifiers: their semantics live in calve-extensions (INV-022), so
/// calve-cli sources name none of them (testkit fixtures use `org.example.*`).
const DOMAIN_LITERALS: &[&str] = &[
    "calve_domain",
    "org.calve.software",
    "org.calve.general",
    "org.calve.rust",
    "org.calve.go",
    "org.calve.python",
    "org.calve.javascript-typescript",
    "org.calve.java",
    "org.calve.c-cpp",
    "org.calve.shell",
    "org.calve.hcl",
];

/// Plan §4.1: no `calve_domain` and no first-party domain literal in any calve-cli source
/// (`src/` and `tests/` alike; guests and evidence excluded).
fn scan_domain_literals(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if name != "target" && name != "guests" && name != "fixtures" {
                scan_domain_literals(&path)?;
            }
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        if let Some(lit) = DOMAIN_LITERALS.iter().find(|l| text.contains(*l)) {
            return Err(format!(
                "{} names {lit}; domain semantics live in calve-extensions (INV-022)",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

const VERIFIER_OWNERS: &[&str] = &[
    "crates/calve-app/src/catalog/tuf.rs",
    "crates/calve-app/src/catalog/state.rs",
];

fn scan_verifier_use(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            scan_verifier_use(&path)?;
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let rel = path.to_string_lossy().replace('\\', "/");
        let owned = VERIFIER_OWNERS.iter().any(|o| rel.ends_with(o));
        let text = fs::read_to_string(&path)?;
        let named = text.contains("sigstore_tuf") && !path.ends_with("main.rs");
        if named && !owned {
            return Err(format!(
                "{} names sigstore_tuf; only {VERIFIER_OWNERS:?} may (ADR 0007)",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn scan_sources(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            scan_sources(&path)?;
            continue;
        }
        if path.file_name().and_then(|s| s.to_str()) == Some("xtask.rs")
            || path.extension().and_then(|s| s.to_str()) != Some("rs")
        {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        for forbidden in [
            "openaevc::runtime::handlers",
            "openaevc::store::sqlite::",
            "FROM changepacks",
            "INTO changepacks",
            "UPDATE changepacks",
            "FROM executions",
            "INTO executions",
            "UPDATE executions",
            "FROM baselines",
            "INTO baselines",
            "UPDATE baselines",
        ] {
            if source.contains(forbidden) {
                return Err(
                    format!("{} contains forbidden access: {forbidden}", path.display()).into(),
                );
            }
        }
    }
    Ok(())
}

/// `openaevc::{store,runtime,transport}` may be named only by the runtime owner.
fn scan_openaevc_modules(name: &str, dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            scan_openaevc_modules(name, &path)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            openaevc_rules::check_source(
                name,
                &path.display().to_string(),
                &fs::read_to_string(&path)?,
            )?;
        }
    }
    Ok(())
}

/// True when `name` reaches the runtime owner through the internal dependency DAG.
fn reaches_runtime_owner(name: &str) -> bool {
    name == openaevc_rules::RUNTIME_OWNER
        || ALLOWED
            .iter()
            .find(|(n, _)| *n == name)
            .is_some_and(|(_, deps)| deps.iter().any(|d| reaches_runtime_owner(d)))
}

/// Plan §5.2 gate 4: every crate that does not reach the runtime owner is built alone in a
/// generated scratch package (path dependency, the workspace lock's versions, offline); its
/// `openaevc` feature tree must not enable store/runtime/transport, and OpenAEVC must still
/// resolve to the pinned tag. The contract crate's closure must exclude calve-*/tokio/rusqlite.
fn check_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root();
    let main_lock = fs::read_to_string(root.join("Cargo.lock"))?;
    let scratch = std::env::temp_dir().join(format!("calve-isolation-{}", std::process::id()));
    let mut members: Vec<(String, PathBuf)> = vec![];
    for dir in fs::read_dir(root.join("crates"))? {
        let dir = dir?.path();
        let package: toml::Value = fs::read_to_string(dir.join("Cargo.toml"))?.parse()?;
        let name = package["package"]["name"]
            .as_str()
            .ok_or("package without name")?
            .to_owned();
        if !reaches_runtime_owner(&name) {
            members.push((name, dir));
        }
    }
    members.sort();
    let want = format!(
        "git+{}?tag={OPENAEVC_TAG}#{OPENAEVC_REVISION}",
        openaevc_rules::GIT
    );
    for (name, dir) in members {
        let ws = scratch.join(&name);
        fs::create_dir_all(ws.join("src"))?;
        fs::write(ws.join("src/lib.rs"), "")?;
        fs::write(
            ws.join("Cargo.toml"),
            format!(
                "[package]\nname = \"isolation-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[dependencies]\n{name} = {{ path = {:?} }}\n\n[workspace]\n",
                dir.display().to_string()
            ),
        )?;
        fs::write(ws.join("Cargo.lock"), &main_lock)?;
        let manifest = ws.join("Cargo.toml");
        run(std::process::Command::new("cargo")
            .args(["check", "--quiet", "--offline", "--manifest-path"])
            .arg(&manifest))?;
        let lock: toml::Value = fs::read_to_string(ws.join("Cargo.lock"))?.parse()?;
        let source = lock["package"]
            .as_array()
            .and_then(|p| p.iter().find(|p| p["name"].as_str() == Some("openaevc")))
            .and_then(|p| p["source"].as_str().map(str::to_owned));
        let tree = |edges: &str, invert: bool| -> Result<String, Box<dyn std::error::Error>> {
            let mut c = std::process::Command::new("cargo");
            c.args([
                "tree",
                "--offline",
                "-e",
                edges,
                "--prefix",
                "none",
                "--manifest-path",
            ])
            .arg(&manifest);
            if invert {
                c.args(["-i", "openaevc"]);
            }
            let out = c.output()?;
            if !out.status.success() {
                return Err(format!(
                    "{name}: cargo tree failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                )
                .into());
            }
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        };
        let features = match &source {
            Some(s) if *s != want => {
                return Err(format!("{name}: isolated build resolved OpenAEVC from {s}").into());
            }
            Some(_) => {
                let t = tree("features", true)?;
                openaevc_rules::check_feature_tree(&name, &t)?;
                "default only"
            }
            None => "not used",
        };
        if name == "calve-integration-contract"
            && let Some(bad) = tree("normal", false)?.lines().find(|l| {
                l.starts_with("tokio ")
                    || l.starts_with("rusqlite ")
                    || (l.starts_with("calve-") && !l.starts_with("calve-integration-contract "))
            })
        {
            return Err(format!("{name}: forbidden dependency in its closure: {bad}").into());
        }
        println!("isolated: {name:28} openaevc: {features}");
    }
    let _ = fs::remove_dir_all(&scratch);
    println!("isolation check passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Negative fixture for the ADR 0007 rule: naming the verifier outside the adapter fails.
    #[test]
    fn verifier_named_outside_the_adapter_is_rejected() {
        let d = tempfile::tempdir().unwrap();
        let ok = d.path().join("crates/calve-app/src/catalog");
        fs::create_dir_all(&ok).unwrap();
        fs::write(ok.join("tuf.rs"), "use sigstore_tuf::Updater;").unwrap();
        assert!(scan_verifier_use(d.path()).is_ok());
        fs::write(ok.join("install.rs"), "use sigstore_tuf::TargetFile;").unwrap();
        assert!(scan_verifier_use(d.path()).is_err());
    }

    /// Negative fixture for INV-022: a domain literal anywhere in a calve-cli source fails.
    #[test]
    fn domain_literals_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("src")).unwrap();
        fs::write(
            d.path().join("src/ok.rs"),
            "const X: &str = \"org.example.toy\";",
        )
        .unwrap();
        assert!(scan_domain_literals(d.path()).is_ok());
        fs::write(
            d.path().join("src/bad.rs"),
            "const X: &str = \"org.calve.software.file\";",
        )
        .unwrap();
        assert!(scan_domain_literals(d.path()).is_err());
    }
}
