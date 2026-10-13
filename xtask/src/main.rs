//! Repository checks that should remain independent of Calve's runtime modules.
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

const OPENAEVC_GIT: &str = "ssh://git@github.com/calvehq/openaevc.git";

const USAGE: &str = "usage: cargo run --bin xtask -- check-architecture
       cargo run --bin xtask -- catalog-keygen <seed-file>
       cargo run --bin xtask -- catalog-publish <catalog-dir> <seed-file>... [--threshold N] [--days D]
         (signs <catalog-dir>/targets.body.json into targets/snapshot/timestamp, creating root.json)
       cargo run --bin xtask -- catalog-rotate <catalog-dir> --old <seed-file>... --new <seed-file>... [--threshold N]
       cargo run --bin xtask -- cli-reference [--check]
       cargo run --bin xtask -- dist [--target <triple>] [--catalog-seed <seed-file>]
       cargo run --bin xtask -- sbom <output.json>";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("check-architecture") if args.len() == 1 => {
            check().map(|()| println!("architecture check passed"))
        }
        Some("catalog-keygen") if args.len() == 2 => keygen(Path::new(&args[1])),
        Some("catalog-publish") if args.len() >= 3 => publish(&args[1..]),
        Some("catalog-rotate") if args.len() >= 5 => rotate(&args[1..]),
        Some("dist") => dist(&args[1..]),
        Some("sbom") if args.len() == 2 => sbom(Path::new(&args[1])),
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
    let mut seed: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--target" => target = iter.next().cloned(),
            "--catalog-seed" => seed = iter.next().cloned(),
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

    // First-party extensions ship separately with a signed catalog snapshot (§51.3).
    let staging = dist.join(format!(".catalog-{triple}"));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;
    let mut packages = Vec::new();
    for entry in fs::read_dir(&bin_dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_binary = if exe.is_empty() {
            !name.contains('.')
        } else {
            name.ends_with(".exe")
        };
        if !name.starts_with("calve_ext_") || !is_binary {
            continue;
        }
        let bytes = fs::read(entry.path())?;
        fs::write(staging.join(&name), &bytes)?;
        let key = name
            .trim_end_matches(".exe")
            .trim_start_matches("calve_ext_")
            .replace('_', "-");
        packages.push(serde_json::json!({
            "id": format!("org.calve.{key}"),
            "version": version,
            "artifact": name,
            "digest": openaevc_crypto::sha256(&bytes),
            "summary": format!("First-party {key} extension"),
        }));
    }
    packages.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    fs::write(
        staging.join("targets.body.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "name": "first-party", "version": 0, "expires": 0, "packages": packages,
        }))?,
    )?;
    if let Some(seed) = seed {
        let seed = read_seed(Path::new(&seed))?;
        let result = calve_app::extensions::publish_catalog(&staging, &[seed], 1, 365)?;
        println!(
            "first-party catalog root digest: {}",
            result["root_digest"].as_str().unwrap_or("")
        );
    }
    let catalog_files: Vec<(PathBuf, String)> = fs::read_dir(&staging)?
        .flatten()
        .map(|e| (e.path(), e.file_name().to_string_lossy().into_owned()))
        .collect();
    outputs.push(archive(
        &dist,
        &format!("calve-extensions-{version}-{triple}"),
        &catalog_files,
        &epoch,
    )?);
    fs::remove_dir_all(&staging)?;

    let sbom_path = dist.join(format!("calve-{version}.cdx.json"));
    sbom(&sbom_path)?;
    outputs.push(sbom_path);
    let mut sums = String::new();
    for output in &outputs {
        let digest = openaevc_crypto::sha256(&fs::read(output)?).to_string();
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

/// Writes a new private seed (hex, mode 0600) and prints the public key to pin with
/// `calve extension catalog-trust --key`.
fn keygen(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let key = openaevc_crypto::SigningKey::generate();
    let seed: String = key
        .seed()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(seed.as_bytes())?;
    let public = calve_app::extensions::public_key(&read_seed(path)?);
    println!("{public}");
    Ok(())
}

fn read_seed(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let text = text.trim();
    if text.len() != 64 {
        return Err(format!("{} must hold a 32-byte hex seed", path.display()).into());
    }
    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
    }
    Ok(seed)
}

/// Splits `[dir, seeds..., --threshold N, --days D]`.
fn options(args: &[String]) -> (Vec<String>, usize, u64) {
    let mut positional = Vec::new();
    let (mut threshold, mut days) = (0usize, 365u64);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--threshold" => threshold = iter.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--days" => days = iter.next().and_then(|v| v.parse().ok()).unwrap_or(365),
            other => positional.push(other.to_owned()),
        }
    }
    (positional, threshold, days)
}

fn publish(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (positional, threshold, days) = options(args);
    let seeds = positional[1..]
        .iter()
        .map(|p| read_seed(Path::new(p)))
        .collect::<Result<Vec<_>, _>>()?;
    let threshold = if threshold == 0 {
        seeds.len()
    } else {
        threshold
    };
    let result =
        calve_app::extensions::publish_catalog(Path::new(&positional[0]), &seeds, threshold, days)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn rotate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (positional, threshold, days) = options(args);
    let dir = Path::new(&positional[0]);
    let split = positional
        .iter()
        .position(|a| a == "--new")
        .ok_or("missing --new")?;
    let old = positional[1..split]
        .iter()
        .filter(|a| *a != "--old")
        .map(|p| read_seed(Path::new(p)))
        .collect::<Result<Vec<_>, _>>()?;
    let new = positional[split + 1..]
        .iter()
        .map(|p| read_seed(Path::new(p)))
        .collect::<Result<Vec<_>, _>>()?;
    let threshold = if threshold == 0 { new.len() } else { threshold };
    let result = calve_app::extensions::rotate_root(dir, &old, &new, threshold, days)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Allowed internal dependency edges (PLAN §10). Anything else fails CI.
const ALLOWED: &[(&str, &[&str])] = &[
    ("calve-domain", &[]),
    ("calve-api", &[]),
    ("calve-ipc", &["calve-api"]),
    ("calve-app", &["calve-api", "calve-domain"]),
    ("calve-client", &["calve-api", "calve-app", "calve-ipc"]),
    // The console reads read models through the client only (PLAN §10).
    ("calve-console", &["calve-api", "calve-client"]),
    ("calve-testkit", &[]),
    (
        "calve",
        &[
            "calve-api",
            "calve-app",
            "calve-client",
            "calve-console",
            "calve-domain",
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
    ("openaevc-runtime", &["calve-app"]),
    ("openaevc-store", &["calve-app"]),
];

fn check() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask has no workspace parent")?
        .to_path_buf();
    let manifest: toml::Value = fs::read_to_string(root.join("Cargo.toml"))?.parse()?;
    let dependencies = manifest["workspace"]["dependencies"]
        .as_table()
        .ok_or("workspace has no dependencies table")?;
    let mut public_dependencies = 0;
    for (name, value) in dependencies {
        if !name.starts_with("openaevc-") {
            continue;
        }
        let table = value
            .as_table()
            .ok_or("OpenAEVC dependency must be a table")?;
        // `branch` is allowed only while no release tag exists; Cargo.lock (built --locked) pins it.
        if table.get("path").is_some()
            || table.get("git").and_then(toml::Value::as_str) != Some(OPENAEVC_GIT)
            || !["rev", "tag", "branch"]
                .iter()
                .any(|key| table.contains_key(*key))
        {
            return Err(format!("{name} must use a pinned public OpenAEVC source").into());
        }
        public_dependencies += 1;
    }
    if public_dependencies == 0 {
        return Err("no OpenAEVC dependencies declared".into());
    }
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
                if let Some(table) = deps[dep].as_table()
                    && table.get("path").is_some()
                    && dep.starts_with("openaevc-")
                {
                    return Err(format!("{name} uses a path dependency on {dep}").into());
                }
            }
        }
        // xtask lists the forbidden strings itself.
        if name != "xtask" {
            scan_sources(&root.join(&member).join("src"))?;
        }
    }
    check_extensions(&root.join("extensions"))?;
    scan_sources(&root.join("apps/calved"))?;
    Ok(())
}

/// Extension sources may use only calve-domain and OpenAEVC contract crates.
fn check_extensions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            check_extensions(&path)?;
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        for token in source.split(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == ':')) {
            let Some(krate) = token.split("::").next().filter(|_| token.contains("::")) else {
                continue;
            };
            let allowed = matches!(
                krate,
                "calve_domain"
                    | "openaevc_protocol"
                    | "openaevc_extension_contract"
                    | "openaevc_crypto"
                    | "serde_json"
                    | "std"
                    | "crate"
                    | "self"
                    | "super"
                    | "core"
            ) || krate.chars().next().is_some_and(char::is_uppercase)
                || !krate.starts_with("calve") && !krate.starts_with("openaevc");
            if !allowed {
                return Err(format!(
                    "{} uses {krate}; extensions may not link Calve internals",
                    path.display()
                )
                .into());
            }
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
            "openaevc_runtime::handlers",
            "openaevc_store::sqlite::",
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
