//! Helpers shared by Calve's integration tests: isolated data directories and a CLI runner.
#![forbid(unsafe_code)]

pub mod cic;
pub mod mini_host;
pub mod tuf;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// A temporary machine: private data/config homes plus a scratch area for Projects.
pub struct Env {
    pub temp: tempfile::TempDir,
    pub calve: PathBuf,
    /// The signed fixture catalog trusted by [`Env::trust_fixture`].
    pub catalog: Option<tuf::Repo>,
    /// Extra environment for every `calve` run (e.g. a test `PATH`).
    pub vars: Vec<(String, std::ffi::OsString)>,
}

pub struct Run {
    pub success: bool,
    pub value: Value,
    pub stderr: String,
}

impl Env {
    /// `calve` is the binary under test, normally `env!("CARGO_BIN_EXE_calve")`.
    pub fn new(calve: &str) -> Self {
        Self {
            temp: tempfile::tempdir().expect("temp dir"),
            calve: PathBuf::from(calve),
            catalog: None,
            vars: vec![],
        }
    }

    /// Publishes the fixture catalog (package `org.example.toy`: `calve-fixture-ext` + the
    /// fixture CIC guest + its signed metadata, listed in `index.json`) and trusts it as `test`
    /// through the real CLI (root pinned by SHA-256).
    pub fn trust_fixture(&mut self) -> Value {
        let cat = ToyCatalog::new();
        let out = self.ok(&cat
            .add_args()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>());
        self.catalog = Some(cat.repo);
        out
    }

    /// Trusts the fixture catalog (once) and enables `org.example.toy` in `project`.
    pub fn enable_toy(&mut self, project: &Path) -> Value {
        if self.catalog.is_none() {
            self.trust_fixture();
        }
        self.ok(&[
            "--project",
            project.to_str().expect("utf-8"),
            "extension",
            "enable",
            "org.example.toy",
            "--acknowledge-native",
        ])
    }

    pub fn path(&self) -> &Path {
        self.temp.path()
    }

    /// Runs `calve --json --no-daemon-start <args>` without asserting success.
    pub fn run(&self, args: &[&str]) -> Run {
        let output = Command::new(&self.calve)
            .env("XDG_DATA_HOME", self.path().join("d"))
            .env("XDG_CONFIG_HOME", self.path().join("c"))
            .envs(self.vars.iter().map(|(k, v)| (k, v)))
            .args(["--json", "--no-daemon-start"])
            .args(args)
            .output()
            .expect("run calve");
        Run {
            success: output.status.success(),
            value: serde_json::from_slice(&output.stdout).unwrap_or(Value::Null),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// Runs and asserts success, returning the JSON output.
    pub fn ok(&self, args: &[&str]) -> Value {
        let run = self.run(args);
        assert!(run.success, "{args:?}: {}", run.stderr);
        run.value
    }

    /// Runs and asserts failure, returning stderr.
    pub fn fails(&self, args: &[&str]) -> String {
        let run = self.run(args);
        assert!(
            !run.success,
            "{args:?} unexpectedly succeeded: {}",
            run.value
        );
        run.stderr
    }
}

pub fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir(to).expect("create copy root");
    for item in fs::read_dir(from).expect("read source") {
        let item = item.expect("dir entry");
        let target = to.join(item.file_name());
        if item.file_type().expect("file type").is_dir() {
            copy_tree(&item.path(), &target);
        } else {
            fs::copy(item.path(), &target).expect("copy file");
        }
    }
}

/// Path of the fixture native extension (`calve-fixture-ext`), built on first use with the
/// test's own profile. `CALVE_FIXTURE_EXT` overrides it (cross-compiled runs on another OS).
pub fn fixture_ext() -> PathBuf {
    if let Some(p) = std::env::var_os("CALVE_FIXTURE_EXT") {
        return PathBuf::from(p);
    }
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let release = !cfg!(debug_assertions);
            let mut cmd = Command::new(env!("CARGO"));
            cmd.current_dir(&root).args([
                "build",
                "--quiet",
                "-p",
                "calve-testkit",
                "--bin",
                "calve-fixture-ext",
            ]);
            if release {
                cmd.arg("--release");
            }
            assert!(
                cmd.status().expect("cargo").success(),
                "building calve-fixture-ext"
            );
            let target = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("target"));
            target
                .join(if release { "release" } else { "debug" })
                .join(format!("calve-fixture-ext{}", std::env::consts::EXE_SUFFIX))
        })
        .clone()
}

/// The fixture package: native fixture, fixture guest, fixture metadata.
pub fn fixture_package() -> tuf::Package<'static> {
    tuf::Package {
        id: "org.example.toy",
        version: "0.1.0",
        kind: "cic-capable",
        native: (
            "calve-fixture-ext",
            fs::read(fixture_ext()).expect("fixture ext"),
        ),
        cic: Some(cic::guest("fixture")),
        metadata: Some(
            fs::read(cic::fixtures().join("fixture-metadata.json")).expect("fixture metadata"),
        ),
    }
}

/// A published fixture catalog for tests with their own CLI runner: run [`ToyCatalog::add_args`]
/// once, then enable with [`ENABLE_TOY`] (`--project <p>` first).
pub struct ToyCatalog {
    pub repo: tuf::Repo,
    root_file: PathBuf,
    digest: String,
}

/// `extension enable org.example.toy --acknowledge-native`.
pub const ENABLE_TOY: [&str; 4] = [
    "extension",
    "enable",
    "org.example.toy",
    "--acknowledge-native",
];

impl Default for ToyCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl ToyCatalog {
    pub fn new() -> Self {
        let mut r = tuf::Repo::new();
        r.add_package("targets", fixture_package());
        r.targets.insert(
            "index.json".into(),
            br#"{"schema":"calve.index/1","ids":["org.example.toy"]}"#.to_vec(),
        );
        r.publish();
        let root = r.root_bytes(1);
        let root_file = r.path().join("pinned-root.json");
        fs::write(&root_file, &root).expect("root");
        ToyCatalog {
            digest: tuf::sha(&root),
            root_file,
            repo: r,
        }
    }

    /// `extension catalog add test <dir> --root <file> --root-digest <sha256>`.
    pub fn add_args(&self) -> Vec<String> {
        [
            "extension",
            "catalog",
            "add",
            "test",
            self.repo.path().to_str().expect("utf-8"),
            "--root",
            self.root_file.to_str().expect("utf-8"),
            "--root-digest",
            &self.digest,
        ]
        .map(String::from)
        .to_vec()
    }
}
