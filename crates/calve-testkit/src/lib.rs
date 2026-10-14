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
        }
    }

    pub fn path(&self) -> &Path {
        self.temp.path()
    }

    /// Runs `calve --json --no-daemon-start <args>` without asserting success.
    pub fn run(&self, args: &[&str]) -> Run {
        let output = Command::new(&self.calve)
            .env("XDG_DATA_HOME", self.path().join("d"))
            .env("XDG_CONFIG_HOME", self.path().join("c"))
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
