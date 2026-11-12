//! Where Calve keeps its state. Production uses each platform's own locations: Linux
//! `$XDG_DATA_HOME/calve` and `$XDG_CONFIG_HOME/calve` (else under `~/.local/share` and
//! `~/.config`), macOS `~/Library/Application Support/Calve`, Windows `%LOCALAPPDATA%\Calve`
//! (data) and `%APPDATA%\Calve` (config). The runtime directory derives from the data root.
//!
//! Tests point Calve elsewhere only through `CALVE_TEST_DATA_ROOT` and `CALVE_TEST_CONFIG_ROOT`
//! (the exact roots), honoured by debug builds alone and only under `CALVE_TEST_GUARD`, and every
//! root, native or overridden, must lie inside the test roots there. Release builds ignore them.
use std::path::{Path, PathBuf};

use crate::{Error, Result};

const TEST_DATA_ROOT: &str = "CALVE_TEST_DATA_ROOT";
const TEST_CONFIG_ROOT: &str = "CALVE_TEST_CONFIG_ROOT";

fn invalid(message: impl Into<String>) -> Error {
    crate::coded("INVALID_CONFIGURATION", message)
}

/// The data root: the platform's, or a guarded test root.
pub fn data_root() -> Result<PathBuf> {
    root(TEST_DATA_ROOT, native_data_root)
}

/// The configuration root: the platform's, or a guarded test root.
pub fn config_root() -> Result<PathBuf> {
    root(TEST_CONFIG_ROOT, native_config_root)
}

fn root(var: &str, native: fn() -> Result<PathBuf>) -> Result<PathBuf> {
    if cfg!(debug_assertions)
        && let Some(path) = std::env::var_os(var)
    {
        // Fail closed: an override without the guard is a mistake, never a quiet redirect.
        if std::env::var_os("CALVE_TEST_GUARD").is_none() {
            return Err(invalid(format!(
                "{var} is for tests and needs CALVE_TEST_GUARD"
            )));
        }
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(invalid(format!("{var} must be an absolute path")));
        }
        return guard_test_root(path);
    }
    guard_test_root(native()?)
}

/// Per-data-root runtime state (daemon socket and pid, spawn records): in the platform runtime
/// directory when there is one (`$XDG_RUNTIME_DIR/calve/<data root digest>/`, so each data root
/// has its own), otherwise the data directory itself. Contents do not outlive a reboot.
pub fn runtime_dir() -> Result<PathBuf> {
    let data = data_root()?;
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

/// The platform's own data directory for Calve (never a test override).
pub fn native_data_root() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| invalid("HOME is not set"))?;
        Ok(PathBuf::from(home).join("Library/Application Support/Calve"))
    }
    #[cfg(windows)]
    {
        let data = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .ok_or_else(|| invalid("LOCALAPPDATA or APPDATA is not set"))?;
        Ok(PathBuf::from(data).join("Calve"))
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

/// The platform's own configuration directory for Calve (never a test override).
pub fn native_config_root() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| invalid("HOME is not set"))?;
        Ok(PathBuf::from(home).join("Library/Application Support/Calve"))
    }
    #[cfg(windows)]
    {
        let home = std::env::var_os("APPDATA").ok_or_else(|| invalid("APPDATA is not set"))?;
        Ok(PathBuf::from(home).join("Calve"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
            let path = PathBuf::from(config);
            if !path.is_absolute() {
                return Err(invalid("XDG_CONFIG_HOME must be an absolute path"));
            }
            return Ok(path.join("calve"));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| invalid("HOME is not set"))?;
        Ok(PathBuf::from(home).join(".config/calve"))
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

    /// The platform's own locations, from this process's real environment (nothing is set).
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn native_roots_on_linux_follow_xdg_then_home() {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let base = |var: &str, fallback: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(fallback))
        };
        assert_eq!(
            super::native_data_root().unwrap(),
            base("XDG_DATA_HOME", ".local/share").join("calve")
        );
        assert_eq!(
            super::native_config_root().unwrap(),
            base("XDG_CONFIG_HOME", ".config").join("calve")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_roots_on_macos_are_application_support() {
        let support =
            PathBuf::from(std::env::var_os("HOME").unwrap()).join("Library/Application Support");
        assert!(
            support.is_dir(),
            "{} is the user's Application Support",
            support.display()
        );
        assert_eq!(super::native_data_root().unwrap(), support.join("Calve"));
        assert_eq!(super::native_config_root().unwrap(), support.join("Calve"));
    }

    /// Calve reads %LOCALAPPDATA% and %APPDATA%; they must be the user's known folders.
    #[cfg(windows)]
    #[test]
    fn native_roots_on_windows_are_the_known_folders() {
        let known = |name: &str| {
            let out = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("[Environment]::GetFolderPath('{name}')"),
                ])
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
            PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
        };
        assert_eq!(
            super::native_data_root().unwrap(),
            known("LocalApplicationData").join("Calve")
        );
        assert_eq!(
            super::native_config_root().unwrap(),
            known("ApplicationData").join("Calve")
        );
    }
}
