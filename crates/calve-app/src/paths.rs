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

/// A path as people read it. Windows canonical paths are verbatim (`\\?\C:\x`,
/// `\\?\UNC\server\share\x`); Calve keeps them so internally, and shows `C:\x` or
/// `\\server\share\x` instead when that names the same file: under 260 characters, no device
/// name (`CON`, `NUL`, `COM1`…) and no component ending in a dot or a space, all of which only
/// the verbatim form preserves. Anything else, and every non-verbatim string, is unchanged.
pub fn readable(path: &str) -> std::borrow::Cow<'_, str> {
    let simpler = if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\")
        && rest.as_bytes().get(1) == Some(&b':')
        && rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
    {
        rest.to_owned()
    } else {
        return path.into();
    };
    let device = |c: &str| {
        let stem = c
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end()
            .to_ascii_uppercase();
        matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.as_bytes()[3].is_ascii_digit())
    };
    let safe = simpler.len() < 260
        && !simpler.contains('/')
        && simpler
            .split('\\')
            .skip_while(|c| c.is_empty() || c.ends_with(':'))
            .all(|c| !device(c) && !c.ends_with('.') && !c.ends_with(' '));
    if safe { simpler.into() } else { path.into() }
}

/// Makes every path in a response readable ([`readable`]): whole path values, and verbatim
/// prefixes inside messages (text for people, never parsed).
pub fn present(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            if let std::borrow::Cow::Owned(simpler) = readable(s) {
                *s = simpler;
            } else if s.contains(r"\\?\") {
                *s = present_text(s);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(present),
        serde_json::Value::Object(fields) => fields.values_mut().for_each(present),
        _ => {}
    }
}

/// Message text: verbatim prefixes dropped where a drive or UNC path follows.
pub fn present_text(text: &str) -> String {
    let unc = text.replace(r"\\?\UNC\", r"\\");
    let mut out = String::with_capacity(unc.len());
    let mut rest = unc.as_str();
    while let Some(i) = rest.find(r"\\?\") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 4..];
        let drive = after.as_bytes().get(1) == Some(&b':')
            && after
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic);
        if !drive {
            out.push_str(r"\\?\");
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Where supervisor sockets are bound: a short, private, per-user directory, so a socket path
/// stays under the platform limit (104 bytes on macOS, 108 on Linux) however deep the data root
/// is. `$XDG_RUNTIME_DIR` where there is one, else `/tmp`; then `calve-<uid>/<data root key>/`,
/// each created owner-only and refused (fail closed) unless it is a real directory of this user
/// that nobody else can enter, so a directory planted in a shared `/tmp` is never used.
#[cfg(unix)]
pub fn socket_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        Some(run) if run.is_absolute() && run.is_dir() => run,
        _ => PathBuf::from("/tmp"),
    };
    let uid = rustix::process::getuid().as_raw();
    let user = private_dir(&base.join(format!("calve-{uid}")), uid)?;
    let key = crate::journal::sha256_hex(data_root()?.to_string_lossy().as_bytes());
    private_dir(&user.join(&key[..12]), uid)
}

#[cfg(unix)]
fn private_dir(path: &Path, uid: u32) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let unusable = |why: String| {
        crate::coded(
            "CONTAINMENT_UNAVAILABLE",
            format!("supervisor socket directory {}: {why}", path.display()),
        )
    };
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(unusable(e.to_string())),
    }
    let m = std::fs::symlink_metadata(path).map_err(|e| unusable(e.to_string()))?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(unusable("not a directory".into()));
    }
    if m.uid() != uid {
        return Err(unusable(format!("owned by uid {}, not {uid}", m.uid())));
    }
    if m.mode() & 0o077 != 0 {
        return Err(unusable(format!(
            "mode {:o} lets others in",
            m.mode() & 0o777
        )));
    }
    Ok(path.to_path_buf())
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

    /// The socket directory is used only when it is a real, owner-only directory of this user.
    #[cfg(unix)]
    #[test]
    fn a_socket_directory_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let uid = rustix::process::getuid().as_raw();
        let fresh = t.path().join("fresh");
        super::private_dir(&fresh, uid).unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        super::private_dir(&fresh, uid).expect("an existing private directory is reused");
        let open = t.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            super::private_dir(&open, uid).is_err(),
            "group/other access"
        );
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&fresh, &link).unwrap();
        assert!(
            super::private_dir(&link, uid).is_err(),
            "a symlink, even to a good directory"
        );
        let file = t.path().join("file");
        std::fs::write(&file, "").unwrap();
        assert!(super::private_dir(&file, uid).is_err(), "not a directory");
        assert!(
            super::private_dir(&fresh, uid + 1).is_err(),
            "another user's"
        );
    }

    /// Readable Windows paths: drive and UNC forms lose the verbatim prefix only where the
    /// result names the same file; long, device-named and dot/space-ended paths keep it.
    #[test]
    fn verbatim_paths_are_shown_readably_only_when_equivalent() {
        use super::readable;
        assert_eq!(readable(r"\\?\C:\Users\me\proj"), r"C:\Users\me\proj");
        assert_eq!(
            readable(r"\\?\UNC\server\share\proj"),
            r"\\server\share\proj"
        );
        let long = format!(r"\\?\C:\{}", "a\\".repeat(140));
        assert_eq!(
            readable(&long),
            long,
            "260 characters or more: verbatim only"
        );
        for kept in [
            r"\\?\C:\proj\CON",
            r"\\?\C:\proj\nul.txt",
            r"\\?\C:\proj\COM1",
            r"\\?\C:\proj\name.",
            r"\\?\C:\proj\name ",
            r"\\?\Volume{0b1c2d3e}\proj",
            r"\\?\GLOBALROOT\Device\x",
        ] {
            assert_eq!(readable(kept), kept);
        }
        for unchanged in [
            r"C:\already",
            r"\\server\share",
            "/home/u/proj",
            "plain text",
        ] {
            assert_eq!(readable(unchanged), unchanged);
        }
        // COM10 and LPT is not a device name.
        assert_eq!(readable(r"\\?\C:\COM10\LPT"), r"C:\COM10\LPT");
    }

    #[test]
    fn responses_show_readable_paths_everywhere() {
        let mut v = serde_json::json!({
            "root": r"\\?\C:\Users\me\proj",
            "items": [r"\\?\UNC\srv\share\p", 7, null],
            "message": r"unknown registered project \\?\C:\a\b; also \\?\UNC\s\x and \\?\Volume{1}\y",
        });
        super::present(&mut v);
        assert_eq!(v["root"], r"C:\Users\me\proj");
        assert_eq!(v["items"][0], r"\\srv\share\p");
        assert_eq!(v["items"][1], 7);
        assert_eq!(
            v["message"],
            r"unknown registered project C:\a\b; also \\s\x and \\?\Volume{1}\y"
        );
    }
}
