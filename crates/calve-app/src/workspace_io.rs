//! Workspace I/O through capability handles (rev 10 §15, ADR 0014). Every path is a validated
//! Project-relative locator, resolved one component at a time from the Project root `Dir`
//! without following any symlink, so nothing escapes the root. Files are hashed through the
//! opened handle and re-identified afterwards (stable-handle rule).

use std::io::{self, Read, Write};
use std::path::Path;

use calve_integration_contract::wire::{Entry, EntryKind};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use sha2::{Digest, Sha256};

pub use calve_integration_contract::locator::{MAX_COMPONENTS, MAX_LOCATOR_BYTES};
/// Rehash attempts before a file that keeps changing is reported `unstable_file`.
const MAX_REHASH: usize = 3;

#[derive(Debug)]
pub enum IoError {
    /// The locator breaks the ADR 0014 rules.
    Locator(String),
    /// A symlink, or a non-directory, sits on the path.
    NotFollowed(String),
    /// The file changed identity or size while it was hashed, `MAX_REHASH` times.
    Unstable(String),
    TooLarge(String),
    Io(io::Error),
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IoError::Locator(m) => write!(f, "invalid locator: {m}"),
            IoError::NotFollowed(m) => write!(f, "{m}: symlinks are never followed"),
            IoError::Unstable(m) => write!(f, "{m}: unstable_file (changed while hashing)"),
            IoError::TooLarge(m) => write!(f, "{m}: exceeds the size limit"),
            IoError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IoError {}

impl From<io::Error> for IoError {
    fn from(e: io::Error) -> Self {
        IoError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, IoError>;

/// ADR 0014 locator rules; see [`calve_integration_contract::locator::validate`].
pub fn validate_locator(loc: &str) -> Result<()> {
    calve_integration_contract::locator::validate(loc).map_err(IoError::Locator)
}

/// Path-based durable rename for Calve-owned state outside the workspace capability (caches,
/// spools, trust state): the rename, then its persistence — the parent directory fsync on
/// Unix, `MOVEFILE_WRITE_THROUGH` on Windows (calve-win-sec), where std cannot open a
/// directory. Callers sync file contents through their own writable handle first.
pub fn rename_durable(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        calve_win_sec::rename_durable(from, to)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(from, to)?;
        if let Some(parent) = to.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
    len: u64,
}

fn id_of(m: &cap_std::fs::Metadata) -> FileId {
    FileId {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
    }
}

/// Unix permission bits worth recording (the executable bit); Windows has none.
fn mode_of(m: &cap_std::fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        Some(if m.permissions().mode() & 0o111 != 0 {
            0o755
        } else {
            0o644
        })
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        None
    }
}

/// The Project root as a capability.
pub struct Workspace {
    root: Dir,
}

impl Workspace {
    pub fn open(root: &Path) -> Result<Self> {
        Ok(Workspace {
            root: Dir::open_ambient_dir(root, ambient_authority())?,
        })
    }

    /// The parent directory of `loc`, opened component by component without following
    /// symlinks, and the final name.
    pub(crate) fn parent<'a>(&self, loc: &'a str) -> Result<(Dir, &'a str)> {
        validate_locator(loc)?;
        let (dirs, name) = loc.rsplit_once('/').unwrap_or(("", loc));
        let mut dir = self.root.try_clone()?;
        for part in dirs.split('/').filter(|p| !p.is_empty()) {
            dir = dir.open_dir_nofollow(part).map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => IoError::Io(e),
                _ => IoError::NotFollowed(loc.to_owned()),
            })?;
        }
        Ok((dir, name))
    }

    fn open_read(&self, loc: &str) -> Result<(Dir, File)> {
        let (dir, name) = self.parent(loc)?;
        let mut o = OpenOptions::new();
        o.read(true).follow(FollowSymlinks::No);
        let f = dir.open_with(name, &o).map_err(|e| {
            if dir
                .symlink_metadata(name)
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                IoError::NotFollowed(loc.to_owned())
            } else {
                IoError::Io(e)
            }
        })?;
        if !f.metadata()?.is_file() {
            return Err(IoError::Locator(format!("{loc}: not a regular file")));
        }
        Ok((dir, f))
    }

    /// Reads a regular file of at most `max` bytes.
    /// Streams a working-tree file to `dest` (outside the Workspace) without following
    /// symlinks at any component.
    pub fn copy_out(&self, loc: &str, dest: &std::path::Path) -> Result<u64> {
        let (_, mut f) = self.open_read(loc)?;
        Ok(std::io::copy(&mut f, &mut std::fs::File::create(dest)?)?)
    }

    pub fn read(&self, loc: &str, max: u64) -> Result<Vec<u8>> {
        let (_, f) = self.open_read(loc)?;
        let mut out = Vec::new();
        f.take(max + 1).read_to_end(&mut out)?;
        if out.len() as u64 > max {
            return Err(IoError::TooLarge(loc.to_owned()));
        }
        Ok(out)
    }

    /// Hashes a regular file through its handle and checks it is still the same file at the
    /// same path afterwards; a change rehashes, up to three times, then `Unstable`.
    pub fn hash(&self, loc: &str) -> Result<Entry> {
        for _ in 0..MAX_REHASH {
            let (dir, mut f) = self.open_read(loc)?;
            let name = loc.rsplit_once('/').map_or(loc, |(_, n)| n);
            let meta = f.metadata()?;
            let before = id_of(&meta);
            let mut h = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            let mut n_total = 0u64;
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                n_total += n as u64;
                h.update(&buf[..n]);
            }
            let after_handle = id_of(&f.metadata()?);
            let after_path = dir.symlink_metadata(name).map(|m| id_of(&m)).ok();
            if after_handle == before && after_path == Some(before) && n_total == before.len {
                return Ok(Entry {
                    path: loc.to_owned(),
                    kind: EntryKind::File,
                    digest: Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect()),
                    size: Some(n_total),
                    mode: mode_of(&meta),
                    target: None,
                });
            }
        }
        Err(IoError::Unstable(loc.to_owned()))
    }

    /// A symlink's target, as recorded (never followed).
    pub fn symlink(&self, loc: &str) -> Result<Entry> {
        let (dir, name) = self.parent(loc)?;
        // Raw contents: an absolute or escaping target is recorded verbatim, never resolved.
        let target = dir.read_link_contents(name)?;
        let target = target
            .to_str()
            .ok_or_else(|| IoError::Locator(format!("{loc}: symlink target is not UTF-8")))?
            .replace('\\', "/");
        Ok(Entry {
            path: loc.to_owned(),
            kind: EntryKind::Symlink,
            digest: None,
            size: None,
            mode: None,
            target: Some(target),
        })
    }

    /// Walks the tree from the root without following symlinks, skipping `.calve` and every
    /// path `skip(locator, is_dir)` returns true for. Files are hashed (stable handle), symlinks
    /// recorded by target. Entries arrive in directory order; callers sort (§6.5 manifests).
    /// Unreadable or unstable files are reported through `on_error` and omitted.
    pub fn scan(
        &self,
        mut skip: impl FnMut(&str, bool) -> bool,
        mut emit: impl FnMut(Entry) -> Result<()>,
        mut on_error: impl FnMut(&str, IoError),
    ) -> Result<()> {
        let mut stack: Vec<(Dir, String)> = vec![(self.root.try_clone()?, String::new())];
        while let Some((dir, prefix)) = stack.pop() {
            let mut names: Vec<String> = Vec::new();
            for e in dir.entries()? {
                match e?.file_name().into_string() {
                    Ok(n) => names.push(n),
                    Err(raw) => on_error(
                        &format!("{prefix}{}", raw.to_string_lossy()),
                        IoError::Locator("name is not UTF-8".into()),
                    ),
                }
            }
            names.sort();
            for name in names {
                let loc = format!("{prefix}{name}");
                if loc == ".calve" || validate_locator(&loc).is_err() {
                    if loc != ".calve" {
                        on_error(&loc, IoError::Locator("invalid name".into()));
                    }
                    continue;
                }
                let meta = match dir.symlink_metadata(&name) {
                    Ok(m) => m,
                    Err(e) => {
                        on_error(&loc, e.into());
                        continue;
                    }
                };
                let ft = meta.file_type();
                if ft.is_dir() {
                    if !skip(&loc, true) {
                        match dir.open_dir_nofollow(&name) {
                            Ok(d) => stack.push((d, format!("{loc}/"))),
                            Err(e) => on_error(&loc, e.into()),
                        }
                    }
                } else if skip(&loc, false) {
                    continue;
                } else if ft.is_symlink() {
                    match self.symlink(&loc) {
                        Ok(entry) => emit(entry)?,
                        Err(e) => on_error(&loc, e),
                    }
                } else if ft.is_file() {
                    match self.hash(&loc) {
                        Ok(entry) => emit(entry)?,
                        Err(e) => on_error(&loc, e),
                    }
                }
            }
        }
        Ok(())
    }

    /// Writes `bytes` to `loc` atomically: a fresh temp file in the same directory (synced
    /// through its writable handle), then a rename over the target. Creates missing parent
    /// directories (never through a symlink). Durability of the rename itself: Unix syncs the
    /// directory; Windows uses write-through rename in calve-win-sec (ADR 0013).
    pub fn write_atomic(&self, loc: &str, bytes: &[u8]) -> Result<()> {
        let (dir, name) = self.parent_create(loc)?;
        if dir
            .symlink_metadata(name)
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(IoError::NotFollowed(loc.to_owned()));
        }
        let tmp = format!(
            ".calve-tmp-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7().simple()
        );
        let res = (|| -> io::Result<()> {
            let mut f = dir.open_with(&tmp, OpenOptions::new().write(true).create_new(true))?;
            f.write_all(bytes)?;
            f.sync_all()?;
            drop(f);
            dir.rename(&tmp, &dir, name)?;
            #[cfg(unix)]
            dir.open(".")?.sync_all()?;
            Ok(())
        })();
        if res.is_err() {
            let _ = dir.remove_file(&tmp);
        }
        Ok(res?)
    }

    /// Like [`Workspace::parent`], creating missing directories (never through a symlink).
    pub(crate) fn parent_create<'a>(&self, loc: &'a str) -> Result<(Dir, &'a str)> {
        validate_locator(loc)?;
        let (dirs, name) = loc.rsplit_once('/').unwrap_or(("", loc));
        let mut dir = self.root.try_clone()?;
        for part in dirs.split('/').filter(|p| !p.is_empty()) {
            dir = match dir.open_dir_nofollow(part) {
                Ok(d) => d,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    dir.create_dir(part)?;
                    dir.open_dir_nofollow(part)?
                }
                Err(_) => return Err(IoError::NotFollowed(loc.to_owned())),
            };
        }
        Ok((dir, name))
    }

    /// The entries of directory `loc` (`""` = the root): `(name, kind, size)`, sorted by
    /// name, without following any symlink and without reading file contents. `.calve` at the
    /// root and names that are not valid locators are left out.
    pub fn list_dir(&self, loc: &str) -> Result<Vec<(String, EntryKind, u64)>> {
        let dir = if loc.is_empty() {
            self.root.try_clone()?
        } else {
            validate_locator(loc)?;
            let mut d = self.root.try_clone()?;
            for part in loc.split('/') {
                d = d.open_dir_nofollow(part).map_err(|e| match e.kind() {
                    io::ErrorKind::NotFound => IoError::Io(e),
                    _ => IoError::NotFollowed(loc.to_owned()),
                })?;
            }
            d
        };
        let mut out = vec![];
        for e in dir.entries()? {
            let e = e?;
            let Ok(name) = e.file_name().into_string() else {
                continue;
            };
            let full = if loc.is_empty() {
                name.clone()
            } else {
                format!("{loc}/{name}")
            };
            if (loc.is_empty() && name == ".calve") || validate_locator(&full).is_err() {
                continue;
            }
            let m = dir.symlink_metadata(&name)?;
            let kind = if m.file_type().is_symlink() {
                EntryKind::Symlink
            } else if m.is_dir() {
                EntryKind::Dir
            } else if m.is_file() {
                EntryKind::File
            } else {
                continue;
            };
            out.push((name, kind, m.len()));
        }
        out.sort();
        Ok(out)
    }

    pub fn exists(&self, loc: &str) -> bool {
        self.parent(loc)
            .is_ok_and(|(dir, name)| dir.symlink_metadata(name).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_rules() {
        for ok in [
            "a",
            "src/main.rs",
            "a b/ü.txt",
            ".github/x",
            "x..y",
            ".calvex",
            "console.rs",
            "COM",
            "com10",
        ] {
            assert!(validate_locator(ok).is_ok(), "{ok}");
        }
        let long = "a/".repeat(64) + "b";
        for bad in [
            "",
            "/abs",
            "a//b",
            "a/./b",
            "a/../b",
            "..",
            ".",
            "a\\b",
            "a\0b",
            ".calve",
            ".calve/x",
            "C:",
            "C:/x",
            ".CALVE/x",
            ".Calve",
            ".calve./x",
            ".calve /x",
            "a:b",
            "f.txt:stream",
            "x/a.",
            "x/a ",
            "CON",
            "nul.txt",
            "x/COM1",
            "lpt9.log",
            "CON .txt",
            "nul  ",
            "x/COM¹",
            "lpt³.x",
            "CALVE~1",
            "calve~1/x",
            "PROGRA~1/x",
            "a/FILE~12.TXT",
            long.as_str(),
            &"x".repeat(4097),
        ] {
            assert!(validate_locator(bad).is_err(), "{bad:?}");
        }
    }
}
