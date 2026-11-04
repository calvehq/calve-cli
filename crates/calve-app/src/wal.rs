//! Materialization write-ahead log (rev 10 §14, ADR 0013).
//!
//! Every working-tree mutation is one journaled step in `.calve/run/materialize/<op>/journal`:
//! `m.intent` → preserve the verified original (`m.backup`, streamed from the same nofollow
//! handle that was hashed) → mutate through a temp file with the strongest primitive the
//! platform offers (exchange, or displace-then-place with two no-replace renames; creates and
//! deletes are no-replace renames) → post-mutation identity check (the destination is Calve's
//! temp inode with the expected digest) → verify the displaced bytes → `m.done`.
//! Anything unexpected is `m.conflicted`: the displaced and Calve's bytes are kept under
//! `.calve/conflicts/<op>/<step>/` and nothing is reversed automatically. These are check-then-act
//! steps, not compare-and-swap: a concurrent writer is detected after the fact, never prevented.
//! A crash leaves an intent without `m.done`, which [`Wal::reconcile`] settles from what is on
//! disk (path, temp, trash, backup).
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::journal::{Journal, Record, fault};
use crate::workspace_io::{IoError, Workspace};
use crate::{Error, Result};

/// Platform mutation primitives (§14 table).
pub(crate) trait Primitives {
    fn name(&self) -> &'static str;
    /// Replace and delete never overwrite a file and always keep the displaced one: no-replace
    /// rename is available (with exchange or displace-then-place for replacement).
    fn atomic(&self) -> bool;
    fn rename_noreplace(&self, dir: &Dir, from: &str, to: &str) -> io::Result<()>;
    /// Puts `temp` at `name` and returns where the displaced `name` now is. The default
    /// displaces then places, both no-replace: the original moves to `spare` (never copied,
    /// never overwritten), then `temp` moves to `name`. Readers can see `name` absent between
    /// the two; a file created there in that gap makes the second fail with `AlreadyExists`
    /// and is kept. Platforms with an atomic exchange override this.
    fn replace<'a>(
        &self,
        dir: &Dir,
        temp: &'a str,
        name: &str,
        spare: &'a str,
    ) -> io::Result<&'a str> {
        self.rename_noreplace(dir, name, spare)?;
        fault("materialize.replace.after_displace");
        self.rename_noreplace(dir, temp, name)?;
        Ok(spare)
    }
}

#[cfg(target_os = "linux")]
struct Linux;

#[cfg(target_os = "linux")]
impl Linux {
    fn exchange(&self, dir: &Dir, a: &str, b: &str) -> io::Result<()> {
        Ok(rustix::fs::renameat_with(
            dir,
            a,
            dir,
            b,
            rustix::fs::RenameFlags::EXCHANGE,
        )?)
    }
}

#[cfg(target_os = "linux")]
fn renameat2_noreplace(dir: &Dir, from: &str, to: &str) -> io::Result<()> {
    Ok(rustix::fs::renameat_with(
        dir,
        from,
        dir,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )?)
}

#[cfg(target_os = "linux")]
impl Primitives for Linux {
    fn name(&self) -> &'static str {
        "linux-renameat2"
    }
    fn atomic(&self) -> bool {
        true
    }
    fn rename_noreplace(&self, dir: &Dir, from: &str, to: &str) -> io::Result<()> {
        renameat2_noreplace(dir, from, to)
    }
    fn replace<'a>(
        &self,
        dir: &Dir,
        temp: &'a str,
        name: &str,
        _spare: &'a str,
    ) -> io::Result<&'a str> {
        self.exchange(dir, temp, name)?;
        Ok(temp)
    }
}

/// Debug builds: Linux no-replace renames with the default displace-then-place replacement,
/// so the Windows algorithm runs under the Linux suites (`CALVE_FS_PRIMITIVES=displace`).
#[cfg(target_os = "linux")]
struct LinuxDisplace;

#[cfg(target_os = "linux")]
impl Primitives for LinuxDisplace {
    fn name(&self) -> &'static str {
        "linux-displace"
    }
    fn atomic(&self) -> bool {
        true
    }
    fn rename_noreplace(&self, dir: &Dir, from: &str, to: &str) -> io::Result<()> {
        renameat2_noreplace(dir, from, to)
    }
}

/// Windows: handle-relative no-replace renames (NtSetInformationFile with the directory as
/// RootDirectory, `calve_win_sec::rename_by_handle`) and displace-then-place replacement.
#[cfg(windows)]
struct Windows;

#[cfg(windows)]
impl Primitives for Windows {
    fn name(&self) -> &'static str {
        "windows-handle-rename"
    }
    fn atomic(&self) -> bool {
        true
    }
    fn rename_noreplace(&self, dir: &Dir, from: &str, to: &str) -> io::Result<()> {
        use cap_std::fs::OpenOptionsExt;
        // DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE; full sharing so Calve never blocks
        // another reader or writer (a holder without FILE_SHARE_DELETE fails this open).
        let file = dir.open_with(
            from,
            OpenOptions::new()
                .read(true)
                .access_mode(0x0001_0000 | 0x80 | 0x0010_0000)
                .share_mode(7)
                .follow(FollowSymlinks::No),
        )?;
        calve_win_sec::rename_by_handle(&file, dir, to, false)
    }
}

/// A filesystem without no-replace rename (and the debug-build stand-in for one): creates go
/// through a no-replace hard link; replace and delete are refused unless `--allow-unsafe-fs`.
/// macOS (`renameatx_np` swap/excl) is not wired yet and uses this path (PENDING, no host).
struct Fallback;

impl Primitives for Fallback {
    fn name(&self) -> &'static str {
        "fallback"
    }
    fn atomic(&self) -> bool {
        false
    }
    fn rename_noreplace(&self, dir: &Dir, from: &str, to: &str) -> io::Result<()> {
        dir.hard_link(from, dir, to)?;
        dir.remove_file(from)
    }
    fn replace<'a>(&self, _: &Dir, _: &'a str, _: &str, _: &'a str) -> io::Result<&'a str> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// The primitives for the Project's filesystem, probed in `.calve/tmp` (same filesystem as the
/// tree). Debug builds: `CALVE_FS_PRIMITIVES=fallback` simulates a weak filesystem and
/// `=displace` (Linux) uses displace-then-place replacement.
pub(crate) fn primitives(root: &Path) -> Box<dyn Primitives> {
    let forced = cfg!(debug_assertions)
        .then(|| std::env::var("CALVE_FS_PRIMITIVES").ok())
        .flatten();
    let forced = forced.as_deref();
    if forced == Some("fallback") {
        return Box::new(Fallback);
    }
    // Two probe files in `.calve/tmp`: the probe `f(dir, a, b)` runs with both present.
    let probe = |f: &dyn Fn(&Dir, &str, &str) -> io::Result<()>| -> io::Result<()> {
        let tmp = root.join(".calve/tmp");
        std::fs::create_dir_all(&tmp)?;
        let dir = Dir::open_ambient_dir(&tmp, cap_std::ambient_authority())?;
        let (a, b) = (
            format!(".probe-{}-a", uuid::Uuid::now_v7().simple()),
            format!(".probe-{}-b", uuid::Uuid::now_v7().simple()),
        );
        dir.write(&a, b"a")?;
        dir.write(&b, b"b")?;
        let r = f(&dir, &a, &b);
        let _ = dir.remove_file(&a);
        let _ = dir.remove_file(&b);
        let _ = dir.remove_file(format!("{a}-moved"));
        r
    };
    // No-replace must refuse an existing target and move to a free one.
    let noreplace = |p: &dyn Primitives| {
        probe(&|dir, a, b| match p.rename_noreplace(dir, a, b) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                p.rename_noreplace(dir, a, &format!("{a}-moved"))
            }
            Ok(()) => Err(io::Error::other("no-replace rename replaced")),
            Err(e) => Err(e),
        })
        .is_ok()
    };
    #[cfg(target_os = "linux")]
    {
        if forced == Some("displace") && noreplace(&LinuxDisplace) {
            return Box::new(LinuxDisplace);
        }
        if probe(&|dir, a, b| Linux.exchange(dir, a, b)).is_ok() {
            return Box::new(Linux);
        }
    }
    #[cfg(windows)]
    if noreplace(&Windows) {
        return Box::new(Windows);
    }
    let _ = noreplace;
    Box::new(Fallback)
}

/// One working-tree mutation: `before`/`after` are content digests, `None` = absent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Mutation {
    pub step: String,
    pub path: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Outcome {
    Done,
    Conflicted(String),
}

fn digest_of(bytes: &[u8]) -> String {
    format!("sha256:{}", crate::journal::sha256_hex(bytes))
}

/// Digest and inode of regular file `name` in `dir`, read through a nofollow handle; `None`
/// when absent. A symlink or directory there is an error.
fn state(dir: &Dir, name: &str) -> io::Result<Option<(String, u64)>> {
    match dir.symlink_metadata(name) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
        Ok(m) if !m.is_file() => {
            return Err(io::Error::other(format!("{name} is not a regular file")));
        }
        Ok(_) => {}
    }
    let mut f = dir.open_with(
        name,
        OpenOptions::new().read(true).follow(FollowSymlinks::No),
    )?;
    let ino = f.metadata()?.ino();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Ok(Some((format!("sha256:{hex}"), ino)))
}

fn digest_at(dir: &Dir, name: &str) -> io::Result<Option<String>> {
    Ok(state(dir, name)?.map(|s| s.0))
}

fn read_at(dir: &Dir, name: &str) -> io::Result<Vec<u8>> {
    let mut out = vec![];
    dir.open_with(
        name,
        OpenOptions::new().read(true).follow(FollowSymlinks::No),
    )?
    .read_to_end(&mut out)?;
    Ok(out)
}

fn sync_dir(dir: &Dir) -> io::Result<()> {
    #[cfg(unix)]
    dir.open(".")?.sync_all()?;
    #[cfg(windows)]
    calve_win_sec::flush_dir_handle(dir)?;
    let _ = dir;
    Ok(())
}

/// Debug builds: `CALVE_TEST_ENOSPC=<step>.temp|<step>.backup` makes that write fail with the
/// platform's disk-full error (ENOSPC / ERROR_DISK_FULL).
fn disk_full(point: &str) -> io::Result<()> {
    if cfg!(debug_assertions) && std::env::var("CALVE_TEST_ENOSPC").is_ok_and(|p| p == point) {
        return Err(io::Error::from_raw_os_error(if cfg!(windows) {
            112
        } else {
            28
        }));
    }
    Ok(())
}

/// Removes `name` from `dir`; on Windows a read-only file is made writable first (DeleteFile
/// refuses read-only files; Calve only removes its own displaced, trash and temp copies).
fn remove(dir: &Dir, name: &str) -> io::Result<()> {
    match dir.remove_file(name) {
        #[cfg(windows)]
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            let md = dir.symlink_metadata(name)?;
            if !md.is_file() || !md.permissions().readonly() {
                return Err(e);
            }
            let mut perm = md.permissions();
            perm.set_readonly(false);
            dir.set_permissions(name, perm)?;
            dir.remove_file(name)
        }
        r => r,
    }
}

/// The permissions a replacement carries over from the file it displaces: the rwx bits on
/// Unix (never setuid, setgid or sticky), the read-only flag on Windows.
fn carried(original: cap_std::fs::Permissions) -> cap_std::fs::Permissions {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt;
        cap_std::fs::Permissions::from_mode(original.mode() & 0o777)
    }
    #[cfg(not(unix))]
    original
}

/// Owner-only file (0600) written and synced.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn private_dir(path: &Path) -> io::Result<()> {
    crate::journal::private_dir(path)
}

/// Debug builds only: a stand-in concurrent writer. `CALVE_TEST_WRITE=<point>=<target>` appends
/// `concurrent\n` at `point` to `<target>` (an absolute path, or `@displaced` for the displaced
/// original's inode right after the exchange).
fn interleave(point: &str, dir: &Dir, displaced: &str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let Ok(v) = std::env::var("CALVE_TEST_WRITE") else {
        return;
    };
    let Some((p, target)) = v.split_once('=') else {
        return;
    };
    if p != point {
        return;
    }
    let r = if target == "@displaced" {
        dir.open_with(displaced, OpenOptions::new().append(true))
            .and_then(|mut f| f.write_all(b"concurrent\n"))
    } else {
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(target)
            .and_then(|mut f| f.write_all(b"concurrent\n"))
    };
    r.expect("CALVE_TEST_WRITE");
}

fn corrupt(e: crate::journal::Error) -> Error {
    crate::coded("RECOVERY_REQUIRED", format!("materialization journal: {e}"))
}

fn io_err(e: IoError) -> Error {
    match e {
        IoError::Io(e) => e.into(),
        other => Error::Message(other.to_string()),
    }
}

/// `.calve/run/materialize`.
pub(crate) fn runs(root: &Path) -> PathBuf {
    root.join(".calve/run/materialize")
}

pub(crate) struct Wal {
    pub j: Journal,
    pub op: String,
    root: PathBuf,
    ws: Workspace,
    pub prims: Box<dyn Primitives>,
}

impl Wal {
    pub(crate) fn create(root: &Path, binding: Value) -> Result<Self> {
        let op = uuid::Uuid::now_v7().simple().to_string();
        let dir = runs(root).join(&op);
        private_dir(&dir)?;
        let j =
            Journal::create(&dir.join("journal"), "materialize", &op, binding).map_err(corrupt)?;
        Self::with(root, op, j)
    }

    pub(crate) fn open(root: &Path, op: &str) -> Result<(Self, Vec<Record>)> {
        if op.len() != 32 || !op.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(crate::coded(
                "INVALID_ARGUMENT",
                format!("{op} is not a materialization operation"),
            ));
        }
        let path = runs(root).join(op).join("journal");
        if !path.is_file() {
            return Err(crate::coded(
                "NOT_FOUND",
                format!("materialization {op} not found"),
            ));
        }
        let opened = Journal::open(&path).map_err(corrupt)?;
        Ok((
            Self::with(root, op.to_owned(), opened.journal)?,
            opened.records,
        ))
    }

    fn with(root: &Path, op: String, j: Journal) -> Result<Self> {
        Ok(Wal {
            j,
            ws: Workspace::open(root).map_err(io_err)?,
            prims: primitives(root),
            root: root.to_owned(),
            op,
        })
    }

    fn temp(&self, step: &str) -> String {
        format!(".calve-mat-{}-{step}", self.op)
    }
    fn trash(&self, step: &str) -> String {
        format!(".calve-trash-{}-{step}", self.op)
    }
    pub(crate) fn backup(&self, step: &str) -> PathBuf {
        runs(&self.root)
            .join(&self.op)
            .join(format!("{step}.backup"))
    }
    pub(crate) fn conflicts(&self, step: &str) -> PathBuf {
        self.root.join(".calve/conflicts").join(&self.op).join(step)
    }

    fn append(&mut self, kind: &str, body: Value) -> Result<()> {
        self.j.append(kind, body).map_err(corrupt)?;
        Ok(())
    }

    /// The parent directory of `path` (nofollow); `Err` names a substituted ancestor.
    fn parent(&self, path: &str, create: bool) -> std::result::Result<(Dir, String), String> {
        let r = if create {
            self.ws.parent_create(path)
        } else {
            self.ws.parent(path)
        };
        match r {
            Ok((d, n)) => Ok((d, n.to_owned())),
            Err(IoError::Io(e)) if e.kind() == io::ErrorKind::NotFound && !create => {
                Err("parent_missing".into())
            }
            Err(IoError::Io(e)) => Err(format!("io: {e}")),
            Err(_) => Err("parent_not_followed".into()),
        }
    }

    /// Applies one mutation under the full WAL pattern.
    pub(crate) fn apply(&mut self, m: &Mutation, bytes: Option<&[u8]>) -> Result<Outcome> {
        let (dir, name) = match self.parent(&m.path, bytes.is_some()) {
            Ok(p) => p,
            Err(reason) => {
                self.append("m.intent", json!({"mutation": m}))?;
                return self.conflict(m, &reason, None, &[], &[]);
            }
        };
        self.append("m.intent", json!({"mutation": m}))?;
        fault(&format!("materialize.{}.after_intent", m.step));
        interleave(&format!("{}.after_intent", m.step), &dir, "");
        self.forward(&dir, &name, m, bytes, false)
    }

    fn forward(
        &mut self,
        dir: &Dir,
        name: &str,
        m: &Mutation,
        bytes: Option<&[u8]>,
        backup_verified: bool,
    ) -> Result<Outcome> {
        // 2. Preserve the verified original, from the handle that is hashed.
        if let Some(before) = &m.before
            && !backup_verified
        {
            let backup = self.backup(&m.step);
            let got = match dir.open_with(
                name,
                OpenOptions::new().read(true).follow(FollowSymlinks::No),
            ) {
                Ok(mut f) => {
                    let mut content = vec![];
                    f.read_to_end(&mut content)?;
                    let d = digest_of(&content);
                    if d == *before {
                        disk_full(&format!("{}.backup", m.step))?;
                        write_private(&backup, &content)?;
                    }
                    Some(d)
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            };
            if got.as_ref() != Some(before) {
                return self.conflict(m, "changed_before_mutation", Some((dir, name)), &[], &[]);
            }
            self.append("m.backup", json!({"step": m.step, "digest": before}))?;
            fault(&format!("materialize.{}.after_backup", m.step));
        }
        let temp = self.temp(&m.step);
        interleave(&format!("{}.after_backup", m.step), dir, &temp);
        match bytes {
            Some(content) => {
                // 3. Mutate through a synced temp file in the same directory.
                let _ = dir.remove_file(&temp);
                let written = (|| -> io::Result<u64> {
                    let mut f =
                        dir.open_with(&temp, OpenOptions::new().write(true).create_new(true))?;
                    disk_full(&format!("{}.temp", m.step))?;
                    f.write_all(content)?;
                    // A replacement keeps the displaced file's mode (an executable stays one).
                    if m.before.is_some()
                        && let Ok(md) = dir.symlink_metadata(name)
                        && md.is_file()
                    {
                        f.set_permissions(carried(md.permissions()))?;
                    }
                    f.sync_all()?;
                    f.metadata().map(|md| md.ino())
                })();
                // A failed write (ENOSPC, EIO) leaves no partial temp behind: the tree is
                // untouched and a resume starts the step again.
                let ino = match written {
                    Ok(ino) => ino,
                    Err(e) => {
                        let _ = remove(dir, &temp);
                        return Err(e.into());
                    }
                };
                fault(&format!("materialize.{}.after_temp", m.step));
                if m.before.is_none() {
                    match self.prims.rename_noreplace(dir, &temp, name) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                            return self.conflict(
                                m,
                                "created_concurrently",
                                Some((dir, name)),
                                &[(&temp, "ours")],
                                &[],
                            );
                        }
                        Err(e) => {
                            let _ = dir.remove_file(&temp);
                            return Err(e.into());
                        }
                    }
                }
                let trash = self.trash(&m.step);
                if m.before.is_some() && dir.symlink_metadata(&trash).is_ok() {
                    return self.conflict(
                        m,
                        "unexpected_trash",
                        Some((dir, name)),
                        &[(&trash, "trash"), (&temp, "ours")],
                        &[],
                    );
                }
                // Where the displaced original is after the mutation (replacement only).
                let displaced: &str = if m.before.is_none() {
                    &temp
                } else if self.prims.atomic() {
                    match self.prims.replace(dir, &temp, name, &trash) {
                        Ok(at) => at,
                        // Displaced, then someone created the path in the gap: keep all three.
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                            return self.conflict(
                                m,
                                "created_concurrently",
                                Some((dir, name)),
                                &[(&trash, "displaced"), (&temp, "ours")],
                                &[],
                            );
                        }
                        Err(e) => return Err(e.into()),
                    }
                } else {
                    // `--allow-unsafe-fs` only (checked before the run): the original is in the
                    // backup, but a write in the window before this rename is lost.
                    dir.rename(&temp, dir, name)?;
                    &temp
                };
                sync_dir(dir)?;
                fault(&format!("materialize.{}.after_mutate", m.step));
                interleave(&format!("{}.after_mutate", m.step), dir, displaced);
                // Post-mutation identity: Calve's inode, with the expected digest.
                let now = state(dir, name)?;
                if now.as_ref().map(|(d, i)| (Some(d), *i)) != Some((m.after.as_ref(), ino)) {
                    let moves: &[(&str, &str)] = if m.before.is_some() && self.prims.atomic() {
                        &[(displaced, "displaced")]
                    } else {
                        &[]
                    };
                    return self.conflict(
                        m,
                        "post_mutation_identity",
                        Some((dir, name)),
                        moves,
                        &[("ours", content)],
                    );
                }
                // 4. The displaced original must be what was preserved.
                if m.before.is_some() && self.prims.atomic() {
                    if digest_at(dir, displaced)? != m.before {
                        return self.conflict(
                            m,
                            "displaced_changed",
                            Some((dir, name)),
                            &[(displaced, "displaced")],
                            &[("ours", content)],
                        );
                    }
                    remove(dir, displaced)?;
                }
            }
            None if m.before.is_some() => {
                let trash = self.trash(&m.step);
                if self.prims.atomic() {
                    self.prims.rename_noreplace(dir, name, &trash)?;
                } else {
                    dir.rename(name, dir, &trash)?;
                }
                sync_dir(dir)?;
                fault(&format!("materialize.{}.after_mutate", m.step));
                if digest_at(dir, &trash)? != m.before {
                    return self.conflict(
                        m,
                        "displaced_changed",
                        Some((dir, name)),
                        &[(&trash, "displaced")],
                        &[],
                    );
                }
                remove(dir, &trash)?;
            }
            None => {}
        }
        sync_dir(dir)?;
        self.append(
            "m.done",
            json!({"step": m.step, "observed_after": m.after, "atomic": self.prims.atomic(),
                "primitives": self.prims.name()}),
        )?;
        fault(&format!("materialize.{}.after_done", m.step));
        Ok(Outcome::Done)
    }

    /// Keeps the evidence (`moves`: names in `dir` moved out of the tree; `writes`: bytes) under
    /// `.calve/conflicts/<op>/<step>/` and journals `m.conflicted`. Never deletes anything.
    fn conflict(
        &mut self,
        m: &Mutation,
        reason: &str,
        at: Option<(&Dir, &str)>,
        moves: &[(&str, &str)],
        writes: &[(&str, &[u8])],
    ) -> Result<Outcome> {
        let cd = self.conflicts(&m.step);
        private_dir(&cd)?;
        let mut current = None;
        if let Some((dir, name)) = at {
            for (from, to) in moves {
                if dir.symlink_metadata(from).is_ok_and(|md| md.is_file()) {
                    write_private(&cd.join(to), &read_at(dir, from)?)?;
                    remove(dir, from)?;
                }
            }
            current = digest_at(dir, name).unwrap_or_default();
        }
        for (to, bytes) in writes {
            write_private(&cd.join(to), bytes)?;
        }
        let meta = json!({"op": self.op, "step": m.step, "path": m.path, "reason": reason,
            "expected_before": m.before, "expected_after": m.after, "current": current});
        write_private(&cd.join("meta.json"), &serde_json::to_vec_pretty(&meta)?)?;
        self.append(
            "m.conflicted",
            json!({"step": m.step, "reason": reason, "current": current}),
        )?;
        Ok(Outcome::Conflicted(reason.to_owned()))
    }

    fn backup_verifies(&self, records: &[Record], m: &Mutation) -> bool {
        m.before.as_ref().is_some_and(|before| {
            records
                .iter()
                .any(|r| r.kind == "m.backup" && r.body["step"] == m.step.as_str())
                && std::fs::read(self.backup(&m.step)).is_ok_and(|b| digest_of(&b) == *before)
        })
    }

    /// Settles a mutation whose intent has no `m.done`/`m.conflicted` (§14 reconciliation).
    pub(crate) fn reconcile(
        &mut self,
        records: &[Record],
        m: &Mutation,
        bytes: Option<&[u8]>,
    ) -> Result<Outcome> {
        let (dir, name) = match self.parent(&m.path, bytes.is_some()) {
            Ok(p) => p,
            Err(reason) => return self.conflict(m, &reason, None, &[], &[]),
        };
        let (temp, trash) = (self.temp(&m.step), self.trash(&m.step));
        let cur = match digest_at(&dir, &name) {
            Ok(c) => c,
            Err(_) => return self.conflict(m, "unexpected_state", None, &[], &[]),
        };
        let backup_ok = self.backup_verifies(records, m);
        let stray = |d: &Dir, n: &str| digest_at(d, n).ok().flatten();
        if cur == m.after {
            if m.before.is_some() && !backup_ok {
                return self.conflict(
                    m,
                    "evidence_missing",
                    Some((&dir, &name)),
                    &[(&temp, "displaced"), (&trash, "displaced")],
                    &[],
                );
            }
            for n in [&temp, &trash] {
                match stray(&dir, n) {
                    None => {}
                    Some(d) if Some(&d) == m.before.as_ref() || Some(&d) == m.after.as_ref() => {
                        remove(&dir, n)?
                    }
                    Some(_) => {
                        return self.conflict(
                            m,
                            "displaced_changed",
                            Some((&dir, &name)),
                            &[(n, "displaced")],
                            &[],
                        );
                    }
                }
            }
            sync_dir(&dir)?;
            self.append(
                "m.done",
                json!({"step": m.step, "observed_after": m.after, "resolved_by": "reconcile"}),
            )?;
            return Ok(Outcome::Done);
        }
        if cur == m.before {
            match stray(&dir, &temp) {
                None => {}
                Some(d) if Some(&d) == m.after.as_ref() => remove(&dir, &temp)?,
                Some(_) => {
                    return self.conflict(
                        m,
                        "unexpected_temp",
                        Some((&dir, &name)),
                        &[(&temp, "temp")],
                        &[],
                    );
                }
            }
            if stray(&dir, &trash).is_some() {
                return self.conflict(
                    m,
                    "unexpected_trash",
                    Some((&dir, &name)),
                    &[(&trash, "trash")],
                    &[],
                );
            }
            return self.forward(&dir, &name, m, bytes, backup_ok);
        }
        // Crashed between displace and place (two-rename replacement): the original is in the
        // trash and Calve's bytes in the temp, both verified; finish placing (no-replace).
        if cur.is_none()
            && m.before.is_some()
            && m.after.is_some()
            && backup_ok
            && stray(&dir, &trash) == m.before
            && stray(&dir, &temp) == m.after
        {
            match self.prims.rename_noreplace(&dir, &temp, &name) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    return self.conflict(
                        m,
                        "created_concurrently",
                        Some((&dir, &name)),
                        &[(&trash, "displaced"), (&temp, "ours")],
                        &[],
                    );
                }
                Err(e) => return Err(e.into()),
            }
            sync_dir(&dir)?;
            if digest_at(&dir, &name)? != m.after {
                return self.conflict(
                    m,
                    "post_mutation_identity",
                    Some((&dir, &name)),
                    &[(&trash, "displaced")],
                    &[],
                );
            }
            remove(&dir, &trash)?;
            sync_dir(&dir)?;
            self.append(
                "m.done",
                json!({"step": m.step, "observed_after": m.after, "resolved_by": "reconcile"}),
            )?;
            return Ok(Outcome::Done);
        }
        self.conflict(
            m,
            "unexpected_state",
            Some((&dir, &name)),
            &[(&temp, "temp"), (&trash, "trash")],
            &[],
        )
    }

    /// Reverses a done mutation after revalidating the path chain, the current content and the
    /// backup; any failure is `Conflicted(rollback_*)` with the current bytes kept and nothing
    /// overwritten.
    pub(crate) fn reverse(&mut self, m: &Mutation) -> Result<Outcome> {
        let r = Mutation {
            step: format!("r{}", m.step),
            path: m.path.clone(),
            before: m.after.clone(),
            after: m.before.clone(),
        };
        let (dir, name) = match self.parent(&m.path, false) {
            Ok(p) => p,
            Err(reason) => {
                self.append("m.intent", json!({"mutation": r}))?;
                return self.conflict(&r, &format!("rollback_{reason}"), None, &[], &[]);
            }
        };
        let backup = match &m.before {
            Some(before) => match std::fs::read(self.backup(&m.step)) {
                Ok(b) if digest_of(&b) == *before => Some(b),
                _ => {
                    self.append("m.intent", json!({"mutation": r}))?;
                    return self.conflict(
                        &r,
                        "rollback_backup_damaged",
                        Some((&dir, &name)),
                        &[],
                        &[],
                    );
                }
            },
            None => None,
        };
        let cur = digest_at(&dir, &name).ok().flatten();
        if cur != m.after {
            self.append("m.intent", json!({"mutation": r}))?;
            let current = if cur.is_some() {
                read_at(&dir, &name).ok()
            } else {
                None
            };
            let writes: Vec<(&str, &[u8])> =
                current.iter().map(|c| ("current", c.as_slice())).collect();
            return self.conflict(&r, "rollback_changed", Some((&dir, &name)), &[], &writes);
        }
        self.apply(&r, backup.as_deref())
    }
}

/// The mutation of each `m.intent`, in order, with whether it reached `m.done` /
/// `m.conflicted`.
pub(crate) fn mutations(records: &[Record]) -> Vec<(Mutation, Option<&'static str>)> {
    let mut out: Vec<(Mutation, Option<&'static str>)> = vec![];
    for r in records {
        match r.kind.as_str() {
            "m.intent" => {
                if let Ok(m) = serde_json::from_value(r.body["mutation"].clone()) {
                    out.push((m, None));
                }
            }
            "m.done" | "m.conflicted" => {
                let end = if r.kind == "m.done" {
                    "done"
                } else {
                    "conflicted"
                };
                if let Some(e) = out
                    .iter_mut()
                    .rev()
                    .find(|(m, _)| r.body["step"] == m.step.as_str())
                {
                    e.1 = Some(end);
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wal(root: &Path) -> Wal {
        Wal::create(root, json!({})).unwrap()
    }

    fn m(step: &str, path: &str, before: Option<&[u8]>, after: Option<&[u8]>) -> Mutation {
        Mutation {
            step: step.into(),
            path: path.into(),
            before: before.map(digest_of),
            after: after.map(digest_of),
        }
    }

    #[test]
    fn create_replace_delete_and_reverse_byte_for_byte() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        std::fs::write(root.join("a"), b"old").unwrap();
        std::fs::write(root.join("gone"), b"bye").unwrap();
        let mut w = wal(root);
        let ops = [
            (m("1", "dir/new", None, Some(b"new")), Some(&b"new"[..])),
            (
                m("2", "a", Some(b"old"), Some(b"fresh")),
                Some(&b"fresh"[..]),
            ),
            (m("3", "gone", Some(b"bye"), None), None),
        ];
        for (mu, bytes) in &ops {
            assert_eq!(w.apply(mu, *bytes).unwrap(), Outcome::Done);
        }
        assert_eq!(std::fs::read(root.join("dir/new")).unwrap(), b"new");
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"fresh");
        assert!(!root.join("gone").exists());
        let names: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            names
                .iter()
                .all(|n| !n.to_string_lossy().starts_with(".calve-")),
            "{names:?}"
        );
        for (mu, _) in ops.iter().rev() {
            assert_eq!(w.reverse(mu).unwrap(), Outcome::Done);
        }
        assert!(!root.join("dir/new").exists());
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"old");
        assert_eq!(std::fs::read(root.join("gone")).unwrap(), b"bye");
    }

    #[test]
    fn a_change_before_the_mutation_is_a_conflict_that_touches_nothing() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        std::fs::write(root.join("a"), b"theirs").unwrap();
        let mut w = wal(root);
        let mu = m("1", "a", Some(b"old"), Some(b"ours"));
        assert_eq!(
            w.apply(&mu, Some(b"ours")).unwrap(),
            Outcome::Conflicted("changed_before_mutation".into())
        );
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"theirs");
        assert!(w.conflicts("1").join("meta.json").is_file());
        // A concurrent create is caught by no-replace; Calve's bytes are kept.
        std::fs::write(root.join("b"), b"theirs").unwrap();
        let mu = m("2", "b", None, Some(b"ours"));
        assert_eq!(
            w.apply(&mu, Some(b"ours")).unwrap(),
            Outcome::Conflicted("created_concurrently".into())
        );
        assert_eq!(std::fs::read(root.join("b")).unwrap(), b"theirs");
        assert_eq!(
            std::fs::read(w.conflicts("2").join("ours")).unwrap(),
            b"ours"
        );
    }

    #[test]
    fn rollback_refuses_changed_content_damaged_backups_and_symlinked_parents() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        std::fs::create_dir(root.join("d")).unwrap();
        for f in ["a", "b", "d/c"] {
            std::fs::write(root.join(f), b"old").unwrap();
        }
        let mut w = wal(root);
        let ops: Vec<Mutation> = ["a", "b", "d/c"]
            .iter()
            .enumerate()
            .map(|(i, p)| m(&i.to_string(), p, Some(b"old"), Some(b"new")))
            .collect();
        for mu in &ops {
            assert_eq!(w.apply(mu, Some(b"new")).unwrap(), Outcome::Done);
        }
        std::fs::write(root.join("a"), b"edited later").unwrap();
        assert_eq!(
            w.reverse(&ops[0]).unwrap(),
            Outcome::Conflicted("rollback_changed".into())
        );
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"edited later");
        assert_eq!(
            std::fs::read(w.conflicts("r0").join("current")).unwrap(),
            b"edited later"
        );
        std::fs::write(w.backup("1"), b"damaged").unwrap();
        assert_eq!(
            w.reverse(&ops[1]).unwrap(),
            Outcome::Conflicted("rollback_backup_damaged".into())
        );
        assert_eq!(std::fs::read(root.join("b")).unwrap(), b"new");
        #[cfg(unix)]
        {
            let elsewhere = t.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            std::fs::rename(root.join("d"), root.join("d.moved")).unwrap();
            std::os::unix::fs::symlink(&elsewhere, root.join("d")).unwrap();
            assert_eq!(
                w.reverse(&ops[2]).unwrap(),
                Outcome::Conflicted("rollback_parent_not_followed".into())
            );
            assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
        }
    }

    #[test]
    fn weak_filesystems_create_without_replacing() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        let mut w = wal(root);
        w.prims = Box::new(Fallback);
        std::fs::write(root.join("x"), b"theirs").unwrap();
        let mu = m("1", "x", None, Some(b"ours"));
        assert_eq!(
            w.apply(&mu, Some(b"ours")).unwrap(),
            Outcome::Conflicted("created_concurrently".into())
        );
        let mu = m("2", "y", None, Some(b"ours"));
        assert_eq!(w.apply(&mu, Some(b"ours")).unwrap(), Outcome::Done);
        assert_eq!(std::fs::read(root.join("y")).unwrap(), b"ours");
    }

    /// chmod: a replacement keeps the displaced file's rwx bits and drops setuid/setgid.
    #[cfg(unix)]
    #[test]
    fn a_replacement_keeps_the_mode_without_setid_bits() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        for (f, mode) in [("run.sh", 0o755), ("suid", 0o4755), ("ro", 0o444)] {
            std::fs::write(root.join(f), b"old").unwrap();
            std::fs::set_permissions(root.join(f), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let mut w = wal(root);
        for (i, f) in ["run.sh", "suid", "ro"].iter().enumerate() {
            let mu = m(&i.to_string(), f, Some(b"old"), Some(b"new"));
            assert_eq!(w.apply(&mu, Some(b"new")).unwrap(), Outcome::Done);
        }
        let mode = |f: &str| {
            std::fs::metadata(root.join(f))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("run.sh"), 0o755);
        assert_eq!(mode("suid"), 0o755);
        assert_eq!(mode("ro"), 0o444);
        assert_eq!(std::fs::read(root.join("ro")).unwrap(), b"new");
    }

    /// A read-only file is replaced (keeping the flag) and deleted; nothing is left behind.
    #[test]
    fn read_only_files_are_replaced_and_deleted() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        for f in ["a", "b"] {
            std::fs::write(root.join(f), b"old").unwrap();
            let mut p = std::fs::metadata(root.join(f)).unwrap().permissions();
            p.set_readonly(true);
            std::fs::set_permissions(root.join(f), p).unwrap();
        }
        let mut w = wal(root);
        let replace = m("1", "a", Some(b"old"), Some(b"new"));
        assert_eq!(w.apply(&replace, Some(b"new")).unwrap(), Outcome::Done);
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"new");
        assert!(
            std::fs::metadata(root.join("a"))
                .unwrap()
                .permissions()
                .readonly()
        );
        let delete = m("2", "b", Some(b"old"), None);
        assert_eq!(w.apply(&delete, None).unwrap(), Outcome::Done);
        assert!(!root.join("b").exists());
        let names: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".calve-"))
            .collect();
        assert!(names.is_empty(), "{names:?}");
    }

    /// symlink: a symlink at the target is never followed; the file it points to is untouched.
    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_target_is_never_followed() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("tree");
        std::fs::create_dir(&root).unwrap();
        let outside = t.path().join("outside");
        std::fs::write(&outside, b"old").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("a")).unwrap();
        let mut w = wal(&root);
        let mu = m("1", "a", Some(b"old"), Some(b"new"));
        let r = w.apply(&mu, Some(b"new"));
        assert!(
            !matches!(r, Ok(Outcome::Done)),
            "a symlinked target was materialized: {r:?}"
        );
        assert_eq!(std::fs::read(&outside).unwrap(), b"old");
        assert!(
            std::fs::symlink_metadata(root.join("a"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // A delete through the symlink is refused the same way.
        let mu = m("2", "a", Some(b"old"), None);
        assert!(!matches!(w.apply(&mu, None), Ok(Outcome::Done)));
        assert_eq!(std::fs::read(&outside).unwrap(), b"old");
    }

    /// Sharing violation: another process holds the file without FILE_SHARE_DELETE. The step
    /// fails with the file untouched; once released, reconciliation completes it.
    #[cfg(windows)]
    #[test]
    fn a_sharing_violation_fails_the_step_and_reconcile_completes_it() {
        use std::os::windows::fs::OpenOptionsExt;
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        std::fs::write(root.join("a"), b"old").unwrap();
        let mut w = wal(root);
        assert_eq!(w.prims.name(), "windows-handle-rename");
        let mu = m("1", "a", Some(b"old"), Some(b"new"));
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1) // FILE_SHARE_READ only
            .open(root.join("a"))
            .unwrap();
        let e = w.apply(&mu, Some(b"new")).unwrap_err().to_string();
        assert!(
            e.contains("32") || e.to_lowercase().contains("used by another process"),
            "{e}"
        );
        drop(held);
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"old");
        let records = Journal::open(&runs(&w.root).join(&w.op).join("journal"))
            .unwrap()
            .records;
        assert_eq!(
            w.reconcile(&records, &mu, Some(b"new")).unwrap(),
            Outcome::Done
        );
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"new");
    }

    /// mkdir / rmdir: parents are created on demand (not journaled); a file in the parent chain
    /// or a directory at the path is never replaced; rollback removes files only, so created
    /// directories stay (documented limitation, ADR 0013).
    #[test]
    fn directories_are_created_on_demand_and_never_replaced() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        let mut w = wal(root);
        let create = m("1", "x/y/new", None, Some(b"new"));
        assert_eq!(w.apply(&create, Some(b"new")).unwrap(), Outcome::Done);
        assert_eq!(std::fs::read(root.join("x/y/new")).unwrap(), b"new");
        // A file where a parent directory is needed.
        std::fs::write(root.join("f"), b"file").unwrap();
        let under_file = m("2", "f/z", None, Some(b"z"));
        assert!(matches!(
            w.apply(&under_file, Some(b"z")).unwrap(),
            Outcome::Conflicted(_)
        ));
        assert_eq!(std::fs::read(root.join("f")).unwrap(), b"file");
        // A directory where a file is expected (replace and delete).
        std::fs::create_dir(root.join("d")).unwrap();
        std::fs::write(root.join("d/keep"), b"k").unwrap();
        for (step, after) in [("3", Some(&b"n"[..])), ("4", None)] {
            let mu = m(step, "d", Some(b"old"), after);
            assert!(!matches!(w.apply(&mu, after), Ok(Outcome::Done)));
            assert_eq!(std::fs::read(root.join("d/keep")).unwrap(), b"k");
        }
        // Rollback removes the file; the directories it needed stay.
        assert_eq!(w.reverse(&create).unwrap(), Outcome::Done);
        assert!(!root.join("x/y/new").exists());
        assert!(root.join("x/y").is_dir());
    }
}
