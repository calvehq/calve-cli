//! Windows primitives that need FFI (rev 10 §4, ADR 0016, ADR 0013): the only Calve crate
//! allowed `unsafe`. Each `unsafe` block is a single Win32 call with owned, NUL-terminated
//! UTF-16 arguments that outlive it, and states its SAFETY invariant. On other platforms the
//! crate is empty.
#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod imp {
    #![allow(unsafe_code)]

    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    fn wide(p: &OsStr) -> Vec<u16> {
        p.encode_wide().chain(Some(0)).collect()
    }

    fn check(ok: i32) -> io::Result<()> {
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Replaces `to` with `from` and returns only after the rename is on disk
    /// (`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`). Windows cannot fsync a directory
    /// through std, so this is the durable rename for atomic writes (ADR 0008, ADR 0013).
    pub fn rename_durable(from: &Path, to: &Path) -> io::Result<()> {
        let (f, t) = (wide(from.as_os_str()), wide(to.as_os_str()));
        // SAFETY: `f` and `t` are valid NUL-terminated UTF-16 strings that live until the call
        // returns; MoveFileExW does not retain them.
        check(unsafe {
            MoveFileExW(
                f.as_ptr(),
                t.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        })
    }

    /// Bytes available to the caller on the volume holding `path`.
    pub fn disk_free(path: &Path) -> Option<u64> {
        let p = wide(path.as_os_str());
        let mut free: u64 = 0;
        // SAFETY: `p` is a valid NUL-terminated UTF-16 string for the call; `free` is a valid,
        // writable u64; the two other out-parameters are null, which the API allows.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                p.as_ptr(),
                &mut free,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(free)
    }
}

#[cfg(windows)]
pub use imp::*;

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn durable_rename_replaces_and_disk_free_reports() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::write(&a, b"new").unwrap();
        std::fs::write(&b, b"old").unwrap();
        rename_durable(&a, &b).unwrap();
        assert_eq!(std::fs::read(&b).unwrap(), b"new");
        assert!(!a.exists());
        assert!(disk_free(d.path()).is_some_and(|f| f > 0));
    }
}
