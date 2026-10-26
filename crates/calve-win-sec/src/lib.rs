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

/// Parent-owned Job Objects (rev 10 §16.3, ADR 0017).
#[cfg(windows)]
mod job {
    #![allow(unsafe_code)]

    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME, TerminateProcess,
    };

    /// A Job Object the parent alone owns: created without inheritable security attributes,
    /// never duplicated, `KILL_ON_JOB_CLOSE`, no breakaway. Closing it (including when the
    /// parent dies) ends every process in it.
    pub struct Job(HANDLE);

    // SAFETY: a job handle is a kernel object handle; it may be used and closed from any
    // thread, and `Job` owns it exclusively (no copies are made).
    unsafe impl Send for Job {}

    /// Optional resource limits of a job.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Limits {
        pub memory_bytes: Option<u64>,
        pub active_processes: Option<u32>,
    }

    impl Job {
        pub fn new(limits: Limits) -> io::Result<Job> {
            // SAFETY: null security attributes (handle not inheritable) and a null name are
            // valid; the result is checked.
            let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Job(h);
            // SAFETY: a plain-old-data struct; all-zero is a valid value.
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if let Some(m) = limits.memory_bytes {
                info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
                info.JobMemoryLimit = m as usize;
            }
            if let Some(n) = limits.active_processes {
                info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                info.BasicLimitInformation.ActiveProcessLimit = n;
            }
            // SAFETY: `job.0` is a live job handle; `info` is a valid struct of the stated
            // size that outlives the call.
            let ok = unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        /// Spawns `cmd` suspended, assigns it to the job, then resumes it: the child never runs
        /// outside the job. If assignment fails (e.g. an outer job forbids nesting) the child is
        /// terminated and the error returned.
        pub fn spawn_suspended_in_job(&self, cmd: &mut Command) -> io::Result<Child> {
            let mut child = cmd.creation_flags(CREATE_SUSPENDED).spawn()?;
            let process = child.as_raw_handle() as HANDLE;
            // SAFETY: both handles are live for the call.
            if unsafe { AssignProcessToJobObject(self.0, process) } == 0 {
                let e = io::Error::last_os_error();
                // SAFETY: `process` is the live handle of our suspended child.
                unsafe { TerminateProcess(process, 1) };
                let _ = child.wait();
                return Err(e);
            }
            if let Err(e) = resume_threads(child.id()) {
                // SAFETY: as above.
                unsafe { TerminateProcess(process, 1) };
                let _ = child.wait();
                return Err(e);
            }
            Ok(child)
        }

        /// Whether the job handle could be inherited by a child (it never should).
        pub fn inheritable(&self) -> io::Result<bool> {
            let mut flags = 0u32;
            // SAFETY: live handle; `flags` is a valid out-parameter.
            if unsafe { GetHandleInformation(self.0, &mut flags) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(flags & HANDLE_FLAG_INHERIT != 0)
        }

        /// Processes currently in the job.
        pub fn active_processes(&self) -> io::Result<u32> {
            // SAFETY: plain-old-data; zero is valid.
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: live handle; `info` is writable for its full size during the call.
            let ok = unsafe {
                QueryInformationJobObject(
                    self.0,
                    JobObjectBasicAccountingInformation,
                    (&raw mut info).cast(),
                    std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(info.ActiveProcesses)
        }

        /// Terminates every process in the job, then waits (up to 10 s) until none is active.
        pub fn terminate(&self, code: u32) -> io::Result<()> {
            // SAFETY: live job handle.
            if unsafe { TerminateJobObject(self.0, code) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let t = Instant::now();
            while self.active_processes()? > 0 {
                if t.elapsed() > Duration::from_secs(10) {
                    return Err(io::Error::other("job processes did not exit"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: we own the handle and close it exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Resumes every thread of process `pid` (a freshly created suspended process has one).
    fn resume_threads(pid: u32) -> io::Result<()> {
        // SAFETY: valid flags; the result is checked.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: plain-old-data; dwSize set as the API requires.
        let mut te: THREADENTRY32 = unsafe { std::mem::zeroed() };
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut resumed = 0;
        // SAFETY: live snapshot handle; `te` is writable with dwSize set.
        let mut more = unsafe { Thread32First(snap, &mut te) } != 0;
        while more {
            if te.th32OwnerProcessID == pid {
                // SAFETY: a thread id from the snapshot; not inheritable; result checked.
                let t = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID) };
                if !t.is_null() {
                    // SAFETY: live thread handle, closed right after.
                    unsafe {
                        ResumeThread(t);
                        CloseHandle(t);
                    }
                    resumed += 1;
                }
            }
            // SAFETY: as for Thread32First.
            more = unsafe { Thread32Next(snap, &mut te) } != 0;
        }
        // SAFETY: we own the snapshot handle.
        unsafe { CloseHandle(snap) };
        if resumed == 0 {
            return Err(io::Error::other("no thread of the child to resume"));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use job::{Job, Limits};

/// The daemon's named pipe (rev 10 §16.2, ADR 0016). The boundary is the OS user: other users,
/// remote clients and pipe squatting by another user are refused; same-user processes are
/// trusted (as for ssh-agent).
#[cfg(windows)]
mod pipe {
    #![allow(unsafe_code)]

    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, RawHandle};
    use std::path::{Path, PathBuf};

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
        PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
        PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    /// SECURITY_IDENTIFICATION in the client's security QoS: the server may identify, never
    /// impersonate beyond that.
    const SECURITY_IDENTIFICATION: u32 = 1 << 16;

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    struct Owned(HANDLE);

    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: we own the handle and close it once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// The user SID (as bytes) of a token handle.
    fn token_sid(token: HANDLE) -> io::Result<Vec<u8>> {
        let mut len = 0u32;
        // SAFETY: a size query with a null buffer is allowed; `len` receives the size.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        let mut buf = vec![0u8; len as usize];
        // SAFETY: `buf` is writable for `len` bytes for the call.
        if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points into it.
        let user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
        let sid = user.User.Sid;
        // The SID bytes copied out, so the comparison never depends on `buf`'s lifetime.
        let sid_len = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
        // SAFETY: `sid` points to `sid_len` valid bytes inside `buf`.
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_len) }.to_vec())
    }

    pub(super) fn own_sid() -> io::Result<Vec<u8>> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle of the current process; `token` receives a new handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Owned(token);
        token_sid(token.0)
    }

    pub(super) fn sid_string(sid: &[u8]) -> io::Result<String> {
        let mut out: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` is a valid SID; `out` receives a LocalAlloc'ed string we free below.
        if unsafe { ConvertSidToStringSidW(sid.as_ptr() as *mut _, &mut out) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `out` is NUL-terminated UTF-16.
        let mut n = 0;
        while unsafe { *out.add(n) } != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, n) });
        // SAFETY: allocated by the API with LocalAlloc.
        unsafe { LocalFree(out.cast()) };
        Ok(s)
    }

    /// `\\.\pipe\calve-<hex(sha256(user SID ‖ data root))>` (the name is not a secret).
    pub fn pipe_name(
        data_root: &Path,
        sha256_hex: impl Fn(&[u8]) -> String,
    ) -> io::Result<PathBuf> {
        let mut key = sid_string(&own_sid()?)?.into_bytes();
        key.extend_from_slice(data_root.to_string_lossy().as_bytes());
        Ok(PathBuf::from(format!(
            r"\\.\pipe\calve-{}",
            &sha256_hex(&key)[..32]
        )))
    }

    /// A server instance: owner = the user, DACL = one ACE (read/write) for the user's SID, no
    /// inheritance; `first` adds FILE_FLAG_FIRST_PIPE_INSTANCE (a second daemon or a squatter
    /// makes creation fail); remote clients are rejected.
    pub fn create_server(name: &Path, first: bool) -> io::Result<NamedPipeServer> {
        let sid = sid_string(&own_sid()?)?;
        let sddl = wide(&format!("O:{sid}D:P(A;;GRGW;;;{sid})"));
        let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'ed descriptor.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let name = wide(&name.to_string_lossy());
        let open = PIPE_ACCESS_DUPLEX
            | FILE_FLAG_OVERLAPPED
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: valid NUL-terminated name and security attributes living through the call.
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                &sa,
            )
        };
        let err = io::Error::last_os_error();
        // SAFETY: the descriptor was allocated by the conversion API.
        unsafe { LocalFree(sd) };
        if h == INVALID_HANDLE_VALUE {
            return Err(err);
        }
        // SAFETY: `h` is a new, owned, overlapped named-pipe handle; tokio takes ownership.
        unsafe { NamedPipeServer::from_raw_handle(h as RawHandle) }
    }

    /// Per connection: the client's token user must be our own user. This enforces the
    /// other-user boundary; it is not authentication between same-user processes.
    pub fn verify_client(server: &NamedPipeServer) -> io::Result<()> {
        let pipe = server.as_raw_handle() as HANDLE;
        // SAFETY: live pipe handle with a connected client.
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the current thread now impersonates; open its token as ourselves.
        let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
        let sid = if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            let t = Owned(token);
            token_sid(t.0)
        };
        // SAFETY: always revert before anything else runs on this thread.
        unsafe { RevertToSelf() };
        let (client, own) = (sid?, own_sid()?);
        // SAFETY: both are valid SIDs.
        if unsafe { EqualSid(client.as_ptr() as *mut _, own.as_ptr() as *mut _) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pipe client is another user",
            ));
        }
        Ok(())
    }

    /// Opens the daemon pipe with SECURITY_IDENTIFICATION QoS.
    pub fn connect(name: &Path) -> io::Result<NamedPipeClient> {
        ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(name)
    }

    /// Client-side integrity check: the server process runs as our user and from
    /// `expected_exe`, re-checked while its handle is held (a stale binary or another user's
    /// squatter is refused; a same-user process is trusted).
    pub fn verify_server(client: &NamedPipeClient, expected_exe: &Path) -> io::Result<()> {
        let pipe = client.as_raw_handle() as HANDLE;
        let mut pid = 0u32;
        // SAFETY: live pipe handle; `pid` is a valid out-parameter.
        if unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: query-only access; result checked.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let process = Owned(process);
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: live process handle.
        if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Owned(token);
        let (server, own) = (token_sid(token.0)?, own_sid()?);
        // SAFETY: valid SIDs.
        if unsafe { EqualSid(server.as_ptr() as *mut _, own.as_ptr() as *mut _) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the daemon pipe belongs to another user",
            ));
        }
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` is writable for `len` UTF-16 units.
        if unsafe { QueryFullProcessImageNameW(process.0, 0, buf.as_mut_ptr(), &mut len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let exe = PathBuf::from(String::from_utf16_lossy(&buf[..len as usize]));
        let same = |a: &Path, b: &Path| {
            std::fs::canonicalize(a)
                .ok()
                .zip(std::fs::canonicalize(b).ok())
                .is_some_and(|(a, b)| a == b)
        };
        if !same(&exe, expected_exe) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "the daemon runs {} instead of {}",
                    exe.display(),
                    expected_exe.display()
                ),
            ));
        }
        // The PID still names the same server (no swap while we checked).
        let mut again = 0u32;
        // SAFETY: as above.
        if unsafe { GetNamedPipeServerProcessId(pipe, &mut again) } == 0 || again != pid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the daemon changed during the check",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use pipe::{
    connect as pipe_connect, create_server as pipe_server, pipe_name,
    verify_client as verify_pipe_client, verify_server as verify_pipe_server,
};

/// Generic credentials in the Windows Credential Manager (R5, dependency vetting A10): the
/// secret `keyring:<name>` is the generic credential `calve:<name>`, its blob UTF-16LE as
/// `cmdkey /generic:calve:<name> /user:calve /pass` and the Credential Manager UI store it.
#[cfg(windows)]
mod cred {
    #![allow(unsafe_code)]

    use std::io;

    use windows_sys::Win32::Security::Credentials::{
        CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
    };

    const ERROR_NOT_FOUND: i32 = 1168;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    pub fn target(name: &str) -> String {
        format!("calve:{name}")
    }

    /// The secret stored for `name`, `None` when there is none. The credential buffer is
    /// zeroed before it is freed; the caller owns (and should zeroize) the returned value.
    pub fn read(name: &str) -> io::Result<Option<String>> {
        let t = wide(&target(name));
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `t` is a valid NUL-terminated UTF-16 string for the call; `cred` is a valid
        // out-pointer that receives a buffer owned by the API, freed below with CredFree.
        if unsafe { CredReadW(t.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) } == 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(ERROR_NOT_FOUND) => Ok(None),
                _ => Err(error),
            };
        }
        // SAFETY: CredReadW succeeded, so `cred` points to a valid CREDENTIALW whose blob is
        // `CredentialBlobSize` readable bytes (or null when the size is 0). The blob is copied,
        // then zeroed and the buffer released exactly once.
        let units = unsafe {
            let c = &*cred;
            let size = c.CredentialBlobSize as usize;
            let units: Vec<u16> = if c.CredentialBlob.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(c.CredentialBlob, size)
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect()
            };
            if !c.CredentialBlob.is_null() {
                std::ptr::write_bytes(c.CredentialBlob, 0, size);
            }
            CredFree(cred.cast());
            units
        };
        let value = String::from_utf16(&units).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the credential is not UTF-16 text",
            )
        });
        let mut units = units;
        units.fill(0);
        value.map(Some)
    }

    /// Test support: stores a session-only generic credential and deletes it.
    #[cfg(test)]
    pub mod testing {
        use super::*;
        use windows_sys::Win32::Security::Credentials::{
            CRED_PERSIST_SESSION, CredDeleteW, CredWriteW,
        };

        pub fn write(name: &str, value: &str) -> io::Result<()> {
            let mut t = wide(&target(name));
            let mut user = wide("calve");
            let mut blob: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
            // SAFETY: CREDENTIALW is a plain C struct; all-zero is a valid empty value.
            let mut c: CREDENTIALW = unsafe { std::mem::zeroed() };
            c.Type = CRED_TYPE_GENERIC;
            c.TargetName = t.as_mut_ptr();
            c.UserName = user.as_mut_ptr();
            c.CredentialBlobSize = blob.len() as u32;
            c.CredentialBlob = blob.as_mut_ptr();
            c.Persist = CRED_PERSIST_SESSION;
            // SAFETY: every pointer in `c` refers to a buffer that outlives the call.
            if unsafe { CredWriteW(&c, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn delete(name: &str) {
            let t = wide(&target(name));
            // SAFETY: `t` is a valid NUL-terminated UTF-16 string for the call.
            unsafe { CredDeleteW(t.as_ptr(), CRED_TYPE_GENERIC, 0) };
        }
    }
}

#[cfg(windows)]
pub use cred::read as read_credential;

/// Owner-only directories (R18; the Windows form of Unix 0700): created with a protected DACL
/// granting full control to the user and SYSTEM only, inherited by everything inside. The
/// descriptor is applied by `CreateDirectoryW` itself, so the directory never exists with a
/// broader ACL. An existing directory is left as it is (callers own pre-existing trees).
#[cfg(windows)]
mod acl {
    #![allow(unsafe_code)]

    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    use super::pipe::{own_sid, sid_string};

    fn wide(p: &OsStr) -> Vec<u16> {
        p.encode_wide().chain(Some(0)).collect()
    }

    /// `path` as a private directory, creating missing parents the ordinary way first.
    pub fn create_private_dir(path: &Path) -> io::Result<()> {
        if path.is_dir() {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let sid = sid_string(&own_sid()?)?;
        let sddl = wide(OsStr::new(&format!(
            "O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"
        )));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'ed descriptor freed below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let p = wide(path.as_os_str());
        // SAFETY: `p` is NUL-terminated and `sa` (with its descriptor) lives through the call.
        let ok = unsafe { CreateDirectoryW(p.as_ptr(), &sa) };
        let error = io::Error::last_os_error();
        // SAFETY: allocated by the conversion above; freed once.
        unsafe { LocalFree(sd) };
        if ok == 0 {
            // Lost a race to another creator: the directory exists, as with create_dir_all.
            if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) && path.is_dir() {
                return Ok(());
            }
            return Err(error);
        }
        Ok(())
    }

    /// The owner and DACL of `path` in SDDL (for checks and diagnostics).
    pub fn security_sddl(path: &Path) -> io::Result<String> {
        let p = wide(path.as_os_str());
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `p` is NUL-terminated; the unused out-pointers are null as the API allows;
        // `sd` receives a LocalAlloc'ed descriptor freed below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                p.as_ptr(),
                SE_FILE_OBJECT,
                info,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut out: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sd` is the valid descriptor from above; `out` receives a LocalAlloc'ed
        // NUL-terminated string.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                info,
                &mut out,
                std::ptr::null_mut(),
            )
        };
        let error = io::Error::last_os_error();
        // SAFETY: allocated by GetNamedSecurityInfoW; freed once.
        unsafe { LocalFree(sd) };
        if ok == 0 {
            return Err(error);
        }
        let mut n = 0;
        // SAFETY: `out` is NUL-terminated UTF-16.
        while unsafe { *out.add(n) } != 0 {
            n += 1;
        }
        // SAFETY: `out` holds `n` valid units; it is freed once after the copy.
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, n) });
        unsafe { LocalFree(out.cast()) };
        Ok(text)
    }

    /// The current user's SID string (to read `security_sddl` output).
    pub fn user_sid() -> io::Result<String> {
        sid_string(&own_sid()?)
    }
}

#[cfg(windows)]
pub use acl::{create_private_dir, security_sddl, user_sid};

/// Handle-relative materialization primitives (§14, ADR 0013): renames by an open handle, so
/// no path is re-resolved between the identity check and the mutation.
#[cfg(windows)]
mod handle_fs {
    #![allow(unsafe_code)]

    use std::io;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_OPEN, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
        FileRenameInformation, NtCreateFile, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_WRITE, HANDLE, NTSTATUS, RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FlushFileBuffers, SYNCHRONIZE,
    };

    fn nt(status: NTSTATUS) -> io::Result<()> {
        if status < 0 {
            // SAFETY: a pure status-code translation.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    }
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    /// Renames the file open as `file` to `to` inside the directory open as `dir`: `to` is a
    /// bare name resolved against `dir` as RootDirectory. This is NtSetInformationFile
    /// directly: the Win32 SetFileInformationByHandle rejects a RootDirectory (error 87, found
    /// natively) and resolves a bare name against the process working directory instead.
    /// Without `replace` an existing `to` fails with `AlreadyExists` and nothing changes.
    /// `file` needs DELETE access.
    pub fn rename_by_handle(
        file: &impl AsRawHandle,
        dir: &impl AsRawHandle,
        to: &str,
        replace: bool,
    ) -> io::Result<()> {
        if to.is_empty() || to.contains(['\\', '/', ':']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rename target must be a bare file name",
            ));
        }
        let name: Vec<u16> = to.encode_utf16().collect();
        let name_bytes = name.len() * 2;
        let header = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
        let size = header + name_bytes + 2;
        // u64 storage keeps the buffer aligned for FILE_RENAME_INFORMATION.
        let mut buf = vec![0u64; size.div_ceil(8)];
        let info = buf.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        // SAFETY: `buf` is zeroed, aligned and at least `size` bytes: the header fields and
        // `name_bytes` of name (plus a NUL) fit; nothing else aliases it during the writes.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = u8::from(replace);
            (*info).RootDirectory = dir.as_raw_handle();
            (*info).FileNameLength = name_bytes as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
        }
        // SAFETY: both handles are open for the call; `info` points to `size` valid bytes and
        // `iosb` is a writable status block.
        let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut iosb,
                info.cast(),
                size as u32,
                FileRenameInformation,
            )
        };
        nt(status)
    }

    /// Flushes a directory's metadata (its entries) through a write handle opened relative to
    /// `dir` (empty name under RootDirectory = the directory itself); no path is resolved.
    /// (ReOpenFile on a directory handle is refused, found natively.)
    pub fn flush_dir_handle(dir: &impl AsRawHandle) -> io::Result<()> {
        let name = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: dir.as_raw_handle(),
            ObjectName: &name,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut h: HANDLE = std::ptr::null_mut();
        // SAFETY: zeroed IO_STATUS_BLOCK is a valid out-parameter.
        let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: `attrs`, `name` and `iosb` live through the call; `h` receives a handle we
        // own and close below.
        nt(unsafe {
            NtCreateFile(
                &mut h,
                GENERIC_WRITE | SYNCHRONIZE,
                &attrs,
                &mut iosb,
                std::ptr::null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        })?;
        // SAFETY: `h` is our handle, flushed and closed exactly once.
        let ok = unsafe { FlushFileBuffers(h) };
        let error = io::Error::last_os_error();
        unsafe { CloseHandle(h) };
        if ok == 0 {
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use handle_fs::{flush_dir_handle, rename_by_handle};

/// Which processes hold files open (Restart Manager; no administrator rights needed): for
/// diagnosing a refused rename or delete. Directory handles (e.g. a process's working
/// directory) are not reported.
#[cfg(windows)]
mod holders {
    #![allow(unsafe_code)]

    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::System::RestartManager::{
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
        RmStartSession,
    };

    const ERROR_MORE_DATA: u32 = 234;

    /// `(pid, application name)` of every process holding one of `files`.
    pub fn file_holders(files: &[&Path]) -> io::Result<Vec<(u32, String)>> {
        let mut session = 0u32;
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        // SAFETY: `session` and `key` are writable for the call (key has room for the
        // CCH_RM_SESSION_KEY characters and a NUL).
        let rc = unsafe { RmStartSession(&mut session, 0, key.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        struct End(u32);
        impl Drop for End {
            fn drop(&mut self) {
                // SAFETY: ends the session started above, once.
                unsafe { RmEndSession(self.0) };
            }
        }
        let _end = End(session);
        let wide: Vec<Vec<u16>> = files
            .iter()
            .map(|p| p.as_os_str().encode_wide().chain(Some(0)).collect())
            .collect();
        let ptrs: Vec<*const u16> = wide.iter().map(|w| w.as_ptr()).collect();
        // SAFETY: `ptrs` points to `ptrs.len()` NUL-terminated strings that outlive the call.
        let rc = unsafe {
            RmRegisterResources(
                session,
                ptrs.len() as u32,
                ptrs.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let mut infos: Vec<RM_PROCESS_INFO> = Vec::new();
        loop {
            let (mut needed, mut count, mut reasons) = (0u32, infos.len() as u32, 0u32);
            // SAFETY: `infos` has room for `count` entries (null when empty, count 0).
            let rc = unsafe {
                RmGetList(
                    session,
                    &mut needed,
                    &mut count,
                    if infos.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        infos.as_mut_ptr()
                    },
                    &mut reasons,
                )
            };
            if rc == ERROR_MORE_DATA {
                // SAFETY: RM_PROCESS_INFO is plain data; zeroed entries are valid inputs.
                infos.resize_with(needed as usize, || unsafe { std::mem::zeroed() });
                continue;
            }
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            infos.truncate(count as usize);
            return Ok(infos
                .iter()
                .map(|i| {
                    let n = i
                        .strAppName
                        .iter()
                        .position(|c| *c == 0)
                        .unwrap_or(i.strAppName.len());
                    (
                        i.Process.dwProcessId,
                        String::from_utf16_lossy(&i.strAppName[..n]),
                    )
                })
                .collect());
        }
    }
}

#[cfg(windows)]
pub use holders::file_holders;

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn eventually(mut f: impl FnMut() -> bool, secs: u64) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// `cmd` running a grandchild `ping` in the background and one in the foreground.
    fn tree() -> Command {
        let mut c = Command::new("cmd");
        c.args([
            "/c",
            "start /b ping -n 120 127.0.0.1 >nul & ping -n 120 127.0.0.1 >nul",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        c
    }

    #[test]
    fn terminating_the_job_ends_the_whole_tree() {
        let job = Job::new(Limits::default()).unwrap();
        assert!(
            !job.inheritable().unwrap(),
            "the job handle is never inheritable"
        );
        let mut child = job.spawn_suspended_in_job(&mut tree()).unwrap();
        assert!(
            eventually(|| job.active_processes().unwrap() >= 3, 15),
            "cmd and both pings are in the job"
        );
        job.terminate(1).unwrap();
        assert_eq!(job.active_processes().unwrap(), 0);
        assert!(child.wait().is_ok());
    }

    #[test]
    fn closing_the_job_ends_the_tree() {
        let job = Job::new(Limits::default()).unwrap();
        let mut child = job.spawn_suspended_in_job(&mut tree()).unwrap();
        assert!(eventually(|| job.active_processes().unwrap() >= 3, 15));
        drop(job);
        let t = Instant::now();
        let _ = child.wait();
        assert!(t.elapsed() < Duration::from_secs(10), "KILL_ON_JOB_CLOSE");
    }

    #[test]
    fn the_active_process_limit_is_enforced() {
        let job = Job::new(Limits {
            memory_bytes: None,
            active_processes: Some(1),
        })
        .unwrap();
        let mut child = job
            .spawn_suspended_in_job(Command::new("cmd").args(["/c", "ping -n 2 127.0.0.1 >nul"]))
            .unwrap();
        let status = child.wait().unwrap();
        assert!(
            !status.success(),
            "cmd may not start a second process in the job"
        );
    }

    /// The parent dies (killed): the job closes with it and the tree goes.
    #[test]
    fn a_killed_parent_takes_the_tree_with_it() {
        if let Some(out) = std::env::var_os("CALVE_JOB_PARENT") {
            let job = Job::new(Limits::default()).unwrap();
            // Never waited on: this parent is killed and the job ends the child.
            #[allow(clippy::zombie_processes)]
            let child = job.spawn_suspended_in_job(&mut tree()).unwrap();
            std::fs::write(out, child.id().to_string()).unwrap();
            std::thread::sleep(Duration::from_secs(120));
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("pid");
        let mut parent = Command::new(std::env::current_exe().unwrap())
            .args(["tests::a_killed_parent_takes_the_tree_with_it", "--exact"])
            .env("CALVE_JOB_PARENT", &file)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        assert!(eventually(|| file.exists(), 30));
        std::thread::sleep(Duration::from_millis(500));
        let pid = std::fs::read_to_string(&file).unwrap();
        parent.kill().unwrap();
        let _ = parent.wait();
        let alive = || {
            let out = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid.trim()), "/NH"])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).contains(pid.trim())
        };
        assert!(
            eventually(|| !alive(), 10),
            "the job's processes died with their parent"
        );
    }

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

    #[test]
    fn generic_credentials_round_trip() {
        let name = format!("test-{}", std::process::id());
        assert_eq!(read_credential(&name).unwrap(), None);
        cred::testing::write(&name, "s3cr\u{e9}t").unwrap();
        let read = read_credential(&name);
        cred::testing::delete(&name);
        assert_eq!(read.unwrap().as_deref(), Some("s3cr\u{e9}t"));
        assert_eq!(read_credential(&name).unwrap(), None);
    }

    #[test]
    fn private_directories_are_owner_only_and_inherit() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("a").join("private");
        create_private_dir(&dir).unwrap();
        create_private_dir(&dir).unwrap();
        std::fs::write(dir.join("f"), b"x").unwrap();
        let sid = user_sid().unwrap();
        let own = security_sddl(&dir).unwrap();
        assert_eq!(
            own,
            format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"),
            "{own}"
        );
        // The file inside carries only the inherited ACEs (ID flag), nothing broader.
        let file = security_sddl(&dir.join("f")).unwrap();
        let dacl = &file[file.find("D:").unwrap()..];
        assert_eq!(dacl, format!("D:(A;ID;FA;;;{sid})(A;ID;FA;;;SY)"), "{file}");
    }

    fn open_dir(path: &std::path::Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0200_0000) // FILE_FLAG_BACKUP_SEMANTICS
            .open(path)
            .unwrap()
    }

    fn open_delete(path: &std::path::Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt;
        // DELETE | FILE_READ_ATTRIBUTES; share everything (the WAL must not block others).
        std::fs::OpenOptions::new()
            .access_mode(0x0001_0000 | 0x80)
            .share_mode(7)
            .open(path)
            .unwrap()
    }

    #[test]
    fn handle_renames_never_replace_unless_asked() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::write(&a, b"A").unwrap();
        std::fs::write(&b, b"B").unwrap();
        let dir = open_dir(d.path());
        let fa = open_delete(&a);
        let e = rename_by_handle(&fa, &dir, "b", false).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{e}");
        assert_eq!(std::fs::read(&b).unwrap(), b"B");
        rename_by_handle(&fa, &dir, "c", false).unwrap();
        drop(fa);
        assert!(!a.exists());
        assert_eq!(std::fs::read(d.path().join("c")).unwrap(), b"A");
        // Never relative to the process working directory.
        assert!(!std::env::current_dir().unwrap().join("c").exists());
        let fb = open_delete(&b);
        assert!(rename_by_handle(&fb, &dir, "..\\x", false).is_err());
        assert!(rename_by_handle(&fb, &dir, "sub/x", false).is_err());
        rename_by_handle(&fb, &dir, "c", true).unwrap();
        drop(fb);
        assert_eq!(std::fs::read(d.path().join("c")).unwrap(), b"B");
    }

    /// A file held open without FILE_SHARE_DELETE cannot be moved: a sharing violation, and
    /// nothing changes.
    #[test]
    fn a_sharing_violation_leaves_the_file_in_place() {
        use std::os::windows::fs::OpenOptionsExt;
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        std::fs::write(&a, b"A").unwrap();
        let _held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&a)
            .unwrap();
        let e = std::fs::OpenOptions::new()
            .access_mode(0x0001_0000)
            .share_mode(7)
            .open(&a)
            .unwrap_err();
        assert_eq!(e.raw_os_error(), Some(32), "{e}");
        assert_eq!(std::fs::read(&a).unwrap(), b"A");
    }

    #[test]
    fn a_directory_handle_flushes() {
        let d = tempfile::tempdir().unwrap();
        let dir = open_dir(d.path());
        flush_dir_handle(&dir).unwrap();
    }

    /// Isolation experiment (M5 E, ignored): how often does renaming a directory fail right
    /// after a file is written into it, for PE bytes (an executable) vs. the same number of
    /// non-PE bytes, single-threaded and 8 threads in parallel? `CALVE_FIXTURE_EXT` names the
    /// PE file. Prints the counts; asserts nothing.
    #[test]
    #[ignore = "experiment"]
    fn rename_after_write_experiment() {
        // A 1 MiB prefix keeps the MZ/PE headers scanners key on without filling the disk.
        let mut pe =
            std::fs::read(std::env::var_os("CALVE_FIXTURE_EXT").expect("CALVE_FIXTURE_EXT"))
                .unwrap();
        pe.truncate(1 << 20);
        let other = vec![0x5au8; pe.len()];
        for (label, bytes) in [("pe", &pe), ("non-pe", &other)] {
            for threads in [1usize, 8] {
                let d = tempfile::tempdir().unwrap();
                let fails = std::sync::atomic::AtomicUsize::new(0);
                let codes = std::sync::Mutex::new(std::collections::BTreeMap::<i32, usize>::new());
                std::thread::scope(|s| {
                    for t in 0..threads {
                        let (d, fails, codes) = (d.path(), &fails, &codes);
                        s.spawn(move || {
                            for i in 0..(200 / threads) {
                                let a = d.join(format!("s-{t}-{i}"));
                                std::fs::create_dir(&a).unwrap();
                                std::fs::write(a.join("ext.exe"), bytes).unwrap();
                                let b = d.join(format!("f-{t}-{i}"));
                                let r = std::fs::rename(&a, &b);
                                let _ = std::fs::remove_dir_all(&a);
                                let _ = std::fs::remove_dir_all(&b);
                                if let Err(e) = r {
                                    fails.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    *codes
                                        .lock()
                                        .unwrap()
                                        .entry(e.raw_os_error().unwrap_or(-1))
                                        .or_default() += 1;
                                }
                            }
                        });
                    }
                });
                println!(
                    "experiment {label} threads={threads}: {} of 200 renames failed {:?}",
                    fails.into_inner(),
                    codes.into_inner().unwrap()
                );
            }
        }
    }

    /// Isolation experiment 2 (M5 E, ignored): rename a directory right after a process run
    /// from it has exited (waited), vs. the same copy never executed. Small PE: whoami.exe.
    #[test]
    #[ignore = "experiment"]
    fn rename_after_execute_experiment() {
        // `CALVE_EXPERIMENT_EXE` (e.g. the unsigned 110 MB fixture) or a small signed tool;
        // `CALVE_EXPERIMENT_N` iterations per configuration (default 160).
        let exe = std::fs::read(
            std::env::var_os("CALVE_EXPERIMENT_EXE")
                .unwrap_or_else(|| r"C:\Windows\System32\whoami.exe".into()),
        )
        .unwrap();
        let total: usize = std::env::var("CALVE_EXPERIMENT_N")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(160);
        for run in [true, false] {
            for threads in [1usize, 4] {
                let d = tempfile::tempdir().unwrap();
                let codes = std::sync::Mutex::new(std::collections::BTreeMap::<i32, usize>::new());
                let retried_ok = std::sync::atomic::AtomicUsize::new(0);
                std::thread::scope(|s| {
                    for t in 0..threads {
                        let (d, exe, codes, retried_ok) = (d.path(), &exe, &codes, &retried_ok);
                        s.spawn(move || {
                            for i in 0..(total / threads) {
                                let a = d.join(format!("s-{t}-{i}"));
                                std::fs::create_dir(&a).unwrap();
                                let p = a.join("tool.exe");
                                std::fs::write(&p, exe).unwrap();
                                if run {
                                    // Exit status irrelevant (the fixture expects a protocol on
                                    // stdin): only that it ran and was waited for.
                                    let mut c = Command::new(&p);
                                    // `CALVE_EXPERIMENT_CWD=1`: the child runs with the directory
                                    // being renamed as its working directory (as OpenAEVC's
                                    // extension host does).
                                    if std::env::var_os("CALVE_EXPERIMENT_CWD").is_some() {
                                        c.current_dir(&a);
                                    }
                                    let _ = c
                                        .stdin(Stdio::null())
                                        .stdout(Stdio::null())
                                        .stderr(Stdio::null())
                                        .status()
                                        .unwrap();
                                }
                                let b = d.join(format!("f-{t}-{i}"));
                                if let Err(e) = std::fs::rename(&a, &b) {
                                    *codes
                                        .lock()
                                        .unwrap()
                                        .entry(e.raw_os_error().unwrap_or(-1))
                                        .or_default() += 1;
                                    // Does it succeed shortly after?
                                    for _ in 0..50 {
                                        std::thread::sleep(Duration::from_millis(20));
                                        if std::fs::rename(&a, &b).is_ok() {
                                            retried_ok
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            break;
                                        }
                                    }
                                }
                                let _ = std::fs::remove_dir_all(&a);
                                let _ = std::fs::remove_dir_all(&b);
                            }
                        });
                    }
                });
                println!(
                    "experiment executed={run} threads={threads}: failed {:?} of {total}; succeeded on retry within 1 s: {}",
                    codes.into_inner().unwrap(),
                    retried_ok.into_inner()
                );
            }
        }
    }

    #[test]
    fn file_holders_names_the_process_holding_a_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("held.txt");
        std::fs::write(&f, b"x").unwrap();
        assert!(file_holders(&[&f]).unwrap().is_empty());
        let _held = std::fs::File::open(&f).unwrap();
        let holders = file_holders(&[&f]).unwrap();
        assert!(
            holders.iter().any(|(pid, _)| *pid == std::process::id()),
            "{holders:?}"
        );
    }
}
