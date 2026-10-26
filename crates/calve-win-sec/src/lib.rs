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

    fn own_sid() -> io::Result<Vec<u8>> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle of the current process; `token` receives a new handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Owned(token);
        token_sid(token.0)
    }

    fn sid_string(sid: &[u8]) -> io::Result<String> {
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
}
