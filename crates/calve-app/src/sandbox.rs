//! CIC host (rev 10 §6.2, §6.7; ADR 0004, ADR 0018): module validation, one fresh wasmi
//! instance per session, fuel slices with a soft wall-clock deadline, the exact buffer and
//! bounds rules, and the supervised child (`calve __cic-sandbox`) that the parent kills on the
//! hard deadline. Isolation comes from wasm without imports; the child's self-restriction is
//! defense in depth only.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

use calve_integration_contract::abi;
use calve_integration_contract::driver::{Driver, HostError, frame};
use calve_integration_contract::jcs;
use sha2::{Digest, Sha256};
use wasmi::{
    CompilationMode, Config, Engine, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, TrapCode, TypedFunc, TypedResumableCall,
};
use wasmi_core::{LimiterError, ResourceLimiter};

pub const SANDBOX_MODE: &str = "__cic-sandbox";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostConfig {
    pub max_memory: usize,
    pub max_table: u32,
    pub max_module: usize,
    pub max_request: u32,
    pub max_response: u32,
    pub fuel_slice: u64,
    pub fuel_per_call: u64,
    pub soft_deadline: Duration,
    pub hard_deadline: Duration,
}

impl Default for HostConfig {
    fn default() -> Self {
        let l = abi::Limits::default();
        HostConfig {
            max_memory: l.max_memory_bytes as usize,
            max_table: l.max_table_elements,
            max_module: l.max_module_bytes as usize,
            max_request: l.max_request,
            max_response: l.max_response,
            fuel_slice: l.fuel_slice,
            fuel_per_call: l.fuel_per_call,
            soft_deadline: Duration::from_millis(l.soft_deadline_ms),
            hard_deadline: Duration::from_millis(l.hard_deadline_ms),
        }
    }
}

fn abi_err(m: impl Into<String>) -> HostError {
    HostError::AbiViolation(m.into())
}

/// Rejects anything outside the ABI shape before compilation (§6.2 guest lifecycle step 1):
/// no imports, no start section, exactly one memory within the cap, tables within the cap, the
/// exact export set (immutable global exports allowed and ignored, FG4).
pub fn validate_module(bytes: &[u8], cfg: &HostConfig) -> Result<(), HostError> {
    use wasmparser::{ExternalKind, Payload};
    if bytes.len() > cfg.max_module {
        return Err(abi_err("module too large"));
    }
    wasmparser::Validator::new()
        .validate_all(bytes)
        .map_err(|e| abi_err(format!("invalid module: {e}")))?;
    let (mut memories, mut exports, mut global_mut) = (0, Vec::new(), Vec::new());
    let cap_pages = (cfg.max_memory / 65536) as u64;
    for p in wasmparser::Parser::new(0).parse_all(bytes) {
        match p.map_err(|e| abi_err(e.to_string()))? {
            Payload::ImportSection(s) if s.count() > 0 => return Err(abi_err("imports present")),
            Payload::StartSection { .. } => return Err(abi_err("start section present")),
            Payload::GlobalSection(s) => {
                for g in s {
                    global_mut.push(g.map_err(|e| abi_err(e.to_string()))?.ty.mutable);
                }
            }
            Payload::MemorySection(s) => {
                for m in s {
                    let m = m.map_err(|e| abi_err(e.to_string()))?;
                    memories += 1;
                    if m.initial > cap_pages
                        || m.maximum.is_some_and(|max| max > cap_pages)
                        || m.memory64
                        || m.shared
                    {
                        return Err(abi_err("memory declaration exceeds the host cap"));
                    }
                }
            }
            Payload::TableSection(s) => {
                for t in s {
                    let t = t.map_err(|e| abi_err(e.to_string()))?;
                    if t.ty.initial > cfg.max_table as u64 {
                        return Err(abi_err("table too large"));
                    }
                }
            }
            Payload::ExportSection(s) => {
                for e in s {
                    let e = e.map_err(|e| abi_err(e.to_string()))?;
                    if e.kind == ExternalKind::Global {
                        if global_mut.get(e.index as usize) != Some(&false) {
                            return Err(abi_err("mutable global export"));
                        }
                        continue;
                    }
                    let want = if e.name == "memory" {
                        ExternalKind::Memory
                    } else {
                        ExternalKind::Func
                    };
                    if e.kind != want {
                        return Err(abi_err("export of the wrong kind"));
                    }
                    exports.push(e.name.to_owned());
                }
            }
            _ => {}
        }
    }
    if memories != 1 {
        return Err(abi_err("exactly one memory required"));
    }
    exports.sort();
    let mut want: Vec<&str> = abi::EXPORTS.to_vec();
    want.sort();
    if exports != want {
        return Err(abi_err("export set differs from the ABI"));
    }
    Ok(())
}

/// StoreLimits plus a record of denied growth, so a trap after a denied `memory.grow` is
/// reported as `OUT_OF_MEMORY`.
struct Limits {
    inner: StoreLimits,
    denied: bool,
}

impl ResourceLimiter for Limits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, LimiterError> {
        let ok = self.inner.memory_growing(current, desired, maximum)?;
        self.denied |= !ok;
        Ok(ok)
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, LimiterError> {
        let ok = self.inner.table_growing(current, desired, maximum)?;
        self.denied |= !ok;
        Ok(ok)
    }
    fn instances(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        1
    }
    fn memories(&self) -> usize {
        1
    }
}

/// In-process ABI 1 host over one fresh instance. Production sessions run it inside the
/// supervised child; tests also use it directly (determinism matrix, §6.8).
pub struct CalveHost {
    cfg: HostConfig,
    store: Store<Limits>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    free: TypedFunc<(i32, i32), ()>,
    init: TypedFunc<(i32, i32), i64>,
    call: TypedFunc<(i32, i32), i64>,
    dead: bool,
    /// Wall time and fuel slices of the last guest call (deadline tests).
    pub last_call: Duration,
    pub last_slices: u64,
    /// Most fuel slices any single guest call needed (sizing evidence).
    pub peak_slices: u64,
}

impl CalveHost {
    pub fn new(wasm: &[u8], cfg: HostConfig) -> Result<Self, HostError> {
        validate_module(wasm, &cfg)?;
        let mut config = Config::default();
        // Eager: lazy translation charges fuel and its out-of-fuel is not resumable (FG4).
        config
            .consume_fuel(true)
            .compilation_mode(CompilationMode::Eager);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, wasm).map_err(|e| abi_err(e.to_string()))?;
        let limits = StoreLimitsBuilder::new()
            .memory_size(cfg.max_memory)
            .table_elements(cfg.max_table as usize)
            .instances(1)
            .tables(1)
            .memories(1)
            .build();
        let mut store = Store::new(
            &engine,
            Limits {
                inner: limits,
                denied: false,
            },
        );
        store.limiter(|l| l);
        store
            .set_fuel(cfg.fuel_slice)
            .map_err(|e| HostError::Internal(e.to_string()))?;
        let instance = Linker::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .map_err(|e| map_err(&e, false))?;
        let f = |e: wasmi::Error| abi_err(format!("export signature: {e}"));
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| abi_err("memory"))?;
        let version: TypedFunc<(), i32> = instance
            .get_typed_func(&store, "cic_abi_version")
            .map_err(f)?;
        let mut host = CalveHost {
            cfg,
            memory,
            alloc: instance.get_typed_func(&store, "cic_alloc").map_err(f)?,
            free: instance.get_typed_func(&store, "cic_free").map_err(f)?,
            init: instance.get_typed_func(&store, "cic_init").map_err(f)?,
            call: instance.get_typed_func(&store, "cic_call").map_err(f)?,
            store,
            dead: false,
            last_call: Duration::ZERO,
            last_slices: 0,
            peak_slices: 0,
        };
        let v = host.run(&version, ())?;
        if v != abi::ABI_VERSION {
            return Err(abi_err(format!("cic_abi_version = {v}")));
        }
        Ok(host)
    }

    /// One guest call in fuel slices; between slices the host checks the wall clock and the
    /// per-call budget (F13: `set_fuel` needs `&mut Store`, so this runs on the calling
    /// thread). A resume grants `max(slice, required_fuel)` (bulk memory ops, FG4).
    fn run<P: wasmi::WasmParams, R: wasmi::WasmResults>(
        &mut self,
        f: &TypedFunc<P, R>,
        p: P,
    ) -> Result<R, HostError> {
        let start = Instant::now();
        let mut slices = 1;
        let mut granted = self.cfg.fuel_slice;
        self.store.data_mut().denied = false;
        self.store
            .set_fuel(self.cfg.fuel_slice)
            .map_err(|e| HostError::Internal(e.to_string()))?;
        let mut call = f.call_resumable(&mut self.store, p);
        let out = loop {
            match call {
                Err(e) => break Err(map_err(&e, self.store.data().denied)),
                Ok(TypedResumableCall::Finished(r)) => break Ok(r),
                Ok(TypedResumableCall::HostTrap(_)) => {
                    break Err(HostError::Internal("host trap without imports".into()));
                }
                Ok(TypedResumableCall::OutOfFuel(c)) => {
                    let next = self.cfg.fuel_slice.max(c.required_fuel());
                    if granted.saturating_add(next) > self.cfg.fuel_per_call {
                        break Err(HostError::OutOfFuel);
                    }
                    if start.elapsed() >= self.cfg.soft_deadline {
                        break Err(HostError::DeadlineExceeded);
                    }
                    slices += 1;
                    granted += next;
                    self.store
                        .set_fuel(next)
                        .map_err(|e| HostError::Internal(e.to_string()))?;
                    call = c.resume(&mut self.store);
                }
            }
        };
        self.last_call = start.elapsed();
        self.last_slices = slices;
        self.peak_slices = self.peak_slices.max(slices);
        out
    }

    fn invoke(
        &mut self,
        which: TypedFunc<(i32, i32), i64>,
        req: &[u8],
    ) -> Result<Vec<u8>, HostError> {
        if self.dead {
            return Err(HostError::Internal(
                "instance discarded after an error".into(),
            ));
        }
        let r = self.invoke_inner(which, req);
        self.dead |= r.is_err();
        r
    }

    fn invoke_inner(
        &mut self,
        which: TypedFunc<(i32, i32), i64>,
        req: &[u8],
    ) -> Result<Vec<u8>, HostError> {
        let n = u32::try_from(req.len())
            .ok()
            .filter(|n| *n <= self.cfg.max_request)
            .ok_or_else(|| HostError::Internal("request exceeds the limit".into()))?;
        if n < 2 {
            return Err(HostError::Internal("empty request".into()));
        }
        let alloc = self.alloc;
        let ptr = self.run(&alloc, n as i32)? as u32;
        if ptr == 0 {
            return Err(HostError::OutOfMemory);
        }
        if !abi::in_bounds(ptr, n, self.memory.data_size(&self.store) as u64) {
            return Err(abi_err("cic_alloc returned an out-of-bounds buffer"));
        }
        self.memory
            .write(&mut self.store, ptr as usize, req)
            .map_err(|e| abi_err(e.to_string()))?;
        let r = self.run(&which, (ptr as i32, n as i32))?;
        if r == 0 {
            return Err(HostError::Internal("null response".into()));
        }
        let (rp, rl) = abi::unpack(r);
        if rl < 2 || rl > self.cfg.max_response {
            return Err(abi_err(format!("response length {rl}")));
        }
        // Bounds against the memory size read *after* the call (memory may have grown).
        if !abi::in_bounds(rp, rl, self.memory.data_size(&self.store) as u64) {
            return Err(abi_err("response out of bounds"));
        }
        if (rp as u64) < ptr as u64 + n as u64 && (ptr as u64) < rp as u64 + rl as u64 {
            return Err(abi_err("response overlaps the request buffer"));
        }
        // Copied immediately: no guest code runs between the return and this copy.
        let mut out = vec![0u8; rl as usize];
        self.memory
            .read(&self.store, rp as usize, &mut out)
            .map_err(|e| abi_err(e.to_string()))?;
        let free = self.free;
        self.run(&free, (rp as i32, rl as i32))?;
        if !jcs::is_canonical(&out) {
            return Err(abi_err("response is not canonical integer-only JSON"));
        }
        Ok(out)
    }
}

impl Driver for CalveHost {
    fn init(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        self.invoke(self.init, req)
    }
    fn call(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        self.invoke(self.call, req)
    }
}

fn map_err(e: &wasmi::Error, denied: bool) -> HostError {
    match e.as_trap_code() {
        Some(TrapCode::OutOfFuel) => HostError::OutOfFuel,
        Some(TrapCode::GrowthOperationLimited | TrapCode::OutOfSystemMemory) => {
            HostError::OutOfMemory
        }
        Some(_) if denied => HostError::OutOfMemory,
        Some(c) => HostError::Trapped(format!("{c:?}")),
        None => HostError::Trapped(e.to_string()),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Supervised driver (§6.7): the guest runs in a child process (`<program> __cic-sandbox`) that
/// the parent kills on the hard wall-clock deadline. The parent never runs guest code.
pub struct SandboxDriver {
    child: Child,
    stdin: ChildStdin,
    replies: Receiver<std::io::Result<(u8, Vec<u8>)>>,
    pub hard_deadline: Duration,
    /// Time from deadline expiry to the child being reaped (deadline tests).
    pub kill_latency: Option<Duration>,
    dead: bool,
}

impl SandboxDriver {
    /// Spawns `program` (a Calve binary) in sandbox mode for the module at `wasm`, whose bytes
    /// must hash to `sha256` (checked again by the child before compilation).
    pub fn spawn(
        program: &Path,
        wasm: &Path,
        sha256: &str,
        cfg: &HostConfig,
    ) -> Result<Self, HostError> {
        let mut cmd = Command::new(program);
        cmd.arg(SANDBOX_MODE)
            .arg(wasm)
            .arg(sha256)
            .args(
                [
                    cfg.fuel_slice,
                    cfg.fuel_per_call,
                    cfg.soft_deadline.as_millis() as u64,
                    cfg.max_memory as u64,
                    cfg.max_request as u64,
                    cfg.max_response as u64,
                ]
                .map(|v| v.to_string()),
            )
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // ponytail: Unix process group only; the Windows parent-owned Job Object lands with
        // calve-win-sec process containment (M5, ADR 0017). The child spawns nothing.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| HostError::Internal(format!("sandbox spawn: {e}")))?;
        let stdin = child.stdin.take().expect("piped");
        let mut stdout = child.stdout.take().expect("piped");
        let max = cfg.max_response.max(4096);
        // Bounded (R16): frames are capped at `max`, at most a few wait unread.
        let (tx, replies) = sync_channel(8);
        std::thread::spawn(move || {
            loop {
                let r = frame::read(&mut stdout, max);
                let end = r.is_err();
                if tx.send(r).is_err() || end {
                    break;
                }
            }
        });
        Ok(SandboxDriver {
            child,
            stdin,
            replies,
            hard_deadline: cfg.hard_deadline,
            kill_latency: None,
            dead: false,
        })
    }

    fn roundtrip(&mut self, tag: u8, req: &[u8]) -> Result<Vec<u8>, HostError> {
        if self.dead {
            return Err(HostError::Internal(
                "sandbox discarded after an error".into(),
            ));
        }
        let r = self.roundtrip_inner(tag, req);
        self.dead |= r.is_err();
        r
    }

    fn roundtrip_inner(&mut self, tag: u8, req: &[u8]) -> Result<Vec<u8>, HostError> {
        frame::write(&mut self.stdin, tag, req)
            .map_err(|e| HostError::Internal(format!("sandbox gone: {e}")))?;
        match self.replies.recv_timeout(self.hard_deadline) {
            Ok(Ok((frame::OK, b))) => Ok(b),
            Ok(Ok((_, code))) => Err(HostError::decode(&String::from_utf8_lossy(&code))),
            Ok(Err(e)) => Err(HostError::Internal(format!("sandbox died: {e}"))),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                let t = Instant::now();
                self.kill();
                self.kill_latency = Some(t.elapsed());
                Err(HostError::DeadlineExceeded)
            }
        }
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for SandboxDriver {
    fn drop(&mut self) {
        self.kill();
    }
}

impl Driver for SandboxDriver {
    fn init(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        self.roundtrip(frame::INIT, req)
    }
    fn call(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        self.roundtrip(frame::CALL, req)
    }
}

/// The Calve executable that serves `__cic-sandbox` (the running binary: `calve` or `calved`).
pub fn sandbox_program() -> Result<PathBuf, HostError> {
    // Debug builds only: in-process library tests run inside a test binary that has no sandbox
    // mode, so they point at a built `calve`. Release binaries never read the variable.
    if cfg!(debug_assertions)
        && let Some(p) = std::env::var_os("CALVE_SANDBOX_PROGRAM")
    {
        return Ok(PathBuf::from(p));
    }
    std::env::current_exe().map_err(|e| HostError::Internal(format!("current_exe: {e}")))
}

/// Dispatches the hidden helper modes of a Calve binary from `main`, before any other thread
/// starts. `None` means a normal invocation.
pub fn hidden_mode() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some(SANDBOX_MODE) => Some(serve_child(&args[2..])),
        #[cfg(unix)]
        Some(crate::supervise::HELPER_MODE) => Some(crate::supervise::helper(&args[2..])),
        #[cfg(unix)]
        Some(crate::supervise::RLIMIT_MODE) => Some(crate::supervise::rlimit_exec(&args[2..])),
        _ => None,
    }
}

/// Child entry point: `calve __cic-sandbox <wasm> <sha256> <fuel_slice> <fuel_per_call>
/// <soft_ms> <max_memory> <max_request> <max_response>`. Reads the module, checks its digest,
/// self-restricts (Linux: Landlock deny-all + no_new_privs), then serves frames on stdio.
pub fn serve_child(args: &[String]) -> i32 {
    let mut out = std::io::stdout().lock();
    let mut input = std::io::stdin().lock();
    let parsed = (|| -> Result<(Vec<u8>, HostConfig), HostError> {
        let bad = || HostError::Internal("sandbox arguments".into());
        let [wasm, digest, slice, per_call, soft, mem, req, resp] = args else {
            return Err(bad());
        };
        let n = |s: &String| s.parse::<u64>().map_err(|_| bad());
        let bytes = std::fs::read(wasm).map_err(|e| HostError::Internal(format!("module: {e}")))?;
        if sha256_hex(&bytes) != *digest {
            return Err(abi_err("module digest differs from the installed package"));
        }
        let cfg = HostConfig {
            fuel_slice: n(slice)?,
            fuel_per_call: n(per_call)?,
            soft_deadline: Duration::from_millis(n(soft)?),
            max_memory: n(mem)? as usize,
            max_request: n(req)? as u32,
            max_response: n(resp)? as u32,
            ..HostConfig::default()
        };
        Ok((bytes, cfg))
    })();
    let (bytes, cfg) = match parsed {
        Ok(p) => p,
        Err(e) => return fail(&mut input, &mut out, e),
    };
    restrict_self();
    let mut host = match CalveHost::new(&bytes, cfg) {
        Ok(h) => h,
        Err(e) => return fail(&mut input, &mut out, e),
    };
    while let Ok((tag, req)) = frame::read(&mut input, cfg.max_request) {
        let r = if tag == frame::INIT {
            host.init(&req)
        } else {
            host.call(&req)
        };
        let sent = match &r {
            Ok(b) => frame::write(&mut out, frame::OK, b),
            Err(e) => frame::write(&mut out, frame::ERR, e.encode().as_bytes()),
        };
        if sent.is_err() || r.is_err() {
            break;
        }
    }
    0
}

/// Reports `e` on the first request, so the parent sees a coded error rather than a hang.
fn fail(input: &mut impl Read, out: &mut impl Write, e: HostError) -> i32 {
    let _ = frame::read(input, 64 * 1024 * 1024);
    let _ = frame::write(out, frame::ERR, e.encode().as_bytes());
    1
}

/// Defense in depth after the module is read: the guest has no imports, so it cannot reach
/// the OS through the host anyway. Linux: Landlock forbids every filesystem access (stdio fds
/// stay usable) and sets no_new_privs. macOS: none (documented). Windows: the parent-owned Job
/// Object (M5).
pub fn restrict_self() {
    #[cfg(target_os = "linux")]
    {
        use landlock::{ABI, Access, AccessFs, Ruleset, RulesetAttr};
        let _ = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V3))
            .and_then(|r| r.create())
            .and_then(|r| r.restrict_self());
    }
}
