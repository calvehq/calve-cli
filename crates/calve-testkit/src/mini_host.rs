//! `testkit::mini_host` (rev 10 §6.8): a second, deliberately different, minimal ABI 1 driver.
//! Plain `call` with the whole fuel budget set up front (no slices, no wall clock), a smaller
//! memory cap, module checks through wasmi's own module reflection, and its own canonical-form
//! check through serde_json's sorted map. It shares no code with `host.rs`.

use serde_json::Value;
use wasmi::{
    Config, Engine, ExternType, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, TrapCode,
};

use calve_integration_contract::driver::{Driver, HostError};

const FUEL: u64 = 500_000_000;
const MEM: usize = 32 * 1024 * 1024;
const MAX_RESP: u64 = 4 * 1024 * 1024;

/// Counts denied growth so a guest trapping after `memory.grow` = -1 reports OUT_OF_MEMORY.
struct Lim(StoreLimits, bool);

impl wasmi_core::ResourceLimiter for Lim {
    fn memory_growing(
        &mut self,
        c: usize,
        d: usize,
        m: Option<usize>,
    ) -> Result<bool, wasmi_core::LimiterError> {
        let r = self.0.memory_growing(c, d, m);
        self.1 |= matches!(r, Ok(false));
        r
    }
    fn table_growing(
        &mut self,
        c: usize,
        d: usize,
        m: Option<usize>,
    ) -> Result<bool, wasmi_core::LimiterError> {
        self.0.table_growing(c, d, m)
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

pub struct MiniHost {
    store: Store<Lim>,
    instance: wasmi::Instance,
    fuel: u64,
}

fn abi(m: &str) -> HostError {
    HostError::AbiViolation(m.into())
}

impl MiniHost {
    pub fn new(wasm: &[u8]) -> Result<Self, HostError> {
        Self::with_fuel(wasm, FUEL)
    }

    /// Whole-call fuel budget (no slices, no wall clock).
    pub fn with_fuel(wasm: &[u8], fuel: u64) -> Result<Self, HostError> {
        // Start sections are visible only to a parser; wasmi's Module hides them.
        for p in wasmparser::Parser::new(0).parse_all(wasm) {
            if let Ok(wasmparser::Payload::StartSection { .. }) = p {
                return Err(abi("start"));
            }
        }
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, wasm).map_err(|e| abi(&e.to_string()))?;
        if module.imports().len() != 0 {
            return Err(abi("imports"));
        }
        let mut names = vec![];
        let mut memories = 0;
        for e in module.exports() {
            match e.ty() {
                ExternType::Memory(m) => {
                    memories += 1;
                    if m.maximum().is_some_and(|max| max > (MEM / 65536) as u64) {
                        return Err(abi("memory max"));
                    }
                }
                ExternType::Func(_) => {}
                ExternType::Global(g) if g.mutability().is_const() => continue,
                _ => return Err(abi("export kind")),
            }
            names.push(e.name().to_owned());
        }
        names.sort();
        if memories != 1
            || names
                != [
                    "cic_abi_version",
                    "cic_alloc",
                    "cic_call",
                    "cic_free",
                    "cic_init",
                    "memory",
                ]
        {
            return Err(abi("exports"));
        }
        // Two memories cannot pass the export check above unless one is internal: count them.
        if wasmparser::Parser::new(0)
            .parse_all(wasm)
            .filter_map(Result::ok)
            .any(|p| matches!(p, wasmparser::Payload::MemorySection(s) if s.count() > 1))
        {
            return Err(abi("memories"));
        }
        let mut store = Store::new(
            &engine,
            Lim(
                StoreLimitsBuilder::new()
                    .memory_size(MEM)
                    .instances(1)
                    .memories(1)
                    .tables(1)
                    .build(),
                false,
            ),
        );
        store.limiter(|l| l);
        store
            .set_fuel(fuel)
            .map_err(|e| HostError::Internal(e.to_string()))?;
        let instance = Linker::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .map_err(trap)?;
        let mut h = MiniHost {
            store,
            instance,
            fuel,
        };
        let v: i32 = h
            .instance
            .get_typed_func::<(), i32>(&h.store, "cic_abi_version")
            .map_err(|e| abi(&e.to_string()))?
            .call(&mut h.store, ())
            .map_err(trap)?;
        if v != 1 {
            return Err(abi("version"));
        }
        Ok(h)
    }

    fn go(&mut self, name: &str, req: &[u8]) -> Result<Vec<u8>, HostError> {
        self.store
            .set_fuel(self.fuel)
            .map_err(|e| HostError::Internal(e.to_string()))?;
        let mem = self
            .instance
            .get_memory(&self.store, "memory")
            .ok_or(abi("memory"))?;
        let alloc = self
            .instance
            .get_typed_func::<i32, i32>(&self.store, "cic_alloc")
            .map_err(|e| abi(&e.to_string()))?;
        let f = self
            .instance
            .get_typed_func::<(i32, i32), i64>(&self.store, name)
            .map_err(|e| abi(&e.to_string()))?;
        let free = self
            .instance
            .get_typed_func::<(i32, i32), ()>(&self.store, "cic_free")
            .map_err(|e| abi(&e.to_string()))?;
        let ptr = alloc
            .call(&mut self.store, req.len() as i32)
            .map_err(trap)? as u32 as u64;
        if ptr == 0 {
            return Err(HostError::OutOfMemory);
        }
        if ptr + req.len() as u64 > mem.data_size(&self.store) as u64 {
            return Err(abi("alloc oob"));
        }
        mem.data_mut(&mut self.store)[ptr as usize..ptr as usize + req.len()].copy_from_slice(req);
        self.store.data_mut().1 = false;
        let r = match f.call(&mut self.store, (ptr as i32, req.len() as i32)) {
            Ok(r) => r as u64,
            Err(_) if self.store.data().1 => return Err(HostError::OutOfMemory),
            Err(e) => return Err(trap(e)),
        };
        if r == 0 {
            return Err(HostError::Internal("null".into()));
        }
        let (rp, rl) = (r >> 32, r & 0xFFFF_FFFF);
        if !(2..=MAX_RESP).contains(&rl) {
            return Err(abi("len"));
        }
        let end = rp.checked_add(rl).ok_or(abi("overflow"))?;
        if rp == 0 || end > mem.data_size(&self.store) as u64 {
            return Err(abi("oob"));
        }
        if rp < ptr + req.len() as u64 && ptr < end {
            return Err(abi("overlap"));
        }
        let out = mem.data(&self.store)[rp as usize..end as usize].to_vec();
        free.call(&mut self.store, (rp as i32, rl as i32))
            .map_err(trap)?;
        // Canonical check: compact (re-serialisation in input order is byte-equal) and every
        // object's keys strictly increasing by bytes (equal to UTF-16 order outside U+E000–U+FFFF
        // vs supplementary planes; documented edge).
        let v: Value = serde_json::from_slice(&out).map_err(|_| abi("not json"))?;
        if has_float(&v) || !sorted(&v) || serde_json::to_vec(&v).unwrap() != out {
            return Err(abi("not canonical"));
        }
        Ok(out)
    }
}

fn sorted(v: &Value) -> bool {
    match v {
        Value::Array(a) => a.iter().all(sorted),
        Value::Object(o) => {
            o.keys()
                .zip(o.keys().skip(1))
                .all(|(a, b)| a.as_bytes() < b.as_bytes())
                && o.values().all(sorted)
        }
        _ => true,
    }
}

fn has_float(v: &Value) -> bool {
    match v {
        Value::Number(n) => {
            n.is_f64()
                || n.as_u64().is_some_and(|u| u > (1 << 53) - 1)
                || n.as_i64().is_some_and(|i| i.unsigned_abs() > (1 << 53) - 1)
        }
        Value::Array(a) => a.iter().any(has_float),
        Value::Object(o) => o.values().any(has_float),
        _ => false,
    }
}

fn trap(e: wasmi::Error) -> HostError {
    match e.as_trap_code() {
        Some(TrapCode::OutOfFuel) => HostError::OutOfFuel,
        Some(TrapCode::GrowthOperationLimited | TrapCode::OutOfSystemMemory) => {
            HostError::OutOfMemory
        }
        Some(c) => HostError::Trapped(format!("{c:?}")),
        None => HostError::Trapped(e.to_string()),
    }
}

impl Driver for MiniHost {
    fn init(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        self.go("cic_init", req)
    }
    fn call(&mut self, req: &[u8]) -> Result<Vec<u8>, HostError> {
        self.go("cic_call", req)
    }
}
