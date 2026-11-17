//! Wasm ABI v1 (rev 10 §6.2): exports, buffer rules and resource limits.

/// Value `cic_abi_version()` must return.
pub const ABI_VERSION: i32 = 1;

/// Exact export set of a CIC module. No imports, no start section, one memory.
pub const EXPORTS: &[&str] = &[
    "memory",
    "cic_abi_version",
    "cic_alloc",
    "cic_free",
    "cic_init",
    "cic_call",
];

/// Host limits (defaults; host configurable downwards only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_memory_bytes: u64,
    pub max_table_elements: u32,
    pub max_request: u32,
    pub max_response: u32,
    pub fuel_slice: u64,
    pub fuel_per_call: u64,
    pub soft_deadline_ms: u64,
    pub hard_deadline_ms: u64,
    pub max_module_bytes: u64,
    pub chunk_entries: u32,
    pub max_group: u32,
    pub max_pending_relations: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_memory_bytes: 64 * 1024 * 1024,
            max_table_elements: 10_000,
            max_request: 4 * 1024 * 1024,
            max_response: 4 * 1024 * 1024,
            fuel_slice: 10_000_000,
            fuel_per_call: 500_000_000,
            soft_deadline_ms: 5_000,
            hard_deadline_ms: 15_000,
            max_module_bytes: 8 * 1024 * 1024,
            chunk_entries: 2_048,
            max_group: 64,
            max_pending_relations: 4_096,
        }
    }
}

/// Unpacks a `cic_init`/`cic_call` result (`ptr << 32 | len`, read as u64).
pub fn unpack(result: i64) -> (u32, u32) {
    let r = result as u64;
    ((r >> 32) as u32, (r & 0xFFFF_FFFF) as u32)
}

pub fn pack(ptr: u32, len: u32) -> i64 {
    (((ptr as u64) << 32) | len as u64) as i64
}

/// Checked bounds for a guest buffer against the memory size read after the call returned.
pub fn in_bounds(ptr: u32, len: u32, memory_size: u64) -> bool {
    ptr != 0
        && (ptr as u64)
            .checked_add(len as u64)
            .is_some_and(|end| end <= memory_size)
}

/// Host-side errors (§6.3).
pub mod host_error {
    pub const TRAPPED: &str = "TRAPPED";
    pub const ABI_VIOLATION: &str = "ABI_VIOLATION";
    pub const OUT_OF_FUEL: &str = "OUT_OF_FUEL";
    pub const DEADLINE_EXCEEDED: &str = "DEADLINE_EXCEEDED";
    pub const OUT_OF_MEMORY: &str = "OUT_OF_MEMORY";
    pub const CANCELLED: &str = "CANCELLED";
    pub const INCOMPATIBLE_CIC: &str = "INCOMPATIBLE_CIC";
}

/// Guest errors (§6.3).
pub mod guest_error {
    pub const INVALID_INPUT: &str = "INVALID_INPUT";
    pub const LIMIT_EXCEEDED: &str = "LIMIT_EXCEEDED";
    pub const UNSUPPORTED_OP: &str = "UNSUPPORTED_OP";
    pub const BAD_STATE: &str = "BAD_STATE";
    pub const INTERNAL: &str = "INTERNAL";
}
