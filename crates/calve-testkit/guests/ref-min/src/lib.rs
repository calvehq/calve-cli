//! cic-ref-min: an independent CIC v1 guest (rev 10 §6.8). `no_std`, zero dependencies: its own
//! byte-level scanner over canonical (JCS) input, its own SHA-256, and canonical output written
//! byte for byte. It shares no code with cic-ref-rust or the contract crate; only the toy
//! policy and the package metadata (data) are common.
//!
//! Because input is canonical, an object/array/string span is already the canonical encoding of
//! its value: spans are compared, hashed and copied as raw bytes.
#![no_std]
#![allow(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

// ---------------------------------------------------------------- allocator (bump, per instance)
// ponytail: bump allocator, memory only grows; an instance lives for one session (§6.2), so the
// bound is the session's total traffic. A free-list allocator if sessions ever get long.
struct Bump(UnsafeCell<usize>);
// SAFETY: wasm32 guests are single-threaded (no shared memory, no threads); the cell is never
// accessed concurrently.
unsafe impl Sync for Bump {}

// SAFETY: `alloc` returns either null or a fresh, `l.align()`-aligned range of `l.size()` bytes
// inside linear memory that no earlier allocation covers (the bump pointer only increases);
// `dealloc` never reuses memory, so no live allocation can alias another.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: single-threaded guest (see `Sync` above); no other reference to the cell exists
        // while this one is alive.
        let next = unsafe { &mut *self.0.get() };
        if *next == 0 {
            *next = core::arch::wasm32::memory_size(0) * 65536;
        }
        let start = (*next + l.align() - 1) & !(l.align() - 1);
        let end = start + l.size();
        let have = core::arch::wasm32::memory_size(0) * 65536;
        if end > have {
            let pages = (end - have).div_ceil(65536);
            if core::arch::wasm32::memory_grow(0, pages) == usize::MAX {
                return core::ptr::null_mut();
            }
        }
        *next = end;
        start as *mut u8
    }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static ALLOC: Bump = Bump(UnsafeCell::new(0));

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

// ---------------------------------------------------------------- SHA-256
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
struct Sha {
    h: [u32; 8],
    buf: [u8; 64],
    n: usize,
    total: u64,
}

impl Sha {
    fn new() -> Sha {
        Sha { h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], buf: [0; 64], n: 0, total: 0 }
    }
    fn block(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([self.buf[4 * i], self.buf[4 * i + 1], self.buf[4 * i + 2], self.buf[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let t2 = s0.wrapping_add((a & b) ^ (a & c) ^ (b & c));
            (h, g, f, e, d, c, b, a) = (g, f, e, d.wrapping_add(t1), c, b, a, t1.wrapping_add(t2));
        }
        for (x, y) in self.h.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *x = x.wrapping_add(y);
        }
    }
    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.buf[self.n] = byte;
            self.n += 1;
            if self.n == 64 {
                self.block();
                self.n = 0;
            }
        }
        self.total += data.len() as u64;
    }
    /// Hex digest of the data so far (works on a copy, so the stream can continue).
    fn hex(&self) -> [u8; 64] {
        let mut s = self.clone();
        let bits = s.total * 8;
        s.update(&[0x80]);
        while s.n != 56 {
            s.update(&[0]);
        }
        s.update(&bits.to_be_bytes());
        let mut out = [0u8; 64];
        for (i, word) in s.h.iter().enumerate() {
            for (j, byte) in word.to_be_bytes().iter().enumerate() {
                out[8 * i + 2 * j] = b"0123456789abcdef"[(byte >> 4) as usize];
                out[8 * i + 2 * j + 1] = b"0123456789abcdef"[(byte & 15) as usize];
            }
        }
        out
    }
}

// ---------------------------------------------------------------- canonical JSON scanner
type Span = (usize, usize);

fn skip_string(b: &[u8], mut i: usize) -> usize {
    i += 1;
    while b[i] != b'"' {
        i += if b[i] == b'\\' { 2 } else { 1 };
    }
    i + 1
}

fn skip(b: &[u8], i: usize) -> usize {
    match b[i] {
        b'"' => skip_string(b, i),
        b'{' | b'[' => {
            let (mut depth, mut j) = (0i32, i);
            loop {
                match b[j] {
                    b'"' => {
                        j = skip_string(b, j);
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return j + 1;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']') {
                j += 1;
            }
            j
        }
    }
}

/// Value of `key` (given with its quotes) in the object at `s`.
fn get(b: &[u8], s: Span, key: &[u8]) -> Option<Span> {
    let mut i = s.0 + 1;
    while i < s.1 && b[i] != b'}' {
        let k_end = skip_string(b, i);
        let v_start = k_end + 1;
        let v_end = skip(b, v_start);
        if &b[i..k_end] == key {
            return Some((v_start, v_end));
        }
        i = v_end + usize::from(b[v_end] == b',');
    }
    None
}

fn items(b: &[u8], s: Span) -> Vec<Span> {
    let (mut out, mut i) = (Vec::new(), s.0 + 1);
    while b[i] != b']' {
        let e = skip(b, i);
        out.push((i, e));
        i = e + usize::from(b[e] == b',');
    }
    out
}

fn num(b: &[u8], s: Span) -> Option<u64> {
    let mut n: u64 = 0;
    if s.0 == s.1 {
        return None;
    }
    for &c in &b[s.0..s.1] {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(n)
}

/// Decoded string bytes (canonical escapes only: \" \\ \b \f \n \r \t \u00XX).
fn decode(b: &[u8], s: Span) -> Vec<u8> {
    let (mut out, mut i) = (Vec::new(), s.0 + 1);
    while i < s.1 - 1 {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let c = match b[i + 1] {
            b'b' => 8,
            b'f' => 12,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'u' => {
                let h = |c: u8| if c.is_ascii_digit() { c - b'0' } else { (c | 0x20) - b'a' + 10 };
                i += 4;
                (h(b[i + 0]) << 4) | h(b[i + 1])
            }
            c => c,
        };
        out.push(c);
        i += 2;
    }
    out
}

fn put_num(out: &mut Vec<u8>, mut n: u64) {
    let mut d = [0u8; 20];
    let mut k = d.len();
    loop {
        k -= 1;
        d[k] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&d[k..]);
}

// ---------------------------------------------------------------- guest
const METADATA: &[u8] = br#"{"abi":1,"capabilities":{"optional":["describe.v1","detect.v1","relate.v1"],"required":["capture.v1"]},"cic":[{"major":1,"max_minor":0,"min_minor":0}],"detect":{"markers":["Cargo.toml","go.mod","package.json"]},"display_name":"Toy","extension_id":"org.example.toy","ops":["capture","describe","detect","relate"],"optional_relations":"omit-on-failure","relations":[{"kind":"org.example.toy.rename","required":false,"schema":{"additionalProperties":false,"properties":{"from":{"type":"string"},"to":{"type":"string"}},"required":["from","to"],"type":"object"}}],"schema":"calve.integration/1","version":"0.1.0"}"#;
const HELLO: &[u8] = br#"{"guest":{"abi":1,"capabilities":{"optional":["describe.v1","detect.v1","relate.v1"],"required":["capture.v1"]},"cic":[{"major":1,"max_minor":0,"min_minor":0}],"extension_id":"org.example.toy","schema":1,"version":"0.1.0"},"hello":0}"#;
const KIND: &[u8] = b"\"org.example.toy.rename\"";

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Ready,
    Capture,
    Relate,
    Finished,
}

struct St {
    seq: u64,
    mode: Mode,
    next_index: u64,
    last_path: Option<Vec<u8>>,
    count: u64,
    expected: u64,
    members: u64,
    exp_members: u64,
    hash: Sha,
    rel_hash: Sha,
    relations: u64,
}

struct Cell(UnsafeCell<Option<St>>);
// SAFETY: single-threaded guest; see `Bump`.
unsafe impl Sync for Cell {}
static STATE: Cell = Cell(UnsafeCell::new(None));

fn state() -> &'static mut St {
    // SAFETY: the guest is single-threaded and has no imports, so the host cannot re-enter it;
    // each export obtains this reference once and drops it before returning.
    let s = unsafe { &mut *STATE.0.get() };
    s.get_or_insert_with(|| St {
        seq: 0,
        mode: Mode::Ready,
        next_index: 0,
        last_path: None,
        count: 0,
        expected: 0,
        members: 0,
        exp_members: 0,
        hash: Sha::new(),
        rel_hash: Sha::new(),
        relations: 0,
    })
}

const INVALID: (&[u8], &[u8]) = (b"INVALID_INPUT", b"invalid input");
const BAD_STATE: (&[u8], &[u8]) = (b"BAD_STATE", b"bad state");
const UNSUPPORTED: (&[u8], &[u8]) = (b"UNSUPPORTED_OP", b"unsupported op");
type Res = Result<Vec<u8>, (&'static [u8], &'static [u8])>;

fn entry_key(b: &[u8], e: Span) -> Option<Span> {
    if get(b, e, b"\"kind\"").map(|k| &b[k.0..k.1]) == Some(b"\"file\"") { get(b, e, b"\"digest\"") } else { None }
}

fn op_obj(out: &mut Vec<u8>, b: &[u8], kind: &[u8], path: Span, key: Option<Span>, reason: Option<&[u8]>) {
    out.push(b'{');
    if let Some(k) = key {
        out.extend_from_slice(b"\"group_key\":");
        out.extend_from_slice(&b[k.0..k.1]);
        out.push(b',');
    }
    out.extend_from_slice(b"\"op\":\"");
    out.extend_from_slice(kind);
    out.extend_from_slice(b"\",\"path\":");
    out.extend_from_slice(&b[path.0..path.1]);
    if let Some(r) = reason {
        out.extend_from_slice(b",\"reason\":\"");
        out.extend_from_slice(r);
        out.push(b'"');
    }
    out.push(b'}');
}

fn capture_chunk(st: &mut St, b: &[u8], body: Span) -> Res {
    let index = get(b, body, b"\"index\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
    if index != st.next_index {
        return Err(INVALID);
    }
    let mut out = Vec::from(&b"{\"ops\":["[..]);
    let tuples = items(b, get(b, body, b"\"tuples\"").ok_or(INVALID)?);
    for (n, t) in tuples.iter().enumerate() {
        let path = get(b, *t, b"\"path\"").ok_or(INVALID)?;
        let p = decode(b, path);
        if st.last_path.as_ref().is_some_and(|l| l.as_slice() >= p.as_slice()) {
            return Err(INVALID);
        }
        st.last_path = Some(p);
        if n > 0 {
            out.push(b',');
        }
        let start = out.len();
        match (get(b, *t, b"\"base\""), get(b, *t, b"\"work\"")) {
            (None, Some(w)) => {
                let big = get(b, w, b"\"kind\"").map(|k| &b[k.0..k.1]) == Some(b"\"file\"")
                    && get(b, w, b"\"size\"").and_then(|s| num(b, s)).unwrap_or(0) > 1024 * 1024;
                if big {
                    op_obj(&mut out, b, b"refuse", path, None, Some(b"too_large"));
                } else {
                    op_obj(&mut out, b, b"add", path, entry_key(b, w), None);
                }
            }
            (Some(x), None) => op_obj(&mut out, b, b"delete", path, entry_key(b, x), None),
            (Some(x), Some(w)) if b[x.0..x.1] == b[w.0..w.1] => op_obj(&mut out, b, b"unchanged", path, None, None),
            (Some(_), Some(_)) => op_obj(&mut out, b, b"modify", path, None, None),
            (None, None) => return Err(INVALID),
        }
        st.hash.update(&out[start..]);
        st.hash.update(b"\n");
    }
    st.next_index += 1;
    st.count += tuples.len() as u64;
    out.extend_from_slice(b"]}");
    Ok(out)
}

fn relate_groups(st: &mut St, b: &[u8], body: Span) -> Res {
    let index = get(b, body, b"\"index\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
    if index != st.next_index {
        return Err(INVALID);
    }
    // (delete op_index, relation bytes)
    let mut rels: Vec<(u64, Vec<u8>)> = Vec::new();
    for g in items(b, get(b, body, b"\"groups\"").ok_or(INVALID)?) {
        st.hash.update(&b[g.0..g.1]);
        st.hash.update(b"\n");
        st.count += 1;
        let Some(ms) = get(b, g, b"\"members\"") else { continue };
        let ms = items(b, ms);
        st.members += ms.len() as u64;
        if ms.len() != 2 {
            continue;
        }
        let kind = |m: Span| get(b, m, b"\"op\"").and_then(|o| get(b, o, b"\"op\"")).map(|k| &b[k.0..k.1]);
        let (d, a) = match (kind(ms[0]), kind(ms[1])) {
            (Some(b"\"delete\""), Some(b"\"add\"")) => (ms[0], ms[1]),
            (Some(b"\"add\""), Some(b"\"delete\"")) => (ms[1], ms[0]),
            _ => continue,
        };
        let di = get(b, d, b"\"op_index\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
        let ai = get(b, a, b"\"op_index\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
        let (dp, ap) = (get(b, d, b"\"path\"").ok_or(INVALID)?, get(b, a, b"\"path\"").ok_or(INVALID)?);
        let mut r = Vec::from(&b"{\"kind\":"[..]);
        r.extend_from_slice(KIND);
        r.extend_from_slice(b",\"members\":[");
        put_num(&mut r, di);
        r.push(b',');
        put_num(&mut r, ai);
        r.extend_from_slice(b"],\"payload\":{\"from\":");
        r.extend_from_slice(&b[dp.0..dp.1]);
        r.extend_from_slice(b",\"to\":");
        r.extend_from_slice(&b[ap.0..ap.1]);
        r.extend_from_slice(b"}}");
        rels.push((di, r));
    }
    rels.sort_by_key(|r| r.0);
    st.next_index += 1;
    let mut out = Vec::from(&b"{\"ack\":{\"groups_received\":"[..]);
    put_num(&mut out, st.count);
    out.extend_from_slice(b",\"index\":");
    put_num(&mut out, index);
    out.extend_from_slice(b",\"members_received\":");
    put_num(&mut out, st.members);
    out.extend_from_slice(b",\"running_groups_digest\":\"");
    out.extend_from_slice(&st.hash.hex());
    out.extend_from_slice(b"\"},\"relations\":[");
    for (i, (_, r)) in rels.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(r);
        st.rel_hash.update(r);
        st.rel_hash.update(b"\n");
        st.relations += 1;
    }
    out.extend_from_slice(b"]}");
    Ok(out)
}

fn detect(b: &[u8], body: Span) -> Res {
    let mut found = [false; 3];
    for m in items(b, get(b, body, b"\"markers\"").ok_or(INVALID)?) {
        match &b[m.0..m.1] {
            b"\"go.mod\"" => found[0] = true,
            b"\"package.json\"" => found[1] = true,
            b"\"Cargo.toml\"" => found[2] = true,
            _ => {}
        }
    }
    let mut out = Vec::from(&b"{\"languages\":["[..]);
    let mut first = true;
    for (f, name) in found.iter().zip([&b"\"go\""[..], b"\"javascript\"", b"\"rust\""]) {
        if *f {
            if !first {
                out.push(b',');
            }
            out.extend_from_slice(name);
            first = false;
        }
    }
    out.extend_from_slice(b"]}");
    Ok(out)
}

fn dispatch(st: &mut St, b: &[u8], op: &[u8], body: Span) -> Res {
    let need = |m: Mode| if st.mode == m { Ok(()) } else { Err(BAD_STATE) };
    match op {
        b"\"describe\"" => Ok(Vec::from(METADATA)),
        b"\"detect\"" => detect(b, body),
        b"\"capture.begin\"" => {
            need(Mode::Ready)?;
            st.expected = get(b, body, b"\"expected_tuples\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
            st.mode = Mode::Capture;
            Ok(Vec::from(&b"{}"[..]))
        }
        b"\"capture.chunk\"" => {
            need(Mode::Capture)?;
            capture_chunk(st, b, body)
        }
        b"\"capture.finish\"" => {
            need(Mode::Capture)?;
            let total = get(b, body, b"\"total_tuples\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
            if total != st.count || total != st.expected {
                return Err(INVALID);
            }
            st.mode = Mode::Finished;
            let mut out = Vec::from(&b"{\"output_digest\":\""[..]);
            out.extend_from_slice(&st.hash.hex());
            out.extend_from_slice(b"\",\"total_ops\":");
            put_num(&mut out, st.count);
            out.push(b'}');
            Ok(out)
        }
        b"\"relate.begin\"" => {
            need(Mode::Ready)?;
            st.expected = get(b, body, b"\"total_groups\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
            st.exp_members = get(b, body, b"\"total_members\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
            st.mode = Mode::Relate;
            Ok(Vec::from(&b"{}"[..]))
        }
        b"\"relate.groups\"" => {
            need(Mode::Relate)?;
            relate_groups(st, b, body)
        }
        b"\"relate.finish\"" => {
            need(Mode::Relate)?;
            let tg = get(b, body, b"\"total_groups\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
            let tm = get(b, body, b"\"total_members\"").and_then(|s| num(b, s)).ok_or(INVALID)?;
            if tg != st.expected || tm != st.exp_members || st.count != tg || st.members != tm {
                return Err(INVALID);
            }
            st.mode = Mode::Finished;
            let mut out = Vec::from(&b"{\"groups_digest_seen\":\""[..]);
            out.extend_from_slice(&st.hash.hex());
            out.extend_from_slice(b"\",\"kinds\":[{\"kind\":");
            out.extend_from_slice(KIND);
            out.extend_from_slice(b",\"status\":\"complete\"}],\"relations_digest\":\"");
            out.extend_from_slice(&st.rel_hash.hex());
            out.extend_from_slice(b"\",\"total_groups_seen\":");
            put_num(&mut out, st.count);
            out.extend_from_slice(b",\"total_members_seen\":");
            put_num(&mut out, st.members);
            out.extend_from_slice(b",\"total_relations\":");
            put_num(&mut out, st.relations);
            out.push(b'}');
            Ok(out)
        }
        _ => Err(UNSUPPORTED),
    }
}

fn call(b: &[u8]) -> Vec<u8> {
    let st = state();
    let whole = (0, b.len());
    let (seq_span, result) = match (get(b, whole, b"\"seq\""), get(b, whole, b"\"op\""), get(b, whole, b"\"v\""), get(b, whole, b"\"body\"")) {
        (Some(seq), Some(op), Some(v), Some(body)) => {
            let n = num(b, seq).unwrap_or(0);
            let r = if &b[v.0..v.1] != b"\"1.0\"" {
                Err(UNSUPPORTED)
            } else if n != st.seq + 1 {
                Err(BAD_STATE)
            } else {
                st.seq += 1;
                dispatch(st, b, &b[op.0..op.1], body)
            };
            (Some(seq), r)
        }
        _ => (None, Err(INVALID)),
    };
    let mut out = Vec::new();
    match result {
        Ok(v) => {
            out.extend_from_slice(b"{\"ok\":");
            out.extend_from_slice(&v);
            out.extend_from_slice(b",\"seq\":");
        }
        Err((code, msg)) => {
            out.extend_from_slice(b"{\"err\":{\"code\":\"");
            out.extend_from_slice(code);
            out.extend_from_slice(b"\",\"message\":\"");
            out.extend_from_slice(msg);
            out.extend_from_slice(b"\",\"retryable\":false},\"seq\":");
        }
    }
    match seq_span {
        Some(s) => out.extend_from_slice(&b[s.0..s.1]),
        None => out.push(b'0'),
    }
    out.push(b'}');
    out
}

// ---------------------------------------------------------------- ABI
fn leak(v: Vec<u8>) -> i64 {
    let len = v.len() as u64;
    let ptr = v.leak().as_ptr() as u64;
    ((ptr << 32) | len) as i64
}

/// # Safety
/// `ptr..ptr+len` must be a buffer returned by `cic_alloc(len)` (ABI §6.2: the host writes the
/// request there and passes exactly that pointer and length). The bump allocator never frees,
/// so the slice stays valid for the instance's lifetime.
unsafe fn slice(ptr: i32, len: i32) -> &'static [u8] {
    // SAFETY: guaranteed by the caller contract above.
    unsafe { core::slice::from_raw_parts(ptr as u32 as usize as *const u8, len as u32 as usize) }
}

#[unsafe(no_mangle)]
pub extern "C" fn cic_abi_version() -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn cic_alloc(len: i32) -> i32 {
    if len < 1 {
        return 0;
    }
    // SAFETY: len ≥ 1 and align 8 is a power of two, so the layout is valid; `alloc` upholds
    // the GlobalAlloc contract above.
    unsafe { ALLOC.alloc(Layout::from_size_align_unchecked(len as u32 as usize, 8)) as u32 as i32 }
}

#[unsafe(no_mangle)]
pub extern "C" fn cic_free(_ptr: i32, _len: i32) {}

#[unsafe(no_mangle)]
pub extern "C" fn cic_init(ptr: i32, len: i32) -> i64 {
    // SAFETY: (ptr, len) is the request buffer the host obtained from `cic_alloc` (ABI §6.2).
    let req = unsafe { slice(ptr, len) };
    if !req.starts_with(b"{\"hello\":0,\"host\":{") {
        core::arch::wasm32::unreachable();
    }
    leak(Vec::from(HELLO))
}

#[unsafe(no_mangle)]
pub extern "C" fn cic_call(ptr: i32, len: i32) -> i64 {
    // SAFETY: (ptr, len) is the request buffer the host obtained from `cic_alloc` (ABI §6.2).
    leak(call(unsafe { slice(ptr, len) }))
}
