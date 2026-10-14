//! cic-fixture: the test fixture guest for Calve's host paths (package `org.example.toy`, with
//! the `calve-fixture-ext` native fixture). It implements every op the host uses — describe,
//! detect, check_plan, classify, capture, relate, diff — with deliberately simple toy
//! semantics, so host behaviour is tested without any first-party domain. Never shipped.
//!
//! ABI glue needs `unsafe` (raw guest pointers ↔ slices), confined to `abi` below (user-approved
//! exemption for Wasm ABI glue and test fixtures, M0 review Decision 2).

use std::cell::RefCell;

use calve_integration_contract::digest::LineHasher;
use calve_integration_contract::hello::{GuestHello, Hello, HelloRequest};
use calve_integration_contract::jcs;
use calve_integration_contract::metadata::Metadata;
use calve_integration_contract::session::*;
use calve_integration_contract::wire::*;
use serde_json::{Value, json};

/// `calve-integration.json` of the fixture package (extracted by build.sh).
pub const METADATA: &str = r#"{"abi":1,"capabilities":{"optional":["relate.v1"],"required":["capture.v1","check_plan.v1","classify.v1","describe.v1","detect.v1","diff.v1"]},"checks":{"verifier":"org.example.toy.checks"},"cic":[{"major":1,"max_minor":0,"min_minor":0}],"detect":{"markers":["toy.toml"]},"display_name":"Toy fixture","extension_id":"org.example.toy","files":{"delete":"org.example.toy.delete","evaluator":"org.example.toy.size","ignore_files":[".toyignore"],"put":"org.example.toy.put","resource_kind":"org.example.toy.file","verifier":"org.example.toy.verify","write_action":"org.example.toy.write"},"ops":["capture","check_plan","classify","describe","detect","diff","relate"],"optional_relations":"omit-on-failure","relations":[{"kind":"org.example.toy.rename","required":false,"schema":{"additionalProperties":false,"properties":{"from":{"type":"string"},"to":{"type":"string"}},"required":["from","to"],"type":"object"}}],"resources":[{"kind":"org.example.toy.note","remove":"org.example.toy.note.remove","set":"org.example.toy.note.set","short":"note","write_action":"org.example.toy.write"}],"schema":"calve.integration/1","version":"0.1.0"}"#;
const KIND: &str = "org.example.toy.rename";
const MAX_INLINE: u64 = 1024 * 1024;

#[derive(Default)]
struct Capture {
    next_index: u64,
    last_path: Option<String>,
    tuples: u64,
    expected: u64,
    ops: LineHasher,
    fault: String,
}

#[derive(Default)]
struct Relate {
    begin: Option<RelateBegin>,
    next_index: u64,
    groups: u64,
    members: u64,
    groups_hash: LineHasher,
    rel_hash: LineHasher,
    relations: u64,
    fault: String,
}

#[derive(Default)]
enum Mode {
    #[default]
    Ready,
    Capture(Capture),
    Relate(Relate),
    Finished,
}

#[derive(Default)]
struct Guest {
    seq: u64,
    mode: Mode,
}

thread_local! {
    static GUEST: RefCell<Guest> = RefCell::new(Guest::default());
}

type R = Result<Value, (&'static str, &'static str)>;
const INVALID: (&str, &str) = ("INVALID_INPUT", "invalid input");
const BAD_STATE: (&str, &str) = ("BAD_STATE", "bad state");
const UNSUPPORTED: (&str, &str) = ("UNSUPPORTED_OP", "unsupported op");

fn body<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, (&'static str, &'static str)> {
    serde_json::from_value(v.clone()).map_err(|_| INVALID)
}

fn fault(params: &Value) -> String {
    params.get("fault").and_then(Value::as_str).unwrap_or_default().to_owned()
}

fn hello(req: &[u8]) -> Vec<u8> {
    let r: HelloRequest = serde_json::from_slice(req).expect("hello/0");
    assert_eq!(r.hello, 0);
    let m: Metadata = serde_json::from_str(METADATA).unwrap();
    let h = Hello {
        hello: 0,
        guest: GuestHello {
            abi: m.abi,
            cic: m.cic.clone(),
            capabilities: m.capabilities.clone(),
            schema: m.schema_number().unwrap(),
            extension_id: m.extension_id.clone(),
            version: m.version.clone(),
        },
        x: None,
    };
    jcs::to_vec(&serde_json::to_value(h).unwrap()).unwrap()
}

fn capture_op(t: &Tuple) -> Result<CaptureOp, (&'static str, &'static str)> {
    let key = |e: &Entry| if e.kind == EntryKind::File { e.digest.clone() } else { None };
    let path = t.path.clone();
    Ok(match (&t.base, &t.work) {
        (None, Some(w)) if w.kind == EntryKind::File && w.size.unwrap_or(0) > MAX_INLINE => CaptureOp::Refuse { path, reason: "too_large".into() },
        (None, Some(w)) => CaptureOp::Add { path, group_key: key(w) },
        (Some(b), None) => CaptureOp::Delete { path, group_key: key(b) },
        (Some(b), Some(w)) if b == w => CaptureOp::Unchanged { path },
        (Some(_), Some(_)) => CaptureOp::Modify { path },
        (None, None) => return Err(INVALID),
    })
}

fn detect(b: &Value) -> R {
    let x: DetectIn = body(b)?;
    let toy = x.markers.iter().any(|m| m == "toy.toml") || x.extensions.iter().any(|e| e == "toy");
    Ok(serde_json::to_value(DetectOut { languages: if toy { vec!["toy".into()] } else { vec![] } }).unwrap())
}

fn check_plan(b: &Value) -> R {
    let x: CheckPlanIn = body(b)?;
    let checks = if x.languages.iter().any(|l| l == "toy") {
        vec![PlannedCheck { language: "toy".into(), name: "test".into(), argv: vec!["toy-check".into(), "--all".into()], takes_files: false, env: vec!["TOY_HOME".into()], sources: vec!["toy".into()] }]
    } else {
        vec![]
    };
    Ok(serde_json::to_value(CheckPlanOut { checks }).unwrap())
}

/// Toy ignore rules: a segment named `ignored` or `target`; per source file (`dir/.toyignore`)
/// lines `name/` (directory segment), `*.ext` (extension) or `name` (any segment), relative to
/// the source's directory. `#` starts a comment.
fn classify(b: &Value) -> R {
    let x: ClassifyIn = body(b)?;
    let mut decisions = Vec::with_capacity(x.entries.len());
    for e in &x.entries {
        let mut rule = None;
        let segs: Vec<&str> = e.path.split('/').collect();
        if segs.iter().any(|s| *s == "ignored" || *s == "target") {
            rule = Some("builtin".to_owned());
        }
        for (src, text) in &x.ignore_sources {
            let dir = src.rsplit_once('/').map_or("", |(d, _)| d);
            let rel = if dir.is_empty() { Some(e.path.as_str()) } else { e.path.strip_prefix(&format!("{dir}/")) };
            let Some(rel) = rel else { continue };
            let rsegs: Vec<&str> = rel.split('/').collect();
            for (n, line) in text.lines().enumerate() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                let hit = if let Some(d) = l.strip_suffix('/') {
                    rsegs[..rsegs.len() - usize::from(e.kind != EntryKind::Dir)].contains(&d)
                } else if let Some(ext) = l.strip_prefix("*.") {
                    rel.rsplit('.').next() == Some(ext) && rel.contains('.')
                } else {
                    rsegs.contains(&l)
                };
                if hit && rule.is_none() {
                    rule = Some(format!("{src}:{}", n + 1));
                }
            }
        }
        decisions.push(Decision { path: e.path.clone(), ignored: rule.is_some(), rule });
    }
    Ok(serde_json::to_value(ClassifyOut { decisions }).unwrap())
}

fn b64(s: &str) -> Result<Vec<u8>, (&'static str, &'static str)> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let bytes: Vec<u8> = s.bytes().filter(|c| *c != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c).ok_or(INVALID)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// Toy diff: one hunk replacing every old line with every new line (unchanged → no hunk).
fn diff(b: &Value) -> R {
    let x: DiffIn = body(b)?;
    let before = x.before.as_deref().map(b64).transpose()?.unwrap_or_default();
    let after = x.after.as_deref().map(b64).transpose()?.unwrap_or_default();
    if before.len() as u64 > MAX_DIFF_SIDE || after.len() as u64 > MAX_DIFF_SIDE {
        return Ok(serde_json::to_value(DiffOut::TooLarge).unwrap());
    }
    if before.contains(&0) || after.contains(&0) {
        return Ok(serde_json::to_value(DiffOut::Binary).unwrap());
    }
    let (Ok(old), Ok(new)) = (std::str::from_utf8(&before), std::str::from_utf8(&after)) else {
        return Ok(serde_json::to_value(DiffOut::Binary).unwrap());
    };
    let hunks = if old == new {
        vec![]
    } else {
        let (o, n): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
        let lines = o.iter().map(|l| format!("-{l}")).chain(n.iter().map(|l| format!("+{l}"))).collect();
        vec![Hunk { old_start: 1, old_lines: o.len() as u64, new_start: 1, new_lines: n.len() as u64, lines }]
    };
    Ok(serde_json::to_value(DiffOut::Hunks { hunks }).unwrap())
}

impl Guest {
    fn dispatch(&mut self, op: &str, b: &Value) -> R {
        match (op, &mut self.mode) {
            ("describe", _) => Ok(serde_json::from_str(METADATA).unwrap()),
            ("detect", _) => detect(b),
            ("check_plan", _) => check_plan(b),
            ("classify", _) => classify(b),
            ("diff", _) => diff(b),
            ("capture.begin", Mode::Ready) => {
                let x: CaptureBegin = body(b)?;
                self.mode = Mode::Capture(Capture { expected: x.expected_tuples, fault: fault(&x.params), ..Default::default() });
                Ok(json!({}))
            }
            ("capture.chunk", Mode::Capture(c)) => {
                let x: CaptureChunk = body(b)?;
                if x.index != c.next_index {
                    return Err(INVALID);
                }
                let mut ops = Vec::with_capacity(x.tuples.len());
                for t in &x.tuples {
                    if c.last_path.as_deref().is_some_and(|p| p.as_bytes() >= t.path.as_bytes()) {
                        return Err(INVALID);
                    }
                    c.last_path = Some(t.path.clone());
                    ops.push(serde_json::to_value(capture_op(t)?).unwrap());
                }
                match c.fault.as_str() {
                    "skip_op" => drop(ops.pop()),
                    "wrong_path" if !ops.is_empty() => ops[0]["path"] = json!("zzz"),
                    _ => {}
                }
                c.next_index += 1;
                c.tuples += x.tuples.len() as u64;
                ops.iter().for_each(|o| c.ops.push(o).unwrap());
                Ok(json!({"ops": ops}))
            }
            ("capture.finish", Mode::Capture(c)) => {
                let x: CaptureFinish = body(b)?;
                if x.total_tuples != c.tuples || x.total_tuples != c.expected {
                    return Err(INVALID);
                }
                let mut o = std::mem::take(&mut c.ops).finish();
                if c.fault == "bad_o" {
                    o = "0".repeat(64);
                }
                let total = c.tuples;
                self.mode = Mode::Finished;
                Ok(json!({"output_digest": o, "total_ops": total}))
            }
            ("relate.begin", Mode::Ready) => {
                let x: RelateBegin = body(b)?;
                let f = fault(&x.params);
                self.mode = Mode::Relate(Relate { begin: Some(x), fault: f, ..Default::default() });
                Ok(json!({}))
            }
            ("relate.groups", Mode::Relate(r)) => {
                let x: RelateGroups = body(b)?;
                if x.index != r.next_index {
                    return Err(INVALID);
                }
                let raw = b["groups"].as_array().ok_or(INVALID)?;
                let mut rels = vec![];
                for (g, raw) in x.groups.iter().zip(raw) {
                    r.groups_hash.push(raw).map_err(|_| INVALID)?;
                    r.groups += 1;
                    r.members += g.delivered_members();
                    let Some(ms) = &g.members else { continue };
                    let del: Vec<_> = ms.iter().filter(|m| m.op["op"] == "delete").collect();
                    let add: Vec<_> = ms.iter().filter(|m| m.op["op"] == "add").collect();
                    if ms.len() == 2 && del.len() == 1 && add.len() == 1 {
                        rels.push(Relation { kind: KIND.into(), members: vec![del[0].op_index, add[0].op_index], payload: json!({"from": del[0].path, "to": add[0].path}) });
                    }
                }
                rels.sort_by_key(|x| x.members[0]);
                // A refused kind emits no relations (only the adversarial fault breaks this).
                let refuse = r.begin.as_ref().and_then(|b| b.params.get("refuse")).and_then(Value::as_bool) == Some(true);
                if refuse {
                    rels.clear();
                }
                let mut ack = Ack { groups_received: r.groups, index: x.index, members_received: r.members, running_groups_digest: r.groups_hash.peek() };
                match r.fault.as_str() {
                    "foreign_member" if !rels.is_empty() => rels[0].members[1] = 999_999,
                    "undeclared_kind" if !rels.is_empty() => rels[0].kind = "org.example.toy.copy".into(),
                    "bad_payload" if !rels.is_empty() => rels[0].payload = json!({"from": 1}),
                    "unsorted" if rels.len() > 1 => rels.reverse(),
                    "overflow_members" => {
                        if let Some(g) = x.groups.iter().find(|g| g.overflow == Some(true)) {
                            let _ = g;
                            rels.push(Relation { kind: KIND.into(), members: vec![0, 1], payload: json!({"from": "a", "to": "b"}) });
                        }
                    }
                    "wrong_ack_count" => ack.members_received += 1,
                    "wrong_running_digest" => ack.running_groups_digest = "0".repeat(64),
                    "trap" => panic!("injected trap"),
                    _ => {}
                }
                r.next_index += 1;
                for rel in &rels {
                    r.rel_hash.push(&serde_json::to_value(rel).unwrap()).unwrap();
                    r.relations += 1;
                }
                Ok(json!({"ack": ack, "relations": rels}))
            }
            ("relate.finish", Mode::Relate(r)) => {
                let x: RelateFinish = body(b)?;
                let begin = r.begin.as_ref().unwrap();
                if x.total_groups != begin.total_groups || x.total_members != begin.total_members || r.groups != begin.total_groups || r.members != begin.total_members {
                    return Err(INVALID);
                }
                let refused = begin.params.get("refuse").and_then(Value::as_bool) == Some(true) || r.fault == "refuse_with_relations";
                let status = if refused { KindStatus::Refused("ambiguous".into()) } else { KindStatus::Complete };
                let mut seen = r.groups_hash.peek();
                if r.fault == "skip_chunk_digest" {
                    seen = "0".repeat(64);
                }
                let mut kinds = vec![KindOutcome { kind: KIND.into(), status }];
                if r.fault == "missing_kind" {
                    kinds.clear();
                }
                let out = RelateFinishOk {
                    groups_digest_seen: seen,
                    kinds,
                    relations_digest: std::mem::take(&mut r.rel_hash).finish(),
                    total_groups_seen: r.groups,
                    total_members_seen: r.members,
                    total_relations: r.relations,
                };
                self.mode = Mode::Finished;
                Ok(serde_json::to_value(out).unwrap())
            }
            ("capture.begin" | "capture.chunk" | "capture.finish" | "relate.begin" | "relate.groups" | "relate.finish", _) => Err(BAD_STATE),
            _ => Err(UNSUPPORTED),
        }
    }

    fn call(&mut self, req: &[u8]) -> Vec<u8> {
        let resp = match serde_json::from_slice::<Request>(req) {
            Err(_) => Response { seq: 0, ok: None, err: Some(err(INVALID)) },
            Ok(r) => {
                let out = if r.v != "1.0" {
                    Err(UNSUPPORTED)
                } else if r.seq != self.seq + 1 {
                    Err(BAD_STATE)
                } else {
                    self.seq += 1;
                    self.dispatch(&r.op, &r.body)
                };
                match out {
                    Ok(v) => Response { seq: r.seq, ok: Some(v), err: None },
                    Err(e) => Response { seq: r.seq, ok: None, err: Some(err(e)) },
                }
            }
        };
        jcs::to_vec(&serde_json::to_value(resp).unwrap()).unwrap()
    }
}

fn err((code, message): (&str, &str)) -> WireError {
    WireError { code: code.into(), message: message.into(), retryable: false }
}

mod abi {
    #![allow(unsafe_code)]
    use super::*;

    fn leak(v: Vec<u8>) -> i64 {
        let len = v.len() as u32;
        let ptr = Box::into_raw(v.into_boxed_slice()) as *mut u8 as u32;
        calve_integration_contract::abi::pack(ptr, len)
    }

    /// Takes ownership of a buffer allocated by `cic_alloc` or returned by `leak`.
    ///
    /// # Safety
    /// `(ptr, len)` must be exactly a live `Box<[u8]>` produced by `cic_alloc(len)` (request
    /// buffers, ABI §6.2) or by `leak` (response buffers freed once through `cic_free`), and must
    /// not be taken twice. The host guarantees both by the buffer lifecycle; a host that breaks it
    /// can only corrupt this instance's own linear memory (wasm isolation).
    unsafe fn take(ptr: i32, len: i32) -> Box<[u8]> {
        // SAFETY: guaranteed by the caller contract above.
        unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr as u32 as usize as *mut u8, len as u32 as usize)) }
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
        Box::into_raw(vec![0u8; len as u32 as usize].into_boxed_slice()) as *mut u8 as u32 as i32
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn cic_free(ptr: i32, len: i32) {
        // SAFETY: the host frees each response exactly once with the pointer/length `leak` gave it.
        drop(unsafe { take(ptr, len) });
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn cic_init(ptr: i32, len: i32) -> i64 {
        // SAFETY: (ptr, len) is the request buffer from `cic_alloc`, owned by the guest from entry.
        let req = unsafe { take(ptr, len) };
        leak(hello(&req))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn cic_call(ptr: i32, len: i32) -> i64 {
        // SAFETY: (ptr, len) is the request buffer from `cic_alloc`, owned by the guest from entry.
        let req = unsafe { take(ptr, len) };
        leak(GUEST.with(|g| g.borrow_mut().call(&req)))
    }
}
