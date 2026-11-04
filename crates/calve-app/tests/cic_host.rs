//! Production CIC host (`calve-app` sandbox) against the testkit's independent mini host and
//! the two independent reference guests (rev 10 §6.2–§6.8): 2×2 byte-identical goldens,
//! determinism over fuel slices, the adversarial module set on both hosts, deadlines, and the
//! relate session (invariance, adversarial guests, atomicity, fatality).

use std::time::Duration;

use calve_app::sandbox::{CalveHost, HostConfig};
use calve_integration_contract::driver::{Driver, HostError, Session};
use calve_integration_contract::metadata::{RelateFatal, SessionEnd, relate_outcome};
use calve_integration_contract::wire::KindStatus;
use calve_testkit::cic::*;
use calve_testkit::mini_host::MiniHost;
use serde_json::{Value, json};

type Transcript = Vec<(Vec<u8>, Vec<u8>)>;
type Make = dyn Fn(&[u8]) -> Box<dyn Driver>;

fn calve(w: &[u8]) -> Box<dyn Driver> {
    Box::new(CalveHost::new(w, HostConfig::default()).unwrap())
}
fn calve_slice(slice: u64) -> impl Fn(&[u8]) -> Box<dyn Driver> {
    move |w| {
        Box::new(
            CalveHost::new(
                w,
                HostConfig {
                    fuel_slice: slice,
                    ..HostConfig::default()
                },
            )
            .unwrap(),
        ) as Box<dyn Driver>
    }
}
/// Classification tests: a debug-build relate call runs close to the 5 s soft deadline, so a
/// slow moment would turn the verdict under test into DEADLINE_EXCEEDED. Deadlines have their
/// own tests; these check what a response is classified as.
fn calve_untimed(w: &[u8]) -> Box<dyn Driver> {
    let cfg = HostConfig {
        soft_deadline: std::time::Duration::from_secs(3600),
        ..HostConfig::default()
    };
    Box::new(CalveHost::new(w, cfg).unwrap())
}
fn mini(w: &[u8]) -> Box<dyn Driver> {
    Box::new(MiniHost::new(w).unwrap())
}

fn open(make: &Make, wasm: &[u8]) -> Session<Box<dyn Driver>> {
    Session::open_recording(make(wasm), &host_hello(), &toy_metadata()).unwrap()
}

/// Every session of the golden scenario, each on a fresh instance (§6.2).
fn transcripts(make: &Make, wasm: &[u8]) -> Vec<Transcript> {
    let meta = toy_metadata();
    let mut out = vec![];
    // 1: stateless ops and wire errors.
    let mut s = open(make, wasm);
    s.raw("describe", json!({})).unwrap().unwrap();
    s.raw(
        "detect",
        json!({"markers": ["package.json", "Cargo.toml", "README"]}),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        s.raw("capture.chunk", json!({"index": 0, "tuples": []}))
            .unwrap()
            .unwrap_err()
            .code,
        "BAD_STATE"
    );
    out.push(s.transcript.take().unwrap());
    // 2: capture.
    let (base, work) = scenario(30);
    let mut s = open(make, wasm);
    let (ops, cap) = capture(&mut s, &base, &work, json!({}), 4).unwrap();
    out.push(s.transcript.take().unwrap());
    // 3: relate over the capture's ops.
    let mut s = open(make, wasm);
    let rel = relate(&mut s, &meta, &cap.output_digest, &ops, json!({}), 64, 3).unwrap();
    assert!(!rel.relations.is_empty(), "renames found");
    out.push(s.transcript.take().unwrap());
    // 4: a guest-detected path-order violation.
    let mut s = open(make, wasm);
    s.request(
        "capture.begin",
        json!({"base_digest": "", "expected_tuples": 2, "params": {}, "work_digest": ""}),
    )
    .unwrap();
    let t = |p: &str| json!({"path": p, "work": {"kind": "file", "path": p}});
    assert_eq!(
        s.raw(
            "capture.chunk",
            json!({"index": 0, "tuples": [t("b"), t("a")]})
        )
        .unwrap()
        .unwrap_err()
        .code,
        "INVALID_INPUT"
    );
    out.push(s.transcript.take().unwrap());
    out
}

fn to_jsonl(ts: &[Transcript]) -> String {
    let mut s = String::new();
    for (i, t) in ts.iter().enumerate() {
        for (req, resp) in t {
            s += &serde_json::to_string(&json!({"session": i, "request": String::from_utf8_lossy(req), "response": String::from_utf8_lossy(resp)})).unwrap();
            s.push('\n');
        }
    }
    s
}

#[test]
fn fixtures_match_their_recorded_digests() {
    let sums = std::fs::read_to_string(fixtures().join("SHA256SUMS")).unwrap();
    for line in sums.lines() {
        let (digest, name) = line.split_once("  ").unwrap();
        let bytes = std::fs::read(fixtures().join(name)).unwrap();
        assert_eq!(calve_app::sandbox::sha256_hex(&bytes), digest, "{name}");
    }
}

#[test]
fn two_guests_by_two_hosts_byte_identical_and_golden() {
    let combos: [(&str, &Make, &str); 4] = [
        ("calve", &calve, "ref-rust"),
        ("calve", &calve, "ref-min"),
        ("mini", &mini, "ref-rust"),
        ("mini", &mini, "ref-min"),
    ];
    let reference = transcripts(combos[0].1, &guest(combos[0].2));
    for (h, make, g) in &combos[1..] {
        let got = transcripts(*make, &guest(g));
        assert_eq!(got.len(), reference.len());
        for (i, (a, b)) in reference.iter().zip(&got).enumerate() {
            assert_eq!(a.len(), b.len(), "{h} × {g}: session {i}");
            for (k, (x, y)) in a.iter().zip(b).enumerate() {
                assert_eq!(
                    String::from_utf8_lossy(&x.1),
                    String::from_utf8_lossy(&y.1),
                    "{h} × {g}: session {i} message {k}"
                );
            }
        }
    }
    let golden = fixtures().join("goldens/v1/session.jsonl");
    let text = to_jsonl(&reference);
    if std::env::var_os("CIC_BLESS").is_some() {
        std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
        std::fs::write(&golden, &text).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(&golden).expect("golden (CIC_BLESS=1 to record)"),
        text,
        "golden drift"
    );
}

#[test]
fn fuel_slice_size_does_not_change_bytes() {
    let w = guest("ref-rust");
    assert_eq!(
        transcripts(&calve_slice(100_000), &w),
        transcripts(&calve_slice(10_000_000), &w)
    );
}

#[test]
fn ops_outside_the_negotiated_set_are_refused_without_a_call() {
    let mut s = open(&calve, &guest("ref-min"));
    let before = s.transcript.as_ref().unwrap().len();
    let e = s.raw("materialize_plan", json!({})).unwrap_err();
    assert_eq!(e.code(), "UNSUPPORTED_OP");
    assert_eq!(
        s.transcript.as_ref().unwrap().len(),
        before,
        "no guest call"
    );
}

#[test]
fn hello_must_equal_the_signed_metadata() {
    let mut meta = toy_metadata();
    meta.capabilities.optional.retain(|c| c != "relate.v1");
    let e = Session::open(calve(&guest("ref-rust")), &host_hello(), &meta)
        .err()
        .unwrap();
    assert_eq!(e.code(), "ABI_VIOLATION");
    let mut meta = toy_metadata();
    meta.version = "9.9.9".into();
    assert_eq!(
        Session::open(calve(&guest("ref-rust")), &host_hello(), &meta)
            .err()
            .unwrap()
            .code(),
        "ABI_VIOLATION"
    );
    // A host without a required capability → INCOMPATIBLE_CIC.
    let mut host = host_hello();
    host.capabilities.retain(|c| c != "capture.v1");
    assert_eq!(
        Session::open(calve(&guest("ref-rust")), &host, &toy_metadata())
            .err()
            .unwrap()
            .code(),
        "INCOMPATIBLE_CIC"
    );
}

// ---------------------------------------------------------------------- adversarial modules

struct Wat {
    top: &'static str,
    memory: String,
    version: &'static str,
    alloc: String,
    free: &'static str,
    call: String,
    extra: &'static str,
    resp: Vec<u8>,
}

const HELLO: &[u8] = br#"{"guest":{"abi":1,"capabilities":{"optional":["describe.v1","detect.v1","relate.v1"],"required":["capture.v1"]},"cic":[{"major":1,"max_minor":0,"min_minor":0}],"extension_id":"org.example.toy","schema":1,"version":"0.1.0"},"hello":0}"#;

fn pack(ptr: u64, len: u64) -> String {
    format!("(i64.const {})", ((ptr << 32) | len) as i64)
}

fn wat_bytes(b: &[u8]) -> String {
    b.iter().map(|c| format!("\\{c:02x}")).collect()
}

impl Default for Wat {
    fn default() -> Self {
        Wat {
            top: "",
            memory: "(memory (export \"memory\") 4)".into(),
            version: "(i32.const 1)",
            alloc: "(local $p i32) global.get $bump local.set $p global.get $bump local.get 0 i32.add global.set $bump local.get $p".into(),
            free: "",
            call: pack(8192, 0),
            extra: "",
            resp: br#"{"ok":{},"seq":1}"#.to_vec(),
        }
    }
}

impl Wat {
    fn build(&self) -> Vec<u8> {
        let call = if self.call == pack(8192, 0) {
            pack(8192, self.resp.len() as u64)
        } else {
            self.call.clone()
        };
        let src = format!(
            r#"(module {top}
  {memory}
  (global $bump (mut i32) (i32.const 65536))
  (func (export "cic_abi_version") (result i32) {version})
  (func (export "cic_alloc") (param i32) (result i32) {alloc})
  (func (export "cic_free") (param i32 i32) {free})
  (func (export "cic_init") (param i32 i32) (result i64) {init})
  (func (export "cic_call") (param i32 i32) (result i64) {call})
  (data (i32.const 1024) "{hello}")
  (data (i32.const 8192) "{resp}")
  {extra})"#,
            top = self.top,
            memory = self.memory,
            version = self.version,
            alloc = self.alloc,
            free = self.free,
            init = pack(1024, HELLO.len() as u64),
            hello = wat_bytes(HELLO),
            resp = wat_bytes(&self.resp),
            extra = self.extra,
        );
        wat::parse_str(&src).unwrap_or_else(|e| panic!("{e}\n{src}"))
    }
}

type MakeResult = fn(&[u8]) -> Result<Box<dyn Driver>, HostError>;

/// hello + one call; the first error code.
fn outcome(make: MakeResult, wasm: &[u8]) -> String {
    let d = match make(wasm) {
        Ok(d) => d,
        Err(e) => return e.code().into(),
    };
    let mut s = match Session::open(d, &host_hello(), &toy_metadata()) {
        Ok(s) => s,
        Err(e) => return e.code().into(),
    };
    match s.raw("describe", json!({})) {
        Ok(Ok(_)) => "OK".into(),
        Ok(Err(e)) => e.code,
        Err(e) => e.code().into(),
    }
}

#[test]
fn adversarial_modules_same_code_on_both_hosts() {
    let c: MakeResult = |w| {
        CalveHost::new(
            w,
            HostConfig {
                fuel_per_call: 20_000_000,
                soft_deadline: Duration::from_secs(600),
                ..HostConfig::default()
            },
        )
        .map(|h| Box::new(h) as _)
    };
    let m: MakeResult = |w| MiniHost::with_fuel(w, 20_000_000).map(|h| Box::new(h) as _);
    let cases: Vec<(&str, Wat, &str)> = vec![
        ("baseline", Wat::default(), "OK"),
        ("import present", Wat { top: r#"(import "env" "f" (func))"#, ..Default::default() }, "ABI_VIOLATION"),
        ("start section", Wat { extra: "(func $s) (start $s)", ..Default::default() }, "ABI_VIOLATION"),
        ("two memories", Wat { extra: "(memory 1)", ..Default::default() }, "ABI_VIOLATION"),
        ("extra export", Wat { extra: r#"(func (export "extra"))"#, ..Default::default() }, "ABI_VIOLATION"),
        ("memory max above cap", Wat { memory: "(memory (export \"memory\") 4 4000)".into(), ..Default::default() }, "ABI_VIOLATION"),
        ("wrong ABI version", Wat { version: "(i32.const 2)", ..Default::default() }, "ABI_VIOLATION"),
        ("cic_alloc returns 0", Wat { alloc: "(i32.const 0)".into(), ..Default::default() }, "OUT_OF_MEMORY"),
        ("cic_alloc out of bounds", Wat { alloc: "(i32.const 2147418112)".into(), ..Default::default() }, "ABI_VIOLATION"),
        ("response ptr out of bounds", Wat { call: pack(0x7FFF_0000, 10), ..Default::default() }, "ABI_VIOLATION"),
        ("ptr+len overflows u32", Wat { call: pack(0xFFFF_FFF0, 0x100), ..Default::default() }, "ABI_VIOLATION"),
        ("len < 2", Wat { call: pack(8192, 1), ..Default::default() }, "ABI_VIOLATION"),
        ("len > max", Wat { call: pack(8192, 5 * 1024 * 1024), ..Default::default() }, "ABI_VIOLATION"),
        ("null result", Wat { call: "(i64.const 0)".into(), ..Default::default() }, "INTERNAL"),
        ("non-JSON", Wat { resp: b"xx".to_vec(), ..Default::default() }, "ABI_VIOLATION"),
        ("non-canonical JSON", Wat { resp: br#"{ "ok":{},"seq":1}"#.to_vec(), ..Default::default() }, "ABI_VIOLATION"),
        ("unsorted keys", Wat { resp: br#"{"seq":1,"ok":{}}"#.to_vec(), ..Default::default() }, "ABI_VIOLATION"),
        ("float in JSON", Wat { resp: br#"{"ok":1.5,"seq":1}"#.to_vec(), ..Default::default() }, "ABI_VIOLATION"),
        ("seq mismatch", Wat { resp: br#"{"ok":{},"seq":7}"#.to_vec(), ..Default::default() }, "ABI_VIOLATION"),
        ("ok and err", Wat { resp: br#"{"err":{"code":"X","message":"","retryable":false},"ok":{},"seq":1}"#.to_vec(), ..Default::default() }, "ABI_VIOLATION"),
        ("response overlaps request", Wat { call: "local.get 0 i64.extend_i32_u i64.const 32 i64.shl local.get 1 i64.extend_i32_u i64.or".into(), ..Default::default() }, "ABI_VIOLATION"),
        ("memory growth past cap then trap", Wat { call: "(if (i32.eq (memory.grow (i32.const 2000)) (i32.const -1)) (then unreachable)) (i64.const 0)".into(), ..Default::default() }, "OUT_OF_MEMORY"),
        ("infinite loop", Wat { call: "(loop $l (br $l)) (i64.const 0)".into(), ..Default::default() }, "OUT_OF_FUEL"),
        ("stack overflow", Wat { call: "(call $r) (i64.const 0)".into(), extra: "(func $r (call $r))", ..Default::default() }, "TRAPPED"),
        ("trap in cic_free", Wat { free: "unreachable", ..Default::default() }, "TRAPPED"),
    ];
    let mut failures = vec![];
    for (name, w, want) in cases {
        let wasm = w.build();
        let (gc, gm) = (outcome(c, &wasm), outcome(m, &wasm));
        if gc != want || gm != want {
            failures.push(format!("{name}: calve={gc} mini={gm} want={want}"));
        }
    }
    assert_eq!(
        outcome(
            c,
            &Wat {
                extra: "(table 20000 funcref)",
                ..Default::default()
            }
            .build()
        ),
        "ABI_VIOLATION",
        "Calve table cap"
    );
    assert_eq!(
        outcome(
            c,
            &Wat {
                extra: "(global $g (export \"g\") (mut i32) (i32.const 0))",
                ..Default::default()
            }
            .build()
        ),
        "ABI_VIOLATION",
        "mutable global export"
    );
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---------------------------------------------------------------------- deadlines (FG3)

fn spin_module(call: &str) -> Vec<u8> {
    Wat {
        memory: "(memory (export \"memory\") 1024)".into(),
        call: format!("{call} (i64.const 0)"),
        ..Default::default()
    }
    .build()
}

#[test]
fn fuel_budget_stops_an_infinite_loop() {
    let mut h = CalveHost::new(
        &spin_module("(loop $l (br $l))"),
        HostConfig {
            fuel_slice: 1_000_000,
            fuel_per_call: 50_000_000,
            soft_deadline: Duration::from_secs(600),
            ..HostConfig::default()
        },
    )
    .unwrap();
    let mut s = Session::open(&mut h, &host_hello(), &toy_metadata()).unwrap();
    assert_eq!(
        s.raw("describe", json!({})).unwrap_err(),
        HostError::OutOfFuel
    );
}

#[test]
fn soft_deadline_stops_within_about_one_slice() {
    for slice in [100_000u64, 10_000_000] {
        let deadline = Duration::from_millis(300);
        let mut h = CalveHost::new(
            &spin_module("(loop $l (br $l))"),
            HostConfig {
                fuel_slice: slice,
                fuel_per_call: u64::MAX / 2,
                soft_deadline: deadline,
                ..HostConfig::default()
            },
        )
        .unwrap();
        let r = Session::open(&mut h, &host_hello(), &toy_metadata())
            .unwrap()
            .raw("describe", json!({}));
        assert_eq!(r.unwrap_err(), HostError::DeadlineExceeded);
        let per_slice = h.last_call / h.last_slices as u32;
        assert!(
            h.last_call.saturating_sub(deadline) <= per_slice * 2 + Duration::from_millis(50),
            "slice {slice}: {:?}",
            h.last_call
        );
    }
}

#[test]
fn an_instance_is_never_reused_after_an_error() {
    let mut h = CalveHost::new(&spin_module("unreachable"), HostConfig::default()).unwrap();
    let hello = calve_integration_contract::driver::canon(
        &json!({"hello": 0, "host": serde_json::to_value(host_hello()).unwrap()}),
    )
    .unwrap();
    h.init(&hello).unwrap();
    assert!(matches!(h.call(b"{}"), Err(HostError::Trapped(_))));
    assert!(
        matches!(h.call(b"{}"), Err(HostError::Internal(_))),
        "discarded"
    );
}

// ---------------------------------------------------------------------- relate (FG13)

fn capture_ops() -> (Vec<Value>, String) {
    let (base, work) = scenario(60);
    let mut s = Session::open(calve(&guest("ref-rust")), &host_hello(), &toy_metadata()).unwrap();
    let (ops, c) = capture(&mut s, &base, &work, json!({}), 7).unwrap();
    (ops, c.output_digest)
}

fn run_relate(
    make: &Make,
    g: &str,
    params: Value,
    max_group: u64,
    chunk: usize,
) -> Result<calve_integration_contract::driver::RelateOut, HostError> {
    let (ops, o) = capture_ops();
    let meta = toy_metadata();
    let mut s = Session::open(make(&guest(g)), &host_hello(), &meta)?;
    relate(&mut s, &meta, &o, &ops, params, max_group, chunk)
}

#[test]
fn relate_same_relations_on_both_hosts_and_guests() {
    let reference = run_relate(&calve, "ref-rust", json!({}), 64, 3).unwrap();
    assert!(reference.relations.len() >= 5);
    for make in [&calve as &Make, &mini] {
        for g in ["ref-rust", "ref-min"] {
            let r = run_relate(make, g, json!({}), 64, 3).unwrap();
            assert_eq!(
                (&r.relations, &r.r, &r.kinds),
                (&reference.relations, &reference.r, &reference.kinds),
                "{g}"
            );
        }
    }
}

#[test]
fn relate_batch_and_max_group_invariance() {
    let r1 = run_relate(&calve, "ref-min", json!({}), 64, 1).unwrap().r;
    for chunk in [3, 64] {
        assert_eq!(
            run_relate(&calve, "ref-min", json!({}), 64, chunk)
                .unwrap()
                .r,
            r1,
            "chunk {chunk}"
        );
    }
    assert_eq!(
        run_relate(&calve, "ref-rust", json!({}), 2, 5).unwrap().r,
        r1
    );
    assert!(
        run_relate(&calve, "ref-rust", json!({}), 1, 5)
            .unwrap()
            .relations
            .is_empty(),
        "overflow → no relation"
    );
}

#[test]
fn relate_adversarial_guests_discard_everything() {
    for (fault, want) in [
        ("foreign_member", "ABI_VIOLATION"),
        ("undeclared_kind", "ABI_VIOLATION"),
        ("bad_payload", "ABI_VIOLATION"),
        ("unsorted", "ABI_VIOLATION"),
        ("overflow_members", "ABI_VIOLATION"),
        ("wrong_ack_count", "ABI_VIOLATION"),
        ("wrong_running_digest", "ABI_VIOLATION"),
        ("skip_chunk_digest", "ABI_VIOLATION"),
        ("refuse_with_relations", "ABI_VIOLATION"),
        ("missing_kind", "ABI_VIOLATION"),
        ("trap", "TRAPPED"),
    ] {
        let max_group = if fault == "overflow_members" { 1 } else { 64 };
        let r = run_relate(
            &calve_untimed,
            "ref-rust",
            json!({"fault": fault}),
            max_group,
            64,
        );
        assert_eq!(
            r.err().map(|e| e.code().to_owned()).as_deref(),
            Some(want),
            "{fault}"
        );
    }
}

#[test]
fn relate_fatality_policy() {
    let meta = toy_metadata();
    let refused = run_relate(&calve, "ref-rust", json!({"refuse": true}), 64, 3).unwrap();
    assert!(refused.relations.is_empty());
    let kinds: Vec<_> = refused
        .kinds
        .iter()
        .map(|k| (k.kind.clone(), k.status.clone()))
        .collect();
    assert_eq!(
        relate_outcome(&meta, &SessionEnd::Finished(kinds))
            .unwrap()
            .len(),
        1
    );
    let failed = run_relate(&calve, "ref-rust", json!({"fault": "trap"}), 64, 3).unwrap_err();
    assert!(
        relate_outcome(&meta, &SessionEnd::Failed(failed.code().into())).unwrap()[0].session_failed
    );
    let mut req = meta.clone();
    req.relations[0].required = true;
    req.capabilities.required.push("relate.v1".into());
    assert!(matches!(
        relate_outcome(&req, &SessionEnd::Failed("TRAPPED".into())),
        Err(RelateFatal::Failed(_))
    ));
    assert!(matches!(
        relate_outcome(
            &req,
            &SessionEnd::Finished(vec![(
                "org.example.toy.rename".into(),
                KindStatus::Refused("x".into())
            )])
        ),
        Err(RelateFatal::Refused(_))
    ));
}
