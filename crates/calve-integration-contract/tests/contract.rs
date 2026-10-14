//! K1–K2: negotiation matrix, JCS, path-local validation, digests.

use calve_integration_contract::hello::*;
use calve_integration_contract::wire::*;
use calve_integration_contract::{abi, digest::LineHasher, jcs};
use serde_json::json;

fn r(major: u32, lo: u32, hi: u32) -> CicRange {
    CicRange {
        major,
        min_minor: lo,
        max_minor: hi,
    }
}

fn host(cic: Vec<CicRange>) -> HostHello {
    HostHello {
        abi: vec![1],
        cic,
        capabilities: vec!["capture.v1".into(), "relate.v1".into(), "diff.v1".into()],
        schemas: vec![1],
    }
}

fn guest(cic: Vec<CicRange>, required: &[&str]) -> (GuestHello, Declared) {
    let caps = Capabilities {
        required: required.iter().map(|s| s.to_string()).collect(),
        optional: vec!["diff.v1".into(), "x.v9".into()],
    };
    let g = GuestHello {
        abi: 1,
        cic: cic.clone(),
        capabilities: caps.clone(),
        schema: 1,
        extension_id: "org.example".into(),
        version: "1.0.0".into(),
    };
    (
        g,
        Declared {
            abi: 1,
            cic,
            capabilities: caps,
            schema: 1,
        },
    )
}

#[test]
fn negotiation_matrix() {
    let cases = [
        (vec![r(1, 0, 3)], vec![r(1, 2, 5)], Ok((1, 3))), // right overlap
        (vec![r(1, 2, 5)], vec![r(1, 0, 3)], Ok((1, 3))), // left overlap
        (vec![r(1, 0, 9)], vec![r(1, 2, 4)], Ok((1, 4))), // contained
        (vec![r(1, 2, 4)], vec![r(1, 2, 4)], Ok((1, 4))), // equal
        (
            vec![r(1, 0, 3), r(2, 0, 2)],
            vec![r(1, 0, 3), r(2, 1, 1)],
            Ok((2, 1)),
        ), // highest common major
        (
            vec![r(1, 0, 1)],
            vec![r(1, 2, 3)],
            Err(NegotiationError::Wire),
        ), // disjoint minors
        (
            vec![r(1, 0, 9)],
            vec![r(2, 0, 9)],
            Err(NegotiationError::Wire),
        ), // no common major
    ];
    for (h, g, want) in cases {
        let (gh, d) = guest(g.clone(), &["capture.v1"]);
        let got = negotiate(&host(h.clone()), &gh, &d).map(|n| (n.major, n.minor));
        assert_eq!(got, want, "host {h:?} guest {g:?}");
    }
}

#[test]
fn capability_sets_and_metadata_equality() {
    let (g, d) = guest(vec![r(1, 0, 0)], &["capture.v1"]);
    let n = negotiate(&host(vec![r(1, 0, 0)]), &g, &d).unwrap();
    assert!(n.capabilities.contains("capture.v1") && n.capabilities.contains("diff.v1"));
    assert!(
        !n.capabilities.contains("x.v9"),
        "only host-supported advertised capabilities"
    );
    let (g, d) = guest(vec![r(1, 0, 0)], &["unknown.v1"]);
    assert_eq!(
        negotiate(&host(vec![r(1, 0, 0)]), &g, &d),
        Err(NegotiationError::Capability("unknown.v1".into()))
    );
    let (mut g, d) = guest(vec![r(1, 0, 0)], &[]);
    g.capabilities.optional.push("relate.v1".into());
    assert_eq!(
        negotiate(&host(vec![r(1, 0, 0)]), &g, &d),
        Err(NegotiationError::MetadataMismatch("capabilities"))
    );
    let (mut g, mut d) = guest(vec![r(1, 0, 0)], &[]);
    g.abi = 2;
    d.abi = 2;
    assert_eq!(
        negotiate(&host(vec![r(1, 0, 0)]), &g, &d),
        Err(NegotiationError::Abi)
    );
    let (mut g, mut d) = guest(vec![r(1, 0, 0)], &[]);
    g.schema = 2;
    d.schema = 2;
    assert_eq!(
        negotiate(&host(vec![r(1, 0, 0)]), &g, &d),
        Err(NegotiationError::Schema(2))
    );
}

#[test]
fn hello_is_strict_with_reserved_x() {
    let ok = json!({"hello": 0, "host": {"abi": [1], "cic": [{"major":1,"min_minor":0,"max_minor":0}], "capabilities": [], "schemas": [1]}, "x": {"anything": 1}});
    assert!(serde_json::from_value::<HelloRequest>(ok).is_ok());
    let bad = json!({"hello": 0, "host": {"abi": [1], "cic": [], "capabilities": [], "schemas": [1], "extra": 1}});
    assert!(serde_json::from_value::<HelloRequest>(bad).is_err());
}

#[test]
fn jcs_rfc8785_subset() {
    // Key order by UTF-16 code units (RFC 8785 §3.2.3 example ordering), compact output.
    let v = json!({"\u{20ac}": "Euro", "\r": "CR", "1": "one", "\u{1f600}": "emoji", "\u{0080}": "ctrl", "\u{00f6}": "o"});
    let out = String::from_utf8(jcs::to_vec(&v).unwrap()).unwrap();
    assert_eq!(
        out,
        "{\"\\r\":\"CR\",\"1\":\"one\",\"\u{0080}\":\"ctrl\",\"\u{00f6}\":\"o\",\"\u{20ac}\":\"Euro\",\"\u{1f600}\":\"emoji\"}"
    );
    assert_eq!(
        jcs::to_vec(&json!({"b": [1, {"d": 2, "c": true}], "a": null})).unwrap(),
        br#"{"a":null,"b":[1,{"c":true,"d":2}]}"#
    );
    assert_eq!(jcs::to_vec(&json!({"f": 1.5})), Err(jcs::FloatNotAllowed));
    assert!(jcs::is_canonical(br#"{"a":1}"#));
    assert!(!jcs::is_canonical(br#"{ "a": 1 }"#));
}

#[test]
fn line_digest_is_order_sensitive_and_chunking_invariant() {
    let items: Vec<_> = (0..10)
        .map(|i| json!({"path": format!("f{i}"), "n": i}))
        .collect();
    let mut a = LineHasher::new();
    items.iter().for_each(|i| a.push(i).unwrap());
    let mut b = LineHasher::new();
    for chunk in items.chunks(3) {
        chunk.iter().for_each(|i| b.push(i).unwrap());
    }
    assert_eq!(a.peek(), b.peek());
    let mut c = LineHasher::new();
    items.iter().rev().for_each(|i| c.push(i).unwrap());
    assert_ne!(a.finish(), c.finish());
}

fn e(path: &str, d: &str) -> Entry {
    Entry {
        path: path.into(),
        kind: EntryKind::File,
        digest: Some(d.into()),
        size: Some(1),
        mode: Some(0o644),
        target: None,
    }
}

#[test]
fn capture_chunk_validation() {
    let t = vec![
        Tuple {
            path: "a".into(),
            base: None,
            work: Some(e("a", "1")),
        },
        Tuple {
            path: "b".into(),
            base: Some(e("b", "1")),
            work: None,
        },
        Tuple {
            path: "c".into(),
            base: Some(e("c", "1")),
            work: Some(e("c", "2")),
        },
        Tuple {
            path: "d".into(),
            base: Some(e("d", "1")),
            work: Some(e("d", "1")),
        },
    ];
    let good = vec![
        CaptureOp::Add {
            path: "a".into(),
            group_key: Some("1".into()),
        },
        CaptureOp::Delete {
            path: "b".into(),
            group_key: Some("1".into()),
        },
        CaptureOp::Modify { path: "c".into() },
        CaptureOp::Unchanged { path: "d".into() },
    ];
    validate_capture_chunk(&t, &good).unwrap();
    assert!(
        validate_capture_chunk(&t, &good[..3]).is_err(),
        "cardinality"
    );
    let mut swapped = good.clone();
    swapped.swap(0, 1);
    assert!(validate_capture_chunk(&t, &swapped).is_err(), "order/path");
    let mut wrong = good.clone();
    wrong[2] = CaptureOp::Add {
        path: "c".into(),
        group_key: None,
    };
    assert!(validate_capture_chunk(&t, &wrong).is_err(), "shape");
    let mut fake = good;
    fake[3] = CaptureOp::Modify { path: "d".into() };
    assert!(
        validate_capture_chunk(&t, &fake).is_err(),
        "modify of identical entry"
    );
}

#[test]
fn abi_pack_and_bounds() {
    let p = abi::pack(0x1234, 99);
    assert_eq!(abi::unpack(p), (0x1234, 99));
    assert_eq!(
        abi::unpack(abi::pack(u32::MAX, u32::MAX)),
        (u32::MAX, u32::MAX)
    );
    assert!(abi::in_bounds(16, 16, 32));
    assert!(!abi::in_bounds(16, 17, 32));
    assert!(!abi::in_bounds(0, 1, 32), "null pointer");
    assert!(
        !abi::in_bounds(u32::MAX, u32::MAX, u64::MAX >> 1)
            || (u32::MAX as u64 + u32::MAX as u64) <= (u64::MAX >> 1)
    );
}
