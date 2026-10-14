//! K1/K6: metadata, payload schema subset, relate fatality, grouping, and host verification of
//! relate/capture streams (rev 10 §6.4, §6.5, §6.5b).

use calve_integration_contract::digest::LineHasher;
use calve_integration_contract::metadata::*;
use calve_integration_contract::session::*;
use calve_integration_contract::wire::*;
use serde_json::{Value, json};

fn meta(required: bool, policy: &str) -> Metadata {
    serde_json::from_value(json!({
        "schema": "calve.integration/1", "extension_id": "org.example.toy", "version": "0.1.0", "abi": 1,
        "cic": [{"major": 1, "min_minor": 0, "max_minor": 0}],
        "capabilities": {"required": if required { json!(["capture.v1", "relate.v1"]) } else { json!(["capture.v1"]) }, "optional": []},
        "display_name": "Toy", "detect": {"markers": []}, "ops": ["capture", "relate"],
        "optional_relations": policy,
        "relations": [{"kind": "org.example.toy.rename", "required": required, "schema": schema()}],
        "future_key": {"ignored": true}
    }))
    .unwrap()
}

fn schema() -> Value {
    json!({"type": "object", "properties": {"from": {"type": "string"}, "to": {"type": "string"}}, "required": ["from", "to"], "additionalProperties": false})
}

#[test]
fn metadata_rules_and_forward_compat() {
    let m = meta(false, "omit-on-failure");
    m.validate().unwrap();
    assert_eq!(m.schema_number(), Some(1));
    assert!(
        m.extra.contains_key("future_key"),
        "unknown keys preserved and ignored"
    );
    let mut bad = m.clone();
    bad.relations[0].kind = "com.evil.rename".into();
    assert!(
        bad.validate().is_err(),
        "kind must carry the extension id prefix"
    );
    let mut bad = meta(true, "fail");
    bad.capabilities.required.retain(|c| c != "relate.v1");
    assert!(
        bad.validate().is_err(),
        "required relation implies required relate.v1"
    );
}

#[test]
fn payload_schema_subset() {
    validate_payload(&schema(), &json!({"from": "a", "to": "b"})).unwrap();
    assert!(validate_payload(&schema(), &json!({"from": "a"})).is_err());
    assert!(validate_payload(&schema(), &json!({"from": "a", "to": "b", "x": 1})).is_err());
    assert!(validate_payload(&schema(), &json!({"from": 1, "to": "b"})).is_err());
    assert!(check_schema(&json!({"type": "object", "properties": {}, "required": [], "additionalProperties": true})).is_err());
    assert!(check_schema(&json!({"type": "object", "properties": {"a": {"type": "number"}}, "required": [], "additionalProperties": false})).is_err());
    assert!(check_schema(&json!({"$ref": "x"})).is_err());
}

#[test]
fn relate_fatality_policy() {
    let k = "org.example.toy.rename".to_string();
    let refused = SessionEnd::Finished(vec![(k.clone(), KindStatus::Refused("ambiguous".into()))]);
    let complete = SessionEnd::Finished(vec![(k.clone(), KindStatus::Complete)]);
    let failed = SessionEnd::Failed("TRAPPED".into());
    // required kind
    let req = meta(true, "omit-on-failure");
    assert!(matches!(
        relate_outcome(&req, &failed),
        Err(RelateFatal::Failed(_))
    ));
    assert!(matches!(
        relate_outcome(&req, &refused),
        Err(RelateFatal::Refused(_))
    ));
    assert_eq!(relate_outcome(&req, &complete), Ok(vec![]));
    // optional kind, omit-on-failure: omitted and audited
    let opt = meta(false, "omit-on-failure");
    let om = relate_outcome(&opt, &failed).unwrap();
    assert_eq!((om.len(), om[0].session_failed), (1, true));
    let om = relate_outcome(&opt, &refused).unwrap();
    assert_eq!(
        (om[0].kind.as_str(), om[0].session_failed),
        ("org.example.toy.rename", false)
    );
    // optional kind, policy fail
    let fail = meta(false, "fail");
    assert!(matches!(
        relate_outcome(&fail, &failed),
        Err(RelateFatal::OptionalFailed(_))
    ));
    assert_eq!(relate_outcome(&fail, &complete), Ok(vec![]));
}

type Mutation = Box<dyn Fn(usize, &mut RelateChunkOk)>;

fn op(kind: &str, path: &str, key: Option<&str>) -> Value {
    match key {
        Some(k) => json!({"op": kind, "path": path, "group_key": k}),
        None => json!({"op": kind, "path": path}),
    }
}

#[test]
fn grouping_is_sorted_and_bounded() {
    let ops = vec![
        op("delete", "b", Some("d1")),
        op("add", "a", Some("d1")),
        op("modify", "c", None),
        op("add", "z", Some("d0")),
    ];
    let g = group_ops(&ops, 64);
    assert_eq!(
        g.iter().map(|g| g.key.as_str()).collect::<Vec<_>>(),
        ["d0", "d1"]
    );
    let d1: Vec<_> = g[1]
        .members
        .as_ref()
        .unwrap()
        .iter()
        .map(|m| (m.path.as_str(), m.op_index))
        .collect();
    assert_eq!(d1, [("a", 1), ("b", 0)], "sorted by (key, path, op_index)");
    let g = group_ops(&ops, 1);
    assert!(g[1].overflow == Some(true) && g[1].members.is_none() && g[1].count == 2);
    assert!(g.iter().all(Group::is_well_formed));
}

fn begin(groups: &[Group]) -> RelateBegin {
    let (tg, tm, c) = commitment(groups);
    RelateBegin {
        groups_commitment: c,
        max_group: 64,
        params: json!({}),
        source_o: "o".into(),
        total_groups: tg,
        total_members: tm,
    }
}

/// A correct guest response for one chunk, computed independently of the verifier.
fn honest(sent: &RelateGroups, h: &mut LineHasher, g: &mut u64, m: &mut u64) -> RelateChunkOk {
    let mut rel = vec![];
    for grp in &sent.groups {
        h.push(&serde_json::to_value(grp).unwrap()).unwrap();
        *g += 1;
        *m += grp.delivered_members();
        if let Some(ms) = &grp.members {
            let del = ms
                .iter()
                .filter(|x| x.op["op"] == "delete")
                .collect::<Vec<_>>();
            let add = ms
                .iter()
                .filter(|x| x.op["op"] == "add")
                .collect::<Vec<_>>();
            if ms.len() == 2 && del.len() == 1 && add.len() == 1 {
                rel.push(Relation {
                    kind: "org.example.toy.rename".into(),
                    members: vec![del[0].op_index, add[0].op_index],
                    payload: json!({"from": del[0].path, "to": add[0].path}),
                });
            }
        }
    }
    rel.sort_by_key(|r| r.members[0]);
    RelateChunkOk {
        ack: Ack {
            groups_received: *g,
            index: sent.index,
            members_received: *m,
            running_groups_digest: h.peek(),
        },
        relations: rel,
    }
}

fn stream() -> Vec<Group> {
    let ops = vec![
        op("delete", "old", Some("k1")),
        op("add", "new", Some("k1")),
        op("delete", "x", Some("k2")),
        op("add", "y", Some("k2")),
    ];
    group_ops(&ops, 64)
}

fn run(chunk: usize, mutate: impl Fn(usize, &mut RelateChunkOk)) -> Result<String, String> {
    let m = meta(false, "omit-on-failure");
    let groups = stream();
    let mut v = RelateVerifier::new(&m, begin(&groups));
    let (mut h, mut g, mut mm, mut rh, mut n) = (LineHasher::new(), 0, 0, LineHasher::new(), 0u64);
    for (i, c) in groups.chunks(chunk).enumerate() {
        let sent = RelateGroups {
            index: i as u64,
            groups: c.to_vec(),
        };
        let mut resp = honest(&sent, &mut h, &mut g, &mut mm);
        mutate(i, &mut resp);
        for r in &resp.relations {
            rh.push(&serde_json::to_value(r).unwrap()).unwrap();
            n += 1;
        }
        v.chunk(&sent, resp)?;
    }
    let fin = RelateFinishOk {
        groups_digest_seen: h.peek(),
        kinds: vec![KindOutcome {
            kind: "org.example.toy.rename".into(),
            status: KindStatus::Complete,
        }],
        relations_digest: rh.finish(),
        total_groups_seen: g,
        total_members_seen: mm,
        total_relations: n,
    };
    v.finish(fin).map(|(_, _, r)| r)
}

#[test]
fn relate_batch_invariance() {
    let r1 = run(1, |_, _| {}).unwrap();
    assert_eq!(run(3, |_, _| {}).unwrap(), r1);
    assert_eq!(run(64, |_, _| {}).unwrap(), r1);
}

#[test]
fn relate_adversarial_responses_rejected() {
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "member from another chunk",
            Box::new(|i, r| {
                if i == 0 {
                    r.relations[0].members[1] = 3
                }
            }),
        ),
        (
            "undeclared kind",
            Box::new(|_, r| r.relations[0].kind = "org.example.toy.copy".into()),
        ),
        (
            "schema-invalid payload",
            Box::new(|_, r| r.relations[0].payload = json!({"from": "a"})),
        ),
        (
            "wrong ack count",
            Box::new(|_, r| r.ack.groups_received += 1),
        ),
        (
            "wrong running digest",
            Box::new(|_, r| r.ack.running_groups_digest = "00".into()),
        ),
        (
            "duplicate member",
            Box::new(|_, r| r.relations[0].members = vec![0, 0]),
        ),
        (
            "empty members",
            Box::new(|_, r| r.relations[0].members.clear()),
        ),
    ];
    for (name, f) in cases {
        assert!(run(1, f).is_err(), "{name} must be ABI_VIOLATION");
    }
}

#[test]
fn relate_finish_rules() {
    let m = meta(false, "omit-on-failure");
    let groups = stream();
    let fin = |v: RelateVerifier, f: &dyn Fn(&mut RelateFinishOk)| {
        let mut x = RelateFinishOk {
            groups_digest_seen: commitment(&groups).2,
            kinds: vec![KindOutcome {
                kind: "org.example.toy.rename".into(),
                status: KindStatus::Complete,
            }],
            relations_digest: LineHasher::new().finish(),
            total_groups_seen: 2,
            total_members_seen: 4,
            total_relations: 0,
        };
        f(&mut x);
        v.finish(x)
    };
    // Host never sent the chunks: a guest claiming the commitment anyway is caught by the host's own count.
    assert!(
        fin(RelateVerifier::new(&m, begin(&groups)), &|_| {}).is_err(),
        "premature finish"
    );
    let feed = || {
        let mut v = RelateVerifier::new(&m, begin(&groups));
        let (mut h, mut g, mut mm) = (LineHasher::new(), 0, 0);
        let sent = RelateGroups {
            index: 0,
            groups: groups.clone(),
        };
        let mut ok = honest(&sent, &mut h, &mut g, &mut mm);
        ok.relations.clear();
        v.chunk(&sent, ok).unwrap();
        v
    };
    assert!(fin(feed(), &|_| {}).is_ok());
    assert!(
        fin(feed(), &|x| x.groups_digest_seen = "ff".into()).is_err(),
        "skipped-chunk digest"
    );
    assert!(
        fin(feed(), &|x| x.relations_digest = "ff".into()).is_err(),
        "R mismatch"
    );
    assert!(
        fin(feed(), &|x| x.kinds.clear()).is_err(),
        "every declared kind reported"
    );
    assert!(
        fin(feed(), &|x| x.kinds[0].status =
            KindStatus::Refused("no".into()))
        .is_ok(),
        "refusal with zero relations is valid"
    );
}

#[test]
fn merge_join_and_capture_verifier() {
    let e = |p: &str, d: &str| Entry {
        path: p.into(),
        kind: EntryKind::File,
        digest: Some(d.into()),
        size: Some(1),
        mode: None,
        target: None,
    };
    let t = merge_join(&[e("a", "1"), e("c", "1")], &[e("b", "2"), e("c", "2")]);
    assert_eq!(
        t.iter()
            .map(|t| (t.path.as_str(), t.base.is_some(), t.work.is_some()))
            .collect::<Vec<_>>(),
        [("a", true, false), ("b", false, true), ("c", true, true)]
    );
    let mut v = CaptureVerifier::default();
    let sent = CaptureChunk {
        index: 0,
        tuples: t,
    };
    let ops = vec![
        op("delete", "a", Some("1")),
        op("add", "b", Some("2")),
        json!({"op": "modify", "path": "c"}),
    ];
    v.chunk(&sent, &CaptureChunkOk { ops: ops.clone() })
        .unwrap();
    let mut h = LineHasher::new();
    ops.iter().for_each(|o| h.push(o).unwrap());
    let o = h.finish();
    assert_eq!(
        v.finish(&CaptureFinishOk {
            output_digest: o.clone(),
            total_ops: 3
        })
        .unwrap(),
        o
    );
    let mut v = CaptureVerifier::default();
    assert!(
        v.chunk(
            &sent,
            &CaptureChunkOk {
                ops: vec![op("add", "a", None), ops[1].clone(), ops[2].clone()]
            }
        )
        .is_err()
    );
    assert!(
        v.chunk(
            &CaptureChunk {
                index: 1,
                tuples: vec![]
            },
            &CaptureChunkOk { ops: vec![] }
        )
        .is_err(),
        "out of order"
    );
}

#[test]
fn jcs_safe_integer_bound() {
    use calve_integration_contract::jcs;
    assert!(jcs::to_vec(&json!(9007199254740991u64)).is_ok());
    assert!(jcs::to_vec(&json!(-9007199254740991i64)).is_ok());
    assert!(jcs::to_vec(&json!(9007199254740992u64)).is_err());
}
