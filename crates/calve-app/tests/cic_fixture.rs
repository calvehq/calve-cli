//! The fixture guest's ops over the production host, and the schema-1 domain declarations
//! (`files`, `resources`, `checks`) the host relies on instead of domain literals.

use calve_app::integration::host_hello;
use calve_app::sandbox::{CalveHost, HostConfig};
use calve_integration_contract::driver::{Driver, Session};
use calve_integration_contract::wire::*;
use calve_testkit::cic::*;
use serde_json::{Value, json};

fn session() -> Session<Box<dyn Driver>> {
    let d: Box<dyn Driver> =
        Box::new(CalveHost::new(&guest("fixture"), HostConfig::default()).unwrap());
    Session::open(d, &host_hello(), &fixture_metadata()).unwrap()
}

fn b64(b: &[u8]) -> String {
    openaevc::protocol::b64::encode(b)
}

#[test]
fn describe_equals_the_signed_metadata_and_declarations_validate() {
    let meta = fixture_metadata();
    meta.validate().unwrap();
    let files = meta.files.as_ref().unwrap();
    assert_eq!(
        (files.put.as_str(), files.delete.as_str()),
        ("org.example.toy.put", "org.example.toy.delete")
    );
    assert_eq!(meta.resources[0].short, "note");
    let d = session().request("describe", json!({})).unwrap();
    let canon = |v: &Value| calve_integration_contract::jcs::to_vec(v).unwrap();
    assert_eq!(canon(&d), canon(&serde_json::to_value(&meta).unwrap()));
}

#[test]
fn declarations_must_use_the_extension_namespace_and_capabilities() {
    let mut m = fixture_metadata();
    m.files.as_mut().unwrap().put = "org.calve.software.snapshot".into();
    assert!(m.validate().is_err(), "foreign kind");
    let mut m = fixture_metadata();
    m.capabilities.required.retain(|c| c != "classify.v1");
    assert!(m.validate().is_err(), "files need classify.v1");
    let mut m = fixture_metadata();
    m.resources.push(m.resources[0].clone());
    assert!(m.validate().is_err(), "duplicate short name");
    let mut m = fixture_metadata();
    m.files.as_mut().unwrap().ignore_files = vec!["../x".into()];
    assert!(m.validate().is_err(), "ignore file names are plain names");
}

#[test]
fn detect_check_plan_classify_diff() {
    let mut s = session();
    let d: DetectOut = serde_json::from_value(
        s.request("detect", json!({"markers": ["toy.toml"], "extensions": []}))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(d.languages, ["toy"]);
    let p: CheckPlanOut = serde_json::from_value(
        s.request("check_plan", json!({"languages": ["toy"], "markers": []}))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(p.checks[0].argv, ["toy-check", "--all"]);
    let entries = vec![
        ClassifyEntry {
            path: "a/target/x".into(),
            kind: EntryKind::File,
            size: Some(1),
        },
        ClassifyEntry {
            path: "src/gen.tmp".into(),
            kind: EntryKind::File,
            size: Some(1),
        },
        ClassifyEntry {
            path: "src/main.toy".into(),
            kind: EntryKind::File,
            size: Some(1),
        },
    ];
    let c: ClassifyOut = serde_json::from_value(
        s.request(
            "classify",
            json!({"entries": entries, "ignore_sources": {"src/.toyignore": "# c\n*.tmp\n"}}),
        )
        .unwrap(),
    )
    .unwrap();
    validate_classify(&entries, &c.decisions).unwrap();
    assert_eq!(
        c.decisions.iter().map(|d| d.ignored).collect::<Vec<_>>(),
        [true, true, false]
    );
    assert_eq!(c.decisions[1].rule.as_deref(), Some("src/.toyignore:2"));
    let h: DiffOut = serde_json::from_value(
        s.request(
            "diff",
            json!({"path": "a", "before": b64(b"x\n"), "after": b64(b"y\n"), "context": 3}),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        h,
        DiffOut::Hunks {
            hunks: vec![Hunk {
                old_start: 1,
                old_lines: 1,
                new_start: 1,
                new_lines: 1,
                lines: vec!["-x".into(), "+y".into()]
            }]
        }
    );
    let b: DiffOut = serde_json::from_value(
        s.request(
            "diff",
            json!({"path": "a", "after": b64(b"\0"), "context": 3}),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(b, DiffOut::Binary);
}
